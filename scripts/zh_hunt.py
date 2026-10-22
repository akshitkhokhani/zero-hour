"""Read-only hunting: incident-card IOCs on disk and in git, AI-agent config audit,
and --deep posture checks (CI, secrets, exposed databases). Python stdlib only.

Never executes anything taken from a card or a config file. Never prints secret values.
"""
import glob
import hashlib
import json
import os
import re
import subprocess
import shutil
import sys

from zh_inventory import walk, _ignore_patterns, _rel, _read

HOME = os.path.expanduser("~")
OS_NAME = {"darwin": "darwin", "win32": "windows"}.get(sys.platform, "linux")

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
]

SUSPICIOUS = [
    (re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|;&\n]*\|\s*(ba|z|da)?sh\b", re.I), "downloads and pipes into a shell"),
    (re.compile(r"\b(curl|wget)\b[^|;&\n]*\|\s*(node|python3?|bun|deno|perl|ruby)\b", re.I), "downloads and pipes into an interpreter"),
    (re.compile(r"base64\s+(-d|--decode|-D)\b|frombase64string", re.I), "decodes base64 payload"),
    (re.compile(r"powershell[^\n]*\s-(e|enc|encodedcommand)\s", re.I), "runs encoded PowerShell"),
    (re.compile(r"\beval\s*[\"'(]?\s*\$\(\s*(curl|wget)", re.I), "evals remote content"),
    (re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}"), "talks to a raw IP address"),
    (re.compile(r"(/tmp/|/dev/shm/|\\temp\\)\S*\.(sh|js|mjs|py|ps1)\b", re.I), "runs a script from a temp dir"),
    (re.compile(r"\b(nohup|disown|setsid)\b"), "detaches a background process"),
    (re.compile(r"(\.ssh/|\.aws/credentials|\.npmrc|\.config/gh/hosts|\.docker/config\.json|\.kube/config)"), "touches credential files"),
]


def redact(text):
    text = re.sub(r"(\b[a-z][a-z0-9+.\-]*://[^:/\s@]+:)([^@\s/]+)@", r"\1[redacted]@", text, flags=re.I)
    text = re.sub(r"(?i)([?&](?:token|key|apikey|api_key|secret|password|pass|pwd|access_token|auth|sig|signature)=)[^&\s\"']+",
                  r"\1[redacted]", text)
    for _, pat in SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0)[:4] + "…[redacted]", text)
    text = re.sub(r"(?i)((?:token|secret|password|passwd|api[_-]?key|authorization)[\"'=:\s]+(?:bearer\s+)?)([^\s\"',]{6,})",
                  lambda m: m.group(1) + m.group(2)[:2] + "…[redacted]", text)
    return text


def short(text, n=140):
    text = redact(" ".join(str(text).split()))
    return text if len(text) <= n else text[: n - 1] + "…"


def tilde(path):
    return "~" + path[len(HOME):] if path.startswith(HOME) else path


# ---------------------------------------------------------------- card IOCs

def expand_ioc_path(path, project, sp_dirs):
    tokens = {
        "{home}": [HOME], "{project}": [project] if project else [],
        "{site-packages}": sp_dirs,
        "{launch-agents}": [os.path.join(HOME, "Library", "LaunchAgents")],
        "{systemd-user}": [os.path.join(HOME, ".config", "systemd", "user")],
        "{appdata}": [os.environ.get("APPDATA", os.path.join(HOME, "AppData", "Roaming"))],
    }
    out = [path]
    for tok, vals in tokens.items():
        nxt = []
        for p in out:
            if tok in p:
                nxt += [p.replace(tok, v) for v in vals]
            else:
                nxt.append(p)
        out = nxt
    return [os.path.expanduser(p.replace("/", os.sep)) for p in out if "{" not in p]


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def hunt_files(card, project, sp_dirs):
    hits = []
    for ioc in (card.get("iocs") or {}).get("files", []) or []:
        oses = ioc.get("os")
        if oses and OS_NAME not in oses:
            continue
        for pattern in expand_ioc_path(ioc.get("path", ""), project, sp_dirs):
            for f in glob.glob(pattern)[:50]:
                if not os.path.isfile(f):
                    continue
                if ioc.get("sha256") and _sha256(f) != ioc["sha256"].lower():
                    continue
                if ioc.get("contains"):
                    try:
                        with open(f, "r", encoding="utf-8", errors="replace") as fh:
                            if ioc["contains"] not in fh.read(2 << 20):
                                continue
                    except OSError:
                        continue
                shown = _rel(project, f) if project and f.startswith(project) else tilde(f)
                what = (' contains "%s"' % ioc["contains"]) if ioc.get("contains") else \
                       (" sha256 matches" if ioc.get("sha256") else " exists")
                hits.append({"level": ioc.get("level", "compromised"), "file": shown, "line": None,
                             "text": "%s%s — %s" % (shown, what, ioc.get("meaning", "known IOC"))})
    return hits


# git reads .git/config from the scanned repo; neutralise every key that can execute a program.
GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "log.showSignature=false", "-c", "gpg.program=false",
            "-c", "core.hooksPath=/dev/null", "-c", "diff.external=", "-c", "core.pager=cat",
            "-c", "safe.directory=*"]


def _git(args, timeout=20):
    from zh_inventory import which_safe
    exe = which_safe("git")
    if not exe:
        return ""
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_PAGER="cat")
    try:
        r = subprocess.run([exe] + GIT_SAFE + args, capture_output=True, text=True, timeout=timeout,
                           env=env, stdin=subprocess.DEVNULL, cwd=os.path.expanduser("~"))
        return r.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


_GIT_LOG_CACHE = {}


def _git_log(project):
    if project in _GIT_LOG_CACHE:
        return _GIT_LOG_CACHE[project]
    out = []
    if project and os.path.isdir(os.path.join(project, ".git")):
        text = _git(["-C", project, "log", "--all", "--no-show-signature", "-n", "5000", "--format=%h%x09%ae%x09%s"])
        out = [l.split("\t", 2) for l in text.splitlines() if l.count("\t") >= 2]
    _GIT_LOG_CACHE[project] = out
    return out


def hunt_git(card, project):
    hits = []
    for ioc in (card.get("iocs") or {}).get("git", []) or []:
        for sha, email, subj in _git_log(project):
            if ioc.get("author_email") and email.lower() != ioc["author_email"].lower():
                continue
            if ioc.get("message_contains") and ioc["message_contains"].lower() not in subj.lower():
                continue
            hits.append({"level": "compromised", "file": None, "line": None,
                         "text": "git commit %s by %s: \"%s\" — %s" % (sha, email, short(subj, 60),
                                                                      ioc.get("meaning", "known IOC"))})
    return hits


def hunt_github(card):
    iocs = (card.get("iocs") or {}).get("github_repos", []) or []
    from zh_inventory import which_safe
    gh = which_safe("gh")
    if not iocs or not gh:
        return [], bool(iocs)
    try:
        r = subprocess.run([gh, "repo", "list", "--limit", "1000", "--json", "name,description"],
                           capture_output=True, text=True, timeout=30)
        repos = json.loads(r.stdout or "[]")
    except (OSError, subprocess.SubprocessError, ValueError):
        return [], True
    hits = []
    for ioc in iocs:
        needle = ioc.get("description_contains", "").lower()
        for repo in repos:
            if needle and needle in (repo.get("description") or "").lower():
                hits.append({"level": "compromised", "file": None, "line": None,
                             "text": "GitHub repo %s has description \"%s\" — %s" % (
                                 repo.get("name"), short(repo.get("description"), 60), ioc.get("meaning", "exfil repo"))})
    return hits, False


# ---------------------------------------------------------------- AI-agent configs

PROJECT_AGENT_FILES = [".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
                       ".cursor/mcp.json", ".vscode/tasks.json", ".vscode/mcp.json", ".gemini/settings.json",
                       ".codex/config.toml", ".kiro/settings/mcp.json", ".windsurf/mcp.json"]
HOST_AGENT_FILES = ["~/.claude/settings.json", "~/.claude.json", "~/.cursor/mcp.json",
                    "~/.gemini/settings.json", "~/.codex/config.toml", "~/.codeium/windsurf/mcp_config.json",
                    "~/.kiro/settings/mcp.json"]


def _commands_from_json(obj, trail=""):
    """Yield (where, command-string, kind) for every command-like value."""
    if isinstance(obj, dict):
        if "command" in obj and isinstance(obj["command"], str):
            args = obj.get("args") if isinstance(obj.get("args"), list) else []
            kind = "hook" if "/hooks" in trail or trail.startswith("hooks") else \
                   "mcp" if "mcpServers" in trail or "servers" in trail else \
                   "task" if "tasks" in trail else "command"
            auto = ((obj.get("runOptions") or {}).get("runOn") == "folderOpen")
            yield trail, " ".join([obj["command"]] + [str(a) for a in args]), ("autorun-task" if auto else kind)
        for k, v in obj.items():
            if k in ("env", "headers"):
                continue
            yield from _commands_from_json(v, trail + "/" + str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _commands_from_json(v, trail + "[%d]" % i)


def _commands_from_toml(text):
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r'^\s*(command|args)\s*=\s*(.+)$', line)
        if m:
            yield i, m.group(2), "mcp"


def _strip_jsonc(text):
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def audit_agent_configs(project, include_host, card_strings):
    """Returns (hygiene findings, {card_id: [evidence]})."""
    findings, card_hits = [], {}
    targets = [(os.path.join(project, p), p, "project") for p in PROJECT_AGENT_FILES]
    if include_host:
        targets += [(os.path.expanduser(p), p, "host") for p in HOST_AGENT_FILES]
    for path, label, where in targets:
        if not os.path.isfile(path):
            continue
        text = _read(path)
        if text is None:
            continue
        lines = text.splitlines()
        cmds = []
        if path.endswith(".toml"):
            cmds = [(ln, c, k) for ln, c, k in _commands_from_toml(text)]
        else:
            try:
                data = json.loads(_strip_jsonc(text))
            except ValueError:
                continue
            for trail, cmd, kind in _commands_from_json(data):
                first = cmd.split()[0] if cmd.split() else cmd
                ln = next((i for i, l in enumerate(lines, 1) if first and first in l), None)
                cmds.append((ln, cmd, kind))
        for ln, cmd, kind in cmds:
            reasons = [why for pat, why in SUSPICIOUS if pat.search(cmd)]
            for cid, strings in card_strings.items():
                for s in strings:
                    if s and s.lower() in cmd.lower():
                        card_hits.setdefault(cid, []).append({
                            "level": "compromised", "file": label, "line": ln,
                            "text": "%s:%s %s references \"%s\" — campaign IOC planted in agent config" % (
                                label, ln or "?", kind, s)})
            if reasons:
                findings.append({"id": "agent-config-suspicious", "level": "high", "file": label, "line": ln,
                                 "title": "%s %s %s" % (kind, "command", "; ".join(reasons)),
                                 "detail": short(cmd), "standard": "CWE-506 · OWASP A08:2025"})
            elif where == "project" and kind in ("hook", "autorun-task"):
                findings.append({"id": "agent-config-autorun", "level": "low", "file": label, "line": ln,
                                 "title": "repo ships a %s that runs on your machine when opened in an AI agent/editor — review it" % kind,
                                 "detail": short(cmd), "standard": "CWE-829"})
            elif kind == "mcp" and re.search(r"\bnpx\s+(-y|--yes)\s+(@?[\w./-]+)(\s|$)", cmd) and \
                    not re.search(r"\bnpx\s+(-y|--yes)\s+@?[\w./-]+@\d", cmd):
                findings.append({"id": "mcp-unpinned", "level": "low", "file": label if where == "project" else tilde(path),
                                 "line": ln, "title": "MCP server runs an unpinned npm package (auto-updates = supply-chain risk); pin a version",
                                 "detail": short(cmd), "standard": "SLSA · CWE-1357"})
    return findings, card_hits


# ---------------------------------------------------------------- --deep checks

DB_IMAGES = ("postgres", "mysql", "mariadb", "mongo", "redis", "elasticsearch", "opensearch",
             "cassandra", "couchdb", "memcached", "clickhouse", "neo4j", "rabbitmq")
DEFAULT_PW = re.compile(r"(?i)(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*['\"]?(postgres|password|root|admin|example|secret|changeme|123456|test)['\"]?\s*$")


def audit_ci(inv):
    out = []
    for a in inv.get("actions", []):
        if not a["pinned"] and not a["name"].startswith(("actions/", "github/")):
            out.append({"id": "ci-unpinned-action", "level": "medium", "file": a["source"], "line": a["line"],
                        "title": "third-party action %s@%s not pinned to a commit SHA" % (a["path"], a["ref"]),
                        "standard": "OpenSSF Scorecard Pinned-Dependencies · SLSA"})
    root = inv["root"]
    for wf in sorted({a["source"] for a in inv.get("actions", [])} |
                     set(_rel(root, p) for p in glob.glob(os.path.join(root, ".github", "workflows", "*.y*ml")))):
        text = _read(os.path.join(root, wf)) or ""
        lines = text.splitlines()
        if re.search(r"(?m)^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target", text) and \
                re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", text):
            ln = next((i for i, l in enumerate(lines, 1) if "pull_request_target" in l), None)
            out.append({"id": "ci-prt-checkout", "level": "high", "file": wf, "line": ln,
                        "title": "pull_request_target + checkout of PR code = attacker code runs with your secrets",
                        "standard": "CWE-829 · OWASP CI/CD-SEC-4"})
        for i, l in enumerate(lines, 1):
            if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|review_comment|head_commit|commits|discussion|pages)[^}]*\b(title|body|message|name|email|label|ref|head_ref|page_name)\b", l) \
                    or re.search(r"\$\{\{\s*github\.head_ref\s*\}\}", l):
                out.append({"id": "ci-script-injection", "level": "high", "file": wf, "line": i,
                            "title": "untrusted event data interpolated into the workflow (script injection) — pass via env: instead",
                            "standard": "CWE-78 · OWASP CI/CD-SEC-4"})
        if re.search(r"(?m)^\s*permissions\s*:\s*write-all", text):
            out.append({"id": "ci-write-all", "level": "medium", "file": wf, "line": None,
                        "title": "permissions: write-all — use least privilege", "standard": "OpenSSF Token-Permissions"})
        elif not re.search(r"(?m)^permissions\s*:", text):
            out.append({"id": "ci-no-permissions", "level": "low", "file": wf, "line": None,
                        "title": "no top-level permissions: block (token may default to write)",
                        "standard": "OpenSSF Token-Permissions"})
    return out


def audit_compose(inv):
    out, root = [], inv["root"]
    for f in sorted({i["source"] for i in inv.get("images", []) if i["source"].endswith((".yml", ".yaml"))}):
        lines = (_read(os.path.join(root, f)) or "").splitlines()
        svc_db = False
        for i, l in enumerate(lines, 1):
            m = re.match(r"^\s*image:\s*['\"]?([^'\"\s#]+)", l)
            if m:
                svc_db = any(db in m.group(1).lower().rsplit("/", 1)[-1] for db in DB_IMAGES)
            pm = re.match(r"^\s*-\s*['\"]?((?:[\d.]+:)?\d+):\d+", l)
            if svc_db and pm and not pm.group(1).startswith(("127.0.0.1:", "localhost:")):
                out.append({"id": "db-port-public", "level": "medium", "file": f, "line": i,
                            "title": "database port published on all interfaces — bind to 127.0.0.1",
                            "standard": "CWE-668 · CIS Docker 5.13"})
            if DEFAULT_PW.search(l):
                out.append({"id": "db-default-password", "level": "medium", "file": f, "line": i,
                            "title": "database uses a default/guessable password", "standard": "CWE-1393 · OWASP A07:2025"})
    for img in inv.get("images", []):
        if img["source"] != "local docker images" and (img["tag"] in (None, "latest")) and not img["pinned"]:
            out.append({"id": "image-floating-tag", "level": "low", "file": img["source"], "line": img["line"],
                        "title": "image %s uses a floating tag — pin a version or digest" % img["name"],
                        "standard": "SLSA · CIS Docker 4.x"})
    return out


def _tracked_files(root):
    if os.path.isdir(os.path.join(root, ".git")):
        out = _git(["-C", root, "ls-files", "-z"])
        if out:
            return [os.path.join(root, p) for p in out.split("\0") if p]
    return walk(root, _ignore_patterns(root))  # generator: no giant in-memory file list


SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".jar", ".woff",
            ".woff2", ".ttf", ".mp4", ".mov", ".so", ".dylib", ".dll", ".exe", ".bin", ".lock", ".min.js",
            ".map", ".svg", ".wasm", ".pyc", ".class", ".sqlite", ".db")
MAX_SECRET_FILES = 20000
MAX_SECRET_BYTES = 64 << 20


def scan_secrets(root, limit=50):
    """Bounded: at most MAX_SECRET_FILES text files / MAX_SECRET_BYTES read, binaries and lockfiles skipped."""
    out, ignore = [], _ignore_patterns(root)
    files_read, bytes_read = 0, 0
    for path in _tracked_files(root):
        if path.lower().endswith(SKIP_EXT) or os.path.basename(path).endswith(("-lock.json", "-lock.yaml")):
            continue
        if files_read >= MAX_SECRET_FILES or bytes_read >= MAX_SECRET_BYTES:
            out.append({"id": "secret-scan-truncated", "level": "info", "file": None, "line": None,
                        "title": "secret scan stopped after %d files / %d MB (resource cap)" % (files_read, bytes_read >> 20)})
            break
        rel = _rel(root, path)
        if any(rel.replace(os.sep, "/").startswith(p + "/") for p in ignore):
            continue
        base = os.path.basename(path)
        if base == ".env" or re.match(r"^\.env\.(?!example|sample|template)", base):
            out.append({"id": "secret-env-file", "level": "high", "file": rel, "line": None,
                        "title": ".env file is tracked by git — remove it and rotate what's inside",
                        "standard": "CWE-538 · OWASP A02:2025"})
        try:
            if os.path.getsize(path) > 1 << 20:
                continue
            with open(path, "r", encoding="utf-8", errors="strict") as fh:
                text = fh.read()
            files_read += 1
            bytes_read += len(text)
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for label, pat in SECRET_PATTERNS:
                m = pat.search(line)
                if m:
                    out.append({"id": "secret-in-repo", "level": "high", "file": rel, "line": i,
                                "title": "%s committed (%s)" % (label, m.group(0)[:4] + "…[redacted]"),
                                "standard": "CWE-798 · OWASP A07:2025"})
                    break
            if len(out) >= limit:
                return out
    return out
