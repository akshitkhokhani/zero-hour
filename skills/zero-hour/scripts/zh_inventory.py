"""Build an inventory of what a project (and this machine) actually runs.

Read-only. Python stdlib only. Every item records the file and line it came from
so the report can cite evidence.
"""
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import deque

from zh_versions import clean, normalize_name

# Directories that only ever hold downloaded dependencies, caches or compiler output.
# "build"/"dist" are NOT pruned: real projects keep tooling lockfiles there (e.g. vscode/build).
PRUNE_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
              ".pytest_cache", ".next", ".nuxt", "target", "vendor", ".gradle",
              ".idea", ".cache", ".terraform", "site-packages", "bower_components", ".yarn"}
MAX_DEPTH = 6
MAX_FILES = 300000  # walk ceiling (a big monorepo is ~100k files)
MAX_CHAIN = 8  # dependency path shown as evidence; bounded so crafted lockfiles can't blow up memory
MAX_FILE_BYTES = 40 * 1024 * 1024


def _rel(root, path):
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return path


def _read(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _pkg(eco, name, version, source, line=None, direct=None, via=None, scope=None):
    return {"ecosystem": eco, "name": name, "version": clean(version), "source": source,
            "line": line, "direct": direct, "via": via, "scope": scope}


def _split_at_version(spec):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3')."""
    idx = spec.rfind("@")
    if idx <= 0:
        return spec, None
    return spec[:idx], spec[idx + 1:]


def _first_lines(text, pattern):
    """{captured name: first line number}, built in one pass (avoids O(packages x lines))."""
    rx, out = re.compile(pattern), {}
    for i, l in enumerate(text.splitlines(), 1):
        m = rx.search(l)
        if m and m.group(1) not in out:
            out[m.group(1)] = i
    return out


def _ignore_patterns(root):
    text = _read(os.path.join(root, ".zerohourignore"))
    if not text:
        return []
    return [l.strip().rstrip("/") for l in text.splitlines() if l.strip() and not l.startswith("#")]


def _ignored(rel, pats):
    rel = rel.replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, p) or rel.startswith(p + "/") for p in pats)


def walk(root, ignore=(), notes=None):
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    seen = 0
    for d, dirs, files in os.walk(root):
        seen += len(files)
        if seen > MAX_FILES:  # hard ceiling: never grind through a whole disk
            if notes is not None:
                notes.append("stopped after %d files — point zero-hour at a single project for full coverage" % MAX_FILES)
            return
        rel = _rel(root, d)
        if rel != "." and _ignored(rel, ignore):
            dirs[:] = []
            continue
        if d.count(os.sep) - base_depth >= MAX_DEPTH:
            if dirs and notes is not None and not any("deeper than" in n for n in notes):
                notes.append("directories deeper than %d levels were not scanned (e.g. %s)" % (MAX_DEPTH, rel))
            dirs[:] = []
        dirs[:] = [x for x in dirs if x not in PRUNE_DIRS]
        for f in files:
            path = os.path.join(d, f)
            if ignore and _ignored(_rel(root, path), ignore):
                continue
            yield path


# ---------------------------------------------------------------- npm family

def _manifest_direct(root_dir):
    data = _read(os.path.join(root_dir, "package.json"))
    try:
        pj = json.loads(data) if data else {}
    except ValueError:
        pj = {}
    out = {}
    for k in ("dependencies", "optionalDependencies", "peerDependencies"):
        for n in (pj.get(k) or {}):
            out[n] = "prod"
    for n in (pj.get("devDependencies") or {}):
        out.setdefault(n, "dev")
    return out


def parse_npm_lock(path, root):
    text = _read(path)
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    src = _rel(root, path)
    key_line = {}
    for i, l in enumerate(text.splitlines(), 1):
        m = re.match(r'\s*"(node_modules/[^"]+)":\s*\{', l)
        if m and m.group(1) not in key_line:
            key_line[m.group(1)] = i
    out = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict) and pkgs:
        root_entry = pkgs.get("", {})
        roots = {}
        for k in ("dependencies", "optionalDependencies", "peerDependencies"):
            roots.update({n: "prod" for n in (root_entry.get(k) or {})})
        for n in (root_entry.get("devDependencies") or {}):
            roots.setdefault(n, "dev")

        def resolve(from_key, dep):
            cur = from_key
            while True:
                cand = (cur + "/node_modules/" + dep) if cur else ("node_modules/" + dep)
                if cand in pkgs:
                    return cand
                if not cur:
                    return None
                idx = cur.rfind("/node_modules/")
                cur = cur[:idx] if idx >= 0 else ""

        parent = {}
        q = deque()
        for n in roots:
            k = resolve("", n)
            if k and k not in parent:
                parent[k] = None
                q.append(k)
        while q:
            k = q.popleft()
            e = pkgs.get(k, {})
            for dk in ("dependencies", "optionalDependencies", "peerDependencies"):
                for dep in (e.get(dk) or {}):
                    t = resolve(k, dep)
                    if t and t not in parent:
                        parent[t] = k
                        q.append(t)

        def chain(k):
            names = []
            while k and len(names) < MAX_CHAIN:
                names.append(k.rsplit("node_modules/", 1)[-1])
                k = parent.get(k)
            return list(reversed(names))

        for key, e in pkgs.items():
            if not key or e.get("link") or "node_modules/" not in key:
                continue
            name = e.get("name") or key.rsplit("node_modules/", 1)[-1]
            out.append(_pkg("npm", name, e.get("version"), src, key_line.get(key),
                            direct=(key == "node_modules/" + name and name in roots),
                            via=chain(key) if key in parent else None,
                            scope="dev" if e.get("dev") else "prod"))
        return out

    def rec(deps, trail):  # lockfileVersion 1
        for name, e in (deps or {}).items():
            out.append(_pkg("npm", name, e.get("version"), src, None, direct=not trail,
                            via=trail + [name], scope="dev" if e.get("dev") else "prod"))
            rec(e.get("dependencies"), trail + [name])
    rec(data.get("dependencies"), [])
    return out


def parse_pnpm_lock(path, root):
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    direct = _manifest_direct(os.path.dirname(path))
    out, seen, section = [], set(), None
    for i, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith(" "):
            section = line.rstrip(":").strip()
            continue
        if section != "packages":
            continue
        m = re.match(r"^  ['\"]?(/?[^'\"\s]+?)['\"]?:\s*$", line)
        if not m:
            continue
        spec = m.group(1).lstrip("/").split("(", 1)[0]
        v5 = re.match(r"^((?:@[^/]+/)?[^/@]+)/(\d[^/]*)$", spec)  # pnpm v5: /name/1.2.3_peer@x
        if v5:
            name, ver = v5.group(1), v5.group(2)
        else:
            name, ver = _split_at_version(spec)
        if ver:
            ver = ver.split("_", 1)[0]
        if not name or not ver or (name, ver) in seen:
            continue
        seen.add((name, ver))
        out.append(_pkg("npm", name, ver, src, i, direct=name in direct or None,
                        scope=direct.get(name)))
    return out


def parse_yarn_lock(path, root):
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    direct = _manifest_direct(os.path.dirname(path))
    out, cur_name, cur_line, seen = [], None, None, set()
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            first = line.rstrip()[:-1].split(",")[0].strip().strip('"')
            if first.startswith("__metadata") or any(x in first for x in ("@workspace:", "@file:", "@link:", "@portal:")):
                cur_name = None
                continue
            if "@patch:" in first:  # "resolve@patch:resolve@npm%3A^1.20.0#..." → resolve
                first = first.split("@patch:", 1)[0] + "@patch"
            elif "@npm:" in first:  # alias "tl@npm:tensorlake@0.5.144" → tensorlake
                target = first.split("@npm:", 1)[1]
                tname, tver = _split_at_version(target)
                if tver and tname and not tname[0].isdigit() and tname[0] not in "^~<>=*":
                    first = target
            cur_name, _ = _split_at_version(first)
            cur_line = i
            continue
        if cur_name:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and (cur_name, m.group(1)) in seen:
                cur_name = None
            elif m:
                seen.add((cur_name, m.group(1)))
                out.append(_pkg("npm", cur_name, m.group(1), src, cur_line,
                                direct=cur_name in direct or None, scope=direct.get(cur_name)))
                cur_name = None
    return out


def parse_bun_lock(path, root):
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    stripped = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    stripped = re.sub(r",(\s*[}\]])", r"\1", stripped)
    try:
        data = json.loads(stripped)
    except ValueError:
        return []
    idx = _first_lines(text, r'"([^"]+@[^"]+)"')
    direct = _manifest_direct(os.path.dirname(path))
    out = []
    for val in (data.get("packages") or {}).values():
        if not isinstance(val, list) or not val or not isinstance(val[0], str):
            continue
        name, ver = _split_at_version(val[0])
        if not ver or ver.startswith(("workspace:", "file:", "link:")):
            continue
        line = idx.get(val[0])
        out.append(_pkg("npm", name, ver, src, line, direct=name in direct or None,
                        scope=direct.get(name)))
    return out


# ---------------------------------------------------------------- python family

def _pyproject_direct(dir_):
    text = _read(os.path.join(dir_, "pyproject.toml")) or ""
    names = set()
    m = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text)
    if m:
        names |= {normalize_name("PyPI", re.split(r"[\s<>=!~;\[]", s, 1)[0])
                  for s in re.findall(r"[\"']([^\"']+)[\"']", m.group(1))}
    m = re.search(r"(?ms)^\[tool\.poetry\.(?:dev-)?dependencies\]\s*(.*?)(?=^\[)", text + "\n[")
    if m:
        names |= {normalize_name("PyPI", k) for k in re.findall(r"(?m)^([A-Za-z0-9_.\-]+)\s*=", m.group(1))}
    names.discard("python")
    return names


def parse_requirements(path, root):
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*===?\s*([^\s;,]+)", line)
        if m:
            out.append(_pkg("PyPI", m.group(1), m.group(3), src, i, direct=True))
        else:
            m = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if m:
                out.append(_pkg("PyPI", m.group(1), None, src, i, direct=True))
    return out


def parse_pipfile_lock(path, root):
    text = _read(path)
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return []
    src = _rel(root, path)
    idx = _first_lines(text, r'^\s*"([^"]+)":\s*\{')
    out = []
    for section, scope in (("default", "prod"), ("develop", "dev")):
        for name, e in (data.get(section) or {}).items():
            ver = (e.get("version") or "").lstrip("=") or None
            line = idx.get(name)
            out.append(_pkg("PyPI", name, ver, src, line, scope=scope))
    return out


def parse_toml_packages(path, root, eco):
    """[[package]] blocks in poetry.lock, uv.lock, pdm.lock, Cargo.lock."""
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    blocks, cur, in_deps, in_poetry_deps = [], None, False, False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line == "[[package]]":
            cur = {"line": i, "deps": [], "root": False}
            blocks.append(cur)
            in_deps = in_poetry_deps = False
            continue
        if cur is None:
            continue
        if line.startswith("["):
            in_deps = False
            in_poetry_deps = line == "[package.dependencies]"
            if not line.startswith("[package"):
                cur = None
            continue
        if in_poetry_deps:
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*=", line)
            if m:
                cur["deps"].append(m.group(1))
            continue
        m = re.match(r'^(name|version)\s*=\s*"([^"]+)"', line)
        if m and m.group(1) not in cur:
            cur[m.group(1)] = m.group(2)
            if m.group(1) == "name":
                cur["line"] = i
            continue
        if re.match(r"^source\s*=\s*\{.*\b(editable|virtual|workspace)\b", line):
            cur["root"] = True
        if line.startswith("source"):
            cur["has_source"] = True
        if re.match(r"^dependencies\s*=\s*\[", line):
            in_deps = True
        if in_deps:
            cur["deps"] += re.findall(r'\{\s*name\s*=\s*"([^"]+)"', line)
            cur["deps"] += re.findall(r'^"([A-Za-z0-9_.\-]+)[ "]', line)  # Cargo style
            if line.endswith("]"):
                in_deps = False

    def norm(n):
        return normalize_name(eco, n)

    by_name = {norm(b["name"]): b for b in blocks if b.get("name")}
    roots = [b for b in blocks if b.get("root")]
    direct = set()
    for r in roots:
        direct |= {norm(d) for d in r["deps"]}
    if not roots and eco == "PyPI":
        direct = _pyproject_direct(os.path.dirname(path))
    parent = {}
    q = deque()
    for d in direct:
        if d in by_name and d not in parent:
            parent[d] = None
            q.append(d)
    while q:
        n = q.popleft()
        for d in by_name[n]["deps"]:
            d = norm(d)
            if d in by_name and d not in parent:
                parent[d] = n
                q.append(d)

    def chain(n):
        names = []
        while n and len(names) < MAX_CHAIN:
            names.append(by_name[n]["name"])
            n = parent.get(n)
        return list(reversed(names))

    out = []
    for b in blocks:
        if not b.get("name") or not b.get("version") or b.get("root"):
            continue
        if eco == "crates.io" and not b.get("has_source"):  # local workspace crate, not from crates.io
            continue
        n = norm(b["name"])
        out.append(_pkg(eco, b["name"], b["version"], src, b["line"],
                        direct=(n in direct) if direct else None,
                        via=chain(n) if n in parent else None))
    return out


# ---------------------------------------------------------------- other ecosystems

def parse_composer_lock(path, root):
    text = _read(path)
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return []
    src = _rel(root, path)
    idx = _first_lines(text, r'"name":\s*"([^"]+)"')
    cj = _read(os.path.join(os.path.dirname(path), "composer.json"))
    try:
        cjd = json.loads(cj) if cj else {}
    except ValueError:
        cjd = {}
    direct = set((cjd.get("require") or {})) | set((cjd.get("require-dev") or {}))
    out = []
    for section, scope in (("packages", "prod"), ("packages-dev", "dev")):
        for e in data.get(section) or []:
            name = e.get("name")
            line = idx.get(name)
            out.append(_pkg("Packagist", name, e.get("version"), src, line,
                            direct=name in direct, scope=scope))
    return out


def parse_go_mod(path, root):
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    out, in_block = [], False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if not (in_block or s.startswith("require ")):
            continue
        m = re.match(r"^(?:require\s+)?(\S+)\s+(v[\w.\-+]+)(.*)$", s)
        if m:
            out.append(_pkg("Go", m.group(1), m.group(2), src, i, direct="// indirect" not in m.group(3)))
    return out


def parse_gemfile_lock(path, root):
    text = _read(path)
    if not text:
        return []
    src = _rel(root, path)
    out, in_specs = [], False
    for i, line in enumerate(text.splitlines(), 1):
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
            if m:
                out.append(_pkg("RubyGems", m.group(1), m.group(2).split("-")[0], src, i))
    return out


LOCKFILES = {
    "package-lock.json": parse_npm_lock,
    "npm-shrinkwrap.json": parse_npm_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "bun.lock": parse_bun_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "poetry.lock": lambda p, r: parse_toml_packages(p, r, "PyPI"),
    "uv.lock": lambda p, r: parse_toml_packages(p, r, "PyPI"),
    "pdm.lock": lambda p, r: parse_toml_packages(p, r, "PyPI"),
    "Cargo.lock": lambda p, r: parse_toml_packages(p, r, "crates.io"),
    "composer.lock": parse_composer_lock,
    "go.mod": parse_go_mod,
    "Gemfile.lock": parse_gemfile_lock,
}


# ---------------------------------------------------------------- containers, CI, runtimes

def image_ref(ref):
    ref = ref.split("@", 1)[0]
    name, tag = ref, None
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
    for p in ("index.docker.io/library/", "docker.io/library/", "docker.io/", "library/"):
        if name.startswith(p):
            name = name[len(p):]
    return name.lower(), tag


def runtime_from_image(name, tag, src, line):
    """php:8.3.30-apache, wordpress:6.6-php8.2-apache, python:3.12-slim, node:22."""
    base = name.rsplit("/", 1)[-1]
    tag = tag or "latest"
    origin = "image %s:%s" % (name, tag)
    sapi = ("apache2handler (mod_php)" if "apache" in tag else
            "fpm" if "fpm" in tag else "cli" if "cli" in tag else None)
    lead = re.match(r"^(\d+(?:\.\d+){0,2})", tag)
    if base in ("php", "php-fpm", "php-apache"):
        return [{"name": "php", "version": lead.group(1) if lead else None, "sapi": sapi or "unknown",
                 "source": src, "line": line, "origin": origin}]
    if base in ("wordpress", "drupal", "joomla", "magento", "nextcloud", "matomo", "mediawiki"):
        m = re.search(r"php(\d+\.\d+)", tag)
        return [{"name": "php", "version": m.group(1) if m else None,
                 "sapi": sapi or "apache2handler (mod_php)", "source": src, "line": line,
                 "origin": origin}]
    if base in ("python", "node"):
        return [{"name": base, "version": lead.group(1) if lead else None, "source": src,
                 "line": line, "origin": origin}]
    return []


INI_KEYS = ("session.upload_progress.enabled", "memory_limit", "fatal_error_backtraces")


def parse_dockerfile(path, root):
    text = _read(path) or ""
    src = _rel(root, path)
    images, stages, runtimes, ini, args = [], set(), [], [], {}
    for i, line in enumerate(text.splitlines(), 1):
        am = re.match(r"^\s*ARG\s+(\w+)=['\"]?([^\s'\"]+)", line, re.I)
        if am:
            args[am.group(1)] = am.group(2)
        m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if m:
            ref = re.sub(r"\$\{?(\w+)(?::-([^}]*))?\}?", lambda v: args.get(v.group(1), v.group(2) or v.group(0)), m.group(1))
            if "$" in ref:  # unresolved build arg: keep it so the verdict becomes UNKNOWN, not CLEAR
                name, tag = image_ref(ref)
                if "$" not in name:
                    runtimes += [dict(rt, version=None) for rt in runtime_from_image(name, tag, src, i)]
                    images.append({"name": name, "tag": tag, "source": src, "line": i, "pinned": False, "unresolved": True})
            elif ref.lower() not in stages and ref.lower() != "scratch":
                name, tag = image_ref(ref)
                images.append({"name": name, "tag": tag, "source": src, "line": i,
                               "pinned": "@sha256:" in ref})
                runtimes += runtime_from_image(name, tag, src, i)
            if m.group(2):
                stages.add(m.group(2).lower())
        for k, v in re.findall(r"([a-z_]+\.[a-z_.]+|memory_limit)\s*=\s*([^\s'\"\\>;]+)", line):
            if k in INI_KEYS:
                ini.append({"key": k, "value": v, "source": src, "line": i})
    return images, runtimes, ini


def parse_compose(path, root):
    text = _read(path) or ""
    src = _rel(root, path)
    images, runtimes = [], []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*image:\s*['\"]?([^'\"\s#]+)", line)
        if m and "$" not in m.group(1):
            name, tag = image_ref(m.group(1))
            images.append({"name": name, "tag": tag, "source": src, "line": i,
                           "pinned": "@sha256:" in m.group(1)})
            runtimes += runtime_from_image(name, tag, src, i)
    return images, runtimes


def parse_workflow(path, root):
    text = _read(path) or ""
    src = _rel(root, path)
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", line)
        if not m or m.group(1).startswith(("./", "docker://")):
            continue
        name, _, ver = m.group(1).partition("@")
        out.append({"name": "/".join(name.split("/")[:2]), "path": name, "ref": ver or None,
                    "source": src, "line": i,
                    "pinned": bool(re.fullmatch(r"[0-9a-f]{40}", ver or ""))})
    return out


def parse_php_ini(path, root):
    text = _read(path) or ""
    src = _rel(root, path)
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(session\.upload_progress\.enabled|memory_limit|fatal_error_backtraces)\s*=\s*\"?([^\s;\"]+)", line)
        if m:
            out.append({"key": m.group(1), "value": m.group(2), "source": src, "line": i})
    return out


def which_safe(name):
    """Resolve an executable from PATH only, never from the current directory (Windows searches
    cwd first, and the scanned project must never be able to plant php.exe / python.exe)."""
    cwd = os.path.realpath(os.getcwd())
    exts = os.environ.get("PATHEXT", ".EXE;.CMD;.BAT").split(";") if os.name == "nt" else [""]
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or d == "." or os.path.realpath(d) == cwd:
            continue
        for ext in exts:
            cand = os.path.join(d, name + ext)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def run(cmd, timeout=6):
    """Run a read-only probe. Absolute executable, neutral cwd: nothing in the scanned
    project (json.py, php.ini, .exe files) can be picked up."""
    exe = which_safe(cmd[0])
    if not exe:
        return None
    try:
        r = subprocess.run([exe] + list(cmd[1:]), capture_output=True, text=True, timeout=timeout,
                           cwd=tempfile.gettempdir(), stdin=subprocess.DEVNULL)
        return (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return None


def local_runtimes():
    rts, ini = [], []
    out = run(["php", "-r", 'echo PHP_VERSION, "|", ini_get("session.upload_progress.enabled"), "|", '
                            'ini_get("memory_limit"), "|", ini_get("fatal_error_backtraces");'])
    if out and "|" in out:
        parts = out.strip().splitlines()[-1].split("|")
        rts.append({"name": "php", "version": parts[0], "sapi": "cli (this machine)",
                    "source": "php on PATH", "line": None, "origin": "local"})
        for k, v in zip(INI_KEYS, parts[1:]):
            ini.append({"key": k, "value": v or "0", "source": "php on PATH (CLI ini)", "line": None})
    for exe, name in (("python3", "python"), ("node", "node")):
        m = re.search(r"(\d+\.\d+\.\d+)", run([exe, "--version"]) or "")
        if m:
            rts.append({"name": name, "version": m.group(1), "source": "%s on PATH" % exe,
                        "line": None, "origin": "local"})
    return rts, ini


def local_docker_images():
    out = run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"], timeout=8)
    imgs = []
    for line in (out or "").splitlines():
        line = line.strip()
        if re.match(r"^[\w./-]+:[\w.-]+$", line) and "<none>" not in line:
            name, tag = image_ref(line)
            imgs.append({"name": name, "tag": tag, "source": "local docker images", "line": None,
                         "pinned": False})
    return imgs


# ---------------------------------------------------------------- installed python envs

def site_packages_dirs(project=None, host=True):
    dirs, pats = [], []
    if project:
        for v in (".venv", "venv", "env", ".env"):
            pats += [os.path.join(project, v, "lib", "python*", "site-packages"),
                     os.path.join(project, v, "Lib", "site-packages")]
    if host:
        home = os.path.expanduser("~")
        pats += [os.path.join(home, ".local", "share", "uv", "tools", "*", "lib", "python*", "site-packages"),
                 os.path.join(home, ".local", "pipx", "venvs", "*", "lib", "python*", "site-packages"),
                 os.path.join(home, ".local", "share", "pipx", "venvs", "*", "lib", "python*", "site-packages"),
                 os.path.join(home, ".local", "lib", "python*", "site-packages"),
                 os.path.join(home, "Library", "Python", "*", "lib", "python", "site-packages"),
                 os.path.join(home, "AppData", "Roaming", "Python", "Python*", "site-packages")]
        for exe in ("python3", "python"):
            out = run([exe, "-I", "-S", "-c", "import site,json;print(json.dumps(site.getsitepackages()+[site.getusersitepackages()]))"])
            try:
                dirs += [d for d in json.loads((out or "[]").strip().splitlines()[-1]) if os.path.isdir(d)]
            except (ValueError, IndexError):
                pass
    for p in pats:
        dirs += [d for d in glob.glob(p) if os.path.isdir(d)]
    seen, uniq = set(), []
    for d in dirs:
        rd = os.path.realpath(d)
        if rd not in seen:
            seen.add(rd)
            uniq.append(d)
    return uniq


def installed_python(sp_dir, label):
    out = []
    for di in glob.glob(os.path.join(sp_dir, "*.dist-info")):
        name, _, ver = os.path.basename(di)[: -len(".dist-info")].partition("-")
        if name and ver:
            out.append(_pkg("PyPI", name, ver, label, None, scope="installed"))
    return out


# ---------------------------------------------------------------- entry point

UNSUPPORTED = {"pom.xml", "build.gradle", "build.gradle.kts", "pubspec.yaml", "Package.swift", "mix.exs",
               "packages.config", "deps.edn", "project.clj", "cpanfile", "rebar.config"}


_EXACT = set(LOCKFILES) | {"bun.lockb", "package.json", "pyproject.toml", "composer.json", "Pipfile",
                           "Containerfile", "php.ini", ".user.ini", ".php-version", ".python-version",
                           ".nvmrc", ".node-version", "constraints.txt"} | UNSUPPORTED


def _interesting(fn):
    return (fn in _EXACT or fn.startswith("Dockerfile") or fn.endswith((".Dockerfile", ".csproj", ".fsproj", ".ini",
            ".yml", ".yaml")) or (fn.endswith(".txt") and "requirements" in fn))


def _nonempty(path):
    try:
        return os.path.getsize(path) > 2
    except OSError:
        return False


def manifest_names(path, root):
    """Dependency names declared in a manifest that has no lockfile (versions unknown)."""
    fn, src = os.path.basename(path), _rel(root, path)
    text = _read(path) or ""
    out = []
    try:
        if fn == "package.json":
            names = _manifest_direct(os.path.dirname(path))
            out = [("npm", n) for n in names]
        elif fn == "composer.json":
            d = json.loads(text)
            out = [("Packagist", n) for n in list(d.get("require") or {}) + list(d.get("require-dev") or {}) if "/" in n]
        elif fn in ("pyproject.toml", "Pipfile"):
            out = [("PyPI", n) for n in _pyproject_direct(os.path.dirname(path))] if fn == "pyproject.toml" else \
                  [("PyPI", n) for n in re.findall(r"(?m)^([A-Za-z0-9_.\-]+)\s*=", text)]
    except (ValueError, AttributeError):
        pass
    return [{"ecosystem": e, "name": n, "source": src} for e, n in out]


def build(root, include_host=True):
    root = os.path.abspath(root)
    ignore = _ignore_patterns(root)
    inv = {"root": root, "packages": [], "images": [], "runtimes": [], "actions": [], "ini": [],
           "files": [], "notes": [], "manifests_without_lock": [], "host_packages": [],
           "site_packages": [], "manifest_packages": [], "unsupported": []}
    have_lock_dirs, manifests = set(), []
    for path in walk(root, ignore, inv["notes"]):
        fn = os.path.basename(path)
        if not _interesting(fn):  # cheap name check first: most files are never touched
            continue
        rel = _rel(root, path)
        norm = path.replace(os.sep, "/")
        parser = LOCKFILES.get(fn)
        if parser:
            try:
                got = parser(path, root)
            except Exception as e:  # a hostile/odd lockfile must not abort the scan
                got = []
                inv["notes"].append("%s could not be parsed (%s)" % (rel, type(e).__name__))
            if not got and _nonempty(path):
                inv["notes"].append("%s could not be parsed or is too large — its dependencies were NOT checked" % rel)
            inv["packages"] += got
            inv["files"].append(rel)
            have_lock_dirs.add(os.path.dirname(path))
        elif fnmatch.fnmatch(fn, "*requirements*.txt") or fn == "constraints.txt":
            inv["packages"] += parse_requirements(path, root)
            inv["files"].append(rel)
            have_lock_dirs.add(os.path.dirname(path))
        elif fn == "bun.lockb":
            inv["notes"].append("%s is binary; run `bun install --save-text-lockfile` for full coverage" % rel)
        elif fn in ("package.json", "pyproject.toml", "composer.json", "Pipfile"):
            manifests.append(path)
        elif fn in UNSUPPORTED or fn.endswith((".csproj", ".fsproj")):
            inv["unsupported"].append(rel)
        elif fn.startswith("Dockerfile") or fn.endswith(".Dockerfile") or fn == "Containerfile":
            imgs, rts, ini = parse_dockerfile(path, root)
            inv["images"] += imgs
            inv["runtimes"] += rts
            inv["ini"] += ini
            inv["files"].append(rel)
        elif re.match(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$", fn):
            imgs, rts = parse_compose(path, root)
            inv["images"] += imgs
            inv["runtimes"] += rts
            inv["files"].append(rel)
        elif fn.endswith((".yml", ".yaml")) and "/.github/workflows/" in norm:
            inv["actions"] += parse_workflow(path, root)
            inv["files"].append(rel)
        elif fn in ("php.ini", ".user.ini") or (fn.endswith(".ini") and (
                "php" in fn.lower() or re.search(r"(^|/)(php[\w.-]*|conf\.d)/", rel.replace(os.sep, "/").lower()))):
            inv["ini"] += parse_php_ini(path, root)
        elif fn in (".php-version", ".python-version", ".nvmrc", ".node-version"):
            v = (_read(path) or "").strip().splitlines()
            name = "php" if "php" in fn else "python" if "python" in fn else "node"
            if v and re.match(r"^v?\d", v[0]):
                inv["runtimes"].append({"name": name, "version": v[0].lstrip("v"), "source": rel,
                                        "line": 1, "origin": "version file"})
    hidden = os.path.join(root, "node_modules", ".package-lock.json")
    if os.path.exists(hidden):  # what is installed right now
        for p in parse_npm_lock(hidden, root):
            p["scope"] = "installed"
            inv["packages"].append(p)
    for m in manifests:
        if os.path.dirname(m) not in have_lock_dirs:
            inv["manifests_without_lock"].append(_rel(root, m))
            inv["manifest_packages"] += manifest_names(m, root)
    for d in site_packages_dirs(root, host=False):
        inv["site_packages"].append(d)
        inv["packages"] += installed_python(d, _rel(root, d))
    cj = _read(os.path.join(root, "composer.json"))
    if cj:
        try:
            plat = ((json.loads(cj).get("config") or {}).get("platform") or {}).get("php")
            if plat:
                inv["runtimes"].append({"name": "php", "version": plat, "source": "composer.json",
                                        "line": None, "origin": "composer platform"})
        except ValueError:
            pass
    if include_host:
        rts, ini = local_runtimes()
        inv["runtimes"] += rts
        inv["ini"] += ini
        inv["images"] += local_docker_images()
        for d in site_packages_dirs(None, host=True):
            inv["site_packages"].append(d)
            inv["host_packages"] += installed_python(d, d)
    return inv


def summary(inv):
    ecos = {}
    for p in inv["packages"]:
        ecos[p["ecosystem"]] = ecos.get(p["ecosystem"], 0) + 1
    return ecos
