"""Live threat intel: OSV.dev (incl. MAL- malicious packages), CISA KEV, FIRST EPSS,
and zero-hour incident cards. Python stdlib only. Never sends anything except
package names + versions (to OSV) and CVE ids (to EPSS).
"""
import concurrent.futures as cf
import datetime as dt
import glob
import hashlib
import json
import os
import re
import urllib.error
import urllib.request

UA = "zero-hour/0.1 (+https://github.com/akshitkhokhani/zero-hour)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/%s"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve=%s"
CARDS_BASE = "https://raw.githubusercontent.com/akshitkhokhani/zero-hour/main/incidents/"
OSV_ECOSYSTEMS = {"npm", "PyPI", "Packagist", "Go", "crates.io", "RubyGems", "Maven", "NuGet",
                  "GitHub Actions"}
TTL = 3600
HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLED_CARDS = os.path.join(os.path.dirname(HERE), "incidents")


def cache_dir():
    if os.environ.get("ZERO_HOUR_CACHE"):
        d = os.environ["ZERO_HOUR_CACHE"]
    else:
        base = os.environ.get("XDG_CACHE_HOME") or \
            (os.environ.get("LOCALAPPDATA") if os.name == "nt" else None) or \
            os.path.join(os.path.expanduser("~"), ".cache")
        d = os.path.join(base, "zero-hour")
    os.makedirs(d, exist_ok=True)
    return d


def prune_cache(max_age_days=3):
    """Keep the cache small: drop intel responses older than a few days (cards are kept)."""
    d, cutoff = cache_dir(), dt.datetime.now().timestamp() - max_age_days * 86400
    try:
        for e in os.scandir(d):
            if e.is_file() and e.name.endswith(".json") and e.stat().st_mtime < cutoff:
                os.remove(e.path)
    except OSError:
        pass


class Net:
    def __init__(self, offline=False, ttl=TTL):
        prune_cache()
        self.offline = offline
        self.ttl = ttl
        self.status = {}  # source -> "ok" | "cached" | "stale cache" | "error: ..." | "offline (no cache)"

    def _cache_path(self, key):
        return os.path.join(cache_dir(), hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")

    def _load(self, cp):
        try:
            with open(cp, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def get_json(self, url, source, body=None, ttl=None, headers=None, with_next=False):
        """GET/POST JSON with a disk cache. with_next=True returns (data, next_url) from the Link header."""
        key = url + (json.dumps(body, sort_keys=True) if body is not None else "")
        cp = self._cache_path(key)
        ttl = self.ttl if ttl is None else ttl
        exists = os.path.exists(cp)
        fresh = exists and (dt.datetime.now().timestamp() - os.path.getmtime(cp) < ttl)
        def done(stored):
            if not with_next:
                return stored
            if isinstance(stored, dict) and "__data" in stored:
                return stored["__data"], stored.get("__next")
            return stored, None

        if fresh or (self.offline and exists):
            data = self._load(cp)
            if data is not None:
                self.status.setdefault(source, "cached" if self.offline else "ok")
                return done(data)
        if self.offline:
            self.status[source] = "offline (no cache)"
            return done(None)
        payload = json.dumps(body).encode() if body is not None else None
        hdrs = {"User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json"}
        hdrs.update(headers or {})
        req = urllib.request.Request(url, data=payload, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                data = json.loads(r.read().decode("utf-8"))
                m = re.search(r'<([^>]+)>;\s*rel="next"', r.headers.get("Link") or "")
                if with_next:
                    data = {"__data": data, "__next": m.group(1) if m else None}
        except (urllib.error.URLError, OSError, ValueError) as e:
            stale = self._load(cp) if exists else None
            if stale is not None:
                self.status[source] = "stale cache (%s)" % type(e).__name__
                return done(stale)
            self.status[source] = "error: %s" % (getattr(e, "reason", None) or e)
            return done(None)
        try:
            with open(cp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except OSError:
            pass
        self.status.setdefault(source, "ok")
        return done(data)


# ---------------------------------------------------------------- OSV

def osv_scan(net, packages, max_vulns=800):
    """{(eco, name, version): [vuln dicts]} for packages with a resolved version.
    Returns None when OSV is unreachable, so callers can report UNKNOWN instead of CLEAR."""
    keys, seen = [], set()
    for p in packages:
        if p["ecosystem"] not in OSV_ECOSYSTEMS or not p.get("version"):
            continue
        k = (p["ecosystem"], p["name"], p["version"])
        if k not in seen:
            seen.add(k)
            keys.append(k)
    hits = {}
    for i in range(0, len(keys), 1000):
        chunk = keys[i:i + 1000]
        body = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        res = net.get_json(OSV_BATCH, "osv", body=body)
        if res is None:
            return None
        for k, r in zip(chunk, res.get("results", [])):
            ids = [v["id"] for v in (r.get("vulns") or [])]
            if ids:
                hits[k] = ids
    # Malicious-package records first; never drop an id silently. Ids without details become
    # minimal stubs so the package still shows up (and MAL- still ranks as malicious).
    all_ids = sorted({i for ids in hits.values() for i in ids}, key=lambda i: (not i.startswith("MAL-"), i))
    details = {}
    with cf.ThreadPoolExecutor(max_workers=6) as ex:  # I/O-bound; small pool keeps CPU/RAM low
        fetch = all_ids[:max_vulns]
        for vid, data in zip(fetch, ex.map(lambda v: net.get_json(OSV_VULN % v, "osv", ttl=6 * TTL), fetch)):
            if data:
                details[vid] = data
    stub = lambda i: {"id": i, "aliases": [], "summary": "details not fetched — see https://osv.dev/vulnerability/" + i}
    return {k: [details.get(i) or stub(i) for i in ids] for k, ids in hits.items()}


# ---------------------------------------------------------------- KEV + EPSS

def kev(net):
    data = net.get_json(KEV_URL, "cisa-kev")
    if not data:
        return {}
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def kev_recent(kev_map, days=7):
    cutoff = (dt.date.today() - dt.timedelta(days=days)).isoformat()
    return sorted((v for v in kev_map.values() if v.get("dateAdded", "") >= cutoff),
                  key=lambda v: v.get("dateAdded", ""), reverse=True)


def epss(net, cves):
    cves = sorted({c for c in cves if c and c.startswith("CVE-")})
    out = {}
    for i in range(0, len(cves), 80):
        data = net.get_json(EPSS_URL % ",".join(cves[i:i + 80]), "first-epss")
        for row in (data or {}).get("data", []):
            try:
                out[row["cve"]] = float(row.get("epss", 0))
            except (TypeError, ValueError):
                pass
    return out


# ---------------------------------------------------------------- incident cards

REQUIRED = ("id", "title", "published", "summary", "sources", "affected", "remediation")


def _strs(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def validate_card(card):
    """Structural + type checks, so a bad card (remote, agent-written or --card) can never crash a scan."""
    if not isinstance(card, dict):
        return ["card must be a JSON object"]
    errs = ["missing '%s'" % k for k in REQUIRED if k not in card]
    for k in ("id", "title", "summary", "published"):
        if k in card and not isinstance(card[k], str):
            errs.append("'%s' must be a string" % k)
    if isinstance(card.get("id"), str) and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,120}", card["id"]):
        errs.append("id may only use letters, digits and . _ : + -")
    for k in ("cves", "aliases"):
        if k in card and not _strs(card[k]):
            errs.append("'%s' must be a list of strings" % k)
    if not isinstance(card.get("affected"), list) or not all(isinstance(a, dict) for a in card.get("affected") or []):
        errs.append("affected must be a list of objects")
    else:
        for i, a in enumerate(card["affected"]):
            if not isinstance(a.get("ecosystem"), str) or not isinstance(a.get("name"), str):
                errs.append("affected[%d] ecosystem/name must be strings" % i)
            for k in ("versions", "tag_contains"):
                if k in a and not _strs(a[k]):
                    errs.append("affected[%d].%s must be a list of strings" % (i, k))
            if "ranges" in a and not (isinstance(a["ranges"], list) and all(
                    isinstance(r, dict) and all(isinstance(v, (str, bool)) for v in r.values()) for r in a["ranges"])):
                errs.append("affected[%d].ranges must be a list of objects with string values" % i)
    if not isinstance(card.get("remediation"), list):
        errs.append("remediation must be a list")
    else:
        for i, st in enumerate(card["remediation"]):
            if not isinstance(st, dict):
                continue
            cmds = st.get("commands", {})
            if not (isinstance(cmds, dict) and all(_strs(v) for v in cmds.values())):
                errs.append("remediation[%d].commands must map os -> list of strings" % i)
            for k in ("step", "why", "danger", "when"):
                if k in st and st[k] is not None and not isinstance(st[k], str):
                    errs.append("remediation[%d].%s must be a string" % (i, k))
    iocs = card.get("iocs", {})
    if not isinstance(iocs, dict):
        errs.append("iocs must be an object")
    else:
        for k in ("files", "git", "github_repos"):
            if k in iocs and not (isinstance(iocs[k], list) and all(isinstance(x, dict) for x in iocs[k])):
                errs.append("iocs.%s must be a list of objects" % k)
        for k in ("network", "strings"):
            if k in iocs and not _strs(iocs[k]):
                errs.append("iocs.%s must be a list of strings" % k)
    if not isinstance(card.get("preconditions", []), list):
        errs.append("preconditions must be a list")
    if not isinstance(card.get("sources"), list) or not card.get("sources"):
        errs.append("sources must be a non-empty list")
    for i, a in enumerate(card.get("affected") or []):
        if "ecosystem" not in a or "name" not in a:
            errs.append("affected[%d] needs ecosystem + name" % i)
        if not any(k in a for k in ("versions", "ranges", "tag_contains", "any_version")):
            errs.append("affected[%d] needs versions, ranges, tag_contains or any_version" % i)
    for i, s in enumerate(card.get("remediation") or []):
        if not isinstance(s, dict) or "step" not in s:
            errs.append("remediation[%d] needs 'step'" % i)
    try:
        dt.date.fromisoformat(str(card.get("published", ""))[:10])
    except ValueError:
        errs.append("published must be YYYY-MM-DD")
    return errs


def user_cards_dir():
    d = os.path.join(cache_dir(), "cards")
    os.makedirs(d, exist_ok=True)
    return d


def read_card(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _stamp(c):
    return str(c.get("updated") or c.get("published"))


def load_cards(net, extra_paths=(), remote=True):
    """Bundled cards, then live cards from GitHub, then agent-written cards, then --card files.
    Same id: the most recently updated wins."""
    cards = {}

    def put(card, origin):
        if not isinstance(card, dict) or validate_card(card):
            return False
        old = cards.get(card["id"])
        # a remote card may only replace a bundled one when it is strictly newer
        newer = _stamp(card) > _stamp(old) if old and origin.startswith("live") else True
        if not old or (newer and _stamp(card) >= _stamp(old)):
            cards[card["id"]] = dict(card, _origin=origin)
        return True

    for p in sorted(glob.glob(os.path.join(BUNDLED_CARDS, "*.json"))):
        if os.path.basename(p) != "index.json":
            try:
                put(read_card(p), "bundled")
            except (OSError, ValueError):
                pass
    if remote and not net.offline:
        idx = net.get_json(CARDS_BASE + "index.json", "zero-hour-cards")
        for entry in (idx or {}).get("cards", []):
            fn = str(entry.get("file", ""))
            if fn.endswith(".json") and "/" not in fn and ".." not in fn:
                put(net.get_json(CARDS_BASE + fn, "zero-hour-cards"), "live (github)")
    for p in sorted(glob.glob(os.path.join(user_cards_dir(), "*.json"))):
        try:
            put(read_card(p), "local (agent research)")
        except (OSError, ValueError):
            pass
    for p in extra_paths:
        card = read_card(p)
        errs = validate_card(card)
        if errs:
            raise ValueError("invalid card %s: %s" % (p, "; ".join(errs)))
        put(card, "--card")
    return sorted(cards.values(), key=_stamp, reverse=True)


# ---------------------------------------------------------------- live advisory feed (no hardcoding)
# Every run pulls what was published in the last N days and turns it into incident cards,
# so brand-new malware and critical advisories are matched against the project automatically.

GHSA_URL = "https://api.github.com/advisories?type=%s&per_page=100&sort=published&direction=desc&published=%%3E%%3D%s"
GH_ECO = {"npm": "npm", "pip": "PyPI", "composer": "Packagist", "go": "Go", "rust": "crates.io",
          "rubygems": "RubyGems", "maven": "Maven", "nuget": "NuGet", "actions": "GitHub Actions",
          "pub": "Pub", "swift": "SwiftURL", "erlang": "Hex"}


def parse_gh_range(text):
    versions, rng = [], {}
    for part in (text or "").split(","):
        m = re.match(r"^\s*(>=|<=|>|<|=)?\s*(\S+)\s*$", part)
        if not m:
            continue
        op, v = m.group(1) or "=", m.group(2)
        if op == "=":
            versions.append(v)
        elif op == ">=":
            rng["introduced"] = v
        elif op == ">":
            rng["introduced"] = v
            rng["introduced_exclusive"] = True
        elif op == "<":
            rng["fixed"] = v
        elif op == "<=":
            rng["last_affected"] = v
    if rng and "introduced" not in rng:
        rng["introduced"] = "0"
    return versions, ([rng] if rng else [])


def ghsa_to_card(a):
    malware = a.get("type") == "malware"
    affected = []
    for v in a.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        eco = GH_ECO.get(pkg.get("ecosystem"))
        if not eco or not pkg.get("name"):
            continue
        versions, ranges = parse_gh_range(v.get("vulnerable_version_range"))
        entry = {"ecosystem": eco, "name": pkg["name"]}
        if versions:
            entry["versions"] = versions
        if ranges:
            entry["ranges"] = ranges
        if not versions and not ranges:
            entry["any_version"] = True
        if v.get("first_patched_version"):
            entry["safe"] = v["first_patched_version"]
        affected.append(entry)
    if not affected:
        return None
    names = ", ".join(sorted({"%s (%s)" % (x["name"], x["ecosystem"]) for x in affected}))
    # Facts and ordering constraints only; the agent builds the concrete fix for the user's setup.
    if malware:
        remediation = [
            {"step": "Contain: stop processes from this project/env; keep new secrets off this machine", "when": "affected"},
            {"step": "Check for persistence and dead-man switches", "when": "affected",
             "danger": "Some worms wipe your home directory when their stolen token is revoked — check before revoking anything."},
            {"step": "Remove %s and reinstall dependencies cleanly with install scripts disabled" % names, "when": "affected"},
            {"step": "Rotate every credential this machine could read, from a clean machine", "when": "affected"},
            {"step": "Hunt for spread (your published packages, repos, CI) and harden installs", "when": "affected"},
        ]
    else:
        fixes = ", ".join("%s → %s" % (x["name"], x["safe"]) for x in affected if x.get("safe")) or \
            "no patched version yet — apply the advisory's workaround"
        remediation = [{"step": "Upgrade: %s" % fixes, "when": "affected"},
                       {"step": "Check whether the vulnerable code path is reachable in your app (advisory details)", "when": "affected"}]
    ids = [i.get("value") for i in a.get("identifiers") or [] if i.get("value")]
    return {"id": a["ghsa_id"], "title": (("MALWARE: " if malware else "") + (a.get("summary") or a["ghsa_id"]))[:120],
            "kind": "malware" if malware else "vulnerability",
            "published": (a.get("published_at") or "")[:10], "updated": (a.get("updated_at") or a.get("published_at") or "")[:10],
            "severity": a.get("severity"), "summary": a.get("summary") or "", "exploited": False,
            "cves": [a["cve_id"]] if a.get("cve_id") else [], "aliases": ids,
            "sources": [{"name": "GitHub Advisory Database", "url": a.get("html_url") or ""}],
            "affected": affected, "remediation": remediation, "live": True}


def live_advisories(net, days=7, max_pages=5):
    """Malware + high/critical reviewed advisories published in the last `days`, as cards."""
    since = (dt.date.today() - dt.timedelta(days=days)).isoformat()
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    hdrs = {"Accept": "application/vnd.github+json"}
    if tok:
        hdrs["Authorization"] = "Bearer " + tok
    cards, seen = [], set()
    for kind in ("malware", "reviewed"):
        url = GHSA_URL % (kind, since)
        for _ in range(max_pages):  # cursor pagination via the Link header
            data, url = net.get_json(url, "github-advisories", headers=hdrs, with_next=True)
            if not isinstance(data, list) or not data:
                break
            for a in data:
                if a.get("withdrawn_at") or a.get("ghsa_id") in seen:
                    continue
                seen.add(a.get("ghsa_id"))
                if kind == "reviewed" and a.get("severity") not in ("critical", "high"):
                    continue
                c = ghsa_to_card(a)
                if c:
                    c["_origin"] = "live (GitHub Advisory DB)"
                    cards.append(c)
            if not url:
                break
    return cards


def kev_live_cards(kev_map, inv, days=14):
    """CISA KEV entries added recently whose product matches something this project runs.
    KEV has no version data, so these become EXPOSED with a 'verify version' note."""
    names = {r["name"].lower() for r in inv.get("runtimes", [])}
    names |= {i["name"].rsplit("/", 1)[-1].lower() for i in inv.get("images", [])}
    names |= {p["name"].lower() for p in inv.get("packages", []) if len(p["name"]) >= 4}
    out = []
    for v in kev_recent(kev_map, days):
        prod = (v.get("product") or "").lower().strip()
        if prod and prod in names:
            out.append(v)
    return out
