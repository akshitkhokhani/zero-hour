"""Version parsing and range matching. Python stdlib only.

Good enough ordering for semver (npm, Cargo, Go), PEP 440 (PyPI), Composer and
runtime versions such as PHP. Not a full implementation of any one of them.
"""
import re

_NUM = re.compile(r"^(\d+(?:\.\d+)*)(.*)$")
_TOK = re.compile(r"\d+|[a-z]+")
_PRE = {"dev": -40, "alpha": -30, "a": -30, "beta": -20, "b": -20,
        "pre": -10, "preview": -10, "c": -10, "rc": -10}
_POST = {"post", "p", "r", "rev", "patch", "pl"}


def normalize_name(ecosystem, name):
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("npm", "Packagist", "Docker", "runtime", "GitHub Actions"):
        return name.lower()
    return name


def clean(version):
    if version is None:
        return None
    v = str(version).strip().lstrip("=vV ")
    return v.split("+", 1)[0] or None


def vkey(version):
    """Sortable key. Pre-release < release < post-release."""
    v = clean(version) or "0"
    epoch = 0
    if "!" in v:  # PEP 440 epoch
        e, v = v.split("!", 1)
        epoch = int(e) if e.isdigit() else 0
    m = _NUM.match(v)
    if not m:
        return (epoch, (0,), (0,) + tuple(_PRE.get(t, -1) if not t.isdigit() else int(t)
                                          for t in _TOK.findall(v.lower())))
    nums = [int(x) for x in m.group(1).split(".")]
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    rest = m.group(2).lower().lstrip(".-_")
    if not rest:
        return (epoch, tuple(nums), (1,))
    toks = _TOK.findall(rest)
    if toks and toks[0] in _POST:
        return (epoch, tuple(nums), (2,) + tuple(int(t) if t.isdigit() else 0 for t in toks[1:]))
    return (epoch, tuple(nums), (0,) + tuple(int(t) if t.isdigit() else _PRE.get(t, -1) for t in toks))


def cmp(a, b):
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def in_range(version, rng):
    """rng: {"introduced": x, "fixed": y} | {"introduced": x, "last_affected": y} |
    {"introduced": x, "limit": y}. A missing introduced means "0"."""
    intro = rng.get("introduced") or "0"
    if intro != "0" and cmp(version, intro) < 0:
        return False
    if rng.get("introduced_exclusive") and cmp(version, intro) == 0:
        return False
    if rng.get("fixed"):
        return cmp(version, rng["fixed"]) < 0
    if rng.get("limit"):
        return cmp(version, rng["limit"]) < 0
    if rng.get("last_affected"):
        return cmp(version, rng["last_affected"]) <= 0
    return True


def osv_ranges(affected_entry):
    """Flatten OSV affected[].ranges[].events into [{introduced, fixed|last_affected}]."""
    out = []
    for r in affected_entry.get("ranges", []) or []:
        if r.get("type") == "GIT":
            continue
        cur = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                if cur:
                    out.append(cur)
                cur = {"introduced": ev["introduced"]}
            elif cur is not None and ("fixed" in ev or "last_affected" in ev or "limit" in ev):
                cur.update(ev)
                out.append(cur)
                cur = None
        if cur:
            out.append(cur)
    return out


def fixed_version_for(version, osv_vuln, ecosystem, name):
    """Smallest fixed version above `version` for this package, or None."""
    want = normalize_name(ecosystem, name)
    best = None
    for aff in osv_vuln.get("affected", []) or []:
        pkg = aff.get("package") or {}
        if normalize_name(pkg.get("ecosystem", ""), pkg.get("name", "")) != want:
            continue
        for rng in osv_ranges(aff):
            fixed = rng.get("fixed")
            if fixed and in_range(version, rng):
                if best is None or cmp(fixed, best) < 0:
                    best = fixed
    return best


def looks_distro_build(version):
    """True for distro builds like 8.1.2-1ubuntu2.18 or 8.2.7-1.el9, which may carry backports."""
    return bool(re.search(r"(ubuntu|deb\d*u|\.el\d|\+deb|-\d+\.fc\d+|~)", str(version)))
