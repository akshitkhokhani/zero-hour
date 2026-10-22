#!/usr/bin/env python3
"""zero-hour: is today's security incident in my project, and what do I do right now?

Usage:
  zerohour.py scan [PATH] [--days N] [--deep] [--incident Q] [--format md|json|sarif] [--out FILE]
                         [--card FILE]... [--offline] [--no-remote-cards] [--no-host] [--github] [--all]
  zerohour.py pulse [--days N] [--format md|json]
  zerohour.py inventory [PATH] [--no-host]
  zerohour.py card template | card validate FILE | card add FILE

Exit codes: 0 nothing affected · 2 affected/compromised found · 3 error.
Python 3.9+ standard library only. Read-only: it never modifies your project or machine.
"""
import argparse
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import zh_hunt  # noqa: E402
import zh_intel  # noqa: E402
import zh_inventory  # noqa: E402
import zh_report  # noqa: E402
from zh_versions import normalize_name  # noqa: E402

CARD_TEMPLATE = {
    "id": "YYYY-MM-DD-short-name",
    "title": "What happened, in under 80 characters",
    "kind": "supply-chain-compromise",
    "published": "YYYY-MM-DD",
    "updated": "YYYY-MM-DD",
    "severity": "critical",
    "exploited": True,
    "summary": "One plain-English sentence: what, who is hit, why it matters.",
    "cves": [],
    "sources": [{"name": "Primary source (vendor / researcher)", "url": "https://..."}],
    "affected": [
        {"ecosystem": "npm | PyPI | Packagist | Go | crates.io | RubyGems | Maven | NuGet | Docker | runtime",
         "name": "package-or-image-or-runtime", "versions": ["1.2.3"], "safe": "1.2.2"}
    ],
    "preconditions": [],
    "iocs": {"files": [{"path": "{site-packages}/evil.pth", "contains": "import evil", "level": "compromised",
                        "meaning": "why this proves infection"}],
             "git": [], "github_repos": [], "network": [], "strings": []},
    "remediation": [
        {"step": "Contain", "when": "compromised", "why": "...", "commands": {"any": []}},
        {"step": "Check for persistence / dead-man switches", "when": "compromised", "danger": "before revoking tokens"},
        {"step": "Rotate credentials from a clean machine", "when": "compromised"},
        {"step": "Upgrade / pin to the safe version", "when": "affected"},
    ],
}


def _emit(text, out):
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print("wrote %s" % out, file=sys.stderr)
    else:
        try:
            sys.stdout.write(text)
        except UnicodeEncodeError:  # legacy Windows consoles
            sys.stdout.write(text.encode("ascii", "replace").decode())


def _relevant_live(cards, inv):
    """Malware is matched against the project AND this machine (an install anywhere means the
    machine is compromised); ordinary vulnerabilities only against the project's dependencies."""
    proj = {(p["ecosystem"], normalize_name(p["ecosystem"], p["name"])) for p in inv["packages"]}
    host = proj | {(p["ecosystem"], normalize_name(p["ecosystem"], p["name"])) for p in inv.get("host_packages", [])}
    out = []
    for c in cards:
        have = host if c.get("kind") == "malware" else proj
        if any((a["ecosystem"], normalize_name(a["ecosystem"], a["name"])) in have for a in c["affected"]):
            out.append(c)
    return out


def _group_live_vulns(results, cards_by_id, days):
    """Many fresh advisories for one package → one line with the highest safe version."""
    from zh_versions import cmp
    groups, out = {}, []
    for r in results:
        c = cards_by_id.get(r["id"])
        if not c or not c.get("live") or c.get("kind") == "malware":
            out.append(r)
            continue
        key = tuple(sorted({a["name"] for a in c["affected"]}))
        groups.setdefault(key, []).append((r, c))
    for key, items in groups.items():
        if len(items) == 1:
            out.append(items[0][0])
            continue
        best = {}
        for _, c in items:
            for a in c["affected"]:
                if a.get("safe") and (a["name"] not in best or cmp(a["safe"], best[a["name"]]) > 0):
                    best[a["name"]] = a["safe"]
        first = items[0][0]
        rank = max(items, key=lambda it: zh_report.RANK[it[0]["verdict"]])[0]["verdict"]
        ids = [r["id"] for r, _ in items]
        crit = sum(1 for _, c in items if c.get("severity") == "critical")
        out.append(dict(first, id="live:" + "+".join(key), verdict=rank,
                        title="%s: %d new high/critical advisories in the last %d days%s" % (
                            ", ".join(key), len(items), days, (" (%d critical)" % crit) if crit else ""),
                        notes=["advisories: " + ", ".join(ids[:8]) + (" …" if len(ids) > 8 else "")],
                        steps=[{"step": "Upgrade: " + (", ".join("%s → %s" % kv for kv in best.items()) or "see advisories"),
                                "why": None, "danger": None, "commands": []},
                               {"step": "Check whether the vulnerable code paths are reachable in your app", "why": None,
                                "danger": None, "commands": []}],
                        safe_versions=["%s %s" % kv for kv in best.items()],
                        cves=sorted({cv for _, c in items for cv in c.get("cves", [])}),
                        sources=[s_ for _, c in items for s_ in c.get("sources", [])][:8]))
    return out


def cmd_scan(a):
    root = os.path.abspath(a.path)
    if not os.path.isdir(root):
        print("zero-hour: %s is not a directory" % root, file=sys.stderr)
        return 3
    net = zh_intel.Net(offline=a.offline)
    include_host = not a.no_host
    inv = zh_inventory.build(root, include_host=include_host)
    curated = zh_intel.load_cards(net, a.card or [], remote=not a.no_remote_cards)
    live = [] if a.offline else zh_intel.live_advisories(net, days=a.days)
    if a.incident:
        curated = [c for c in curated if zh_report.card_matches(c, a.incident)]
        live = [c for c in live if zh_report.card_matches(c, a.incident)]
    live = _relevant_live(live, inv)
    curated_ids = {c["id"] for c in curated}
    live = [c for c in live if c["id"] not in curated_ids]

    sp_dirs = inv.get("site_packages", [])
    card_strings = {c["id"]: (c.get("iocs") or {}).get("strings", []) for c in curated}
    hygiene, config_hits = zh_hunt.audit_agent_configs(root, include_host, card_strings)
    unknowns = list(inv.get("notes", []))
    incidents = []
    for c in curated + live:
        hits = zh_hunt.hunt_files(c, root, sp_dirs) + zh_hunt.hunt_git(c, root) + config_hits.get(c["id"], [])
        if a.github:
            gh_hits, gh_unknown = zh_hunt.hunt_github(c)
            hits += gh_hits
            if gh_unknown:
                unknowns.append("%s: could not list your GitHub repos (is `gh` logged in?)" % c["title"])
        scope = inv if (not c.get("live") or c.get("kind") == "malware") else dict(inv, host_packages=[])
        res = zh_report.eval_card(c, scope, hits)
        if c.get("live") and res["verdict"] == "clear":
            continue
        incidents.append(res)
    incidents = _group_live_vulns(incidents, {c["id"]: c for c in live}, a.days)

    kev_map = zh_intel.kev(net)
    for v in zh_intel.kev_live_cards(kev_map, inv, days=max(a.days, 14)):
        if a.incident and a.incident.lower() not in json.dumps(v).lower():
            continue
        incidents.append({"id": v["cveID"], "title": "%s %s — %s (CISA KEV, added %s)" % (
            v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", v["cveID"]), v.get("dateAdded")),
            "verdict": "exposed", "confidence": "low",
            "evidence": [{"text": "this project uses %s; CISA lists %s as exploited in the wild — check your version against the vendor advisory" % (
                v.get("product"), v["cveID"]), "file": None, "line": None}],
            "via": None, "notes": [], "steps": [{"step": v.get("requiredAction", "Apply vendor updates"), "why": None,
                                                  "danger": None, "commands": []}],
            "network_iocs": [], "sources": [{"name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
            "origin": "live (CISA KEV)", "published": v.get("dateAdded"), "cves": [v["cveID"]]})

    covered = set()
    for inc in incidents:
        covered |= {inc["id"]} | set(inc.get("cves") or [])
    for c in curated + live:
        if c["id"] in covered:
            covered |= set(c.get("aliases") or [])
    osv_hits = zh_intel.osv_scan(net, inv["packages"])
    if osv_hits is None:
        unknowns.append("OSV.dev unreachable — known-vulnerable and malicious dependency versions were NOT checked")
        osv_hits = {}
    cves = {i for vs in osv_hits.values() for v in vs for i in [v["id"]] + list(v.get("aliases") or [])}
    epss_map = zh_intel.epss(net, cves) if cves else {}
    advisories = zh_report.build_advisories(osv_hits, inv, kev_map, epss_map, covered)
    if a.incident:
        q = a.incident.lower()
        advisories = [x for x in advisories if q in (x["package"]["name"] + " " + x["id"] + " " + " ".join(x["aliases"])).lower()]
    if a.deep:
        hygiene += zh_hunt.audit_ci(inv) + zh_hunt.audit_compose(inv) + zh_hunt.scan_secrets(root)
    for m in inv.get("manifests_without_lock", []):
        unknowns.append("%s has no lockfile next to it — exact versions unknown" % m)
    if not kev_map:
        unknowns.append("CISA KEV feed unavailable — 'exploited in the wild' ranking is incomplete")

    status = dict(net.status)
    origins = sorted({c.get("_origin", "?").split(" ")[0] for c in curated} |
                     ({"live-advisories"} if not a.offline and "github-advisories" in status else set()))
    cards_meta = {"count": len(curated) + len(live), "curated": len(curated), "live_matched": len(live),
                  "origins": origins, "days": a.days}
    report = zh_report.assemble(inv, incidents, advisories, hygiene, status, cards_meta, unknowns, a.deep)
    if a.format == "json":
        _emit(json.dumps(report, indent=2) + "\n", a.out)
    elif a.format == "sarif":
        _emit(json.dumps(zh_report.render_sarif(report), indent=2) + "\n", a.out)
    else:
        _emit(zh_report.render_md(report, show_all=a.all), a.out)
    return zh_report.exit_code(report)


def cmd_pulse(a):
    net = zh_intel.Net(offline=a.offline)
    curated = zh_intel.load_cards(net, remote=not a.no_remote_cards)
    live = [] if a.offline else zh_intel.live_advisories(net, days=a.days)
    kev_map = zh_intel.kev(net)
    recent_kev = zh_intel.kev_recent(kev_map, a.days)
    scores = zh_intel.epss(net, [v["cveID"] for v in recent_kev]) if recent_kev else {}
    import datetime as dt
    cutoff = (dt.date.today() - dt.timedelta(days=a.days)).isoformat()
    fresh = [c for c in curated if str(c.get("updated") or c["published"]) >= cutoff]
    malware = [c for c in live if c["kind"] == "malware"]
    vulns = [c for c in live if c["kind"] != "malware"]
    data = {"days": a.days, "intel": net.status,
            "incident_cards": [{k: c.get(k) for k in ("id", "title", "published", "updated", "severity", "summary", "_origin")} for c in fresh],
            "kev": [{"cve": v["cveID"], "vendor": v.get("vendorProject"), "product": v.get("product"),
                     "name": v.get("vulnerabilityName"), "added": v.get("dateAdded"),
                     "ransomware": v.get("knownRansomwareCampaignUse"), "epss": scores.get(v["cveID"])} for v in recent_kev],
            "malware_packages": len(malware),
            "malware_by_ecosystem": {},
            "critical_advisories": [{"id": c["id"], "title": c["title"], "severity": c["severity"], "published": c["published"],
                                     "packages": sorted({"%s (%s)" % (x["name"], x["ecosystem"]) for x in c["affected"]})[:4]}
                                    for c in vulns if c.get("severity") == "critical"][:20]}
    for c in malware:
        for x in c["affected"]:
            data["malware_by_ecosystem"][x["ecosystem"]] = data["malware_by_ecosystem"].get(x["ecosystem"], 0) + 1
    if a.format == "json":
        _emit(json.dumps(data, indent=2) + "\n", None)
        return 0
    L = ["ZERO-HOUR PULSE · last %d days · intel: %s" % (a.days, ", ".join("%s %s" % (k, zh_report._mark(v)) for k, v in net.status.items())), ""]
    if fresh:
        L.append("INCIDENT CARDS (researched, with IOCs + safe fix order)")
        for c in fresh:
            L.append("  %s  %s — %s" % (c.get("updated") or c["published"], c["title"], c.get("summary", "")[:110]))
        L.append("")
    if recent_kev:
        L.append("EXPLOITED IN THE WILD (CISA KEV, newest first)")
        for v in data["kev"][:20]:
            L.append("  %s  %s  %s %s — %s%s" % (v["added"], v["cve"], v["vendor"], v["product"], (v["name"] or "")[:70],
                                                ("  EPSS %.2f" % v["epss"]) if v.get("epss") is not None else ""))
        L.append("")
    if malware:
        L.append("NEW MALICIOUS PACKAGES: %d (%s)" % (len(malware), ", ".join("%s %d" % kv for kv in sorted(data["malware_by_ecosystem"].items(), key=lambda kv: -kv[1]))))
        L.append("")
    if data["critical_advisories"]:
        L.append("NEW CRITICAL ADVISORIES")
        for c in data["critical_advisories"][:12]:
            L.append("  %s  %s  %s — %s" % (c["published"], c["id"], ", ".join(c["packages"]), c["title"][:70]))
        L.append("")
    L.append("Next: run `zerohour scan` in your project to see which of these hit you.")
    _emit("\n".join(L) + "\n", None)
    return 0


def cmd_inventory(a):
    inv = zh_inventory.build(os.path.abspath(a.path), include_host=not a.no_host)
    _emit(json.dumps(inv, indent=2) + "\n", None)
    return 0


def cmd_card(a):
    if a.action == "template":
        _emit(json.dumps(CARD_TEMPLATE, indent=2) + "\n", None)
        return 0
    if not a.file:
        print("zero-hour: card %s needs a FILE" % a.action, file=sys.stderr)
        return 3
    try:
        card = zh_intel.read_card(a.file)
    except (OSError, ValueError) as e:
        print("zero-hour: cannot read %s: %s" % (a.file, e), file=sys.stderr)
        return 3
    errs = zh_intel.validate_card(card)
    if errs:
        print("invalid card:\n  - " + "\n  - ".join(errs), file=sys.stderr)
        return 3
    if a.action == "validate":
        print("ok: %s" % card["id"])
        return 0
    dest = os.path.join(zh_intel.user_cards_dir(), os.path.basename(card["id"]) + ".json")
    shutil.copyfile(a.file, dest)
    print("added %s → %s (used by every scan from now on)" % (card["id"], dest))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="zerohour", description="Is today's security incident in my project, and what do I do right now?")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="check this project against live incidents (default)")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--days", type=int, default=7, help="live advisory window in days (default 7)")
    s.add_argument("--deep", action="store_true", help="also CI/CD, secrets in git, exposed databases, floating image tags")
    s.add_argument("--incident", help="focus on one incident / package / CVE (substring match)")
    s.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    s.add_argument("--out", help="write the report to a file")
    s.add_argument("--card", action="append", help="extra incident card JSON (repeatable)")
    s.add_argument("--offline", action="store_true", help="no network; use cached intel only")
    s.add_argument("--no-remote-cards", action="store_true", help="don't fetch community incident cards from GitHub")
    s.add_argument("--no-host", action="store_true", help="only look inside the project, not this machine")
    s.add_argument("--github", action="store_true", help="also list your GitHub repos via `gh` to find worm exfil repos")
    s.add_argument("--all", action="store_true", help="show low-priority advisories too")
    s.set_defaults(fn=cmd_scan)
    pl = sub.add_parser("pulse", help="what is being exploited / published right now")
    pl.add_argument("--days", type=int, default=7)
    pl.add_argument("--format", choices=["md", "json"], default="md")
    pl.add_argument("--offline", action="store_true")
    pl.add_argument("--no-remote-cards", action="store_true")
    pl.set_defaults(fn=cmd_pulse)
    iv = sub.add_parser("inventory", help="print what this project runs (JSON)")
    iv.add_argument("path", nargs="?", default=".")
    iv.add_argument("--no-host", action="store_true")
    iv.set_defaults(fn=cmd_inventory)
    cd = sub.add_parser("card", help="incident cards: template | validate FILE | add FILE")
    cd.add_argument("action", choices=["template", "validate", "add"])
    cd.add_argument("file", nargs="?")
    cd.set_defaults(fn=cmd_card)
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("scan", "pulse", "inventory", "card", "-h", "--help"):
        argv = ["scan"] + argv
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 3
    except Exception as e:  # never crash with a traceback in the user's face
        print("zero-hour: internal error: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        if os.environ.get("ZERO_HOUR_DEBUG"):
            raise
        return 3


if __name__ == "__main__":
    sys.exit(main())
