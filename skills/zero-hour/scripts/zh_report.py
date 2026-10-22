"""Turn intel + inventory + hunt results into verdicts, ordered fixes and output
(markdown, JSON, SARIF). Python stdlib only."""
import datetime as dt
import os
import re

from zh_versions import cmp, in_range, normalize_name, fixed_version_for, looks_distro_build
from zh_hunt import OS_NAME, short, tilde

VERSION = "0.1.0"
ICON = {"compromised": "🔴 COMPROMISED", "affected": "🔴 AFFECTED   ", "exposed": "🟠 EXPOSED    ",
        "unknown": "⚪ UNKNOWN    ", "clear": "🟢 CLEAR      "}
RANK = {"compromised": 5, "affected": 4, "exposed": 3, "unknown": 2, "clear": 1}
LEVEL_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def _loc(p):
    return "%s:%s" % (p["source"], p["line"]) if p.get("line") else p["source"]


def _strip_registry(name):
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    return "/".join(parts)


def _version_hit(version, aff):
    if aff.get("any_version"):
        return True
    for v in aff.get("versions", []) or []:
        if cmp(version, v) == 0:
            return True
    return any(in_range(version, r) for r in aff.get("ranges", []) or [])


# ---------------------------------------------------------------- incident cards

def eval_card(card, inv, hunt_hits):
    ev, notes, via, level = [], [], None, "clear"
    present = False

    def bump(lv):
        nonlocal level
        if RANK[lv] > RANK[level]:
            level = lv

    for aff in card.get("affected", []):
        eco, want = aff["ecosystem"], normalize_name(aff["ecosystem"], aff["name"])
        if eco == "runtime":
            for rt in inv.get("runtimes", []):
                if rt["name"] != want:
                    continue
                present = True
                v = rt.get("version")
                where = "%s%s" % (rt["source"], (":%s" % rt["line"]) if rt.get("line") else "")
                sapi = (" (%s)" % rt["sapi"]) if rt.get("sapi") and rt["sapi"] != "unknown" else ""
                if not v:
                    bump("unknown")
                    notes.append("%s: %s version not pinned (%s) — check `%s -v` where it really runs" % (where, want, rt["origin"], want))
                    continue
                hit_ranges = [r for r in aff.get("ranges", []) if in_range(v, r)]
                if v.count(".") < 2:  # only "8" or "8.3" known (floating tag): patch level is unknowable here
                    pad = 2 - v.count(".")
                    low, high = v + ".0" * pad, v + ".99999" * pad
                    over = [r for r in aff.get("ranges", []) if in_range(low, r) or in_range(high, r) or
                            (r.get("introduced") not in (None, "0") and cmp(low, r["introduced"]) <= 0 <= cmp(high, r["introduced"]))]
                    if over:
                        bump("exposed")
                        fixes = ", ".join(sorted({r["fixed"] for r in over if r.get("fixed")})) or "see advisory"
                        ev.append({"text": "%s %s %s%s — floating tag, patch level unknown; run `%s -v` inside the image (fixed: %s)" % (
                            where, want, v, sapi, want, fixes), "file": rt["source"] if rt.get("line") else None, "line": rt.get("line")})
                    continue
                if not hit_ranges:
                    continue
                note = "; ".join(r["note"] for r in hit_ranges if r.get("note"))
                text = "%s %s %s%s%s" % (where, want, v, sapi, (" — " + note) if note else "")
                if looks_distro_build(v):
                    bump("exposed")
                    text += " — distro build, may carry a backport: check your vendor advisory"
                elif rt.get("origin") == "local":
                    bump("exposed")
                    text += " — on this machine (CLI); patch it, and check the servers that run your site"
                else:
                    bump("affected")
                ev.append({"text": text, "file": rt["source"] if rt.get("line") else None, "line": rt.get("line")})
        elif eco == "Docker":
            for img in inv.get("images", []):
                if _strip_registry(img["name"]) != _strip_registry(want):
                    continue
                present = True
                tag = img.get("tag") or "latest"
                if any(t in tag for t in aff.get("tag_contains", [])):
                    bump("affected")
                    ev.append({"text": "%s image %s:%s" % (_loc(img), img["name"], tag),
                               "file": img["source"] if img.get("line") else None, "line": img.get("line")})
                elif tag in ("latest", "main", "main-latest", "main-stable") and not img.get("pinned"):
                    bump("exposed")
                    ev.append({"text": "%s image %s:%s — floating tag; if pulled during the incident window, re-pull and check the digest" % (
                        _loc(img), img["name"], tag), "file": img["source"] if img.get("line") else None, "line": img.get("line")})
        else:
            pkgs = inv.get("packages", []) + inv.get("host_packages", [])
            if any(p["ecosystem"] == eco for p in pkgs):
                present = True
            declared = [m for m in inv.get("manifest_packages", [])
                        if m["ecosystem"] == eco and normalize_name(eco, m["name"]) == want]
            if declared and not any(p["ecosystem"] == eco and normalize_name(eco, p["name"]) == want for p in pkgs):
                present = True
                bump("unknown")
                notes.append("%s declares %s but has no lockfile — exact version unknown; run your package manager's lock/list command" % (
                    declared[0]["source"], aff["name"]))
            for p in pkgs:
                if p["ecosystem"] != eco or normalize_name(eco, p["name"]) != want:
                    continue
                if not p.get("version"):
                    bump("unknown")
                    notes.append("%s: %s has no pinned version — add a lockfile" % (_loc(p), p["name"]))
                    continue
                if not _version_hit(p["version"], aff):
                    continue
                bump("affected")
                where = _loc(p) if p.get("scope") != "installed" or not os.path.isabs(p["source"]) else \
                    "installed in " + tilde(p["source"])
                if p.get("via") and len(p["via"]) > 1:
                    via = via or p["via"]
                ev.append({"text": "%s %s %s%s" % (where, p["name"], p["version"],
                                                   ("  via " + " → ".join(p["via"])) if p.get("via") and len(p["via"]) > 1 else ""),
                           "file": p["source"] if p.get("line") else None, "line": p.get("line")})
    # config preconditions (e.g. php ini) can downgrade to EXPOSED when every mitigation is in place
    pre = card.get("preconditions") or []
    if pre and level == "affected":
        mitigated_all = True
        for c in pre:
            vals = [i for i in inv.get("ini", []) if i["key"] == c.get("ini")]
            ok = [i for i in vals if str(i["value"]).strip().strip('"').lower() in [m.lower() for m in c.get("mitigated_if", [])]]
            bad = [i for i in vals if i not in ok]
            for i in bad:
                ev.append({"text": "%s%s %s=%s (%s not mitigated)" % (
                    i["source"], (":%s" % i["line"]) if i.get("line") else "", i["key"], i["value"], c.get("cve", c["id"])),
                    "file": i["source"] if i.get("line") else None, "line": i.get("line")})
            if not ok or bad:
                mitigated_all = False
        if mitigated_all:
            level = "exposed"
            notes.append("config mitigations are in place — still patch; the vendor says upgrading is the only complete fix")
    # IOCs
    for h in hunt_hits:
        if h["level"] == "compromised":
            bump("compromised")
            ev.insert(0, h)
        else:
            ev.append(dict(h, text=h["text"] + " (review: can be legitimate)"))
            if level == "clear":
                level = "unknown"
    confidence = "high" if level in ("compromised", "affected") and any(e.get("file") for e in ev) else \
        "medium" if level != "clear" else "high"
    if level == "clear":
        notes.append("not used in this project" if not present else "no affected version, no IOCs found")
    when = {"compromised": {"compromised", "affected", "always"}, "affected": {"affected", "always"},
            "exposed": {"affected", "always"}}.get(level, set())
    steps = []
    for s in card.get("remediation", []):
        if s.get("when", "always") in when:
            cmds = s.get("commands") or {}
            steps.append({"step": s["step"], "why": s.get("why"), "danger": s.get("danger"),
                          "commands": list(cmds.get(OS_NAME, [])) + list(cmds.get("any", []))})
    return {"id": card["id"], "title": card["title"], "verdict": level, "confidence": confidence,
            "evidence": ev, "via": via, "notes": notes, "steps": steps,
            "network_iocs": (card.get("iocs") or {}).get("network", []) if level in ("compromised", "affected") else [],
            "safe_versions": ["%s %s" % (a_["name"], a_["safe"]) for a_ in card.get("affected", []) if a_.get("safe")],
            "sources": card.get("sources", []), "origin": card.get("_origin"),
            "advisory_ids": sorted({card["id"]} | set(card.get("aliases") or []) | set(card.get("cves") or [])),
            "published": card.get("published"), "cves": card.get("cves", [])}


def card_matches(card, query):
    q = query.lower()
    hay = " ".join([card["id"], card["title"], " ".join(card.get("cves", [])), " ".join(card.get("aliases", []))] +
                   [a["name"] for a in card.get("affected", [])]).lower()
    return q in hay


# ---------------------------------------------------------------- OSV advisories

def build_advisories(osv_hits, inv, kev_map, epss_map, card_ids):
    out = []
    by_key = {}
    for p in inv.get("packages", []):
        by_key.setdefault((p["ecosystem"], p["name"], p["version"]), []).append(p)
    for key, vulns in (osv_hits or {}).items():
        eco, name, ver = key
        for v in vulns:
            ids = {v["id"]} | set(v.get("aliases") or [])
            if ids & card_ids:
                continue
            cves = sorted(i for i in ids if i.startswith("CVE-"))
            sev = str((v.get("database_specific") or {}).get("severity", "")).upper()
            score = max([epss_map.get(c, 0.0) for c in cves] or [0.0])
            if any(i.startswith("MAL-") for i in ids):
                kind = "malicious"
            elif any(c in kev_map for c in cves):
                kind = "kev"
            elif score >= 0.1:
                kind = "epss"
            elif sev == "CRITICAL":
                kind = "critical"
            else:
                kind = "other"
            locs = by_key.get(key, [])
            out.append({"id": v["id"], "aliases": sorted(ids - {v["id"]}), "kind": kind,
                        "summary": short(v.get("summary") or v.get("details") or "", 90),
                        "package": {"ecosystem": eco, "name": name, "version": ver},
                        "fixed": None if kind == "malicious" else fixed_version_for(ver, v, eco, name),
                        "epss": score or None, "severity": sev or None,
                        "evidence": [{"text": _loc(p) + (("  via " + " → ".join(p["via"])) if p.get("via") and len(p["via"]) > 1 else ""),
                                      "file": p["source"] if p.get("line") else None, "line": p.get("line")} for p in locs[:3]]})
    order = {"malicious": 0, "kev": 1, "epss": 2, "critical": 3, "other": 4}
    out.sort(key=lambda a: (order[a["kind"]], -(a["epss"] or 0), a["package"]["name"]))
    return out


# ---------------------------------------------------------------- assemble

def assemble(inv, incidents, advisories, hygiene, intel_status, cards_meta, unknowns, deep):
    s = {"compromised": 0, "affected": 0, "exposed": 0, "review": 0, "unknown": 0, "clear": 0}
    for i in incidents:
        s[i["verdict"]] += 1
    for a in advisories:
        if a["kind"] in ("malicious", "kev"):
            s["affected"] += 1
        elif a["kind"] in ("epss", "critical"):
            s["exposed"] += 1
    s["review"] = sum(1 for h in hygiene if h["level"] in ("high", "medium"))
    s["unknown"] += len(unknowns)
    return {"tool": "zero-hour", "version": VERSION,
            "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "root": inv["root"], "deep": deep, "intel": intel_status, "cards": cards_meta,
            "scanned": {"files": len(inv.get("files", [])), "packages": len(inv.get("packages", [])),
                        "images": len(inv.get("images", [])), "runtimes": len(inv.get("runtimes", [])),
                        "site_packages_dirs": len(inv.get("site_packages", []))},
            "summary": s, "incidents": incidents, "advisories": advisories, "hygiene": hygiene,
            "unknowns": unknowns}


def exit_code(report):
    bad = any(i["verdict"] in ("compromised", "affected") for i in report["incidents"]) or \
        any(a["kind"] in ("malicious", "kev") for a in report["advisories"])
    return 2 if bad else 0


# ---------------------------------------------------------------- render

def _mark(status):
    if status is None:
        return "–"
    return "✓" if status in ("ok", "cached") else ("~" if str(status).startswith("stale") else "✗")


_CMD_WORDS = {"Get-ScheduledTask", "Unregister-ScheduledTask", "Get-ChildItem", "Remove-Item", "Get-Content",
              "Select-String", "Test-Path", "Get-Process", "Stop-Process", "Get-ItemProperty", "Move-Item", "New-Item"}


def _is_prose(cmd):
    first = cmd.split(" ", 1)[0]
    return first[:1].isupper() and first not in _CMD_WORDS and " " in cmd and not first.startswith(("$", "~", "/"))


def render_md(r, show_all=False):
    L = []
    name = os.path.basename(r["root"].rstrip(os.sep)) or r["root"]
    when = r["generated"].replace("T", " ").replace("Z", " UTC")[:20] + "UTC"
    intel = r["intel"]
    L.append("ZERO-HOUR · %s · %s" % (name, when))
    L.append("intel: OSV %s · CISA KEV %s · EPSS %s · GitHub advisories %s · incident cards %d (%s)" % (
        _mark(intel.get("osv")), _mark(intel.get("cisa-kev")),
        _mark(intel.get("first-epss")), _mark(intel.get("github-advisories")), r["cards"]["count"], ", ".join(r["cards"]["origins"]) or "none"))
    sc = r["scanned"]
    L.append("scanned: %d files · %d packages · %d images · %d runtimes · %d python envs%s" % (
        sc["files"], sc["packages"], sc["images"], sc["runtimes"], sc["site_packages_dirs"],
        " · deep" if r["deep"] else ""))
    L.append("")
    clear = []
    for inc in sorted(r["incidents"], key=lambda i: -RANK[i["verdict"]]):
        if inc["verdict"] == "clear":
            clear.append(inc["title"])
            continue
        L.append("%s  %s   [confidence: %s]" % (ICON[inc["verdict"]], inc["title"], inc["confidence"]))
        for e in inc["evidence"][:6]:
            L.append("   evidence: %s" % e["text"])
        if len(inc["evidence"]) > 6:
            L.append("   … +%d more" % (len(inc["evidence"]) - 6))
        if inc.get("via"):
            L.append("   via: %s" % " → ".join(inc["via"]))
        for n in inc["notes"]:
            L.append("   note: %s" % n)
    if clear:
        L.append("%s  %s" % (ICON["clear"].strip(), " · ".join(clear)))
    if not r["incidents"]:
        L.append("(no incident cards loaded — run without --offline, or have your agent research today's incidents)")
    adv = r["advisories"]
    top = [a for a in adv if show_all or a["kind"] != "other"]
    if top:
        L.append("")
        L.append("ADVISORIES IN YOUR DEPENDENCIES (malicious → exploited → likely exploited → critical)")
        tag = {"malicious": "🔴 MALICIOUS", "kev": "🔴 EXPLOITED (KEV)", "epss": "🟠 EPSS %.2f",
               "critical": "🟠 CRITICAL", "other": "🟡 %s"}
        for a in top[:25]:
            t = tag[a["kind"]]
            t = t % a["epss"] if a["kind"] == "epss" else (t % (a["severity"] or "ADVISORY") if a["kind"] == "other" else t)
            cve = next((x for x in a["aliases"] if x.startswith("CVE-")), "")
            fix = "remove it; treat installs as compromised" if a["kind"] == "malicious" else \
                ("→ upgrade to %s" % a["fixed"] if a["fixed"] else "→ no fixed version yet")
            ev = a["evidence"][0]["text"] if a["evidence"] else ""
            L.append("%s  %s %s  %s %s  %s · %s" % (t, a["package"]["name"], a["package"]["version"], a["id"], cve, fix, ev))
        if len(top) > 25:
            L.append("… +%d more (see --format json)" % (len(top) - 25))
    hidden = len([a for a in adv if a["kind"] == "other"]) if not show_all else 0
    if hidden:
        L.append("… +%d lower-priority advisories (not exploited, low EPSS) — run with --all" % hidden)
    acted = [i for i in sorted(r["incidents"], key=lambda i: -RANK[i["verdict"]]) if i["steps"]]
    for inc in acted:
        L.append("")
        L.append("SAFE ORDER — %s" % inc["title"])
        for n, st in enumerate(inc["steps"], 1):
            L.append("%d. %s" % (n, st["step"]))
            if st.get("danger"):
                L.append("   ⚠ %s" % st["danger"].lstrip("⚠ ").strip())
        if inc.get("network_iocs"):
            L.append("   look for in DNS/egress logs: %s" % ", ".join(inc["network_iocs"]))
        safe = [s_ for s_ in inc.get("safe_versions", []) if s_]
        if safe:
            L.append("   safe versions: %s" % "; ".join(safe))
    if acted:
        L.append("")
        L.append("→ Fix plan: ask your AI agent (\"/zero-hour fix\") — it turns this order into exact, verified steps")
        L.append("  for your package manager, OS and deployment, applies only what you approve, then re-scans.")
        L.append("  Source guidance with example commands: --format json (incidents[].steps).")
    hy = sorted(r["hygiene"], key=lambda h: ["high", "medium", "low", "info"].index(h["level"]))
    if hy:
        L.append("")
        L.append("HARDENING (top %d of %d)" % (min(10, len(hy)), len(hy)))
        for h in hy[:10]:
            loc = h["file"] + (":%s" % h["line"] if h.get("line") else "") if h.get("file") else ""
            L.append("%s %s  %s%s" % (LEVEL_ICON[h["level"]], loc, h["title"], ("  [%s]" % h["standard"]) if h.get("standard") else ""))
    if r["unknowns"]:
        L.append("")
        L.append("NOT VERIFIED")
        for u in r["unknowns"]:
            L.append("⚪ %s" % u)
    L.append("")
    s = r["summary"]
    L.append("summary: %d compromised · %d affected · %d exposed · %d to review · %d unknown · %d clear" % (
        s["compromised"], s["affected"], s["exposed"], s["review"], s["unknown"], s["clear"]))
    return "\n".join(L) + "\n"


def render_sarif(r):
    rules, results = {}, []
    lvl = {"compromised": "error", "affected": "error", "exposed": "warning", "unknown": "note",
           "high": "error", "medium": "warning", "low": "note", "info": "note",
           "malicious": "error", "kev": "error", "epss": "warning", "critical": "warning", "other": "note"}

    def add(rule_id, name, level, msg, file, line):
        rules.setdefault(rule_id, {"id": rule_id, "name": name, "shortDescription": {"text": name[:200]}})
        res = {"ruleId": rule_id, "level": level, "message": {"text": msg}}
        if file and not os.path.isabs(file):
            loc = {"physicalLocation": {"artifactLocation": {"uri": file.replace(os.sep, "/")}}}
            if line:
                loc["physicalLocation"]["region"] = {"startLine": int(line)}
            res["locations"] = [loc]
        results.append(res)

    for inc in r["incidents"]:
        if inc["verdict"] in ("clear",):
            continue
        for e in inc["evidence"] or [{"text": inc["verdict"], "file": None, "line": None}]:
            add(inc["id"], inc["title"], lvl[inc["verdict"]], "%s: %s" % (inc["verdict"].upper(), e["text"]), e.get("file"), e.get("line"))
    for a in r["advisories"]:
        e = a["evidence"][0] if a["evidence"] else {}
        add(a["id"], "%s %s" % (a["package"]["name"], a["summary"] or a["id"]), lvl[a["kind"]],
            "%s %s %s (%s)%s" % (a["package"]["name"], a["package"]["version"], a["id"], a["kind"],
                                 (" fix: " + a["fixed"]) if a["fixed"] else ""), e.get("file"), e.get("line"))
    for h in r["hygiene"]:
        add(h["id"], h["title"], lvl[h["level"]], h["title"], h.get("file"), h.get("line"))
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "zero-hour", "version": VERSION,
                                          "informationUri": "https://github.com/akshitkhokhani/zero-hour",
                                          "rules": list(rules.values())}}, "results": results}]}
