#!/usr/bin/env python3
"""Render bench/results.json as Markdown (docs/BENCHMARKS.md). No hand-typed numbers."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    data = json.load(open(os.path.join(HERE, "results.json")))
    rows = data["rows"]
    L = ["# Benchmarks", "",
         "Real numbers from `python3 bench/run.py <dir>` on %s (Python %s, %s, Apple Silicon laptop)." % (
             data["generated"], data["python"], data["platform"]),
         "Each repo is a shallow clone of the default branch at the commit shown. Every scan is live"
         " (OSV, GitHub Advisory DB, CISA KEV, EPSS, incident cards) with `--no-host`, so this machine doesn't skew results.", "",
         "## Cost", "",
         "| Repo | Commit | Packages | First run (cold cache) | Repeat run CPU | Peak memory | `--deep` CPU / memory |",
         "|---|---|---:|---:|---:|---:|---:|"]
    for r in rows:
        L.append("| %s | `%s` | %d | %.1f s | %.1f s | %.0f MB | %.1f s / %.0f MB |" % (
            r["repo"], r["commit"], r["packages"], r["cold"]["wall_s"], r["cpu_s"], r["peak_rss_mb"],
            r["deep"]["cpu_s"], r["deep"]["peak_rss_mb"]))
    cold = [r["cold"]["wall_s"] for r in rows]
    peak = [max(r["peak_rss_mb"], r["deep"]["peak_rss_mb"], r["cold"]["peak_rss_mb"]) for r in rows]
    cpu = [r["cold"]["cpu_s"] for r in rows]
    L += ["", "Max peak memory across all runs: **%.0f MB**. Max CPU time: **%.1f s**. First-run wall time is mostly"
          " network (live feeds). Repeat runs within an hour use the cache." % (max(peak), max(cpu)), "",
          "## Accuracy vs osv-scanner", "",
          "Baseline: Google's [osv-scanner](https://github.com/google/osv-scanner) `scan source -r` on the same checkout."
          " A finding is one (package, version, advisory) pair.", "",
          "| Repo | osv-scanner findings | Same row | Reported as a live incident line | osv-scanner's guess from unpinned `requirements.txt` | Missed by zero-hour |",
          "|---|---:|---:|---:|---:|---:|"]
    tot = {"total": 0, "same": 0, "as_incident": 0, "requirements_guess": 0, "missed": 0}
    for r in rows:
        o = r.get("osv_scanner") or {}
        if "total" not in o:
            L.append("| %s | — | — | — | — | — (%s) |" % (r["repo"], o.get("error", "not run")))
            continue
        for k in tot:
            tot[k] += o[k]
        L.append("| %s | %d | %d | %d | %d | %d |" % (r["repo"], o["total"], o["same"], o["as_incident"],
                                                     o["requirements_guess"], o["missed"]))
    L.append("| **Total** | **%d** | **%d** | **%d** | **%d** | **%d** |" % (
        tot["total"], tot["same"], tot["as_incident"], tot["requirements_guess"], tot["missed"]))
    base = tot["total"] - tot["requirements_guess"]
    L += ["", "On lockfile-backed findings, zero-hour reports **%d of %d (%.2f%%)**." % (
        base - tot["missed"], base, 100.0 * (base - tot["missed"]) / base if base else 0), "",
          "How to read the columns:", "",
          "- **Reported as a live incident line**: advisories published in the last 7 days. zero-hour lists these as incidents"
          " (\"Pillow: 15 new high/critical advisories\") instead of advisory rows.",
          "- **Guess from unpinned requirements**: for a plain `requirements.txt`, osv-scanner resolves transitive"
          " dependencies itself and picks versions. zero-hour reports only versions that a lockfile or `==` pin proves."
          " Add a lockfile (`uv lock`, `pip-compile`) to cover these.",
          "- **Missed**: the remaining gaps. `bench/results.json` lists each one.", "",
          "## What zero-hour found that a CVE scanner does not", ""]
    for r in rows:
        inc = [t for v, t in r["incidents"] if v in ("compromised", "affected", "exposed")]
        if inc:
            L.append("- **%s**:" % r["repo"])
            L += ["  - %s" % t for t in inc[:3]] + (["  - … +%d more" % (len(inc) - 3)] if len(inc) > 3 else [])
    L += ["", "## Reproduce", "", "```bash",
          "mkdir repos && cd repos",
          "for r in " + " ".join(r["repo"] for r in rows) + "; do",
          "  git clone --depth 1 https://github.com/$r.git $(echo $r | tr / _)",
          "done",
          "cd .. && python3 bench/run.py repos && python3 bench/report.py",
          "```", ""]
    out = os.path.join(os.path.dirname(HERE), "docs", "BENCHMARKS.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as fh:
        fh.write("\n".join(L))
    print("\n".join(L[:40]))


if __name__ == "__main__":
    sys.exit(main())
