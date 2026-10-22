#!/usr/bin/env python3
"""Reproducible benchmark: run zero-hour on real repos and record cost + results.

Usage: python3 bench/run.py <dir-with-cloned-repos> [--out bench/results.json]
Each sub-directory is one repo (shallow clone). Measures wall time, CPU time and
peak RSS of a full live scan (--no-host, so this machine doesn't skew results),
plus what zero-hour found. Optionally compares dependency/advisory coverage with
osv-scanner when it is installed. Stdlib only; POSIX (uses resource/wait4).
"""
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(os.path.dirname(HERE), "skills", "zero-hour", "scripts", "zerohour.py")


def scan(repo, deep=False, cold=False):
    """One live scan in its own process; exact per-process CPU and peak RSS via wait4."""
    args = [sys.executable, CLI, "scan", repo, "--no-host", "--format", "json"] + (["--deep"] if deep else [])
    env = dict(os.environ)
    if cold:  # empty intel cache: every feed is fetched live over the network
        env["ZERO_HOUR_CACHE"] = tempfile.mkdtemp(prefix="zh-bench-")
    with tempfile.TemporaryFile() as out:
        t0 = time.time()
        p = subprocess.Popen(args, stdout=out, stderr=subprocess.DEVNULL, env=env)
        _, status, ru = os.wait4(p.pid, 0)
        wall = time.time() - t0
        out.seek(0)
        rep = json.load(out)
    peak_mb = ru.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    return rep, {"wall_s": round(wall, 2), "cpu_s": round(ru.ru_utime + ru.ru_stime, 2),
                 "peak_rss_mb": round(peak_mb, 1), "exit": os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status >> 8}


def osv_baseline(repo):
    exe = shutil.which("osv-scanner")
    if not exe:
        return None
    r = subprocess.run([exe, "scan", "source", "-r", "--format", "json", repo], capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
    except ValueError:
        return {"error": "no package sources found" if "No package sources" in (r.stderr or "") else (r.stderr or "")[-120:]}
    vulns = {}
    for res in data.get("results", []):
        src = os.path.basename(res["source"]["path"])
        for p in res.get("packages", []):
            pk = p["package"]
            for v in p.get("vulnerabilities", []):
                vulns[(norm(pk.get("name", "")), pk.get("version"), v["id"])] = src
    return {"vulns": vulns}


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def inv_packages(repo):
    r = subprocess.run([sys.executable, CLI, "inventory", repo, "--no-host"], capture_output=True, text=True)
    return json.loads(r.stdout)["packages"]


def main():
    root = sys.argv[1]
    out_path = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else os.path.join(HERE, "results.json")
    rows = []
    for name in sorted(os.listdir(root)):
        repo = os.path.join(root, name)
        if not os.path.isdir(repo):
            continue
        sha = subprocess.run(["git", "-C", repo, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
        _, cost_cold = scan(repo, cold=True)   # first run: live network, empty cache
        rep, cost = scan(repo)                 # warm: intel cached (normal repeat run)
        _, cost_deep = scan(repo, deep=True)
        s = rep["summary"]
        ours = {(norm(a["package"]["name"]), a["package"]["version"], a["id"]) for a in rep["advisories"]}
        # fresh advisories are reported as incident lines; count the ids they carry
        inc_ids = {x for i in rep["incidents"] if i["verdict"] != "clear" for x in i.get("advisory_ids", [])}
        locked = {(norm(p["name"]), p["version"]) for p in inv_packages(repo)}
        osv = osv_baseline(repo)
        row = {"repo": name.replace("_", "/", 1), "commit": sha, **cost, "cold": cost_cold, "deep": cost_deep,
               "files": rep["scanned"]["files"], "packages": rep["scanned"]["packages"],
               "images": rep["scanned"]["images"], "runtimes": rep["scanned"]["runtimes"],
               "summary": rep["summary"], "advisories": len(rep["advisories"]),
               "kinds": {k: sum(1 for a in rep["advisories"] if a["kind"] == k) for k in ("malicious", "kev", "epss", "critical", "other")},
               "incidents": [(i["verdict"], i["title"][:90]) for i in rep["incidents"] if i["verdict"] != "clear"],
               "hygiene": len(rep["hygiene"]), "unknowns": len(rep["unknowns"])}
        if osv and "vulns" in osv:
            same = in_incident = guessed = missed = 0
            missed_examples = []
            for (n, v, vid), src in osv["vulns"].items():
                if (n, v, vid) in ours:
                    same += 1
                elif vid in inc_ids:
                    in_incident += 1
                elif (n, v) not in locked and "requirements" in src.lower():
                    guessed += 1  # osv-scanner resolved an unpinned/transitive requirement itself
                else:
                    missed += 1
                    missed_examples.append("%s@%s %s (%s)" % (n, v, vid, src))
            row["osv_scanner"] = {"total": len(osv["vulns"]), "same": same, "as_incident": in_incident,
                                  "requirements_guess": guessed, "missed": missed,
                                  "missed_examples": missed_examples[:5],
                                  "only_zero_hour": len({o for o in ours if o not in osv["vulns"]})}
        elif osv:
            row["osv_scanner"] = osv
        rows.append(row)
        print("%-32s cold %5.1fs | warm %6.1fs wall %6.1fs cpu %6.1f MB  pkgs=%-5d adv=%-4d %s" % (
            row["repo"], cost_cold["wall_s"], cost["wall_s"], cost["cpu_s"], cost["peak_rss_mb"], row["packages"], row["advisories"],
            {k: v for k, v in row.get("osv_scanner", {}).items() if k != "missed_examples"}), flush=True)
    with open(out_path, "w") as fh:
        json.dump({"generated": time.strftime("%Y-%m-%d"), "python": sys.version.split()[0], "platform": sys.platform,
                   "rows": rows}, fh, indent=2)
    print("wrote", out_path)


if __name__ == "__main__":
    main()
