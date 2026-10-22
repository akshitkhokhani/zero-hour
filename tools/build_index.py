#!/usr/bin/env python3
"""Build incidents/index.json from incidents/*.json (stdlib only).

    python3 tools/build_index.py           # validate cards, write index.json
    python3 tools/build_index.py --check   # exit 1 if any card is invalid or index.json is stale
"""
import argparse
import datetime as dt
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCIDENTS = os.path.join(ROOT, "skills", "zero-hour", "incidents")
INDEX = os.path.join(INCIDENTS, "index.json")
SKIP = {"index.json", "schema.json"}

sys.path.insert(0, os.path.join(ROOT, "skills", "zero-hour", "scripts"))
from zh_intel import validate_card  # noqa: E402


def collect():
    entries, errors = [], []
    for path in sorted(glob.glob(os.path.join(INCIDENTS, "*.json"))):
        fn = os.path.basename(path)
        if fn in SKIP:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                card = json.load(fh)
        except (OSError, ValueError) as e:
            errors.append("%s: unreadable JSON (%s)" % (fn, e))
            continue
        errs = validate_card(card)
        if isinstance(card, dict) and card.get("id") and fn != card["id"] + ".json":
            errs.append("file name must be <id>.json (id is %r)" % card["id"])
        if errs:
            errors += ["%s: %s" % (fn, e) for e in errs]
            continue
        entries.append({"file": fn, "id": card["id"], "title": card["title"],
                        "published": card["published"],
                        "updated": card.get("updated") or card["published"],
                        "severity": card.get("severity", "")})
    entries.sort(key=lambda e: (e["updated"], e["published"], e["id"]), reverse=True)
    return entries, errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if invalid or stale")
    args = ap.parse_args(argv)

    entries, errors = collect()
    for e in errors:
        print("INVALID " + e, file=sys.stderr)

    if args.check:
        try:
            with open(INDEX, encoding="utf-8") as fh:
                current = json.load(fh).get("cards")
        except (OSError, ValueError, AttributeError):
            current = None
        stale = current != entries
        if stale:
            print("STALE incidents/index.json: run python3 tools/build_index.py", file=sys.stderr)
        if errors or stale:
            return 1
        print("ok: %d cards, index up to date" % len(entries))
        return 0

    if errors:
        print("not writing index.json: fix the invalid cards first", file=sys.stderr)
        return 1
    index = {"generated": dt.date.today().isoformat(), "cards": entries}
    with open(INDEX, "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("wrote incidents/index.json (%d cards)" % len(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
