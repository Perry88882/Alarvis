#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copy C0 verdicts to C4 for real-source projects where the C4 model input
SHA-256 equals the C0 input SHA-256 (frozen reuse rule).

Input : verdict CSV from aggregate_queue.py, reuse CSV from make_real_queue.py
Output: verdict CSV with the same columns plus C4 rows copied from C0.

No API calls.  A project listed in the reuse CSV but missing a valid C0
verdict is reported and left without C4 (never synthesised).
"""

import argparse
import csv
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--reuse", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.reuse, newline="", encoding="utf-8-sig") as f:
        reuse = {r["project"] for r in csv.DictReader(f)
                 if r.get("condition") == "c4"
                 and r.get("reuse_from") == "c0"}

    with open(args.verdicts, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        fields = rd.fieldnames
        rows = list(rd)

    have = {(r["program"], r["condition"]): r for r in rows}
    added, missing = [], []
    for project in sorted(reuse):
        src = have.get((project, "C0"))
        if src is None or src.get("status") != "ok":
            missing.append(project)
            continue
        dst = dict(src)
        dst["condition"] = "C4"
        added.append(dst)
        have[(project, "C4")] = dst

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows + added)

    print("reuse_projects=%d added_C4_rows=%d missing_valid_C0=%d"
          % (len(reuse), len(added), len(missing)))
    for project in missing:
        print("MISSING_C0 %s" % project, file=sys.stderr)
    print("wrote %s" % args.out)
    return 0 if not missing else 2


if __name__ == "__main__":
    sys.exit(main())
