#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Raw JSONL -> program-level verdicts for the 2026-11-02 final round.

Rules frozen for this round:
  * five planned repetitions per program × condition;
  * majority = strictly more than half of the VALID votes;
  * a tie is invalid, not "benign";
  * a truncated response with no answer is invalid;
  * fewer than --require valid votes => status insufficient.

Outputs:
  * program_verdicts.csv : one row per (queue, program, condition)
  * a per-condition summary on stdout (counts, alarm rate, Wilson 95% CI)

Zero API cost; reads only the raw JSONL.
"""

import argparse
import csv
import json
import math
import os
import sys
from collections import defaultdict


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def load(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception as e:
                print("BADJSON %s" % e, file=sys.stderr)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--require", type=int, default=3)
    args = ap.parse_args()

    rows = load(args.raw)
    groups = defaultdict(list)
    for r in rows:
        key = (r.get("queue", ""), r.get("program", ""),
               r.get("label", ""), r.get("condition", ""))
        groups[key].append(r)

    out_rows = []
    for (queue, program, label, cond), rs in sorted(groups.items()):
        reps = sorted({r.get("rep") for r in rs})
        valid = [r for r in rs if r.get("answer") in ("malicious", "benign")]
        n_mal = sum(1 for r in valid if r["answer"] == "malicious")
        n_ben = sum(1 for r in valid if r["answer"] == "benign")
        truncated = sum(1 for r in rs if r.get("finish") == "length")
        errors = sum(1 for r in rs if r.get("error"))
        if n_mal * 2 > len(valid):
            verdict, status = "malicious", "ok"
        elif n_ben * 2 > len(valid):
            verdict, status = "benign", "ok"
        else:
            verdict = ""
            status = "tie" if valid else "no_valid"
        if len(valid) < args.require:
            status = "insufficient"
        out_rows.append(dict(
            queue=queue, program=program, label=label, condition=cond,
            reps=";".join(str(x) for x in reps if x is not None),
            n_rows=len(rs), n_valid=len(valid), n_mal=n_mal, n_ben=n_ben,
            verdict=verdict, status=status,
            truncated=truncated, errors=errors,
        ))

    hdr = ["queue", "program", "label", "condition", "reps", "n_rows",
           "n_valid", "n_mal", "n_ben", "verdict", "status", "truncated",
           "errors"]
    out = args.out or (os.path.splitext(args.raw)[0] + "_verdicts.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=hdr)
        w.writeheader()
        w.writerows(out_rows)

    # summary per queue/condition x label
    agg = defaultdict(lambda: [0, 0, 0])  # k, n, invalid
    for r in out_rows:
        key = (r["queue"], r["condition"], r["label"])
        if r["status"] == "ok" and r["verdict"] == "malicious":
            agg[key][0] += 1
            agg[key][1] += 1
        elif r["status"] == "ok" and r["verdict"] == "benign":
            agg[key][1] += 1
        else:
            agg[key][2] += 1

    print("%-10s %-12s %-8s %7s %5s %5s  %s" %
          ("queue", "condition", "label", "alarm/den", "rate", "CI95", "invalid"))
    print("-" * 88)
    for key in sorted(agg):
        k, n, inv = agg[key]
        lo, hi = wilson(k, n)
        rate = (k / n * 100) if n else float("nan")
        print("%-10s %-12s %-8s %3d/%-3d %6.1f%%  [%5.1f,%5.1f]  %d"
              % (key[0], key[1], key[2], k, n, rate, lo * 100, hi * 100, inv))
    print("\nwrote %s (%d rows)" % (out, len(out_rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
