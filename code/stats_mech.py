#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent mechanism confirmation: reads mech_raw.jsonl, no model calls.

Rules (frozen before the calls were made):
  - 5 repeats per cell; a valid binary vote = status ok, a parsed
    malicious/benign answer, and finish != length;
  - >=3 valid votes, strict majority; fewer than 3 or a tie is undetermined;
  - the unit is the program (30), not the call; pairing uses only programs
    determined in both arms;
  - primary comparison B vs C, two-sided exact McNemar, direction must be B>C;
  - auxiliary D vs B, E vs B, A vs C are interpretive only, not confirmation.

Usage (from the repository root):
    python3 code/stats_mech.py
"""

import argparse
import collections
import csv
import json
import math
import os
import sys


def binom_two_sided(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / float(2 ** n)
    return min(1.0, 2.0 * tail)


def wilson(k, n, z=1.959963985):
    if n == 0:
        return None
    p = float(k) / n
    d = 1.0 + z * z / n
    centre = (p + z * z / (2.0 * n)) / d
    half = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / d
    return {"p": p, "lo": max(0.0, centre - half), "hi": min(1.0, centre + half)}


def is_valid(r):
    if r.get("status") != "ok":
        return False
    if r.get("finish") == "length":
        return False
    return r.get("verdict") in ("malicious", "benign")


def arm_verdict(rows):
    """rows: the rows of one (program, arm). Returns (verdict, n_valid, detail)."""
    votes = [1 if r["verdict"] == "malicious" else 0 for r in rows if is_valid(r)]
    n = len(votes)
    mal = sum(votes)
    if n < 3:
        return ("undetermined", n, "%d/%d" % (mal, n))
    if mal * 2 == n:
        return ("undetermined", n, "%d/%d tie" % (mal, n))
    return ("malicious" if mal * 2 > n else "benign", n, "%d/%d" % (mal, n))


def paired(cells, prog_list, a, b):
    both, bb, cc, drop = [], 0, 0, []
    for p in prog_list:
        va, vb = cells[p][a][0], cells[p][b][0]
        if va == "undetermined" or vb == "undetermined":
            drop.append(p)
            continue
        both.append(p)
        if va == "malicious" and vb != "malicious":
            bb += 1
        elif vb == "malicious" and va != "malicious":
            cc += 1
    return {"a": a, "b_arm": b, "n_pairs": len(both), "b": bb, "c": cc,
            "p_two_sided": binom_two_sided(bb, cc),
            "direction_expected": "%s > %s" % (a, b),
            "direction_observed": "%s%s%s" % (a, ">" if bb > cc else ("<" if cc > bb else "="), b),
            "excluded": drop}


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=os.path.join(root, "data", "responses", "mech_raw.jsonl"))
    ap.add_argument("--out", default=os.path.join(root, "recompute_out", "mech"))
    ap.add_argument("--arms", default="A,B,C,D,E")
    args = ap.parse_args()
    arms = args.arms.split(",")

    rows_by = collections.defaultdict(list)
    n_rows = 0
    with open(args.raw, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                r = json.loads(line)
            except Exception:
                continue
            n_rows += 1
            rows_by[(r["program"], r["condition"])].append(r)

    progs = sorted({k[0] for k in rows_by})
    cells = {}
    for p in progs:
        cells[p] = {}
        for a in arms:
            cells[p][a] = arm_verdict(rows_by.get((p, a), []))

    per_arm = {}
    for a in arms:
        det = [cells[p][a] for p in progs if cells[p][a][0] != "undetermined"]
        mal = sum(1 for c in det if c[0] == "malicious")
        per_arm[a] = {
            "malicious": mal, "determined": len(det), "undetermined": len(progs) - len(det),
            "rate": round(mal / float(len(det)), 4) if det else None,
            "wilson": wilson(mal, len(det)),
            "undetermined_programs": [p for p in progs if cells[p][a][0] == "undetermined"],
        }

    primary = paired(cells, progs, "B", "C")
    aux = [paired(cells, progs, "D", "B"), paired(cells, progs, "E", "B"),
           paired(cells, progs, "A", "C")]

    if primary["p_two_sided"] < 0.05 and primary["b"] > primary["c"]:
        verdict = "independent confirmation (primary p<0.05 and B>C)"
    elif primary["b"] > primary["c"]:
        verdict = "direction repeated, underpowered (p>=0.05; not evidence of no effect)"
    elif primary["b"] == primary["c"]:
        verdict = "no direction (b=c)"
    else:
        verdict = "failed (opposite direction; reported as observed)"

    out = {"raw": args.raw, "rows": n_rows, "programs": len(progs),
           "arms": arms, "per_arm": per_arm, "primary": primary,
           "auxiliary": aux, "verdict": verdict,
           "cell_table": {p: {a: cells[p][a][2] for a in arms} for p in progs}}

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "mech_stats.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    with open(os.path.join(args.out, "mech_stats_cells.csv"), "w", encoding="utf-8",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["program"] + arms + ["note"])
        for p in progs:
            row = [p]
            for a in arms:
                v, n, detail = cells[p][a]
                row.append("%s (%s)" % (v, detail))
            note = "primary pair" if cells[p]["B"][0] != "undetermined" and cells[p]["C"][0] != "undetermined" else ""
            row.append(note)
            w.writerow(row)

    print(json.dumps({"rows": n_rows, "programs": len(progs),
                      "per_arm": {a: {k: v for k, v in per_arm[a].items()
                                      if k != "undetermined_programs"} for a in arms},
                      "primary": primary, "auxiliary": aux,
                      "verdict": verdict}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
