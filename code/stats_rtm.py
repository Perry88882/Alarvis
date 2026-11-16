#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""R1/R4/C1 real-source supplementary trial (project-level majority + Wilson +
paired exact McNemar).

No model calls; reads rtm_raw.jsonl, w01_raw.jsonl, and the queue.
R0/R3 are not re-called: their model input is identical to W01 clean/prot
(same input SHA-256), so their verdicts come from the W01 responses by
project-level majority.

Usage (from the repository root):
    python3 code/stats_rtm.py
Outputs (recompute_out/rtm/): rtm_stats.json, rtm_stats_cells.csv, rtm_stats.md
"""

import argparse
import csv
import json
import math
import os
from collections import defaultdict

PROJECTS = ["zlib", "cjson", "md4c", "libpng"]
CONDS = ["R0", "R1", "R3", "R4", "C1"]
# W01 version reused per condition
REUSE_VERSION = {"R0": "clean", "R3": "prot"}


def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return [0.0, 100.0]
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [100 * (mid - half), 100 * (mid + half)]


def binom_two_sided(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def vote(rows, key_fields, verdict_field="verdict", status_field="status"):
    v = [r for r in rows
         if all(r.get(f) == val for f, val in key_fields.items())
         and r.get(status_field) == "ok"
         and r.get(verdict_field) in ("malicious", "benign")]
    if len(v) < 2:
        return {"determined": False, "n_valid": len(v), "votes": [r.get(verdict_field) for r in v]}
    mal = sum(1 for r in v if r["verdict"] == "malicious")
    ben = len(v) - mal
    if mal > ben:
        verdict = "malicious"
    elif ben > mal:
        verdict = "benign"
    else:
        return {"determined": False, "n_valid": len(v), "votes": [r.get(verdict_field) for r in v]}
    return {"determined": True, "verdict": verdict, "n_valid": len(v),
            "votes": [r.get(verdict_field) for r in v]}


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=os.path.join(root, "data", "responses", "rtm_raw.jsonl"))
    ap.add_argument("--w01", default=os.path.join(root, "data", "responses", "w01_raw.jsonl"))
    ap.add_argument("--out", default=os.path.join(root, "recompute_out", "rtm"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    new = [json.loads(l) for l in open(args.raw, encoding="utf-8") if l.strip()]
    w01 = [r for r in (json.loads(l) for l in open(args.w01, encoding="utf-8") if l.strip())
           if r.get("model") == "deepseek"]

    cells = {}
    for proj in PROJECTS:
        for cond in CONDS:
            if cond in REUSE_VERSION:
                ver = REUSE_VERSION[cond]
                key = {"program": proj, "condition": ver, "model": "deepseek"}
                src = "w01"
            else:
                key = {"program": proj, "condition": cond, "model": "deepseek"}
                src = "rtm"
            rows = w01 if src == "w01" else new
            cells[(proj, cond)] = dict(vote(rows, key), source=src)

    # not administered: zlib R1
    cells[("zlib", "R1")] = {"determined": False, "n_valid": 0, "votes": [],
                             "source": "not_administered",
                             "note": "input identical to R0; the rename never reached the build"}

    stat = {"phase": "rtm", "unit": "project",
            "rule": "3 repeats per cell; >=2 valid votes and strict majority; otherwise undetermined",
            "cells": {"%s/%s" % k: v for k, v in cells.items()},
            "per_cond": {}, "paired": {}}

    for cond in CONDS:
        ks, ns, det = 0, 0, 0
        for proj in PROJECTS:
            c = cells[(proj, cond)]
            if c.get("determined"):
                det += 1
                ns += 1
                ks += 1 if c["verdict"] == "malicious" else 0
            elif c.get("n_valid", 0) >= 2:
                ns += 1  # tie/undetermined: in the denominator, not counted as an alarm
        ci = wilson(ks, ns) if ns else [0.0, 100.0]
        stat["per_cond"][cond] = {
            "projects_in_scope": 4 if cond != "R1" else 3,
            "denominator_determined": det,
            "malicious": ks,
            "rate_pct": round(100 * ks / ns, 1) if ns else None,
            "wilson95": [round(x, 1) for x in ci] if ns else None,
        }

    def paired(a, b):
        pairs = []
        for proj in PROJECTS:
            ca, cb = cells[(proj, a)], cells[(proj, b)]
            if ca.get("determined") and cb.get("determined"):
                pairs.append((proj, ca["verdict"], cb["verdict"]))
        bb = sum(1 for _, va, vb in pairs if va == "malicious" and vb == "benign")
        cc = sum(1 for _, va, vb in pairs if va == "benign" and vb == "malicious")
        n = bb + cc
        return {"n_pairs": len(pairs), "b": bb, "c": cc,
                "p_two_sided": binom_two_sided(bb, cc),
                "min_achievable_p": (2 / (2 ** n)) if n else None,
                "pairs": [{"project": p, a: va, b: vb} for p, va, vb in pairs]}

    stat["paired"]["R1_vs_R0"] = paired("R1", "R0")
    stat["paired"]["R3_vs_R0"] = paired("R3", "R0")
    stat["paired"]["R4_vs_R0"] = paired("R4", "R0")
    stat["paired"]["C1_vs_R0"] = paired("C1", "R0")
    stat["paired"]["C1_vs_R3"] = paired("C1", "R3")

    with open(os.path.join(args.out, "rtm_stats.json"), "w", encoding="utf-8") as f:
        json.dump(stat, f, ensure_ascii=False, indent=1)

    with open(os.path.join(args.out, "rtm_stats_cells.csv"), "w",
              encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["project", "cond", "source", "determined", "verdict",
                    "n_valid", "votes"])
        for (proj, cond), c in sorted(cells.items()):
            w.writerow([proj, cond, c["source"], c.get("determined"),
                        c.get("verdict", ""), c.get("n_valid"),
                        " ".join(c.get("votes", []))])

    lines = ["# Real-source supplementary trial (R1/R4/C1)", "",
             "Unit = project; 3 repeats per cell; >=2 valid votes and strict majority. "
             "R0/R3 reuse the W01 responses (identical input SHA-256).", "",
             "| Condition | Projects in scope | Determined | Malicious | Alarm rate | Wilson 95% |",
             "|---|---:|---:|---:|---:|---|"]
    for cond in CONDS:
        p = stat["per_cond"][cond]
        lines.append("| %s | %d | %d | %d | %s | %s |"
                     % (cond, p["projects_in_scope"], p["denominator_determined"],
                        p["malicious"],
                        ("%.1f%%" % p["rate_pct"]) if p["rate_pct"] is not None else "—",
                        p["wilson95"] or "—"))
    lines += ["", "| Contrast | Valid pairs | First only malicious | Second only malicious | Two-sided exact p | Smallest attainable p at this n |",
              "|---|---:|---:|---:|---:|---:|"]
    for name, d in stat["paired"].items():
        lines.append("| %s | %d | %d | %d | %.4f | %s |"
                     % (name, d["n_pairs"], d["b"], d["c"], d["p_two_sided"],
                        ("%.3f" % d["min_achievable_p"]) if d["min_achievable_p"] else "—"))
    lines += ["", "> With n<=4 the two-sided exact test cannot return p below 0.125; this table is descriptive only."]
    with open(os.path.join(args.out, "rtm_stats.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
