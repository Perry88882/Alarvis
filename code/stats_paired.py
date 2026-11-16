#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic program-level paired comparison for the RQ3 / real-source queues.

Input: verdict CSV from aggregate_queue.py.
Each pair is (base condition, target condition) on the same program; only
programs with valid strict-majority verdicts in both cells enter.

Reports the 2x2 transition table, exact two-sided McNemar p, risk difference
in percentage points, and a program-level bootstrap 95% CI.  Holm correction
is applied across all pairs passed on one invocation.

Example:
    python3 stats_paired.py --verdicts v.csv --queue RQ3 \
        --pairs E0:ES,E0:EA,E0:ESA,SN:ST

Zero API cost.
"""

import argparse
import csv
import json
import math
import random
import sys
from collections import defaultdict


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = max(b, c)
    tail = sum(math.comb(n, i) for i in range(k, n + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - r) / d, (c + r) / d)


def holm(ps):
    """Return Holm-adjusted p in the input order."""
    m = len(ps)
    order = sorted(range(m), key=lambda i: ps[i])
    adj = [1.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        val = min(1.0, (m - rank) * ps[i])
        running = max(running, val)
        adj[i] = running
    return adj


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--queue", required=True)
    ap.add_argument("--pairs", required=True,
                    help="comma list base:target, e.g. E0:ES,E0:EA")
    ap.add_argument("--label", default="benign")
    ap.add_argument("--bootstrap", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20261104)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    pairs = []
    for p in args.pairs.split(","):
        a, b = p.split(":")
        pairs.append((a.strip(), b.strip()))

    data = defaultdict(dict)
    labels = {}
    status = {}
    with open(args.verdicts, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            key = (r["queue"], r["program"])
            data[key][r["condition"]] = r["verdict"]
            labels[key] = r["label"]
            status[(key, r["condition"])] = r["status"]

    rng = random.Random(args.seed)
    out = []
    for base, target in pairs:
        used = [k for k, c in data.items()
                if k[0] == args.queue and labels.get(k) == args.label
                and c.get(base) in ("malicious", "benign")
                and c.get(target) in ("malicious", "benign")
                and status.get((k, base)) == "ok"
                and status.get((k, target)) == "ok"]
        n = len(used)
        if n == 0:
            out.append(dict(base=base, target=target, n=0, note="no valid pairs"))
            continue
        y0 = [1 if data[k][base] == "malicious" else 0 for k in used]
        y1 = [1 if data[k][target] == "malicious" else 0 for k in used]
        b = sum(1 for a, c in zip(y0, y1) if a == 0 and c == 1)
        c_ = sum(1 for a, c in zip(y0, y1) if a == 1 and c == 0)
        both1 = sum(1 for a, c in zip(y0, y1) if a == 1 and c == 1)
        both0 = sum(1 for a, c in zip(y0, y1) if a == 0 and c == 0)
        p = mcnemar_exact(b, c_)
        diff = sum(y1) / n - sum(y0) / n
        boots = []
        for _ in range(args.bootstrap):
            acc = 0
            for _i in range(n):
                i = rng.randrange(n)
                acc += y1[i] - y0[i]
            boots.append(acc / n)
        boots.sort()
        lo = boots[int(0.025 * (len(boots) - 1))]
        hi = boots[int(0.975 * (len(boots) - 1))]
        out.append(dict(base=base, target=target, n=n,
                        base_rate=sum(y0) / n * 100,
                        target_rate=sum(y1) / n * 100,
                        diff_pp=diff * 100, ci_pp=[lo * 100, hi * 100],
                        both0=both0, both1=both1,
                        new_alarm=b, resolved=c_, p=p))

    ps = [r["p"] for r in out if "p" in r]
    adj = holm(ps)
    it = iter(adj)
    for r in out:
        if "p" in r:
            r["p_holm"] = next(it)

    for r in out:
        print("=" * 72)
        print("%s -> %s  n=%s" % (r["base"], r["target"], r["n"]))
        if "p" not in r:
            print("  " + r.get("note", ""))
            continue
        print("  base=%.1f%% (%d/%d) target=%.1f%% (%d/%d) diff=%+.1f pp CI[%+.1f,%+.1f]"
              % (r["base_rate"], round(r["base_rate"] * n / 100), n,
                 r["target_rate"], round(r["target_rate"] * n / 100), n,
                 r["diff_pp"], r["ci_pp"][0], r["ci_pp"][1]))
        print("  both0=%d both1=%d new=%d resolved=%d  McNemar p=%.4g  Holm p=%.4g"
              % (r["both0"], r["both1"], r["new_alarm"], r["resolved"],
                 r["p"], r["p_holm"]))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
