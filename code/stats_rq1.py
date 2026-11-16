#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RQ1 four-cell interaction statistics (program-level, paired).

Frozen estimator:
    y = 1 if the program's strict-majority verdict is "malicious" (alarm)
    d_i = y11 - y01 - y10 + y00
    Delta = mean_i d_i            (percentage points when x100)

Cells are supplied by name, e.g.:
    --cells S0,D0,St_str,Dt_str
    (S0 = no protection / source, D0 = no protection / decompiled,
     St = protected source, Dt = protected decompiled)

Only programs with a valid strict-majority verdict in ALL FOUR cells enter
the primary analysis.  Programs dropped for invalid/insufficient are counted
and reported separately.

Reports:
  * four cell alarm counts / denominators
  * Delta in percentage points
  * program-level bootstrap 95% CI (resampling programs, fixed seed)
  * exact two-sided sign test on d_i != 0
  * transition counts between cells
No API; input is the verdict CSV from aggregate_queue.py.
"""

import argparse
import csv
import json
import math
import random
import sys
from collections import defaultdict


def binom_two_sided(k, n):
    """Exact two-sided sign test p for k successes out of n (p0=0.5)."""
    if n == 0:
        return 1.0
    k = max(k, n - k)
    tail = sum(math.comb(n, i) for i in range(k, n + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def load_verdicts(path):
    data = defaultdict(dict)
    labels = {}
    status = {}
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            key = (r["queue"], r["program"])
            data[key][r["condition"]] = r["verdict"]
            labels[key] = r["label"]
            status[(key, r["condition"])] = r["status"]
    return data, labels, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--cells", required=True,
                    help="S0,D0,St,Dt in that order")
    ap.add_argument("--queue", required=True)
    ap.add_argument("--label", default="benign")
    ap.add_argument("--bootstrap", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20261104)
    ap.add_argument("--out", default="")
    ap.add_argument("--include", default="",
                    help="file with one program name per line; only these "
                         "programs enter the analysis (e.g. rename_applicable)")
    args = ap.parse_args()

    cells = [c.strip() for c in args.cells.split(",")]
    if len(cells) != 4:
        sys.exit("--cells must be exactly 4 condition names, e.g. S0,D0,St_str,Dt_str")
    data, labels, status = load_verdicts(args.verdicts)

    include = None
    if args.include:
        with open(args.include, encoding="utf-8") as f:
            include = {line.strip() for line in f if line.strip()}

    used, dropped, not_applicable = [], [], []
    for key, conds in data.items():
        q, prog = key
        if q != args.queue or labels.get(key) != args.label:
            continue
        if include is not None and prog not in include:
            not_applicable.append(key)
            continue
        if all(conds.get(c) in ("malicious", "benign")
               and status.get((key, c)) == "ok" for c in cells):
            used.append(key)
        else:
            dropped.append(key)

    def alarm(key, c):
        return 1 if data[key][c] == "malicious" else 0

    n = len(used)
    if n == 0:
        sys.exit("no program has a valid verdict in all four cells; cannot compute")
    counts = {c: sum(alarm(k, c) for k in used) for c in cells}
    rates = {c: counts[c] / n for c in cells}

    d = [alarm(k, cells[3]) - alarm(k, cells[1])
         - alarm(k, cells[2]) + alarm(k, cells[0]) for k in used]
    delta = sum(d) / n

    pos = sum(1 for x in d if x > 0)
    neg = sum(1 for x in d if x < 0)
    p_sign = binom_two_sided(max(pos, neg), pos + neg)

    rng = random.Random(args.seed)
    boots = []
    for _ in range(args.bootstrap):
        acc = 0
        for _i in range(n):
            acc += d[rng.randrange(n)]
        boots.append(acc / n)
    boots.sort()
    lo = boots[int(0.025 * (len(boots) - 1))]
    hi = boots[int(0.975 * (len(boots) - 1))]

    trans = defaultdict(int)
    for k in used:
        trans[(alarm(k, cells[0]), alarm(k, cells[1]),
               alarm(k, cells[2]), alarm(k, cells[3]))] += 1

    print("queue=%s label=%s cells=%s" % (args.queue, args.label, cells))
    print("programs used=%d dropped=%d not_applicable=%d"
          % (n, len(dropped), len(not_applicable)))
    for c in cells:
        print("  %-6s alarm %2d/%2d = %5.1f%%" %
              (c, counts[c], n, rates[c] * 100))
    print("Delta = (p11-p01)-(p10-p00) = %+.1f pp" % (delta * 100))
    print("bootstrap 95%% CI = [%+.1f, %+.1f] pp (B=%d, seed=%d)"
          % (lo * 100, hi * 100, args.bootstrap, args.seed))
    from collections import Counter
    dist = dict(sorted(Counter(d).items()))
    print("d_i distribution %s ; +%d/0/%d ; sign test p=%.4g"
          % (dist, pos, neg, p_sign))
    print("transitions (S0,D0,St,Dt) -> count:")
    for t in sorted(trans):
        print("  %s : %d" % (t, trans[t]))
    if dropped:
        print("dropped (invalid/insufficient in >=1 cell):")
        for k in dropped[:20]:
            print("  %s/%s" % k)

    result = dict(queue=args.queue, label=args.label, cells=cells, n=n,
                  dropped=len(dropped),
                  not_applicable=len(not_applicable), counts=counts, rates=rates,
                  delta_pp=delta * 100, ci_pp=[lo * 100, hi * 100],
                  d_pos=pos, d_zero=n - pos - neg, d_neg=neg,
                  p_sign=p_sign, seed=args.seed, bootstrap=args.bootstrap,
                  transitions={"".join(map(str, t)): v
                               for t, v in trans.items()})
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
