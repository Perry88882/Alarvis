#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check recompute_out/ against the published summary files and paper numbers.

Usage (from the repository root, after code/run_all.py):
    python3 code/verify_outputs.py

Exits 0 when every check passes, 1 otherwise.  Comparisons on floating-point
values use an absolute tolerance of 1e-6.
"""

import csv
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "recompute_out")
SUMM = os.path.join(ROOT, "data", "results", "summaries")
TOL = 1e-6

results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))


def close(a, b):
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= TOL
    return a == b


def same_json(a, b, path=""):
    """Recursively compare two JSON values; return first mismatch or None."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                return "%s.%s missing on one side" % (path, k)
            m = same_json(a[k], b[k], "%s.%s" % (path, k))
            if m:
                return m
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return "%s length %d vs %d" % (path, len(a), len(b))
        for i, (x, y) in enumerate(zip(a, b)):
            m = same_json(x, y, "%s[%d]" % (path, i))
            if m:
                return m
        return None
    return None if close(a, b) else "%s: %r vs %r" % (path, a, b)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def majority(vals):
    v = [x for x in vals if x in ("malicious", "benign")]
    if not v:
        return None
    m = v.count("malicious")
    if m * 2 > len(v):
        return "malicious"
    if (len(v) - m) * 2 > len(v):
        return "benign"
    return None


def check_hist_table(csv_name, hist_key, conds, prefix, label):
    """Compare a verdict CSV with the recomputed per-model benign cells."""
    path = os.path.join(ROOT, "data", "results", "verdicts", csv_name)
    groups = defaultdict(lambda: defaultdict(list))
    with open(path, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if not r["program"].startswith(prefix):
                continue
            groups[(r["model"], r["condition"])][r["program"]].append(r["verdict"])
    bad = []
    for model, block in hist_key.items():
        for display, key in conds:
            vals = [majority(v) for v in groups[(model, display)].values()]
            valid = [v for v in vals if v]
            k = sum(1 for v in valid if v == "malicious")
            if "cells" in block:
                want = block["cells"][key + "|" + label]
            else:
                want = block["conditions"][key][label]
            if k != want["k"] or len(valid) != want["n"]:
                bad.append((model, display, k, len(valid), want["k"], want["n"]))
    check("%s verdict table matches recompute" % csv_name, not bad, str(bad[:3]))


def compare_summary(name, published_name, recomputed_name):
    pub = load(os.path.join(SUMM, published_name))
    got = load(os.path.join(OUT, recomputed_name))
    # The raw-input path recorded by mech/rtm differs by design.
    if isinstance(pub, dict) and "raw" in pub and "raw" in got:
        pub = dict(pub, raw="<path>")
        got = dict(got, raw="<path>")
    m = same_json(pub, got)
    check("matches data/results/summaries/%s" % published_name, m is None, m or "")


def main():
    hist = load(os.path.join(OUT, "historical_recompute.json"))
    a = hist["alpha"]
    check("alpha: 9 models", len(a["models"]) == 9, str(len(a["models"])))
    d = a["delta_fpr"]
    check("alpha H1->H3 mean = +29.8", close(round(d["1->2"]["mean"], 2), 29.78))
    check("alpha H3->H4 mean = +36.6", close(round(d["2->3"]["mean"], 2), 36.58))
    check("alpha H1->H4 mean = +66.4", close(round(d["1->3"]["mean"], 2), 66.36))
    check("alpha H1->H4 sd = 12.4", close(round(d["1->3"]["sd"], 2), 12.44))
    check("alpha: all models c=0 on H1->H4",
          all(x["paired"]["1->3|benign"]["after_correct"] == 0
              for x in a["models"].values()))
    check("beta: 8 models", len(hist["beta"]) == 8, str(len(hist["beta"])))

    check_hist_table("alpha_verdicts.csv", a["models"],
                     [("H1", "1"), ("H3", "2"), ("H4", "3")], "hb", "benign")
    check_hist_table("beta_verdicts.csv", hist["beta"],
                     [("L%d" % i, str(i + 1)) for i in range(6)], "b", "benign")

    m03 = hist["M03"]
    ds, gm = m03["main_B_vs_C"]["deepseek"], m03["main_B_vs_C"]["gemini"]
    check("M03 DeepSeek B vs C = 9/0", (ds["b_only"], ds["c_only"]) == (9, 0))
    check("M03 DeepSeek p = 0.00390625", close(ds["p_exact"], 0.00390625))
    check("M03 Gemini B vs C = 3/0", (gm["b_only"], gm["c_only"]) == (3, 0))

    m04 = hist["M04"]
    check("M04 DeepSeek P1 = 17/20",
          (m04["cells"]["deepseek|P1|raw"]["malicious"],
           m04["cells"]["deepseek|P1|raw"]["n"]) == (17, 20))
    check("M04 Gemini P1 = 17/17",
          (m04["cells"]["gemini|P1|raw"]["malicious"],
           m04["cells"]["gemini|P1|raw"]["n"]) == (17, 17))
    b = hist["M04b"]["by_version"]
    check("M04b clean = 0/8", (b["clean"]["malicious"], b["clean"]["valid"]) == (0, 8))
    check("M04b protected = 3/8", (b["protected"]["malicious"], b["protected"]["valid"]) == (3, 8))

    compare_summary("rq1_dyn", "rq1_stats_dyn.json", "rq1/rq1_stats_dyn.json")
    compare_summary("rq1_str", "rq1_stats_str.json", "rq1/rq1_stats_str.json")
    compare_summary("rq1_rename", "rq1_stats_rename.json", "rq1/rq1_stats_rename.json")
    compare_summary("rq3_main", "rq3_stats_main.json", "rq3/rq3_stats_main.json")
    compare_summary("rq3_n28", "rq3_stats_main_n28.json", "rq3/rq3_stats_main_n28.json")
    compare_summary("rq3_aux", "rq3_stats_aux.json", "rq3/rq3_stats_aux.json")
    compare_summary("real", "real_stats.json", "real/real_stats.json")

    rq1d = load(os.path.join(OUT, "rq1", "rq1_stats_dyn.json"))
    check("RQ1 dyn: n=40, Delta=+27.5 pp",
          rq1d["n"] == 40 and close(round(rq1d["delta_pp"], 1), 27.5))
    rq1r = load(os.path.join(OUT, "rq1", "rq1_stats_rename.json"))
    check("RQ1 rename: n=26, Delta=-3.8 pp",
          rq1r["n"] == 26 and close(round(rq1r["delta_pp"], 1), -3.8))

    rq3 = {r["target"]: r for r in load(os.path.join(OUT, "rq3", "rq3_stats_main.json"))}
    check("RQ3 E0=14/30", close(rq3["ES"]["base_rate"], 46.6666667))
    check("RQ3 ES=4/30", close(rq3["ES"]["target_rate"], 13.3333333))
    check("RQ3 EA=18/30", close(rq3["EA"]["target_rate"], 60.0))
    check("RQ3 ESA=3/30", close(rq3["ESA"]["target_rate"], 10.0))

    real = {r["target"]: r for r in load(os.path.join(OUT, "real", "real_stats.json"))}
    check("REAL C3=8/8", close(real["C3"]["target_rate"], 100.0))
    check("REAL C4=0/8", close(real["C4"]["target_rate"], 0.0))
    check("REAL C0->C3 Holm p=0.03125", close(real["C3"]["p_holm"], 0.03125))

    w01 = load(os.path.join(OUT, "w01", "w01_stats.json"))
    ds10, gm10 = w01["models"]["deepseek"]["main10"], w01["models"]["gemini"]["main10"]
    check("W01 DeepSeek clean/prot = 0/1", (ds10["clean_mal"], ds10["prot_mal"]) == (0, 1))
    check("W01 DeepSeek p=1.0", close(ds10["p_exact"], 1.0))
    check("W01 Gemini clean/prot = 0/3", (gm10["clean_mal"], gm10["prot_mal"]) == (0, 3))
    check("W01 Gemini p=0.25, Holm=0.5",
          close(gm10["p_exact"], 0.25) and close(gm10["p_holm"], 0.5))

    mech = load(os.path.join(OUT, "mech", "mech_stats.json"))
    check("MECH A/B/C/D/E = 0/28/0/16/27",
          [mech["per_arm"][x]["malicious"] for x in "ABCDE"] == [0, 28, 0, 16, 27])
    check("MECH B vs C p = 7.450580596923828e-09",
          close(mech["primary"]["p_two_sided"], 7.450580596923828e-09))

    rtm = load(os.path.join(OUT, "rtm", "rtm_stats.json"))["per_cond"]
    check("RTM R4=1/4, others 0",
          rtm["R4"]["malicious"] == 1 and rtm["R4"]["denominator_determined"] == 4
          and all(rtm[x]["malicious"] == 0 for x in ("R0", "R1", "R3", "C1")))

    width = max(len(n) for n, _, _ in results)
    failed = 0
    for name, ok, detail in results:
        print("%-*s  %s%s" % (width, name, "PASS" if ok else "FAIL",
                              "" if ok else "  " + detail))
        failed += 0 if ok else 1
    print("\n%d checks, %d failed." % (len(results), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
