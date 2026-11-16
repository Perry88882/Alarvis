#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recompute every program-level table and statistic from data/.

Usage (from the repository root):
    python3 code/run_all.py

Reads only data/responses/*.jsonl plus data/manifests/*.csv.
Writes recompute_out/.  No network access, no API calls, no API keys.
"""

import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS = os.path.join(ROOT, "code")
RESP = os.path.join(ROOT, "data", "responses")
META = os.path.join(ROOT, "data", "manifests")
VERD = os.path.join(ROOT, "data", "results", "verdicts")
OUT = os.path.join(ROOT, "recompute_out")


def run(*args, **kwargs):
    script = os.path.join(SCRIPTS, args[0])
    rest = list(args[1:])
    cmd = [sys.executable, script] + rest
    shown = ["python3", os.path.relpath(script, ROOT).replace(os.sep, "/")]
    shown += [os.path.relpath(a, ROOT).replace(os.sep, "/")
              if os.path.isabs(a) else a for a in rest]
    print("\n$ " + " ".join(shown))
    subprocess.run(cmd, check=True, cwd=ROOT, **kwargs)


def main():
    for sub in ("rq1", "rq3", "real", "w01", "mech", "rtm"):
        os.makedirs(os.path.join(OUT, sub), exist_ok=True)

    # 1. Historical cohorts: alpha, beta, M03, M04, bridge pilot.
    run("recompute_historical.py")

    # 2. Program-level verdicts for the final round.
    run("aggregate_queue.py",
        "--raw", os.path.join(RESP, "rq1_raw.jsonl"),
        "--out", os.path.join(OUT, "rq1", "rq1_verdicts.csv"),
        "--require", "3")
    run("aggregate_queue.py",
        "--raw", os.path.join(RESP, "rq3_raw.jsonl"),
        "--out", os.path.join(OUT, "rq3", "rq3_verdicts.csv"),
        "--require", "3")
    run("aggregate_queue.py",
        "--raw", os.path.join(RESP, "real_raw.jsonl"),
        "--out", os.path.join(OUT, "real", "real_verdicts.csv"),
        "--require", "3")

    # 3. RQ1 four-cell interaction.
    for tag, cells, include in (
        ("dyn", "S0,D0,St_dyn,Dt_dyn", None),
        ("str", "S0,D0,St_str,Dt_str", None),
        ("rename", "S0,D0,St_rename,Dt_rename",
         os.path.join(META, "rename_applicable_benign.txt")),
    ):
        extra = ["--include", include] if include else []
        run("stats_rq1.py",
            "--verdicts", os.path.join(OUT, "rq1", "rq1_verdicts.csv"),
            "--queue", "RQ1", "--cells", cells,
            "--out", os.path.join(OUT, "rq1", "rq1_stats_%s.json" % tag),
            *extra)

    # 4. RQ3 recovery paths: primary (n=30), sensitivity (n=28), auxiliary.
    run("stats_paired.py",
        "--verdicts", os.path.join(OUT, "rq3", "rq3_verdicts.csv"),
        "--queue", "RQ3", "--pairs", "E0:ES,E0:EA,E0:ESA",
        "--out", os.path.join(OUT, "rq3", "rq3_stats_main.json"))
    run("stats_paired.py",
        "--verdicts", os.path.join(VERD, "rq3_verdicts_n28.csv"),
        "--queue", "RQ3", "--pairs", "E0:ES,E0:EA,E0:ESA",
        "--out", os.path.join(OUT, "rq3", "rq3_stats_main_n28.json"))
    run("stats_paired.py",
        "--verdicts", os.path.join(OUT, "rq3", "rq3_verdicts.csv"),
        "--queue", "RQ3", "--pairs", "S0:ST,S0:SN,SN:ST",
        "--out", os.path.join(OUT, "rq3", "rq3_stats_aux.json"))

    # 5. Real-source cohort.  C4 reuses C0 where the input SHA-256 matches.
    run("merge_real_reuse.py",
        "--verdicts", os.path.join(OUT, "real", "real_verdicts.csv"),
        "--reuse", os.path.join(META, "real_reuse_source.csv"),
        "--out", os.path.join(OUT, "real", "real_verdicts_c4.csv"))
    run("stats_paired.py",
        "--verdicts", os.path.join(OUT, "real", "real_verdicts_c4.csv"),
        "--queue", "REAL", "--pairs", "C0:C1,C0:C2,C0:C3,C3:C4",
        "--out", os.path.join(OUT, "real", "real_stats.json"))

    # 6. Source-protection and mechanism cohorts.
    run("stats_w01.py")
    run("stats_mech.py")
    run("stats_rtm.py")

    print("\nRecomputed outputs are under recompute_out/.")
    print("Run `python3 code/verify_outputs.py` to compare against the "
          "published summary files.")


if __name__ == "__main__":
    main()
