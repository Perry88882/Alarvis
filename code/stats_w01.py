#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W01 statistics: project-level verdicts, paired table, exact McNemar, Holm.

Usage (from the repository root): python3 code/stats_w01.py
Reads only the archived raw responses and input_manifest.csv; no model calls.
"""

import argparse
import csv
import json
import math
import os
from collections import Counter, defaultdict

MAL, BEN = "malicious", "benign"
MODELS = ("deepseek", "gemini")
PILOT = {"bzip2", "lua"}


def exact_mcnemar(b, c):
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n) * 2
    return min(1.0, p)


def holm(pvals):
    """pvals: dict name -> p. Returns name -> adjusted p."""
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items)
    out, prev = {}, 0.0
    for i, (k, p) in enumerate(items):
        adj = min(1.0, max(prev, (m - i) * p))
        out[k] = adj
        prev = adj
    return out


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=os.path.join(root, "data", "responses", "w01_raw.jsonl"))
    ap.add_argument("--manifest", default=os.path.join(root, "data", "manifests", "w01_input_manifest.csv"))
    ap.add_argument("--out", default=os.path.join(root, "recompute_out", "w01"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    manifest = {}
    if os.path.isfile(args.manifest):
        with open(args.manifest, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                manifest[r["tag"]] = r

    votes = defaultdict(list)
    terminal = Counter()
    n_rows = 0
    if os.path.isfile(args.raw):
        with open(args.raw, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                n_rows += 1
                key = (r.get("model"), r.get("program"), r.get("condition"))
                if r.get("status") != "ok":
                    terminal["transport_error"] += 1
                    continue
                if r.get("verdict") in (MAL, BEN):
                    votes[key].append(r["verdict"])
                else:
                    terminal[r.get("status") or "unknown"] += 1

    def project_verdict(model, project, version):
        v = votes.get((model, project, version), [])
        if len(v) < 2:
            return None, len(v)
        nmal = sum(1 for x in v if x == MAL)
        if nmal * 2 == len(v):
            return None, len(v)  # a tie is undetermined, never benign
        return (MAL if nmal * 2 > len(v) else BEN), len(v)

    projects = sorted({p for (_, p, _) in votes} | set(
        t.rsplit("_", 1)[0] for t in manifest))
    result = {"n_raw_rows": n_rows, "terminal": dict(terminal), "models": {}}

    for model in MODELS:
        table = []
        for p in projects:
            cv, cn = project_verdict(model, p, "clean")
            pv, pn = project_verdict(model, p, "prot")
            table.append({"project": p, "pilot_overlap": p in PILOT,
                          "clean": cv, "clean_valid": cn,
                          "prot": pv, "prot_valid": pn})
        b = sum(1 for r in table if r["prot"] == MAL and r["clean"] == BEN)
        c = sum(1 for r in table if r["clean"] == MAL and r["prot"] == BEN)
        both_mal = sum(1 for r in table if r["clean"] == MAL and r["prot"] == MAL)
        both_ben = sum(1 for r in table if r["clean"] == BEN and r["prot"] == BEN)
        unknown = sum(1 for r in table if r["clean"] is None or r["prot"] is None)
        known = len(table) - unknown

        def summarize(rows):
            bb = sum(1 for r in rows if r["prot"] == MAL and r["clean"] == BEN)
            cc = sum(1 for r in rows if r["clean"] == MAL and r["prot"] == BEN)
            return {"n": len(rows),
                    "clean_mal": sum(1 for r in rows if r["clean"] == MAL),
                    "prot_mal": sum(1 for r in rows if r["prot"] == MAL),
                    "both_mal": sum(1 for r in rows if r["clean"] == MAL and r["prot"] == MAL),
                    "both_ben": sum(1 for r in rows if r["clean"] == BEN and r["prot"] == BEN),
                    "b_only_prot": bb, "c_only_clean": cc,
                    "unknown": sum(1 for r in rows if r["clean"] is None or r["prot"] is None),
                    "p_exact": exact_mcnemar(bb, cc)}

        result["models"][model] = {
            "all": summarize(table),
            "main10": summarize([r for r in table if not r["pilot_overlap"]]),
            "projects": table,
            "input_tokens": sum(int(manifest.get("%s_clean" % p, {}).get("total_tokens_est", 0))
                                + int(manifest.get("%s_prot" % p, {}).get("total_tokens_est", 0))
                                for p in projects),
        }

    # Holm (two-model primary analysis): reported only when both models have
    # a fully determined paired table.
    pv = {}
    for m in MODELS:
        s = result["models"][m]["main10"]
        if s["unknown"] == 0 and (s["b_only_prot"] + s["c_only_clean"]) > 0:
            pv[m] = s["p_exact"]
    if len(pv) == 2:
        adj = holm(pv)
        for m in MODELS:
            result["models"][m]["main10"]["p_holm"] = adj[m]

    result["n_projects"] = len(projects)
    result["pending"] = n_rows == 0
    out_json = os.path.join(args.out, "w01_stats.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=1)

    lines = ["# W01 statistics (%s)" % ("pending: no raw file" if n_rows == 0 else "raw loaded"),
             "",
             "Unit = project; 3 repeats per model per version, strict majority "
             "(>=2 valid votes); fewer than 2 or a tie is undetermined.",
             ""]
    if n_rows == 0:
        lines.append("No raw records present; no p values reported.")
    else:
        lines += ["| Model | Analysis set | n | clean malicious | prot malicious | b (prot only) | c (clean only) | Undetermined | Exact p | Holm p |",
                  "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for m in MODELS:
            for name, key in (("primary: 10 new projects", "main10"), ("sensitivity: 12 projects", "all")):
                s = result["models"][m][key]
                lines.append("| %s | %s | %d | %d | %d | %d | %d | %d | %s | %s |"
                             % (m, name, s["n"], s["clean_mal"], s["prot_mal"],
                                s["b_only_prot"], s["c_only_clean"], s["unknown"],
                                ("%.4f" % s["p_exact"]) if s["unknown"] == 0 else "—",
                                ("%.4f" % s["p_holm"]) if "p_holm" in s else "—"))
    out_md = os.path.join(args.out, "w01_stats.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %s / %s" % (out_json, out_md))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
