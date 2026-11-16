# Alarvis artifact

Response records and offline recomputation scripts for the paper
**“Alarvis: Diagnosing False Alarms in Large Language Model Executable
Analysis.”**

This repository contains the response-level records behind the paper's
program-level tables and every script needed to rebuild those tables from
scratch. Nothing here calls a model or the network.

## Quick start

Requires Python 3.8 or newer; the scripts use only the standard library.

```bash
python3 code/run_all.py        # rebuild all tables and statistics
python3 code/verify_outputs.py # compare with data/results/summaries/
sha256sum -c checksums/SHA256SUMS.txt   # confirm the checkout is unmodified
```

`run_all.py` writes `recompute_out/` (generated, not tracked). `verify_outputs.py`
prints 39 checks and exits 0 when all pass.

Expected final line:

```
39 checks, 0 failed.
```

## What is included

| Path | Contents |
|---|---|
| `data/responses/` | One JSONL file per cohort: one row per model request |
| `data/results/verdicts/` | Program-level verdict tables (strict majority of valid votes) |
| `data/manifests/` | Build status, terminal states, input manifests, reuse map |
| `data/results/summaries/` | The statistics files reported in the paper |
| `code/` | Offline aggregation and statistics code |
| `prompts/` | The final-round prompt, byte-exact, with its SHA-256 |
| `experiments/` | Cohort definitions, data dictionary, release policy |
| `checksums/` | SHA-256 of every tracked file |

## What is not included

- No program source code, decompiled code, PE files, or obfuscated binaries.
- No model reasoning / chain-of-thought.
- The only response text retained is the one-word verdict (`恶意` / `正常`,
  or an equivalent short label) needed to recompute the tables.
- No API keys, endpoints, credentials, or personal data.

See `experiments/safety.md` for the release policy and `experiments/data-dictionary.md` for every field.

## Cohorts

| Cohort | Design | Responses | Program-level cells |
|---|---|---:|---:|
| `alpha` | 9 models × 3 stages (H1/H3/H4) × 10 repeats × 40 programs | 10,857 | 1,080 |
| `beta` | 8 models × 6 levels (L0–L5) × 10 repeats × 40 programs | 19,242 | 1,920 |
| `M03` | 2 models × 4 arms × 5 repeats × 20 programs | 802 | 160 |
| `W01` | 2 models × 2 versions × 3 repeats × 12 projects | 144 | 48 |
| `M04` | 2 models × 3 versions × 3 repeats × 54 project-versions | 333 | 108 |
| `MECH` | 1 model × 5 arms × 5 repeats × 30 programs | 761 | 150 |
| `RTM` | 1 model × 3 administered conditions × 3 repeats × 4 projects | 33 | 20 |
| `BRIDGE` | 2 models × 2 versions × 2 repeats × 2 pilot projects | 16 | 8 |
| `RQ1` | 1 model × 8 conditions × 3 repeats × 60 programs | 1,452 | 480 |
| `RQ3` | 1 model × 7 conditions × 3 repeats × 30 programs | 644 | 210 |
| `REAL` | 1 model × 4 conditions × 3 repeats × 8 projects | 96 | 32 (+8 reused C4) |

Row counts exceed the nominal design where a request was retried; retries carry
a distinct `attempt` value and are all retained. The verdict tables collapse
retries by strict majority. `experiments/cohorts.md` gives the condition definitions.

## Headline recomputed results

| Analysis | Result |
|---|---|
| α false-alarm increase, H1→H4 | +66.4 pp (mean over 9 models; sd 12.4) |
| RQ1 four-cell interaction (n=40) | Δ = +27.5 pp, 95% CI [12.5, 42.5], sign-test p = 0.0034 |
| RQ3 E0→ES (n=28, primary) | 12/28 → 4/28, McNemar p = 0.0078, Holm p = 0.0156 |
| RQ3 E0→ESA (n=28, primary) | 12/28 → 3/28, McNemar p = 0.0039, Holm p = 0.0117 |
| REAL C0→C3 | 0/8 → 8/8, p = 0.0078, Holm p = 0.031 |
| REAL C3→C4 | 8/8 → 0/8, p = 0.0078, Holm p = 0.031 |
| MECH B vs C (30 programs) | 28/30 vs 0/30, exact McNemar p = 7.45 × 10⁻⁹ |
| W01 Gemini clean vs protected | 0/10 vs 3/10, p = 0.25 (Holm 0.5) |
| M03 DeepSeek B vs C | 9 vs 0 discordant programs, p = 0.0039 |

The RQ3 **prespecified main analysis** excludes two programs whose API state was
partly visible to the model; the frozen `n=28` table is
`data/results/verdicts/rq3_verdicts_n28.csv` and the headline rows above use it.
The all-30 set is the sensitivity analysis (E0/ES/EA/ESA = 14/4/18/3 alarms;
Holm p = 0.0039, 0.1250, 0.0029) and is reported in the manuscript appendix; its
statistics are `data/results/summaries/rq3_stats_main.json`. The four-project RTM
trial is descriptive only: with at most four pairs, the smallest attainable
two-sided p is 0.125.

## Prompt and model access

- The final-round prompt is `prompts/base_prompt_zh.txt`, SHA-256
  `410aabf1…f50c`. Each request sends it as the single user message followed by
  two newlines and the input code; temperature 0, non-streaming.
- Final-round cohorts (`RQ1`, `RQ3`, `REAL`) use the official DeepSeek endpoint,
  model `deepseek-flash`.
- `M03`, `W01`, `M04`, and `BRIDGE` use DeepSeek and Gemini.
- Historical `alpha` / `beta` span nine and eight model families respectively.
- Non-DeepSeek models were reached through a commercial API aggregation service.
  The service is not identified in the paper or in these files.

## Reproducing the paper

`REPRODUCE.md` gives the exact commands, the mapping from each output file to the
corresponding table in the paper, and the interpretation rules (strict majority,
minimum valid votes, tie handling, Holm correction).

## License

Code: MIT (`LICENSE`). Response records and derived tables: CC BY 4.0
(`DATA_LICENSE.md`). Third-party project names remain the property of their
respective projects; no third-party code is redistributed.

## Citation

Please cite the paper. A BibTeX entry will be added when the submission record
is public.
