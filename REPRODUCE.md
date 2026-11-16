# Reproducing the tables and statistics

Everything below runs offline from the files in `data/`. No model is called and
no network connection is used.

## Requirements

- Python 3.8 or newer (tested with CPython 3.11). On Windows, `py -3` works
  wherever the commands below say `python3`.
- No third-party packages. `code/` imports only the standard library.

## One command

From the repository root:

```bash
python3 code/run_all.py
```

This rebuilds, in order:

1. `recompute_out/historical_recompute.{json,md}` — α, β, M03, M04, bridge.
2. `recompute_out/rq1/rq1_verdicts.csv` — 480 program-level RQ1 cells.
3. `recompute_out/rq3/rq3_verdicts.csv` — 210 program-level RQ3 cells.
4. `recompute_out/real/real_verdicts.csv` — 32 program-level REAL cells.
5. `recompute_out/rq1/rq1_stats_{dyn,str,rename}.json`.
6. `recompute_out/rq3/rq3_stats_{main,main_n28,aux}.json`.
7. `recompute_out/real/real_verdicts_c4.csv` and `real_stats.json`.
8. `recompute_out/w01/w01_stats.{json,md}`.
9. `recompute_out/mech/mech_stats.{json,csv}`.
10. `recompute_out/rtm/rtm_stats.{json,md,csv}`.

Runtime is a few seconds. The bootstrap procedures use a fixed seed
(`20261104`) and 10,000 resamples, so confidence intervals are byte-identical
across runs.

## Verification

```bash
python3 code/verify_outputs.py
```

The script compares each recomputed file with its published counterpart in
`data/results/summaries/` (numeric tolerance 1e-6) and checks the headline counts
quoted in the paper. Expected output ends with:

```
39 checks, 0 failed.
```

Any other result means the checkout or the Python environment differs from the
released artifact; please report the failing line.

## Output-to-table mapping

| Recomputed output | Published summary | Paper element |
|---|---|---|
| `historical_recompute.json` → `alpha` | — | α stage table, McNemar table |
| `historical_recompute.json` → `beta` | — | β level table |
| `historical_recompute.json` → `M03` | — | mechanism arms, B vs C |
| `historical_recompute.json` → `M04` | — | P0/P1/P2 diagnostic migration |
| `historical_recompute.json` → `M04b` | — | bridge pilot |
| `rq1/rq1_stats_dyn.json` | `rq1_stats_dyn.json` | RQ1 interaction, dynamic API |
| `rq1/rq1_stats_str.json` | `rq1_stats_str.json` | RQ1 interaction, string mapping |
| `rq1/rq1_stats_rename.json` | `rq1_stats_rename.json` | RQ1 rename-only control |
| `rq3/rq3_stats_main.json` | `rq3_stats_main.json` | RQ3 primary (n=30) |
| `rq3/rq3_stats_main_n28.json` | `rq3_stats_main_n28.json` | RQ3 sensitivity (n=28) |
| `rq3/rq3_stats_aux.json` | `rq3_stats_aux.json` | RQ3 auxiliary paths |
| `real/real_stats.json` | `real_stats.json` | real-source cohort C0–C4 |
| `w01/w01_stats.json` | `w01_stats.json` | source protection |
| `mech/mech_stats.json` | `mech_stats.json` | independent mechanism confirmation |
| `rtm/rtm_stats.json` | `rtm_stats.json` | four-project trial (descriptive) |

## Aggregation rules

The rules are frozen and implemented identically across cohorts.

- **Unit of analysis.** One `(program, condition, model)` cell. All repetitions
  of that cell are pooled.
- **Valid vote.** `answer` is exactly `malicious` or `benign`. A truncated
  response with no answer (`finish = length`) and a transport error are invalid.
- **Strict majority.** A cell is `malicious` only if more than half of the valid
  votes are `malicious`; the same for `benign`. A tie is `tie`, never `benign`.
- **Minimum valid votes.** Three for the final-round queues (RQ1/RQ3/REAL) and
  for M03/MECH; one for the historical α/β tables (10 repeats, majority over
  whatever parsed); two for W01/M04/bridge/RTM. Fewer than the minimum is
  `insufficient`.
- **Pairing.** Paired tests use only programs with a valid verdict in both cells.
  Invalid cells are reported, not imputed.
- **Multiplicity.** Holm correction is applied within each family of contrasts
  (RQ3 primary: three contrasts; REAL: four; W01: two models).
- **Intervals.** Wilson 95% for single proportions; program-level percentile
  bootstrap (10,000 resamples, seed 20261104) for paired differences.

These rules are also enforced by `code/aggregate_queue.py` for the final
round and by `code/recompute_historical.py` for the historical cohorts.

## Cohort-specific notes

- **α / β.** The historical tables use `parse_verdict()` from
  `code/realpe_score.py`. The released `content`, `answer`, and `verdict`
  fields are the strict parse result reduced to its one-word form, so the JSONL
  and the recomputation agree. Repetitions whose text yields no unambiguous
  verdict are retained with an empty `content`/`answer` and count as invalid,
  never as `benign`.
- **RQ1 rename.** Only 26 of 40 benign programs are rename-applicable; the list
  is `data/manifests/rename_applicable_benign.txt`. The other 14 are counted as
  `not_applicable`, not as missing.
- **RQ3 n=28.** `data/results/verdicts/rq3_verdicts_n28.csv` is the frozen table with
  the two excluded programs removed. `run_all.py` recomputes the statistics from
  that table; the n=30 table is rebuilt from raw responses.
- **REAL C4.** C4 is not a separate model call. For eight projects the C4 input
  SHA-256 equals C0, so C4 verdicts are copied from C0 by
  `code/merge_real_reuse.py` using `data/manifests/real_reuse_source.csv`.
  The merge never synthesises a missing C0 verdict.
- **RTM.** Only R1, R4, C1 were administered in this trial. R0 and R3 reuse the
  W01 clean/protected responses because the input SHA-256 matches; the verdict
  table contains all five conditions, the raw file contains three.
- **M04.** Zero-function P1 versions stay in the raw file but are excluded from
  the analysis denominator according to
  `data/manifests/m04_terminal_states.csv` (`counts_in_confirm_denominator`).

## Checksums

Confirm the checkout is unmodified:

```bash
sha256sum -c checksums/SHA256SUMS.txt
```

Regenerate the manifest after verifying, for example after editing a file:

```bash
python3 code/make_checksums.py
```

`checksums/SHA256SUMS.txt` covers every tracked file and excludes generated
output and the manifest itself.
