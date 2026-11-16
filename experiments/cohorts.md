# Cohorts and conditions

Every cohort below is independent; numbers from different cohorts are never
pooled into one test. Definitions are the frozen ones used for the paper. The
paper's protocol sections remain the authority on procedure.

## α (`alpha`)

- 40 constructed programs: 20 benign (`hb*`) and 20 malicious (`hm*`).
- 9 model families, 10 repetitions per program and stage.
- Three stages, produced in one run:

| Condition | Input |
|---|---|
| `H1` (H①) | Original C source, no transformation |
| `H3` (H③) | Compile → PE → Ghidra decompiled text |
| `H4` (H④) | Obfuscate (string XOR + identifier rename) → compile → decompile |

Nominal design: 9 × 3 × 10 × 40 = 10,800. The released table has 1,080
program-level cells. Models: DeepSeek, Claude Sonnet 5.5, Gemini 3.8 Flash,
GLM-4-Flash, GLM-Z1-Flash, GPT-5.5, Kimi K2.5, MiniMax M2.5, Qwen-Plus.

## β (`beta`)

- 40 constructed programs: 20 benign (`b*`) and 20 malicious (`m*`).
- 8 model families, 10 repetitions per program and level.
- Six levels, all through the same pipeline (transform → compile → decompile):

| Level | Transformation |
|---|---|
| `L0` | None |
| `L1` | Dead code + instruction substitution |
| `L2` | UPX packing (binary layer) |
| `L3` | String encryption + identifier rename |
| `L4` | L3 + dynamic API resolution |
| `L5` | L4 + shape legalisation |

Nominal design: 8 × 6 × 10 × 40 = 19,200; 1,920 program-level cells.

## M03 (`m03`)

- 20 benign constructed programs, 2 models (DeepSeek, Gemini),
  5 repetitions, 4 text-level arms.
- Nominal design: 20 × 4 × 2 × 5 = 800.

| Arm | Text |
|---|---|
| `H` | Obfuscated source → compile → decompile (baseline) |
| `A` | Strings restored to plaintext; decrypter definition removed |
| `B` | A plus a dead decrypter appended (`fn_aux`, XOR 0x5A) |
| `C` | A plus a near-equal-length ordinary dead function (`fn_aux`, same signature and position) |

The primary contrast is `B` vs `C`: the application body is byte-identical
between them; only the appended dead block differs.

## MECH (`mech`)

- 30 new benign programs, 1 model (`deepseek-flash`), 5 repetitions, 5 arms.
- Nominal design: 30 × 5 × 5 = 750.

| Arm | Text |
|---|---|
| `A` | Program body only (floor) |
| `B` | Body + dead decrypter (`fn_aux`, XOR 0x5A, `slots_*`/`turn_*` shape) |
| `C` | Body + equal-length ordinary dead function (same name, signature, position) |
| `D` | Body with one call to the same decrypter added in `_main` (called vs dead) |
| `E` | Body + the same decrypter renamed `dk_dec` (semantic vs neutral name) |

The primary contrast is `B` vs `C`. `D` and `E` are auxiliary.

## W01 (`w01`)

- 12 real open-source C projects, built as 32-bit Windows PE with
  `i686-w64-mingw32-gcc -O0`, decompiled with Ghidra.
- 2 models (DeepSeek, Gemini), 2 versions, 3 repetitions.
- Nominal design: 12 × 2 × 2 × 3 = 144.

| Version | Input |
|---|---|
| `clean` | Unmodified source → PE → decompile |
| `prot` | Source-protected (string encryption + identifier rename) → PE → decompile |

The main analysis uses the 10 projects that do not overlap the earlier
bzip2/Lua pilot; the 12-project table is the sensitivity analysis.

## M04 (`m04`)

- 20 real benign projects, each in up to three versions; 54 project-versions
  reach the analysis denominator; 2 models, 3 repetitions.
- Nominal confirm requests: 54 × 2 × 3 = 324. The released raw file has 333
  rows including retries.

| Version | Construction |
|---|---|
| `P0` | Original PE from the official release |
| `P1` | `upx --strip-relocs=0` packing of P0 |
| `P2` | `upx -d` unpack of P1 (not guaranteed byte-identical to P0) |

Versions with zero decompilable functions in P1 remain in the raw file but are
excluded from the analysis denominator; `m04_terminal_states.csv` records
`counts_in_confirm_denominator` per cell.

## BRIDGE (`bridge`)

- Two pilot projects (bzip2, Lua), clean and protected versions, two models,
  two repetitions: 2 × 2 × 2 × 2 = 16 responses, 8 cells.
- This is an exploratory pilot, not part of any confirmation.

## RTM (`rtm`)

- Four real projects (zlib, cJSON, md4c, libpng), 3 repetitions, one model
  (`deepseek-flash`).
- Only `R1`, `R4`, `C1` were administered (33 responses).

| Condition | Definition |
|---|---|
| `R0` | Original source → 32-bit PE (reused from W01 `clean`) |
| `R3` | String protection (reused from W01 `prot`) |
| `R1` | File-local `static` function names changed (3 projects; zlib not administered) |
| `R4` | Decode-shape variant: three-argument `dk_dec(dest, src, n)`, plaintext written to a stack buffer |
| `C1` | String protection + rename |

R0 and R3 are derived from the W01 responses because the input SHA-256 matches.
The verdict table therefore has five conditions; `rtm_raw.jsonl` has three.
With at most four pairs the smallest attainable two-sided p is 0.125, so the
trial is reported descriptively only.

## RQ1 (`rq1`)

- 60 constructed programs: 40 benign (`b*`) and 20 controlled malicious (`m*`).
- 8 conditions, 3 repetitions, one model (`deepseek-flash`).
- Nominal design: 60 × 8 × 3 = 1,440; 1,452 raw rows including retries.

| Condition | Input |
|---|---|
| `S0` | Original source |
| `D0` | Original source → PE → Ghidra decompile |
| `St_str` | String-protected source |
| `Dt_str` | String-protected source → PE → decompile |
| `St_rename` | Identifier-renamed source |
| `Dt_rename` | Identifier-renamed source → PE → decompile |
| `St_dyn` | Dynamic API resolution source (construction also applies string protection) |
| `Dt_dyn` | Dynamic API resolution source → PE → decompile |

The four-cell interaction is
Δ = (p11 − p01) − (p10 − p00) with `S0, D0, St_*, Dt_*` in that order.
Only 26 of the 40 benign programs are rename-applicable; the other 14 are
`not_applicable`, not missing.

## RQ3 (`rq3`)

- 30 benign programs (`b01`–`b30`), 7 conditions, 3 repetitions, one model
  (`deepseek-flash`). 30 × 7 × 3 = 630 planned requests; 644 raw rows
  including retries; 210 program-level cells.

Path A, decompiled text with evidence hidden or restored:

| Condition | Strings | API identity |
|---|---|---|
| `E0` | Hidden | Hidden |
| `ES` | Restored | Hidden |
| `EA` | Hidden | Restored |
| `ESA` | Restored | Restored |

`E0` uses the same input organisation as RQ1 `Dt_dyn`; RQ3 was called and judged
independently.

Path B, source-level non-decryption helper:

| Condition | Source |
|---|---|
| `S0` | Clean program text |
| `ST` | S0 + an uncalled dynamic-API resolution helper (`fx_block`) |
| `SN` | S0 + an uncalled ordinary function (same name, signature, position, similar length) |

Primary contrasts: `ES`, `EA`, `ESA` vs `E0` (Holm over three). Auxiliary:
`ST` vs `SN`, plus `S0` as the source-level floor.

The prespecified main set for Path A is `n=28`: two programs, `b02_file_copy`
and `b30_reg_backup`, already expose partial API identities in the input, so
their `EA` edit could not fully control what the model saw. The all-30 counts
are the sensitivity analysis (manuscript Appendix B).

## REAL (`real`)

- 8 real benign projects, 4 administered conditions, 3 repetitions, one model
  (`deepseek-flash`). Planned 8 × 5 × 3 = 120; frozen queue 32 × 3 = 96 because
  the C4 input matched C0 for all eight projects.

| Condition | Construction |
|---|---|
| `C0` | Original build (clean source → PE) |
| `C1` | String protection (XOR 0x5A, per-file static decryption helper) |
| `C2` | Non-string source transform: rename file-local `static` identifiers |
| `C3` | UPX `-9` packing of the C0 PE |
| `C4` | `upx -d` unpack of C3; re-decompiled and passed through the same selector |

After unpacking, all eight C4 inputs had the same SHA-256 as C0, so C4 verdicts
are reused from C0. The reuse map is `data/manifests/real_reuse_source.csv`.
