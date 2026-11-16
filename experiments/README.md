# Experiments

Documentation of how each cohort was built and scored.

| File | Contents |
|---|---|
| `cohorts.md` | Every cohort (`alpha`, `beta`, `M03`, `W01`, `M04`, `MECH`, `RTM`, `BRIDGE`, `RQ1`, `RQ3`, `REAL`): conditions, inputs, and what each contrast tests |
| `data-dictionary.md` | Every field in `data/responses/`, `data/results/verdicts/`, `data/manifests/`, and `data/results/summaries/` |
| `safety.md` | What was removed before release, what remains, and the dual-use assessment |

The aggregation rules shared by all cohorts (unit of analysis, strict majority,
minimum valid votes, tie handling, Holm correction, intervals) are stated in
`../REPRODUCE.md` and implemented once in `../code/`.
