# Release and safety policy

This repository is a response-record artifact, not a malware corpus and not a
detector implementation.

## What was removed before release

| Removed | Reason |
|---|---|
| Program source code (constructed and real projects) | Not needed to recompute any table; some constructed programs are controlled malicious test cases |
| Compiled PE files and decompiled text | Same; also avoids redistributing third-party binaries |
| Model reasoning / chain-of-thought | Reduces redistribution of model-generated text and removes a potential source of leakage |
| Input code sent to the model | Not redistributed; each row carries the input SHA-256 instead |
| Model API endpoints, API keys, account identifiers | Credential hygiene |
| Names of the commercial API aggregation service | Required by the paper's disclosure policy |
| File comments that name a sample's class | The corpora were built without such labels |

## What remains

- One row per model request with: cohort, program identifier, label, condition,
  repetition, model label, the one-word verdict, finish/status, token counts,
  latency, timestamps, and input/prompt SHA-256 where recorded.
- `content` is the one-word answer retained for audit. No surrounding
  explanation, code, or chain-of-thought is included.
- `prompts/base_prompt_zh.txt` is the final-round prompt, byte-exact. It asks
  for a one-word `恶意` / `正常` judgement and contains no sample-specific text.
- Program identifiers for constructed corpora are synthetic (`hb01_*`,
  `m01_*`, `b01_*`, …). Real-source identifiers are the public names of the
  open-source projects used (e.g. zlib, cJSON, libpng); no third-party code is
  redistributed.

## Dual-use assessment

The artifact reports whether large language models raise false alarms on benign
programs under different protection and evidence conditions. It contains no
working attack payload, no obfuscator implementation, no evasion recipe, and no
executable sample. Recomputing the tables only requires arithmetic over the
released verdict words.

Constructed programs labelled `malicious` in α, β, and RQ1 are controlled test
programs written for the study. They were compiled but never executed, and
neither their source nor their binaries are part of this repository.

## Privacy and credentials

- No contact details or personal data about the experimenters are present in
  tracked files.
- Internal hostnames, IP addresses, and absolute filesystem paths were removed.
- `data/manifests/m04_provenance_labels.csv` retains upstream download URLs and
  the maintainers credited by each project; this is provenance for the public
  binaries used, not personal data about the authors.
- The model access service is referred to only as a commercial API aggregator;
  its name and endpoint are not recorded.

## Reporting a problem

If you believe a file in this repository exposes sensitive material, please
contact the corresponding author of the paper before opening a public issue.
