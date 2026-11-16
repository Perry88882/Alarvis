# Prompts

`base_prompt_zh.txt` is the prompt used for the final-round cohorts (`RQ1`,
`RQ3`, `REAL`). The file is byte-exact, with no trailing newline:

```
SHA-256  410aabf11ed7cf70288137c8fed9feb58a131d3d2c9e9370e5728128c044f50c
bytes    111
```

Verify it with:

```bash
sha256sum prompts/base_prompt_zh.txt
```

## How a request is assembled

The prompt is sent as the single user message, followed by two newlines and the
program text:

```python
messages = [{"role": "user", "content": PROMPT + "\n\n" + code}]
```

Requests are non-streaming with `temperature = 0`. No system message is sent.

## Which cohorts record it

Every row of `data/responses/rq1_raw.jsonl`, `rq3_raw.jsonl`, and
`real_raw.jsonl` carries `prompt_sha256 = 410aabf1…f50c`.

The earlier cohorts (`alpha`, `beta`, `M03`, `W01`, `M04`, `MECH`, `RTM`,
`BRIDGE`) ran with the same wording but their rows do not record a prompt hash,
so this file documents only the request that the recorded hash certifies.
