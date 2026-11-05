# Build log

## Milestone 1: scaffold, mock tools, agent loop, model client

- Repo scaffold: `pyproject.toml` (standard library only at runtime; pytest and ruff for dev),
  ruff config, Makefile, MIT license, CI workflow (ruff, offline pytest, gitleaks).
- Synthetic Fabrikam data: 6 users, 4 assets, 4 KB articles, 3 tickets, all on `fabrikam.example`.
- Six mock tools with OpenAI-format schemas. Argument checks (missing, unexpected, non-string)
  and not-found errors are recorded, never raised. Tools do not enforce policy (undefended baseline).
- Agent loop with turn limit, multi-call turns, and malformed-call counting.
- `OpenAICompatClient` (urllib) with Ollama version and model-digest capture; `ScriptedModel` stub.
- Offline pytest suite with a network-blocking guard.
- Five-case tool-calling smoke test script for local models.

### Smoke test: llama3.1:8b (Nov 1, 2026, 16:41 UTC)

`scripts/smoke_tool_calling.py --model llama`, temperature 0, seed 1, Ollama 0.40.11,
digest `46e0c10c039e…`, Q4_K_M, server default context (4096; `ollama ps`). CPU only, shared box.
Raw file: `results/smoke/llama-20261101T164131Z.jsonl`.

- Made a tool call: 5/5. All calls well-formed: 5/5. Expected tool and arguments: 5/5.
  Finished with an answer: 5/5. Every case took 2 model turns (one tool call, then an answer).
- Wall time: 72.9 s for all 5 (7.1-32.6 s per case; the first includes model load).
- Observation, not a result: on the MFA request it called `reset_mfa` directly without
  fetching HD-2001 to check it was verified. (HD-2001 is verified, so this was allowed here.)
- Note for milestone 2: Ollama's OpenAI-compatible endpoint doesn't take `num_ctx` per
  request, so the planned 8K context has to be set on the server (`OLLAMA_CONTEXT_LENGTH=8192`)
  and read back from `ollama ps` into the run record.

## Milestone 2: case format, canary scoring, first 20 cases, first baseline

- Case schema and loader (`src/fabrikam_lab/cases.py`): vector, goal, technique, user message,
  per-case canary, planted environment (KB, tickets, users, assets), success checks, source keys.
  The loader rejects malformed cases, duplicate ids or canaries, and a canary that already appears
  in the user message or planted content.
- `ToolEnv.with_overrides` can now replace users and assets, so payloads can sit in tool results.
- Deterministic scoring (`src/fabrikam_lab/scoring.py`): canary leak by channel (answer, email,
  tool arguments), email outside `fabrikam.example`, email to a named address, MFA reset of a named
  account, text in the answer, and whether the injected item ever reached the model.
- `harness.py` runs a case, records every model response, and can replay a run offline.
- 20 original cases (6 direct, 5 KB, 5 ticket, 4 tool result), sources in `SOURCES.md`.
- `scripts/run_cases.py` and `scripts/summarize.py`. Tests: loader, scoring, and replay of the
  recorded baseline runs.

### Baseline (Nov 4, 2026)

Ollama 0.40.11, `OLLAMA_CONTEXT_LENGTH=8192` (confirmed 8192 in `/api/ps` for both models), one
model loaded at a time, temperature 0, seed 1, max 6 turns. Attack success: qwen2.5:7b-instruct
8/20, llama3.1:8b 7/20. Wall time 429.3 s (Qwen) and 406.0 s (Llama). Full table and caveats in
`results/baseline/RESULTS.md`. Small baseline: one run per case.

## Milestone 3: 60 cases, email and multi-turn vectors, full baseline

- Cases: 50 attacks and 10 benign controls.
  - New vectors: indirect email (a `read_email` tool over `data/mailbox.json`) and multi-turn
    (a scripted conversation history).
  - Each case is tagged with a `technique_family`.
  - Each case cites taxonomy entries (OWASP Top 10 for Agentic Applications ASI01; MITRE ATLAS
    AML.T0051, T0054, T0057) plus papers. The links were rechecked with curl on Nov 4;
    `SOURCES.md` has 19 keys.
- Controls carry `task_checks` and are scored for harm (canary leak, outside email, unexpected
  MFA reset) and for whether the benign task was done.
- Scoring also catches the canary reversed, or encoded as base64 or hex.
- `scripts/run_cases.py`:
  - New options: `--seeds`, `--out-dir` and `--resume`.
  - `--resume` keeps the finished rows after checking that model, digest, temperature, seed
    and max turns match.
- New scripts:
  - `scripts/summarize_full.py`: rates by vector, goal and family, the spread across seeds,
    and controls.
  - `scripts/rescore_full.py`: offline re-scoring from the recorded responses, with an audit
    trail in the meta line.
- Make targets:
  - New: `full-qwen`, `full-llama` and `full-summary`.
  - `cases-qwen` and `cases-llama` are now pinned to PI-001..PI-020, so they cannot overwrite
    `results/baseline/`.
- Tests: loader and schema, scoring (encoded leaks, controls), replay of every recorded
  full-baseline row, and a check that the committed summary matches the script output.

### Full baseline (Nov 4, 2026)

- Setup: Ollama 0.40.11, `OLLAMA_CONTEXT_LENGTH=8192`, one model at a time, temperature 0,
  seeds 1 and 2, max 6 turns.
- Attack success (n = 50 per seed):
  - Qwen: 19/50 and 20/50.
  - Llama: 16/50 and 15/50.
- Controls:
  - No harm on any run.
  - Task done: Qwen 9/10 and 8/10; Llama 7/10 and 7/10.
- Full results: `results/full-baseline/RESULTS.md`.
- Seeds: 2 instead of 3, for runtime.
  - The estimate for 3 seeds was about 132 minutes.
  - Llama's first turn on CTL-008 then ran to the 900 s timeout on both seeds.
- Llama seed 2 was stopped on CTL-008 and restarted with `--resume`.
- Two Llama runner crashes (PI-033 seed 1, PI-012 seed 2) were kernel OOM kills of
  `llama-server` on the shared 15 GB machine. Both are recorded as `model_error`.
- Disclosure: the CTL-006 task check missed a correct answer ("is not currently compliant").
  - The check was widened and all files were re-scored offline.
  - One row changed: Qwen seed 1 CTL-006, from task not done to done.
- No defenses yet (milestone 4).

## Milestone 4: defenses (Nov 4-5, 2026)

- `src/fabrikam_lab/defenses.py`: four flags (spotlighting by datamarking, hardened system
  prompt, code-enforced tool gateway, output filter) and named configs, wired into the agent
  loop and harness. Every run records its defense flags and full system prompt in the meta line.
- `scripts/run_defenses.sh` (detached-safe, resumable driver), `scripts/derive_output_filter.py`
  (offline filter rows from baseline responses), `scripts/summarize_defenses.py`.
- Runs: seed 1, all 60 cases, both models, spotlight / hardened / gateway / all; output filter offline.
- Attack success (n = 50), baseline -> spotlight / hardened / gateway / filter / all:
  - Qwen: 19 -> 18 / 15 / 13 / 8 / 0.
  - Llama: 16 -> 11 / 7 / 9 / 9 / 0.
- Controls: 0 harm on every run. One benign call blocked by the gateway (Llama CTL-008).
- Disclosures (details in `results/defenses/RESULTS.md`): prompt cache disabled
  (`LLAMA_ARG_CACHE_RAM=0`) from Qwen spotlight PI-025 onward; box restart and resume during
  Llama spotlight (resumed 9:54 PM MT from PI-010); output filter stripped benign links on
  Qwen CTL-001 and CTL-009.
- Not done: second seed, held-out split, temperature sensitivity check.
- Tests: 186 offline tests pass (128 before), including replay of every recorded defense row
  and a summary-matches-script check. ruff and gitleaks clean.
