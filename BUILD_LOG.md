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
