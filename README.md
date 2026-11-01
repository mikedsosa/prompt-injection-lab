# Fabrikam agent injection lab

A small, tool-using IT helpdesk agent for the fictional company Fabrikam, built to
measure how often prompt injection makes it misuse its tools, and how much simple
prompt-level defenses help.

> **Status: work in progress. Results: not yet run.**
> Milestone 1 (scaffold, mock tools, agent loop, model client, offline tests) is built.
> No attack or benign cases have been run against any model, so this README contains
> no results. Numbers will be added only from real, recorded runs.

## What's here so far

- **Mock tools over synthetic data** (`src/fabrikam_lab/tools.py`, `src/fabrikam_lab/data/`):
  read a KB article, fetch a ticket, look up a user or asset, reset MFA, send email.
  All data is made up and uses the reserved `fabrikam.example` domain. Side effects
  (MFA resets, outgoing email) only land in in-memory logs. Nothing touches a real
  account, mailbox or network.
- **Plain Python agent loop** (`src/fabrikam_lab/agent.py`): no framework. Model mistakes
  (unknown tool, bad JSON, wrong arguments) are returned to the model as tool errors and
  counted, instead of crashing the run.
- **Pluggable model client** (`src/fabrikam_lab/models/`): one small interface,
  `chat(messages, tools, temperature, seed)`. The real client talks to any
  OpenAI-compatible `/chat/completions` endpoint (by default a local Ollama server); a
  scripted stub drives the offline tests.
- **Tests** (`tests/`): run fully offline. A test-wide guard blocks every network
  connection, so no test can reach a model.
- **Smoke test** (`scripts/smoke_tool_calling.py`): five benign requests that check a
  model can drive the loop. It is a readiness check, not an attack result.

## Design choices

- **Local, open-weight models only.** Planned pair: `qwen2.5:7b-instruct` and
  `llama3.1:8b`, served by Ollama on a CPU-only machine. No paid APIs, no API keys.
  Only one model is loaded at a time.
- **Undefended baseline first.** The tools do not enforce policy (for example, "reset MFA
  only with a verified ticket"); that policy lives in the system prompt and KB. Prompt-level
  mitigations come in a later milestone, and a code-enforced tool gateway is a separate,
  follow-on project measured with this same harness.
- **Deterministic scoring (planned).** Success is judged from the mock tool logs (canary
  tokens, forbidden recipients, unauthorized resets), not by another model.
- **Reproducibility.** Every run will record the model tag and digest, Ollama version,
  temperature and seed.

## Roadmap

1. Scaffold, mock tools, agent loop, model client, offline tests and CI. **Done.**
2. Case format, canary scoring, a first 20 cases, then a first baseline run on that subset
   with both models. Recorded responses get replayed in CI.
3. Full case set tagged to OWASP LLM Top 10, OWASP Agentic Top 10 and MITRE ATLAS, baseline
   run across all cases.
4. Prompt-level mitigations, measured on seen and held-out cases, plus a temperature
   sensitivity check.
5. Threat model, runbook, write-up and results.

## Limitations (will apply to any results)

- Small (7-8B), quantized local models. Findings won't automatically carry over to larger
  hosted models, which often have extra provider-side safety layers.
- Temperature 0 with one seed measures one decoding path.

## Running it

```bash
make setup      # venv + pinned pytest and ruff
make check      # ruff, pytest (offline), gitleaks
PYTHONPATH=src python -m fabrikam_lab tools
PYTHONPATH=src python -m fabrikam_lab ask --model stub "How do I connect to the VPN?"
```

Against a local model (needs [Ollama](https://ollama.com) with the model pulled):

```bash
PYTHONPATH=src python -m fabrikam_lab ask --model qwen "Is laptop LT-3002 compliant?"
make smoke-llama
```

Model endpoints live in `config/models.toml`. Pointing the harness at a different
OpenAI-compatible endpoint is a config change, not a code change.

## License

MIT. All data in this repository is synthetic.
