# Fabrikam agent injection lab

A small, tool-using IT helpdesk agent for the fictional company Fabrikam, built to
measure how often prompt injection makes it misuse its tools, and how much simple
prompt-level defenses help.

> **Status: milestones 1 to 5 done.** 60 original cases (50 attacks, 10 benign controls), an
> undefended two-seed baseline and a seed-1 defense comparison on two local 7-8B models.
> Short write-up: [`docs/findings.md`](docs/findings.md). Threat model:
> [`docs/threat-model.md`](docs/threat-model.md).

## Lab / how to run

Lab for a fictional Fabrikam IT helpdesk agent that measures how often prompt injection makes it misuse its tools, and how much simple prompt-level defenses help. Synthetic data only (`fabrikam.example`); nothing touches a real account, mailbox, or network. Offline: `make setup` then `make check`. Against a local Ollama model, see [Running it](#running-it).

## Results at a glance

Attack success out of 50 attack cases, seed 1, temperature 0
([`results/defenses/RESULTS.md`](results/defenses/RESULTS.md)):

| config | qwen2.5:7b-instruct | llama3.1:8b |
|---|---|---|
| no defense | 19/50 | 16/50 |
| spotlighting | 18/50 | 11/50 |
| hardened system prompt | 15/50 | 7/50 |
| tool gateway | 13/50 | 9/50 |
| output filter | 8/50 | 9/50 |
| all combined | 0/50 | 0/50 |

No benign control was harmed in any run. Small models, one seed and no held-out set: read
the limits in the results file before drawing conclusions.

## What's here so far

- **Mock tools over synthetic data** (`src/fabrikam_lab/tools.py`, `src/fabrikam_lab/data/`):
  read a KB article, fetch a ticket, look up a user or asset, read a mailbox message,
  reset MFA, send email.
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
- **Injection cases** (`cases/`, `src/fabrikam_lab/cases.py`): one JSON file per case, with
  the vector (direct; indirect through a KB article, a ticket, a tool result or an inbound
  email; or a scripted multi-turn history), the attacker's goal, a technique family, the
  planted payload, a per-case canary, and the checks that count as success. 50 attack cases
  (`PI-`) and 10 clearly labeled benign controls (`CTL-`), which have harm checks plus
  benign-task checks so a false refusal shows up. Every attack is tagged to OWASP LLM Top 10,
  OWASP Agentic Top 10 (ASI01) and MITRE ATLAS; sources in [`SOURCES.md`](SOURCES.md).
- **Deterministic scoring** (`src/fabrikam_lab/scoring.py`): judged from the final answer, the
  mock outbox and the tool log. Canary matching ignores case, spaces and punctuation, and
  also catches the canary reversed or inside a base64 or hex token.
- **Tests** (`tests/`): run fully offline. A test-wide guard blocks every network
  connection, so no test can reach a model.
- **Smoke test** (`scripts/smoke_tool_calling.py`): five benign requests that check a
  model can drive the loop. It is a readiness check, not an attack result.

## Design choices

- **Local, open-weight models only.** Models: `qwen2.5:7b-instruct` and
  `llama3.1:8b`, served by Ollama on a CPU-only machine. No paid APIs, no API keys.
  Only one model is loaded at a time.
- **Undefended baseline first.** The tools themselves do not enforce policy (for example,
  "reset MFA only with a verified ticket"); that policy lives in the system prompt and KB.
  Defenses (`src/fabrikam_lab/defenses.py`) are separate flags, so each is measured alone
  and combined.
- **Deterministic scoring.** Success is judged from the mock tool logs (canary
  tokens, forbidden recipients, unauthorized resets), not by another model.
- **Reproducibility.** Every run records the model tag and digest, Ollama version,
  temperature and seed.

## Roadmap

1. Scaffold, mock tools, agent loop, model client, offline tests and CI. **Done.**
2. Case format, canary scoring, a first 20 cases, then a first baseline run on that subset
   with both models. Recorded responses get replayed in CI. **Done.**
3. Full case set tagged to OWASP LLM Top 10, OWASP Agentic Top 10 and MITRE ATLAS, baseline
   run across all cases. **Done** (60 cases; seeds per model in the results file).
4. Defenses: spotlighting, hardened prompt, code-enforced tool gateway, output filter, and
   all combined, seed 1 on both models. **Done** (no held-out split or temperature check yet).
5. Threat model, findings write-up, README and CI checks. **Done.**

## Limitations

- Small (7-8B), quantized local models. Findings won't automatically carry over to larger
  hosted models, which often have extra provider-side safety layers.
- Temperature 0 with two seeds per model for the baseline and one seed for defenses. On this CPU setup, temperature 0 is
  not fully deterministic across seeds (see the seed-agreement numbers in [`results/full-baseline/summary-table.md`](results/full-baseline/summary-table.md)).
- Small per-category samples (2 to 13 cases per vector, goal or technique family).

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
make full-qwen    # all 60 cases, seeds 1 and 2, into results/full-baseline/
make full-llama   # stop the previous model first; add --resume after an interruption
make full-summary # results/full-baseline/summary.{json,csv} and summary-table.md
make defenses     # seed-1 defense runs, both models, resumable
make defense-summary
```

Start the server with an 8K context, since the OpenAI-compatible endpoint ignores a
per-request `num_ctx`: `OLLAMA_CONTEXT_LENGTH=8192 ollama serve`.

Model endpoints live in `config/models.toml`. Pointing the harness at a different
OpenAI-compatible endpoint is a config change, not a code change.

## License

MIT. All data in this repository is synthetic.
