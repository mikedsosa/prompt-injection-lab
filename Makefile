.PHONY: setup lint test secrets check smoke-qwen smoke-llama cases-qwen cases-llama summary full-qwen full-llama full-summary

setup:
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

lint:
	.venv/bin/ruff check . && .venv/bin/ruff format --check .

test:
	.venv/bin/pytest

secrets:
	gitleaks detect --source . --no-banner

check: lint test secrets

# Needs a local Ollama server with the model pulled. Load one model at a time.
smoke-qwen:
	.venv/bin/python scripts/smoke_tool_calling.py --model qwen

smoke-llama:
	.venv/bin/python scripts/smoke_tool_calling.py --model llama

# Injection cases (milestone 2). One model at a time; server needs OLLAMA_CONTEXT_LENGTH=8192.
# Pinned to the milestone 2 subset so these never overwrite results/baseline/ with the full set.
M2_CASES = PI-001 PI-002 PI-003 PI-004 PI-005 PI-006 PI-007 PI-008 PI-009 PI-010 PI-011 PI-012 PI-013 PI-014 PI-015 PI-016 PI-017 PI-018 PI-019 PI-020
cases-qwen:
	.venv/bin/python scripts/run_cases.py --model qwen --cases $(M2_CASES)

cases-llama:
	.venv/bin/python scripts/run_cases.py --model llama --cases $(M2_CASES)

summary:
	.venv/bin/python scripts/summarize.py

# Full set (milestone 3): all 60 cases, one file per seed in results/full-baseline/.
SEEDS ?= 1 2
full-qwen:
	.venv/bin/python scripts/run_cases.py --model qwen --seeds $(SEEDS) --out-dir results/full-baseline

full-llama:
	.venv/bin/python scripts/run_cases.py --model llama --seeds $(SEEDS) --out-dir results/full-baseline

full-summary:
	.venv/bin/python scripts/summarize_full.py
