.PHONY: setup lint test secrets check smoke-qwen smoke-llama

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
