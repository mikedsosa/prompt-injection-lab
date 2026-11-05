#!/usr/bin/env bash
# Milestone 4 runner: every defense config for one or more models, seed 1 (or SEEDS), one
# model loaded at a time. Safe to re-run: finished files are skipped and an interrupted file
# is resumed from its last written case.
#
#   nohup scripts/run_defenses.sh qwen llama > results/defenses/run.log 2>&1 &
#
# Needs a local Ollama server started with an 8K context, e.g.
#   OLLAMA_CONTEXT_LENGTH=8192 OLLAMA_NUM_PARALLEL=1 OLLAMA_MAX_LOADED_MODELS=1 ollama serve
set -u
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
CONFIGS=${CONFIGS:-"spotlight hardened gateway all"}
SEEDS=${SEEDS:-1}
MAX_TOKENS=${MAX_TOKENS:-1024}
OUT=${OUT:-results/defenses}
declare -A TAG=([qwen]=qwen2.5:7b-instruct [llama]=llama3.1:8b)
for model in "$@"; do
  for cfg in $CONFIGS; do
    for seed in $SEEDS; do
      f="$OUT/$model-$cfg-seed$seed.jsonl"
      if [[ -f "$f" ]] && tail -n 1 "$f" | grep -q '"end"'; then
        echo "skip $f (finished)"; continue
      fi
      for attempt in 1 2 3; do
        echo "$(date -Is) start $model $cfg seed $seed attempt $attempt"
        if "$PY" scripts/run_cases.py --model "$model" --seeds "$seed" --defense "$cfg" \
            --max-tokens "$MAX_TOKENS" --out-dir "$OUT" --resume; then
          break
        fi
        echo "$(date -Is) run failed, retrying with --resume"; sleep 20
      done
    done
  done
  ollama stop "${TAG[$model]}" || true
  echo "$(date -Is) done $model"
done
