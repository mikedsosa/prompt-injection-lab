# Results

No lab results yet. The attack and benign suites have not been run.

- `smoke/` holds tool-calling smoke tests (5 benign cases per model). They only check
  that a model can drive the agent loop. They are not attack results.
- Real runs (milestone 2 onward) will add one JSON line per run, with the model tag and
  digest, Ollama version, temperature, seed and context length recorded alongside.
