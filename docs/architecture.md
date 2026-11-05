# Architecture

One page on how a case runs. Everything runs locally; the only network call is
from the model client to an OpenAI-compatible endpoint (by default a local
Ollama server), and the offline tests use a scripted stub instead.

```mermaid
flowchart LR
    C["cases/*.json<br/>attack (PI-) or control (CTL-)<br/>vector · payload · canary · checks"] --> H["harness.py<br/>run_case / replay_case"]
    CFG["config/models.toml"] --> M
    H --> A["agent.py<br/>plain Python loop"]
    A <--> M["models/<br/>OpenAI-compatible client (Ollama)<br/>or scripted stub"]
    A -- "tool calls (via gateway if enabled)" --> T["tools.py<br/>mock tools over synthetic data<br/>(fabrikam.example)"]
    T -- "tool results (spotlighted if enabled)" --> A
    D["defenses.py<br/>spotlighting · hardened prompt<br/>tool gateway · output filter"] -.-> A
    A --> S["scoring.py<br/>deterministic: final answer,<br/>mock outbox, tool log, canary"]
    H --> R["results/<br/>recorded responses (replayable)<br/>summaries"]
    S --> R
```

- **Cases** are data, validated by `cases.py` on load.
- **Defenses** are switched by a `DefenseConfig`: the system prompt, how tool
  results are wrapped, an optional gateway in front of tool calls, and an
  optional filter on the final answer.
- **Side effects** (MFA resets, outgoing email) only land in the in-memory
  `ToolEnv` logs, which is what scoring reads.
- **Recorded responses** under `results/` are replayed offline in CI through the
  same loop, so the published numbers can be re-scored without a model.
