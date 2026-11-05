# Sources

The 60 cases in `cases/` (50 attacks, 10 benign controls) are written from scratch for the
fictional Fabrikam helpdesk.
No case text is copied from a dataset. Each case lists the source keys below for the
technique it is based on. All links were checked on Nov 4, 2026 (the
milestone 3 additions were checked again with curl the same day).

| Key | Source | Used for |
|-----|--------|----------|
| `OWASP-LLM01` | OWASP Top 10 for LLM Applications 2025, LLM01: Prompt Injection. https://genai.owasp.org/llmrisk/llm01-prompt-injection/ | Direct and indirect injection (all cases) |
| `OWASP-LLM02` | OWASP Top 10 for LLM Applications 2025, LLM02: Sensitive Information Disclosure. https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/ | Sending directory data out |
| `OWASP-LLM06` | OWASP Top 10 for LLM Applications 2025, LLM06: Excessive Agency. https://genai.owasp.org/llmrisk/llm062025-excessive-agency/ | Injected instructions that trigger a privileged tool (MFA reset, email) |
| `OWASP-LLM07` | OWASP Top 10 for LLM Applications 2025, LLM07: System Prompt Leakage. https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/ | Canary secret planted in the system prompt |
| `PEREZ-2022` | Perez and Ribeiro, "Ignore Previous Prompt: Attack Techniques For Language Models" (2022). https://arxiv.org/abs/2211.09527 | "Ignore previous instructions" and prompt leaking |
| `GRESHAKE-2023` | Greshake et al., "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (2023). https://arxiv.org/abs/2302.12173 | Indirect injection through retrieved content, hidden instructions, phishing links |
| `LIU-HOUYI-2023` | Liu et al., "Prompt Injection attack against LLM-integrated Applications" (2023). https://arxiv.org/abs/2306.05499 | Context-separator and fake-context payloads |
| `LIU-BENCH-2023` | Liu et al., "Formalizing and Benchmarking Prompt Injection Attacks and Defenses" (2023). https://arxiv.org/abs/2310.12815 | Fake completion and escape-character attacks |
| `INJECAGENT-2024` | Zhan et al., "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents" (2024). https://arxiv.org/abs/2403.02691 | Attacker goals split into direct harm and data stealing, for tool-using agents |
| `AGENTDOJO-2024` | Debenedetti et al., "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents" (2024). https://arxiv.org/abs/2406.13352 | Injections placed in tool results; scoring from environment state, not a model judge |
| `WEI-2023` | Wei, Haghtalab and Steinhardt, "Jailbroken: How Does LLM Safety Training Fail?" (2023). https://arxiv.org/abs/2307.02483 | Role-play and obfuscated-output requests; base64-encoded instructions (the paper tests base64 input and output attacks) |
| `KANG-2023` | Kang et al., "Exploiting Programmatic Behavior of LLMs: Dual-Use Through Standard Security Attacks" (2023). https://arxiv.org/abs/2302.05733 | Obfuscation to get around a content rule |
| `DENG-2023` | Deng et al., "Multilingual Jailbreak Challenges in Large Language Models" (2023). https://arxiv.org/abs/2310.06474 | Payloads written in languages other than English (Spanish, German, French, Portuguese, Italian) |
| `RUSSINOVICH-2024` | Russinovich, Salem and Eldan, "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack" (2024). https://arxiv.org/abs/2404.01833 | Multi-turn setups, where earlier turns prepare the request that comes later |
| `LI-2023` | Li et al., "Multi-step Jailbreaking Privacy Attacks on ChatGPT" (2023). https://arxiv.org/abs/2304.05197 | A fabricated assistant turn in the history that "agrees" to the attacker's framing |
| `OWASP-ASI01` | OWASP Top 10 for Agentic Applications for 2026, ASI01: Agent Goal Hijack. https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | Agent goal hijack (tagged on every attack case); especially inbound email and instructions split across sources |
| `ATLAS-T0051` | MITRE ATLAS AML.T0051 LLM Prompt Injection (direct .000 and indirect .001), from the ATLAS data release. https://github.com/mitre-atlas/atlas-data/blob/main/dist/ATLAS.yaml | Direct and indirect injection (tagged on every attack case), as a second taxonomy next to OWASP |
| `ATLAS-T0054` | MITRE ATLAS AML.T0054 LLM Jailbreak, same data release. https://github.com/mitre-atlas/atlas-data/blob/main/dist/ATLAS.yaml | Role-play personas used to set aside the assistant's rules (tagged on every role-play case) |
| `ATLAS-T0057` | MITRE ATLAS AML.T0057 LLM Data Leakage, same data release. https://github.com/mitre-atlas/atlas-data/blob/main/dist/ATLAS.yaml | Prompts that try to make the model leak a secret (tagged on every leak case) |

All addresses use the reserved `.example` domain (`fabrikam.example`, `attacker.example`),
which does not route. The canary values are random strings with no meaning outside this lab.
