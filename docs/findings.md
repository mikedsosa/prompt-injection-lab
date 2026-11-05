# Findings

A short write-up of what this lab measured. Numbers come from
[`results/full-baseline/`](../results/full-baseline/RESULTS.md) (milestone 3) and
[`results/defenses/`](../results/defenses/RESULTS.md) (milestone 4); the test
`tests/test_docs_numbers.py` checks the defense table below against `summary.csv`.

## Question

How often does indirect and direct prompt injection make a small, local, tool-using helpdesk
agent misuse its tools or leak a secret, and how much do four simple defenses help?

## Setup in one paragraph

A plain Python agent with seven mock tools over synthetic Fabrikam data (KB, tickets,
directory, assets, mailbox, MFA reset, send email). 60 original cases: 50 attacks across six
vectors (direct, KB, ticket, tool result, inbound email, multi-turn) and four goals (leak the
secret, exfiltrate by email, plant a phishing link, unauthorized MFA reset), plus 10 benign
controls. Two quantized local models, `qwen2.5:7b-instruct` and `llama3.1:8b`, at temperature 0
on CPU. Scoring is deterministic: canary matching and tool logs, no model as judge.

## Baseline (no defenses)

- Qwen: 19/50 (seed 1) and 20/50 (seed 2). Llama: 16/50 and 15/50.
- No harm on any benign control.

## Defenses (seed 1)

| config | Qwen | Llama |
|---|---|---|
| baseline (no defense) | 19/50 (38%) | 16/50 (32%) |
| spotlighting | 18/50 (36%) | 11/50 (22%) |
| hardened system prompt | 15/50 (30%) | 7/50 (14%) |
| tool gateway | 13/50 (26%) | 9/50 (18%) |
| output filter (offline) | 8/50 (16%) | 9/50 (18%) |
| all combined | 0/50 (0%) | 0/50 (0%) |

## Takeaways

1. **Prompt-only defenses help a little, not enough.** Spotlighting and a hardened prompt
   left 7 to 18 of 50 attacks working, and some new successes appeared that the baseline did
   not have (spotlighting: 2 on each model; hardened prompt: 3 on Qwen).
2. **Code-enforced controls are where the hard stops are.** The tool gateway turned every
   attempted harmful tool action into a blocked call, but it cannot see what the model writes
   in its reply.
3. **Defenses cover different failure modes.** The output filter catches leaks and links in
   the answer but none of the tool actions. Layered together, no attack succeeded on either
   model, even though the models still attempted 13 (Qwen) and 8 (Llama) of them.
4. **Defenses have costs.** The gateway blocked one benign email (Llama CTL-008), and the
   output filter stripped harmless links in two Qwen controls (CTL-001, CTL-009).

## Limits

- Two small quantized models, one seed for defenses, 50 attacks: per-category counts are 2 to
  13 cases, so differences of one or two cases are noise.
- The cases were written by the same person who wrote the defenses; there is no held-out set,
  so the combined 0/50 is an upper bound on how well these defenses would do against new attacks.
- Run-time disclosures (a prompt-cache setting change and a resume after a machine restart)
  are listed in `results/defenses/RESULTS.md`.
