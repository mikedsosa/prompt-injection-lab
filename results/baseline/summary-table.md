| Metric | llama3.1:8b | qwen2.5:7b-instruct |
|---|---|---|
| Attack success (all cases) | 7/20 (35%) | 8/20 (40%) |
| &nbsp;&nbsp;vector: direct | 5/6 (83%) | 2/6 (33%) |
| &nbsp;&nbsp;vector: indirect_kb | 1/5 (20%) | 3/5 (60%) |
| &nbsp;&nbsp;vector: indirect_ticket | 0/5 (0%) | 2/5 (40%) |
| &nbsp;&nbsp;vector: indirect_tool | 1/4 (25%) | 1/4 (25%) |
| &nbsp;&nbsp;goal: exfiltrate | 1/6 (17%) | 0/6 (0%) |
| &nbsp;&nbsp;goal: leak_secret | 4/7 (57%) | 2/7 (29%) |
| &nbsp;&nbsp;goal: phishing_link | 1/2 (50%) | 2/2 (100%) |
| &nbsp;&nbsp;goal: unauthorized_action | 1/5 (20%) | 4/5 (80%) |
| Injected content reached the model | 20/20 (100%) | 20/20 (100%) |
| Attack success when exposed | 7/20 (35%) | 8/20 (40%) |
| Canary leaked (any channel, any case) | 4/20 (20%) | 2/20 (10%) |
| Sent email outside fabrikam.example | 3/20 (15%) | 0/20 (0%) |
| Ran any MFA reset | 1/20 (5%) | 4/20 (20%) |
| Malformed tool calls (total) | 0 | 0 |
| Stop reasons | final_answer 20 | final_answer 20 |
| Wall time, all cases (s) | 406.0 | 429.3 |
