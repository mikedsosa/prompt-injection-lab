# Security policy

This repository is a **lab project, not production software**. All data is synthetic (`fabrikam.example`) and the tools are mocks; nothing touches a real account, mailbox or network.

## Reporting a problem

If you find a security issue (for example a query, script or config that could cause harm if copied as is, or anything that looks like an exposed secret), please report it privately through GitHub's **[Report a vulnerability](https://github.com/mikedsosa/prompt-injection-lab/security/advisories/new)** form rather than opening a public issue. Ordinary bugs and corrections can go in a normal issue.

Please include the file and line, what you expected and what happened. Reports are handled on a best-effort basis; there is no SLA.

## Secrets and data

- Never include credentials, tokens, tenant IDs or real user data in an issue, pull request or report.
- This repo is meant to contain no secrets. Commits are scanned with `gitleaks`.
- Injection payloads in `cases/` are test fixtures against a mock agent. Do not point them at real systems you do not own.

## Supported versions

Only the latest commit on `main` is maintained.
