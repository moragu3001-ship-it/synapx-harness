# Contributing to Synareon Harness

Thank you for your interest in the Synareon Harness Public Alpha (`0.1.x`).

## Useful contribution types

- Reproducible failure cases
- Benchmark fixtures
- Verification providers
- Agent adapters
- Policy experiments
- Documentation improvements
- External reproduction reports

## Bug reports

Please include:

- Synareon Harness version
- OS
- Python version
- Agent / provider (and Codex version where relevant)
- Reproduction steps
- Expected result
- Actual result
- Relevant evidence / logs

## Pull requests

Please describe:

- Problem
- Failure condition
- Scope
- Verification
- Evidence
- Core / Extension / Adapter classification:
  - **Core** — changes to assurance authority, verification, evidence, or terminal completion
  - **Extension** — new verification providers, policy experiments, or benchmark fixtures
  - **Adapter** — new or changed coding-agent adapters

Core assurance changes must not bypass authority, verification,
evidence, or terminal completion.

## Review question

Every non-trivial change should answer:

> If coding agents become much smarter, should this responsibility still remain in Synareon?

Possible architectural dispositions:

- **KEEP** — the responsibility stays in Synareon
- **SPLIT** — part stays, part moves to the agent or tooling
- **DELEGATE** — the responsibility moves out of Synareon
- **REJECT** — the change is declined

## Scope notes

- Public Alpha supports the Codex Official Headless CLI only.
  Additional providers are not yet qualified.
- Keep contributions minimal and evidence-backed. This is not a
  large-contributor-handbook project; small, reproducible,
  well-evidenced changes are preferred.
