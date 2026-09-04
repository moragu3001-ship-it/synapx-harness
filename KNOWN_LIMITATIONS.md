# Known Limitations

This document is the authoritative list of known limitations for the
SynapX-Harness Public Alpha Candidate. Limitations are listed with
their qualification / backlog gates where applicable.

## Release status limitations

- **Public Alpha Candidate only.** This is not a production-ready
  release. Each included capability must still pass additional
  release-qualification gates (see `PUBLIC_ALPHA_SCOPE.md`).
- **Not yet public-released.** Internal GitLab is the only origin;
  public GitHub publication is not authorized.
- **No production-ready claim.** "Production-ready" is a forbidden
  claim for Public Alpha.

## Platform limitations

- **Python >= 3.12.** `requires-python = ">=3.12"`. No Python 3.13+
  testing in this release.
- **uv-based install.** `uv` is the implied build system. `pip` /
  `poetry` install paths are not exercised.

## Coding-agent coverage limitations

- **Codex headless CLI only.** The only supported agent surface in
  Public Alpha is the Codex headless CLI invocation (`codex exec`).
- **Codex authentication owned by user / vendor.** SynapX-Harness
  does not provide Codex authentication. The user authenticates
  Codex CLI independently.
- **No Codex SDK / API adapter.** No SDK backend exists; the SDK
  API surface is explicitly unsupported.
- **No interactive TUI authority.** Codex interactive TUI scraping
  is non-authoritative and disallowed.
- **No Claude / Gemini / OpenCode adapters.** Other commercial
  agent CLIs are not supported.
- **Kiro is a protocol-only placeholder.** No concrete Kiro
  adapter implementation is shipped.

## Front Door limitations

- **Front Door default runtime wiring not yet qualified.** The
  `synapx` Front Door is implemented, but its default `RuntimePort`
  is not yet wired to the governed runtime for a normal end-user
  installation. This is a release qualification target for RQ-3.
- **No resume / history UI.** There is no `synapx resume`, no
  history browser, and no interactive Execution Map in Public Alpha.

## Orchestration limitations

- **No full Autopilot.** Public Alpha is single-shot, governed
  runtime only. Multi-attempt autonomous retry is post-Alpha.
- **No parallel-agent orchestration.** Single-agent runtime only.
- **No cost-aware model routing.** Single Codex model per invocation.

## Validation / verification limitations

- **Verification has no benchmark.** No benchmark numbers ship in
  Public Alpha. Performance claims are deferred until RQ-6B1.
- **No zero-regression guarantee.** Quantitative regression
  reduction is not a Public Alpha claim.
- **No published benchmark superiority.** Comparisons against other
  agents are deferred until RQ-6B1.

## Service Pack limitations

- **Service Pack validation only.** The Harness can validate a
  Service Pack against its governance contracts. It cannot author,
  edit, or publish a Service Pack in Public Alpha.

## Production platform limitations (all deferred post-Alpha)

- No full Service Pack platform.
- No full Graphify (knowledge graph execution).
- No Cognitive production pipeline.
- No Atlas / Nexus integration.
- No Chronos, Lens, Aegis, or Nomos production platforms.

## Sandbox limitations

- **No built-in sandbox.** Public Alpha does not ship a container,
  VM, or OS-level isolation layer. The Harness relies on host
  isolation (git working-tree cleanliness + the environment
  isolation validator's forbidden-package checks).

## Evidence / storage limitations

- **Evidence storage is local.** `_runs` directory on the host
  filesystem. No remote / cloud evidence storage.
- **Default retention:** 90-day TTL, 5 GiB quota.
- **GC is opt-in.** Dry-run by default; `--apply` required for
  actual deletion.

## Stability expectations

- **0.x API breakage is possible.** SynapX-Harness follows SemVer
  0.x conventions. Minor versions may contain breaking changes.
  Pin exact versions in any downstream consumption.

## What this document does NOT claim

- It does not claim "zero regressions", "guaranteed safe", or
  "guaranteed correct".
- It does not claim enterprise production readiness.
- It does not claim full coding-agent coverage.
- It does not claim full autonomous software development.

These are explicitly forbidden claims for the Public Alpha.

## Authority

This limitations list is owned by the Project Owner. Adding or
removing a limitation requires a new Project Owner decision.