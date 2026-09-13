# Known Limitations

This document is the authoritative list of known limitations for the
SynapX-Harness Public Alpha 0.1.0 release. Limitations are listed
with their qualification / backlog gates where applicable.

## Release status

- **Public Alpha 0.1.0 released.** GitHub public publication is
  complete and the RQ8 clean-room qualification is accepted.
- **Default Front Door canonical governed execution qualified.**
  The `synapx` Front Door converges on the canonical governed
  execution path under the same Harness-owned terminal authority
  as the explicit governed path (see `README.md`).
- **Codex Official Headless CLI is the current qualified
  provider.** Additional agent providers are not yet qualified.
- **Not production-ready.** Each Public Alpha capability remains
  subject to the scope and qualification boundaries in
  `PUBLIC_ALPHA_SCOPE.md`. "Production-ready" is a forbidden
  claim for Public Alpha.

## Platform limitations

- **Python/OSS-focused qualification.** Public Alpha
  qualification is Python/OSS focused. Broad language and
  framework coverage is not claimed.
- **Python >= 3.12.** `requires-python = ">=3.12"`. No Python 3.13+
  testing in this release.
- **Qualified install path is narrow.** The qualified path is
  installing the released `0.1.0` Wheel with `pip` into a clean
  virtual environment (the RQ8 wheel-only clean-install path
  documented in `README.md`). `uv`-based, `poetry`-based, and
  other install surfaces are not exercised and remain
  unqualified.
- **Large source context on Windows.** When the governed pipeline
  embeds a very large source file (~40KB or more) into a Codex
  instruction that is then passed through a Windows `CreateProcess`
  invocation, the host process command-line length limit can affect
  invocation. RQ6 qualification covered normal Python OSS single-file
  repair and did not exercise this boundary. Downstream users on
  Windows who attempt very-large single-file mutations may need to
  split the work. This limitation is included in the Public Alpha
  Known Limitations list per Project Owner decision.

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

- **Minimal interactive Front Door.** The `synapx` Front Door runs
  the canonical governed execution path, but its interactive
  surface is intentionally minimal, not a full TUI.
- **No resume / history UI.** There is no `synapx resume`, no
  history browser, no interactive Execution Map, and no full
  graphical Evidence Explorer in Public Alpha.

## Orchestration limitations

- **No full Autopilot.** Public Alpha is single-shot, governed
  runtime only. Multi-attempt autonomous retry is post-Alpha.
- **No parallel-agent orchestration.** Single-agent runtime only.
- **No cost-aware model routing.** Single Codex model per invocation.

## Validation / verification limitations

- **Explicit allowed write set required.** Mutation tasks require
  an explicitly declared allowed write set. There is no automatic
  scope inference; missing scope fails closed before mutation.
- **Qualified RED expectation required where RED qualification
  applies.** Repair paths that require a known failing state must
  bind the observed failure to a qualified expectation before
  mutation authority is granted.

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