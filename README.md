# SynapX-Harness

**Use your coding agent. SynapX checks whether the work is actually complete.**

SynapX-Harness is an open-source assurance layer for coding-agent execution.

Your coding agent still explores, reasons, writes code, and fixes bugs. SynapX controls the assurance boundary around that work: whether execution was admitted, whether mutation stayed in scope, whether deterministic verification passed, whether the evidence is sufficient, and whether completion may be declared.

> **Agent DONE ≠ SynapX COMPLETED.**

**Public Alpha 0.1.0** · Codex-first · Not production-certified

Public Alpha currently supports the **Codex Official Headless CLI**.

---

## Public Alpha in action

Representative output from the accepted RQ8 governed clean-room path:

```text

Agent Activity

  Completed

Changes

  src/itsdangerous/url_safe.py

SynapX Assurance

  ✓ Mutation observed

  ✓ Scope authorized

Verification

  uv run pytest -q

  ✓ PASS

Evidence

  ✓ Qualified

VERIFIED

```

`VERIFIED` is not an agent self-report.

It is the public presentation of a Harness-owned terminal decision reached after the governed execution path qualifies the required controls.

Internally, terminal completion authority remains separate from the UI presentation label.

---

## Quick Start — validated Windows path

The Public Alpha clean-room qualification path was validated on Windows using a sealed Wheel on a separate PC.

### Requirements

* Python 3.12 or later, according to the current package contract

* Git

* Codex Official Headless CLI available on `PATH`

RQ8 clean-room qualification used:

```text

Python 3.12.14

Codex CLI 0.153.4

```

Public Alpha does not require those exact versions unless the release contract or package metadata says otherwise.

### Install

Download the `0.1.0` Wheel from the GitHub Release, create a clean virtual environment, and install it:

```powershell

python -m venv .venv

.\.venv\Scripts\Activate.ps1

python -m pip install .\synapx_harness-0.1.0-py3-none-any.whl

```

### Check readiness

```powershell

synapx doctor

```

A ready environment reports:

* installed SynapX-Harness distribution

* supported coding agent

* Codex CLI readiness

* current workspace

For machine-readable output:

```powershell

synapx doctor --json

```

### Run a governed task

Mutation tasks currently require an **explicit allowed write set**.

This is a fail-closed assurance boundary, not automatic scope inference.

```powershell

$TASK = @'

Fix the requested defect without modifying files outside the declared scope.

Allowed write paths:

- src/example.py

'@

synapx --workspace . --task "$TASK"

```

If the required write scope is missing, SynapX may stop with:

```text

NEEDS_ATTENTION

```

before allowing the coding agent to mutate the repository.

The default execution timeout is 120 seconds.

For legitimately longer bounded tasks:

```powershell

synapx --workspace . --task "$TASK" --timeout-seconds 600

```

Public Alpha permits an explicit timeout override within the supported runtime bounds.

---

## Interactive Front Door

Running:

```powershell

synapx

```

opens the minimal interactive Front Door when the terminal is interactive.

Mutation tasks still require an explicit write scope, so the explicit `--task` example above is the clearest first example for scoped code changes.

---

## Explicit governed command

```powershell

synapx run --workspace . --task "$TASK"

```

`synapx` and `synapx run` converge on the same canonical governed execution and the same Harness-owned terminal authority.

`synapx run` remains the explicit governed execution surface and can also expose the same-run receipt option where supported.

---

## What just happened?

At a high level:

```text

User Task

    ↓

Admission / Explicit Scope

    ↓

Coding Agent

    ↓

Controlled Mutation

    ↓

Independent Verification

    ↓

Evidence Qualification

    ↓

Terminal Decision

```

The coding agent performs the reasoning and implementation work.

SynapX decides whether the result is qualified to be called complete.

---

## Why SynapX?

A coding agent can say:

```text

"Done."

"Tests look good."

"The bug is fixed."

```

Those statements are useful proposals, but they are still produced by a probabilistic system.

SynapX-Harness asks a different question:

> **What evidence qualifies this work for completion?**

Its core principle is:

> **Reasoning proposes. Evidence qualifies. Authority decides.**

This lets an agent remain useful and autonomous without making its own completion claim the final source of truth.

---

## A failure that shaped Public Alpha

During RQ8 clean-room dogfooding, an early Front Door path could present:

```text

VERIFIED

```

even though the intended source mutation had not occurred and the controlled regression still had:

```text

24 failed, 273 passed

```

The release was blocked.

The default Front Door was then converged onto the canonical governed execution path so that user-visible completion follows the same Harness-owned terminal authority as the explicit governed path.

> **Failure is permitted. Unqualified completion is not.**

The point of this story is not that failures disappeared.

It is that a failure must not be silently promoted into completion.

---

## Current Public Alpha support

### Currently supported

* Codex Official Headless CLI

* canonical governed execution from the public Front Door

* explicit mutation-scope admission

* controlled mutation observation

* scope qualification

* deterministic verification

* evidence qualification

* Harness-owned terminal completion

* readiness diagnostics with `synapx doctor`

* bounded public execution timeout control

* minimal interactive Front Door

* operator-facing review and storage CLI surfaces

### Current limitations

* Codex is the only qualified coding-agent provider in Public Alpha.

* Mutation tasks require an explicit allowed write set.

* Some repair paths require a qualified RED expectation bound to the WorkContract.

* Missing RED qualification fails closed before mutation where RED qualification is required.

* Public Alpha qualification is Python/OSS focused.

* Broad language and framework coverage is not claimed.

* The interactive Front Door is intentionally minimal, not a full TUI.

* Multi-agent orchestration is not a Public Alpha feature.

* Rich Execution Map and graphical Evidence Explorer are not Public Alpha features.

* Autonomous bounded repair loops are not Public Alpha features.

* Additional coding-agent providers are not yet qualified.

See `KNOWN_LIMITATIONS.md` and `PUBLIC_ALPHA_SCOPE.md` for authoritative repository-level detail.

---

## RQ8 clean-room validation

Public Alpha's core governed execution path was qualified through RQ8 clean-room dogfooding on a separate Windows PC using a sealed Wheel rather than the SynapX-Harness source checkout.

The target was a fresh checkout of:

```text

pallets/itsdangerous

```

The experiment deliberately injected a controlled regression.

It did **not** claim to discover a naturally occurring upstream ItsDangerous bug.

The accepted flow was:

```text

Sealed Wheel

→ wheel-only clean install

→ Codex readiness

→ fresh external OSS checkout

→ pristine baseline

→ controlled regression

→ qualified RED

→ scoped governed repair

→ deterministic verification

→ Evidence qualification

→ Terminal Finalizer COMPLETED

→ public VERIFIED

→ independent GREEN verification

```

The pristine baseline was:

```text

297 passed

```

The controlled RED state was:

```text

24 failed, 273 passed

```

The first governed attempt failed closed because the task did not declare the required write scope.

No source repair was authorized by that attempt.

A bounded task-contract repair added:

```text

src/itsdangerous/url_safe.py

```

to the allowed write set without changing the target source itself.

The second governed attempt passed the required assurance path and produced the public result:

```text

VERIFIED

```

with process exit code:

```text

0

```

The accepted RQ8 record reports an operator-observed final independent GREEN result of:

```text

297 passed

```

The standalone raw GREEN execution receipt was not preserved, so this README does not claim stronger evidence than the accepted RQ8 record supports.

This is qualification evidence for the Public Alpha execution path.

It is **not** a benchmark claim about superiority over raw coding-agent workflows.

---

## How SynapX works

SynapX separates **agent intelligence** from **execution assurance**.

### Coding agent

Typically owns:

```text

repository exploration

reasoning

planning

implementation

debugging

repair strategy

tool use

```

### SynapX-Harness

Focuses on:

```text

authority

admission

scope

mutation control

deterministic verification

evidence

lineage

terminal completion

```

Internal contract names and implementation details are intentionally secondary to the user-facing outcome.

Contributors can inspect the repository contracts and architecture documentation when they need that level of detail.

---

## Terminal semantics

Public output uses three terminal-facing labels.

### `VERIFIED`

The governed terminal decision qualified completion.

### `FAILED`

Execution reached an authoritative failure.

### `NEEDS_ATTENTION`

The run was blocked or could not qualify completion.

Agent completion alone cannot produce authoritative `VERIFIED`.

The public presentation label is derived from the governed terminal state; the Front Door does not independently create completion authority.

---

## Controlled RED qualification

For repair paths that require a known failing state, SynapX does not assume:

```text

command failed

=

intended defect reproduced

```

A failing command could instead represent:

```text

environment failure

dependency failure

collection failure

unrelated regression

intended defect

```

Where RED qualification is required, the observed failure must be bound to a qualified expectation before mutation authority is granted.

In other words:

```text

Qualified RED Expectation

        +

Observed Failure

        ↓

Deterministic Qualification

        ↓

Mutation Admission

```

A failed command by itself is not proof that the intended defect has been reproduced.

---

## Benchmark / Open Lab

> **No benchmark superiority is claimed yet. Public Alpha begins the open measurement phase.**

The intended comparison is:

```text

Raw coding agent

vs

Coding agent + SynapX-Harness

```

Future measurements may examine:

* qualified task success

* false completion

* regression escape

* scope violations

* repair attempts

* human intervention

* token usage

* execution time

* cost

Numbers will be published only when the corresponding task set, revisions, lineage, raw evidence, and reproduction method are available.

SynapX-Harness is also an open experiment in Agent Assurance:

```text

Hypothesis

→ Minimal implementation

→ Dogfood / Benchmark

→ Evidence

→ Failure analysis

→ Adjustment

→ Re-measure

```

Negative results are evidence, not something to hide.

---

## AI-assisted development

AI coding agents were extensively used to assist implementation and verification.

Architecture, contracts, acceptance criteria, qualification gates, and final release decisions remained maintainer-controlled.

This disclosure applies to the source code, contract tests, and release documentation of SynapX-Harness.

---

## Contributing

Contributions are welcome, especially:

* reproducible failure cases

* benchmark fixtures

* verification providers

* agent adapters

* policy experiments

* documentation improvements

* external reproduction reports

Core assurance changes must not bypass:

```text

authority

verification

evidence

terminal completion

```

See `CONTRIBUTING.md`.

---

## Security

Do not report sensitive vulnerabilities through a public GitHub Issue when disclosure could create risk.

See `SECURITY.md`.

---

## License

Apache License 2.0.

See `LICENSE`.

---

## Philosophy

SynapX-Harness explores a broader question:

> **How can probabilistic AI agents be given meaningful autonomy while reliably converging on trustworthy outcomes without shifting the control burden back to humans?**

Guiding principles:

> **Users experience the outcome. Contributors discover the architecture.**

> **Agent DONE ≠ SynapX COMPLETED.**

> **Failure is permitted. Unqualified completion is not.**

> **Reasoning proposes. Evidence qualifies. Authority decides.**
