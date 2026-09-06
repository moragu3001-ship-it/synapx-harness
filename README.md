# SynapX-Harness

## Primary positioning

**Keep your Codex. Add governed verification, evidence, and completion control.**

SynapX-Harness wraps Codex-driven work with Work Contracts, independent
verification, evidence, and Harness-owned terminal completion authority.
The Harness, not the agent, owns completion decisions.

## Status

- **Release status:** Public Alpha Candidate
- **Public release:** Not yet
- **Production-ready:** No
- **Version:** 0.1.0-dev

Public Alpha Candidate means the release scope is frozen at the
capability-surface level (see `PUBLIC_ALPHA_SCOPE.md`), but each
included capability must still pass additional release-qualification
gates (see `KNOWN_LIMITATIONS.md` and the qualification mapping in
`PUBLIC_ALPHA_SCOPE.md`).

## Why SynapX-Harness

Coding agents are increasingly capable but completion claims from
agents are not the same as verified completion. SynapX-Harness sits
between the agent and the user, holding the authority to confirm
or refuse completion based on independent evidence.

The Harness does not replace Codex. It wraps Codex-driven work with
four harness-owned guarantees:

1. **Governed execution session.** Every run starts from a canonical
   Work Contract issued by the Harness, never self-issued by an agent
   or model.
2. **Independent verification.** VerificationPort runs independently
   of the agent. Agent "DONE" does not imply Verification "PASS".
3. **Evidence-backed results.** Every artifact in the evidence chain is
   hash-bound and sealed; the review package is verifiable end to end.
4. **Harness-owned terminal completion authority.** The Terminal
   Finalizer is the sole issuer of COMPLETED, FAILED, BLOCKED. Agents,
   verifiers, evidence sealers, schedulers, and registries are
   explicitly forbidden as terminal issuers.

## How It Works

```
User / CI
   |
   v
synapx / synapx-harness   (Front Door)
   |
   v
GovernedRuntimeProvider   (Harness-owned orchestrator)
   |
   +---> Work Contract + Execution Identity   (HARNESS_CORE_ADMISSION)
   |
   +---> Shared Understanding (FACT/ASSERTION/UNKNOWN)
   |
   +---> Codex Adapter  (Provider-Neutral Agent Boundary)
   |
   +---> VerificationPort (Fail-Closed Default)
   |
   +---> Evidence Envelope Seal Chain
   |
   +---> Terminal Finalizer   (sole issuer of COMPLETED/FAILED/BLOCKED)
   |
   v
Presentation  (VERIFIED / FAILED / NEEDS_ATTENTION)
```

Authority separation is enforced by the activation authority gate
(`SkillActivationContract` with sole issuer `HARNESS_CORE_ADMISSION`)
and the terminal finalizer (`FORBIDDEN_TERMINAL_ISSUERS` rejects
Verifier, Evidence Sealer, Agent, Provider, Scheduler, Registry).

## Public Alpha Scope

Public Alpha scope is defined in `PUBLIC_ALPHA_SCOPE.md`.

| Bucket | Count |
|---|---|
| PUBLIC_ALPHA_INCLUDED | 21 |
| PUBLIC_ALPHA_INTERNAL | 4 |
| DEFERRED_POST_ALPHA | 1 |
| NOT_SUPPORTED | 0 |
| **Total** | **26** |

21 capabilities are included in the Public Alpha scope. **Inclusion
in scope is not the same as release qualification.** Each included
capability must still pass the qualification gates mapped in
`PUBLIC_ALPHA_SCOPE.md` before the corresponding user-facing surface
can be claimed as ready.

## Supported Coding Agent

| Agent | Support |
|---|---|
| Codex (headless CLI, `codex exec`) | **Included in Public Alpha scope** |
| Codex interactive TUI | Not supported |
| Codex SDK API | Not supported |
| Kiro concrete adapter | Not supported (protocol-only placeholder exists) |
| Claude Code | Not supported |
| Gemini | Not supported |
| Generic OpenCode adapter | Not supported |
| Generic chat-completion adapters | Not supported |

Provider-neutral `AgentRequest` / `AgentResult` contract models exist
in the source for future adapters, but the presence of those models
is not a support claim for any provider that does not have a
concrete, tested adapter.

## CLI Surface

The repository ships two console-scripts:

| Script | Purpose |
|---|---|
| `synapx-harness` | Operator CLI: validation, review pipeline, storage maintenance |
| `synapx` | Front Door: natural-language task entry |

### `synapx-harness` subcommands

```text
synapx-harness --version

synapx-harness scaffold validate     --root <service-pack-path>
synapx-harness contract validate    --root <service-pack-path>
synapx-harness repository list      --root <service-pack-path>
synapx-harness policy validate      --root <service-pack-path>

synapx-harness review build         --workspace-root <path> --phase <phase> --core <path> --core-ref <sha> --service-pack <path> --service-pack-ref <sha> --out <zip>
synapx-harness review verify        <zip>
synapx-harness review seal          <zip> --output-receipt <path>
synapx-harness review verify-seal   <zip> --receipt <path>

synapx-harness storage census       --runs-root <path> [--project-root <path>] [--skip-ref-scan]
synapx-harness storage gc           --runs-root <path> [--project-root <path>] [--skip-ref-scan] [--ttl-days <N>] [--max-total-bytes <N>] [--apply]
```

### `synapx` (Front Door)

```text
synapx --version
synapx [--workspace <path>] [--task <task>]
```

### `synapx doctor` (readiness diagnostic)

```text
synapx doctor            # human-readable readiness summary
synapx doctor --json     # machine-readable readiness JSON
```

`doctor` reports the installed distribution version, the supported
agent, the Codex CLI version (or `NOT_FOUND`), and the workspace path.
It is the recommended first-run check before
`synapx --workspace <repo> --task <task>`.

### `synapx run` (governed execution)

```text
synapx run --workspace <repo> --task "<task>" [--receipt-out <path>]
```

`run` drives the canonical positive path: Shared Understanding ->
WorkContract -> ExecutionIdentity -> Codex Official Headless CLI ->
structured proposal -> mutation chain -> independent verifier ->
evidence seal -> terminal decision. Output is one of the public
presentation labels: `VERIFIED`, `FAILED`, or `NEEDS_ATTENTION`.
`--receipt-out` (optional) writes the canonical same-run lineage
envelope to a file. The Front Door does NOT decide terminal
authority; that authority lives in the Terminal Finalizer.

## Current Limitations

See `KNOWN_LIMITATIONS.md` for the authoritative list.

The single highest-priority Public Alpha limitation:

> The `synapx` Front Door is present, but its default RuntimePort
> is not yet wired to the governed runtime for a normal end-user
> installation. This is a release qualification target for RQ-3.

The Front Door is not absent; its implementation is present and
its default user-runtime wiring is the release-qualification target.

## What Is Not In Public Alpha

The following are explicitly carved out of Public Alpha and remain
deferred to post-Alpha:

- Autopilot completion export and `synapx export latest`
- Review-handoff bundle
- Full Autopilot loop (multi-attempt autonomous retry)
- Parallel-agent orchestration
- Cost-aware model routing
- Full Service Pack platform (authoring + lifecycle)
- Full Graphify (knowledge graph execution)
- Cognitive production pipeline
- Atlas / Nexus integration
- Chronos / Lens / Aegis / Nomos production platforms
- Fullscreen TUI / history browser / interactive Execution Map
- Graphical Evidence Explorer
- Full Intent Grounding implementation
- Codex SDK API adapter (no SDK backend exists in source)
- Kiro concrete adapter (protocol-only placeholder only)

These items are not pulled back into the Public Alpha critical path.

## AI-assisted development

> AI coding agents were extensively used to assist implementation and
> verification. Architecture, contracts, acceptance criteria,
> qualification gates, and final release decisions remained
> maintainer-controlled.

This applies to the source code, contract tests, and release
documentation of SynapX-Harness.

## License

This project is licensed under the Apache License 2.0. See the
[`LICENSE`](./LICENSE) file for the full canonical text.

SPDX-License-Identifier: `Apache-2.0`

No NOTICE file is currently distributed. Apache-2.0 §4(d) NOTICE
preservation obligations are conditional on the original Work
containing a NOTICE file; with no NOTICE shipped, no §4(d)
obligation is triggered on Derivative Works.