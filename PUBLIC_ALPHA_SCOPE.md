# Synareon Harness Public Alpha Scope

This document preserves the Public Alpha scope originally frozen for SynapX-Harness 0.1.0.
The project is now publicly branded Synareon Harness.
Frozen capability counts and IDs are unchanged.
Current qualification state may be described using current public terminology.

This document is the authoritative Public Alpha scope statement as of release scope freeze. It is owned by the
Project Owner and binding for the Public Alpha release.

## Scope Freeze != Qualification State

Scope freeze and qualification state are separate dimensions:

- **Scope freeze** records which capabilities are in the Public
  Alpha release scope (the buckets below). The frozen counts and
  capability ID sets are unchanged.
- **Qualification / release state** records what has since been
  released and qualified. Current truth:
  - `v0.1.0` Public Alpha released.
  - GitHub public publication complete.
  - Independently-validated governed Front Door path: the default `synapx`
    Front Door converges on the canonical governed execution
    under the same Harness-owned terminal authority as the
    explicit governed path.
  - Codex Official Headless CLI is the qualified provider.

Statements below that predate the release and describe
pre-release qualification targets are labeled `[HISTORICAL —
scope-freeze wording]` where they are preserved. They are not
current release truth.

## Scope buckets

```yaml
scope:

  PUBLIC_ALPHA_INCLUDED:
    count: 21

  PUBLIC_ALPHA_INTERNAL:
    count: 4

  DEFERRED_POST_ALPHA:
    count: 1

  NOT_SUPPORTED:
    count: 0

  total: 26
```

`PUBLIC_ALPHA_INCLUDED` means **the capability is part of the Public
Alpha release scope**. It does NOT mean the capability is already
qualified for release. Qualification status is tracked separately in
see
[Release Qualification Mapping](#release-qualification-mapping).

## PUBLIC_ALPHA_INCLUDED (21)

| Stable capability ID | Description |
|---|---|
| CAP-002 | CLI `synapx-harness` (validation + review pipeline + storage) |
| CAP-003 | CLI `synapx` (minimal Front Door for governed runtime) |
| CAP-004 | Codex adapter (Lane D headless CLI + provider-neutral models) |
| CAP-006 | Work Contract builder (canonical runtime authority) |
| CAP-007 | Lane C Shared Understanding (FACT/ASSERTION/UNKNOWN) scanner + context |
| CAP-008 | Deterministic verification admission (canonical 18-check) |
| CAP-009 | Independent VerificationPort interface (fail-closed default) |
| CAP-010 | Evidence envelope seal chain (7-state) |
| CAP-011 | 9-stage evidence pipeline (review/ artifact generation) |
| CAP-012 | Review package build/verify/seal/verify-seal (CR4 phase) |
| CAP-013 | Sole terminal finalizer (TERMINAL_FINALIZER issuer) |
| CAP-014 | Activation Validator (SkillActivationContract sole authority) |
| CAP-015 | Governance validator (deterministic, fail-closed) |
| CAP-016 | Knowledge authority validator |
| CAP-017 | Ratification validator (canonical 4-ratifier unanimous) |
| CAP-018 | Environment isolation validator (R2 hardened) |
| CAP-020 | Operational storage hardening (catalog/census/classifier/GC) |
| CAP-021 | Package configuration (`pyproject.toml` metadata) |
| CAP-022 | Documentation (README + CHANGELOG + Kiro README) |
| CAP-023 | GovernedRuntimeProvider (I2-GRW1-R2 integration orchestrator) |
| CAP-024 | JSON Schema 2020-12 validation infrastructure |

## PUBLIC_ALPHA_INTERNAL (4)

| Stable capability ID | Description |
|---|---|
| CAP-001 | Python package identity (synapx-harness 0.1.0-dev [HISTORICAL — scope-freeze wording; released as 0.1.0]) |
| CAP-019 | Production mutation authority (5-stage fail-closed). Used internally by GovernedRuntimeProvider; not exposed via CLI. |
| CAP-025 | Test fixture infrastructure (valid/invalid JSON envelopes) |
| CAP-026 | `.kilo` backup vs current comparison tool (internal-only) |

## DEFERRED_POST_ALPHA (1)

| Stable capability ID | Description |
|---|---|
| CAP-005 | Kiro adapter (transport-only protocol placeholder). Deferred until a concrete Kiro contract is finalized. |

## NOT_SUPPORTED (0)

None.

## Release Qualification Mapping

Inclusion in `PUBLIC_ALPHA_INCLUDED` is the scope statement.
Qualification status is a separate dimension tracked by the following
mapping. A capability must pass the relevant qualification gate
before its user-facing claim can be promoted from "in scope" to
"qualified for release."

| Qualification gate | Capability area |
|---|---|
| RQ-2 | Installation and packaging |
| RQ-3 | Front Door first-run user experience |
| RQ-4 | Governed execution path |
| RQ-5 | Verification / evidence / terminal authority |
| RQ-6 | External repository compatibility |
| RQ-6B1 | Benchmark protocol |
| RQ-7 | Sealed release candidate |
| RQ-8 | Project Owner clean-room dogfood |

See `KNOWN_LIMITATIONS.md` for the current qualification gaps.

## What this document does NOT claim

- It does not claim that all included capabilities are production
  ready.
- It does not claim that benchmark superiority has been established.
- It does not claim full agent coverage. Only Codex (headless CLI) is
  in the Public Alpha support contract.
- [HISTORICAL — scope-freeze wording] At scope freeze, the Front
   Door's default user-runtime wiring was an open
   release-qualification target. Current truth: the independently-validated
   governed Front Door path is released in `v0.1.0` (see
  [Scope Freeze != Qualification State](#scope-freeze--qualification-state)
  and `KNOWN_LIMITATIONS.md`).

## Authority

This scope statement is binding for the Public Alpha release and
is owned by the Project Owner. Modifying the bucket counts or
capability ID sets requires a new Project Owner decision.