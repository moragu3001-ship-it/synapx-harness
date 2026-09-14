# Changelog

All notable changes to this project are documented here.

## [Unreleased] - Post-publication docs/metadata hotfix (main only)

> This hotfix is documentation and repository metadata only. It is
> not part of the immutable `v0.1.0` tag payload or release
> artifacts. Runtime is unchanged. `0.1.1` is not created.

### Added
- `CONTRIBUTING.md`: minimal OSS contributor guide.
- `SECURITY.md`: private vulnerability reporting policy (GitHub Private Vulnerability Reporting).

### Changed
- `KNOWN_LIMITATIONS.md`: retired pre-publication active-state claims; reflects released 0.1.0 truth. Install-path limitation narrowed to the qualified pip-wheel clean-install path.
- `PUBLIC_ALPHA_SCOPE.md`: separated Scope Freeze from Qualification State; historical scope-freeze wording labeled as historical.
- GitHub repository metadata: description and topic set aligned with the Public Alpha.
- Public project brand renamed from SynapX-Harness to Synareon Harness.
- GitHub repository renamed to `synareon-harness`.
- Historical `v0.1.0` release identity and artifacts remain unchanged.

## [0.1.0] - 2026-09-14 - Public Alpha

### Added
- Public Alpha publication: `v0.1.0` released on GitHub with public repository access.
- RQ8 clean-room qualification accepted for the canonical governed Front Door path.
- Bounded public timeout control for governed execution.
- Public `README.md` / repository publication materials for the 0.1.0 Public Alpha.

### Notes
- No new functional capability beyond the already-qualified Public Alpha scope.
- `v0.1.0` tag and release artifacts are immutable. No version 0.1.1 created; no tag moved; no qualification rerun.

## [0.1.0-dev] - Unreleased (historical pre-release record, superseded by 0.1.0 above)

### Added
- Apache License 2.0 (`LICENSE`) applied per Project Owner decision (D3).
- `PUBLIC_ALPHA_SCOPE.md`: authoritative Public Alpha scope statement (21 INCLUDED / 4 INTERNAL / 1 DEFERRED / 0 NOT_SUPPORTED) per Project Owner decision (D1).
- `KNOWN_LIMITATIONS.md`: authoritative Public Alpha known-limitations list per Project Owner decision (D1 + D4).

### Changed
- `pyproject.toml`: PEP 639 license metadata (`license = "Apache-2.0"`, `license-files = ["LICENSE"]`) and updated `description`.
- `README.md`: Public Alpha Candidate framing with primary positioning *"Keep your Codex. Add governed verification, evidence, and completion control."*, mechanism-claim language only, and explicit deferred-item carve-outs.

### Notes
- No release version bump. Version remains `0.1.0-dev`.
- No new source code, schema, test, or lockfile changes.
- Source application is bounded to the RQ1-R2 allowlist: `LICENSE`, `README.md`, `CHANGELOG.md`, `pyproject.toml`, `PUBLIC_ALPHA_SCOPE.md`, `KNOWN_LIMITATIONS.md`.

## [0.1.0-dev] - 2026-08-07

### Changed
- Public identity rename (H0): distribution `customos-core` -> `synapx-harness`, import namespace `customos_core` -> `synapx_harness`, CLI `customos` -> `synapx-harness`, env prefix `CUSTOMOS_` -> `SYNAPX_HARNESS_`.
- Historical sealed evidence (`_runs`, `_tracks`, review, receipts) left immutable.

## [0.1.0-dev] - 2026-07-23

### Added
- Bootstrap scaffold for customos-core.
- OKF, Governance, and Runtime contract skeletons.
- Minimum CLI (`customos`) with --version, scaffold validate, contract validate, repository list, policy validate.
- TDD-based contract tests and isolation validator.
- Environment isolation validator (rejects SynapX / legacy Kilo runtime / symlink / forbidden package names).
