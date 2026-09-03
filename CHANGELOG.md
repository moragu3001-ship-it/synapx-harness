# Changelog

All notable changes to this project are documented here.

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
