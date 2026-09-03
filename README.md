# synapx-harness

SynapX-Harness Core Scaffold and Contract Skeleton.

## Status

- Phase: SYNAPX-HARNESS-H2-I5-DOGFOOD
- Version: 0.1.0-dev
- Classification: HARNESS_VALIDATED

## Scope

- OKF base contract skeleton.
- Governance Profile schemas.
- SynapX-Harness Runtime Contract schemas.
- CLI (`synapx-harness`, `synapx`).
- Environment isolation validator.
- TDD-based contract tests.
- R7 review pipeline (build, verify, seal).
- Storage management (census, gc).

## Out of Scope

- Source Census / Graphify execution.
- Obsidian activation.
- Release Candidate generation.
- Kerberos / Kiro Hook implementation.
- Application source mutation.

## Repository Hygiene

- Backup is FROZEN reference only.
- No imports from backup scripts, schemas, fixtures, or wiki.
- No SynapX runtime imports.
- No legacy Kilo runtime product adapters.

## CLI Commands

### Validation

```text
synapx-harness --version
synapx-harness scaffold validate --root <service-pack-path>
synapx-harness contract validate --root <service-pack-path>
synapx-harness repository list --root <service-pack-path>
synapx-harness policy validate --root <service-pack-path>
```

### Review Pipeline

```text
synapx-harness review build --workspace-root <path> --phase <phase> --core <path> --core-ref <sha> --service-pack <path> --service-pack-ref <sha> --out <zip>
synapx-harness review verify <zip>
synapx-harness review seal <zip> --output-receipt <path>
synapx-harness review verify-seal <zip> --receipt <path>
```

### Storage

```text
synapx-harness storage census --root <path>
synapx-harness storage gc --root <path>
```

### Frontdoor (synapx CLI)

```text
synapx --version
synapx <command>
```
