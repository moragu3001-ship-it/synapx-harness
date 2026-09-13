"""Repository registry contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_repository_registry_valid_payload() -> None:
    payload = {
        "contract_type": "COMMUNIS_REPOSITORY_REGISTRY",
        "schema_version": "0.1.0",
        "service_id": "communis-portal",
        "registry_state": "DRAFT",
        "authority": "NON_AUTHORITATIVE",
        "repositories": [
            {
                "repository_id": "x",
                "local_path": "D:/x",
                "role": "AS_IS_LEGACY_CANDIDATE",
                "analysis_mode": "READ_ONLY",
                "authority": "NON_AUTHORITATIVE",
                "ratification_state": "NOT_RATIFIED",
            }
        ],
    }
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/repository_registry.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors


def test_repository_registry_requires_contract_type() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/repository_registry.schema.json",
        payload={"schema_version": "0.1.0", "repositories": []},
    )
    assert not report.ok, report.errors
