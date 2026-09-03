"""Release candidate contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def _valid_rc_payload() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_RC_BUNDLE",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "0" * 64,
        "document_refs": [
            {
                "document_id": "doc-1",
                "document_version": "0.1.0",
                "document_sha256": "f" * 64,
            }
        ],
        "ratification_status": "PENDING",
        "execution_authority": False,
    }


def test_release_candidate_has_no_execution_authority() -> None:
    payload = _valid_rc_payload()
    payload["execution_authority"] = True
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/release_candidate_bundle.schema.json",
        payload=payload,
    )
    assert not report.ok, report.errors


def test_release_candidate_is_not_active() -> None:
    payload = _valid_rc_payload()
    payload["ratification_status"] = "ACTIVE"
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/release_candidate_bundle.schema.json",
        payload=payload,
    )
    assert not report.ok, report.errors


def test_release_candidate_requires_bundle_sha256() -> None:
    payload = _valid_rc_payload()
    payload["bundle_sha256"] = "not-hex"
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/release_candidate_bundle.schema.json",
        payload=payload,
    )
    assert not report.ok, report.errors


def test_release_candidate_valid_payload() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/release_candidate_bundle.schema.json",
        payload=_valid_rc_payload(),
    )
    assert report.ok, report.errors
