"""Activation contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.activation_validator import validate_activation
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def _valid_rc() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_RC_BUNDLE",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "b" * 64,
        "document_refs": [],
        "ratification_status": "RATIFIED",
        "execution_authority": False,
    }


def _valid_receipt() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_RATIFICATION_RECEIPT",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "b" * 64,
        "ratifiers_required": 4,
        "ratifiers_approved": 4,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
        "decision": "RATIFIED",
        "ratifiers": [],
        "receipt_id": "receipt-001",
        "receipt_sha256": "c" * 64,
    }


def _valid_activation() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_ACTIVATION_MANIFEST",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "b" * 64,
        "ratification_receipt_ref": {"receipt_id": "receipt-001", "receipt_sha256": "c" * 64},
        "documents": [
            {
                "document_id": "doc-1",
                "document_version": "0.1.0",
                "document_sha256": "d" * 64,
            }
        ],
        "ratifiers_approved": 4,
        "blocking_issue_count": 0,
        "activation_status": "ACTIVE",
    }


def _valid_documents() -> dict[str, dict[str, object]]:
    return {
        "doc-1": {
            "document_version": "0.1.0",
            "document_sha256": "d" * 64,
        }
    }


def test_activation_requires_ratified_receipt() -> None:
    receipt = _valid_receipt()
    receipt["decision"] = "PENDING"
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=receipt,
        activation=_valid_activation(),
        actual_documents=_valid_documents(),
    )
    assert not report.ok


def test_activation_requires_document_hash_match() -> None:
    docs = {"doc-1": {"document_version": "0.1.0", "document_sha256": "e" * 64}}
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=_valid_activation(),
        actual_documents=docs,
    )
    assert not report.ok


def test_activation_valid_payload() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/activation_manifest.schema.json",
        payload=_valid_activation(),
    )
    assert report.ok, report.errors


def test_activation_missing_document_is_rejected() -> None:
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=_valid_activation(),
        actual_documents={},
    )
    assert not report.ok


def test_activation_unexpected_document_is_rejected() -> None:
    docs = {
        "doc-1": {"document_version": "0.1.0", "document_sha256": "d" * 64},
        "doc-2": {"document_version": "0.1.0", "document_sha256": "e" * 64},
    }
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=_valid_activation(),
        actual_documents=docs,
    )
    assert not report.ok


def test_activation_rc_id_must_match_receipt() -> None:
    receipt = _valid_receipt()
    receipt["release_candidate_id"] = "RC-002"
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=receipt,
        activation=_valid_activation(),
        actual_documents=_valid_documents(),
    )
    assert not report.ok
