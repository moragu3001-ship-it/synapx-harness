"""R2 Activation binding tests."""
from __future__ import annotations

from synapx_harness.validators.activation_validator import validate_activation
from synapx_harness.validators.ratification_validator import compute_receipt_sha256


def _valid_rc() -> dict[str, object]:
    return {
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
    }


def _valid_receipt() -> dict[str, object]:
    receipt = {
        "contract_type": "COMMUNIS_RATIFICATION_RECEIPT",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "ratifiers_required": 4,
        "ratifiers_approved": 4,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
        "decision": "RATIFIED",
        "ratifiers": [],
        "receipt_id": "receipt-001",
    }
    receipt["receipt_sha256"] = compute_receipt_sha256(receipt)
    return receipt


def _valid_activation() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_ACTIVATION_MANIFEST",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "ratification_receipt_ref": {
            "receipt_id": "receipt-001",
            "receipt_sha256": _valid_receipt()["receipt_sha256"],
        },
        "documents": [
            {
                "document_id": "doc-1",
                "document_version": "0.1.0",
                "document_sha256": "b" * 64,
            }
        ],
        "ratifiers_approved": 4,
        "blocking_issue_count": 0,
        "activation_status": "ACTIVE",
    }


def _valid_actual_documents() -> dict[str, dict[str, object]]:
    return {"doc-1": {"document_version": "0.1.0", "document_sha256": "b" * 64}}


def test_activation_requires_ratification_receipt_reference() -> None:
    activation = _valid_activation()
    del activation["ratification_receipt_ref"]
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok


def test_activation_requires_receipt_decision_ratified() -> None:
    receipt = _valid_receipt()
    receipt["decision"] = "PENDING"
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=receipt,
        activation=_valid_activation(),
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok


def test_activation_rc_id_matches_receipt() -> None:
    activation = _valid_activation()
    activation["release_candidate_id"] = "RC-002"
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok


def test_activation_rc_version_matches_receipt() -> None:
    activation = _valid_activation()
    activation["release_candidate_version"] = "0.2.0-rc1"
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok


def test_activation_bundle_hash_matches_receipt() -> None:
    activation = _valid_activation()
    activation["bundle_sha256"] = "c" * 64
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok


def test_activation_document_manifest_is_not_empty() -> None:
    activation = _valid_activation()
    activation["documents"] = []
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok


def test_every_document_hash_matches_actual_manifest() -> None:
    docs = {"doc-1": {"document_version": "0.1.0", "document_sha256": "d" * 64}}
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=_valid_activation(),
        actual_documents=docs,
    )
    assert not report.ok


def test_active_document_requires_activation_manifest_entry() -> None:
    """The activation manifest is the only place ACTIVE status lives."""
    docs: dict[str, dict[str, object]] = {}
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=_valid_activation(),
        actual_documents=docs,
    )
    assert not report.ok


def test_pending_manifest_cannot_grant_execution_authority() -> None:
    activation = _valid_activation()
    activation["activation_status"] = "PENDING"
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok, "PENDING activation cannot grant authority"
    assert not report.activation_status_valid


def test_activation_fails_when_any_document_is_missing() -> None:
    docs = {
        "doc-1": {"document_version": "0.1.0", "document_sha256": "b" * 64},
        "doc-2": {"document_version": "0.1.0", "document_sha256": "c" * 64},
    }
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=_valid_activation(),
        actual_documents=docs,
    )
    assert not report.ok


def test_activation_receipt_sha256_mismatch_is_rejected() -> None:
    activation = _valid_activation()
    activation["ratification_receipt_ref"] = {
        "receipt_id": "receipt-001",
        "receipt_sha256": "z" * 64,
    }
    report = validate_activation(
        rc_bundle=_valid_rc(),
        receipt=_valid_receipt(),
        activation=activation,
        actual_documents=_valid_actual_documents(),
    )
    assert not report.ok
