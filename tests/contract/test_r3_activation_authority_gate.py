"""R3 Activation Authority Gate Tests.

Tests that enforce strict authority validation:
  - PENDING activation is rejected
  - BLOCKED activation is rejected
  - Only ACTIVE activation grants authority
  - Receipt hash must be present and valid
  - Ratification must be re-validated
"""
from __future__ import annotations

import hashlib
from typing import cast


def _make_doc_dict() -> dict[str, str]:
    return {
        "document_id": "doc-001",
        "document_version": "1.0.0",
        "document_sha256": "b" * 64,
    }


def _make_doc_dict_c() -> dict[str, str]:
    return {
        "document_id": "doc-001",
        "document_version": "1.0.0",
        "document_sha256": "c" * 64,
    }


def _valid_rc_bundle() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_RC_BUNDLE",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "document_refs": [],
        "ratification_status": "RATIFIED",
        "execution_authority": True,
    }


def _valid_ratifier_records() -> list[dict[str, object]]:
    return [
        {
            "ratifier_id": f"r{i}",
            "decision": "APPROVE",
            "release_candidate_id": "RC-001",
            "release_candidate_version": "0.1.0-rc1",
            "bundle_sha256": "a" * 64,
            "approved_at": "2026-07-23T00:00:00Z",
        }
        for i in range(4)
    ]


def _build_valid_receipt() -> dict[str, object]:
    from synapx_harness.validators.ratification_validator import compute_receipt_sha256

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
        "receipt_id": "receipt-001",
        "ratifiers": _valid_ratifier_records(),
    }
    receipt["receipt_sha256"] = compute_receipt_sha256(receipt)
    return receipt


def _receipt_ratifiers(receipt: dict[str, object]) -> list[dict[str, object]]:
    return cast(list[dict[str, object]], receipt["ratifiers"])


def _valid_activation() -> dict[str, object]:
    receipt = _build_valid_receipt()
    return {
        "contract_type": "COMMUNIS_ACTIVATION_MANIFEST",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "ratification_receipt_ref": {
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
        },
        "documents": [
            {
                "document_id": "doc-001",
                "document_version": "1.0.0",
                "document_sha256": "b" * 64,
            }
        ],
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "ratifiers_approved": 4,
        "blocking_issue_count": 0,
        "activation_status": "ACTIVE",
    }


def test_pending_activation_is_rejected_for_authority() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    activation["activation_status"] = "PENDING"
    receipt = _build_valid_receipt()
    receipt["ratification_receipt_ref"] = activation["ratification_receipt_ref"]

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.authority_granted, "PENDING activation should be rejected for authority"
    assert not report.activation_status_valid


def test_blocked_activation_is_rejected_for_authority() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    activation["activation_status"] = "BLOCKED"
    receipt = _build_valid_receipt()
    receipt["ratification_receipt_ref"] = activation["ratification_receipt_ref"]

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.authority_granted, "BLOCKED activation should be rejected for authority"
    assert not report.activation_status_valid


def test_active_activation_is_required_for_authority() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    receipt = _build_valid_receipt()
    activation = _valid_activation()
    activation["ratification_receipt_ref"] = {
        "receipt_id": receipt["receipt_id"],
        "receipt_sha256": receipt["receipt_sha256"],
    }

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert report.authority_granted, "ACTIVE activation should grant authority"
    assert report.activation_status_valid


def test_missing_receipt_hash_reference_is_rejected() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    activation["ratification_receipt_ref"] = {"receipt_id": "receipt-001"}
    receipt = _build_valid_receipt()

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.ok, "Missing receipt_sha256 reference should be rejected"


def test_forged_receipt_self_hash_is_rejected() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    receipt = _build_valid_receipt()
    receipt["receipt_sha256"] = "forged" + "0" * 59

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.ok, "Forged receipt hash should be rejected"


def test_tampered_receipt_content_is_rejected() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    receipt = _build_valid_receipt()
    receipt["decision"] = "REJECTED"

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.ok, "Tampered receipt content should be rejected"


def test_receipt_with_empty_ratifier_records_is_rejected() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    receipt = _build_valid_receipt()
    receipt["ratifiers"] = []

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.ok, "Empty ratifier records should be rejected"


def test_activation_calls_ratification_validation() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["decision"] = "REJECT"

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.ratification_valid, "Ratification should be validated"


def test_activation_manifest_hash_is_required() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    activation = _valid_activation()
    del activation["bundle_sha256"]
    receipt = _build_valid_receipt()
    receipt["ratification_receipt_ref"] = activation.get("ratification_receipt_ref", {})

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict()},
    )
    assert not report.ok, "Missing manifest hash should be rejected"


def test_activation_manifest_hash_is_recomputed() -> None:
    from synapx_harness.validators.activation_validator import (
        compute_activation_manifest_hash,
        validate_activation_for_authority,
    )

    receipt = _build_valid_receipt()
    docs = {
        "documents": [
            {
                "document_id": "doc-001",
                "document_version": "1.0.0",
                "document_sha256": "c" * 64,
            }
        ]
    }
    expected_manifest_hash = compute_activation_manifest_hash(docs)

    activation = {
        "contract_type": "COMMUNIS_ACTIVATION_MANIFEST",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "ratification_receipt_ref": {
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
        },
        "documents": docs["documents"],
        "manifest_sha256": expected_manifest_hash,
        "ratifiers_approved": 4,
        "blocking_issue_count": 0,
        "activation_status": "ACTIVE",
    }

    report = validate_activation_for_authority(
        rc_bundle=_valid_rc_bundle(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
        activation=activation,
        actual_documents={"doc-001": _make_doc_dict_c()},
    )
    assert report.ok, f"Manifest hash should be recomputed and match: {report.violations}"
