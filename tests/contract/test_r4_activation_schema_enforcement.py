"""R4 Activation Schema Enforcement Tests.

Tests that verify activation schema and manifest hash enforcement.
"""
from __future__ import annotations

import hashlib


def test_activation_missing_contract_type_fails() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "documents": [],
        "ratifiers_approved": 0,
        "blocking_issue_count": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert not report.ok


def test_activation_missing_schema_version_fails() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "documents": [],
        "ratifiers_approved": 0,
        "blocking_issue_count": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert not report.ok


def test_activation_missing_manifest_hash_fails() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "documents": [],
        "ratifiers_approved": 0,
        "blocking_issue_count": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert not report.ok, "Missing manifest_sha256 should fail"


def test_activation_manifest_hash_mismatch_fails() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "manifest_sha256": "a" * 64,
        "documents": [],
        "ratifiers_approved": 0,
        "blocking_issue_count": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert not report.ok, "Manifest hash mismatch should fail"


def test_activation_missing_ratifiers_approved_fails() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "documents": [],
        "blocking_issue_count": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert not report.ok, "Missing ratifiers_approved should fail"


def test_activation_missing_blocking_issue_count_fails() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "documents": [],
        "ratifiers_approved": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert not report.ok, "Missing blocking_issue_count should fail"


def test_contract_valid_is_boolean() -> None:
    from synapx_harness.validators.activation_validator import validate_activation_for_authority

    rc_bundle = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
    }
    receipt = {
        "receipt_id": "receipt-1",
        "receipt_sha256": hashlib.sha256(b"receipt").hexdigest(),
        "decision": "RATIFIED",
        "ratifiers": [],
        "ratifiers_approved": 0,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
    }
    receipt_sha256 = hashlib.sha256(b"receipt").hexdigest()
    activation = {
        "release_candidate_id": "rc-1",
        "release_candidate_version": "1.0.0",
        "bundle_sha256": hashlib.sha256(b"bundle").hexdigest(),
        "ratification_receipt_ref": {"receipt_id": "receipt-1", "receipt_sha256": receipt_sha256},
        "activation_status": "ACTIVE",
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "documents": [],
        "ratifiers_approved": 0,
        "blocking_issue_count": 0,
    }
    actual_docs = {}

    report = validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_docs,
    )
    assert isinstance(report.contract_valid, bool), "contract_valid must be a boolean"
