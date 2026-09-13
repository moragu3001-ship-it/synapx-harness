"""R3 Ratification Receipt Integrity Tests.

Tests that enforce strict validation of ratification receipts:
  - receipt_sha256 is required and must match computed hash
  - receipt_id is required
  - Receipt ratifier records must deep-equal source records
  - No REJECT decisions allowed
  - All 4 ratifiers must approve unanimously
"""
from __future__ import annotations

from typing import cast


def _valid_rc() -> dict[str, object]:
    return {
        "contract_type": "COMMUNIS_RC_BUNDLE",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "document_refs": [],
        "ratification_status": "PENDING",
        "execution_authority": False,
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


def test_missing_receipt_sha256_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    del receipt["receipt_sha256"]
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Missing receipt_sha256 should be rejected"
    assert "receipt_sha256 is required" in report.violations


def test_empty_receipt_sha256_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    receipt["receipt_sha256"] = ""
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Empty receipt_sha256 should be rejected"


def test_incorrect_receipt_sha256_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    receipt["receipt_sha256"] = "b" * 64
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Incorrect receipt_sha256 should be rejected"
    assert "mismatch" in report.violations[0].lower()


def test_receipt_ratifier_reject_decision_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["decision"] = "REJECT"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "REJECT decision should be rejected"


def test_receipt_ratifier_bundle_hash_mismatch_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["bundle_sha256"] = "c" * 64
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Bundle hash mismatch should be rejected"


def test_receipt_ratifier_version_mismatch_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["release_candidate_version"] = "0.2.0-rc1"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Version mismatch should be rejected"


def test_receipt_ratifier_approved_at_mismatch_is_rejected() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["approved_at"] = "2026-08-01T00:00:00Z"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "approved_at mismatch should be rejected"


def test_receipt_ratifier_records_must_deep_equal_source_records() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["ratifier_id"] = "different-id"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Deep equality mismatch should be rejected"


def test_receipt_id_is_required() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    del receipt["receipt_id"]
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok
    assert "receipt_id is required" in report.violations


def test_receipt_canonical_hash_is_stable() -> None:
    from synapx_harness.validators.ratification_validator import (
        compute_receipt_sha256,
        validate_ratification,
    )

    receipt1 = _build_valid_receipt()
    receipt2 = _build_valid_receipt()
    hash1 = compute_receipt_sha256(receipt1)
    hash2 = compute_receipt_sha256(receipt2)
    assert hash1 == hash2, "Same receipt should produce same hash"

    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt1,
    )
    assert report.receipt_sha256 == hash1


def test_ratifier_records_must_be_exactly_four() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    receipt["ratifiers"] = _receipt_ratifiers(receipt)[:3]
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Must have exactly 4 ratifiers"


def test_ratifier_ids_must_be_distinct() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["ratifier_id"] = "r1"
    _receipt_ratifiers(receipt)[1]["ratifier_id"] = "r1"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "Ratifier IDs must be distinct"


def test_ratifiers_approved_must_match_actual_approve_count() -> None:
    from synapx_harness.validators.ratification_validator import validate_ratification

    receipt = _build_valid_receipt()
    _receipt_ratifiers(receipt)[0]["decision"] = "REJECT"
    receipt["ratifiers_approved"] = 4
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok, "ratifiers_approved must match actual count"


def test_receipt_sha256_not_self_referential() -> None:
    from synapx_harness.validators.ratification_validator import (
        canonical_receipt_bytes,
        compute_receipt_sha256,
    )

    receipt = _build_valid_receipt()
    canonical = canonical_receipt_bytes(receipt)
    computed = compute_receipt_sha256(receipt)
    assert "receipt_sha256" not in str(canonical), "Canonical bytes should exclude receipt_sha256"
    assert computed == receipt["receipt_sha256"]
