"""R2 Ratification binding tests."""
from __future__ import annotations

import copy

from synapx_harness.validators.ratification_validator import (
    compute_receipt_sha256,
    invalidate_on_change,
    validate_ratification,
)


def _valid_rc() -> dict[str, object]:
    return {
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
    }


def _valid_records() -> list[dict[str, object]]:
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


def _valid_receipt() -> dict[str, object]:
    receipt = {
        "contract_type": "COMMUNIS_RATIFICATION_RECEIPT",
        "schema_version": "0.1.0",
        "release_candidate_id": "RC-001",
        "release_candidate_version": "0.1.0-rc1",
        "bundle_sha256": "a" * 64,
        "receipt_id": "receipt-001",
        "ratifiers": copy.deepcopy(_valid_records()),
        "ratifiers_required": 4,
        "ratifiers_approved": 4,
        "approval_rule": "UNANIMOUS",
        "blocking_issues": 0,
        "decision": "RATIFIED",
    }
    receipt["receipt_sha256"] = compute_receipt_sha256(receipt)
    return receipt


def test_ratification_requires_exactly_four_ratifier_records() -> None:
    records = _valid_records()[:3]
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=_valid_receipt(),
    )
    assert not report.ok


def test_ratifier_ids_must_be_distinct() -> None:
    records = _valid_records()
    for r in records:
        r["ratifier_id"] = "same"
    receipt = _valid_receipt()
    receipt["ratifiers"] = copy.deepcopy(records)
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=receipt,
    )
    assert not report.ok


def test_every_ratifier_approves_same_rc_id() -> None:
    records = _valid_records()
    records[1]["release_candidate_id"] = "RC-002"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=_valid_receipt(),
    )
    assert not report.ok


def test_every_ratifier_approves_same_rc_version() -> None:
    records = _valid_records()
    records[0]["release_candidate_version"] = "0.2.0-rc1"
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=_valid_receipt(),
    )
    assert not report.ok


def test_every_ratifier_approves_same_bundle_hash() -> None:
    records = _valid_records()
    records[2]["bundle_sha256"] = "b" * 64
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=_valid_receipt(),
    )
    assert not report.ok


def test_ratification_receipt_binds_rc_bundle_hash() -> None:
    rc = _valid_rc()
    records = _valid_records()
    receipt = _valid_receipt()
    receipt["ratifiers"] = copy.deepcopy(records)
    receipt["receipt_sha256"] = compute_receipt_sha256(receipt)
    report = validate_ratification(
        rc_bundle=rc,
        ratifier_records=records,
        receipt=receipt,
    )
    assert report.ok, report.violations
    assert invalidate_on_change(receipt=receipt, new_rc_hash="c" * 64)


def test_changed_bundle_invalidates_existing_receipt() -> None:
    receipt = _valid_receipt()
    assert invalidate_on_change(receipt=receipt, new_rc_hash="d" * 64)


def test_changed_rc_version_invalidates_existing_receipt() -> None:
    receipt = _valid_receipt()
    assert invalidate_on_change(receipt=receipt, new_rc_version="0.5.0-rc1")


def test_rejected_or_pending_vote_cannot_ratify() -> None:
    records = _valid_records()
    records[3]["decision"] = "REJECT"
    receipt = _valid_receipt()
    receipt["ratifiers"] = copy.deepcopy(records)
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=receipt,
    )
    assert not report.ok


def test_blocking_issue_prevents_ratification() -> None:
    receipt = _valid_receipt()
    receipt["blocking_issues"] = 1
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_records(),
        receipt=receipt,
    )
    assert not report.ok


def test_receipt_sha256_must_be_recomputed_on_change() -> None:
    receipt = _valid_receipt()
    original = receipt["receipt_sha256"]
    receipt["release_candidate_version"] = "0.5.0-rc1"
    new = compute_receipt_sha256(receipt)
    assert new != original
