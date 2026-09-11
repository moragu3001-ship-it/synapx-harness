"""Ratification contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.ratification_validator import (
    compute_receipt_sha256,
    invalidate_on_change,
    validate_ratification,
)
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


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
        "receipt_id": "receipt-001",
        "ratifiers": [
            {
                "ratifier_id": f"r{i}",
                "decision": "APPROVE",
                "release_candidate_id": "RC-001",
                "release_candidate_version": "0.1.0-rc1",
                "bundle_sha256": "a" * 64,
                "approved_at": "2026-07-23T00:00:00Z",
            }
            for i in range(4)
        ],
    }
    receipt["receipt_sha256"] = compute_receipt_sha256(receipt)
    return receipt


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


def test_ratification_requires_four_distinct_ratifiers() -> None:
    receipt = _valid_receipt()
    ratifier_records = _valid_records()
    for ratifier in ratifier_records:
        ratifier["ratifier_id"] = "same"
    receipt["ratifiers"] = [dict(r) for r in ratifier_records]
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=ratifier_records,
        receipt=receipt,
    )
    assert not report.ok


def test_ratification_requires_four_of_four_approvals() -> None:
    records = _valid_ratifier_records()
    records[0]["decision"] = "REJECT"
    receipt = _valid_receipt()
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=receipt,
    )
    assert not report.ok


def test_all_ratifiers_approve_same_bundle_hash() -> None:
    records = _valid_ratifier_records()
    records[0]["bundle_sha256"] = "b" * 64
    receipt = _valid_receipt()
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=records,
        receipt=receipt,
    )
    assert not report.ok


def test_blocking_issues_must_be_zero() -> None:
    receipt = _valid_receipt()
    receipt["blocking_issues"] = 1
    report = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    )
    assert not report.ok


def test_ratification_valid_payload() -> None:
    receipt = _valid_receipt()
    sha = validate_ratification(
        rc_bundle=_valid_rc(),
        ratifier_records=_valid_ratifier_records(),
        receipt=receipt,
    ).receipt_sha256
    receipt["receipt_sha256"] = sha
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/ratification_receipt.schema.json",
        payload=receipt,
    )
    assert schema_report.ok, schema_report.errors


def test_changed_bundle_invalidates_existing_receipt() -> None:
    receipt = _valid_receipt()
    receipt["receipt_sha256"] = "irrelevant"
    assert invalidate_on_change(receipt=receipt, new_rc_hash="different")


def test_changed_rc_version_invalidates_existing_receipt() -> None:
    receipt = _valid_receipt()
    receipt["receipt_sha256"] = "irrelevant"
    assert invalidate_on_change(receipt=receipt, new_rc_version="0.2.0-rc1")
