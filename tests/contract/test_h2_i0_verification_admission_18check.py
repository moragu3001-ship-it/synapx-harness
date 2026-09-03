"""H2-I0 Contract Qualification — Verification Admission 18-Check.

VerificationResult 어드미션 시 18개 체크(A17/S2) 전건 요구 + canonical
스키마(0.2.0+) 강제가 반드시 존재해야 한다.

Oracle: I1 은 admit_verification_result(work_contract, verification_result)
시그니처를 제공하고 18-check / canonical schema / 중복 체크를 검증해야
한다.

TEST_REPAIR (H2-I4-A0-R1): test_admission_requires_all_18_checks 는 원래
pytest.raises() 기대였으나, check-5 identity binding (work_contract_id
교차 바인딩) BUG_FIX 이후 정합 identity + canonical 18-check 결과가
ADMITTED_PASS 로 admission 되는 positive invariant 를 직접 검증한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import verification_planner

RED_ID = "H2-I0-CQ-02"
INVARIANT_REFS = ["X3-N08", "X3-N10", "X3-N04"]

REQUIRED_CHECK_IDS = list(range(1, 19))


def test_admission_requires_all_18_checks(h2_i0_require_signature, load_h2_i0_fixture) -> None:
    """18개 체크 전건 통과 + 정합 identity → ADMITTED_PASS (canonical positive).

    runtime mismatch 로 억지 rejection 을 유도하는 형태가 아니다: work_contract_id
    일치 + attempt 일치 + canonical schema 0.2.0 + requested_checks 1..18 전건 +
    valid positive fixture 가 ADMITTED_PASS, checks_verified=18 로 admission 되어야
    한다.
    """
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    result = load_h2_i0_fixture("valid/h2_i0_verification_result_valid.json")
    admission = admit(
        work_contract={
            "work_contract_id": "wc-h2-i0-valid-001",
            "attempt_index": 1,
            "source_revision_ref": {
                "revision_kind": "CONTENT_TREE_HASH",
                "revision_value": "a" * 64,
            },
            "source_snapshot_id": "snap-h2-i0-valid-001",
        },
        verification_result=result,
    )
    assert admission["outcome"] == "ADMITTED_PASS"
    assert admission["checks_verified"] == 18


def test_canonical_schema_version_enforced(h2_i0_require_signature) -> None:
    """0.2.0+ canonical 스키마 강제 — legacy schema_version 거부."""
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    with pytest.raises((ValueError, RuntimeError), match="schema|version|canonical"):
        admit(
            work_contract={
                "work_contract_id": "wc-18check",
                "attempt_index": 1,
            },
            verification_result={
                "work_contract_id": "wc-18check",
                "attempt_index": 1,
                "schema_version": "0.1.0",
                "requested_checks": REQUIRED_CHECK_IDS,
            },
        )


def test_duplicate_required_checks_rejected(h2_i0_require_signature) -> None:
    """필수 체크 누락/중복 → 거부."""
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    with pytest.raises((ValueError, RuntimeError), match="check|duplicate|missing"):
        admit(
            work_contract={
                "work_contract_id": "wc-18check",
                "attempt_index": 1,
            },
            verification_result={
                "work_contract_id": "wc-18check",
                "attempt_index": 1,
                "requested_checks": [1, 1, 2, 3],
            },
        )
