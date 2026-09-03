"""RED-I0-10 — stale evidence reuse (X3-N10).

만료/과거 evidence 가 재사용되어 검증 PASS 로 수용되는 경로는 반드시
거부되어야 한다 (freshness threshold 초과 → REJECTED_STALE).

Oracle: I1 은 admit_verification_result 의 freshness 검증과
validate_evidence_freshness 시그니처를 제공해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.evidence import evidence_validator
from synapx_harness.kernel import verification_planner

RED_ID = "RED-I0-10"
INVARIANT_REFS = ["X3-N10"]
GUARDED_TASKS = ["T09", "T10"]


def test_stale_evidence_is_rejected(h2_i0_require_signature, load_h2_i0_fixture) -> None:
    """freshness_threshold 초과 evidence → REJECTED_STALE 강제."""
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    stale = load_h2_i0_fixture("invalid/h2_i0_stale_verification.json")
    with pytest.raises((ValueError, RuntimeError), match="stale|fresh"):
        admit(
            work_contract={
                "work_contract_id": "wc-stale",
                "attempt_index": 1,
            },
            verification_result=stale,
        )


def test_evidence_freshness_gate_required(h2_i0_require_signature) -> None:
    """evidence admission 에 freshness 검증 함수가 반드시 존재해야 한다."""
    validate = h2_i0_require_signature(
        evidence_validator,
        "validate_evidence_freshness",
        params=("evidence_timestamp", "threshold_seconds", "reference_now"),
    )
    with pytest.raises((ValueError, RuntimeError), match="fresh|evidence"):
        validate(
            evidence_timestamp="2026-01-01T00:00:00.000000+00:00",
            threshold_seconds=86400,
            reference_now="2026-08-15T00:00:00.000000+00:00",
        )
