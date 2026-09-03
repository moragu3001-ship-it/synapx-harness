"""RED-I0-04 — Verifier PASS -> COMPLETED (X3-N04).

검증 PASS 를 직접 COMPLETED 판정으로 승격하는 경로는 Terminal Finalizer
경로를 생략하므로 반드시 거부되어야 한다.

Oracle: I3 은 promote_pass_to_completed / classify_admission_outcome /
issue_terminal_decision 시그니처를 추가하고 PASS → COMPLETED 직접 승격을
거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import terminal_finalizer, verification_planner

RED_ID = "RED-I0-04"
INVARIANT_REFS = ["X3-N04"]
GUARDED_TASKS = ["T08", "T09", "T12", "T13"]


def test_verifier_pass_cannot_be_directly_completed(h2_i0_require_signature) -> None:
    """Verifier PASS 를 직접 COMPLETED 로 승격 → 거부."""
    promote = h2_i0_require_signature(
        verification_planner,
        "promote_pass_to_completed",
        params=("verification_status", "evidence_status", "active_blocker_count"),
    )
    with pytest.raises((ValueError, RuntimeError), match="admitted|finaliz"):
        promote(
            verification_status="PASS",
            evidence_status="VALID",
            active_blocker_count=0,
        )


def test_verifier_pass_maps_to_admitted_pass_only(h2_i0_require_signature) -> None:
    """PASS 는 ADMITTED_PASS 로만 매핑되어야 한다."""
    classify = h2_i0_require_signature(
        verification_planner,
        "classify_admission_outcome",
        params=("verification_status", "evidence_status", "active_blocker_count"),
    )
    with pytest.raises((ValueError, RuntimeError), match="admitted"):
        classify(
            verification_status="PASS",
            evidence_status="VALID",
            active_blocker_count=0,
        )


def test_supplementary_red_i0_trm01_verifier_issuance_forbidden(h2_i0_require_signature) -> None:
    """RED-I0-TRM01 — Verifier 가 TerminalDecisionRecord 발급 → 거부."""
    issue = h2_i0_require_signature(
        terminal_finalizer,
        "issue_terminal_decision",
        params=("work_contract_id", "decision", "issued_by"),
    )
    with pytest.raises((ValueError, RuntimeError), match="issuer|finaliz"):
        issue(
            work_contract_id="wc-verifier-pass",
            decision="COMPLETED",
            issued_by="Verifier",
        )
