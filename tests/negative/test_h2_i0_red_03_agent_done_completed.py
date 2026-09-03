"""RED-I0-03 — Agent DONE -> COMPLETED (X3-N03).

AgentDoneClaim 을 Terminal Decision COMPLETED 로 승격하는 경로는 검증
어드미션 + Evidence Sealed + Finalizer 를 생략하므로 반드시 거부되어야 한다.

Oracle: I3 은 finalize_from_agent_done / advance_agent_claim / issue_terminal_decision
시그니처를 추가하고 DONE → COMPLETED 직접 승격을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import terminal_finalizer

RED_ID = "RED-I0-03"
INVARIANT_REFS = ["X3-N03"]
GUARDED_TASKS = ["T05", "T07", "T12", "T13"]


def test_agent_done_claim_cannot_be_promoted_to_completed(h2_i0_require_signature) -> None:
    """AgentDoneClaim 을 직접 COMPLETED 로 승격 → 거부."""
    finalize = h2_i0_require_signature(
        terminal_finalizer,
        "finalize_from_agent_done",
        params=("work_contract_id", "claim"),
    )
    with pytest.raises((ValueError, RuntimeError), match="finaliz|terminal"):
        finalize(
            work_contract_id="wc-agent-done",
            claim={"claim_type": "AGENT_DONE_CLAIM", "asserted_result": "COMPLETED"},
        )


def test_agent_done_only_transitions_to_verifying(h2_i0_require_signature) -> None:
    """DONE claim 은 VERIFYING 전이만 허용되어야 한다."""
    advance = h2_i0_require_signature(
        terminal_finalizer,
        "advance_agent_claim",
        params=("claim", "target_state"),
    )
    with pytest.raises((ValueError, RuntimeError), match="verifying|transition"):
        advance(
            claim={"claim_type": "AGENT_DONE_CLAIM"},
            target_state="COMPLETED",
        )


def test_supplementary_red_i0_trm02_agent_issuance_forbidden(h2_i0_require_signature) -> None:
    """RED-I0-TRM02 — Agent 가 TerminalDecisionRecord 발급 → 거부."""
    issue = h2_i0_require_signature(
        terminal_finalizer,
        "issue_terminal_decision",
        params=("work_contract_id", "decision", "issued_by"),
    )
    with pytest.raises((ValueError, RuntimeError), match="issuer|finaliz"):
        issue(
            work_contract_id="wc-agent-done",
            decision="COMPLETED",
            issued_by="Agent",
        )
