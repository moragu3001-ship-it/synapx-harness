"""RED-I0-06 — non-Finalizer terminal issuance (X3-N06).

Terminal Decision 발급자는 TERMINAL_FINALIZER 단일 주체만 허용된다.
Verifier / Evidence Sealer / Agent / Provider / Scheduler / Registry 6 주체의
발급은 전부 거부되어야 한다.

Oracle: I3 은 issue_terminal_decision 시그니처를 추가하고 forbidden 발급자
6 종 전건 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import terminal_finalizer

RED_ID = "RED-I0-06"
INVARIANT_REFS = ["X3-N06"]
GUARDED_TASKS = ["T10", "T11", "T12", "T13"]

FORBIDDEN_ISSUERS = [
    "Verifier",
    "Evidence Sealer",
    "Agent",
    "Provider",
    "Scheduler",
    "Registry",
]


@pytest.mark.parametrize("issuer", FORBIDDEN_ISSUERS)
def test_non_finalizer_issuer_rejected(h2_i0_require_signature, issuer: str) -> None:
    """6 주체 전건 TerminalDecisionRecord 발급 → 거부."""
    issue = h2_i0_require_signature(
        terminal_finalizer,
        "issue_terminal_decision",
        params=("work_contract_id", "decision", "issued_by"),
    )
    with pytest.raises((ValueError, RuntimeError), match="issuer|finaliz"):
        issue(
            work_contract_id="wc-terminal",
            decision="COMPLETED",
            issued_by=issuer,
        )


def test_only_terminal_finalizer_can_issue(h2_i0_require_signature) -> None:
    """TERMINAL_FINALIZER 단일 발급 경로 존재 확인."""
    issue = h2_i0_require_signature(
        terminal_finalizer,
        "issue_terminal_decision",
        params=("work_contract_id", "decision", "issued_by", "terminalization_input"),
    )
    with pytest.raises((ValueError, RuntimeError), match="finaliz"):
        issue(
            work_contract_id="wc-terminal",
            decision="COMPLETED",
            issued_by="TERMINAL_FINALIZER",
            terminalization_input={"evidence_chain": ["SEALED"]},
        )


def test_terminal_decision_contract_from_fixture_rejected(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """fixture TerminalDecision 의 발급자가 Finalizer 가 아니면 거부되어야 한다."""
    issue = h2_i0_require_signature(
        terminal_finalizer,
        "issue_terminal_decision",
        params=("work_contract_id", "decision", "issued_by"),
    )
    decision = load_h2_i0_fixture("valid/h2_i0_terminal_decision_valid.json")
    with pytest.raises((ValueError, RuntimeError), match="issuer|finaliz"):
        issue(
            work_contract_id=decision["work_contract_id"],
            decision=decision["decision"],
            issued_by="Provider",
        )


def test_supplementary_red_i0_trm03_provider_issuance_forbidden(
    h2_i0_require_signature,
) -> None:
    """RED-I0-TRM03 — Provider 가 TerminalDecisionRecord 발급 → 거부."""
    issue = h2_i0_require_signature(
        terminal_finalizer,
        "issue_terminal_decision",
        params=("work_contract_id", "decision", "issued_by"),
    )
    with pytest.raises((ValueError, RuntimeError), match="issuer|finaliz"):
        issue(
            work_contract_id="wc-terminal",
            decision="FAILED",
            issued_by="Provider",
        )
