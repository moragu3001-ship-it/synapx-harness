"""H2-I0 Contract Qualification — Evidence Terminal Chain.

Evidence Envelope(SEALED) → TerminalizationInput → TerminalDecisionRecord
(COMPLETED/FAILED/BLOCKED) 체인이 단일 경로(INV-R3R2-TRM-001)로 제공되고,
TerminalDecisionRecord 발급자는 TERMINAL_FINALIZER 단일이어야 한다.

Oracle: I3 은 finalize_terminal_chain(work_contract_id, sealed_evidence,
terminalization_input) 와 TerminalDecisionSet 를 제공해야 한다. 현재는
시그니처 부재로 EXPECTED_RED.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import terminal_finalizer

RED_ID = "H2-I0-CQ-03"
INVARIANT_REFS = ["X3-N03", "X3-N04", "X3-N05", "X3-N06"]


def test_terminal_chain_single_path_exists(h2_i0_require_signature) -> None:
    """Evidence → TerminalizationInput → TerminalDecision 단일 경로 존재."""
    finalize = h2_i0_require_signature(
        terminal_finalizer,
        "finalize_terminal_chain",
        params=("work_contract_id", "sealed_evidence", "terminalization_input"),
    )
    with pytest.raises((ValueError, RuntimeError), match="terminal|finaliz|chain"):
        finalize(
            work_contract_id="wc-chain",
            sealed_evidence={"integrity_status": "SEALED", "envelope_id": "env-1"},
            terminalization_input={
                "decision_candidates": ["COMPLETED"],
                "reason": "all invariants satisfied",
            },
        )


def test_terminalization_input_required(h2_i0_require_signature) -> None:
    """TerminalizationInput 부재 시 체인 진행 → 거부."""
    finalize = h2_i0_require_signature(
        terminal_finalizer,
        "finalize_terminal_chain",
        params=("work_contract_id", "sealed_evidence", "terminalization_input"),
    )
    with pytest.raises((ValueError, RuntimeError), match="terminal|input"):
        finalize(
            work_contract_id="wc-chain",
            sealed_evidence={"integrity_status": "SEALED", "envelope_id": "env-1"},
            terminalization_input=None,
        )


def test_terminal_decision_enum_complete(h2_i0_require_signature) -> None:
    """TerminalDecision enum 은 COMPLETED/FAILED/BLOCKED 3 값이어야 한다."""
    h2_i0_require_signature(
        terminal_finalizer,
        "TerminalDecisionSet",
    )


def test_evidence_chain_must_be_sealed_before_terminal(h2_i0_require_signature) -> None:
    """SEALED 가 아닌 evidence 로 terminal 판정 → 거부."""
    finalize = h2_i0_require_signature(
        terminal_finalizer,
        "finalize_terminal_chain",
        params=("work_contract_id", "sealed_evidence", "terminalization_input"),
    )
    with pytest.raises((ValueError, RuntimeError), match="seal|evidence"):
        finalize(
            work_contract_id="wc-chain",
            sealed_evidence={"integrity_status": "ADMITTED", "envelope_id": "env-1"},
            terminalization_input={
                "decision_candidates": ["COMPLETED"],
                "reason": "premature",
            },
        )
