"""RED-I5-R1-VERIFY-FAIL — Verification FAIL -> COMPLETED bypass.

Production runtime hole discovered in I5-R1:
  finalize_terminal_chain(work_contract_id, sealed_evidence, terminalization_input)
  accepts proposed_outcome=COMPLETED regardless of verification_status.

This test enforces the invariant:
  VerificationResult.verification_status == 'FAIL'
  =>
  finalize_terminal_chain / finalize_from_sealed_evidence
     MUST NOT emit TerminalDecisionRecord.decision == 'COMPLETED'

Oracle (post-repair):
  terminal_finalizer.finalize_terminal_chain raises ValueError when
  terminalization_input['verification_admission_receipt']['verification_status']
  != 'PASS'.
  terminal_finalizer.finalize_from_sealed_evidence applies the same guard.

This test fails RED against the pre-repair production runtime and passes
GREEN after the minimal verification-guard patch.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import terminal_finalizer

RED_ID = "RED-I5-R1-VERIFY-FAIL"
INVARIANT_REFS = ["I5-R1-VERIFY-FAIL-001"]
GUARDED_TASKS = ["T12", "T13"]


def _sealed_evidence(work_contract_id: str) -> dict[str, object]:
    return {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
    }


def _terminalization_input(
    *,
    work_contract_id: str,
    verification_status: str,
    evidence_status: str,
    active_blocker_count: int,
    proposed_outcome: str,
) -> dict[str, object]:
    return {
        "execution_identity": {
            "producer": "synapx_harness.kernel.terminal_finalizer",
            "module": "synapx_harness.kernel.terminal_finalizer",
            "function": "finalize_terminal_chain",
            "run_id": f"run-{work_contract_id}",
            "job_id": f"job-{work_contract_id}",
            "task_id": work_contract_id,
            "source_revision": "i5_r1_red_test",
            "created_at": "2026-08-30T14:30:00Z",
        },
        "work_contract_id": work_contract_id,
        "verification_admission_receipt": {
            "receipt_id": f"vad/{work_contract_id}",
            "work_contract_id": work_contract_id,
            "verification_status": verification_status,
            "evidence_status": evidence_status,
            "active_blocker_count": active_blocker_count,
            "admitted_at": "2026-08-30T14:30:00Z",
        },
        "sealed_evidence": _sealed_evidence(work_contract_id),
        "source_revision_ref": {"revision": "i5_r1_red_test"},
        "active_blocker_count": active_blocker_count,
        "proposed_outcome": proposed_outcome,
        "reason": "I5-R1 red regression",
    }


def test_finalize_terminal_chain_rejects_fail_to_completed() -> None:
    """verification_status=FAIL + proposed_outcome=COMPLETED -> reject."""
    finalize_chain = terminal_finalizer.finalize_terminal_chain
    work_contract_id = "wc-i5-r1-red-fail"
    sealed_evidence: dict[str, object] = {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
    }
    terminalization_input: dict[str, object] = _terminalization_input(
        work_contract_id=work_contract_id,
        verification_status="FAIL",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises((ValueError, RuntimeError), match="verification|fail|completed"):
        finalize_chain(
            work_contract_id=work_contract_id,
            sealed_evidence=sealed_evidence,
            terminalization_input=terminalization_input,
        )


def test_finalize_terminal_chain_rejects_invalid_evidence_to_completed() -> None:
    """evidence_status=INVALID + proposed_outcome=COMPLETED -> reject."""
    finalize_chain = terminal_finalizer.finalize_terminal_chain
    work_contract_id = "wc-i5-r1-red-evidence-invalid"
    sealed_evidence: dict[str, object] = {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
    }
    terminalization_input: dict[str, object] = _terminalization_input(
        work_contract_id=work_contract_id,
        verification_status="PASS",
        evidence_status="INVALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises((ValueError, RuntimeError), match="evidence|invalid"):
        finalize_chain(
            work_contract_id=work_contract_id,
            sealed_evidence=sealed_evidence,
            terminalization_input=terminalization_input,
        )


def test_finalize_terminal_chain_rejects_blocker_to_completed() -> None:
    """active_blocker_count > 0 + proposed_outcome=COMPLETED -> reject."""
    finalize_chain = terminal_finalizer.finalize_terminal_chain
    work_contract_id = "wc-i5-r1-red-blocker"
    sealed_evidence: dict[str, object] = {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
    }
    terminalization_input: dict[str, object] = _terminalization_input(
        work_contract_id=work_contract_id,
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=1,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises((ValueError, RuntimeError), match="blocker"):
        finalize_chain(
            work_contract_id=work_contract_id,
            sealed_evidence=sealed_evidence,
            terminalization_input=terminalization_input,
        )


def test_finalize_from_sealed_evidence_rejects_fail_to_completed() -> None:
    """verification_status=FAIL + proposed_outcome=COMPLETED -> reject (sealed)."""
    finalize_sealed = terminal_finalizer.finalize_from_sealed_evidence
    work_contract_id = "wc-i5-r1-red-sealed-fail"
    sealed_evidence: dict[str, object] = {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
    }
    terminalization_input: dict[str, object] = _terminalization_input(
        work_contract_id=work_contract_id,
        verification_status="FAIL",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises((ValueError, RuntimeError), match="verification|fail|completed"):
        finalize_sealed(
            sealed_evidence=sealed_evidence,
            terminalization_input=terminalization_input,
        )


def test_finalize_terminal_chain_allows_pass_to_completed() -> None:
    """verification_status=PASS + evidence_status=VALID + blocker=0 -> COMPLETED allowed."""
    finalize_chain = terminal_finalizer.finalize_terminal_chain
    work_contract_id = "wc-i5-r1-red-pass-ok"
    sealed_evidence: dict[str, object] = {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
    }
    terminalization_input: dict[str, object] = _terminalization_input(
        work_contract_id=work_contract_id,
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    decision = finalize_chain(
        work_contract_id=work_contract_id,
        sealed_evidence=sealed_evidence,
        terminalization_input=terminalization_input,
    )
    assert decision.decision == "COMPLETED", (
        f"expected COMPLETED for fully satisfied invariants, got {decision.decision}"
    )
