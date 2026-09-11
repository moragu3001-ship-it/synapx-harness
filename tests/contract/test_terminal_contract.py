"""Terminal contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.kernel.terminal_finalizer import TerminalDecision, finalize
from synapx_harness.kernel.verification_planner import plan
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def _payload(
    *,
    status: str = "PASS",
    evidence: str = "VALID",
    blockers: int = 0,
) -> dict[str, object]:
    return {
        "contract_type": "CUSTOMOS_VERIFICATION_RESULT",
        "schema_version": "0.1.0",
        "work_contract_id": "WC-001",
        "verification_status": status,
        "evidence_status": evidence,
        "active_blocker_count": blockers,
        "checks": [],
    }


def test_completed_requires_verification_pass() -> None:
    result = plan(
        work_contract_id="WC-001",
        verification_status="FAIL",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    decision = finalize(result)
    assert decision.decision == TerminalDecision.FAILED


def test_completed_requires_valid_evidence() -> None:
    result = plan(
        work_contract_id="WC-001",
        verification_status="PASS",
        evidence_status="INVALID",
        active_blocker_count=0,
    )
    decision = finalize(result)
    assert decision.decision == TerminalDecision.FAILED


def test_completed_cannot_have_active_blocker() -> None:
    result = plan(
        work_contract_id="WC-001",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=1,
    )
    decision = finalize(result)
    assert decision.decision == TerminalDecision.BLOCKED


def test_completed_when_all_invariants_satisfied() -> None:
    result = plan(
        work_contract_id="WC-001",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    decision = finalize(result)
    assert decision.decision == TerminalDecision.COMPLETED


def test_verification_schema_valid() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/verification_result.schema.json",
        payload=_payload(),
    )
    assert report.ok, report.errors


def test_terminal_decision_schema_valid() -> None:
    payload = {
        "contract_type": "CUSTOMOS_TERMINAL_DECISION",
        "schema_version": "0.1.0",
        "work_contract_id": "WC-001",
        "decision": "COMPLETED",
        "reason": "all invariants satisfied",
    }
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/terminal_decision.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors
