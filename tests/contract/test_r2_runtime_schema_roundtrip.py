"""R2 Runtime/Schema round-trip tests."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from synapx_harness.contracts.runtime_models import (
    TerminalDecisionRecord,
    build_terminal_decision,
    build_verification_result,
    build_work_contract,
)
from synapx_harness.kernel.terminal_finalizer import TerminalDecision, finalize
from synapx_harness.kernel.verification_planner import plan
from synapx_harness.kernel.work_contract_builder import build
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_work_contract_builder_output_validates_against_schema() -> None:
    contract = build(
        work_contract_id="WC-R2-001",
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R2",
        risk_class="R0",
        objective="round-trip",
        scope=["tests"],
    )
    payload = contract.model_dump(mode="json")
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/work_contract.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors


def test_verification_result_output_validates_against_schema() -> None:
    result = plan(
        work_contract_id="WC-R2-001",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    payload = result.model_dump(mode="json")
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/verification_result.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors


def test_terminal_decision_output_validates_against_schema() -> None:
    verification = plan(
        work_contract_id="WC-R2-001",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    decision = finalize(verification)
    payload = decision.model_dump(mode="json")
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/terminal_decision.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors


def test_runtime_outputs_include_contract_type() -> None:
    contract = build_work_contract(
        work_contract_id="X",
        phase="X",
        risk_class="R0",
        objective="X",
        scope=["src"],
    )
    assert contract.contract_type == "CUSTOMOS_WORK_CONTRACT"
    verification = build_verification_result(
        work_contract_id="X",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    assert verification.contract_type == "CUSTOMOS_VERIFICATION_RESULT"
    decision = build_terminal_decision(
        work_contract_id="X",
        decision="FAILED",
        reason="x",
    )
    assert decision.contract_type == "CUSTOMOS_TERMINAL_DECISION"


def test_runtime_outputs_include_schema_version() -> None:
    contract = build_work_contract(
        work_contract_id="X",
        phase="X",
        risk_class="R0",
        objective="X",
        scope=["src"],
    )
    assert contract.schema_version == "0.1.0"
    verification = build_verification_result(
        work_contract_id="X",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    assert verification.schema_version == "0.1.0"
    decision = build_terminal_decision(
        work_contract_id="X",
        decision="FAILED",
        reason="x",
    )
    assert decision.schema_version == "0.1.0"


def test_verification_result_rejects_negative_blocker_count() -> None:
    with pytest.raises(ValidationError):
        build_verification_result(
            work_contract_id="X",
            verification_status="PASS",
            evidence_status="VALID",
            active_blocker_count=-1,
        )


def test_verification_result_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        build_verification_result(
            work_contract_id="X",
            verification_status="MAYBE",
            evidence_status="VALID",
            active_blocker_count=0,
        )


def test_terminal_completed_requires_schema_valid_input() -> None:
    """A COMPLETED decision requires the upstream VerificationResult to
    satisfy the invariants. finalize() must produce a typed record that
    validates against the terminal_decision schema."""
    verification = plan(
        work_contract_id="WC-R2-COMPLETED",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
    )
    decision = finalize(verification)
    assert decision.decision == TerminalDecision.COMPLETED
    payload = decision.model_dump(mode="json")
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/terminal_decision.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors


def test_terminal_decision_rejects_invalid_decision_value() -> None:
    with pytest.raises(ValidationError):
        TerminalDecisionRecord(
            work_contract_id="X",
            decision="PARTIAL",  # type: ignore[arg-type]
            reason="x",
        )
