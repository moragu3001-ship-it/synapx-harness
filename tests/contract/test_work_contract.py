"""Work contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.contracts.models import PilotRisk
from synapx_harness.contracts.runtime_models import (
    WorkContract,
    build_work_contract,
)
from synapx_harness.kernel.risk_classifier import classify, is_blocked_in_pilot
from synapx_harness.kernel.work_contract_builder import build
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def _payload(risk: str = "R0") -> dict[str, object]:
    return {
        "contract_type": "CUSTOMOS_WORK_CONTRACT",
        "schema_version": "0.1.0",
        "work_contract_id": "WC-001",
        "phase": "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R2",
        "risk_class": risk,
        "objective": "test",
        "scope": ["src"],
        "success_criteria": ["pytest passes"],
    }


def test_r0_can_be_auto_admitted() -> None:
    assert classify(PilotRisk.R0) == "AUTO_ADMIT"


def test_r1_is_limited_to_document_or_test_scope() -> None:
    assert classify(PilotRisk.R1) == "DOCUMENT_OR_TEST_SCOPE"


def test_r2_requires_explicit_mutation_policy_and_hitl() -> None:
    assert classify(PilotRisk.R2) == "EXPLICIT_MUTATION_POLICY_AND_HITL"


def test_r3_is_blocked_in_pilot() -> None:
    assert is_blocked_in_pilot(PilotRisk.R3)
    assert classify(PilotRisk.R3) == "BLOCKED"


def test_r4_is_blocked_in_pilot() -> None:
    assert is_blocked_in_pilot(PilotRisk.R4)
    assert classify(PilotRisk.R4) == "BLOCKED"


def test_work_contract_schema_valid_r0() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/work_contract.schema.json",
        payload=_payload("R0"),
    )
    assert report.ok, report.errors


def test_work_contract_schema_rejects_unknown_risk() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/work_contract.schema.json",
        payload=_payload("R9"),
    )
    assert not report.ok, report.errors


def test_work_contract_builder_round_trip() -> None:
    contract: WorkContract = build(
        work_contract_id="WC-002",
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R2",
        risk_class=PilotRisk.R1,
        objective="bootstrap",
        scope=["tests"],
        success_criteria=["ci green"],
    )
    payload = contract.model_dump(mode="json")
    assert payload["risk_class"] == "R1"
    assert payload["scope"] == ["tests"]


def test_work_contract_typed_builder() -> None:
    contract = build_work_contract(
        work_contract_id="WC-003",
        phase="x",
        risk_class="R0",
        objective="y",
        scope=["src"],
    )
    payload = contract.model_dump(mode="json")
    assert payload["contract_type"] == "CUSTOMOS_WORK_CONTRACT"
    assert payload["schema_version"] == "0.1.0"
