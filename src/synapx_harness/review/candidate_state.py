"""Candidate State — single compute for the three lockstep gates.

Computes ``review_candidate_state.json``, ``gate_summary.json`` and
``review_decision.json`` from a single :class:`CandidateStateInputs`
so the three artifacts cannot disagree. The Terminal Seal reads
these from the package; CLI-injected PASS/FAIL or PENDING values
cannot influence the computation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from synapx_harness.review.review_phase_contract import (
    ALL_GATE_STATES,
    CANDIDATE_STATUS_NOT_READY,
    CANDIDATE_STATUS_READY,
    GATE_FAIL,
    GATE_PASS,
    INDEPENDENT_REVIEW_PENDING,
    PHASE,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class CandidateStateInputs:
    phase: str
    implementation_gate: str
    scm_snapshot_binding_gate: str
    command_receipt_gate: str
    test_evidence_gate: str
    internal_index_gate: str
    negative_exploit_gate: str
    package_structural_gate: str
    package_semantic_gate: str
    independent_review: str = INDEPENDENT_REVIEW_PENDING
    p3_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "implementation_gate": self.implementation_gate,
            "scm_snapshot_binding_gate": self.scm_snapshot_binding_gate,
            "command_receipt_gate": self.command_receipt_gate,
            "test_evidence_gate": self.test_evidence_gate,
            "internal_index_gate": self.internal_index_gate,
            "negative_exploit_gate": self.negative_exploit_gate,
            "package_structural_gate": self.package_structural_gate,
            "package_semantic_gate": self.package_semantic_gate,
            "independent_review": self.independent_review,
            "p3_authorized": self.p3_authorized,
        }


@dataclass(frozen=True)
class CandidateStateOutput:
    review_candidate_state: dict[str, object]
    gate_summary: dict[str, object]
    review_decision: dict[str, object]
    terminal_candidate_gate: str

    def to_dict(self) -> dict[str, object]:
        return {
            "review_candidate_state": self.review_candidate_state,
            "gate_summary": self.gate_summary,
            "review_decision": self.review_decision,
            "terminal_candidate_gate": self.terminal_candidate_gate,
        }


def _validate_gate(gate: str) -> str:
    if gate not in ALL_GATE_STATES:
        raise ValueError(f"gate must be PASS or FAIL, got {gate!r}")
    return gate


def compute_candidate_state(inputs: CandidateStateInputs) -> CandidateStateOutput:
    """Compute the three lockstep artifacts from a single input."""
    if inputs.phase != PHASE:
        raise ValueError(f"phase mismatch: got {inputs.phase!r}, expected {PHASE!r}")
    gates = {
        "implementation_gate": _validate_gate(inputs.implementation_gate),
        "scm_snapshot_binding_gate": _validate_gate(inputs.scm_snapshot_binding_gate),
        "command_receipt_gate": _validate_gate(inputs.command_receipt_gate),
        "test_evidence_gate": _validate_gate(inputs.test_evidence_gate),
        "internal_index_gate": _validate_gate(inputs.internal_index_gate),
        "negative_exploit_gate": _validate_gate(inputs.negative_exploit_gate),
        "package_structural_gate": _validate_gate(inputs.package_structural_gate),
        "package_semantic_gate": _validate_gate(inputs.package_semantic_gate),
    }
    all_internal_pass = all(v == GATE_PASS for v in gates.values())
    candidate_status = CANDIDATE_STATUS_READY if all_internal_pass else CANDIDATE_STATUS_NOT_READY
    terminal_candidate_gate = GATE_PASS if all_internal_pass else GATE_FAIL

    review_candidate_state = {
        "phase": inputs.phase,
        **gates,
        "candidate_status": candidate_status,
        "independent_review": inputs.independent_review,
        "p3_authorized": inputs.p3_authorized,
    }
    gate_summary = {
        "phase": inputs.phase,
        "gates": gates,
        "all_internal_pass": all_internal_pass,
        "terminal_candidate_gate": terminal_candidate_gate,
    }
    review_decision = {
        "phase": inputs.phase,
        "decision": terminal_candidate_gate,
        "candidate_status": candidate_status,
        "independent_review": inputs.independent_review,
        "p3_authorized": inputs.p3_authorized,
        "rationale": (
            "all internal gates PASS"
            if all_internal_pass
            else f"one or more internal gates FAIL: {gates}"
        ),
    }
    return CandidateStateOutput(
        review_candidate_state=review_candidate_state,
        gate_summary=gate_summary,
        review_decision=review_decision,
        terminal_candidate_gate=terminal_candidate_gate,
    )


def write_candidate_state_artifacts(
    output: CandidateStateOutput,
    *,
    review_dir: Path,
) -> tuple[Path, Path, Path]:
    review_dir.mkdir(parents=True, exist_ok=True)
    state_path = review_dir / "review_candidate_state.json"
    gate_path = review_dir / "gate_summary.json"
    decision_path = review_dir / "review_decision.json"
    state_path.write_text(
        json.dumps(output.review_candidate_state, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    gate_path.write_text(
        json.dumps(output.gate_summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    decision_path.write_text(
        json.dumps(output.review_decision, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return state_path, gate_path, decision_path


def verify_candidate_state_consistency(
    state: Mapping[str, object],
    gate_summary: Mapping[str, object],
    decision: Mapping[str, object],
) -> tuple[bool, list[str]]:
    """Confirm the three artifacts do not contradict each other."""
    violations: list[str] = []
    state_status = state.get("candidate_status")
    summary_status = (
        CANDIDATE_STATUS_READY
        if gate_summary.get("all_internal_pass")
        else CANDIDATE_STATUS_NOT_READY
    )
    if state_status != summary_status:
        violations.append(
            f"candidate_status mismatch: state={state_status} summary={summary_status}"
        )
    if decision.get("candidate_status") != state_status:
        violations.append(
            f"decision candidate_status != state candidate_status: "
            f"{decision.get('candidate_status')} vs {state_status}"
        )
    gates_field: object = gate_summary.get("gates", {})
    gates_map: dict[str, object] = gates_field if isinstance(gates_field, dict) else {}
    if decision.get("decision") == GATE_PASS and any(
        gates_map.get(k) == GATE_FAIL
        for k in (
            "implementation_gate",
            "scm_snapshot_binding_gate",
            "command_receipt_gate",
            "test_evidence_gate",
            "internal_index_gate",
            "negative_exploit_gate",
            "package_structural_gate",
            "package_semantic_gate",
        )
    ):
        violations.append("decision=PASS but a gate is FAIL")
    _GATE_KEYS_IN_STATE = (
        "implementation_gate",
        "scm_snapshot_binding_gate",
        "command_receipt_gate",
        "test_evidence_gate",
        "internal_index_gate",
        "negative_exploit_gate",
        "package_structural_gate",
        "package_semantic_gate",
    )
    for k in _GATE_KEYS_IN_STATE:
        if state.get(k) == "PENDING":
            violations.append(f"gate field {k} has forbidden PENDING value")
    return (not violations, violations)


__all__ = [
    "CandidateStateInputs",
    "CandidateStateOutput",
    "compute_candidate_state",
    "verify_candidate_state_consistency",
    "write_candidate_state_artifacts",
]
