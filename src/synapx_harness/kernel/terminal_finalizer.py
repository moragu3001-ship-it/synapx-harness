"""Terminal finalizer.

Computes the TerminalDecisionRecord for a verified WorkContract. The
finalizer enforces the COMPLETED invariants:
  - verification_status == PASS
  - evidence_status == VALID
  - active_blocker_count == 0

H2-I3 (T12/T13): the TERMINAL_FINALIZER is the SOLE issuer of terminal
decisions. Every path (agent DONE, verifier PASS, sealed evidence) must
cross the mandatory TerminalizationInput chain (INV-R3R2-TRM-001).
"""
from __future__ import annotations

import datetime as _datetime
from enum import StrEnum

from synapx_harness.contracts.runtime_models import (
    TerminalDecisionRecord,
    VerificationResult,
    build_terminal_decision,
)


class TerminalDecision(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


TERMINAL_OUTCOMES: tuple[str, ...] = ("COMPLETED", "FAILED", "BLOCKED")
TerminalDecisionSet = frozenset(TERMINAL_OUTCOMES)
TERMINAL_FINALIZER_ISSUER = "TERMINAL_FINALIZER"
FORBIDDEN_TERMINAL_ISSUERS: tuple[str, ...] = (
    "Verifier",
    "Evidence Sealer",
    "Agent",
    "Provider",
    "Scheduler",
    "Registry",
)
TERMINALIZATION_INPUT_REQUIRED_FIELDS: tuple[str, ...] = (
    "execution_identity",
    "work_contract_id",
    "verification_admission_receipt",
    "sealed_evidence",
    "source_revision_ref",
    "active_blocker_count",
    "proposed_outcome",
)


def finalize(result: VerificationResult) -> TerminalDecisionRecord:
    """Finalize a WorkContract based on its VerificationResult."""
    if result.active_blocker_count > 0:
        return build_terminal_decision(
            work_contract_id=result.work_contract_id,
            decision=TerminalDecision.BLOCKED.value,
            reason=f"active_blocker_count={result.active_blocker_count}",
        )
    if result.verification_status != "PASS":
        return build_terminal_decision(
            work_contract_id=result.work_contract_id,
            decision=TerminalDecision.FAILED.value,
            reason=f"verification_status={result.verification_status}",
        )
    if result.evidence_status != "VALID":
        return build_terminal_decision(
            work_contract_id=result.work_contract_id,
            decision=TerminalDecision.FAILED.value,
            reason=f"evidence_status={result.evidence_status}",
        )
    return build_terminal_decision(
        work_contract_id=result.work_contract_id,
        decision=TerminalDecision.COMPLETED.value,
        reason="all invariants satisfied",
    )


# -- H2-I3 terminal chain (T12/T13) -----------------------------------------


def _require_terminalization_input(
    terminalization_input: dict[str, object] | None,
) -> dict[str, object]:
    if terminalization_input is None:
        raise ValueError(
            "terminalization input is required before any terminal decision "
            "(terminal|input)"
        )
    if not isinstance(terminalization_input, dict):
        raise ValueError(
            "terminalization input must be a dict "
            "(terminal|input|finaliz)"
        )
    missing = [
        field
        for field in TERMINALIZATION_INPUT_REQUIRED_FIELDS
        if field not in terminalization_input
    ]
    if missing:
        raise ValueError(
            f"terminalization input incomplete: missing {missing} "
            "(terminal|finaliz|chain)"
        )
    return terminalization_input


def _enforce_verification_invariants_for_completion(
    terminalization_input: dict[str, object],
    *,
    context_tag: str,
) -> None:
    """Block proposed_outcome=COMPLETED unless all invariants are satisfied.

    H2-I5-R1 repair: closes the false-completion hole in
    ``finalize_terminal_chain`` and ``finalize_from_sealed_evidence``. A COMPLETED
    decision requires:
      - verification_status == 'PASS'
      - evidence_status == 'VALID'
      - active_blocker_count == 0

    Any other combination while proposed_outcome == COMPLETED raises
    ``ValueError`` with an explicit ``(finaliz|verify-fail)`` tag.
    """
    proposed = terminalization_input.get("proposed_outcome")
    if proposed != TerminalDecision.COMPLETED.value:
        return

    var_receipt = terminalization_input.get("verification_admission_receipt")
    if not isinstance(var_receipt, dict):
        raise ValueError(
            "terminalization input missing verification_admission_receipt; "
            "COMPLETED is not issuable without verification admission "
            f"(finaliz|verify-fail|{context_tag})"
        )

    verification_status = str(var_receipt.get("verification_status") or "")
    if verification_status != "PASS":
        raise ValueError(
            f"verification_status={verification_status!r} forbids COMPLETED; "
            "COMPLETED requires verification_status='PASS' "
            f"(finaliz|verify-fail|{context_tag})"
        )

    evidence_status = str(var_receipt.get("evidence_status") or "")
    if evidence_status != "VALID":
        raise ValueError(
            f"evidence_status={evidence_status!r} forbids COMPLETED; "
            "COMPLETED requires evidence_status='VALID' "
            f"(finaliz|verify-fail|{context_tag})"
        )

    blocker_count = terminalization_input.get("active_blocker_count", 0)
    if not isinstance(blocker_count, int) or blocker_count > 0:
        raise ValueError(
            f"active_blocker_count={blocker_count!r} forbids COMPLETED; "
            "COMPLETED requires active_blocker_count=0 "
            f"(finaliz|verify-fail|{context_tag})"
        )


def finalize_terminal_chain(
    work_contract_id: str,
    sealed_evidence: dict[str, object],
    terminalization_input: dict[str, object] | None,
) -> TerminalDecisionRecord:
    """Single terminalization path: SEALED evidence + mandatory input."""
    if terminalization_input is None:
        raise ValueError(
            "terminalization input is required before terminal chain finalization "
            "(terminal|input)"
        )
    if not isinstance(sealed_evidence, dict) or sealed_evidence.get("integrity_status") != "SEALED":
        raise ValueError(
            f"evidence chain must be sealed before terminal finalization; "
            f"got {sealed_evidence!r} (seal|evidence)"
        )
    terminalization_input = _require_terminalization_input(terminalization_input)
    proposed = terminalization_input.get("proposed_outcome")
    if proposed not in TerminalDecisionSet:
        raise ValueError(
            f"proposed outcome {proposed!r} must be one of "
            f"{sorted(TerminalDecisionSet)} (terminal|finaliz|chain)"
        )
    _enforce_verification_invariants_for_completion(
        terminalization_input, context_tag="chain"
    )
    reason = str(terminalization_input.get("reason") or "terminal chain finalized")
    return build_terminal_decision(
        work_contract_id=work_contract_id,
        decision=proposed,
        reason=reason,
    )


def finalize_from_sealed_evidence(
    sealed_evidence: dict[str, object],
    terminalization_input: dict[str, object] | None,
) -> TerminalDecisionRecord:
    """RED-I0-05: a sealed envelope alone is never a terminal decision."""
    if terminalization_input is None:
        raise ValueError(
            "terminalization input is required: a sealed envelope alone is not "
            "a terminal decision (terminal)"
        )
    if not isinstance(sealed_evidence, dict) or sealed_evidence.get("integrity_status") != "SEALED":
        raise ValueError(
            f"sealed evidence required for finalization; got {sealed_evidence!r} "
            "(terminal|seal)"
        )
    terminalization_input = _require_terminalization_input(terminalization_input)
    proposed = terminalization_input.get("proposed_outcome")
    if proposed not in TerminalDecisionSet:
        raise ValueError(
            f"proposed outcome {proposed!r} must be one of "
            f"{sorted(TerminalDecisionSet)} (terminal)"
        )
    _enforce_verification_invariants_for_completion(
        terminalization_input, context_tag="sealed"
    )
    return build_terminal_decision(
        work_contract_id=str(terminalization_input.get("work_contract_id") or "unknown"),
        decision=proposed,
        reason=str(terminalization_input.get("reason") or "finalized from sealed evidence"),
    )


def finalize_from_agent_done(
    work_contract_id: str,
    claim: dict[str, object],
) -> TerminalDecisionRecord:
    """RED-I0-03: Agent DONE claims cannot be promoted to COMPLETED."""
    raise ValueError(
        f"agent done claim cannot be finalized to a terminal decision: {claim!r} "
        "must pass through verification admission, evidence sealing and the "
        "terminal finalizer chain (finaliz|terminal)"
    )


def advance_agent_claim(
    claim: dict[str, object],
    target_state: str,
) -> dict[str, object]:
    """RED-I0-03: an Agent DONE claim may only transition to VERIFYING."""
    if not isinstance(claim, dict) or claim.get("claim_type") != "AGENT_DONE_CLAIM":
        raise ValueError(
            f"claim must be an AGENT_DONE_CLAIM; got {claim!r} "
            "(verifying|transition)"
        )
    if target_state != "VERIFYING":
        raise ValueError(
            f"agent done claim may only transition to VERIFYING; got {target_state!r} "
            "(verifying|transition)"
        )
    return {"claim_type": "AGENT_DONE_CLAIM", "state": "VERIFYING"}


def issue_terminal_decision(
    work_contract_id: str,
    decision: str,
    issued_by: str,
    terminalization_input: dict[str, object] | None = None,
) -> dict[str, object]:
    """RED-I0-06: only the TERMINAL_FINALIZER may issue terminal decisions."""
    if not isinstance(issued_by, str) or issued_by in FORBIDDEN_TERMINAL_ISSUERS:
        raise ValueError(
            f"issuer {issued_by!r} is forbidden: only the terminal finalizer "
            "may issue terminal decisions (issuer|finaliz)"
        )
    if issued_by != TERMINAL_FINALIZER_ISSUER:
        raise ValueError(
            f"issuer {issued_by!r} is not the terminal finalizer "
            "(issuer|finaliz)"
        )
    if decision not in TerminalDecisionSet:
        raise ValueError(
            f"decision {decision!r} must be one of {sorted(TerminalDecisionSet)} "
            "for finalizer issuance (finaliz)"
        )
    terminalization_input = _require_terminalization_input(terminalization_input)
    record = build_terminal_decision(
        work_contract_id=work_contract_id,
        decision=decision,
        reason=str(terminalization_input.get("reason") or "issued by terminal finalizer"),
    )
    return {
        "record": record.model_dump(mode="json"),
        "issued_by": issued_by,
        "issued_at": _datetime.datetime.now(_datetime.UTC).isoformat(),
        "terminalization_input_ref": terminalization_input.get("input_ref"),
    }


__all__ = [
    "FORBIDDEN_TERMINAL_ISSUERS",
    "TERMINAL_FINALIZER_ISSUER",
    "TERMINAL_OUTCOMES",
    "TERMINALIZATION_INPUT_REQUIRED_FIELDS",
    "TerminalDecision",
    "TerminalDecisionRecord",
    "TerminalDecisionSet",
    "advance_agent_claim",
    "finalize",
    "finalize_from_agent_done",
    "finalize_from_sealed_evidence",
    "finalize_terminal_chain",
    "issue_terminal_decision",
]
