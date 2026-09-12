"""RQ8 Phase 2B authoritative assurance projection (read-only).

This module is CLI-local and holds NO authority:

*  No policy decision, no terminal decision, no verification execution,
   no mutation execution, no evidence sealing.
*  It only reads a canonical ``GovernedExecutionResult`` (via duck-typed
   attribute access, so this module never imports
   ``synapx_harness.kernel``) and projects it onto an immutable
   :class:`AssurancePresentation` value object plus line-oriented text.

Truth rules enforced here (Owner R1 corrections):

*  Scope AUTHORIZED requires the full ALLOW chain
   (admission ALLOW **and** path-gate ALLOW). Admission ALLOW alone is
   never promoted.
*  Evidence QUALIFIED requires VALID **and** a SEALED evidence chain.
*  Terminal reason follows first-failure precedence:
   ``primary_failure_message`` > ``errors[0]`` >
   ``terminal_decision.reason`` > deterministic fallback.
*  Synthetic verification sentinels (``verification-not-run``,
   ``verification-attempted``, ``blocked-0``) are never user-visible.
*  Structured test counts do not exist in the canonical result, so the
   projection always reports them unavailable and never fabricates
   numbers from stdout text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

MutationState = Literal["OBSERVED", "ATTEMPTED_NO_WRITE", "NOT_ATTEMPTED", "UNAVAILABLE"]
ChangedFilesState = Literal["AVAILABLE", "ZERO", "NOT_ATTEMPTED", "UNAVAILABLE"]
ScopeState = Literal["AUTHORIZED", "DENIED", "NOT_EVALUATED", "PARTIAL", "UNKNOWN"]
VerificationState = Literal["PASS", "FAIL", "NOT_RUN", "UNAVAILABLE", "UNKNOWN"]
TestCountsState = Literal["UNAVAILABLE"]
EvidenceState = Literal["QUALIFIED", "INVALID", "NOT_RUN", "UNAVAILABLE", "UNKNOWN"]
TerminalState = Literal["COMPLETED", "FAILED", "BLOCKED", "UNKNOWN"]

SYNTHETIC_VERIFICATION_COMMANDS: frozenset[str] = frozenset(
    {
        "verification-not-run",
        "verification-attempted",
        "blocked-0",
    }
)

TERMINAL_LABELS: dict[str, str] = {
    "COMPLETED": "VERIFIED",
    "FAILED": "FAILED",
    "BLOCKED": "NEEDS_ATTENTION",
    "UNKNOWN": "NEEDS_ATTENTION",
}

_FALLBACK_REASON: str = "No canonical reason recorded"


@dataclass(frozen=True)
class AssurancePresentation:
    """Read-only projection of one canonical governed execution result."""

    mutation_state: MutationState = "UNAVAILABLE"
    changed_files: tuple[str, ...] | None = None
    changed_file_count: int | None = None
    changed_files_state: ChangedFilesState = "UNAVAILABLE"
    scope_state: ScopeState = "UNKNOWN"
    verification_attempted: bool = False
    verification_command: str | None = None
    verification_state: VerificationState = "UNKNOWN"
    test_counts_state: TestCountsState = "UNAVAILABLE"
    evidence_state: EvidenceState = "UNKNOWN"
    terminal_state: TerminalState = "UNKNOWN"
    terminal_reason: str | None = None


def unknown_presentation(reason: str | None = None) -> AssurancePresentation:
    """Fail-closed presentation for unknown/malformed source data."""
    return AssurancePresentation(
        mutation_state="UNAVAILABLE",
        changed_files=None,
        changed_file_count=None,
        changed_files_state="UNAVAILABLE",
        scope_state="UNKNOWN",
        verification_attempted=False,
        verification_command=None,
        verification_state="UNKNOWN",
        test_counts_state="UNAVAILABLE",
        evidence_state="UNKNOWN",
        terminal_state="UNKNOWN",
        terminal_reason=reason or _FALLBACK_REASON,
    )


def _is_nonempty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _resolve_terminal_reason(result: Any) -> str:
    """Apply first-failure precedence for the user-facing reason."""
    primary = getattr(result, "primary_failure_message", None)
    if _is_nonempty_str(primary):
        return str(primary).strip()
    errors = getattr(result, "errors", None)
    if isinstance(errors, list) and errors:
        first = errors[0]
        if _is_nonempty_str(first):
            return str(first).strip()
    decision_obj = getattr(result, "terminal_decision", None)
    terminal_reason: object = None
    if isinstance(decision_obj, dict):
        terminal_reason = decision_obj.get("reason")
    else:
        terminal_reason = getattr(decision_obj, "reason", None)
    if _is_nonempty_str(terminal_reason):
        return str(terminal_reason).strip()
    return _FALLBACK_REASON


def build_assurance_presentation(result: Any) -> AssurancePresentation:
    """Project a canonical governed result onto a read-only presentation.

    The function never raises on malformed input: anything it cannot prove
    becomes an explicit unknown/unavailable state (fail closed).
    """
    if result is None or isinstance(result, (str, bytes, int, float, bool)):
        return unknown_presentation()
    if isinstance(result, dict):
        return unknown_presentation()

    try:
        mutation_attempted = bool(getattr(result, "mutation_attempted", False))
        apply_receipt = getattr(result, "apply_receipt", None)
        if apply_receipt is not None and not isinstance(apply_receipt, dict):
            applied_raw = getattr(apply_receipt, "applied_paths", None)
            write_raw = getattr(apply_receipt, "write_count", None)
        elif isinstance(apply_receipt, dict):
            applied_raw = apply_receipt.get("applied_paths")
            write_raw = apply_receipt.get("write_count")
        else:
            applied_raw = None
            write_raw = None

        applied_paths: tuple[str, ...] | None = None
        if isinstance(applied_raw, (list, tuple)):
            cleaned = [p for p in applied_raw if isinstance(p, str) and p]
            applied_paths = tuple(cleaned)
        write_count: int | None = None
        if isinstance(write_raw, int) and not isinstance(write_raw, bool):
            write_count = int(write_raw)

        if not mutation_attempted:
            mutation_state: MutationState = "NOT_ATTEMPTED"
        elif apply_receipt is None:
            mutation_state = "UNAVAILABLE"
        elif write_count is not None and write_count > 0 and applied_paths:
            mutation_state = "OBSERVED"
        elif write_count == 0:
            mutation_state = "ATTEMPTED_NO_WRITE"
        else:
            mutation_state = "UNAVAILABLE"

        if not mutation_attempted:
            changed_files_state: ChangedFilesState = "NOT_ATTEMPTED"
            changed_files: tuple[str, ...] | None = None
            changed_file_count: int | None = None
        elif apply_receipt is None:
            changed_files_state = "UNAVAILABLE"
            changed_files = None
            changed_file_count = None
        elif write_count is not None and write_count > 0 and applied_paths:
            changed_files_state = "AVAILABLE"
            changed_files = applied_paths
            changed_file_count = int(write_count)
        elif write_count == 0:
            changed_files_state = "ZERO"
            changed_files = ()
            changed_file_count = 0
        else:
            changed_files_state = "UNAVAILABLE"
            changed_files = None
            changed_file_count = None

        admission = getattr(result, "admission_receipt", None)
        path_gate = getattr(result, "path_gate_receipt", None)
        if isinstance(admission, dict):
            admission_decision = admission.get("admission_decision")
        else:
            admission_decision = getattr(admission, "admission_decision", None)
        if isinstance(path_gate, dict):
            path_decision = path_gate.get("gate_decision")
        else:
            path_decision = getattr(path_gate, "gate_decision", None)

        if admission_decision == "ALLOW" and path_decision == "ALLOW":
            scope_state: ScopeState = "AUTHORIZED"
        elif admission_decision == "DENY" or path_decision == "DENY":
            scope_state = "DENIED"
        elif admission is None and path_gate is None:
            scope_state = "NOT_EVALUATED"
        elif admission_decision == "ALLOW" and path_gate is None:
            scope_state = "PARTIAL"
        else:
            scope_state = "UNKNOWN"

        verification_attempted = bool(getattr(result, "verification_attempted", False))
        verification = getattr(result, "verification", None)
        if isinstance(verification, dict):
            verification_status = verification.get("verification_status")
            evidence_status = verification.get("evidence_status")
            command_result = verification.get("command_result")
        else:
            verification_status = getattr(verification, "verification_status", None)
            evidence_status = getattr(verification, "evidence_status", None)
            command_result = getattr(verification, "command_result", None)
        if isinstance(command_result, dict):
            sanitized = command_result.get("sanitized_command")
            command_id = command_result.get("command_id")
        else:
            sanitized = getattr(command_result, "sanitized_command", None)
            command_id = getattr(command_result, "command_id", None)

        verification_command: str | None = None
        if (
            verification_attempted
            and _is_nonempty_str(sanitized)
            and str(sanitized).strip() not in SYNTHETIC_VERIFICATION_COMMANDS
            and command_id != "blocked-0"
        ):
            verification_command = str(sanitized).strip()

        if verification_status == "PASS":
            verification_state: VerificationState = "PASS"
        elif verification_status == "FAIL":
            verification_state = "FAIL"
        elif verification_status == "NOT_RUN":
            verification_state = "NOT_RUN"
        else:
            verification_state = "UNKNOWN"

        sealed = getattr(result, "sealed_evidence", None)
        if isinstance(sealed, dict):
            integrity_status = sealed.get("integrity_status")
        else:
            integrity_status = getattr(sealed, "integrity_status", None)

        if evidence_status == "VALID" and integrity_status == "SEALED":
            evidence_state: EvidenceState = "QUALIFIED"
        elif evidence_status == "INVALID":
            evidence_state = "INVALID"
        elif evidence_status == "NOT_RUN":
            evidence_state = "NOT_RUN"
        elif evidence_status == "VALID":
            evidence_state = "UNAVAILABLE"
        else:
            evidence_state = "UNKNOWN"

        decision_obj = getattr(result, "terminal_decision", None)
        if isinstance(decision_obj, dict):
            decision_value = decision_obj.get("decision")
        elif isinstance(decision_obj, str):
            decision_value = decision_obj
        else:
            decision_value = getattr(decision_obj, "decision", None)
        if decision_value == "COMPLETED":
            terminal_state: TerminalState = "COMPLETED"
        elif decision_value == "FAILED":
            terminal_state = "FAILED"
        elif decision_value == "BLOCKED":
            terminal_state = "BLOCKED"
        else:
            terminal_state = "UNKNOWN"

        return AssurancePresentation(
            mutation_state=mutation_state,
            changed_files=changed_files,
            changed_file_count=changed_file_count,
            changed_files_state=changed_files_state,
            scope_state=scope_state,
            verification_attempted=bool(verification_attempted),
            verification_command=verification_command,
            verification_state=verification_state,
            test_counts_state="UNAVAILABLE",
            evidence_state=evidence_state,
            terminal_state=terminal_state,
            terminal_reason=_resolve_terminal_reason(result),
        )
    except Exception:
        return unknown_presentation()


def terminal_label(presentation: AssurancePresentation) -> str:
    """Map the projected terminal state onto the public label (fail closed)."""
    return TERMINAL_LABELS.get(presentation.terminal_state, "NEEDS_ATTENTION")


def render_assurance_lines(presentation: AssurancePresentation) -> list[str]:
    """Render the projection as line-oriented UI (no full-screen TUI)."""
    lines: list[str] = []

    lines.append("Changes")
    if presentation.changed_files_state == "AVAILABLE" and presentation.changed_files:
        for path in presentation.changed_files:
            lines.append(f"  {path}")
        count = presentation.changed_file_count or len(presentation.changed_files)
        lines.append(f"  {count} file changed" if count == 1 else f"  {count} files changed")
    elif presentation.changed_files_state == "ZERO":
        lines.append("  No files changed")
    elif presentation.changed_files_state == "NOT_ATTEMPTED":
        lines.append("  Mutation not attempted")
    else:
        lines.append("  Changed files unavailable")
    lines.append("")

    lines.append("SynapX Assurance")
    if presentation.mutation_state == "OBSERVED":
        lines.append("  ✓ Mutation observed")
    elif presentation.mutation_state == "ATTEMPTED_NO_WRITE":
        lines.append("  ✗ No qualified mutation produced")
    elif presentation.mutation_state == "NOT_ATTEMPTED":
        lines.append("  - Mutation not attempted")
    else:
        lines.append("  - Mutation unavailable")
    if presentation.scope_state == "AUTHORIZED":
        lines.append("  ✓ Scope authorized")
    elif presentation.scope_state == "DENIED":
        lines.append("  ✗ Scope denied")
    elif presentation.scope_state == "NOT_EVALUATED":
        lines.append("  - Scope not evaluated")
    elif presentation.scope_state == "PARTIAL":
        lines.append("  - Scope not fully evaluated")
    else:
        lines.append("  - Scope unavailable")
    lines.append("")

    lines.append("Verification")
    if presentation.verification_state == "NOT_RUN" or not presentation.verification_attempted:
        lines.append("  Not run")
    elif presentation.verification_command:
        lines.append(f"  {presentation.verification_command}")
    else:
        lines.append("  Verification unavailable")
    if presentation.verification_state == "PASS":
        lines.append("  ✓ PASS")
    elif presentation.verification_state == "FAIL":
        lines.append("  ✗ FAILED")
    elif presentation.verification_state == "NOT_RUN":
        lines.append("  - Not run")
    else:
        lines.append("  - Verification unavailable")
    if presentation.verification_state in ("PASS", "FAIL"):
        lines.append("  Test counts unavailable")
    lines.append("")

    lines.append("Evidence")
    if presentation.evidence_state == "QUALIFIED":
        lines.append("  ✓ Qualified")
    elif presentation.evidence_state == "INVALID":
        lines.append("  ✗ Invalid")
    elif presentation.evidence_state == "NOT_RUN":
        lines.append("  - Qualification not run")
    else:
        lines.append("  - Qualification unavailable")

    return lines


__all__ = [
    "AssurancePresentation",
    "ChangedFilesState",
    "EvidenceState",
    "MutationState",
    "ScopeState",
    "SYNTHETIC_VERIFICATION_COMMANDS",
    "TERMINAL_LABELS",
    "TerminalState",
    "TestCountsState",
    "VerificationState",
    "build_assurance_presentation",
    "render_assurance_lines",
    "terminal_label",
    "unknown_presentation",
]
