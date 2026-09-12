"""RQ8 Phase 2C generic agent-activity projection (read-only, Path B).

This module is CLI-local and holds NO authority:

*  No verification, no mutation, no scope, no evidence, no terminal claim.
*  It only projects the bounded invoke lifecycle the Front Door observed
   (invoke started / invoke returned) onto an immutable
   :class:`AgentActivityPresentation` value object plus line-oriented text.

Path selection (Owner decision record ``ACTIVITY_IMPLEMENTATION_DECISION``):

*  ``B_GENERIC_FALLBACK`` -- the Codex structured-event census
   (``RQ8_PHASE2C_CODEX_ACTIVITY_CENSUS``) found that rich activity would
   require a provider runtime redesign (``--json`` invocation change),
   heuristic stdout reconstruction (proposal-payload break), and an
   ``AgentResult`` schema change. All three are Phase 2C STOP conditions,
   so only the generic lifecycle (Running / Completed / Failed) is shown.

Truth rules enforced here:

*  ``Completed`` is rendered only when the invoke returned a well-formed
   ``COMPLETED`` presentation status. Every other outcome (``FAILED``,
   ``BLOCKED``, abstain, malformed) is ``Failed`` or ``Unavailable`` --
   never ``Completed`` (fail closed).
*  No command, path, session, or prose inference is rendered: Path B has
   no structured provider evidence, so anything beyond the lifecycle
   would be a fabricated timeline.
*  ``Agent completed`` here means ONLY that the invoke lifecycle finished;
   it is NOT verification, evidence qualification, or terminal completion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AgentActivityStatus = Literal["RUNNING", "COMPLETED", "FAILED", "UNKNOWN"]

ACTIVITY_HEADER: str = "Agent Activity"


@dataclass(frozen=True)
class AgentActivityPresentation:
    """Read-only projection of the bounded invoke lifecycle.

    The DTO carries NO authority fields (no verified / scope_authorized /
    evidence_valid / terminal_decision / mutation_authorized slots exist,
    by construction) and no provider-derived detail (no command / path /
    session slots): Path B has no structured provider evidence to fill
    them truthfully.
    """

    status: AgentActivityStatus = "UNKNOWN"


def unknown_activity() -> AgentActivityPresentation:
    """Fail-closed presentation for unknown/malformed source data."""
    return AgentActivityPresentation(status="UNKNOWN")


def running_activity() -> AgentActivityPresentation:
    """Pre-invoke presentation: the runtime was asked and has not returned."""
    return AgentActivityPresentation(status="RUNNING")


def activity_for_presentation_status(status: object) -> AgentActivityPresentation:
    """Map a Front Door presentation status onto generic activity.

    Only a well-formed ``COMPLETED`` status becomes ``Completed``. Every
    other terminal-shaped outcome (``FAILED`` / ``BLOCKED``) becomes
    ``Failed``; anything else (abstain, malformed, unknown) becomes
    ``UNKNOWN`` so the renderer admits ignorance instead of inventing a
    lifecycle state.
    """
    if status == "COMPLETED":
        return AgentActivityPresentation(status="COMPLETED")
    if status in ("FAILED", "BLOCKED"):
        return AgentActivityPresentation(status="FAILED")
    return AgentActivityPresentation(status="UNKNOWN")


def render_activity_lines(presentation: object) -> list[str]:
    """Render the projection as line-oriented UI (no full-screen TUI).

    The function never raises on malformed input: anything it cannot prove
    becomes an explicit unavailable state (fail closed).
    """
    try:
        status = (
            presentation.status
            if isinstance(presentation, AgentActivityPresentation)
            else None
        )
    except Exception:
        status = None
    if status == "RUNNING":
        detail = "  Running..."
    elif status == "COMPLETED":
        detail = "  Completed"
    elif status == "FAILED":
        detail = "  Failed"
    else:
        detail = "  Unavailable"
    return [ACTIVITY_HEADER, detail, ""]


__all__ = [
    "ACTIVITY_HEADER",
    "AgentActivityPresentation",
    "AgentActivityStatus",
    "activity_for_presentation_status",
    "render_activity_lines",
    "running_activity",
    "unknown_activity",
]
