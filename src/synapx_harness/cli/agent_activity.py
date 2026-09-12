"""RQ8 Phase 2C-R1 agent-truth activity projection (read-only).

This module is CLI-local and holds NO authority:

*  No verification, no mutation, no scope, no evidence, no terminal claim.
*  It only projects EXISTING agent-lifecycle signals already carried by
   the canonical governed result (``process_started``,
   ``failure_class``, ``codex_process_exit_code``,
   ``primary_failure_stage``, ``agent_stdout_sha256``) onto an immutable
   value object plus line-oriented text. No kernel/contract/adapter
   change was needed to read them (see
   ``PHASE2C_R1_AGENT_TRUTH_SOURCE_CENSUS``).

Truth rules (Owner R1 repair):

*  Agent Activity NEVER derives from ``PresentationResult.status`` (the
   governed terminal/presentation truth). Terminal FAILED with a
   completed agent renders ``Completed`` beside ``FAILED``; a pre-agent
   block renders ``Not run`` -- never ``Running``/``Completed``/``Failed``.
*  ``Completed`` requires positive start evidence (``process_started`` is
   ``True``) AND success evidence (``failure_class`` is
   ``PROCESS_SUCCESS`` with exit code ``0``) AND no agent-stage primary
   failure (``primary_failure_stage != "AGENT_PROCESS"``).
*  ``process_started`` is ``False`` with no post-invoke evidence renders
   ``Not run`` (admission blocked before any agent start).
*  Missing or contradictory signals render ``Unavailable`` (fail closed).
   In particular a ``False`` start flag combined with post-invoke
   evidence (exit code / captured-output hash) is contradictory and must
   NOT be resolved by inference.
*  ``PROCESS_LAUNCH_ERROR`` with an unstarted process renders ``Failed``:
   the invocation itself failed (stable provider-neutral class).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

AgentActivityStatus = Literal["COMPLETED", "FAILED", "NOT_RUN", "UNKNOWN"]

ACTIVITY_HEADER: str = "Agent Activity"

AGENT_PROCESS_STAGE: str = "AGENT_PROCESS"
PROCESS_SUCCESS_CLASS: str = "PROCESS_SUCCESS"
PROCESS_LAUNCH_ERROR_CLASS: str = "PROCESS_LAUNCH_ERROR"

_MISSING: Any = object()


@dataclass(frozen=True)
class AgentActivitySource:
    """Snapshot of existing agent-truth signals (no authority).

    Every slot mirrors a field ALREADY present on the canonical governed
    result. All slots are optional so partial/artificial fixtures project
    to ``Unavailable`` instead of inventing a lifecycle.
    """

    process_started: bool | None = None
    failure_class: str | None = None
    exit_code: int | None = None
    primary_failure_stage: str | None = None
    stdout_present: bool = False


@dataclass(frozen=True)
class AgentActivityPresentation:
    """Read-only projection of the agent lifecycle.

    The DTO carries NO authority fields (no verified / scope_authorized /
    evidence_valid / terminal_decision / mutation_authorized slots exist,
    by construction) and NO terminal status slot: the activity state is
    fully determined by the attached agent source, never by the Harness
    terminal outcome.
    """

    status: AgentActivityStatus = "UNKNOWN"


def source_from_result(result: Any) -> AgentActivitySource | None:
    """Snapshot existing agent-truth signals from a governed result.

    Duck-typed read-only access (never imports kernel modules). Returns
    ``None`` when the object exposes none of the known agent signals, so
    terminal-only/artificial fixtures project to ``Unavailable`` instead
    of an inferred lifecycle.
    """
    try:
        process_started = getattr(result, "process_started", _MISSING)
        failure_class = getattr(result, "failure_class", _MISSING)
        exit_code = getattr(result, "codex_process_exit_code", _MISSING)
        primary_failure_stage = getattr(
            result, "primary_failure_stage", _MISSING
        )
        stdout_sha = getattr(result, "agent_stdout_sha256", _MISSING)
    except Exception:
        return None
    if (
        process_started is _MISSING
        and failure_class is _MISSING
        and exit_code is _MISSING
        and primary_failure_stage is _MISSING
        and stdout_sha is _MISSING
    ):
        return None
    try:
        stdout_present = isinstance(stdout_sha, str) and bool(stdout_sha)
    except Exception:
        stdout_present = False
    return AgentActivitySource(
        process_started=process_started
        if isinstance(process_started, bool)
        else None,
        failure_class=failure_class
        if isinstance(failure_class, str)
        else None,
        exit_code=exit_code
        if isinstance(exit_code, int) and not isinstance(exit_code, bool)
        else None,
        primary_failure_stage=primary_failure_stage
        if isinstance(primary_failure_stage, str)
        else None,
        stdout_present=stdout_present,
    )


def unknown_activity() -> AgentActivityPresentation:
    """Fail-closed presentation for unknown/malformed source data."""
    return AgentActivityPresentation(status="UNKNOWN")


def activity_for_agent_source(
    source: AgentActivitySource | None,
) -> AgentActivityPresentation:
    """Map existing agent-truth signals onto the activity lifecycle.

    The mapping reads ONLY agent signals. The Harness terminal outcome
    is never an input, so an agent ``Completed`` coexists truthfully
    with a terminal ``FAILED``/``BLOCKED``.
    """
    if source is None:
        return AgentActivityPresentation(status="UNKNOWN")
    try:
        process_started = source.process_started
        failure_class = source.failure_class
        exit_code = source.exit_code
        primary_failure_stage = source.primary_failure_stage
        stdout_present = source.stdout_present
    except Exception:
        return AgentActivityPresentation(status="UNKNOWN")

    if process_started is True:
        if primary_failure_stage == AGENT_PROCESS_STAGE:
            return AgentActivityPresentation(status="FAILED")
        if (
            failure_class == PROCESS_SUCCESS_CLASS
            and exit_code == 0
        ):
            return AgentActivityPresentation(status="COMPLETED")
        if isinstance(failure_class, str) or isinstance(exit_code, int):
            return AgentActivityPresentation(status="FAILED")
        return AgentActivityPresentation(status="UNKNOWN")

    if process_started is False:
        if failure_class == PROCESS_LAUNCH_ERROR_CLASS:
            return AgentActivityPresentation(status="FAILED")
        if (
            failure_class is not None
            or exit_code is not None
            or stdout_present
        ):
            # Contradictory signals (e.g. unstarted flag with post-invoke
            # evidence): fail closed instead of inferring a lifecycle.
            return AgentActivityPresentation(status="UNKNOWN")
        return AgentActivityPresentation(status="NOT_RUN")

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
    if status == "COMPLETED":
        detail = "  Completed"
    elif status == "FAILED":
        detail = "  Failed"
    elif status == "NOT_RUN":
        detail = "  Not run"
    else:
        detail = "  Unavailable"
    return [ACTIVITY_HEADER, detail, ""]


__all__ = [
    "ACTIVITY_HEADER",
    "AGENT_PROCESS_STAGE",
    "PROCESS_LAUNCH_ERROR_CLASS",
    "PROCESS_SUCCESS_CLASS",
    "AgentActivityPresentation",
    "AgentActivitySource",
    "AgentActivityStatus",
    "activity_for_agent_source",
    "render_activity_lines",
    "source_from_result",
    "unknown_activity",
]
