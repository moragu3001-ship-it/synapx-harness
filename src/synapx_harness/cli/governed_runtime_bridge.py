"""RQ4-R2-C3 Public Front Door Governed Runtime Bridge.

This bridge is the public-facing seam that wires the canonical
``RuntimePort`` protocol (used by ``synapx_harness.cli.frontdoor``) to the
thin ``governed_execution`` composition module.

Contract
--------
* The bridge is workspace-bound.
* ``is_available()`` reports Codex CLI readiness via the canonical probe.
* ``invoke(task)`` delegates the full lifecycle to
  :func:`synapx_harness.kernel.governed_execution.run_governed_execution`
  and maps the resulting ``TerminalDecisionRecord`` to a
  :class:`PresentationResult` for the Front Door.

* On the positive path the underlying Codex runtime is the canonical
  :class:`SubprocessCodexRuntime`. ``FakeCodexRuntime`` is never used here.

Forbidden
---------
* No policy engine, no terminal finalizer, no evidence platform. The bridge
  only maps the canonical :class:`TerminalDecisionRecord` onto the existing
  presentation surface.
"""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import Any, Callable

from synapx_harness.adapters.codex.runtime import SubprocessCodexRuntime
from synapx_harness.cli.frontdoor import PresentationResult
from synapx_harness.cli.runtime_bridge import (
    CODEX_BIN_NAME,
    CodexReadiness,
    discover_codex,
)
from synapx_harness.kernel.governed_execution import (
    DEFAULT_TIMEOUT_SECONDS,
    GovernedExecutionRequest,
    run_governed_execution,
)
from synapx_harness.kernel.terminal_finalizer import TerminalDecision


SUPPORTED_AGENT_LABEL: str = "Codex_OFFICIAL_HEADLESS_CLI"


def _default_codex_runtime_factory() -> SubprocessCodexRuntime:
    """Return the canonical real Codex runtime (positive path)."""
    return SubprocessCodexRuntime(codex_bin=CODEX_BIN_NAME)


class GovernedFrontDoorRuntimeBridge:
    """Workspace-bound public runtime bridge.

    Implements the same duck-typed interface as
    :class:`synapx_harness.cli.runtime_bridge.FrontDoorRuntimeBridge` so the
    Front Door can hold either implementation transparently.
    """

    def __init__(
        self,
        workspace_root: str,
        *,
        model: str = "gpt-5.6-luna",
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        codex_runtime_factory: Callable[[], Any] | None = None,
    ) -> None:
        if not workspace_root:
            raise ValueError("workspace_root must be a non-empty string")
        self._workspace_root = str(Path(workspace_root).resolve())
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._readiness: CodexReadiness | None = None
        self._codex_runtime_factory: Callable[[], Any] = (
            codex_runtime_factory or _default_codex_runtime_factory
        )

    @property
    def workspace_root(self) -> str:
        return self._workspace_root

    def codex_runtime_factory(self) -> Callable[[], Any]:
        return self._codex_runtime_factory

    def readiness(self) -> CodexReadiness:
        if self._readiness is None:
            self._readiness = discover_codex()
        return self._readiness

    def is_available(self) -> bool:
        return self.readiness().ready

    def invoke(self, task: str) -> PresentationResult | None:
        """Run the full governed lifecycle and map to a presentation result."""
        if not task or not task.strip():
            return PresentationResult("BLOCKED", "Empty task is not allowed.")

        readiness = self.readiness()
        if not readiness.ready:
            return PresentationResult(
                "BLOCKED",
                (
                    "Codex CLI prerequisite not satisfied: "
                    f"reason_code={readiness.reason_code}"
                ),
            )

        return self.invoke_governed(task=task)

    def invoke_governed(
        self,
        *,
        task: str,
        red_qualification_ref: str | None = None,
        verification_command: list[str] | None = None,
        codex_stdout_override: str | None = None,
        codex_proposal_instruction_override: str | None = None,
        red_qualified_override: bool | None = None,
        model: str | None = None,
        timeout_seconds: int | None = None,
        repository_id: str | None = None,
        work_contract_id: str | None = None,
        codex_runtime_factory: Callable[[], Any] | None = None,
    ) -> PresentationResult | None:
        """Run the governed lifecycle with optional test seams.

        All seams are explicit kwargs; the bridge never inspects environment
        variables to alter behavior.
        """
        request = GovernedExecutionRequest(
            workspace_root=Path(self._workspace_root),
            task=task,
            model=model or self._model,
            timeout_seconds=timeout_seconds or self._timeout_seconds,
            red_qualification_ref=red_qualification_ref,
            verification_command=verification_command,
            codex_runtime_factory=codex_runtime_factory
            or self._codex_runtime_factory,
            codex_stdout_override=codex_stdout_override,
            codex_proposal_instruction_override=codex_proposal_instruction_override,
            red_qualified_override=red_qualified_override,
            repository_id=repository_id or "synapx-rq4-c3",
            work_contract_id=work_contract_id,
        )
        result = run_governed_execution(request)
        return self._map_to_presentation(result)

    @staticmethod
    def _map_to_presentation(result: Any) -> PresentationResult | None:
        """Map the governed execution result onto Front Door presentation."""
        decision = result.terminal_decision
        if hasattr(decision, "decision"):
            decision_value = decision.decision
        else:
            decision_value = str(decision)
        if decision_value == TerminalDecision.COMPLETED.value:
            return PresentationResult("COMPLETED", None)
        if decision_value == TerminalDecision.BLOCKED.value:
            first_error = (
                result.errors[0] if getattr(result, "errors", None) else None
            )
            return PresentationResult(
                "BLOCKED",
                first_error or "Governed execution was blocked",
            )
        # FAILED
        first_error = (
            result.errors[0] if getattr(result, "errors", None) else None
        )
        return PresentationResult(
            "FAILED",
            first_error or "Governed execution reported FAILED",
        )


__all__ = [
    "GovernedFrontDoorRuntimeBridge",
    "SUPPORTED_AGENT_LABEL",
]
