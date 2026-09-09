"""Front Door Runtime Bridge (RQ3-R2 bounded repair).

This module bridges the public Front Door ``RuntimePort`` protocol to the
canonical Codex adapter contract. It is the ONLY module in ``synapx_harness.cli``
allowed to:

*  Probe the supported Codex CLI on ``PATH`` (``shutil.which`` + ``codex --version``).
*  Build a canonical :class:`~synapx_harness.adapters.codex.models.AgentRequest`.
*  Invoke :class:`~synapx_harness.adapters.codex.contract.CodexAdapter`.

The bridge exists so the user-facing ``frontdoor.py`` can remain free of
``subprocess``, ``shutil.which``, and direct provider wiring, satisfying the
existing Front Door contract tests (``test_frontdoor_cli.TestA6`` /
``TestA9``).

Authority boundary
------------------

*  The bridge constructs the canonical request and invokes the canonical
   adapter. It does NOT self-authorize verification, evidence sufficiency, or
   terminal completion.
*  ``AgentResult.status == DONE`` is mapped to ``PresentationResult("COMPLETED", ...)``
   for Front Door presentation only. ``COMPLETED`` is then mapped to the
   ``VERIFIED`` presentation string. ``VERIFIED`` is a *presentation* label
   reflecting a successful Codex run; it is NOT a Harness terminal authority
   (``VERIFIED`` here means "Front Door observed a successful agent run",
   never "evidence was sealed and reviewed").

Fake runtime guard
------------------

This module never instantiates ``FakeCodexRuntime`` for the positive path.
``FakeCodexRuntime`` exists solely for unit-level contract tests in
``tests/contract/test_lane_d_codex_adapter.py`` and must not appear here.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.models import (
    AGENT_RUNTIME_SCHEMA_VERSION,
    AgentContext,
    AgentExecutionContext,
    AgentInvocation,
    AgentLimits,
    AgentRequest,
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentWorkspace,
    DEFAULT_MAX_OUTPUT_BYTES,
)
from synapx_harness.adapters.codex.runtime import (
    RuntimeInvocation,
    SubprocessCodexRuntime,
    build_invocation,
    detect_codex_version,
)
from synapx_harness.cli.frontdoor import PresentationResult, RuntimePort
from synapx_harness.contracts.runtime_models import ExecutionIdentity


SUPPORTED_PUBLIC_AGENT: str = "Codex_OFFICIAL_HEADLESS_CLI"
CODEX_BIN_NAME: str = "codex"
# Default model is host-agnostic: Codex CLI discovers the actual model
# catalog at runtime; this is only a sane default for the first task. An
# operator can override it with the ``SYNAPX_CODEX_MODEL`` environment
# variable (no seam env in the Front Door itself; the bridge is allowed to
# read its own configuration environment).
DEFAULT_MODEL: str = os.environ.get("SYNAPX_CODEX_MODEL", "gpt-5.6-luna")
DEFAULT_TIMEOUT_SECONDS: int = 120
DEFAULT_MAX_OUTPUT_BYTES_LOCAL: int = DEFAULT_MAX_OUTPUT_BYTES


# Reason codes for the readiness surface. Strings are kept stable so that
# downstream surfaces (doctor output, JSON evidence) can rely on them.
REASON_CODE_OK: str = "OK"
REASON_CODE_BIN_NOT_FOUND: str = "CODEX_BIN_NOT_FOUND"
REASON_CODE_VERSION_PROBE_FAILED: str = "CODEX_VERSION_PROBE_FAILED"
REASON_CODE_UNSUPPORTED_RUNTIME_BACKEND: str = "UNSUPPORTED_RUNTIME_BACKEND"


@dataclass(frozen=True)
class CodexReadiness:
    """Result of probing the supported Codex CLI on PATH.

    Attributes
    ----------
    executable_found:
        True if ``shutil.which`` returned a non-empty path.
    executable_path:
        Absolute path to the codex binary, or ``None`` if not found.
    version:
        Reported version string from ``codex --version``, or ``None`` if
        the version probe failed.
    supported:
        True iff the probe succeeded and the binary is callable.
    ready:
        True iff ``executable_found`` and ``supported`` are both True.
    reason_code:
        Stable reason code for evidence / doctor output. One of the
        ``REASON_CODE_*`` constants.
    """

    executable_found: bool
    executable_path: str | None
    version: str | None
    supported: bool
    ready: bool
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "executable_found": self.executable_found,
            "executable_path": self.executable_path,
            "version": self.version,
            "supported": self.supported,
            "ready": self.ready,
            "reason_code": self.reason_code,
        }


def discover_codex() -> CodexReadiness:
    """Probe the supported Codex CLI on PATH.

    The probe is read-only: it never mutates the host filesystem, never
    invokes ``codex login`` or ``codex logout``, and never reads credentials.

    RQ8-R1 invariant: once discovery has resolved the canonical executable
    path (``shutil.which(CODEX_BIN_NAME)``), the same resolved absolute path
    MUST be the target of the version probe. Windows npm-installed Codex is
    exposed as a ``.CMD`` wrapper; passing the bare ``"codex"`` string back
    to ``subprocess.run`` can fail Windows ``CreateProcess`` even though the
    resolved path executes successfully. Discovery, probe, and execution
    MUST therefore share the same resolved target.
    """
    codex_path = shutil.which(CODEX_BIN_NAME)
    if not codex_path:
        return CodexReadiness(
            executable_found=False,
            executable_path=None,
            version=None,
            supported=False,
            ready=False,
            reason_code=REASON_CODE_BIN_NOT_FOUND,
        )
    version = detect_codex_version(codex_path)
    if version is None:
        return CodexReadiness(
            executable_found=True,
            executable_path=codex_path,
            version=None,
            supported=False,
            ready=False,
            reason_code=REASON_CODE_VERSION_PROBE_FAILED,
        )
    return CodexReadiness(
        executable_found=True,
        executable_path=codex_path,
        version=version,
        supported=True,
        ready=True,
        reason_code=REASON_CODE_OK,
    )


def _generate_session_id() -> str:
    """Allocate a SynapX-owned agent session id.

    The id is generated locally; the canonical identity is supplied by the
    caller (front door) via ``root_task_id``. This guarantees that the
    SynapX-owned session id never collides with the provider's session id
    (NEG-D-01 / AgentResult identity separation).
    """
    return f"sess-{uuid.uuid4().hex}"


def _build_agent_request(
    *,
    task_instruction: str,
    workspace_root: str,
    model: str,
    timeout_seconds: int,
) -> AgentRequest:
    """Construct a canonical ``AgentRequest`` for the supported Codex adapter.

    The request is workspace-bound (``AgentWorkspace.root``) and task-bound
    (``AgentTask.instruction``). It also carries a freshly-allocated
    ``agent_session_id`` and a canonical ``ExecutionIdentity`` whose
    ``root_task_id`` is the agent session id (so the canonical lineage
    invariant from CA-01 / CA-02 is satisfied).
    """
    if not task_instruction or not task_instruction.strip():
        raise ValueError("task_instruction must be a non-empty string")
    if not workspace_root:
        raise ValueError("workspace_root must be a non-empty string")

    session_id = _generate_session_id()
    task_id = f"task-{uuid.uuid4().hex}"
    attempt_id = f"att-{uuid.uuid4().hex}"

    execution_identity = ExecutionIdentity(
        job_id=session_id,
        task_id=task_id,
        root_task_id=session_id,
        attempt_id=attempt_id,
        tool_call_id=None,
    )

    agent_context = AgentExecutionContext(
        execution_identity=execution_identity,
        agent_session_id=session_id,
    )
    workspace = AgentWorkspace(root=str(Path(workspace_root).resolve()))
    task = AgentTask(instruction=task_instruction.strip())
    limits = AgentLimits(
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=DEFAULT_MAX_OUTPUT_BYTES_LOCAL,
        max_stderr_bytes=DEFAULT_MAX_OUTPUT_BYTES_LOCAL,
    )
    invocation = AgentInvocation(
        provider="codex",
        model=model,
        provider_config={"sandbox": "read-only"},
    )

    return AgentRequest(
        contract_type="CUSTOMOS_AGENT_REQUEST",
        schema_version=AGENT_RUNTIME_SCHEMA_VERSION,
        execution_identity=agent_context,
        workspace=workspace,
        task=task,
        context=AgentContext(),
        limits=limits,
        invocation=invocation,
    )


def _map_agent_result(result: AgentResult) -> PresentationResult:
    """Translate a canonical ``AgentResult`` into a Front Door ``PresentationResult``.

    The mapping is presentation-only. It does NOT promote agent ``DONE`` into a
    Harness terminal authority: ``VERIFIED`` here is the Front Door presentation
    label that means "agent completed successfully"; verification, evidence
    sufficiency, and terminal completion remain Harness-owned concerns.
    """
    status = result.status
    if status == AgentStatus.DONE:
        return PresentationResult("COMPLETED", None)
    if status == AgentStatus.TIMEOUT:
        failure = result.failure
        reason = failure.message if failure is not None else "Codex runtime timed out"
        return PresentationResult("BLOCKED", f"TIMEOUT: {reason}")
    if status == AgentStatus.CANCELLED:
        return PresentationResult("BLOCKED", "Cancelled by Harness")
    # FAILED or anything else
    failure = result.failure
    if failure is not None:
        return PresentationResult(
            "FAILED",
            f"{failure.category.value}: {failure.message}",
        )
    return PresentationResult("FAILED", "Codex runtime reported failure")


class FrontDoorRuntimeBridge(RuntimePort):
    """Concrete ``RuntimePort`` implementation backed by the canonical CodexAdapter.

    The bridge is **workspace-bound**: it owns a single workspace path and
    passes it through into the canonical ``AgentRequest.workspace.root``
    field on every invocation. The runtime discovery probe (``is_available``)
    is performed lazily on first access and the result is cached for the
    lifetime of this instance.

    A new instance should be constructed per workspace; the front door does
    this in :func:`synapx_harness.cli.frontdoor.run` so that two consecutive
    runs against different workspaces do not leak state.
    """

    def __init__(
        self,
        workspace_root: str,
        *,
        model: str = DEFAULT_MODEL,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        adapter: CodexAdapter | None = None,
    ) -> None:
        if not workspace_root:
            raise ValueError("workspace_root must be a non-empty string")
        self._workspace_root = workspace_root
        self._model = model
        self._timeout_seconds = timeout_seconds
        self._readiness: CodexReadiness | None = None
        self._adapter = adapter

    @property
    def workspace_root(self) -> str:
        return self._workspace_root

    def readiness(self) -> CodexReadiness:
        """Return the cached Codex readiness probe (computed lazily)."""
        if self._readiness is None:
            self._readiness = discover_codex()
        return self._readiness

    def is_available(self) -> bool:
        return self.readiness().ready

    def _ensure_adapter(self) -> CodexAdapter:
        if self._adapter is not None:
            return self._adapter
        # RQ8-R1: discovery, version probe, and execution MUST share the
        # same resolved absolute executable path. ``self.readiness()``
        # is already cached by the time ``invoke`` reaches this method,
        # so the resolved path returned here is the exact target the
        # version probe passed on the same admission cycle.
        resolved_path = self.readiness().executable_path or CODEX_BIN_NAME
        backend = SubprocessCodexRuntime(codex_bin=resolved_path)
        self._adapter = CodexAdapter(backend=backend, codex_bin=resolved_path)
        return self._adapter

    def invoke(self, task: str) -> PresentationResult | None:
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

        try:
            request = _build_agent_request(
                task_instruction=task,
                workspace_root=self._workspace_root,
                model=self._model,
                timeout_seconds=self._timeout_seconds,
            )
        except ValueError as exc:
            return PresentationResult("BLOCKED", str(exc))

        adapter = self._ensure_adapter()
        try:
            result = adapter.execute(request)
        except Exception as exc:  # pragma: no cover - defensive
            return PresentationResult("FAILED", f"Codex adapter raised: {exc}")
        return _map_agent_result(result)


__all__ = [
    "CODEX_BIN_NAME",
    "DEFAULT_MODEL",
    "DEFAULT_TIMEOUT_SECONDS",
    "CodexReadiness",
    "FrontDoorRuntimeBridge",
    "REASON_CODE_BIN_NOT_FOUND",
    "REASON_CODE_OK",
    "REASON_CODE_UNSUPPORTED_RUNTIME_BACKEND",
    "REASON_CODE_VERSION_PROBE_FAILED",
    "SUPPORTED_PUBLIC_AGENT",
    "build_invocation",
    "detect_codex_version",
    "discover_codex",
]