"""Front Door Runtime Bridge contract tests (RQ3-R2 bounded repair).

These tests target the bridge module directly: discovery, readiness
classification, AgentRequest construction, canonical adapter wiring,
presentation mapping, and version identity preservation. They are
intentionally non-subprocess tests (in-process) so they are deterministic
regardless of the host's PATH layout.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.models import (
    AgentContext,
    AgentExecutionContext,
    AgentLimits,
    AgentRequest,
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentWorkspace,
    DEFAULT_MAX_OUTPUT_BYTES,
    ProviderMeta,
    ProcessResult,
    AgentOutput,
    AgentFailure,
    FailureCategory,
)
from synapx_harness.cli.frontdoor import PresentationResult
from synapx_harness.cli.runtime_bridge import (
    CODEX_BIN_NAME,
    DEFAULT_MODEL,
    REASON_CODE_BIN_NOT_FOUND,
    REASON_CODE_OK,
    REASON_CODE_VERSION_PROBE_FAILED,
    SUPPORTED_PUBLIC_AGENT,
    CodexReadiness,
    FrontDoorRuntimeBridge,
    _build_agent_request,
    _map_agent_result,
    discover_codex,
)
from synapx_harness.contracts.runtime_models import ExecutionIdentity


def _make_agent_result(
    *,
    status: AgentStatus,
    message: str | None = None,
    duration_ms: int = 10,
    stdout: str = "",
    stderr: str = "",
) -> AgentResult:
    execution_identity = AgentExecutionContext(
        execution_identity=ExecutionIdentity(
            job_id="j1",
            task_id="t1",
            root_task_id="j1",
            attempt_id="a1",
            tool_call_id=None,
        ),
        agent_session_id="sess-1",
    )
    return AgentResult(
        status=status,
        execution_identity=execution_identity,
        provider=ProviderMeta(name="codex", model=DEFAULT_MODEL),
        process=ProcessResult(exit_code=0, duration_ms=duration_ms),
        output=AgentOutput(stdout=stdout, stderr=stderr),
        failure=(
            AgentFailure(
                category=(
                    FailureCategory.TIMEOUT
                    if status == AgentStatus.TIMEOUT
                    else FailureCategory.PROCESS_ERROR
                ),
                message=message or "n/a",
            )
            if message
            else None
        ),
        cancellation_uncertain=False,
    )


class TestDiscoverCodex:
    def test_codex_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: "C:\\fake\\codex.exe")

        captured: dict[str, object] = {}

        def fake_run(cmd, *args, **kwargs):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="codex-cli 99.99.0\n", stderr=""
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        readiness = discover_codex()
        assert readiness.executable_found is True
        assert readiness.executable_path == "C:\\fake\\codex.exe"
        assert readiness.version == "99.99.0"
        assert readiness.supported is True
        assert readiness.ready is True
        assert readiness.reason_code == REASON_CODE_OK
        # RQ8-R1: the version probe MUST receive the resolved absolute
        # executable path, not the bare ``"codex"`` token, so that
        # Windows ``.CMD`` npm installations are admitted consistently
        # with the discovered authority.
        assert captured["cmd"][0] == "C:\\fake\\codex.exe"
        assert captured["cmd"][1] == "--version"

    def test_codex_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)
        readiness = discover_codex()
        assert readiness.executable_found is False
        assert readiness.executable_path is None
        assert readiness.supported is False
        assert readiness.ready is False
        assert readiness.reason_code == REASON_CODE_BIN_NOT_FOUND

    def test_codex_version_probe_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: "C:\\fake\\codex.exe")

        def fake_run(cmd, *args, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr="boom"
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        readiness = discover_codex()
        assert readiness.executable_found is True
        assert readiness.supported is False
        assert readiness.ready is False
        assert readiness.reason_code == REASON_CODE_VERSION_PROBE_FAILED


class TestBuildAgentRequest:
    def test_request_is_workspace_and_task_bound(self) -> None:
        request = _build_agent_request(
            task_instruction="hello",
            workspace_root="C:\\work\\repo",
            model="gpt-4o-mini",
            timeout_seconds=60,
        )
        assert isinstance(request, AgentRequest)
        assert isinstance(request.workspace, AgentWorkspace)
        assert isinstance(request.task, AgentTask)
        assert isinstance(request.limits, AgentLimits)
        assert isinstance(request.execution_identity, AgentExecutionContext)
        assert isinstance(request.context, AgentContext)
        assert request.task.instruction == "hello"
        assert request.workspace.root.endswith(("work\\repo", "work/repo"))
        assert request.limits.timeout_seconds == 60
        assert request.limits.max_stdout_bytes == DEFAULT_MAX_OUTPUT_BYTES
        assert request.limits.max_stderr_bytes == DEFAULT_MAX_OUTPUT_BYTES

    def test_empty_task_rejected(self) -> None:
        with pytest.raises(ValueError):
            _build_agent_request(
                task_instruction="",
                workspace_root="C:\\work",
                model="gpt-4o-mini",
                timeout_seconds=60,
            )

    def test_empty_workspace_rejected(self) -> None:
        with pytest.raises(ValueError):
            _build_agent_request(
                task_instruction="hi",
                workspace_root="",
                model="gpt-4o-mini",
                timeout_seconds=60,
            )

    def test_attempt_id_distinct_from_task_id(self) -> None:
        request = _build_agent_request(
            task_instruction="hello",
            workspace_root="C:\\work\\repo",
            model="gpt-4o-mini",
            timeout_seconds=60,
        )
        eid = request.execution_identity.execution_identity
        assert eid.attempt_id != eid.task_id
        assert eid.root_task_id == request.execution_identity.agent_session_id


class TestMapAgentResult:
    def test_done_maps_to_completed(self) -> None:
        result = _map_agent_result(_make_agent_result(status=AgentStatus.DONE))
        assert isinstance(result, PresentationResult)
        assert result.status == "COMPLETED"
        assert result.reason is None

    def test_failed_maps_to_failed(self) -> None:
        result = _map_agent_result(
            _make_agent_result(
                status=AgentStatus.FAILED,
                message="exit code 1",
            )
        )
        assert result.status == "FAILED"
        assert result.reason is not None
        assert "exit code 1" in result.reason

    def test_timeout_maps_to_blocked(self) -> None:
        result = _map_agent_result(
            _make_agent_result(
                status=AgentStatus.TIMEOUT,
                message="deadline",
            )
        )
        assert result.status == "BLOCKED"
        assert "TIMEOUT" in result.reason

    def test_cancelled_maps_to_blocked(self) -> None:
        result = _map_agent_result(
            _make_agent_result(status=AgentStatus.CANCELLED)
        )
        assert result.status == "BLOCKED"


class TestFrontDoorRuntimeBridge:
    def _bridge(
        self,
        tmp_path: Path,
        *,
        readiness: CodexReadiness,
    ) -> FrontDoorRuntimeBridge:
        br = FrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        # Force the readiness cache directly.
        object.__setattr__(br, "_readiness", readiness)
        return br

    def test_workspace_root_attribute_preserved(self, tmp_path: Path) -> None:
        br = FrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        assert br.workspace_root == str(tmp_path)

    def test_empty_workspace_root_rejected(self) -> None:
        with pytest.raises(ValueError):
            FrontDoorRuntimeBridge(workspace_root="")

    def test_is_available_false_when_codex_missing(self, tmp_path: Path) -> None:
        br = self._bridge(
            tmp_path,
            readiness=CodexReadiness(
                executable_found=False,
                executable_path=None,
                version=None,
                supported=False,
                ready=False,
                reason_code=REASON_CODE_BIN_NOT_FOUND,
            ),
        )
        assert br.is_available() is False

    def test_is_available_true_when_codex_ready(self, tmp_path: Path) -> None:
        br = self._bridge(
            tmp_path,
            readiness=CodexReadiness(
                executable_found=True,
                executable_path="C:\\fake\\codex.exe",
                version="99.99.0",
                supported=True,
                ready=True,
                reason_code=REASON_CODE_OK,
            ),
        )
        assert br.is_available() is True

    def test_invoke_blocked_when_codex_missing(self, tmp_path: Path) -> None:
        br = self._bridge(
            tmp_path,
            readiness=CodexReadiness(
                executable_found=False,
                executable_path=None,
                version=None,
                supported=False,
                ready=False,
                reason_code=REASON_CODE_BIN_NOT_FOUND,
            ),
        )
        result = br.invoke("hello")
        assert isinstance(result, PresentationResult)
        assert result.status == "BLOCKED"
        assert result.reason is not None
        assert "CODEX_BIN_NOT_FOUND" in result.reason

    def test_invoke_delegates_to_canonical_adapter(
        self, tmp_path: Path
    ) -> None:
        br = self._bridge(
            tmp_path,
            readiness=CodexReadiness(
                executable_found=True,
                executable_path="C:\\fake\\codex.exe",
                version="99.99.0",
                supported=True,
                ready=True,
                reason_code=REASON_CODE_OK,
            ),
        )

        adapter = mock.MagicMock(spec=CodexAdapter)
        adapter.execute.return_value = _make_agent_result(
            status=AgentStatus.DONE, stdout="ok"
        )
        object.__setattr__(br, "_adapter", adapter)

        result = br.invoke("hello world")
        assert isinstance(result, PresentationResult)
        assert result.status == "COMPLETED"
        adapter.execute.assert_called_once()
        request = adapter.execute.call_args[0][0]
        assert isinstance(request, AgentRequest)
        assert request.task.instruction == "hello world"
        assert request.workspace.root.endswith(tmp_path.name)
        assert request.invocation.provider == "codex"

    def test_invoke_empty_task_blocked(self, tmp_path: Path) -> None:
        br = self._bridge(
            tmp_path,
            readiness=CodexReadiness(
                executable_found=True,
                executable_path="C:\\fake\\codex.exe",
                version="99.99.0",
                supported=True,
                ready=True,
                reason_code=REASON_CODE_OK,
            ),
        )
        adapter = mock.MagicMock(spec=CodexAdapter)
        object.__setattr__(br, "_adapter", adapter)
        result = br.invoke("")
        assert isinstance(result, PresentationResult)
        assert result.status == "BLOCKED"
        adapter.execute.assert_not_called()


class TestCanonicalContractPreserved:
    """Make sure the bridge never distorts the canonical AgentRequest /
    AgentResult shapes from the existing Codex adapter."""

    def test_workspace_root_passed_verbatim(self, tmp_path: Path) -> None:
        request = _build_agent_request(
            task_instruction="hi",
            workspace_root=str(tmp_path),
            model="gpt-4o-mini",
            timeout_seconds=60,
        )
        assert isinstance(request.workspace, AgentWorkspace)
        assert isinstance(request.execution_identity, AgentExecutionContext)
        # Root is resolved but must equal the input on POSIX or end with the
        # original basename on Windows.
        assert str(tmp_path) in request.workspace.root

    def test_supported_agent_constant_is_stable(self) -> None:
        assert SUPPORTED_PUBLIC_AGENT == "Codex_OFFICIAL_HEADLESS_CLI"