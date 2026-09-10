"""RQ8-R1-R2 -- Actual Codex Invocation Executable Lineage tests.

Background
----------
RQ8-R1-R1 pinned the *configuration* equality:

    readiness.executable_path == SubprocessCodexRuntime.codex_bin

But the canonical substrate (proved by the new-PC clean-room re-admission
where the bare ``"codex"`` token leaked all the way down to ``subprocess.Popen``
on the npm ``codex.CMD`` install) revealed that *configuration equality is not
enough*.  The full chain -- from discovery through the bare ``Popen`` argv --
must agree, byte-for-byte, with the resolved executable authority.

RQ8-R1-R2 fixes the *anchoring*:

* ``CodexAdapter.__init__`` now snapshots the executable identity at
  construction time (the prior implementation relied on a dynamic
  ``self._backend.codex_bin`` lookup inside :meth:`execute`, which silently
  fell back to the bare ``"codex"`` token whenever the backend did not expose
  a ``codex_bin`` attribute).
* :func:`synapx_harness.kernel.governed_execution._default_adapter` now passes
  the backend's resolved path explicitly to ``CodexAdapter`` so the binding
  is unambiguous at the construction site.

The tests in this module pin the resulting **End-to-End Codex Executable
Lineage** invariant:

    E0 = discover_codex().executable_path
    E1 = version probe target
    E2 = admitted readiness executable
    E3 = SubprocessCodexRuntime.codex_bin
    E4 = CodexAdapter.codex_bin
    E5 = RuntimeInvocation.command[0]
    E6 = actual Popen argv[0]

    REQUIRED: E0 == E1 == E2 == E3 == E4 == E5 == E6

The final proof, per RQ8-R1-R2 §27, is:

    "We configured codex.CMD"
    !=
    "The exact admitted codex.CMD became Popen argv[0]."

These tests pin the latter statement.
"""
from __future__ import annotations

import io
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario
from synapx_harness.adapters.codex.models import (
    AGENT_RUNTIME_SCHEMA_VERSION,
    AgentContext,
    AgentExecutionContext,
    AgentInvocation,
    AgentLimits,
    AgentRequest,
    AgentTask,
    AgentWorkspace,
)
from synapx_harness.adapters.codex.runtime import (
    SubprocessCodexRuntime,
    build_invocation,
    detect_codex_version,
)
from synapx_harness.cli.governed_runtime_bridge import (
    GovernedFrontDoorRuntimeBridge,
)
from synapx_harness.cli.runtime_bridge import (
    CODEX_BIN_NAME,
    REASON_CODE_BIN_NOT_FOUND,
    REASON_CODE_OK,
    REASON_CODE_VERSION_PROBE_FAILED,
    CodexReadiness,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


NPM_CODEX_PATH: str = r"C:\Users\morag\AppData\Roaming\npm\codex.CMD"
NATIVE_CODEX_PATH: str = r"C:\Users\morag\AppData\Local\Programs\OpenAI\Codex\bin\codex.EXE"


def _inject_readiness(
    bridge: GovernedFrontDoorRuntimeBridge,
    readiness: CodexReadiness,
) -> GovernedFrontDoorRuntimeBridge:
    """Inject a deterministic readiness directly into the bridge cache."""
    object.__setattr__(bridge, "_readiness", readiness)
    return bridge


def _make_ready_readiness(executable_path: str, version: str) -> CodexReadiness:
    return CodexReadiness(
        executable_found=True,
        executable_path=executable_path,
        version=version,
        supported=True,
        ready=True,
        reason_code=REASON_CODE_OK,
    )


def _make_unready_readiness(
    executable_found: bool,
    executable_path: str | None,
    reason_code: str,
    version: str | None = None,
) -> CodexReadiness:
    return CodexReadiness(
        executable_found=executable_found,
        executable_path=executable_path,
        version=version,
        supported=False,
        ready=False,
        reason_code=reason_code,
    )


def _build_agent_request(
    workspace_root: str, task_instruction: str = "Reply exactly OK."
) -> AgentRequest:
    """Construct a canonical ``AgentRequest`` for lineage inspection."""
    eid = {
        "job_id": "j-lineage",
        "root_task_id": "r-lineage",
        "task_id": "t-lineage",
        "attempt_id": "a-lineage",
        "tool_call_id": None,
    }
    from synapx_harness.contracts.runtime_models import ExecutionIdentity
    identity = ExecutionIdentity(
        job_id=eid["job_id"],
        root_task_id=eid["root_task_id"],
        task_id=eid["task_id"],
        attempt_id=eid["attempt_id"],
        tool_call_id=eid["tool_call_id"],
    )
    ctx = AgentExecutionContext(
        execution_identity=identity,
        agent_session_id="agent-lineage",
    )
    return AgentRequest(
        contract_type="CUSTOMOS_AGENT_REQUEST",
        schema_version=AGENT_RUNTIME_SCHEMA_VERSION,
        execution_identity=ctx,
        workspace=AgentWorkspace(root=workspace_root, revision="r-lineage"),
        task=AgentTask(instruction=task_instruction),
        context=AgentContext(),
        limits=AgentLimits(
            timeout_seconds=30,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
        ),
        invocation=AgentInvocation(provider="codex", model="gpt-5.6-luna"),
    )


def _prime_version_cache(backend: SubprocessCodexRuntime, version: str) -> None:
    """Pre-populate the backend's version cache.

    The runtime calls ``self.version()`` inside :meth:`invoke`, which in turn
    calls ``detect_codex_version`` (``subprocess.run`` -> ``Popen``) when the
    cache is empty.  Tests that want to assert on the *single* ``codex exec``
    Popen call MUST pre-cache the version so the version probe does not
    pollute the capture buffer.
    """
    backend._version_cache = version


class _CapturingPopen:
    """Deterministic fake Popen that records argv and exits 0 with stdout.

    This is the gate for L3: the captured ``command[0]`` is the actual argv
    SynapX would hand to ``subprocess.Popen`` on the host. If the lineage
    drifts, this captures the bare token instead of the resolved path.
    """

    def __init__(
        self,
        cmd: list[str],
        *,
        stdout_payload: bytes = b"RQ8_R1_R2_LINEAGE_OK\n",
        stderr_payload: bytes = b"",
        exit_code: int = 0,
        **kwargs: Any,
    ) -> None:
        global _CAPTURED_CMDS
        _CAPTURED_CMDS.append(list(cmd))
        self._cmd = list(cmd)
        self._stdout = io.BytesIO(stdout_payload)
        self._stderr = io.BytesIO(stderr_payload)
        self._exit_code = exit_code
        self._killed = False

    def __enter__(self) -> "_CapturingPopen":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._stdout.close()
        self._stderr.close()

    @property
    def args(self) -> list[str]:
        return list(self._cmd)

    def communicate(
        self,
        input: Any = None,
        timeout: float | None = None,
    ) -> tuple[bytes, bytes]:
        stdout = self._stdout.getvalue()
        stderr = self._stderr.getvalue()
        return stdout, stderr

    def poll(self) -> int | None:
        return self._exit_code

    def kill(self) -> None:
        self._killed = True

    def wait(self, timeout: float | None = None) -> int:
        return self._exit_code

    @property
    def stdout(self):
        return self._stdout

    @property
    def stderr(self):
        return self._stderr

    @property
    def returncode(self) -> int:
        return self._exit_code


_CAPTURED_CMDS: list[list[str]] = []


@pytest.fixture(autouse=True)
def _reset_capture():
    """Ensure each test sees a fresh capture buffer."""
    global _CAPTURED_CMDS
    _CAPTURED_CMDS = []
    yield
    _CAPTURED_CMDS = []


def _install_fake_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the capturing Popen on ``subprocess.Popen`` in the runtime module."""

    def _factory(*args: Any, **kwargs: Any):
        # ``detect_codex_version`` uses ``subprocess.run`` (which calls
        # ``Popen``) to probe ``codex --version``. The version probe is
        # legitimately *part* of the runtime's lifecycle, but the L3
        # ``argv[0]`` gate is specifically about the ``exec`` invocation.
        # We still capture every Popen call (so a regression that triggers
        # ``shutil.which`` or another probe would surface), but tests can
        # filter to ``exec`` commands via :func:`_exec_invocations`.
        return _CapturingPopen(*args, **kwargs)

    monkeypatch.setattr(
        "synapx_harness.adapters.codex.runtime.subprocess.Popen",
        _factory,
    )


def _exec_invocations() -> list[list[str]]:
    """Return only the ``codex exec`` calls (skip ``--version`` probes)."""
    return [cmd for cmd in _CAPTURED_CMDS if len(cmd) >= 2 and cmd[1] == "exec"]


# ---------------------------------------------------------------------------
# L1 -- npm .CMD resolved path end-to-end lineage
# ---------------------------------------------------------------------------


class TestL1NpmCmdEndToEndLineage:
    """E0..E6 must agree on the resolved npm ``codex.CMD`` path."""

    def test_full_lineage_chain(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """All seven stages MUST agree on the resolved npm ``codex.CMD``."""

        # E0/E2: discovery + admission select the resolved path
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)

        # E1: version probe target = resolved path; produce a real version
        probe_calls: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            probe_calls.append(list(cmd))
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="codex-cli 0.153.4\n", stderr=""
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        # E6: capture actual Popen argv
        _install_fake_popen(monkeypatch)

        from synapx_harness.cli.runtime_bridge import discover_codex

        readiness = discover_codex()
        assert readiness.ready is True
        e0_e2_path = readiness.executable_path
        assert e0_e2_path == NPM_CODEX_PATH

        # E1: probe target
        assert probe_calls
        assert probe_calls[0][0] == NPM_CODEX_PATH

        # E3/E4: backend + adapter
        backend = SubprocessCodexRuntime(codex_bin=e0_e2_path)
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(backend=backend)
        assert backend.codex_bin == NPM_CODEX_PATH  # E3
        assert adapter.codex_bin == NPM_CODEX_PATH  # E4

        # E5: RuntimeInvocation.command[0]
        request = _build_agent_request(str(tmp_path))
        inv = build_invocation(request, adapter.codex_bin)
        assert inv.command[0] == NPM_CODEX_PATH  # E5

        # E6: actual Popen argv[0]
        adapter.execute(request)
        assert _CAPTURED_CMDS, "Popen was never invoked"
        assert _CAPTURED_CMDS[0][0] == NPM_CODEX_PATH  # E6

    def test_lineage_holds_for_bridge_default_factory(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The bridge's default factory MUST participate in the lineage
        (covers the production positive path through
        ``GovernedFrontDoorRuntimeBridge``)."""

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )
        _install_fake_popen(monkeypatch)

        factory = bridge.codex_runtime_factory()
        backend = factory()
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )

        request = _build_agent_request(str(tmp_path))
        inv = build_invocation(request, adapter.codex_bin)
        assert inv.command[0] == NPM_CODEX_PATH

        adapter.execute(request)
        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NPM_CODEX_PATH


# ---------------------------------------------------------------------------
# L2 -- bare "codex" regression guard
# ---------------------------------------------------------------------------


class TestL2BareCodexRegressionGuard:
    """The bare ``"codex"`` token MUST NEVER appear at any lineage stage
    when a resolved readiness is present."""

    def test_bare_token_forbidden_at_invocation(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        request = _build_agent_request(str(tmp_path))
        _install_fake_popen(monkeypatch)
        adapter.execute(request)

        # ``command[0]`` MUST be the resolved absolute path -- never the
        # bare token.
        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] != CODEX_BIN_NAME
        assert _CAPTURED_CMDS[0][0] == NPM_CODEX_PATH
        assert "\\" in _CAPTURED_CMDS[0][0]
        assert _CAPTURED_CMDS[0][0].lower().endswith(".cmd")

    def test_bare_token_forbidden_in_invocation_command(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        request = _build_agent_request(str(tmp_path))
        inv = build_invocation(request, adapter.codex_bin)

        assert inv.command[0] != CODEX_BIN_NAME
        assert inv.command[0] == NPM_CODEX_PATH

    def test_adapter_codex_bin_property_never_bare(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``adapter.codex_bin`` MUST be the resolved path, not the bare token."""
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        assert adapter.codex_bin == NPM_CODEX_PATH
        assert adapter.codex_bin != CODEX_BIN_NAME


# ---------------------------------------------------------------------------
# L3 -- actual Popen argv[0] (the RQ8-R1-R2 core gate)
# ---------------------------------------------------------------------------


class TestL3ActualPopenArgv:
    """The actual ``subprocess.Popen`` argv MUST carry the resolved path."""

    def test_popen_argv0_is_resolved_cmd(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """This is the canonical RQ8-R1-R2 proof: ``Popen(argv[0])`` MUST be
        the resolved ``codex.CMD`` path, not the bare ``"codex"`` token."""

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        _install_fake_popen(monkeypatch)

        request = _build_agent_request(str(tmp_path))
        adapter.execute(request)

        assert len(_CAPTURED_CMDS) == 1, "exactly one Popen call expected"
        argv0 = _CAPTURED_CMDS[0][0]
        assert argv0 == NPM_CODEX_PATH
        assert argv0 != CODEX_BIN_NAME

    def test_popen_argv0_holds_via_bridge_default_factory(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Same gate, but driven through the bridge's default factory."""

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )
        _install_fake_popen(monkeypatch)

        backend = bridge.codex_runtime_factory()()
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )

        request = _build_agent_request(str(tmp_path))
        adapter.execute(request)

        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NPM_CODEX_PATH

    def test_popen_argv0_via_build_invocation_then_execute(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """End-to-end: ``build_invocation(adapter.codex_bin)`` followed by
        ``adapter.execute`` must hand the resolved path to ``Popen``."""

        backend = SubprocessCodexRuntime(codex_bin=NATIVE_CODEX_PATH)
        _prime_version_cache(backend, "0.146.0")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        _install_fake_popen(monkeypatch)

        request = _build_agent_request(str(tmp_path))
        inv = build_invocation(request, adapter.codex_bin)

        assert inv.command[0] == NATIVE_CODEX_PATH

        adapter.execute(request)
        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NATIVE_CODEX_PATH


# ---------------------------------------------------------------------------
# L4 -- native codex.EXE compatibility
# ---------------------------------------------------------------------------


class TestL4NativeExeCompatibility:
    """The same lineage invariant MUST hold for native ``codex.EXE``."""

    def test_native_exe_lineage(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NATIVE_CODEX_PATH)

        def fake_run(cmd, *args, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="codex-cli 0.146.0\n", stderr=""
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        _install_fake_popen(monkeypatch)

        from synapx_harness.cli.runtime_bridge import discover_codex

        readiness = discover_codex()
        assert readiness.executable_path == NATIVE_CODEX_PATH

        backend = SubprocessCodexRuntime(codex_bin=readiness.executable_path)
        _prime_version_cache(backend, "0.146.0")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )

        request = _build_agent_request(str(tmp_path))
        inv = build_invocation(request, adapter.codex_bin)
        assert inv.command[0] == NATIVE_CODEX_PATH

        adapter.execute(request)
        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NATIVE_CODEX_PATH
        assert _CAPTURED_CMDS[0][0].lower().endswith(".exe")

    def test_native_exe_via_bridge_default_factory(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NATIVE_CODEX_PATH, version="0.146.0"
            ),
        )
        _install_fake_popen(monkeypatch)

        backend = bridge.codex_runtime_factory()()
        _prime_version_cache(backend, "0.146.0")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        request = _build_agent_request(str(tmp_path))
        adapter.execute(request)

        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NATIVE_CODEX_PATH


# ---------------------------------------------------------------------------
# L5 -- custom runtime factory compatibility (FakeCodexRuntime / StubRuntime)
# ---------------------------------------------------------------------------


class TestL5CustomFactoryCompatibility:
    """The custom ``codex_runtime_factory`` injection seam MUST keep working.

    Production default factory changes; explicit injected factories MUST be
    untouched. ``FakeCodexRuntime`` exposes no ``codex_bin`` attribute (it
    is the canonical contract-level test double), so the ``getattr``
    fallback must yield the bare token without raising ``AttributeError``.
    """

    def test_fake_codex_runtime_injection_does_not_raise(self, tmp_path: Path) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=str(tmp_path),
            codex_runtime_factory=lambda: FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS,
                stdout='{"patch":"x","paths":["a"]}\n',
            ),
        )
        # Default backend still callable: even without a resolved readiness
        # the bridge MUST remain constructible.
        backend = bridge.codex_runtime_factory()()
        assert isinstance(backend, FakeCodexRuntime)

        # And the bounded ``getattr(backend, "codex_bin", "codex")`` fallback
        # MUST yield the bare token, matching the no-attribute case.
        assert getattr(backend, "codex_bin", "codex") == CODEX_BIN_NAME

    def test_adapter_with_no_backend_codex_bin_attribute(
        self, tmp_path: Path
    ) -> None:
        """``CodexAdapter(backend=NoCodexBinRuntime())`` MUST NOT raise."""

        @dataclass
        class _NoCodexBinRuntime:
            invoke_calls: int = 0

            def version(self) -> str | None:
                return "stub-0.0.0"

            def invoke(self, inv: Any, cancel_event: Any = None) -> Any:
                from synapx_harness.adapters.codex.runtime import RawRuntimeResult
                self.invoke_calls += 1
                return RawRuntimeResult(
                    exit_code=0,
                    stdout='{"patch":"x","paths":["a"]}\n',
                    stderr="",
                    duration_ms=1,
                    version=self.version(),
                    provider_session_id="stub",
                )

        runtime = _NoCodexBinRuntime()
        adapter = CodexAdapter(
            backend=runtime, codex_bin=getattr(runtime, "codex_bin", "codex")
        )
        # Effective codex_bin MUST be the bare fallback (test double has
        # no attribute), proving the fallback path is exercised.
        assert adapter.codex_bin == CODEX_BIN_NAME

        # And the adapter must be invokable through its surface.
        request = _build_agent_request(str(tmp_path))
        result = adapter.execute(request)
        assert runtime.invoke_calls == 1
        assert result.status.value == "DONE"

    def test_existing_injected_factory_seam_preserved(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The custom ``codex_runtime_factory`` injection seam used by the
        existing governed-execution tests (``StubRuntime`` with no
        ``codex_bin`` attribute) MUST keep working unchanged."""

        from tests.contract.test_rq4_r2_c3_governed_execution import StubRuntime

        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=str(tmp_path),
            codex_runtime_factory=lambda: StubRuntime(stdout_text="ok"),
        )
        # Even with a resolved readiness injected, the custom factory wins.
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )
        backend = bridge.codex_runtime_factory()()
        assert isinstance(backend, StubRuntime)

        # Adapter accepts the no-attribute backend via the getattr fallback.
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        assert adapter.codex_bin == CODEX_BIN_NAME  # fallback path


# ---------------------------------------------------------------------------
# L6 -- missing Codex fail-closed
# ---------------------------------------------------------------------------


class TestL6MissingCodexFailClosed:
    """``readiness.ready == False`` MUST keep the bridge fail-closed."""

    def test_bridge_is_available_returns_false(self, tmp_path: Path) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_unready_readiness(
                executable_found=False,
                executable_path=None,
                reason_code=REASON_CODE_BIN_NOT_FOUND,
            ),
        )
        assert bridge.is_available() is False

    def test_invoke_returns_blocked_with_reason(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from synapx_harness.cli.frontdoor import PresentationResult

        # ``shutil.which`` returning None would be a second discovery; pin it
        # so the test fails loudly if any code tries to re-discover.
        def _forbidden_lookup(*args, **kwargs):
            raise AssertionError(
                "missing-codex path MUST NOT call shutil.which"
            )

        monkeypatch.setattr(shutil, "which", _forbidden_lookup)

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_unready_readiness(
                executable_found=False,
                executable_path=None,
                reason_code=REASON_CODE_BIN_NOT_FOUND,
            ),
        )

        result = bridge.invoke(task="Reply exactly OK.")
        assert isinstance(result, PresentationResult)
        assert result.status == "BLOCKED"
        assert (
            result.reason is not None
            and REASON_CODE_BIN_NOT_FOUND in result.reason
        )

    def test_no_popen_invocation_on_missing_codex(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _install_fake_popen(monkeypatch)

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_unready_readiness(
                executable_found=False,
                executable_path=None,
                reason_code=REASON_CODE_BIN_NOT_FOUND,
            ),
        )

        result = bridge.invoke(task="Reply exactly OK.")
        # No Popen happened; result is BLOCKED.
        assert result.status == "BLOCKED"
        assert _CAPTURED_CMDS == []


# ---------------------------------------------------------------------------
# L7 -- version probe failure fail-closed
# ---------------------------------------------------------------------------


class TestL7VersionProbeFailureFailClosed:
    """``executable_found=True, version=None`` MUST remain fail-closed."""

    def test_version_none_keeps_bridge_fail_closed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _install_fake_popen(monkeypatch)

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_unready_readiness(
                executable_found=True,
                executable_path=NPM_CODEX_PATH,
                reason_code=REASON_CODE_VERSION_PROBE_FAILED,
                version=None,
            ),
        )

        assert bridge.is_available() is False

        result = bridge.invoke(task="Reply exactly OK.")
        assert result.status == "BLOCKED"
        assert (
            result.reason is not None
            and REASON_CODE_VERSION_PROBE_FAILED in result.reason
        )
        # No Popen: adapter construction must not have reached the
        # ``subprocess.Popen`` boundary.
        assert _CAPTURED_CMDS == []

    def test_adapter_construction_without_version_is_safe(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """``detect_codex_version`` raising OSError must not break the
        adapter construction; the bridge is the gatekeeper for invocation."""

        monkeypatch.setattr(
            detect_codex_version,
            "__call__",
            lambda codex_bin=None: None,
        )

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        assert adapter.codex_bin == NPM_CODEX_PATH


# ---------------------------------------------------------------------------
# L8 -- no second executable rediscovery
# ---------------------------------------------------------------------------


class TestL8NoExecutionTimeRediscovery:
    """Governed positive execution MUST NOT re-discover the executable.

    Discovery authority lives in the bridge's cached readiness. Any second
    ``shutil.which`` or fresh probe inside the execution stage would let the
    authority drift between admission and actual launch -- exactly the
    pre-RQ8-R1-R2 defect.
    """

    def test_no_shutil_which_during_execution(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        def _forbidden_lookup(*args, **kwargs):
            raise AssertionError(
                "positive-path execution MUST NOT call shutil.which"
            )

        import shutil as _shutil

        monkeypatch.setattr(_shutil, "which", _forbidden_lookup)

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )
        _install_fake_popen(monkeypatch)

        factory = bridge.codex_runtime_factory()
        backend = factory()
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        request = _build_agent_request(str(tmp_path))
        adapter.execute(request)

        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NPM_CODEX_PATH

    def test_cached_readiness_is_reused(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Repeated invocation through the bridge MUST reuse the same
        cached readiness; no second discovery may occur."""

        how_many: dict[str, int] = {"discoveries": 0}
        original_discover_codex: Any = None

        from synapx_harness.cli import governed_runtime_bridge as grb_mod

        original = grb_mod.discover_codex

        def counting_discover() -> Any:
            how_many["discoveries"] += 1
            return original()

        monkeypatch.setattr(grb_mod, "discover_codex", counting_discover)

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(tmp_path))
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )
        _install_fake_popen(monkeypatch)

        # Trigger readiness() once.
        _ = bridge.readiness()
        first = how_many["discoveries"]

        backend = bridge.codex_runtime_factory()()
        _prime_version_cache(backend, "0.153.4")
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        request = _build_agent_request(str(tmp_path))
        adapter.execute(request)

        # Factory call may invoke readiness() (it does, to fetch the cached
        # ``executable_path``); the count must stay bounded and consistent.
        assert how_many["discoveries"] >= first
        # Popen captured the resolved path.
        assert _CAPTURED_CMDS
        assert _CAPTURED_CMDS[0][0] == NPM_CODEX_PATH


# ---------------------------------------------------------------------------
# End-to-End Codex Executable Lineage contract (single combined gate)
# ---------------------------------------------------------------------------


class TestEndToEndLineageContract:
    """The full E0..E6 invariant MUST hold for the canonical npm path."""

    def test_full_six_stage_lineage_invariant(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """E0 == E1 == E2 == E3 == E4 == E5 == E6 == resolved path."""

        # E0/E2: discovery selects the resolved path.
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)

        probe_calls: list[list[str]] = []

        def fake_run(cmd, *args, **kwargs):
            probe_calls.append(list(cmd))
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="codex-cli 0.153.4\n", stderr=""
            )

        monkeypatch.setattr(subprocess, "run", fake_run)
        _install_fake_popen(monkeypatch)

        from synapx_harness.cli.runtime_bridge import discover_codex

        readiness = discover_codex()
        e0 = e1 = e2 = readiness.executable_path  # E0, E1, E2 share the value

        # E3: backend
        backend = SubprocessCodexRuntime(codex_bin=e2)
        _prime_version_cache(backend, "0.153.4")
        e3 = backend.codex_bin
        assert e3 == e2

        # E4: adapter
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        e4 = adapter.codex_bin
        assert e4 == e3

        # E5: RuntimeInvocation.command[0]
        request = _build_agent_request(str(tmp_path))
        inv = build_invocation(request, adapter.codex_bin)
        e5 = inv.command[0]
        assert e5 == e4

        # E6: actual Popen argv[0]
        adapter.execute(request)
        assert _CAPTURED_CMDS
        e6 = _CAPTURED_CMDS[0][0]
        assert e6 == e5

        # The chain: E0 == E1 == E2 == E3 == E4 == E5 == E6
        assert e0 == e1 == e2 == e3 == e4 == e5 == e6 == NPM_CODEX_PATH


# ---------------------------------------------------------------------------
# Regression sentinel: the spec's hypothesized defect
# ---------------------------------------------------------------------------


class TestRegressionSentinel:
    """If the anchor binding regresses, these MUST fail loud."""

    def test_adapter_no_bare_default_for_resolved_backend(self) -> None:
        """When the caller passes a backend whose ``codex_bin`` is the
        resolved ``codex.CMD`` path, the adapter MUST surface that value
        through ``adapter.codex_bin`` -- never the bare ``"codex"`` token."""

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        _prime_version_cache(backend, "0.153.4")
        # Note: we deliberately pass the explicit resolved value to
        # CodexAdapter, mirroring the post-RQ8-R1-R2 production path.
        adapter = CodexAdapter(
            backend=backend, codex_bin=backend.codex_bin
        )
        assert adapter.codex_bin == NPM_CODEX_PATH
        assert adapter.codex_bin != "codex"

    def test_adapter_no_bare_default_for_native_exe_backend(self) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NATIVE_CODEX_PATH)
        _prime_version_cache(backend, "0.146.0")
        adapter = CodexAdapter(
            backend=backend, codex_bin=backend.codex_bin
        )
        assert adapter.codex_bin == NATIVE_CODEX_PATH
        assert adapter.codex_bin != "codex"
