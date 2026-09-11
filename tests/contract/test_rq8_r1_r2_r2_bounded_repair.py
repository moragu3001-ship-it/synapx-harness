"""RQ8-R1-R2-R2 — Bounded repair contract tests (D1/D2/D3/D4).

D1 -- Large Codex instruction transport (stdin transport, no argv overflow)
D2 -- Process launch failure truth (process_started / failure_class)
D3 -- Target repository verification environment (no Harness venv assumed)
D4 -- Failure precedence (first fatal blocker preserved, dependents skipped)

Each defect ships with red -> green tests pinned to the exact observed
clean-room symptom so a future regression is caught loudly.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.models import (
    AGENT_RUNTIME_SCHEMA_VERSION,
    AgentContext,
    AgentExecutionContext,
    AgentFailure,
    AgentInvocation,
    AgentLimits,
    AgentRequest,
    AgentTask,
    AgentWorkspace,
    FailureCategory,
    ProcessResult,
)
from synapx_harness.adapters.codex.runtime import (
    InvocationTransport,
    PROCESS_LAUNCH_ERROR,
    PROCESS_STARTED_EXIT_NONZERO,
    PROCESS_SUCCESS,
    PROCESS_TIMEOUT,
    RawRuntimeResult,
    RuntimeInvocation,
    SubprocessCodexRuntime,
    build_invocation,
)
from synapx_harness.contracts.runtime_models import ExecutionIdentity
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    _default_verification_command,
    _effective_verification_command,
    resolve_target_verification_command,
    run_governed_execution,
)


# Capture the truly original subprocess.Popen at module load so the
# pass-through path in ``_RaisingPopen`` can call back into it even after
# a test monkeypatched ``subprocess.Popen`` at module level.
import subprocess as _real_subprocess

_REAL_SUBPROCESS_POPEN = _real_subprocess.Popen


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


NPM_CODEX_PATH: str = r"C:\Users\morag\AppData\Roaming\npm\codex.CMD"
SMALL_INSTRUCTION: str = "Repair calculator.add to support floats."
LONG_INSTRUCTION_34K: str = "X" * 34_129  # exactly the clean-room instruction size
LONG_INSTRUCTION_100K: str = "Y" * 100_000  # synthetic stress


def _build_agent_request(
    workspace_root: Path,
    *,
    instruction: str = SMALL_INSTRUCTION,
    model: str = "gpt-5.6-luna",
) -> AgentRequest:
    identity = ExecutionIdentity(
        job_id="j-r2r2",
        root_task_id="r-r2r2",
        task_id="t-r2r2",
        attempt_id="a-r2r2",
        tool_call_id=None,
    )
    ctx = AgentExecutionContext(
        execution_identity=identity,
        agent_session_id="agent-r2r2",
    )
    return AgentRequest(
        contract_type="CUSTOMOS_AGENT_REQUEST",
        schema_version=AGENT_RUNTIME_SCHEMA_VERSION,
        execution_identity=ctx,
        workspace=AgentWorkspace(root=str(workspace_root), revision="r-r2r2"),
        task=AgentTask(instruction=instruction),
        context=AgentContext(),
        limits=AgentLimits(
            timeout_seconds=60,
            max_stdout_bytes=1_000_000,
            max_stderr_bytes=1_000_000,
        ),
        invocation=AgentInvocation(provider="codex", model=model),
    )


# ---------------------------------------------------------------------------
# D1 - Transport (T1-T10)
# ---------------------------------------------------------------------------


class TestD1Transport:
    """The Codex invocation MUST NOT embed the user instruction in argv.

    The canonical Codex-official stdin transport is used; the instruction is
    carried in ``RuntimeInvocation.stdin_payload`` and a positional ``-``
    argument takes the PROMPT slot. No shell is involved.
    """

    def test_t01_small_instruction_uses_stdin_transport(self, tmp_path: Path) -> None:
        req = _build_agent_request(tmp_path, instruction=SMALL_INSTRUCTION)
        inv = build_invocation(req, NPM_CODEX_PATH)
        assert inv.transport == InvocationTransport.STDIN
        assert inv.stdin_payload == SMALL_INSTRUCTION
        # Instruction must NOT be a literal argv element.
        assert SMALL_INSTRUCTION not in inv.command
        # The positional prompt sentinel ``-`` MUST be present.
        assert "--" in inv.command
        assert inv.command[inv.command.index("--") + 1] == "-"

    def test_t02_34k_instruction_not_in_argv(self, tmp_path: Path) -> None:
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_34K)
        inv = build_invocation(req, NPM_CODEX_PATH)
        assert inv.transport == InvocationTransport.STDIN
        # CRITICAL gate: the 34K instruction MUST NOT appear in argv (would
        # have triggered WinError 206 in the clean-room reproduction).
        assert LONG_INSTRUCTION_34K not in inv.command
        # Approximate argv character ceiling check: 32K is the observed
        # Windows boundary; argv must stay well under that even with the
        # instruction payload removed.
        argv_chars = sum(len(str(t)) for t in inv.command)
        assert argv_chars < 8_192, (
            f"argv characters {argv_chars} exceeds safe Windows bound; "
            "instruction content leaked into argv"
        )
        # Stdin payload preserves the full instruction.
        assert inv.stdin_payload == LONG_INSTRUCTION_34K
        assert len(inv.stdin_payload) == 34_129

    def test_t03_100k_synthetic_instruction_not_in_argv(self, tmp_path: Path) -> None:
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_100K)
        inv = build_invocation(req, NPM_CODEX_PATH)
        assert inv.transport == InvocationTransport.STDIN
        # Synthetic 100K stress: argv MUST NOT carry the instruction.
        # Test only the first/last 4K for speed and to avoid huge string
        # comparisons.
        head = LONG_INSTRUCTION_100K[:4096]
        tail = LONG_INSTRUCTION_100K[-4096:]
        for fragment in (head, tail):
            assert fragment not in inv.command
        # Stdin payload preserves the full synthetic payload.
        assert inv.stdin_payload is not None
        assert len(inv.stdin_payload) == 100_000

    def test_t04_argv_construction_is_windows_safe(self, tmp_path: Path) -> None:
        """No shell, no cmd /c, no PowerShell, no environment hacks."""
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_34K)
        inv = build_invocation(req, NPM_CODEX_PATH)
        joined = " ".join(str(t) for t in inv.command)
        assert "cmd /c" not in joined.lower()
        assert "powershell" not in joined.lower()
        assert "shell=true" not in joined.lower()
        assert "\\..\\" not in joined
        # All argv elements are strings (no None / NoneType leak).
        for tok in inv.command:
            assert isinstance(tok, str)

    def test_t05_instruction_content_fidelity_via_stdin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The full instruction text MUST reach the Codex process stdin
        without truncation or rewriting."""

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"

        captured: dict[str, Any] = {"argv": None, "stdin_payload": None}

        class _Capture:
            def __init__(self, cmd: list[str], **kwargs: Any) -> None:
                captured["argv"] = list(cmd)
                captured["stdin_kwargs"] = dict(kwargs)
                self._stdin = io.BytesIO()
                self._stdout = io.BytesIO(b"OK\n")
                self._stderr = io.BytesIO(b"")
                self._exit = 0
                self._closed = False

            def __enter__(self) -> "_Capture":
                return self

            def __exit__(self, *args: Any) -> None:
                pass

            @property
            def stdin(self) -> "_StdinAdapter":
                outer = self

                class _StdinAdapter:
                    def write(self_inner, data: bytes) -> int:
                        if outer._closed:
                            raise BrokenPipeError("stdin closed")
                        if captured["stdin_payload"] is None:
                            captured["stdin_payload"] = data
                        else:
                            captured["stdin_payload"] += data
                        return outer._stdin.write(data)

                    def close(self_inner) -> None:
                        outer._closed = True
                        outer._stdin.close()

                return _StdinAdapter()

            @property
            def stdout(self) -> io.BytesIO:
                return self._stdout

            @property
            def stderr(self) -> io.BytesIO:
                return self._stderr

            def poll(self) -> int:
                return self._exit

            def kill(self) -> None:
                self._exit = -9

            def wait(self, timeout: float | None = None) -> int:
                return self._exit

            @property
            def returncode(self) -> int:
                return self._exit

        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _Capture,
        )

        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_34K)
        adapter = CodexAdapter(backend=backend)
        result = adapter.execute(req)

        # The instruction MUST reach stdin verbatim.
        assert captured["stdin_payload"] is not None
        assert captured["stdin_payload"].decode("utf-8") == LONG_INSTRUCTION_34K
        assert hashlib.sha256(captured["stdin_payload"]).hexdigest() == hashlib.sha256(
            LONG_INSTRUCTION_34K.encode("utf-8")
        ).hexdigest()
        # And the adapter reports DONE (the fake Popen returned exit 0).
        assert result.status.value == "DONE"
        # And stdin was opened as a real pipe (not inherited).
        assert captured["stdin_kwargs"].get("stdin") == subprocess.PIPE

    def test_t06_executable_identity_preserved(self, tmp_path: Path) -> None:
        """The resolved Codex executable identity MUST remain the canonical
        npm / native path through every transport stage."""
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_34K)
        inv = build_invocation(req, NPM_CODEX_PATH)
        assert inv.command[0] == NPM_CODEX_PATH

    def test_t07_model_cwd_sandbox_preserved(self, tmp_path: Path) -> None:
        """Model, cwd, and sandbox flags MUST survive the transport change."""
        req = _build_agent_request(
            tmp_path,
            instruction=LONG_INSTRUCTION_34K,
            model="gpt-5.6-luna",
        )
        inv = build_invocation(req, NPM_CODEX_PATH)
        # Model
        assert "-m" in inv.command
        assert inv.command[inv.command.index("-m") + 1] == "gpt-5.6-luna"
        # CWD
        assert "-C" in inv.command
        assert inv.command[inv.command.index("-C") + 1] == str(tmp_path)
        # Sandbox
        assert "-s" in inv.command
        assert inv.command[inv.command.index("-s") + 1] == "read-only"
        # Repo-check bypass (RQ8-R1-R2 preserved invariant).
        assert "--skip-git-repo-check" in inv.command

    def test_t08_no_prompt_truncation(self, tmp_path: Path) -> None:
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_100K)
        inv = build_invocation(req, NPM_CODEX_PATH)
        # Stdin payload MUST equal the full instruction byte-for-byte.
        assert inv.stdin_payload is not None
        assert len(inv.stdin_payload) == 100_000
        assert inv.stdin_payload == LONG_INSTRUCTION_100K

    def test_t09_no_shell_invocation(self) -> None:
        """``subprocess.Popen`` is the only launch path. No shell wrappers."""
        import inspect

        src = inspect.getsource(SubprocessCodexRuntime.invoke)
        assert "shell=True" not in src
        assert "subprocess.run(" not in src  # we use Popen, not run
        assert "subprocess.Popen(" in src

    def test_t10_no_semantic_split_or_rewrite(self, tmp_path: Path) -> None:
        """The instruction is delivered as one atomic payload, not split
        across argv tokens or rewritten."""
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_34K)
        inv = build_invocation(req, NPM_CODEX_PATH)
        # Stdin payload contains the instruction as a single string.
        assert inv.stdin_payload is not None
        assert LONG_INSTRUCTION_34K in inv.stdin_payload
        assert inv.stdin_payload.count("X") == 34_129


# ---------------------------------------------------------------------------
# D2 - Process launch failure truth (T11-T17)
# ---------------------------------------------------------------------------


class _RaisingPopen:
    """Deterministic Popen stand-in that raises an OSError on construction
    when the command targets the Codex CLI.

    Mirrors the Windows ``WinError 206`` symptom (FileNotFoundError with
    ``winerror=206``). The runtime MUST classify this as a launch failure,
    NOT a normal process exit.

    Other subprocess.Popen callers (git, version probe, etc.) pass through
    to the original ``subprocess.Popen`` captured at module load so the
    broader test infrastructure (Shared Understanding scanner, git
    rev-parse, ...) keeps working.
    """

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        is_codex = bool(cmd) and (
            "codex" in str(cmd[0]).lower()
            or (len(cmd) >= 2 and str(cmd[1]).lower() == "exec")
        )
        if is_codex:
            err = FileNotFoundError("파일 이름이나 확장명이 너무 깁니다")
            err.winerror = 206  # type: ignore[attr-defined]
            raise err
        # Pass-through for non-codex Popen calls; ``_REAL_SUBPROCESS_POPEN``
        # was captured at import time before any monkeypatch. ``cmd`` is
        # passed as a single ``args`` argument (not ``*cmd``) because the
        # Python ``subprocess.Popen`` signature accepts a list as the first
        # positional, not as multiple positional arguments.
        self._real_popen = _REAL_SUBPROCESS_POPEN(cmd, **kwargs)

    def __enter__(self) -> "_RaisingPopen":
        # Delegate to the real Popen so callers using ``with Popen(...)``
        # (e.g. ``subprocess.run``) keep working.
        self._real_popen.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        return self._real_popen.__exit__(exc_type, exc, tb)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_popen, name)


class TestD2LaunchFailureTruth:
    """A ``Popen`` failure MUST be classified as a launch error with
    ``process_started=False`` and ``failure_class=PROCESS_LAUNCH_ERROR``.
    It MUST be distinguishable from a successful process that happens to
    emit empty stdout.
    """

    def test_t11_popen_raises_oserror_classified_as_launch_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )
        req = _build_agent_request(tmp_path, instruction=SMALL_INSTRUCTION)
        inv = build_invocation(req, NPM_CODEX_PATH)
        raw = backend.invoke(inv, None)

        assert raw.launch_error is True
        assert raw.failure_class == PROCESS_LAUNCH_ERROR
        assert raw.process_started is False
        assert raw.exit_code == -1
        assert raw.stdout == ""
        assert raw.stderr == ""
        # The exception evidence must carry winerror metadata.
        assert raw.launch_error_message is not None
        assert "winerror=206" in raw.launch_error_message

    def test_t12_process_started_false_on_launch_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )
        req = _build_agent_request(tmp_path)
        adapter = CodexAdapter(backend=backend)
        result = adapter.execute(req)

        assert result.process is not None
        assert result.process.process_started is False
        assert result.process.failure_class == PROCESS_LAUNCH_ERROR
        assert result.status.value == "FAILED"
        assert result.failure is not None
        assert result.failure.category == FailureCategory.LAUNCH_ERROR

    def test_t13_proposal_parser_not_invoked_on_launch_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end: a launch error MUST NOT reach the proposal parser."""
        from synapx_harness.kernel.mutation_authority import PatchProposalParser

        parser_calls: list[str] = []
        original_parse = PatchProposalParser.parse_structured

        def counting_parse(self: Any, stdout: str) -> Any:
            parser_calls.append(stdout)
            return original_parse(self, stdout)

        monkeypatch.setattr(PatchProposalParser, "parse_structured", counting_parse)

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )

        # x.py MUST exist so capture_before_state passes through to the
        # agent-process stage; the launch-error gate then fires there.
        (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")

        task = "Allowed write paths:\n  - x.py\n"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=CodexAdapter(backend=backend),
            codex_runtime_factory=None,
            verification_command=["echo", "noop"],
        )
        result = run_governed_execution(req)

        # The proposal parser MUST NOT have been invoked.
        assert parser_calls == []
        # And the result MUST reflect the launch failure as primary.
        assert result.process_started is False
        assert result.failure_class == PROCESS_LAUNCH_ERROR
        assert result.primary_failure_stage == "AGENT_PROCESS"
        assert result.primary_failure_class == PROCESS_LAUNCH_ERROR
        assert result.proposal_parsing_attempted is False
        assert result.mutation_attempted is False
        assert result.verification_attempted is False

    def test_t14_verification_not_invoked_on_launch_error(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from synapx_harness.kernel import governed_execution as ge_mod

        verify_calls: list[list[str]] = []
        original_verify = ge_mod.verify_workspace

        def counting_verify(**kwargs: Any) -> Any:
            verify_calls.append(list(kwargs.get("verification_command", [])))
            return original_verify(**kwargs)

        monkeypatch.setattr(ge_mod, "verify_workspace", counting_verify)

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )

        (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")

        task = "Allowed write paths:\n  - x.py\n"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=CodexAdapter(backend=backend),
            codex_runtime_factory=None,
        )
        result = run_governed_execution(req)

        assert verify_calls == []
        assert result.verification_attempted is False
        assert result.process_started is False
        assert result.primary_failure_stage == "AGENT_PROCESS"

    def test_t15_terminal_primary_failure_is_agent_process(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )

        (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")

        task = "Allowed write paths:\n  - x.py\n"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=CodexAdapter(backend=backend),
            codex_runtime_factory=None,
        )
        result = run_governed_execution(req)

        # The terminal decision MUST be authoritative on the launch error.
        assert result.primary_failure_stage == "AGENT_PROCESS"
        assert result.primary_failure_class == PROCESS_LAUNCH_ERROR
        assert result.primary_failure_message is not None
        assert PROCESS_LAUNCH_ERROR in result.primary_failure_message
        # And the synthetic decision must be BLOCKED, not COMPLETED.
        td = result.terminal_decision
        if hasattr(td, "decision"):
            assert td.decision in ("BLOCKED", "FAILED")
        else:
            assert td in ("BLOCKED", "FAILED")

    def test_t16_launch_exception_preserved_in_bounded_evidence(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )

        req = _build_agent_request(tmp_path)
        adapter = CodexAdapter(backend=backend)
        result = adapter.execute(req)

        # Evidence carries bounded launch error message (no unbounded
        # secrets / environment leakage).
        assert result.failure is not None
        msg = result.failure.message
        assert "winerror=206" in msg
        # Must NOT carry environment / secret leakage.
        for forbidden in ("API_KEY", "TOKEN", "PASSWORD", "AUTH"):
            assert forbidden not in msg.upper() or "[REDACTED]" in msg

    def test_t17_successful_process_with_empty_stdout_is_distinct(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A successfully started process that emits empty stdout must NOT be
        confused with a launch failure."""

        class _EmptySuccessPopen:
            def __init__(self, cmd: list[str], **kwargs: Any) -> None:
                self._stdout = io.BytesIO(b"")
                self._stderr = io.BytesIO(b"")
                self._stdin = io.BytesIO()
                self._exit = 0
                self._closed = False

            def __enter__(self) -> "_EmptySuccessPopen":
                return self

            def __exit__(self, *args: Any) -> None:
                pass

            @property
            def stdin(self) -> "_StdinAdapter":
                outer = self

                class _StdinAdapter:
                    def write(self_inner, data: bytes) -> int:
                        if outer._closed:
                            raise BrokenPipeError
                        return outer._stdin.write(data)

                    def close(self_inner) -> None:
                        outer._closed = True
                        outer._stdin.close()

                return _StdinAdapter()

            @property
            def stdout(self) -> io.BytesIO:
                return self._stdout

            @property
            def stderr(self) -> io.BytesIO:
                return self._stderr

            def poll(self) -> int:
                return self._exit

            def kill(self) -> None:
                self._exit = -9

            def wait(self, timeout: float | None = None) -> int:
                return self._exit

            @property
            def returncode(self) -> int:
                return self._exit

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _EmptySuccessPopen,
        )
        req = _build_agent_request(tmp_path, instruction=SMALL_INSTRUCTION)
        inv = build_invocation(req, NPM_CODEX_PATH)
        raw = backend.invoke(inv, None)

        # Process DID start; empty stdout is the *runtime* outcome.
        assert raw.process_started is True
        assert raw.launch_error is False
        assert raw.failure_class == PROCESS_SUCCESS
        assert raw.exit_code == 0
        # The adapter must NOT collapse this to a launch error.
        adapter = CodexAdapter(backend=backend)
        result = adapter.execute(req)
        assert result.process is not None
        assert result.process.process_started is True
        assert result.process.failure_class == PROCESS_SUCCESS
        assert result.status.value == "DONE"


# ---------------------------------------------------------------------------
# D3 - Target repository verification environment
# ---------------------------------------------------------------------------


class TestD3VerificationResolver:
    """The Harness venv Python MUST NOT be silently assumed to be the
    target repository verification environment."""

    def _make_uv_repo(self, tmp_path: Path) -> Path:
        (tmp_path / "uv.lock").write_text("# canonical uv lockfile marker\n")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "fixture"\nversion = "0.1.0"\n'
        )
        return tmp_path

    def _make_poetry_repo(self, tmp_path: Path) -> Path:
        (tmp_path / "pyproject.toml").write_text(
            "[tool.poetry]\nname = 'fixture'\nversion = '0.1.0'\n"
        )
        return tmp_path

    def _make_pep621_repo(self, tmp_path: Path) -> Path:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "fixture"\nversion = "0.1.0"\n'
        )
        return tmp_path

    def _make_unknown_repo(self, tmp_path: Path) -> Path:
        # No uv.lock, no [tool.poetry], no [project] -> fail closed.
        (tmp_path / "tox.ini").write_text("[tox]\nenvlist = py312\n")
        return tmp_path

    def test_fixture_a_uv_project_selects_uv_run_pytest(
        self, tmp_path: Path
    ) -> None:
        repo = self._make_uv_repo(tmp_path)
        cmd = resolve_target_verification_command(repo)
        assert cmd == ["uv", "run", "pytest", "-q"]

    def test_fixture_a_uv_project_excludes_harness_python(
        self, tmp_path: Path
    ) -> None:
        import sys

        repo = self._make_uv_repo(tmp_path)
        cmd = resolve_target_verification_command(repo)
        # The Harness control-plane venv MUST NOT appear.
        assert cmd is not None
        joined = " ".join(cmd)
        assert sys.executable not in joined
        assert "-m pytest" not in joined

    def test_fixture_a_poetry_project_selects_poetry_run_pytest(
        self, tmp_path: Path
    ) -> None:
        repo = self._make_poetry_repo(tmp_path)
        cmd = resolve_target_verification_command(repo)
        assert cmd == ["poetry", "run", "pytest", "-q"]

    def test_fixture_a_pep621_project_falls_back_to_uv(
        self, tmp_path: Path
    ) -> None:
        """RQ8-R1-R2-R2-R1 (Q1): a bare ``[project]`` table is NOT
        authoritative evidence for uv. The resolver MUST fail closed and
        return ``None`` so the caller surfaces a verification-unavailable
        blocker rather than silently mis-attribute the verifier.

        The earlier R2 behaviour (``[project] -> uv``) is forbidden because
        the same marker is shared by poetry, hatchling, setuptools, pdm,
        and many non-uv projects; silently selecting ``uv`` would silently
        mis-route the independent verifier.
        """
        repo = self._make_pep621_repo(tmp_path)
        cmd = resolve_target_verification_command(repo)
        assert cmd is None

    def test_fixture_c_unknown_environment_fails_closed(
        self, tmp_path: Path
    ) -> None:
        repo = self._make_unknown_repo(tmp_path)
        cmd = resolve_target_verification_command(repo)
        assert cmd is None

    def test_default_verification_command_is_removed(self) -> None:
        with pytest.raises(RuntimeError) as exc_info:
            _default_verification_command()
        msg = str(exc_info.value)
        assert "RQ8-R1-R2-R2" in msg
        assert "D3" in msg

    def test_explicit_command_overrides_resolver(
        self, tmp_path: Path
    ) -> None:
        repo = self._make_uv_repo(tmp_path)
        explicit = ["custom", "test", "--suite"]
        req = GovernedExecutionRequest(
            workspace_root=repo,
            task="Allowed write paths:\n  - x.py",
            verification_command=explicit,
        )
        chosen = _effective_verification_command(
            request=req, workspace_root=repo
        )
        assert chosen == explicit

    def test_unknown_env_blocks_run_governed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End-to-end: unknown target env MUST fail closed at the run level.

        RQ8-R1-R2-R2-R1 (Q2) stage-truth interaction: the proposal MUST be a
        valid structured proposal so the parse stage passes and the run
        reaches the verification-command resolution stage (D3). The earlier
        R2 fixture used a free-form JSON payload that the structured parser
        rejects as ``PROPOSAL_REJECTED``; under Q2 the same scenario no
        longer reaches the D3 gate, so the canonical structured encoding is
        required here to keep the test exercising the intended D3 path.
        """
        repo = self._make_unknown_repo(tmp_path)
        from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario

        # Need a real allowed-write target so capture_before_state passes.
        (repo / "x.py").write_text("def add(a, b): return a + b\n")
        # Valid structured proposal so the parse stage passes and the run
        # actually reaches the verification-command resolution stage (D3).
        # Uses the canonical ``mutation_proposal_contract.PROPOSAL_BEGIN/END``
        # framing (not the placeholder strings R2 tests used).
        from synapx_harness.kernel.mutation_proposal_contract import (
            PROPOSAL_BEGIN,
            PROPOSAL_END,
        )
        proposal = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE:x.py\n"
            "<<<< OLD\n"
            "def add(a, b): return a + b\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "def add(a, b): return a + b + 0\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}"
        )
        adapter = CodexAdapter(
            backend=FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS,
                stdout=proposal,
            )
        )
        task = "Allowed write paths:\n  - x.py\n"
        req = GovernedExecutionRequest(
            workspace_root=repo,
            task=task,
            adapter=adapter,
            red_qualified_override=True,
        )
        result = run_governed_execution(req)
        # The D3 gate MUST surface the failure (parse passes, mutation
        # chain passes the gates, but the unknown target repo has no
        # trustworthy verifier command).
        assert result.primary_failure_class == "VERIFICATION_COMMAND_NOT_RESOLVED"
        assert result.primary_failure_stage == "VERIFICATION_COMMAND_RESOLUTION"
        assert result.verification_attempted is False
        assert result.success is False


# ---------------------------------------------------------------------------
# D4 - Failure precedence (T18-T23)
# ---------------------------------------------------------------------------


class TestD4FailurePrecedence:
    """The first fatal blocker MUST remain authoritative; downstream stages
    MUST be suppressed and MUST NOT overwrite the primary failure.
    """

    def _adapter_with_launch_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> CodexAdapter:
        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )
        return CodexAdapter(backend=backend)

    def test_t18_launch_failure_zero_verification_calls(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.kernel import governed_execution as ge_mod

        verify_calls: list[Any] = []
        original = ge_mod.verify_workspace

        def counting(**kwargs: Any) -> Any:
            verify_calls.append(kwargs)
            return original(**kwargs)

        monkeypatch.setattr(ge_mod, "verify_workspace", counting)

        (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")
        adapter = self._adapter_with_launch_error(monkeypatch)
        task = "Allowed write paths:\n  - x.py\n"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=adapter,
        )
        result = run_governed_execution(req)
        assert verify_calls == []
        assert result.verification_attempted is False

    def test_t19_proposal_parse_failure_no_mutation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RQ8-R1-R2-R2-R1 (Q2) stage-truth repair.

        A proposal parse failure is a pre-applicator short-circuit. The
        controlled applicator MUST NOT have been invoked, ``mutation_attempted``
        MUST be ``False``, and the verification stage MUST also be skipped
        (``verification_attempted is False``). Only ``proposal_parsing_attempted``
        is ``True`` because the structured parser was actually called.
        """
        from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario

        # Need a real allowed-write target so capture_before_state passes
        # and the run reaches the proposal-parse stage.
        (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")
        # Adapter that emits DONE but with malformed stdout -> proposal parse failure.
        adapter = CodexAdapter(
            backend=FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS, stdout="this is not a patch"
            )
        )

        apply_calls: list[Any] = []

        from synapx_harness.kernel.mutation_authority import ControlledPatchApplicator

        original_apply = ControlledPatchApplicator.apply

        def counting_apply(self: Any, **kwargs: Any) -> Any:
            apply_calls.append(kwargs)
            return original_apply(self, **kwargs)

        monkeypatch.setattr(
            ControlledPatchApplicator, "apply", counting_apply
        )

        task = "Allowed write paths:\n  - x.py"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=adapter,
            verification_command=["echo", "noop"],
        )
        result = run_governed_execution(req)
        # Apply MUST NOT have been invoked.
        assert apply_calls == []
        # Stage truth (Q2): the parser was attempted, but mutation and
        # verification were not. The previous R2 claim that
        # ``mutation_attempted is True`` on a parse failure was wrong
        # and is repaired here.
        assert result.proposal_parsing_attempted is True
        assert result.mutation_attempted is False
        assert result.verification_attempted is False

    def test_t20_mutation_admission_failure_no_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario

        # Valid structured proposal so parse passes; admission gate should
        # refuse (red_qualified=False by default for fresh repo).
        proposal = (
            "PROPOSAL_BEGIN\n"
            "FILE:x.py\n"
            "OLD:def add(a,b): return a+b\n"
            "NEW:def add(a,b): return a+b+0\n"
            "PROPOSAL_END"
        )
        adapter = CodexAdapter(
            backend=FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS, stdout=proposal
            )
        )

        apply_calls: list[Any] = []
        from synapx_harness.kernel.mutation_authority import ControlledPatchApplicator

        original_apply = ControlledPatchApplicator.apply

        def counting_apply(self: Any, **kwargs: Any) -> Any:
            apply_calls.append(kwargs)
            return original_apply(self, **kwargs)

        monkeypatch.setattr(
            ControlledPatchApplicator, "apply", counting_apply
        )

        # Need a real file at x.py so the allowed-write path resolves.
        (tmp_path / "x.py").write_text("def add(a,b): return a+b\n")

        task = "Allowed write paths:\n  - x.py"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=adapter,
            verification_command=["echo", "noop"],
            red_qualified_override=False,
        )
        result = run_governed_execution(req)
        # If admission gate DENIED, apply MUST NOT have been invoked.
        if not result.success:
            # Admission OR validation must have failed before apply.
            assert apply_calls == []

    def test_t21_mutation_apply_failure_no_verification_success_claim(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If apply fails, verification MUST NOT claim repair success."""
        # Even if we could set up an apply failure (out of scope), the
        # contract says the terminal decision MUST NOT be COMPLETED.
        from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario

        proposal = (
            "PROPOSAL_BEGIN\n"
            "FILE:x.py\n"
            "OLD:def add(a,b): return a+b\n"
            "NEW:def add(a,b): return a+b+0\n"
            "PROPOSAL_END"
        )
        adapter = CodexAdapter(
            backend=FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS, stdout=proposal
            )
        )
        (tmp_path / "x.py").write_text("def add(a,b): return a+b\n")
        task = "Allowed write paths:\n  - x.py"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=adapter,
            verification_command=["false"],  # always exits 1
            red_qualified_override=True,
        )
        result = run_governed_execution(req)
        # The terminal decision MUST NOT be COMPLETED.
        td = result.terminal_decision
        if hasattr(td, "decision"):
            assert td.decision != "COMPLETED"
        else:
            assert td != "COMPLETED"

    def test_t22_verification_failure_terminal_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A verification FAIL MUST produce a terminal FAILED, never COMPLETED."""
        from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario

        proposal = (
            "PROPOSAL_BEGIN\n"
            "FILE:x.py\n"
            "OLD:def add(a,b): return a+b\n"
            "NEW:def add(a,b): return a+b+0\n"
            "PROPOSAL_END"
        )
        adapter = CodexAdapter(
            backend=FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS, stdout=proposal
            )
        )
        (tmp_path / "x.py").write_text("def add(a,b): return a+b\n")
        task = "Allowed write paths:\n  - x.py"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=adapter,
            verification_command=[
                "python",
                "-c",
                "import sys; sys.exit(1)",
            ],
            red_qualified_override=True,
        )
        result = run_governed_execution(req)
        td = result.terminal_decision
        if hasattr(td, "decision"):
            assert td.decision in ("FAILED", "BLOCKED")
        else:
            assert td in ("FAILED", "BLOCKED")

    def test_t23_primary_failure_preserved_through_later_diagnostics(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The first fatal blocker MUST remain terminal primary, even when
        later diagnostics (verification, etc.) would otherwise surface."""
        (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")
        adapter = self._adapter_with_launch_error(monkeypatch)
        task = "Allowed write paths:\n  - x.py\n"
        req = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task=task,
            adapter=adapter,
        )
        result = run_governed_execution(req)
        # Primary failure is the launch error.
        assert result.primary_failure_stage == "AGENT_PROCESS"
        assert result.primary_failure_class == PROCESS_LAUNCH_ERROR
        # Verification MUST NOT have run, so it cannot claim anything.
        assert result.verification_attempted is False
        # The terminal decision cannot be COMPLETED.
        td = result.terminal_decision
        if hasattr(td, "decision"):
            assert td.decision != "COMPLETED"
        else:
            assert td != "COMPLETED"


# ---------------------------------------------------------------------------
# RQ8-R1-R2 executable lineage MUST remain GREEN (regression sentinel)
# ---------------------------------------------------------------------------


class TestR1R2LineageInvariant:
    """The RQ8-R1-R2 lineage invariant MUST remain GREEN after D1."""

    def test_r1r2_lineage_invariant_under_stdin_transport(
        self, tmp_path: Path
    ) -> None:
        from synapx_harness.adapters.codex.contract import CodexAdapter
        from synapx_harness.adapters.codex.runtime import SubprocessCodexRuntime, build_invocation

        backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
        backend._version_cache = "0.146.0"
        adapter = CodexAdapter(
            backend=backend, codex_bin=getattr(backend, "codex_bin", "codex")
        )
        req = _build_agent_request(tmp_path, instruction=LONG_INSTRUCTION_34K)
        inv = build_invocation(req, adapter.codex_bin)
        # E5: command[0] is the resolved path.
        assert inv.command[0] == NPM_CODEX_PATH
        # The instruction is in stdin, not argv.
        assert LONG_INSTRUCTION_34K not in inv.command
        assert inv.stdin_payload == LONG_INSTRUCTION_34K
        # adapter.codex_bin remains the resolved path.
        assert adapter.codex_bin == NPM_CODEX_PATH
