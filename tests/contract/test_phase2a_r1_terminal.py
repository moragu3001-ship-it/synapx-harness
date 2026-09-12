"""RQ8 Phase 2A-R1 terminal-input repair contract tests (R1-T1..R1-T8).

Covers the key-aware idle-prompt backend: standalone ESC exits with no
Enter required, idle Ctrl+C exits gracefully, and leaving the console
never rewrites prior terminal results. Existing C0-C12 contracts in
``test_phase2a_console.py`` are preserved unchanged.
"""
from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from synapx_harness.cli import terminal_input as terminal_input_module
from synapx_harness.cli.console import (
    ConsoleEvent,
    ConsoleEventKind,
    classify_console_line,
)
from synapx_harness.cli.frontdoor import PresentationResult, run_console
from synapx_harness.cli.terminal_input import (
    build_key_bindings,
    create_terminal_reader,
    is_key_aware_available,
    read_terminal_event,
)

CORE_ROOT = Path(__file__).resolve().parents[2]

_NO_CODEX_PATH = (
    f"{os.path.dirname(sys.executable)}"
    + os.pathsep
    + "C:\\Windows\\System32"
    + os.pathsep
    + "C:\\Windows"
)


def _run_synapx_subprocess(
    *args: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    full_env = dict(os.environ)
    full_env["PATH"] = _NO_CODEX_PATH
    return subprocess.run(
        [sys.executable, "-m", "synapx_harness.cli.frontdoor", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or CORE_ROOT),
        check=False,
        env=full_env,
    )


class _FakeRuntime:
    def __init__(self, results: list[Any]) -> None:
        self._results = list(results)
        self.tasks: list[str] = []

    def is_available(self) -> bool:
        return True

    def invoke(self, task: str) -> Any:
        self.tasks.append(task)
        if len(self._results) > 1:
            return self._results.pop(0)
        return self._results[0]


def _scripted_events(*items: Any):
    queue = list(items)

    def _next() -> ConsoleEvent:
        if not queue:
            return ConsoleEvent(ConsoleEventKind.EOF)
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        if isinstance(item, ConsoleEvent):
            return item
        return classify_console_line(item)

    return _next


def _pipe_event(text: str) -> ConsoleEvent:
    from prompt_toolkit.input.defaults import create_pipe_input
    from prompt_toolkit.output.base import DummyOutput

    with create_pipe_input() as pipe:
        pipe.send_text(text)
        return read_terminal_event(app_input=pipe, app_output=DummyOutput())


class TestR1T1StandaloneEscape:
    def test_escape_event_exits_immediately(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE)
            ),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()

    def test_escape_binding_is_registered(self) -> None:
        from prompt_toolkit.keys import Keys

        bindings = build_key_bindings()
        assert any(Keys.Escape in binding.keys for binding in bindings.bindings)

    def test_escape_handler_exits_without_raising(self) -> None:
        from prompt_toolkit.keys import Keys

        from synapx_harness.cli.terminal_input import EXIT_ESCAPE_SENTINEL

        bindings = build_key_bindings()
        binding = next(
            b for b in bindings.bindings if Keys.Escape in b.keys
        )
        seen: dict[str, Any] = {}

        class _StubApp:
            def exit(self, result: Any = None) -> None:
                seen["result"] = result

        event = types.SimpleNamespace(app=_StubApp())
        binding.handler(event)
        assert seen["result"] is EXIT_ESCAPE_SENTINEL

    def test_escape_token_line_still_exits(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("\x1b"),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()


class TestR1T2InterruptExitsGracefully:
    def test_interrupt_event_exits_zero_without_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT)
            ),
        )
        assert code == 0
        assert runtime.tasks == []
        captured = capsys.readouterr()
        assert "Traceback" not in captured.out + captured.err

    def test_ctrl_c_key_maps_to_interrupt_event(self) -> None:
        event = _pipe_event("\x03")
        assert event.kind is ConsoleEventKind.EXIT_INTERRUPT

    def test_eof_key_maps_to_eof_event(self) -> None:
        event = _pipe_event("\x04")
        assert event.kind is ConsoleEventKind.EOF

    def test_headless_line_maps_to_task_event(self) -> None:
        event = _pipe_event("polish widgets\r")
        assert event.kind is ConsoleEventKind.TASK
        assert event.text == "polish widgets"


class TestR1T3EscapeAfterCompletedTask:
    def test_escape_after_verified_returns_shell_semantics(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                "ship it",
                ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE),
            ),
        )
        assert code == 0
        assert runtime.tasks == ["ship it"]
        output = capsys.readouterr().out
        assert "VERIFIED" in output


class TestR1T4InterruptAfterFailure:
    def test_interrupt_after_failed_task(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("FAILED", "red")])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                "ship it",
                ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT),
            ),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "FAILED" in output
        assert "VERIFIED" not in output

    def test_interrupt_after_blocked_task(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("BLOCKED", "stuck")])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                "ship it",
                ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT),
            ),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output


class TestR1T5ExitNeverRewritesTerminalResult:
    def test_quit_freezes_invocation_count(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime(
            [
                PresentationResult("COMPLETED", None),
                PresentationResult("FAILED", "red"),
            ]
        )
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("task A", "task B", ":quit"),
        )
        assert code == 0
        assert runtime.tasks == ["task A", "task B"]
        output = capsys.readouterr().out
        assert "VERIFIED" in output
        assert "FAILED" in output

    def test_escape_freezes_invocation_count(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                "task A",
                ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE),
            ),
        )
        assert code == 0
        assert runtime.tasks == ["task A"]
        output = capsys.readouterr().out
        assert "VERIFIED" in output


class TestR1T6OneShotRemains:
    def test_task_option_does_not_enter_repl(self, tmp_path: Path) -> None:
        result = _run_synapx_subprocess(
            "--workspace", str(tmp_path), "--task", "hello", cwd=tmp_path
        )
        output = result.stdout + result.stderr
        assert "synapx>" not in output
        assert "NEEDS_ATTENTION" in output
        assert result.returncode == 1


class TestR1T7RunUnchanged:
    def test_run_help_still_available(self, tmp_path: Path) -> None:
        result = _run_synapx_subprocess("run", "--help", cwd=tmp_path)
        assert result.returncode == 0

    def test_run_without_task_still_rejected(self, tmp_path: Path) -> None:
        result = _run_synapx_subprocess(
            "run", "--workspace", str(tmp_path), cwd=tmp_path
        )
        output = result.stdout + result.stderr
        assert result.returncode == 1
        assert "NEEDS_ATTENTION" in output
        assert "--task is required" in output


class TestR1T8AgentDoneAloneCannotVerify:
    def test_unknown_done_status_maps_to_attention(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("DONE", "agent done")])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output

    def test_input_modules_hold_no_execution_authority(self) -> None:
        for name in ("console.py", "terminal_input.py"):
            path = CORE_ROOT / "src" / "synapx_harness" / "cli" / name
            content = path.read_text(encoding="utf-8")
            assert "from synapx_harness.kernel" not in content
            assert "terminal_finalizer" not in content
            assert "build_terminal_decision" not in content
            assert "from synapx_harness.contracts.runtime_models" not in content
            assert "FakeCodexRuntime" not in content


class TestR1BackendSeam:
    def test_key_aware_unavailable_off_tty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _NoTty:
            def isatty(self) -> bool:
                return False

        monkeypatch.setattr(sys, "stdin", _NoTty())
        assert is_key_aware_available() is False

    def test_key_aware_available_on_tty_with_library(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Tty:
            def isatty(self) -> bool:
                return True

        monkeypatch.setattr(sys, "stdin", _Tty())
        assert is_key_aware_available() is True

    def test_fallback_reader_echoes_prompt_and_reads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def _fake_echo(message: object = "", **kwargs: Any) -> None:
            seen["prompt"] = message

        monkeypatch.setattr(
            terminal_input_module, "is_key_aware_available", lambda: False
        )
        monkeypatch.setattr(
            terminal_input_module,
            "read_line_event",
            lambda: ConsoleEvent(ConsoleEventKind.QUIT),
        )
        reader = create_terminal_reader("synapx> ", _fake_echo)
        event = reader()
        assert seen["prompt"] == "synapx> "
        assert event.kind is ConsoleEventKind.QUIT


class _StubApp:
    """Minimal ``event.app`` double capturing ``exit(result=...)``."""

    def __init__(self) -> None:
        self.result: Any = None
        self.calls = 0

    def exit(self, result: Any = None) -> None:
        self.calls += 1
        self.result = result


class _StubSession:
    """``PromptSession`` double returning a fixed ``prompt()`` result."""

    def __init__(self, result: Any) -> None:
        self._result = result

    def prompt(self) -> Any:
        return self._result


class TestR2T1EscapeHandlerNeverRaises:
    def test_no_exception_escapes_escape_callback(self) -> None:
        from prompt_toolkit.keys import Keys

        from synapx_harness.cli.terminal_input import EXIT_ESCAPE_SENTINEL

        bindings = build_key_bindings()
        binding = next(
            b for b in bindings.bindings if Keys.Escape in b.keys
        )
        app = _StubApp()
        binding.handler(types.SimpleNamespace(app=app))
        assert app.calls == 1
        assert app.result is EXIT_ESCAPE_SENTINEL

    def test_no_exception_escapes_interrupt_callback(self) -> None:
        from prompt_toolkit.keys import Keys

        from synapx_harness.cli.terminal_input import EXIT_INTERRUPT_SENTINEL

        bindings = build_key_bindings()
        binding = next(
            b for b in bindings.bindings if Keys.ControlC in b.keys
        )
        app = _StubApp()
        binding.handler(types.SimpleNamespace(app=app))
        assert app.calls == 1
        assert app.result is EXIT_INTERRUPT_SENTINEL

    def test_forbidden_exception_pattern_absent_from_source(self) -> None:
        path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "terminal_input.py"
        content = path.read_text(encoding="utf-8")
        assert "_EscapePressed" not in content
        assert "raise _EscapePressed" not in content
        assert "Unhandled exception in event loop" not in content
        assert "Press ENTER to continue" not in content


class TestR2T2EscapeReturnsNormalizedExit:
    def test_sentinel_result_maps_to_escape_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.cli.terminal_input import EXIT_ESCAPE_SENTINEL

        monkeypatch.setattr(
            terminal_input_module,
            "_build_session",
            lambda *args, **kwargs: _StubSession(EXIT_ESCAPE_SENTINEL),
        )
        event = read_terminal_event()
        assert event.kind is ConsoleEventKind.EXIT_ESCAPE


class TestR2T3InterruptReturnsNormalizedExit:
    def test_sentinel_result_maps_to_interrupt_event(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.cli.terminal_input import EXIT_INTERRUPT_SENTINEL

        monkeypatch.setattr(
            terminal_input_module,
            "_build_session",
            lambda *args, **kwargs: _StubSession(EXIT_INTERRUPT_SENTINEL),
        )
        event = read_terminal_event()
        assert event.kind is ConsoleEventKind.EXIT_INTERRUPT


class TestR2T4EscapeTerminatesLoop:
    def test_loop_returns_with_invoke_count_unchanged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE)
            ),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()


class TestR2T5InterruptTerminatesLoop:
    def test_loop_returns_with_invoke_count_unchanged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT)
            ),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()


class TestR2T6NoPostExitTaskConsumption:
    def test_no_further_reads_after_exit(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """R2 incident regression: after EXIT the loop must be gone.

        Historical failure: the console looked dead but stayed alive and
        consumed later shell input as agent tasks. A reader that counts
        its own polls proves the loop performs exactly one read before
        terminating — no later input can ever reach ``runtime.invoke``.
        """
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        polls = 0

        def _reader() -> ConsoleEvent:
            nonlocal polls
            polls += 1
            return ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE)

        code = run_console(
            workspace=tmp_path, runtime=runtime, read_event=_reader
        )
        assert code == 0
        assert polls == 1
        assert runtime.tasks == []
        output = capsys.readouterr().out
        assert "Unhandled exception in event loop" not in output
        assert "Press ENTER to continue" not in output
        assert output.count("synapx>") == 1


class TestR2T7NormalTaskRemainsFunctional:
    def test_task_dispatches_and_returns_to_prompt(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("repair the widget", ":quit"),
        )
        assert code == 0
        assert runtime.tasks == ["repair the widget"]
        output = capsys.readouterr().out
        assert "VERIFIED" in output
        assert output.count("synapx>") >= 2


class TestR2T8QuitUnchanged:
    def test_quit_exits_zero_without_execution(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("COMPLETED", None)])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(":quit"),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()


class TestR2T9OneShotUnchanged:
    def test_task_option_does_not_enter_repl(self, tmp_path: Path) -> None:
        result = _run_synapx_subprocess(
            "--workspace", str(tmp_path), "--task", "hello", cwd=tmp_path
        )
        output = result.stdout + result.stderr
        assert "synapx>" not in output
        assert "NEEDS_ATTENTION" in output
        assert result.returncode == 1


class TestR2T10FalseVerifiedRegression:
    def test_done_status_with_exit_never_verifies(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([PresentationResult("DONE", "agent done")])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(
                "do work",
                ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE),
            ),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output
