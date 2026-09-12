"""RQ8 Phase 2A minimal interactive console contract tests (C1-C12).

The console is a presentation / input shell around the canonical governed
runtime bridge: every task is an independent ``RuntimePort.invoke`` call and
the existing terminal presentation is rendered per task. ``VERIFIED`` still
means only that the governed terminal decision was ``COMPLETED``.
"""
from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import typer

from synapx_harness.cli import frontdoor as frontdoor_module
from synapx_harness.cli.console import (
    ConsoleEvent,
    ConsoleEventKind,
    classify_console_line,
    read_line_event,
)
from synapx_harness.cli.frontdoor import PresentationResult, frontdoor, run_console

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
    """In-memory RuntimePort double backed by a queued result list."""

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


def _completed(reason: str | None = None) -> PresentationResult:
    return PresentationResult("COMPLETED", reason)


def _failed(reason: str = "boom") -> PresentationResult:
    return PresentationResult("FAILED", reason)


def _blocked(reason: str = "blocked") -> PresentationResult:
    return PresentationResult("BLOCKED", reason)


def _scripted_events(*items: Any):
    """Build an injected idle-prompt event source for run_console."""
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


class _FakeStdin:
    def __init__(self, tty: bool) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


class TestC1ConsoleEntry:
    def test_console_renders_header_and_prompt(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path, runtime=runtime, read_event=_scripted_events()
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "SynapX Harness" in output
        assert "Workspace" in output
        assert tmp_path.name in output
        assert "Agent" in output
        assert "Codex" in output
        assert "Ready" in output
        assert "synapx>" in output

    def test_no_task_performed_on_entry_without_input(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        run_console(
            workspace=tmp_path, runtime=runtime, read_event=_scripted_events()
        )
        assert runtime.tasks == []
        capsys.readouterr()


class TestC2GovernedRuntimeDispatch:
    def test_task_reaches_runtime_port(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("my task", ":quit"),
        )
        assert runtime.tasks == ["my task"]
        capsys.readouterr()

    def test_console_builds_runtime_via_canonical_builder(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from synapx_harness.cli.governed_runtime_bridge import (
            GovernedFrontDoorRuntimeBridge,
        )

        fake = _FakeRuntime([_completed()])
        seen: dict[str, Any] = {}
        real_build = frontdoor_module._build_runtime

        def _spy(workspace: Path) -> Any:
            seen["workspace"] = workspace
            return fake

        monkeypatch.setattr(frontdoor_module, "_build_runtime", _spy)
        code = run_console(
            workspace=tmp_path, read_event=_scripted_events("hi", ":quit")
        )
        assert code == 0
        assert seen["workspace"] == tmp_path
        assert fake.tasks == ["hi"]
        assert isinstance(real_build(tmp_path), GovernedFrontDoorRuntimeBridge)
        capsys.readouterr()

    def test_console_never_uses_legacy_agent_only_bridge(self) -> None:
        console_path = (
            CORE_ROOT / "src" / "synapx_harness" / "cli" / "console.py"
        )
        content = console_path.read_text(encoding="utf-8")
        assert "FrontDoorRuntimeBridge" not in content


class TestC3SuccessReturnsToPrompt:
    def test_verified_then_prompt_again(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "VERIFIED" in output
        assert output.count("synapx>") >= 2


class TestC4FailureReturnsToPrompt:
    def test_failed_then_prompt_again(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_failed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "FAILED" in output
        assert "VERIFIED" not in output
        assert output.count("synapx>") >= 2

    def test_blocked_then_prompt_again(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_blocked()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output
        assert output.count("synapx>") >= 2

    def test_none_result_then_prompt_again(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([None])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "NEEDS_ATTENTION" in output
        assert output.count("synapx>") >= 2


class TestC5TasksAreIndependent:
    def test_each_task_invokes_runtime_separately(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed(), _failed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("task A", "task B", ":quit"),
        )
        assert code == 0
        assert runtime.tasks == ["task A", "task B"]
        output = capsys.readouterr().out
        assert output.index("VERIFIED") < output.index("FAILED")


class TestC6EmptyInput:
    def test_empty_input_executes_nothing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("", "   ", ":quit"),
        )
        assert code == 0
        assert runtime.tasks == []
        output = capsys.readouterr().out
        assert "VERIFIED" not in output
        assert output.count("synapx>") >= 3


class TestC7QuitCommand:
    def test_quit_exits_zero_without_execution(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(":quit"),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()

    def test_help_renders_and_stays_in_console(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(":help", ":quit"),
        )
        assert code == 0
        assert runtime.tasks == []
        output = capsys.readouterr().out
        assert ":help" in output
        assert ":quit" in output


class TestC8InterruptAtIdle:
    def test_interrupt_event_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
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

    def test_keyboard_interrupt_maps_to_interrupt_event(self) -> None:
        def _raise() -> str | None:
            raise KeyboardInterrupt

        event = read_line_event(reader=_raise)
        assert event.kind is ConsoleEventKind.EXIT_INTERRUPT

    def test_eof_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events(None),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()


class TestC9EscapeAtIdle:
    def test_escape_token_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("\x1b"),
        )
        assert code == 0
        assert runtime.tasks == []
        capsys.readouterr()

    def test_escape_event_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([_completed()])
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

    def test_classify_escape_help_quit_unknown(self) -> None:
        assert (
            classify_console_line("\x1b").kind
            is ConsoleEventKind.EXIT_ESCAPE
        )
        assert classify_console_line(":help").kind is ConsoleEventKind.HELP
        assert classify_console_line(":quit").kind is ConsoleEventKind.QUIT
        assert classify_console_line("").kind is ConsoleEventKind.EMPTY
        assert classify_console_line("   ").kind is ConsoleEventKind.EMPTY
        assert classify_console_line(None).kind is ConsoleEventKind.EOF
        unknown = classify_console_line(":details")
        assert unknown.kind is ConsoleEventKind.UNKNOWN_COMMAND
        task = classify_console_line("Fix widgets")
        assert task.kind is ConsoleEventKind.TASK
        assert task.text == "Fix widgets"


class TestC10OneShotCompatibility:
    def test_task_option_does_not_enter_repl(self, tmp_path: Path) -> None:
        result = _run_synapx_subprocess(
            "--workspace", str(tmp_path), "--task", "hello", cwd=tmp_path
        )
        output = result.stdout + result.stderr
        assert "synapx>" not in output
        assert "NEEDS_ATTENTION" in output
        assert result.returncode == 1


class TestC11RunSubcommandCompatibility:
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


class TestC12NoFalseCompletion:
    def test_dict_result_cannot_produce_verified(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        runtime = _FakeRuntime([{"decision": "COMPLETED"}])
        code = run_console(
            workspace=tmp_path,
            runtime=runtime,
            read_event=_scripted_events("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output

    def test_console_module_has_no_terminal_authority(self) -> None:
        console_path = (
            CORE_ROOT / "src" / "synapx_harness" / "cli" / "console.py"
        )
        content = console_path.read_text(encoding="utf-8")
        assert "subprocess" not in content
        assert "shutil.which" not in content
        assert "os.system" not in content
        assert "terminal_finalizer" not in content
        assert "build_terminal_decision" not in content
        assert "from synapx_harness.kernel" not in content
        assert "from synapx_harness.contracts.runtime_models" not in content
        assert "FakeCodexRuntime" not in content


class TestC0EntryRule:
    def test_task_provided_uses_one_shot(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: dict[str, Any] = {}

        def _fake_run(
            workspace: Path | None = None,
            task: str | None = None,
            runtime: Any = None,
        ) -> None:
            calls["run"] = (workspace, task)

        def _fake_console(
            workspace: Path | None = None,
            runtime: Any = None,
            **kwargs: Any,
        ) -> int:
            calls["console"] = workspace
            return 0

        monkeypatch.setattr(frontdoor_module, "run", _fake_run)
        monkeypatch.setattr(frontdoor_module, "run_console", _fake_console)
        ctx = types.SimpleNamespace(invoked_subcommand=None)
        frontdoor(ctx, workspace=tmp_path, task="hello")  # type: ignore[arg-type]
        assert calls["run"] == (tmp_path, "hello")
        assert "console" not in calls

    def test_no_task_on_tty_enters_console(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: dict[str, Any] = {}

        def _fake_run(
            workspace: Path | None = None,
            task: str | None = None,
            runtime: Any = None,
        ) -> None:
            calls["run"] = (workspace, task)

        def _fake_console(
            workspace: Path | None = None,
            runtime: Any = None,
            **kwargs: Any,
        ) -> int:
            calls["console"] = workspace
            return 0

        monkeypatch.setattr(frontdoor_module, "run", _fake_run)
        monkeypatch.setattr(frontdoor_module, "run_console", _fake_console)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(True))
        ctx = types.SimpleNamespace(invoked_subcommand=None)
        with pytest.raises(typer.Exit) as exc_info:
            frontdoor(ctx, workspace=tmp_path, task=None)  # type: ignore[arg-type]
        assert exc_info.value.exit_code == 0
        assert calls["console"] == tmp_path
        assert "run" not in calls

    def test_no_task_off_tty_keeps_one_shot_failsafe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: dict[str, Any] = {}

        def _fake_run(
            workspace: Path | None = None,
            task: str | None = None,
            runtime: Any = None,
        ) -> None:
            calls["run"] = (workspace, task)

        def _fake_console(
            workspace: Path | None = None,
            runtime: Any = None,
            **kwargs: Any,
        ) -> int:
            calls["console"] = workspace
            return 0

        monkeypatch.setattr(frontdoor_module, "run", _fake_run)
        monkeypatch.setattr(frontdoor_module, "run_console", _fake_console)
        monkeypatch.setattr(sys, "stdin", _FakeStdin(False))
        ctx = types.SimpleNamespace(invoked_subcommand=None)
        frontdoor(ctx, workspace=tmp_path, task=None)  # type: ignore[arg-type]
        assert calls["run"] == (tmp_path, None)
        assert "console" not in calls
