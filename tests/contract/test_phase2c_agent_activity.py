"""RQ8 Phase 2C-R1 agent-truth activity contract tests.

Agent Activity describes the AGENT lifecycle projection from EXISTING
agent signals only. It NEVER renames the Harness terminal state:

*  N1  admission block before any agent start -> no Running/Completed/
   Failed claim (``Not run``).
*  N2  agent DONE + verification FAIL -> ``Completed`` beside ``FAILED``.
*  N3  agent DONE + terminal BLOCKED -> ``Completed`` beside ``BLOCKED``.
*  N4  terminal COMPLETED without agent source -> ``Unavailable`` (never
   an inferred ``Completed``).
*  P1  agent DONE + terminal COMPLETED -> ``Completed`` with ``VERIFIED``.

All governed scenarios use explicit test seams (``codex_stdout_override``,
``red_qualified_override``, ``verification_command``); no live Codex
binary is required.
"""

from __future__ import annotations

import dataclasses
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import typer

import synapx_harness.cli.frontdoor as _fd
from synapx_harness.cli.agent_activity import (
    AGENT_PROCESS_STAGE,
    AgentActivityPresentation,
    AgentActivitySource,
    activity_for_agent_source,
    render_activity_lines,
    source_from_result,
    unknown_activity,
)
from synapx_harness.cli.assurance_presentation import AssurancePresentation
from synapx_harness.cli.console import ConsoleEvent, ConsoleEventKind
from synapx_harness.cli.frontdoor import (
    PresentationResult,
    _render_governed_result,
    _render_result,
    run,
    run_console,
)
from synapx_harness.cli.governed_runtime_bridge import (
    GovernedFrontDoorRuntimeBridge,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)

FORBIDDEN_TIMELINE_PHRASES: tuple[str, ...] = (
    "Inspecting repository",
    "Understanding code",
    "Planning fix",
    "Editing file",
    "Running tests",
    "Reviewing changes",
    "Running...",
)

FORBIDDEN_AUTHORITY_FIELDS: tuple[str, ...] = (
    "verified",
    "scope_authorized",
    "evidence_valid",
    "terminal_decision",
    "mutation_authorized",
    "terminal_status",
)

TASK_TEXT = "Allowed write paths:\n- calculator.py\n\nAdd subtract(a, b).\n"
TASK_NO_WRITE_SET = "Describe in one sentence what you see in the workspace."


def _write_calc_fixture(root: Path) -> Path:
    repo = root / "fixture"
    repo.mkdir(exist_ok=True)
    (repo / "calculator.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
    )
    tests_dir = repo / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_calculator.py").write_text(
        textwrap.dedent(
            """\
            import calculator


            def test_add():
                assert calculator.add(2, 3) == 5


            def test_subtract():
                assert calculator.subtract(5, 3) == 2
            """
        ),
        encoding="utf-8",
    )
    return repo


def _proposal_text(file_path: str, old: str, new: str) -> str:
    return (
        f"{PROPOSAL_BEGIN}\n"
        f"FILE: {file_path}\n"
        f"<<<< OLD\n"
        f"{old}\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"{new}\n"
        f">>>> NEW\n"
        f"{PROPOSAL_END}\n"
    )


def _valid_proposal(fixture: Path) -> str:
    current = (fixture / "calculator.py").read_text(encoding="utf-8")
    replacement = current + "\n\ndef subtract(a, b):\n    return a - b\n"
    return _proposal_text("calculator.py", current, replacement)


def _bridge(fixture: Path) -> GovernedFrontDoorRuntimeBridge:
    return GovernedFrontDoorRuntimeBridge(workspace_root=str(fixture))


class _EchoCapture:
    """Capture ``typer.echo`` traffic split by stdout / stderr."""

    def __init__(self) -> None:
        self.out: list[str] = []
        self.err: list[str] = []

    def __call__(self, msg: object = "", **kw: Any) -> None:
        if kw.get("err"):
            self.err.append(str(msg))
        else:
            self.out.append(str(msg))


def _patched_echo(monkeypatch: pytest.MonkeyPatch) -> _EchoCapture:
    capture = _EchoCapture()
    monkeypatch.setattr(_fd.typer, "echo", capture)
    return capture


def _qualified_assurance() -> AssurancePresentation:
    return AssurancePresentation(
        mutation_state="OBSERVED",
        changed_files=("calculator.py",),
        changed_file_count=1,
        changed_files_state="AVAILABLE",
        scope_state="AUTHORIZED",
        verification_attempted=True,
        verification_command="pytest -q",
        verification_state="PASS",
        test_counts_state="UNAVAILABLE",
        evidence_state="QUALIFIED",
        terminal_state="COMPLETED",
        terminal_reason="ok",
    )


def _done_source() -> AgentActivitySource:
    return AgentActivitySource(
        process_started=True,
        failure_class="PROCESS_SUCCESS",
        exit_code=0,
        primary_failure_stage=None,
        stdout_present=True,
    )


# ---------------------------------------------------------------------------
# Mapping units: agent signals only, terminal never an input
# ---------------------------------------------------------------------------


class TestAgentTruthMapping:
    def test_done_triple_maps_to_completed(self) -> None:
        assert activity_for_agent_source(_done_source()).status == "COMPLETED"

    def test_agent_stage_failure_overrides_process_success(self) -> None:
        # Adapter-level FAILED with a successful process triple (e.g. an
        # unconfirmed cancellation) surfaces as primary_failure_stage
        # AGENT_PROCESS: the agent did NOT complete.
        source = AgentActivitySource(
            process_started=True,
            failure_class="PROCESS_SUCCESS",
            exit_code=0,
            primary_failure_stage=AGENT_PROCESS_STAGE,
            stdout_present=True,
        )
        assert activity_for_agent_source(source).status == "FAILED"

    @pytest.mark.parametrize(
        "failure_class,exit_code",
        [
            ("PROCESS_STARTED_EXIT_NONZERO", 1),
            ("PROCESS_TIMEOUT", -1),
            (None, 3),
        ],
    )
    def test_started_non_success_maps_to_failed(
        self, failure_class: str | None, exit_code: int
    ) -> None:
        source = AgentActivitySource(
            process_started=True,
            failure_class=failure_class,
            exit_code=exit_code,
            primary_failure_stage=AGENT_PROCESS_STAGE,
            stdout_present=True,
        )
        assert activity_for_agent_source(source).status == "FAILED"

    def test_started_without_outcome_evidence_is_unavailable(self) -> None:
        source = AgentActivitySource(
            process_started=True,
            failure_class=None,
            exit_code=None,
            primary_failure_stage=None,
            stdout_present=False,
        )
        assert activity_for_agent_source(source).status == "UNKNOWN"

    def test_unstarted_without_evidence_is_not_run(self) -> None:
        source = AgentActivitySource(
            process_started=False,
            failure_class=None,
            exit_code=None,
            primary_failure_stage=None,
            stdout_present=False,
        )
        assert activity_for_agent_source(source).status == "NOT_RUN"

    def test_launch_error_is_failed(self) -> None:
        source = AgentActivitySource(
            process_started=False,
            failure_class="PROCESS_LAUNCH_ERROR",
            exit_code=-1,
            primary_failure_stage=AGENT_PROCESS_STAGE,
            stdout_present=False,
        )
        assert activity_for_agent_source(source).status == "FAILED"

    def test_contradictory_signals_are_unavailable(self) -> None:
        # Unstarted flag combined with post-invoke evidence must NOT be
        # resolved by inference.
        source = AgentActivitySource(
            process_started=False,
            failure_class=None,
            exit_code=0,
            primary_failure_stage=None,
            stdout_present=True,
        )
        assert activity_for_agent_source(source).status == "UNKNOWN"

    @pytest.mark.parametrize(
        "source",
        [None, "x", 123, object(), AgentActivitySource()],
    )
    def test_missing_source_is_unavailable(self, source: object) -> None:
        assert (
            activity_for_agent_source(source).status == "UNKNOWN"  # type: ignore[arg-type]
        )

    def test_non_bool_process_started_is_unavailable(self) -> None:
        source = AgentActivitySource(process_started="yes")  # type: ignore[arg-type]
        assert activity_for_agent_source(source).status == "UNKNOWN"

    def test_terminal_decision_decoy_is_ignored(self) -> None:
        class Decoy:
            terminal_decision = "COMPLETED"
            verification = "PASS"

        assert source_from_result(Decoy()) is None
        assert source_from_result(None) is None
        assert source_from_result("COMPLETED") is None

    def test_source_snapshot_reads_existing_fields(self) -> None:
        class Result:
            process_started = True
            failure_class = "PROCESS_SUCCESS"
            codex_process_exit_code = 0
            primary_failure_stage = None
            agent_stdout_sha256 = "ab" * 32

        source = source_from_result(Result())
        assert source is not None
        assert activity_for_agent_source(source).status == "COMPLETED"

    def test_render_vocabulary_has_no_running(self) -> None:
        assert render_activity_lines(
            AgentActivityPresentation(status="COMPLETED")
        ) == ["Agent Activity", "  Completed", ""]
        assert render_activity_lines(
            AgentActivityPresentation(status="FAILED")
        ) == ["Agent Activity", "  Failed", ""]
        assert render_activity_lines(
            AgentActivityPresentation(status="NOT_RUN")
        ) == ["Agent Activity", "  Not run", ""]
        assert render_activity_lines(unknown_activity()) == [
            "Agent Activity",
            "  Unavailable",
            "",
        ]

    def test_no_detail_or_timeline_leak(self) -> None:
        corpus = "\n".join(
            line
            for status in ("COMPLETED", "FAILED", "NOT_RUN", "UNKNOWN")
            for line in render_activity_lines(
                AgentActivityPresentation(status=status)  # type: ignore[arg-type]
            )
        )
        assert "Command:" not in corpus
        assert "File activity" not in corpus
        assert "session" not in corpus.lower()
        for phrase in FORBIDDEN_TIMELINE_PHRASES:
            assert phrase not in corpus

    def test_dto_carries_no_authority(self) -> None:
        for cls in (AgentActivityPresentation, AgentActivitySource):
            names = {f.name for f in dataclasses.fields(cls)}
            for forbidden in FORBIDDEN_AUTHORITY_FIELDS:
                assert forbidden not in names
        with pytest.raises(dataclasses.FrozenInstanceError):
            _done_source().exit_code = 0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# N1 -- admission block before any agent start
# ---------------------------------------------------------------------------


class TestN1AdmissionBlockBeforeAgent:
    def test_no_agent_claim_without_start_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        presentation = _bridge(tmp_path).invoke_governed(task=TASK_NO_WRITE_SET)
        assert presentation is not None
        assert presentation.status == "BLOCKED"
        label = _render_governed_result(presentation)
        assert label == "NEEDS_ATTENTION"
        assert "  Not run" in capture.out
        for claim in ("Running", "  Completed", "  Failed"):
            assert claim not in capture.out
            assert claim not in capture.err
        assert "VERIFIED" not in capture.out


# ---------------------------------------------------------------------------
# N2 -- agent DONE + verification FAIL coexist
# ---------------------------------------------------------------------------


class TestN2AgentDoneVerificationFail:
    def test_completed_beside_failed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        capture = _patched_echo(monkeypatch)
        presentation = _bridge(fixture).invoke_governed(
            task=TASK_TEXT,
            codex_stdout_override=_valid_proposal(fixture),
            red_qualified_override=True,
            verification_command=[
                sys.executable,
                "-c",
                "import sys; sys.exit(1)",
            ],
        )
        assert presentation is not None
        assert presentation.status == "FAILED"
        # The agent source proves completion independently of the terminal.
        assert presentation.agent is not None
        assert presentation.agent.process_started is True
        label = _render_governed_result(presentation)
        assert label == "FAILED"
        assert "  Completed" in capture.out
        assert "  Failed" not in capture.out
        assert "VERIFIED" not in capture.out
        assert "  ✗ FAILED" in capture.out


# ---------------------------------------------------------------------------
# N3 -- agent DONE + terminal BLOCKED coexist
# ---------------------------------------------------------------------------


class TestN3AgentDoneTerminalBlocked:
    def test_completed_beside_blocked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        capture = _patched_echo(monkeypatch)
        presentation = _bridge(fixture).invoke_governed(
            task=TASK_TEXT,
            codex_stdout_override=_valid_proposal(fixture),
            red_qualified_override=False,
        )
        assert presentation is not None
        assert presentation.status == "BLOCKED"
        assert presentation.agent is not None
        assert presentation.agent.process_started is True
        label = _render_governed_result(presentation)
        assert label == "NEEDS_ATTENTION"
        assert "  Completed" in capture.out
        assert "  Failed" not in capture.out
        assert "VERIFIED" not in capture.out


# ---------------------------------------------------------------------------
# N4 -- terminal COMPLETED without agent source
# ---------------------------------------------------------------------------


class TestN4TerminalCompletedWithoutAgentSource:
    def test_no_inferred_completed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        label = _render_governed_result(
            PresentationResult("COMPLETED", None, assurance=_qualified_assurance())
        )
        assert label == "VERIFIED"
        assert "  Unavailable" in capture.out
        assert "  Completed" not in capture.out
        # Phase 2B authoritative claims are unchanged beside the section.
        text = "\n".join(capture.out)
        assert text.index("Agent Activity") < text.index("Changes")
        assert "✓ Mutation observed" in text
        assert "✓ PASS" in text


# ---------------------------------------------------------------------------
# P1 -- agent DONE + terminal COMPLETED
# ---------------------------------------------------------------------------


class TestP1AgentDoneTerminalCompleted:
    def test_completed_with_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        capture = _patched_echo(monkeypatch)
        presentation = _bridge(fixture).invoke_governed(
            task=TASK_TEXT,
            codex_stdout_override=_valid_proposal(fixture),
            red_qualified_override=True,
            verification_command=[
                sys.executable,
                "-c",
                "import sys; sys.exit(0)",
            ],
        )
        assert presentation is not None
        assert presentation.status == "COMPLETED"
        label = _render_governed_result(presentation)
        assert label == "VERIFIED"
        assert "  Completed" in capture.out


# ---------------------------------------------------------------------------
# Front Door wiring: agent slot only, terminal never consulted
# ---------------------------------------------------------------------------


class TestFrontDoorAgentWiring:
    def test_run_completed_agent_beside_failed_terminal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.cli.frontdoor import RuntimePort

        class Stub(RuntimePort):
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult | None:
                return PresentationResult(
                    "FAILED", "boom", agent=_done_source()
                )

        capture = _patched_echo(monkeypatch)
        with pytest.raises(typer.Exit):
            run(workspace=tmp_path, task="hello", runtime=Stub())
        assert "  Completed" in capture.out
        assert "  Failed" not in capture.out
        assert "FAILED" in capture.out
        assert "VERIFIED" not in capture.out

    def test_run_without_agent_source_is_unavailable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.cli.frontdoor import RuntimePort

        class Stub(RuntimePort):
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult | None:
                return PresentationResult("COMPLETED", None)

        capture = _patched_echo(monkeypatch)
        run(workspace=tmp_path, task="hello", runtime=Stub())
        assert "  Unavailable" in capture.out
        assert "  Completed" not in capture.out
        assert "VERIFIED" in capture.out

    def test_no_fake_timeline_in_outputs(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        _render_result(
            "VERIFIED", None, _qualified_assurance(), agent=_done_source()
        )
        _render_governed_result(PresentationResult("FAILED", "boom"))
        corpus = "\n".join(capture.out) + "\n" + "\n".join(capture.err)
        for phrase in FORBIDDEN_TIMELINE_PHRASES:
            assert phrase not in corpus

    def test_console_task_then_quit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from synapx_harness.cli.frontdoor import RuntimePort

        class Stub(RuntimePort):
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult | None:
                return PresentationResult(
                    "COMPLETED", None, agent=_done_source()
                )

        capture = _patched_echo(monkeypatch)
        events = [
            ConsoleEvent(ConsoleEventKind.TASK, text="hello"),
            ConsoleEvent(ConsoleEventKind.QUIT),
        ]
        echoed: list[str] = []
        code = run_console(
            workspace=tmp_path,
            runtime=Stub(),
            read_event=lambda: events.pop(0),
            echo=lambda msg="", **kw: echoed.append(str(msg)),
        )
        assert code == 0
        assert "  Completed" in capture.out
        assert "VERIFIED" in capture.out
