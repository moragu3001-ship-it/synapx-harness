"""RQ8 Phase 2C generic agent-activity contract tests (Path B).

Path B (``B_GENERIC_FALLBACK``) shows only the bounded invoke lifecycle
(Running / Completed / Failed) that the Front Door actually observed.
Every assertion targets lifecycle presence / lifecycle absence / authority
separation / ordering. Cosmetic layout is never contracted.

Boundaries guarded here:

*  No fake timeline: without structured provider evidence, no stage prose
   (inspecting / planning / editing / testing) may appear.
*  No assurance authority: activity lines never carry verification, scope,
   evidence, mutation, or terminal claims and never change them.
*  No terminal authority: ``Completed`` activity never implies ``VERIFIED``;
   ``VERIFIED`` still appears only for a ``COMPLETED`` presentation.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest
import typer

import synapx_harness.cli.frontdoor as _fd
from synapx_harness.cli.agent_activity import (
    AgentActivityPresentation,
    activity_for_presentation_status,
    render_activity_lines,
    running_activity,
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

FORBIDDEN_TIMELINE_PHRASES: tuple[str, ...] = (
    "Inspecting repository",
    "Understanding code",
    "Planning fix",
    "Editing file",
    "Running tests",
    "Reviewing changes",
)

FORBIDDEN_AUTHORITY_FIELDS: tuple[str, ...] = (
    "verified",
    "scope_authorized",
    "evidence_valid",
    "terminal_decision",
    "mutation_authorized",
)


class _StubRuntime:
    """Minimal ``RuntimePort`` double returning a preset presentation."""

    def __init__(self, result: PresentationResult) -> None:
        self._result = result
        self.invoke_calls: list[str] = []

    def is_available(self) -> bool:
        return True

    def invoke(self, task: str) -> PresentationResult | None:
        self.invoke_calls.append(task)
        return self._result


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


# ---------------------------------------------------------------------------
# DTO: no authority, bounded vocabulary only
# ---------------------------------------------------------------------------


class TestActivityDtoHasNoAuthority:
    def test_fields_carry_no_authority(self) -> None:
        names = {f.name for f in dataclasses.fields(AgentActivityPresentation)}
        assert names == {"status"}
        for forbidden in FORBIDDEN_AUTHORITY_FIELDS:
            assert forbidden not in names

    def test_dto_is_immutable(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            running_activity().status = "COMPLETED"  # type: ignore[misc]

    def test_mapping_success_to_completed(self) -> None:
        assert activity_for_presentation_status("COMPLETED").status == "COMPLETED"

    def test_mapping_failure_and_block_to_failed(self) -> None:
        assert activity_for_presentation_status("FAILED").status == "FAILED"
        assert activity_for_presentation_status("BLOCKED").status == "FAILED"

    @pytest.mark.parametrize("weird", [None, "", "DONE", "done", 123, [], object()])
    def test_mapping_malformed_to_unknown(self, weird: object) -> None:
        assert activity_for_presentation_status(weird).status == "UNKNOWN"

    def test_render_vocabulary(self) -> None:
        assert render_activity_lines(running_activity()) == [
            "Agent Activity",
            "  Running...",
            "",
        ]
        assert render_activity_lines(
            AgentActivityPresentation(status="COMPLETED")
        ) == ["Agent Activity", "  Completed", ""]
        assert render_activity_lines(
            AgentActivityPresentation(status="FAILED")
        ) == ["Agent Activity", "  Failed", ""]
        assert render_activity_lines(unknown_activity()) == [
            "Agent Activity",
            "  Unavailable",
            "",
        ]

    @pytest.mark.parametrize("weird", [None, 123, "x", object()])
    def test_render_never_raises_on_malformed(self, weird: object) -> None:
        lines = render_activity_lines(weird)
        assert lines[0] == "Agent Activity"
        assert lines[1] == "  Unavailable"

    def test_no_detail_or_timeline_leak(self) -> None:
        corpus = "\n".join(
            line
            for p in (
                running_activity(),
                AgentActivityPresentation(status="COMPLETED"),
                AgentActivityPresentation(status="FAILED"),
                unknown_activity(),
            )
            for line in render_activity_lines(p)
        )
        assert "Command:" not in corpus
        assert "File activity" not in corpus
        assert "session" not in corpus.lower()
        for phrase in FORBIDDEN_TIMELINE_PHRASES:
            assert phrase not in corpus


# ---------------------------------------------------------------------------
# Front Door: invoke lifecycle projection (§28 Path B)
# ---------------------------------------------------------------------------


class TestFrontDoorActivityLifecycle:
    def test_invoke_start_renders_running(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        stub = _StubRuntime(PresentationResult("COMPLETED", None))
        run(workspace=tmp_path, task="hello", runtime=stub)
        assert stub.invoke_calls == ["hello"]
        assert "Agent Activity" in capture.err
        assert "  Running..." in capture.err

    def test_invoke_success_renders_completed_and_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        run(
            workspace=tmp_path,
            task="hello",
            runtime=_StubRuntime(PresentationResult("COMPLETED", None)),
        )
        assert "Agent Activity" in capture.out
        assert "  Completed" in capture.out
        assert "VERIFIED" in capture.out

    @pytest.mark.parametrize("status", ["FAILED", "BLOCKED"])
    def test_invoke_failure_or_block_renders_failed_without_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
    ) -> None:
        capture = _patched_echo(monkeypatch)
        with pytest.raises(typer.Exit):
            run(
                workspace=tmp_path,
                task="hello",
                runtime=_StubRuntime(PresentationResult(status, "boom")),
            )
        assert "  Failed" in capture.out
        assert "  Completed" not in capture.out
        assert "VERIFIED" not in capture.out

    def test_activity_precedes_assurance_and_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        _render_result("VERIFIED", None, _qualified_assurance(), activity_status="COMPLETED")
        text = "\n".join(capture.out)
        assert text.index("Agent Activity") < text.index("Changes")
        assert text.index("Changes") < text.index("SynapX Assurance")
        assert text.index("SynapX Assurance") < text.index("VERIFIED")
        # Phase 2B authoritative claims are unchanged beside the new section.
        assert "✓ Mutation observed" in text
        assert "✓ Scope authorized" in text
        assert "pytest -q" in text
        assert "✓ PASS" in text
        assert "✓ Qualified" in text

    def test_failed_activity_keeps_failed_terminal_without_verified(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        _render_governed_result(PresentationResult("FAILED", "boom"))
        assert "  Failed" in capture.out
        assert "FAILED" in capture.out
        assert "VERIFIED" not in capture.out

    def test_completed_activity_does_not_promote_blocked_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        _render_governed_result(PresentationResult("BLOCKED", "blocked"))
        assert "  Failed" in capture.out
        assert "VERIFIED" not in capture.out

    @pytest.mark.parametrize("status", ["COMPLETED", "FAILED", "BLOCKED"])
    def test_no_fake_timeline_in_outputs(
        self, monkeypatch: pytest.MonkeyPatch, status: str
    ) -> None:
        capture = _patched_echo(monkeypatch)
        _render_governed_result(PresentationResult(status, "reason"))
        corpus = "\n".join(capture.out) + "\n" + "\n".join(capture.err)
        for phrase in FORBIDDEN_TIMELINE_PHRASES:
            assert phrase not in corpus

    def test_console_task_then_quit_preserves_lifecycle(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capture = _patched_echo(monkeypatch)
        events = [
            ConsoleEvent(ConsoleEventKind.TASK, text="hello"),
            ConsoleEvent(ConsoleEventKind.QUIT),
        ]
        echoed: list[str] = []
        code = run_console(
            workspace=tmp_path,
            runtime=_StubRuntime(PresentationResult("COMPLETED", None)),
            read_event=lambda: events.pop(0),
            echo=lambda msg="", **kw: echoed.append(str(msg)),
        )
        assert code == 0
        assert "  Running..." in capture.err
        assert "  Completed" in capture.out
        assert "VERIFIED" in capture.out
