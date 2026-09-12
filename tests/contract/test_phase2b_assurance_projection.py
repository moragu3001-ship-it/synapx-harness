"""RQ8 Phase 2B authoritative assurance projection tests.

Semantic tests only: every assertion targets claim presence / claim
absence / source truth / terminal mapping. Cosmetic layout (spacing,
ANSI codes, box width, blank-line counts) is never contracted.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer

from synapx_harness.cli.assurance_presentation import (
    AssurancePresentation,
    build_assurance_presentation,
    render_assurance_lines,
    terminal_label,
)
from synapx_harness.cli.console import (
    ConsoleEvent,
    ConsoleEventKind,
    classify_console_line,
)
from synapx_harness.cli.frontdoor import (
    PRESENTATION_MAP,
    PresentationResult,
    _map_to_presentation,
    run,
    run_console,
)
from synapx_harness.cli.governed_runtime_bridge import (
    GovernedFrontDoorRuntimeBridge,
)
from synapx_harness.contracts.runtime_models import (
    build_execution_identity,
    build_terminal_decision,
)
from synapx_harness.evidence.command_runner import CommandResult
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    GovernedExecutionResult,
    VerificationOutcome,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_authority import (
    AdmissionReceipt,
    ApplyReceipt,
    PathGateReceipt,
)

CORE_ROOT = Path(__file__).resolve().parents[2]

_DIGITS_PASSED_RE = re.compile(r"\d+\s+passed")


def _identity(tag: str) -> Any:
    return build_execution_identity(
        job_id=f"job-{tag}",
        task_id=f"task-{tag}",
        root_task_id=f"root-{tag}",
        attempt_id=f"att-{tag}",
    )


def _command(
    sanitized: str,
    *,
    exit_code: int = 0,
    command_id: str = "cmd-1",
    gate: str = "PASS",
) -> CommandResult:
    digest = "b" * 64
    return CommandResult(
        command_id=command_id,
        sanitized_command=sanitized,
        working_directory=str(CORE_ROOT),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        exit_code=exit_code,
        stdout_path="/tmp/stdout",
        stderr_path="/tmp/stderr",
        stdout_sha256=digest,
        stderr_sha256=digest,
        stdout_size=0,
        stderr_size=0,
        gate=gate,
    )


def _verification(
    status: str,
    evidence: str,
    sanitized: str,
    *,
    exit_code: int = 0,
    command_id: str = "cmd-1",
) -> VerificationOutcome:
    return VerificationOutcome(
        verification_status=status,
        evidence_status=evidence,
        active_blocker_count=0 if status == "PASS" else 1,
        command_result=_command(sanitized, exit_code=exit_code, command_id=command_id),
        red_qualified=True,
        red_qualification_ref="red-ref",
    )


def _admission(decision: str, tag: str) -> AdmissionReceipt:
    return AdmissionReceipt(
        receipt_id=f"rct/{tag}",
        admission_decision=decision,
        work_contract_id=f"wc-{tag}",
        red_qualified=decision == "ALLOW",
        red_qualification_ref="red-ref",
        source_revision="src-1",
        execution_identity={},
        mutation_authority={},
        admitted_at="2026-01-01T00:00:00+00:00",
    )


def _path_gate(decision: str, tag: str) -> PathGateReceipt:
    return PathGateReceipt(
        gate_decision=decision,
        apply_authority="ISSUED" if decision == "ALLOW" else "NOT_ISSUED",
        proposal_sha256="p" * 64,
        canonical_patch_sha256="c" * 64,
        authorized_paths=["calc.py"],
        proposal_paths=["calc.py"],
        source_revision="src-1",
        admission_receipt_id=f"rct/{tag}",
    )


def _apply(paths: list[str], write_count: int) -> ApplyReceipt:
    return ApplyReceipt(
        applied_paths=list(paths),
        before_sha256="b" * 64,
        after_sha256="a" * 64,
        patch_sha256="p" * 64,
        canonical_patch_sha256="c" * 64,
        write_count=write_count,
        apply_started_at="2026-01-01T00:00:00+00:00",
        apply_completed_at="2026-01-01T00:00:01+00:00",
        authorization_ref="rct/x",
        admission_receipt_id="rct/x",
        path_gate_receipt_id="rct/x",
        source_revision="src-1",
    )


def _make_result(
    tag: str,
    *,
    mutation_attempted: bool = True,
    apply: ApplyReceipt | None = None,
    admission: AdmissionReceipt | None = None,
    path_gate: PathGateReceipt | None = None,
    verification: VerificationOutcome | None = None,
    verification_attempted: bool = True,
    sealed_status: str = "SEALED",
    terminal: str = "COMPLETED",
    terminal_reason: str = "all invariants satisfied",
    primary_message: str | None = None,
    errors: list[str] | None = None,
) -> GovernedExecutionResult:
    return GovernedExecutionResult(
        success=terminal == "COMPLETED",
        work_contract_id=f"wc-{tag}",
        execution_identity=_identity(tag),
        shared_understanding=cast(Any, SimpleNamespace()),
        work_contract=cast(Any, SimpleNamespace()),
        source_revision="src-1",
        agent_session_id=f"agent-{tag}",
        allowed_write_paths=["calc.py"],
        admission_receipt=admission,
        path_gate_receipt=path_gate,
        apply_receipt=apply,
        verification=verification,
        sealed_evidence={
            "integrity_status": sealed_status,
            "sealed_by": "CORE_EVIDENCE_SEALER",
        },
        terminal_decision=build_terminal_decision(
            work_contract_id=f"wc-{tag}",
            decision=terminal,
            reason=terminal_reason,
        ),
        errors=list(errors or []),
        process_started=True,
        failure_class=None,
        proposal_parsing_attempted=True,
        mutation_attempted=mutation_attempted,
        verification_attempted=verification_attempted,
        primary_failure_stage="STAGE" if primary_message else None,
        primary_failure_class="CLASS" if primary_message else None,
        primary_failure_message=primary_message,
    )


def _success_result(tag: str = "p1") -> GovernedExecutionResult:
    return _make_result(
        tag,
        mutation_attempted=True,
        apply=_apply(["calc.py"], 1),
        admission=_admission("ALLOW", tag),
        path_gate=_path_gate("ALLOW", tag),
        verification=_verification("PASS", "VALID", "uv run pytest -q"),
        verification_attempted=True,
        sealed_status="SEALED",
        terminal="COMPLETED",
        terminal_reason="all invariants satisfied",
        errors=[],
    )


def _text(result: GovernedExecutionResult) -> str:
    return "\n".join(render_assurance_lines(build_assurance_presentation(result)))


class _FakeRuntime:
    def __init__(self, result: Any) -> None:
        self._result = result
        self.tasks: list[str] = []

    def is_available(self) -> bool:
        return True

    def invoke(self, task: str) -> Any:
        self.tasks.append(task)
        return self._result


def _scripted(*items: Any) -> Any:
    queue = list(items)

    def _next() -> ConsoleEvent:
        if not queue:
            return ConsoleEvent(ConsoleEventKind.EOF)
        item = queue.pop(0)
        if isinstance(item, ConsoleEvent):
            return item
        return classify_console_line(item)

    return _next


def _passing_workspace(root: Path) -> Path:
    (root / "calc.py").write_text("x=1\n", encoding="utf-8")
    (root / "uv.lock").write_text("", encoding="utf-8")
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "test_calc.py").write_text("def test_x():\n    assert True\n", encoding="utf-8")
    return root


class TestP1FullSuccessfulAssurance:
    def test_success_projects_all_true_claims(self) -> None:
        text = _text(_success_result())
        assert "✓ Mutation observed" in text
        assert "✓ Scope authorized" in text
        assert "✓ PASS" in text
        assert "✓ Qualified" in text
        assert terminal_label(build_assurance_presentation(_success_result())) == "VERIFIED"

    def test_success_shows_file_and_command(self) -> None:
        text = _text(_success_result())
        assert "calc.py" in text
        assert "1 file changed" in text
        assert "uv run pytest -q" in text

    def test_real_governed_run_maps_completed_with_assurance(self, tmp_path: Path) -> None:
        from synapx_harness.kernel.mutation_proposal_contract import (
            PROPOSAL_BEGIN,
            PROPOSAL_END,
        )

        _passing_workspace(tmp_path)
        proposal = (
            PROPOSAL_BEGIN
            + "\nFILE: calc.py\n<<<< OLD\nx=1\n>>>> OLD\n<<<< NEW\nx=2\n>>>> NEW\n"
            + PROPOSAL_END
        )
        request = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task="Fix calc\nAllowed write paths:\n- calc.py",
            codex_stdout_override=proposal,
            verification_command=[sys.executable, "-m", "pytest", "-q"],
            red_qualified_override=True,
        )
        result = run_governed_execution(request)
        assert result.terminal_decision.decision == "COMPLETED"
        presentation = GovernedFrontDoorRuntimeBridge._map_to_presentation(result)
        assert presentation is not None
        assert presentation.status == "COMPLETED"
        assert presentation.assurance is not None
        assert isinstance(presentation.assurance, AssurancePresentation)
        text = "\n".join(
            render_assurance_lines(presentation.assurance)  # type: ignore[arg-type]
        )
        assert "✓ Mutation observed" in text
        assert "✓ Scope authorized" in text
        assert "✓ PASS" in text
        assert "✓ Qualified" in text
        assert "calc.py" in text
        assert result.verification is not None
        assert result.verification.command_result.sanitized_command in text


class TestP2ChangedFilesExactness:
    def test_two_files_projected_exactly(self) -> None:
        result = _make_result(
            "p2",
            apply=_apply(["src/a.py", "src/b.py"], 2),
            admission=_admission("ALLOW", "p2"),
            path_gate=_path_gate("ALLOW", "p2"),
            verification=_verification("PASS", "VALID", "uv run pytest -q"),
        )
        text = _text(result)
        assert "src/a.py" in text
        assert "src/b.py" in text
        assert "2 files changed" in text


class TestP3VerificationCommandExactness:
    def test_actual_command_projected_verbatim(self) -> None:
        result = _success_result("p3")
        assert result.verification is not None
        expected = result.verification.command_result.sanitized_command
        presentation = build_assurance_presentation(result)
        assert presentation.verification_command == expected
        assert expected in _text(result)


class TestP4CountsUnavailable:
    def test_counts_line_without_fabricated_numbers(self) -> None:
        text = _text(_success_result("p4"))
        assert "Test counts unavailable" in text
        assert "297 passed" not in text
        assert _DIGITS_PASSED_RE.search(text) is None


class TestN1TerminalNotCompleted:
    @pytest.mark.parametrize("terminal", ["FAILED", "BLOCKED"])
    def test_verified_absent(self, terminal: str) -> None:
        result = _make_result(
            f"n1-{terminal}",
            apply=_apply(["calc.py"], 1),
            admission=_admission("ALLOW", "n1"),
            path_gate=_path_gate("ALLOW", "n1"),
            verification=_verification("FAIL", "INVALID", "uv run pytest -q", exit_code=1),
            terminal=terminal,
            terminal_reason="verification_status=FAIL",
            errors=["verification failed"],
        )
        text = _text(result)
        assert "VERIFIED" not in text
        assert terminal_label(build_assurance_presentation(result)) != "VERIFIED"

    def test_unknown_terminal_fail_closed(self) -> None:
        presentation = build_assurance_presentation(None)
        assert terminal_label(presentation) == "NEEDS_ATTENTION"
        assert "VERIFIED" not in "\n".join(render_assurance_lines(presentation))


class TestN2VerificationFail:
    def test_pass_absent_on_fail(self) -> None:
        result = _make_result(
            "n2",
            apply=_apply(["calc.py"], 1),
            admission=_admission("ALLOW", "n2"),
            path_gate=_path_gate("ALLOW", "n2"),
            verification=_verification("FAIL", "INVALID", "uv run pytest -q", exit_code=1),
            terminal="FAILED",
            terminal_reason="verification_status=FAIL",
        )
        text = _text(result)
        assert "✓ PASS" not in text
        assert "✗ FAILED" in text


class TestN3VerificationNotRun:
    def test_pass_and_passed_absent(self) -> None:
        result = _make_result(
            "n3",
            mutation_attempted=False,
            admission=None,
            path_gate=None,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            sealed_status="ADMITTED",
            terminal="BLOCKED",
            terminal_reason="verification_status=NOT_RUN",
            errors=["task does not declare an explicit allowed write set"],
        )
        text = _text(result)
        assert "PASS" not in text
        assert "passed" not in text
        assert "verification-not-run" not in text


class TestN4MutationAbsent:
    def test_no_changed_file_claim(self) -> None:
        result = _make_result(
            "n4",
            mutation_attempted=False,
            admission=None,
            path_gate=None,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            terminal="BLOCKED",
            errors=["blocked"],
        )
        text = _text(result)
        assert "file changed" not in text
        assert "files changed" not in text
        assert "Mutation not attempted" in text


class TestN5ChangedFileSourceUnavailable:
    def test_zero_claim_forbidden(self) -> None:
        result = _make_result(
            "n5",
            mutation_attempted=True,
            apply=None,
            admission=_admission("ALLOW", "n5"),
            path_gate=None,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            terminal="BLOCKED",
            errors=["blocked"],
        )
        text = _text(result)
        assert "No files changed" not in text
        assert "Changed files unavailable" in text


class TestN6ScopePartial:
    def test_allow_without_path_gate_never_authorized(self) -> None:
        result = _make_result(
            "n6",
            mutation_attempted=False,
            admission=_admission("ALLOW", "n6"),
            path_gate=None,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            terminal="BLOCKED",
            errors=["blocked"],
        )
        text = _text(result)
        assert "Scope authorized" not in text
        assert "Scope not fully evaluated" in text


class TestN7ScopeDenyChain:
    def test_path_deny_denies_scope(self) -> None:
        result = _make_result(
            "n7",
            mutation_attempted=False,
            admission=_admission("ALLOW", "n7"),
            path_gate=_path_gate("DENY", "n7"),
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            terminal="BLOCKED",
            errors=["Admission DENIED"],
        )
        text = _text(result)
        assert "Scope denied" in text
        assert "Scope authorized" not in text


class TestN8EvidenceValidWithoutSeal:
    def test_qualified_requires_seal(self) -> None:
        result = _make_result(
            "n8",
            apply=_apply(["calc.py"], 1),
            admission=_admission("ALLOW", "n8"),
            path_gate=_path_gate("ALLOW", "n8"),
            verification=_verification("PASS", "VALID", "uv run pytest -q"),
            sealed_status="ADMITTED",
            terminal="FAILED",
            terminal_reason="evidence not sealed",
        )
        text = _text(result)
        assert "✓ Qualified" not in text
        assert "Qualification unavailable" in text


class TestN9EvidenceInvalid:
    def test_qualified_absent_on_invalid(self) -> None:
        result = _make_result(
            "n9",
            apply=_apply(["calc.py"], 1),
            admission=_admission("ALLOW", "n9"),
            path_gate=_path_gate("ALLOW", "n9"),
            verification=_verification("FAIL", "INVALID", "uv run pytest -q", exit_code=1),
            terminal="FAILED",
            terminal_reason="verification_status=FAIL",
        )
        text = _text(result)
        assert "✓ Qualified" not in text
        assert "✗ Invalid" in text


class TestN10EvidenceNotRun:
    def test_qualified_absent_on_not_run(self) -> None:
        result = _make_result(
            "n10",
            mutation_attempted=False,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            sealed_status="ADMITTED",
            terminal="BLOCKED",
            errors=["blocked"],
        )
        text = _text(result)
        assert "✓ Qualified" not in text
        assert "Qualification not run" in text


class TestN11AgentProseHasNoAuthority:
    def test_prose_tests_passed_changes_nothing(self, tmp_path: Path) -> None:
        _passing_workspace(tmp_path)
        request = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task="Fix calc\nAllowed write paths:\n- calc.py",
            codex_stdout_override="tests passed, all good! DONE",
            verification_command=[sys.executable, "-m", "pytest", "-q"],
            red_qualified_override=True,
        )
        result = run_governed_execution(request)
        text = _text(result)
        assert "✓ PASS" not in text
        assert "VERIFIED" not in text
        assert terminal_label(build_assurance_presentation(result)) != "VERIFIED"


class TestN12AgentDoneOnly:
    def test_done_string_cannot_verify(self) -> None:
        assert _map_to_presentation("COMPLETED") == "NEEDS_ATTENTION"
        assert _map_to_presentation({"decision": "COMPLETED"}) == "NEEDS_ATTENTION"
        presentation = build_assurance_presentation("DONE")
        assert terminal_label(presentation) != "VERIFIED"


class TestN13FirstFailureWins:
    def test_primary_overwrites_downstream(self) -> None:
        result = _make_result(
            "n13",
            mutation_attempted=False,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            terminal="BLOCKED",
            terminal_reason="verification_status=NOT_RUN",
            primary_message="task does not declare an explicit allowed write set",
            errors=["downstream generic"],
        )
        presentation = build_assurance_presentation(result)
        assert presentation.terminal_reason == "task does not declare an explicit allowed write set"


class TestN14ErrorsBeforeGenericReason:
    def test_errors_zero_beats_terminal_generic(self) -> None:
        result = _make_result(
            "n14",
            verification=_verification("FAIL", "INVALID", "uv run pytest -q", exit_code=1),
            terminal="FAILED",
            terminal_reason="verification_status=FAIL",
            errors=["Admission DENIED: red not qualified"],
        )
        presentation = build_assurance_presentation(result)
        assert presentation.terminal_reason == "Admission DENIED: red not qualified"


class TestN15MalformedFailClosed:
    @pytest.mark.parametrize("bad", [None, {}, "COMPLETED", 0, []])
    def test_malformed_renders_truth_preserving(self, bad: Any) -> None:
        presentation = build_assurance_presentation(bad)
        text = "\n".join(render_assurance_lines(presentation))
        assert "VERIFIED" not in text
        assert "✓ PASS" not in text
        assert "✓ Scope authorized" not in text
        assert "✓ Qualified" not in text
        assert "✓ Mutation observed" not in text
        assert terminal_label(presentation) == "NEEDS_ATTENTION"


class TestZeroVsUnknownDistinct:
    def test_authoritative_zero(self) -> None:
        result = _make_result(
            "zero",
            apply=_apply([], 0),
            admission=_admission("ALLOW", "zero"),
            path_gate=_path_gate("ALLOW", "zero"),
            verification=_verification("FAIL", "INVALID", "uv run pytest -q", exit_code=1),
            terminal="FAILED",
            terminal_reason="Apply failed",
        )
        text = _text(result)
        assert "No files changed" in text
        assert "Changed files unavailable" not in text

    def test_synthetic_command_never_visible(self) -> None:
        for sentinel in (
            "verification-not-run",
            "verification-attempted",
            "blocked-0",
        ):
            result = _make_result(
                f"syn-{sentinel}",
                mutation_attempted=False,
                verification=_verification("NOT_RUN", "NOT_RUN", sentinel, command_id="blocked-0"),
                verification_attempted=False,
                terminal="BLOCKED",
                errors=["blocked"],
            )
            assert sentinel not in _text(result)


class TestFrontDoorIntegration:
    def test_run_renders_shared_sections(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assured = PresentationResult(
            "COMPLETED", None, assurance=build_assurance_presentation(_success_result("i1"))
        )
        try:
            run(task="do work", runtime=_FakeRuntime(assured))
        except typer.Exit:
            pass
        output = capsys.readouterr().out
        assert "Changes" in output
        assert "SynapX Assurance" in output
        assert "Verification" in output
        assert "Evidence" in output
        assert "VERIFIED" in output

    def test_run_without_assurance_stays_compatible(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class LegacyRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult("COMPLETED", "done")

        try:
            run(task="do work", runtime=LegacyRuntime())
        except typer.Exit:
            pass
        output = capsys.readouterr().out
        assert "VERIFIED" in output

    def test_console_renders_same_sections(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assured = PresentationResult(
            "COMPLETED", None, assurance=build_assurance_presentation(_success_result("i2"))
        )
        code = run_console(
            workspace=tmp_path,
            runtime=_FakeRuntime(assured),
            read_event=_scripted("do work", ":quit"),
        )
        assert code == 0
        output = capsys.readouterr().out
        assert "Changes" in output
        assert "VERIFIED" in output
        assert output.count("synapx>") >= 2

    def test_failure_reason_uses_first_failure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result(
            "i3",
            mutation_attempted=False,
            verification=_verification(
                "NOT_RUN", "NOT_RUN", "verification-not-run", command_id="blocked-0"
            ),
            verification_attempted=False,
            terminal="BLOCKED",
            terminal_reason="verification_status=NOT_RUN",
            primary_message="task does not declare an explicit allowed write set",
            errors=["task does not declare an explicit allowed write set"],
        )
        assured = PresentationResult(
            "BLOCKED",
            "task does not declare an explicit allowed write set",
            assurance=build_assurance_presentation(result),
        )
        try:
            run(task="do work", runtime=_FakeRuntime(assured))
        except typer.Exit:
            pass
        output = capsys.readouterr().out + capsys.readouterr().err
        assert "NEEDS_ATTENTION" in output

    def test_display_prefers_terminal_reason_over_generic_fallback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _passing_workspace(tmp_path)
        request = GovernedExecutionRequest(
            workspace_root=tmp_path,
            task="Fix calc\nAllowed write paths:\n- calc.py",
            codex_stdout_override=(
                "--- BEGIN SYNAPX MUTATION PROPOSAL ---\n"
                "FILE: calc.py\n<<<< OLD\nx=1\n>>>> OLD\n"
                "<<<< NEW\nx=2\n>>>> NEW\n"
                "--- END SYNAPX MUTATION PROPOSAL ---"
            ),
            verification_command=[sys.executable, "-c", "import sys; sys.exit(1)"],
            red_qualified_override=True,
        )
        result = run_governed_execution(request)
        assert result.terminal_decision.decision == "FAILED"
        assured = GovernedFrontDoorRuntimeBridge._map_to_presentation(result)
        assert assured is not None
        try:
            run(task="do work", runtime=_FakeRuntime(assured))
        except typer.Exit:
            pass
        captured = capsys.readouterr()
        assert "FAILED" in captured.out
        assert "verification_status=FAIL" in captured.err
        assert "Governed execution reported FAILED" not in captured.err

    def test_presentation_map_contract_intact(self) -> None:
        assert PRESENTATION_MAP["COMPLETED"] == "VERIFIED"
        assert PRESENTATION_MAP["FAILED"] == "FAILED"
        assert PRESENTATION_MAP["BLOCKED"] == "NEEDS_ATTENTION"


class TestImportBoundary:
    def test_frontdoor_has_no_kernel_import(self) -> None:
        content = (CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py").read_text(
            encoding="utf-8"
        )
        assert "from synapx_harness.kernel" not in content
        assert "from synapx_harness.contracts.runtime_models" not in content

    def test_projection_module_has_no_kernel_import(self) -> None:
        content = (
            CORE_ROOT / "src" / "synapx_harness" / "cli" / "assurance_presentation.py"
        ).read_text(encoding="utf-8")
        assert "from synapx_harness.kernel" not in content
        assert "from synapx_harness.contracts" not in content
        assert "import subprocess" not in content
