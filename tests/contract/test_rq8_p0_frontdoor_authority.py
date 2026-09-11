"""RQ8-P0 Front Door authority convergence contract tests.

Release blocker repair for ``FRONTDOOR_FALSE_VERIFIED``: the default
``synapx`` entry previously mapped agent ``DONE`` to ``VERIFIED`` without
entering governed execution, verification, evidence, or the terminal
authority. After convergence both public entries
(``synapx`` and ``synapx run``) drive the canonical governed execution
and ``VERIFIED`` is rendered only for a terminal ``COMPLETED`` decision.

Negative contracts (must never emit ``VERIFIED``):

    N1  agent DONE without mutation
    N2  verification FAIL after mutation
    N3  verification never entered
    N4  fake successful agent claim (prose, no verifier receipt)
    N5  terminal authority bypass (agent claim / foreign issuer)

Positive contract: qualified RED -> proposal -> admission ALLOW ->
path gate ALLOW -> mutation -> independent verification PASS ->
evidence VALID -> terminal COMPLETED -> ``VERIFIED`` + exit 0.

Entry equivalence: ``synapx`` and ``synapx run`` produce equivalent
terminal semantics (label + exit code) for the same runtime outcome.

All governed runs use explicit test seams (``codex_stdout_override``,
``red_qualified_override``, ``verification_command``); no live Codex
binary is required.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from synapx_harness.cli import frontdoor
from synapx_harness.cli.frontdoor import PresentationResult
from synapx_harness.cli.governed_runtime_bridge import (
    GovernedFrontDoorRuntimeBridge,
)
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)
from synapx_harness.kernel.terminal_finalizer import (
    FORBIDDEN_TERMINAL_ISSUERS,
    TERMINAL_FINALIZER_ISSUER,
    TerminalDecision,
    finalize_from_agent_done,
    issue_terminal_decision,
)

TASK_TEXT = "Allowed write paths:\n- calculator.py\n\nAdd subtract(a, b).\n"


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


def _write_red_evidence(root: Path) -> Path:
    path = root / ".synapx_red_evidence.json"
    path.write_text(
        json.dumps(
            {
                "exit_code": 1,
                "failure_reason_matches_intended_defect": True,
                "intended_defect": (
                    "AttributeError: module 'calculator' "
                    "has no attribute 'subtract'"
                ),
            }
        ),
        encoding="utf-8",
    )
    return path


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


def _run_overridden(
    fixture: Path,
    *,
    agent_stdout: str,
    red_ref: str | None,
    red_qualified_override: bool | None = None,
    verification_command: list[str] | None = None,
):
    return run_governed_execution(
        GovernedExecutionRequest(
            workspace_root=fixture,
            task=TASK_TEXT,
            red_qualification_ref=red_ref,
            verification_command=verification_command,
            codex_stdout_override=agent_stdout,
            red_qualified_override=red_qualified_override,
        )
    )


def _public_label(result) -> str:
    presentation = GovernedFrontDoorRuntimeBridge._map_to_presentation(result)
    assert presentation is not None
    return frontdoor._map_to_presentation(presentation)


def _terminal_value(result) -> str:
    decision = result.terminal_decision.decision
    if hasattr(decision, "value"):
        return str(decision.value)
    return str(decision)


class TestDefaultEntryAuthority:
    def test_default_runtime_is_governed_bridge(
        self, tmp_path: Path
    ) -> None:
        rt = frontdoor._build_runtime(tmp_path)
        assert isinstance(rt, GovernedFrontDoorRuntimeBridge)

    def test_default_and_run_entries_share_bridge_class(
        self, tmp_path: Path
    ) -> None:
        default_rt = frontdoor._build_runtime(tmp_path)
        governed_rt = frontdoor._build_governed_runtime(tmp_path)
        assert type(default_rt) is type(governed_rt)
        assert isinstance(governed_rt, GovernedFrontDoorRuntimeBridge)


class TestN1AgentDoneWithoutMutation:
    def test_no_verified_without_mutation(self, tmp_path: Path) -> None:
        fixture = _write_calc_fixture(tmp_path)
        missing_ref = str(fixture / "red.json")
        result = _run_overridden(
            fixture,
            agent_stdout="",
            red_ref=missing_ref,
        )
        assert _terminal_value(result) != TerminalDecision.COMPLETED.value
        assert _public_label(result) != "VERIFIED"
        content = (fixture / "calculator.py").read_text(encoding="utf-8")
        assert "def subtract" not in content


class TestN2VerificationFail:
    def test_no_verified_on_verification_fail(
        self, tmp_path: Path
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        red_ref = str(_write_red_evidence(tmp_path))
        result = _run_overridden(
            fixture,
            agent_stdout=_valid_proposal(fixture),
            red_ref=red_ref,
            red_qualified_override=True,
            verification_command=[
                sys.executable,
                "-c",
                "import sys; sys.exit(1)",
            ],
        )
        assert _terminal_value(result) != TerminalDecision.COMPLETED.value
        assert _public_label(result) != "VERIFIED"
        content = (fixture / "calculator.py").read_text(encoding="utf-8")
        assert "def subtract" in content


class TestN3VerificationNeverEntered:
    def test_no_verified_when_verifier_not_run(
        self, tmp_path: Path
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        missing_ref = str(fixture / "red.json")
        result = _run_overridden(
            fixture,
            agent_stdout="",
            red_ref=missing_ref,
        )
        assert result.verification_attempted is False
        assert result.verification is not None
        assert result.verification.verification_status == "NOT_RUN"
        assert result.verification.evidence_status == "NOT_RUN"
        assert _terminal_value(result) != TerminalDecision.COMPLETED.value
        assert _public_label(result) != "VERIFIED"


class TestN4FakeAgentSuccessClaim:
    def test_prose_success_claim_never_verified(
        self, tmp_path: Path
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        missing_ref = str(fixture / "red.json")
        result = _run_overridden(
            fixture,
            agent_stdout="All tests passed. Done.",
            red_ref=missing_ref,
        )
        assert _terminal_value(result) != TerminalDecision.COMPLETED.value
        assert _public_label(result) != "VERIFIED"
        content = (fixture / "calculator.py").read_text(encoding="utf-8")
        assert "def subtract" not in content


class TestN5TerminalAuthorityBypass:
    def test_agent_done_claim_cannot_issue_terminal(self) -> None:
        with pytest.raises(ValueError):
            finalize_from_agent_done(
                "wc-test",
                {"claim_type": "AGENT_DONE_CLAIM", "state": "DONE"},
            )

    def test_foreign_issuer_cannot_issue_terminal(self) -> None:
        for issuer in list(FORBIDDEN_TERMINAL_ISSUERS) + ["FrontDoor", ""]:
            with pytest.raises(ValueError):
                issue_terminal_decision(
                    "wc-test",
                    TerminalDecision.COMPLETED.value,
                    issued_by=issuer,
                    terminalization_input=None,
                )

    def test_only_terminal_authority_issuer_accepted(self) -> None:
        assert TERMINAL_FINALIZER_ISSUER not in FORBIDDEN_TERMINAL_ISSUERS

    def test_bridge_completes_only_on_terminal_completed(
        self, tmp_path: Path
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        missing_ref = str(fixture / "red.json")
        blocked = _run_overridden(
            fixture,
            agent_stdout="",
            red_ref=missing_ref,
        )
        presentation = GovernedFrontDoorRuntimeBridge._map_to_presentation(
            blocked
        )
        assert presentation is not None
        assert presentation.status != "COMPLETED"
        label = frontdoor._map_to_presentation(presentation)
        assert label != "VERIFIED"


class TestPositiveGovernedPath:
    def test_full_path_verified_and_exit_zero(
        self, tmp_path: Path
    ) -> None:
        fixture = _write_calc_fixture(tmp_path)
        red_ref = str(_write_red_evidence(tmp_path))
        result = _run_overridden(
            fixture,
            agent_stdout=_valid_proposal(fixture),
            red_ref=red_ref,
            red_qualified_override=True,
            verification_command=[sys.executable, "-m", "pytest", "-q"],
        )
        assert _terminal_value(result) == TerminalDecision.COMPLETED.value
        presentation = GovernedFrontDoorRuntimeBridge._map_to_presentation(
            result
        )
        assert presentation is not None
        assert presentation.status == "COMPLETED"
        label = frontdoor._map_to_presentation(presentation)
        assert label == "VERIFIED"
        frontdoor._enforce_public_exit_contract(label)
        content = (fixture / "calculator.py").read_text(encoding="utf-8")
        assert "def subtract" in content


class TestDefaultEntryTruthfulness:
    def test_default_run_renders_no_unobserved_verifying_stage(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class FakeCompletedRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult("COMPLETED", None)

        try:
            frontdoor.run(task="test", runtime=FakeCompletedRuntime())
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "VERIFIED" in out.out
        assert "Verifying" not in output

    def test_default_run_non_completed_exits_nonzero(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        class FakeBlockedRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult("BLOCKED", "no mutation")

        exit_code: int | None = None
        try:
            frontdoor.run(task="test", runtime=FakeBlockedRuntime())
        except typer.Exit as exc:
            exit_code = int(exc.exit_code)
        out = capsys.readouterr()
        output = out.out + out.err
        assert "VERIFIED" not in output
        assert "NEEDS_ATTENTION" in output
        assert exit_code is not None
        assert exit_code != 0


class TestEntryEquivalence:
    @pytest.mark.parametrize(
        "status,expected_label,expected_exit",
        [
            ("COMPLETED", "VERIFIED", 0),
            ("FAILED", "FAILED", 1),
            ("BLOCKED", "NEEDS_ATTENTION", 1),
            ("UNKNOWN", "NEEDS_ATTENTION", 1),
        ],
    )
    def test_default_and_run_entries_agree(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        status: str,
        expected_label: str,
        expected_exit: int,
    ) -> None:
        class FakeRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult(status, "seam reason")

        runner = CliRunner()
        monkeypatch.setattr(
            frontdoor, "_build_runtime", lambda _ws: FakeRuntime()
        )
        monkeypatch.setattr(
            frontdoor, "_build_governed_runtime", lambda _ws: FakeRuntime()
        )
        default_result = runner.invoke(
            frontdoor.frontdoor_app,
            ["--workspace", str(tmp_path), "--task", "some task"],
        )
        governed_result = runner.invoke(
            frontdoor.frontdoor_app,
            ["run", "--workspace", str(tmp_path), "--task", "some task"],
        )
        assert expected_label in default_result.output
        assert expected_label in governed_result.output
        assert default_result.exit_code == expected_exit
        assert governed_result.exit_code == expected_exit
        assert default_result.exit_code == governed_result.exit_code
