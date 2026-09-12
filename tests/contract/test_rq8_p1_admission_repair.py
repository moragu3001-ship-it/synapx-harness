"""RQ8-P1 admission repair regression tests (bounded).

Covers Work Order Sec 15-19 for the POSITIVE_MUTATION_ADMISSION_BLOCKED /
ADMISSION_DENIAL_REASON_MISSING repair:

* Sec 15: exact RQ8 contract (canonical write set + exact proposed path)
  must reach Admission ALLOW / PathGate ALLOW / mutation eligible.
* Sec 16: path-normalization ALLOW matrix + negatives that must stay DENIED.
* Sec 17: every deterministic DENIED carries a non-None authoritative reason.
* Sec 18: first-failure precedence (admission DENY suppresses downstream).
* Sec 19: agent-activity / terminal coexistence invariant.

No production semantics are weakened here: negatives assert BLOCKED +
mutation never attempted.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from synapx_harness.cli.agent_activity import source_from_result
from synapx_harness.cli.assurance_presentation import build_assurance_presentation
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_authority import (
    ExactPathMutationGate,
    MutationAdmissionGate,
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
    parse_allowed_write_paths,
)

TASK_TEXT = (
    "Fix the subtract regression.\n"
    "\n"
    "Allowed write paths:\n"
    "- calculator.py\n"
    "\n"
    "Do not modify unrelated files.\n"
    "Run the repository's authoritative tests and only complete "
    "if verification passes.\n"
)

CALC_BROKEN = 'def add(a, b):\n    return a + b\n'

CALC_FIXED = (
    'def add(a, b):\n'
    '    return a + b\n'
    '\n'
    '\n'
    'def subtract(a, b):\n'
    '    return a - b\n'
)

TEST_CALC = textwrap.dedent(
    """\
    import calculator


    def test_add():
        assert calculator.add(2, 3) == 5


    def test_subtract():
        assert calculator.subtract(5, 3) == 2
    """
)


def _write_repo(root: Path, *, broken: bool) -> Path:
    """Create a minimal calculator fixture (fails when broken)."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "calculator.py").write_text(
        CALC_BROKEN if broken else CALC_FIXED, encoding="utf-8"
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_calculator.py").write_text(TEST_CALC, encoding="utf-8")
    return root


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


def _fix_proposal() -> str:
    return _proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)


def _run(
    repo: Path,
    *,
    proposal: str,
    task: str = TASK_TEXT,
    red_qualification_ref: str | None = None,
    red_qualified_override: bool | None = None,
):  # -> GovernedExecutionResult
    request = GovernedExecutionRequest(
        workspace_root=repo,
        task=task,
        verification_command=[sys.executable, "-m", "pytest", "-q"],
        codex_stdout_override=proposal,
        red_qualification_ref=red_qualification_ref,
        red_qualified_override=red_qualified_override,
    )
    return run_governed_execution(request)


# ---------------------------------------------------------------------------
# Sec 15 -- Required positive contract test (exact RQ8 contract)
# ---------------------------------------------------------------------------


class TestPositiveAdmissionContract:
    def test_canonical_write_set_parses_exactly(self) -> None:
        assert parse_allowed_write_paths(TASK_TEXT) == ["calculator.py"]

    def test_exact_authorized_path_is_admitted_and_mutates(
        self, tmp_path: Path
    ) -> None:
        """Exact RQ8 contract: canonical write set + exact proposed path.

        Pre-repair this fails with ``Admission DENIED: None`` because no
        lifecycle step ever stages RED evidence; post-repair the harness
        executes the authoritative suite as RED and admits the valid
        proposal.
        """
        repo = _write_repo(tmp_path / "red", broken=True)
        result = _run(repo, proposal=_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"
        assert result.path_gate_receipt is not None
        assert result.path_gate_receipt.gate_decision == "ALLOW"
        assert result.mutation_attempted is True
        assert result.verification_attempted is True
        assert result.errors == []
        assert result.terminal_decision.decision == "COMPLETED"
        assert (repo / "calculator.py").read_text(
            encoding="utf-8"
        ) == CALC_FIXED

    def test_explicit_staged_red_still_honored(self, tmp_path: Path) -> None:
        """Operator-staged RED evidence keeps working (no subprocess needed)."""
        repo = _write_repo(tmp_path / "staged", broken=True)
        red_path = repo / ".synapx_red_evidence.json"
        red_path.write_text(
            json.dumps(
                {
                    "exit_code": 1,
                    "failure_reason_matches_intended_defect": True,
                }
            ),
            encoding="utf-8",
        )
        result = _run(
            repo,
            proposal=_fix_proposal(),
            red_qualification_ref=str(red_path),
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"
        assert result.mutation_attempted is True

    def test_explicit_override_seams_unchanged(self, tmp_path: Path) -> None:
        repo = _write_repo(tmp_path / "override", broken=True)
        result = _run(
            repo, proposal=_fix_proposal(), red_qualified_override=True
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"


# ---------------------------------------------------------------------------
# Sec 16 -- Path-normalization matrix (ALLOW) and negatives (DENY)
# ---------------------------------------------------------------------------


class TestPathGateMatrix:
    def _parsed(self, file_path: str) -> object:
        proposal = PatchProposalParser().parse_structured(
            _proposal_text(file_path, "old-text", "new-text")
        )
        assert proposal.valid
        return proposal

    def test_exact_relative_path_allow(self) -> None:
        gate = ExactPathMutationGate()
        receipt = gate.check(
            proposal=self._parsed("calculator.py"),  # type: ignore[arg-type]
            allowed_write_paths=["calculator.py"],
            source_revision="rev",
            admission_receipt_id="rct/x",
        )
        assert receipt.gate_decision == "ALLOW"
        assert receipt.apply_authority == "ISSUED"
        assert receipt.reason is None

    def test_admission_gate_denies_without_reason_loss(self) -> None:
        """Gate-level safety net: DENY never carries a None reason."""
        gate = MutationAdmissionGate()
        receipt = gate.admit(
            work_contract_id="wc-test",
            red_qualified=False,
            red_qualification_ref="/nonexistent/red.json",
            source_revision="rev",
            execution_identity={},
            allowed_write_paths=["calculator.py"],
        )
        assert receipt.admission_decision == "DENY"
        assert receipt.denied_reason is not None
        assert "None" not in str(receipt.denied_reason)

    @pytest.mark.parametrize(
        "proposed",
        [
            "../escape.py",
            "/abs/outside.py",
            "other.py",
            "calculator.py.bak",
            "sub/calculator.py",
        ],
    )
    def test_negative_paths_stay_denied(self, proposed: str) -> None:
        """Traversal / absolute / sibling / prefix-confusion / basename
        collisions must never be admitted."""
        gate = ExactPathMutationGate()
        receipt = gate.check(
            proposal=self._parsed(proposed),  # type: ignore[arg-type]
            allowed_write_paths=["calculator.py"],
            source_revision="rev",
            admission_receipt_id="rct/x",
        )
        assert receipt.gate_decision == "DENY"
        assert receipt.apply_authority == "NOT_ISSUED"
        assert receipt.reason is not None

    def test_unauthorized_sibling_end_to_end_blocked(
        self, tmp_path: Path
    ) -> None:
        """A proposal for a file outside the write set never mutates and
        never surfaces a None reason."""
        repo = _write_repo(tmp_path / "neg", broken=True)
        (repo / "other.py").write_text("x = 1\n", encoding="utf-8")
        sibling_proposal = _proposal_text("other.py", "x = 1\n", "x = 2\n")
        result = _run(repo, proposal=sibling_proposal)
        assert result.mutation_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert result.errors
        assert all("None" not in str(e) for e in result.errors)
        assert (repo / "other.py").read_text(encoding="utf-8") == "x = 1\n"


# ---------------------------------------------------------------------------
# Sec 17 -- Required reason tests (DENIED never renders None)
# ---------------------------------------------------------------------------


class TestDenialReasons:
    def test_green_tree_denial_names_red_gate(self, tmp_path: Path) -> None:
        """No defect to repair (suite green) -> deterministic DENY whose
        reason identifies the RED gate and never renders None."""
        repo = _write_repo(tmp_path / "green", broken=False)
        green_proposal = _proposal_text(
            "calculator.py", CALC_FIXED, CALC_FIXED + "\n# touch\n"
        )
        result = _run(repo, proposal=green_proposal)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        reason = result.admission_receipt.denied_reason
        assert reason is not None
        assert "RED" in str(reason).upper()
        assert result.errors
        assert result.errors[0] == result.primary_failure_message
        assert "None" not in str(result.errors[0])
        assert "RED" in str(result.errors[0]).upper()

    def test_missing_command_denial_is_deterministic(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unresolvable verification command -> fail-closed DENY with a
        deterministic, gate-identifying reason (no None)."""
        import synapx_harness.kernel.governed_execution as gov

        repo = _write_repo(tmp_path / "noresolve", broken=True)
        monkeypatch.setattr(
            gov, "resolve_target_verification_command", lambda root: None
        )
        request = GovernedExecutionRequest(
            workspace_root=repo,
            task=TASK_TEXT,
            codex_stdout_override=_fix_proposal(),
        )
        result = run_governed_execution(request)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.admission_receipt.denied_reason is not None
        assert "None" not in str(result.errors[0])


# ---------------------------------------------------------------------------
# Sec 18 -- First-failure precedence
# ---------------------------------------------------------------------------


class TestFirstFailurePrecedence:
    def test_admission_deny_suppresses_downstream(self, tmp_path: Path) -> None:
        repo = _write_repo(tmp_path / "prec", broken=False)
        green_proposal = _proposal_text(
            "calculator.py", CALC_FIXED, CALC_FIXED + "\n# touch\n"
        )
        result = _run(repo, proposal=green_proposal)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert result.verification_attempted is False
        assert result.path_gate_receipt is None
        # Downstream states may not replace the admission cause.
        assert result.errors
        assert result.errors[0] == result.primary_failure_message
        assert "RED" in str(result.errors[0]).upper()
        assurance = build_assurance_presentation(result)
        assert assurance.terminal_reason == result.errors[0]


# ---------------------------------------------------------------------------
# Sec 19 -- Agent activity invariant (Phase 2C coexistence)
# ---------------------------------------------------------------------------


class TestAgentActivityCoexistence:
    def test_completed_agent_beside_blocked_terminal(
        self, tmp_path: Path
    ) -> None:
        """Agent DONE + later admission DENY -> agent Completed coexists
        with NEEDS_ATTENTION; activity is never derived from terminal."""
        repo = _write_repo(tmp_path / "coexist", broken=False)
        green_proposal = _proposal_text(
            "calculator.py", CALC_FIXED, CALC_FIXED + "\n# touch\n"
        )
        result = _run(repo, proposal=green_proposal)
        agent = source_from_result(result)
        assert agent is not None
        assert agent.process_started is True
        assurance = build_assurance_presentation(result)
        assert assurance.terminal_state == "BLOCKED"
