"""RQ8-P1-R3-R3 Phase A pre-repair RED tests -- post-comparator RED lineage.

These tests pin RQ8-P1-R3-R3 §A. Every post-comparator branch MUST preserve
the comparator's sealed evidence (qualification + observation receipt)
all the way to the terminal decision. R3-R2 already closes the
proposal/admission/path-gate short-circuit (Q2 lineage); R3-R3 closes the
four remaining gaps identified in
``R3_R3_POST_COMPARATOR_BRANCH_CENSUS.json``:

    1. VERIFICATION_COMMAND_NOT_RESOLVED_BLOCK_ON_ZERO_WRITE_PATH
    2. VERIFICATION_FAILED_ENVELOPE_ON_ZERO_WRITE_PATH
    3. VERIFICATION_FAILED_RESULT_ON_ZERO_WRITE_PATH
    4. VERIFICATION_COMMAND_NOT_RESOLVED_BLOCK_ON_POSITIVE_PATH

Pre-repair (HEAD 95431b37), tests F1/F2/F3 FAIL because the lineage is
dropped on those branches. Post-repair, every test PASSES because the
``_block()`` helper carries the comparator evidence (qualification and
actual controlled observation receipt) on every post-comparator branch,
and the result projection carries the same identity.
"""
from __future__ import annotations

import hashlib
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    _fixture_root_sha,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_authority import (
    ControlledPatchApplicator,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)

CALC_BROKEN = "def add(a, b):\n    return a + b\n"

CALC_FIXED = (
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "\n"
    "def subtract(a, b):\n"
    "    return a - b\n"
)

CALC_TEST = textwrap.dedent(
    """\
    import calculator


    def test_add():
        assert calculator.add(2, 3) == 5


    def test_subtract():
        assert calculator.subtract(5, 3) == 2
    """
)

CALC_TASK = (
    "Fix the subtract regression.\n"
    "\n"
    "Allowed write paths:\n"
    "- calculator.py\n"
    "\n"
    "Do not modify unrelated files.\n"
    "Run the repository's authoritative tests and only complete "
    "if verification passes.\n"
)

CALC_FAILED_IDS = ["tests/test_calculator.py::test_subtract"]
VERIFICATION_COMMAND = [sys.executable, "-m", "pytest", "-q"]
EXPECTATION_FILENAME = ".synapx_red_expectation.json"


def _fp(command: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _write_calc_repo(root: Path, *, broken: bool) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "calculator.py").write_text(
        CALC_BROKEN if broken else CALC_FIXED, encoding="utf-8"
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_calculator.py").write_text(CALC_TEST, encoding="utf-8")
    return root


def _stage_expectation(
    repo: Path,
    *,
    revision: str | None = None,
    fingerprint: str | None = None,
    failed_ids: list[str] | None = None,
) -> Path:
    path = repo / EXPECTATION_FILENAME
    payload: dict[str, object] = {
        "expectation_id": "test/r3r3/expectation/v1",
        "expectation_version": 1,
        "status": "QUALIFIED",
        "source_type": "BENCHMARK_FIXTURE",
        "source_revision": (
            revision if revision is not None else _fixture_root_sha(repo)
        ),
        "verification_command_fingerprint": fingerprint or "",
        "expected_exit_code": 1,
        "match_rule": "EXACT_FAILED_TEST_IDS",
        "required_failed_test_ids": (
            list(CALC_FAILED_IDS) if failed_ids is None else list(failed_ids)
        ),
        "provenance": {"source_ref": "test", "source_sha256": "a" * 64},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _proposal(old: str, new: str, path: str = "calculator.py") -> str:
    return (
        f"{PROPOSAL_BEGIN}\n"
        f"FILE: {path}\n"
        f"<<<< OLD\n"
        f"{old}\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"{new}\n"
        f">>>> NEW\n"
        f"{PROPOSAL_END}\n"
    )


def _run(repo: Path, *, proposal: str, verification_command: list[str] | None = None):
    return run_governed_execution(
        GovernedExecutionRequest(
            workspace_root=repo,
            task=CALC_TASK,
            verification_command=(
                list(verification_command)
                if verification_command is not None
                else list(VERIFICATION_COMMAND)
            ),
            codex_stdout_override=proposal,
        )
    )


def _force_zero_write_applicator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replace ``ControlledPatchApplicator.apply`` so the applicator
    returns success=False with ``write_count=0`` and ``mutation_attempted=True``
    (the zero-write downstream branch)."""

    original_apply = ControlledPatchApplicator.apply

    def zero_write_apply(self, *args: Any, **kwargs: Any):
        result = original_apply(self, *args, **kwargs)
        if result.write_count > 0:
            from synapx_harness.kernel.mutation_authority import ApplyReceipt

            return ApplyReceipt(
                applied_paths=[],
                before_sha256="",
                after_sha256="",
                patch_sha256="",
                canonical_patch_sha256="",
                write_count=0,
                denied_reason="FORCED_ZERO_WRITE_FOR_R3_R3_TEST",
                apply_started_at="",
                apply_completed_at="",
                authorization_ref=(
                    result.authorization_ref
                    if getattr(result, "authorization_ref", None)
                    else ""
                ),
                admission_receipt_id=(
                    result.admission_receipt_id
                    if getattr(result, "admission_receipt_id", None)
                    else ""
                ),
                path_gate_receipt_id=(
                    result.path_gate_receipt_id
                    if getattr(result, "path_gate_receipt_id", None)
                    else ""
                ),
                source_revision=(
                    result.source_revision
                    if getattr(result, "source_revision", None)
                    else ""
                ),
            )
        return result

    monkeypatch.setattr(ControlledPatchApplicator, "apply", zero_write_apply)


# ---------------------------------------------------------------------------
# F1 -- MATCH then zero-write/downstream failure: lineage preserved
# ---------------------------------------------------------------------------


class TestPostComparatorZeroWriteLineage:
    def test_match_then_zero_write_preserves_lineage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F1: comparator MATCHes -> applicator produces zero writes ->
        terminal BLOCKED. Both qualification evidence AND observation
        receipt MUST survive into the result and sealed envelope.
        """
        repo = _write_calc_repo(tmp_path / "zw", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=list(CALC_FAILED_IDS),
        )

        _force_zero_write_applicator(monkeypatch)

        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        # Comparator MATCHed before the forced zero-write.
        assert result.red_qualification_evidence is not None, (
            "F1: zero-write branch dropped comparator evidence"
        )
        assert result.red_qualification_evidence.match_result is True, (
            "F1: comparator evidence must carry MATCH"
        )
        assert result.red_observation_receipt is not None, (
            "F1: zero-write branch dropped observation receipt"
        )

        # Sealed envelope carries BOTH under the same identity.
        sealed = result.sealed_evidence
        assert isinstance(sealed, dict) and sealed
        qualification = sealed.get("red_qualification")
        assert isinstance(qualification, dict), (
            "F1: sealed envelope lost red_qualification on zero-write path"
        )
        assert (
            qualification.get("qualification_id")
            == result.red_qualification_evidence.qualification_id
        ), "F1: sealed/run identity mismatch on zero-write path"
        receipt = sealed.get("red_observation_receipt")
        assert isinstance(receipt, dict), (
            "F1: sealed envelope lost red_observation_receipt on zero-write path"
        )
        assert (
            receipt.get("command_id")
            == result.red_qualification_evidence.command_receipt_id
        ), "F1: receipt/evidence command identity mismatch on zero-write path"

    def test_match_then_verification_failure_preserves_lineage(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F1b: comparator MATCHes -> applicator zero-writes -> verifier
        runs and FAILS. Both qualification and observation receipt MUST
        be sealed into the FAILED envelope (gap 2/3)."""
        repo = _write_calc_repo(tmp_path / "vf", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=list(CALC_FAILED_IDS),
        )

        _force_zero_write_applicator(monkeypatch)

        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        # Sealed envelope must carry the actual controlled receipt.
        sealed = result.sealed_evidence
        assert isinstance(sealed, dict) and sealed
        qualification = sealed.get("red_qualification")
        receipt = sealed.get("red_observation_receipt")
        assert isinstance(qualification, dict)
        assert isinstance(receipt, dict), (
            "F1b: post-apply verification-failure envelope lost "
            "red_observation_receipt (R3-R3 gap 3)"
        )
        assert (
            receipt.get("command_id")
            == result.red_qualification_evidence.command_receipt_id
        )

        # Result projection also carries both.
        projected = result.to_dict()
        assert projected.get("red_observation_receipt") is not None, (
            "F1b: result.to_dict dropped red_observation_receipt on "
            "verification-failure path (R3-R3 gap 4)"
        )


# ---------------------------------------------------------------------------
# F2 -- MATCH then verification-command resolution failure: lineage preserved
# ---------------------------------------------------------------------------


class TestPostComparatorVerificationCommandResolutionLineage:
    def test_match_then_d3_preserves_lineage_on_zero_write_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F2: comparator MATCHes -> applicator zero-writes -> the
        verification command becomes unresolvable (D3) between the
        comparator stage and the verification stage. The D3 BLOCKED
        MUST still carry qualification + observation receipt (gap 1)."""
        import synapx_harness.kernel.governed_execution as gov

        repo = _write_calc_repo(tmp_path / "d3zw", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=list(CALC_FAILED_IDS),
        )

        _force_zero_write_applicator(monkeypatch)

        # First call (scope resolution at WorkContract build) returns
        # the valid command so the comparator MATCHes. Second call
        # (verification stage) returns None so D3 fires with lineage
        # already produced by the comparator.
        calls: list[int] = []

        def scripted(
            *, request: Any, workspace_root: Any
        ) -> list[str] | None:
            calls.append(1)
            if len(calls) == 1:
                return list(VERIFICATION_COMMAND)
            return None


        monkeypatch.setattr(gov, "_effective_verification_command", scripted)

        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        # Comparator MATCHed before mutation; lineage MUST survive D3.
        assert result.red_qualification_evidence is not None, (
            "F2: D3 block on zero-write path dropped qualification evidence"
        )
        assert result.red_qualification_evidence.match_result is True
        assert result.red_observation_receipt is not None, (
            "F2: D3 block on zero-write path dropped observation receipt"
        )
        assert result.primary_failure_class == "VERIFICATION_COMMAND_NOT_RESOLVED"

        sealed = result.sealed_evidence
        assert isinstance(sealed, dict) and sealed
        assert isinstance(sealed.get("red_qualification"), dict)
        assert isinstance(sealed.get("red_observation_receipt"), dict)

    def test_match_then_d3_preserves_lineage_on_positive_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F2b: comparator MATCHes -> mutation success -> verification
        command becomes unresolvable (D3) at the verification stage.
        The D3 BLOCKED MUST still carry qualification + observation
        receipt (gap 4)."""
        repo = _write_calc_repo(tmp_path / "d3pos", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=list(CALC_FAILED_IDS),
        )

        calls: list[int] = []

        def scripted(
            *, request: Any, workspace_root: Any
        ) -> list[str] | None:
            calls.append(1)
            if len(calls) == 1:
                return list(VERIFICATION_COMMAND)
            return None

        import synapx_harness.kernel.governed_execution as gov

        monkeypatch.setattr(gov, "_effective_verification_command", scripted)

        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        # Comparator MATCHed before mutation; lineage MUST survive.
        assert result.red_qualification_evidence is not None, (
            "F2b: D3 block on positive path dropped qualification evidence"
        )
        assert result.red_qualification_evidence.match_result is True
        assert result.red_observation_receipt is not None, (
            "F2b: D3 block on positive path dropped observation receipt"
        )
        assert result.primary_failure_class == "VERIFICATION_COMMAND_NOT_RESOLVED"

        sealed = result.sealed_evidence
        assert isinstance(sealed, dict) and sealed
        assert isinstance(sealed.get("red_qualification"), dict)
        assert isinstance(sealed.get("red_observation_receipt"), dict), (
            "F2b: D3 block on positive path dropped observation receipt "
            "from sealed envelope (R3-R3 gap 4)"
        )


# ---------------------------------------------------------------------------
# F3 -- later BLOCKED terminal: qualification_id + command_receipt_id preserved
# ---------------------------------------------------------------------------


class TestPostComparatorTerminalPreservation:
    def test_qualification_and_command_identity_preserved_on_zero_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F3: zero-write downstream failure -> BLOCKED. The terminal
        decision must carry the SAME qualification_id and
        command_receipt_id as the sealed envelope and the receipt
        projection. Identity loss across these surfaces is a hard
        lineage gap."""
        repo = _write_calc_repo(tmp_path / "ti", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=list(CALC_FAILED_IDS),
        )

        _force_zero_write_applicator(monkeypatch)

        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        evidence = result.red_qualification_evidence
        receipt = result.red_observation_receipt
        assert evidence is not None
        assert receipt is not None

        # Three surfaces must carry the same identity.
        sealed = result.sealed_evidence
        assert isinstance(sealed, dict)
        sealed_qual = sealed.get("red_qualification")
        sealed_recv = sealed.get("red_observation_receipt")
        assert isinstance(sealed_qual, dict)
        assert isinstance(sealed_recv, dict)
        assert sealed_qual.get("qualification_id") == evidence.qualification_id
        assert sealed_recv.get("command_id") == evidence.command_receipt_id
        assert sealed_recv.get("command_id") == receipt.get("command_id")

        projected = result.to_dict()
        proj_qual = projected.get("red_qualification_evidence")
        proj_recv = projected.get("red_observation_receipt")
        assert isinstance(proj_qual, dict)
        assert isinstance(proj_recv, dict)
        assert proj_qual.get("qualification_id") == evidence.qualification_id
        assert proj_recv.get("command_id") == evidence.command_receipt_id

        # Terminal decision reflects BLOCKED/FAILED.
        assert result.terminal_decision is not None
        assert result.terminal_decision.decision in ("FAILED", "BLOCKED")
