"""RQ4-R2-C2-R1 authority/truth repair tests.

These tests cover the four Project Owner findings that held C2 open:

* Repair A — ``red_qualified`` is derived from the actual RED evidence
  artifact (``red/result.json``) by
  :func:`derive_red_qualification_from_evidence`; no literal ``True``
  may be cited as the authoritative positive proof.
* Repair B — proposal parse + validation PRECEDE mutation admission; an
  invalid or unauthorized proposal must produce ``admission_receipt=None``
  and never reach the application stage.
* Repair C — non-vacuous pre/post byte binding for source-revision
  mismatch (and the same pre/post pattern applied to C10 / C12 / C13b in
  the C2 file).
* Repair D — real terminal authority proof via canonical
  ``terminal_finalizer`` APIs; Agent DONE alone cannot produce
  COMPLETED; verification FAIL outranks Agent DONE.

These tests run against:

* the live TEST_REPAIR fixture at
  ``C:/krag_work/synapx_harness/_rq4_r2_tmp/rq4_c2_test_repair_fixture``
  for the RED/positive chain (Repair A);
* an in-process temporary repository for Repair B and Repair C;
* the canonical terminal finalizer for Repair D.

They are not unit-mocking the gates; they exercise the real
``GovernedMutationExecutor`` and the real ``terminal_finalizer``.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from synapx_harness.kernel.mutation_authority import (
    ControlledPatchApplicator,
    ExactPathMutationGate,
    GovernedMutationExecutor,
    MutationAdmissionGate,
    PatchProposalParser,
    RedQualificationDerivationError,
    derive_red_qualification_from_evidence,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)
from synapx_harness.kernel import terminal_finalizer


FIXTURE_ROOT = Path(
    "C:/krag_work/synapx_harness/_rq4_r2_tmp/rq4_c2_test_repair_fixture"
)
HARNESS_VENV_PYTHON = Path(
    "C:/krag_work/synapx_harness_rq0_bootstrap/.venv/Scripts/python.exe"
)

CALCULATOR_BASELINE = "def add(a, b):\n    return a + b\n"
CALCULATOR_TARGET = (
    "def add(a, b):\n    return a + b\n\n\n"
    "def subtract(a, b):\n    return a - b\n"
)
TEST_BODY = (
    "import calculator\n\n\n"
    "def test_add():\n    assert calculator.add(2, 3) == 5\n\n\n"
    "def test_subtract():\n    assert calculator.subtract(5, 3) == 2\n"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalized_sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes().replace(b"\r\n", b"\n"))


def _build_structured_proposal(file_path: str, old: str, new: str) -> str:
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


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calculator.py").write_text(CALCULATOR_BASELINE, encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_calculator.py").write_text(TEST_BODY, encoding="utf-8")
    return repo


@pytest.fixture
def executor() -> GovernedMutationExecutor:
    return GovernedMutationExecutor(
        admission_gate=MutationAdmissionGate(),
        path_gate=ExactPathMutationGate(),
        applicator=ControlledPatchApplicator(),
        parser=PatchProposalParser(),
    )


@pytest.fixture(scope="module")
def live_red_evidence_path() -> Path:
    """The physically written RED evidence artifact under the TEST_REPAIR
    fixture. The harness must READ this file (not a literal True) to
    derive ``red_qualified``. The fixture's run_red_evidence.py produced
    it via a real pytest subprocess; see raw/c2/red/result.json."""
    candidate = FIXTURE_ROOT / "red" / "result.json"
    if not candidate.is_file():
        pytest.fail(
            f"live RED evidence artifact missing: {candidate}. "
            "Re-run fixture/run_red_evidence.py first."
        )
    return candidate


# ---------------------------------------------------------------------------
# Repair A — RED admission binding
# ---------------------------------------------------------------------------


class TestRepairAREDAdmissionBinding:
    def test_r1a_real_red_evidence_loads_and_qualifies(
        self, live_red_evidence_path: Path,
    ) -> None:
        """The positive proof must READ the actual RED evidence file and
        DERIVE ``red_qualified`` from its contents. A literal ``True``
        must NOT appear as the authoritative source."""
        red_qualified = derive_red_qualification_from_evidence(
            str(live_red_evidence_path)
        )
        assert red_qualified is True, (
            f"real RED evidence at {live_red_evidence_path} did not qualify; "
            "expected exit_code=1 and failure_reason_matches_intended_defect=true"
        )

        payload = json.loads(live_red_evidence_path.read_text(encoding="utf-8"))
        assert payload["exit_code"] == 1
        assert payload["failure_reason_matches_intended_defect"] is True

    def test_r1b_positive_chain_uses_derived_red_qualified(
        self, executor: GovernedMutationExecutor, live_red_evidence_path: Path,
    ) -> None:
        """Wire the derived ``red_qualified`` through a fresh test_repo
        that copies the fixture's RED evidence path; assert ALLOW +
        write_count=1."""
        # Build a fresh temporary repo so the test is fully isolated.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            (repo / "calculator.py").write_text(CALCULATOR_BASELINE, encoding="utf-8")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_calculator.py").write_text(TEST_BODY, encoding="utf-8")

            # Copy the fixture's RED evidence into the temp repo so the
            # admission ref points to a real, physically-present artifact
            # under the same logical repository root.
            repo_red = repo / "red"
            repo_red.mkdir()
            shutil.copyfile(live_red_evidence_path, repo_red / "result.json")

            red_qualified = derive_red_qualification_from_evidence(
                str(repo_red / "result.json")
            )
            assert red_qualified is True

            proposal_text = _build_structured_proposal(
                "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
            )
            before_bytes = (repo / "calculator.py").read_bytes()
            before_sha = _sha256_bytes(before_bytes)
            test_file_before = (repo / "tests" / "test_calculator.py").read_bytes()

            normalized_before_sha = _sha256_bytes(
                before_bytes.replace(b"\r\n", b"\n")
            )

            result = executor.execute(
                work_contract_id="wc/c2r1-A",
                red_qualified=red_qualified,  # DERIVED, not literal True
                red_qualification_ref=str(repo_red / "result.json"),
                source_revision="REV-C2R1-001",
                execution_identity={
                    "job_id": "j", "task_id": "t", "attempt_id": "a"
                },
                allowed_write_paths=["calculator.py"],
                repository_root=repo,
                expected_before_sha256_by_path={
                    "calculator.py": normalized_before_sha,
                },
                current_source_revision_at_apply="REV-C2R1-001",
                agent_stdout=proposal_text,
            )
            assert result.success is True, result.error
            assert result.admission_receipt is not None
            assert result.admission_receipt.admission_decision == "ALLOW"
            assert result.apply_receipt is not None
            assert result.apply_receipt.write_count == 1
            assert result.apply_receipt.applied_paths == ["calculator.py"]

            # Target bytes changed; test file unchanged.
            after_bytes = (repo / "calculator.py").read_bytes()
            assert _sha256_bytes(after_bytes) != before_sha
            assert (
                (repo / "tests" / "test_calculator.py").read_bytes()
                == test_file_before
            )

    def test_r1c_invalid_red_evidence_denies_admission(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
    ) -> None:
        """N-RED-1: an artificial RED evidence file with exit_code=0
        must yield red_qualified=False; admission DENY; zero writes."""
        red_dir = tmp_repo / "red"
        red_dir.mkdir()
        bad_red = red_dir / "result.json"
        bad_red.write_text(
            json.dumps({
                "schema": "synthetic",
                "exit_code": 0,
                "failure_reason_matches_intended_defect": True,
            }),
            encoding="utf-8",
        )

        red_qualified = derive_red_qualification_from_evidence(str(bad_red))
        assert red_qualified is False

        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )
        normalized_calculator_sha = _normalized_sha256_file(
            tmp_repo / "calculator.py"
        )
        before_bytes = (tmp_repo / "calculator.py").read_bytes()

        result = executor.execute(
            work_contract_id="wc/c2r1-A-invalid",
            red_qualified=red_qualified,
            red_qualification_ref=str(bad_red),
            source_revision="REV-C2R1",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-C2R1",
            agent_stdout=proposal_text,
        )
        assert result.success is False
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.apply_receipt is None

        # Target bytes unchanged (pre/post).
        after_bytes = (tmp_repo / "calculator.py").read_bytes()
        assert after_bytes == before_bytes

    def test_r1d_wrong_red_classification_denies_admission(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
    ) -> None:
        """N-RED-2: exit_code=1 BUT failure_reason_matches_intended_defect
        = False → red_qualified=False; admission DENY."""
        red_dir = tmp_repo / "red"
        red_dir.mkdir()
        bad_red = red_dir / "result.json"
        bad_red.write_text(
            json.dumps({
                "schema": "synthetic",
                "exit_code": 1,
                "failure_reason_matches_intended_defect": False,
            }),
            encoding="utf-8",
        )

        red_qualified = derive_red_qualification_from_evidence(str(bad_red))
        assert red_qualified is False

        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )
        normalized_calculator_sha = _normalized_sha256_file(
            tmp_repo / "calculator.py"
        )
        before_bytes = (tmp_repo / "calculator.py").read_bytes()

        result = executor.execute(
            work_contract_id="wc/c2r1-A-wrongclass",
            red_qualified=red_qualified,
            red_qualification_ref=str(bad_red),
            source_revision="REV-C2R1",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-C2R1",
            agent_stdout=proposal_text,
        )
        assert result.success is False
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.apply_receipt is None

        after_bytes = (tmp_repo / "calculator.py").read_bytes()
        assert after_bytes == before_bytes

    def test_r1e_missing_red_evidence_raises(self) -> None:
        with pytest.raises(RedQualificationDerivationError):
            derive_red_qualification_from_evidence(
                "C:/no/such/file/red.result.json"
            )

    def test_r1f_malformed_red_evidence_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "result.json"
        bad.write_text("not json", encoding="utf-8")
        with pytest.raises(RedQualificationDerivationError):
            derive_red_qualification_from_evidence(str(bad))


# ---------------------------------------------------------------------------
# Repair B — proposal validation precedes mutation admission
# ---------------------------------------------------------------------------


class TestRepairBMutationAdmissionOrder:
    def test_r1g_invalid_proposal_produces_no_admission_receipt(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
    ) -> None:
        normalized_calculator_sha = _normalized_sha256_file(
            tmp_repo / "calculator.py"
        )
        before_bytes = (tmp_repo / "calculator.py").read_bytes()

        result = executor.execute(
            work_contract_id="wc/c2r1-B-invalidprop",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="REV-C2R1",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-C2R1",
            agent_stdout="I'll modify calculator.py to add subtract.",
        )

        assert result.success is False
        assert result.admission_receipt is None  # <-- key invariant
        assert result.path_gate_receipt is None
        assert result.apply_receipt is None
        assert result.proposal is not None
        assert result.proposal.valid is False
        assert result.validation_blockers == []
        assert "Proposal INVALID" in (result.error or "")

        after_bytes = (tmp_repo / "calculator.py").read_bytes()
        assert after_bytes == before_bytes

    def test_r1h_unauthorized_proposal_produces_no_admission_receipt(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
    ) -> None:
        normalized_calculator_sha = _normalized_sha256_file(
            tmp_repo / "calculator.py"
        )
        before_bytes = (tmp_repo / "calculator.py").read_bytes()

        proposal_text = _build_structured_proposal(
            "README.md", "old docs", "new docs"
        )
        result = executor.execute(
            work_contract_id="wc/c2r1-B-unauthorized",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="REV-C2R1",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-C2R1",
            agent_stdout=proposal_text,
        )

        assert result.success is False
        assert result.admission_receipt is None  # <-- key invariant
        assert result.path_gate_receipt is None
        assert result.apply_receipt is None
        assert any(
            "outside declared write set" in b
            for b in result.validation_blockers
        )

        after_bytes = (tmp_repo / "calculator.py").read_bytes()
        assert after_bytes == before_bytes

    def test_r1i_validation_blockers_surfaces_no_receipt(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
    ) -> None:
        """Validation must surface blockers before admission. A proposal
        that fails OLD-binding must yield admission_receipt=None."""
        # Calculator.py contains CRLF on Windows tmp_path. Construct an OLD
        # block with trailing whitespace difference that will not match the
        # normalized bytes.
        proposal_text = _build_structured_proposal(
            "calculator.py",
            CALCULATOR_BASELINE + " \n",  # trailing whitespace — will NOT match
            CALCULATOR_TARGET,
        )
        normalized_calculator_sha = _normalized_sha256_file(
            tmp_repo / "calculator.py"
        )
        before_bytes = (tmp_repo / "calculator.py").read_bytes()

        result = executor.execute(
            work_contract_id="wc/c2r1-B-oldbinding",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="REV-C2R1",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-C2R1",
            agent_stdout=proposal_text,
        )
        assert result.success is False
        assert result.admission_receipt is None  # <-- key invariant
        assert result.apply_receipt is None
        assert any("before-content binding" in b for b in result.validation_blockers)

        after_bytes = (tmp_repo / "calculator.py").read_bytes()
        assert after_bytes == before_bytes


# ---------------------------------------------------------------------------
# Repair C — non-vacuous pre/post byte binding on revision mismatch
# ---------------------------------------------------------------------------


class TestRepairCSourceRevisionPrePostBinding:
    def test_r1j_revision_mismatch_zero_writes_and_bytes_unchanged(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
    ) -> None:
        normalized_calculator_sha = _normalized_sha256_file(
            tmp_repo / "calculator.py"
        )
        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )

        target = tmp_repo / "calculator.py"
        before_bytes = target.read_bytes()
        before_sha = _sha256_bytes(before_bytes)

        result = executor.execute(
            work_contract_id="wc/c2r1-C",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="REV-A",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-B",
            agent_stdout=proposal_text,
        )

        assert result.success is False
        assert result.apply_receipt is not None
        assert result.apply_receipt.write_count == 0
        assert result.apply_receipt.applied_paths == []
        assert "revision" in (result.apply_receipt.denied_reason or "").lower()

        # Non-vacuous: read the file AFTER the failed execution.
        after_bytes = target.read_bytes()
        after_sha = _sha256_bytes(after_bytes)
        assert after_sha == before_sha
        assert after_bytes == before_bytes


# ---------------------------------------------------------------------------
# Repair D — canonical Terminal Finalizer authority proof
# ---------------------------------------------------------------------------


class TestRepairDCanonicalTerminalAuthority:
    def test_r1k_agent_done_direct_finalization_impossible(self) -> None:
        """Calling the canonical ``finalize_from_agent_done`` with a
        proper Agent DONE claim raises by design (RED-I0-03). This is
        the canonical evidence that Agent DONE has no terminal authority."""
        claim = {"claim_type": "AGENT_DONE_CLAIM", "state": "DONE"}
        with pytest.raises(ValueError) as excinfo:
            terminal_finalizer.finalize_from_agent_done(
                work_contract_id="wc/agent-done",
                claim=claim,
            )
        msg = str(excinfo.value)
        assert "agent done claim" in msg.lower()
        assert "terminal" in msg.lower() or "finaliz" in msg.lower()

    def test_r1l_advance_agent_claim_only_to_verifying(self) -> None:
        claim = {"claim_type": "AGENT_DONE_CLAIM", "state": "DONE"}
        advanced = terminal_finalizer.advance_agent_claim(claim, "VERIFYING")
        assert advanced["state"] == "VERIFYING"
        with pytest.raises(ValueError):
            terminal_finalizer.advance_agent_claim(claim, "COMPLETED")

    def test_r1m_verification_fail_outranks_agent_done(self) -> None:
        """A verification FAIL with active_blocker_count=0 + evidence
        INVALID must produce a terminal decision that is NOT COMPLETED."""
        from synapx_harness.contracts.runtime_models import (
            VerificationResult,
        )
        vr_fail = VerificationResult(
            work_contract_id="wc/r1m",
            verification_status="FAIL",
            evidence_status="VALID",
            active_blocker_count=0,
            checks=[],
        )
        decision = terminal_finalizer.finalize(vr_fail)
        assert decision.decision in {"FAILED", "BLOCKED"}
        assert decision.decision != "COMPLETED"

        vr_invalid_evidence = VerificationResult(
            work_contract_id="wc/r1m2",
            verification_status="PASS",
            evidence_status="INVALID",
            active_blocker_count=0,
            checks=[],
        )
        decision_invalid = terminal_finalizer.finalize(vr_invalid_evidence)
        assert decision_invalid.decision in {"FAILED", "BLOCKED"}
        assert decision_invalid.decision != "COMPLETED"

        vr_blockers = VerificationResult(
            work_contract_id="wc/r1m3",
            verification_status="PASS",
            evidence_status="VALID",
            active_blocker_count=2,
            checks=[],
        )
        decision_blockers = terminal_finalizer.finalize(vr_blockers)
        assert decision_blockers.decision == "BLOCKED"

    def test_r1n_completed_requires_pass_valid_no_blockers(self) -> None:
        from synapx_harness.contracts.runtime_models import (
            VerificationResult,
        )
        vr = VerificationResult(
            work_contract_id="wc/r1n",
            verification_status="PASS",
            evidence_status="VALID",
            active_blocker_count=0,
            checks=[],
        )
        decision = terminal_finalizer.finalize(vr)
        assert decision.decision == "COMPLETED"

    def test_r1o_completed_via_sealed_evidence_requires_invariants(
        self,
    ) -> None:
        """``finalize_from_sealed_evidence`` with proposed_outcome=COMPLETED
        but missing verification_admission_receipt invariants must raise.
        With invariants satisfied, it returns COMPLETED."""
        sealed = {"integrity_status": "SEALED"}
        terminalization_input = {
            "execution_identity": {"job_id": "j", "task_id": "t", "attempt_id": "a"},
            "work_contract_id": "wc/r1o",
            "verification_admission_receipt": {
                "verification_status": "FAIL",  # <-- not PASS
                "evidence_status": "VALID",
                "active_blocker_count": 0,
            },
            "sealed_evidence": sealed,
            "source_revision_ref": "REV-1",
            "active_blocker_count": 0,
            "proposed_outcome": "COMPLETED",
        }
        with pytest.raises(ValueError) as excinfo:
            terminal_finalizer.finalize_from_sealed_evidence(
                sealed_evidence=sealed,
                terminalization_input=terminalization_input,
            )
        assert "verify-fail" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Repair A+B+L — full positive chain end-to-end with real pytest GREEN
# ---------------------------------------------------------------------------


class TestFullPositiveChainWithRealGreen:
    def test_r1p_full_chain_derives_red_and_mutates_and_greens(
        self, executor: GovernedMutationExecutor, live_red_evidence_path: Path,
    ) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            (repo / "calculator.py").write_text(CALCULATOR_BASELINE, encoding="utf-8")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_calculator.py").write_text(TEST_BODY, encoding="utf-8")

            repo_red = repo / "red"
            repo_red.mkdir()
            shutil.copyfile(live_red_evidence_path, repo_red / "result.json")

            red_qualified = derive_red_qualification_from_evidence(
                str(repo_red / "result.json")
            )
            assert red_qualified is True

            proposal_text = _build_structured_proposal(
                "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
            )
            normalized_before_sha = _normalized_sha256_file(repo / "calculator.py")
            test_file_before = (repo / "tests" / "test_calculator.py").read_bytes()

            result = executor.execute(
                work_contract_id="wc/c2r1-full",
                red_qualified=red_qualified,
                red_qualification_ref=str(repo_red / "result.json"),
                source_revision="REV-C2R1-FULL",
                execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
                allowed_write_paths=["calculator.py"],
                repository_root=repo,
                expected_before_sha256_by_path={
                    "calculator.py": normalized_before_sha,
                },
                current_source_revision_at_apply="REV-C2R1-FULL",
                agent_stdout=proposal_text,
            )
            assert result.success is True, result.error
            assert result.admission_receipt is not None
            assert result.admission_receipt.admission_decision == "ALLOW"
            assert result.apply_receipt is not None
            assert result.apply_receipt.write_count == 1
            assert result.apply_receipt.applied_paths == ["calculator.py"]

            assert (
                (repo / "tests" / "test_calculator.py").read_bytes()
                == test_file_before
            )

            # Real GREEN
            env = dict(os.environ)
            env["PYTHONNOUSERSITE"] = "1"
            env.pop("PYTHONPATH", None)
            proc = subprocess.run(
                [
                    str(HARNESS_VENV_PYTHON),
                    "-m", "pytest",
                    "tests/test_calculator.py",
                    "-v", "--tb=short", "--no-header",
                ],
                cwd=str(repo),
                capture_output=True,
                text=True,
                env=env,
            )
            assert proc.returncode == 0, (
                f"real GREEN failed: stdout={proc.stdout!r} stderr={proc.stderr!r}"
            )
            assert "2 passed" in proc.stdout
