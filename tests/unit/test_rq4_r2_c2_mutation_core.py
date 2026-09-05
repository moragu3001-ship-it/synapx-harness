"""RQ4-R2-C2 mutation core contract tests (C5..C14).

These tests cover the single-file TEST_REPAIR first slice. They:

* build a controlled in-memory fixture (calculator.py + tests/test_calculator.py)
  inside a tmp dir;
* run the deterministic RED runner against the fixture;
* build a canonical structured proposal via
  ``mutation_proposal_contract.build_proposal_instruction`` then a
  hand-shaped deterministic proposal string;
* drive the full mutation chain through ``GovernedMutationExecutor``;
* assert GREEN (test_subtract now passes, test_add still passes);
* assert the test evidence file SHA is unchanged across the mutation;
* assert the negative cases C5..C14 produce empty ApplyReceipts without
  mutating the target file.

No real Codex is exercised in C2; this is a deterministic substrate
closure test. C3 will replace the deterministic proposal source with
real read-only Codex.
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
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
    MutationProposalContractError,
    build_proposal_instruction,
    parse_allowed_write_paths,
    validate_mutation_proposal,
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

HARNESS_VENV_PYTHON = Path(
    "C:/krag_work/synapx_harness_rq0_bootstrap/.venv/Scripts/python.exe"
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _normalized_sha256_file(path: Path) -> str:
    """SHA256 over CRLF-normalized bytes (matches validator + applicator)."""
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
    test_path = repo / "tests" / "test_calculator.py"
    test_path.write_text(TEST_BODY, encoding="utf-8")
    return repo


@pytest.fixture
def baseline_calculator_sha(tmp_repo: Path) -> str:
    return _sha256_file(tmp_repo / "calculator.py")


@pytest.fixture
def baseline_test_sha(tmp_repo: Path) -> str:
    return _sha256_file(tmp_repo / "tests" / "test_calculator.py")


@pytest.fixture
def normalized_calculator_sha(tmp_repo: Path) -> str:
    """SHA256 over CRLF-normalized bytes — the value the validator and
    applicator bind against (matching their normalization)."""
    return _normalized_sha256_file(tmp_repo / "calculator.py")


@pytest.fixture
def source_revision() -> str:
    return "REV-C2-TEST-0001"


@pytest.fixture
def admission_receipt(source_revision: str) -> dict:
    return {
        "admission_decision": "ALLOW",
        "red_qualified": True,
        "red_qualification_ref": "red/result.json",
        "source_revision": source_revision,
        "execution_identity": {"job_id": "job", "task_id": "task", "attempt_id": "att"},
        "allowed_write_paths": ["calculator.py"],
        "receipt_id": "rct/c2-test",
    }


@pytest.fixture
def parser() -> PatchProposalParser:
    return PatchProposalParser()


@pytest.fixture
def executor(tmp_repo: Path) -> GovernedMutationExecutor:
    return GovernedMutationExecutor(
        admission_gate=MutationAdmissionGate(),
        path_gate=ExactPathMutationGate(),
        applicator=ControlledPatchApplicator(),
        parser=PatchProposalParser(),
    )


# ---------------------------------------------------------------------------
# C5 / C6 - absolute path / traversal rejected by validate_mutation_proposal
# ---------------------------------------------------------------------------


class TestPathSecurityProposalsRejected:
    def test_c5_absolute_path_rejected(self, tmp_repo: Path) -> None:
        proposal_text = _build_structured_proposal(
            "/abs/calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )
        proposal = PatchProposalParser().parse_structured(proposal_text)
        blockers = validate_mutation_proposal(
            proposal,
            repository_root=tmp_repo,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path={"calculator.py": "ignored"},
        )
        assert any("absolute" in b for b in blockers), blockers

    def test_c6_traversal_path_rejected(self, tmp_repo: Path) -> None:
        proposal_text = _build_structured_proposal(
            "../secret.py", "old", "new"
        )
        proposal = PatchProposalParser().parse_structured(proposal_text)
        blockers = validate_mutation_proposal(
            proposal,
            repository_root=tmp_repo,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path={"calculator.py": "ignored"},
        )
        assert any("traversal" in b or "INVALID_WRITE_SET_PATH" in b for b in blockers), blockers

    def test_c7_unauthorized_readme_rejected(self, tmp_repo: Path) -> None:
        proposal_text = _build_structured_proposal(
            "README.md", "old", "new"
        )
        proposal = PatchProposalParser().parse_structured(proposal_text)
        blockers = validate_mutation_proposal(
            proposal,
            repository_root=tmp_repo,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path={"calculator.py": "ignored"},
        )
        assert any("outside declared write set" in b for b in blockers), blockers


# ---------------------------------------------------------------------------
# C8 - ExactPathMutationGate NON_EMPTY_SUBSET semantics
# ---------------------------------------------------------------------------


class TestExactPathMutationGateSemantics:
    def test_exact_set_allowed(self) -> None:
        from synapx_harness.kernel.mutation_authority import (
            PatchProposal,
            _canonical_patch_bytes,
        )
        canonical = _canonical_patch_bytes(["calculator.py"], ["old"], ["new"])
        sha = hashlib.sha256(canonical).hexdigest()
        proposal = PatchProposal(
            valid=True,
            paths=["calculator.py"],
            hunks=[],
            old_lines=["old"],
            new_lines=["new"],
            sha256=sha,
            raw_input_sha256="x",
            canonical_patch_sha256=sha,
        )
        receipt = ExactPathMutationGate().check(
            proposal, ["calculator.py"], "rev", "rct"
        )
        assert receipt.gate_decision == "ALLOW"

    def test_strict_subset_allowed(self) -> None:
        from synapx_harness.kernel.mutation_authority import (
            PatchProposal,
            _canonical_patch_bytes,
        )
        canonical = _canonical_patch_bytes(["calculator.py"], ["old"], ["new"])
        sha = hashlib.sha256(canonical).hexdigest()
        proposal = PatchProposal(
            valid=True,
            paths=["calculator.py"],
            hunks=[],
            old_lines=["old"],
            new_lines=["new"],
            sha256=sha,
            raw_input_sha256="x",
            canonical_patch_sha256=sha,
        )
        receipt = ExactPathMutationGate().check(
            proposal, ["calculator.py", "tests/test_calculator.py"], "rev", "rct"
        )
        assert receipt.gate_decision == "ALLOW"

    def test_empty_proposal_denied(self) -> None:
        from synapx_harness.kernel.mutation_authority import PatchProposal
        proposal = PatchProposal(
            valid=True, paths=[], hunks=[], old_lines=[], new_lines=[],
            sha256="", raw_input_sha256="x", canonical_patch_sha256="",
        )
        receipt = ExactPathMutationGate().check(
            proposal, ["calculator.py"], "rev", "rct"
        )
        assert receipt.gate_decision == "DENY"

    def test_outside_path_denied(self) -> None:
        from synapx_harness.kernel.mutation_authority import (
            PatchProposal,
            _canonical_patch_bytes,
        )
        canonical = _canonical_patch_bytes(["README.md"], ["old"], ["new"])
        sha = hashlib.sha256(canonical).hexdigest()
        proposal = PatchProposal(
            valid=True, paths=["README.md"], hunks=[],
            old_lines=["old"], new_lines=["new"],
            sha256=sha, raw_input_sha256="x", canonical_patch_sha256=sha,
        )
        receipt = ExactPathMutationGate().check(
            proposal, ["calculator.py"], "rev", "rct"
        )
        assert receipt.gate_decision == "DENY"


# ---------------------------------------------------------------------------
# C9 - source revision mismatch blocks mutation
# ---------------------------------------------------------------------------


class TestSourceRevisionBinding:
    def test_c9_revision_mismatch_blocks(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
        normalized_calculator_sha: str, source_revision: str,
    ) -> None:
        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )

        # Capture the pre-image of the target file BEFORE invoking the
        # mutation core. This byte sequence is the authoritative "target
        # unchanged" reference.
        target = tmp_repo / "calculator.py"
        before_bytes = target.read_bytes()
        before_sha = _sha256_bytes(before_bytes)

        result = executor.execute(
            work_contract_id="wc/c2-c9",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision=source_revision,
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply="REV-DIFFERENT",
            agent_stdout=proposal_text,
        )

        assert result.success is False
        assert result.apply_receipt is not None
        assert result.apply_receipt.write_count == 0
        assert result.apply_receipt.applied_paths == []
        assert "revision" in (result.apply_receipt.denied_reason or "").lower()

        # Non-vacuous post-condition: read the file AGAIN after the
        # failed execution and prove both byte equality AND SHA equality
        # against the pre-image captured above.
        after_bytes = target.read_bytes()
        after_sha = _sha256_bytes(after_bytes)
        assert after_sha == before_sha, (
            f"source-revision mismatch must leave the target SHA unchanged; "
            f"before={before_sha} after={after_sha}"
        )
        assert after_bytes == before_bytes, (
            "source-revision mismatch must leave target bytes byte-identical"
        )


# ---------------------------------------------------------------------------
# C10 - before-hash mismatch blocks mutation
# ---------------------------------------------------------------------------


class TestBeforeHashBinding:
    def test_c10_before_hash_mismatch_blocks(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
        source_revision: str,
    ) -> None:
        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )

        target = tmp_repo / "calculator.py"
        before_bytes = target.read_bytes()
        before_sha = _sha256_bytes(before_bytes)

        result = executor.execute(
            work_contract_id="wc/c2-c10",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision=source_revision,
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": "0" * 64,  # WRONG on purpose
            },
            current_source_revision_at_apply=source_revision,
            agent_stdout=proposal_text,
        )
        assert result.success is False
        # Validator must reject before-hash mismatch; apply_receipt is None.
        assert result.apply_receipt is None
        assert any("before-hash mismatch" in b for b in result.validation_blockers)

        # Non-vacuous: target bytes AND SHA must equal the pre-image.
        after_bytes = target.read_bytes()
        after_sha = _sha256_bytes(after_bytes)
        assert after_sha == before_sha
        assert after_bytes == before_bytes


# ---------------------------------------------------------------------------
# C11 - proposal hash mismatch blocks mutation
# ---------------------------------------------------------------------------


class TestProposalHashBinding:
    def test_c11b_proposal_internal_sha_inconsistency_rejected(
        self, tmp_repo: Path, normalized_calculator_sha: str,
    ) -> None:
        """A PatchProposal whose sha256 != canonical_patch_sha256 is rejected
        by ``validate_mutation_proposal`` (deterministic self-consistency).

        C11 covers proposal-hash integrity. The harness cannot detect
        byte-level tampering of OLD/NEW by hash mismatch alone (those are
        content-binding checks); it CAN and MUST detect a proposal whose
        own ``sha256`` disagrees with its ``canonical_patch_sha256`` because
        that is an internal structural inconsistency.
        """
        from synapx_harness.kernel.mutation_authority import (
            PatchHunk,
            PatchProposal,
            _canonical_patch_bytes,
        )
        canonical = _canonical_patch_bytes(
            ["calculator.py"], [CALCULATOR_BASELINE], [CALCULATOR_TARGET]
        )
        good_sha = hashlib.sha256(canonical).hexdigest()
        bad_sha = "f" * 64
        proposal = PatchProposal(
            valid=True,
            paths=["calculator.py"],
            hunks=[PatchHunk(
                file_path="calculator.py",
                old_lines=[CALCULATOR_BASELINE],
                new_lines=[CALCULATOR_TARGET],
            )],
            old_lines=[CALCULATOR_BASELINE],
            new_lines=[CALCULATOR_TARGET],
            sha256=bad_sha,
            raw_input_sha256="x",
            canonical_patch_sha256=good_sha,
        )
        blockers = validate_mutation_proposal(
            proposal,
            repository_root=tmp_repo,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
        )
        assert any("proposal" in b and ("hash" in b or "sha" in b or "disagreement" in b) for b in blockers), blockers


# ---------------------------------------------------------------------------
# C12 / C13 - applicator writes only after ALL preconditions; failure leaves bytes unchanged
# ---------------------------------------------------------------------------


class TestApplicatorPreconditions:
    def test_c12_c13_admission_deny_leaves_bytes_unchanged(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
        normalized_calculator_sha: str, baseline_calculator_sha: str,
        source_revision: str,
    ) -> None:
        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )

        target = tmp_repo / "calculator.py"
        before_bytes = target.read_bytes()
        before_sha = _sha256_bytes(before_bytes)

        result = executor.execute(
            work_contract_id="wc/c2-c12",
            red_qualified=False,  # FORCES admission DENY
            red_qualification_ref="red/result.json",
            source_revision=source_revision,
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply=source_revision,
            agent_stdout=proposal_text,
        )
        assert result.success is False
        assert result.apply_receipt is None
        # Non-vacuous pre/post binding against the freshly captured
        # pre-image AND the fixture-level baseline_calculator_sha.
        after_bytes = target.read_bytes()
        after_sha = _sha256_bytes(after_bytes)
        assert after_sha == before_sha
        assert after_bytes == before_bytes
        assert _sha256_file(target) == baseline_calculator_sha

    def test_c13b_unauthorized_path_leaves_bytes_unchanged(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
        normalized_calculator_sha: str, baseline_calculator_sha: str,
        source_revision: str,
    ) -> None:
        proposal_text = _build_structured_proposal(
            "README.md", "old", "new"
        )

        target = tmp_repo / "calculator.py"
        before_bytes = target.read_bytes()
        before_sha = _sha256_bytes(before_bytes)

        result = executor.execute(
            work_contract_id="wc/c2-c13b",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision=source_revision,
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply=source_revision,
            agent_stdout=proposal_text,
        )
        assert result.success is False
        # Validation must reject the unauthorized path BEFORE applicator;
        # therefore apply_receipt is None and validation_blockers is
        # non-empty.
        assert result.apply_receipt is None
        assert any("outside declared write set" in b for b in result.validation_blockers)
        # Non-vacuous pre/post binding.
        after_bytes = target.read_bytes()
        after_sha = _sha256_bytes(after_bytes)
        assert after_sha == before_sha
        assert after_bytes == before_bytes
        assert _sha256_file(target) == baseline_calculator_sha


# ---------------------------------------------------------------------------
# C14 - Agent DONE alone cannot create terminal COMPLETED (smoke-level)
# ---------------------------------------------------------------------------


class TestAgentDoneTerminalAuthority:
    def test_c14_agent_done_simulation_does_not_imply_completion(self) -> None:
        """Smoke-level: an object that carries only DONE-shaped status has
        no terminal authority. The terminal finalizer (out-of-scope for C2)
        is expected to require verification PASS + evidence VALID +
        blockers == 0. Here we assert the canonical mutation core never
        returns ``success=True`` without an ApplyReceipt.write_count==1.
        """
        executor = GovernedMutationExecutor(
            admission_gate=MutationAdmissionGate(),
            path_gate=ExactPathMutationGate(),
            applicator=ControlledPatchApplicator(),
            parser=PatchProposalParser(),
        )
        # Empty stdout -> parse_structured returns invalid -> no success.
        result = executor.execute(
            work_contract_id="wc/c2-c14",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="REV",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=Path("."),
            expected_before_sha256_by_path={},
            current_source_revision_at_apply="REV",
            agent_stdout="",
        )
        assert result.success is False
        assert result.apply_receipt is None or result.apply_receipt.write_count == 0


# ---------------------------------------------------------------------------
# Structured proposal strictness negatives
# ---------------------------------------------------------------------------


class TestStructuredProposalStrictness:
    def test_prose_before_proposal_rejected(self, parser: PatchProposalParser) -> None:
        proposal_text = "I'll do this.\n" + _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )
        proposal = parser.parse_structured(proposal_text)
        assert proposal.valid is False
        assert "Leading prose" in (proposal.parse_error or "")

    def test_prose_after_proposal_rejected(self, parser: PatchProposalParser) -> None:
        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        ) + "Done."
        proposal = parser.parse_structured(proposal_text)
        assert proposal.valid is False
        assert "Trailing prose" in (proposal.parse_error or "")

    def test_two_proposal_blocks_rejected(self, parser: PatchProposalParser) -> None:
        proposal_text = (
            _build_structured_proposal("calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET)
            + _build_structured_proposal("calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET)
        )
        proposal = parser.parse_structured(proposal_text)
        assert proposal.valid is False

    def test_proposal_with_only_whitespace_around_is_valid(self, parser: PatchProposalParser) -> None:
        proposal_text = "\n\n  \n" + _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        ) + "   \n\n"
        proposal = parser.parse_structured(proposal_text)
        assert proposal.valid is True, proposal.parse_error

    def test_legacy_parse_structured_unified_diff_rejected(self, parser: PatchProposalParser) -> None:
        """Legacy heuristic ``parse()`` is not used on the governed path.
        ``parse_structured()`` must reject unified-diff-only output."""
        unified = (
            "--- a/calculator.py\n"
            "+++ b/calculator.py\n"
            "@@ -1 +1 @@\n"
            "-def add(a, b):\n"
            "+def add(a, b):\n"
            "+def subtract(a, b):\n"
        )
        proposal = parser.parse_structured(unified)
        assert proposal.valid is False


# ---------------------------------------------------------------------------
# Core green proof (deterministic; not real Codex)
# ---------------------------------------------------------------------------


class TestCoreGreenProof:
    def test_deterministic_proposal_applies_and_test_file_unchanged(
        self, executor: GovernedMutationExecutor, tmp_repo: Path,
        normalized_calculator_sha: str, baseline_test_sha: str,
        source_revision: str,
    ) -> None:
        proposal_text = _build_structured_proposal(
            "calculator.py", CALCULATOR_BASELINE, CALCULATOR_TARGET
        )

        # Build proposal via the canonical instruction builder as a smoke
        # check that the API used in C3 public wiring works deterministically.
        instruction = build_proposal_instruction(
            task="Add subtract(a, b) to calculator.py.",
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
        )
        assert "calculator.py" in instruction
        assert PROPOSAL_BEGIN in instruction
        assert PROPOSAL_END in instruction

        # Apply
        result = executor.execute(
            work_contract_id="wc/c2-core-green",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision=source_revision,
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=["calculator.py"],
            repository_root=tmp_repo,
            expected_before_sha256_by_path={
                "calculator.py": normalized_calculator_sha,
            },
            current_source_revision_at_apply=source_revision,
            agent_stdout=proposal_text,
        )

        assert result.success is True, result.error
        assert result.apply_receipt is not None
        assert result.apply_receipt.write_count == 1
        assert result.apply_receipt.applied_paths == ["calculator.py"]

        # The mutation target changed (compare against the normalized
        # pre-image so the comparison survives CRLF normalization on
        # write).
        after_calculator_sha = _normalized_sha256_file(tmp_repo / "calculator.py")
        assert after_calculator_sha != normalized_calculator_sha

        # The test evidence file is unchanged (raw SHA — write never
        # happened).
        assert _sha256_file(tmp_repo / "tests" / "test_calculator.py") == baseline_test_sha

        # Real GREEN: run pytest against the now-mutated fixture.
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
            cwd=str(tmp_repo),
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0, (
            f"pytest must pass after mutation; "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        assert "2 passed" in proc.stdout
        assert "test_subtract" in proc.stdout


# ---------------------------------------------------------------------------
# parse_allowed_write_paths helper contract
# ---------------------------------------------------------------------------


class TestParseAllowedWritePaths:
    def test_parses_canonical_header(self) -> None:
        text = (
            "Allowed write paths:\n"
            "- calculator.py\n"
            "- tests/test_calculator.py\n"
        )
        assert parse_allowed_write_paths(text) == [
            "calculator.py",
            "tests/test_calculator.py",
        ]

    def test_no_header_returns_empty(self) -> None:
        assert parse_allowed_write_paths("do something") == []

    def test_absolute_in_header_rejected(self) -> None:
        with pytest.raises(MutationProposalContractError):
            parse_allowed_write_paths("Allowed write paths:\n- /a.py\n")

    def test_traversal_in_header_rejected(self) -> None:
        with pytest.raises(MutationProposalContractError):
            parse_allowed_write_paths("Allowed write paths:\n- ../x.py\n")


# ---------------------------------------------------------------------------
# RQ4-R2-C2-R2 §12 — Strong truth test: interior-space path E2E
# ---------------------------------------------------------------------------


class TestInteriorSpacePathEndToEnd:
    """The two unit normalizers agreeing is necessary but not sufficient.

    This class proves the FULL mutation chain (WorkContract write path
    -> proposal FILE path -> normalized write path -> validate ->
    PathGate -> apply) actually treats an interior-space filename
    identically across every layer. The fixture file is
    ``my calculator.py``; both the WorkContract declaration and the
    structured proposal FILE line carry the same canonical path.
    """

    FIXTURE_FILENAME = "my calculator.py"
    BASELINE = "def square(x):\n    return x * x\n"
    TARGET = (
        "def square(x):\n    return x * x\n\n\n"
        "def cube(x):\n    return x * x * x\n"
    )

    def _build_repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "interior_repo"
        repo.mkdir()
        (repo / self.FIXTURE_FILENAME).write_text(self.BASELINE, encoding="utf-8")
        return repo

    def test_interior_space_filename_full_chain(
        self, executor: GovernedMutationExecutor, tmp_path: Path,
    ) -> None:
        repo = self._build_repo(tmp_path)
        target = repo / self.FIXTURE_FILENAME

        # ---- WorkContract side accepts the interior-space path ----
        from synapx_harness.evidence.command_runner import (
            normalize_write_token_path,
        )

        wc_normalized = normalize_write_token_path(
            "write:" + self.FIXTURE_FILENAME
        )
        # normalize_write_token_path strips the prefix? No — caller strips it.
        wc_normalized = normalize_write_token_path(self.FIXTURE_FILENAME)
        assert wc_normalized == self.FIXTURE_FILENAME

        # ---- Proposal side must accept and produce the same canonical form ----
        from synapx_harness.kernel.mutation_proposal_contract import (
            _normalize_repo_relative,
        )
        proposal_normalized = _normalize_repo_relative(self.FIXTURE_FILENAME)
        assert proposal_normalized == wc_normalized, (
            f"semantic divergence on {self.FIXTURE_FILENAME!r}: "
            f"workcontract={wc_normalized!r} proposal={proposal_normalized!r}"
        )

        # ---- parse_allowed_write_paths also normalizes identically ----
        task_text = (
            "Allowed write paths:\n"
            f"- {self.FIXTURE_FILENAME}\n"
        )
        parsed = parse_allowed_write_paths(task_text)
        assert parsed == [self.FIXTURE_FILENAME]
        assert parsed[0] == wc_normalized == proposal_normalized

        # ---- Full mutation chain end-to-end ----
        before_bytes = target.read_bytes()
        before_sha = _sha256_bytes(before_bytes)
        normalized_before_sha = _sha256_bytes(
            before_bytes.replace(b"\r\n", b"\n")
        )

        proposal_text = _build_structured_proposal(
            self.FIXTURE_FILENAME, self.BASELINE, self.TARGET
        )
        result = executor.execute(
            work_contract_id="wc/c2r2-interior",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="REV-C2R2-INTERIOR",
            execution_identity={"job_id": "j", "task_id": "t", "attempt_id": "a"},
            allowed_write_paths=[self.FIXTURE_FILENAME],
            repository_root=repo,
            expected_before_sha256_by_path={
                self.FIXTURE_FILENAME: normalized_before_sha,
            },
            current_source_revision_at_apply="REV-C2R2-INTERIOR",
            agent_stdout=proposal_text,
        )

        assert result.success is True, result.error
        assert result.apply_receipt is not None
        assert result.apply_receipt.write_count == 1
        assert result.apply_receipt.applied_paths == [self.FIXTURE_FILENAME]
        # The applied path MUST be the canonical (interior-space) form, not a
        # silently substituted alternative.
        assert result.apply_receipt.applied_paths[0] == self.FIXTURE_FILENAME

        # Target bytes changed (compare against the pre-image).
        after_bytes = target.read_bytes()
        after_sha = _sha256_bytes(after_bytes)
        assert after_sha != before_sha
        assert self.TARGET.encode("utf-8") in after_bytes
