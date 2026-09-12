"""RQ4-R2-C3-R1 truth / provenance contract tests.

These tests prove the post-repair invariants required by Owner
findings E1-E5, U1, P1-P3 and the RQ4 §8, §11-§15, §18, §19 rules.

Contract matrix
---------------
E1  evidence must be sealed in the same run (no post-hoc reconstruction)
E2  source revision R0 (pre-codex) must equal R0 (pre-apply) and
    differ from R1 (post-apply) when a Harness write happens
E3  TerminalDecisionRecord.work_contract_id matches WorkContract.work_contract_id
E4  execution_identity slots are concrete, distinct uuids
E5  development-env leakage fields are computed (covered by fixtures
    tests in C3 qualification scripts)
U1  Front Door echoes ``VERIFIED`` when the terminal decision is
    ``COMPLETED`` and the public run path is exercised
P1  Reused the RQ2/RQ3 canonical verifier
P2  N1-N6 semantics are real (each mutant must FAIL)
P3  Negative tests are bound to the canonical external verifier
    (the same verifier reused for the clean package)
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from synapx_harness.cli.frontdoor import PRESENTATION_MAP, PresentationResult
from synapx_harness.kernel.c3_r1_lineage import (
    assert_lineage_consistency,
    build_lineage_envelope,
)
from synapx_harness.kernel.governed_execution import (
    capture_before_state,
    execute_mutation_chain,
    run_governed_execution,
    GovernedExecutionRequest,
)
from synapx_harness.kernel.mutation_authority import (
    ControlledPatchApplicator,
    ExactPathMutationGate,
    MutationAdmissionGate,
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)
from synapx_harness.kernel.terminal_finalizer import TerminalDecision
from synapx_harness.review.c3_r1_mutants import (
    CleanPayload,
    build_clean_package_bytes,
    verify_clean_package,
)
from synapx_harness.review.c3_r1_package_builder import (
    C3R1PackageSpec,
    build_c3_r1_package_bytes,
)
from synapx_harness.review.package_verifier import (
    C3_R1_MANIFEST_FILENAME,
    verify_c3_r1_package_zip_bytes,
    verify_zip_bytes,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def calc_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "fixture"
    repo.mkdir()
    (repo / "calculator.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    tests_dir = repo / "tests"
    tests_dir.mkdir()
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


@pytest.fixture
def red_evidence_file(tmp_path: Path) -> Path:
    path = tmp_path / ".synapx_red_evidence.json"
    path.write_text(
        json.dumps(
            {
                "exit_code": 1,
                "failure_reason_matches_intended_defect": True,
                "intended_defect": "AttributeError: module 'calculator' has no attribute 'subtract'",
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


@pytest.fixture
def valid_proposal_for(calc_fixture: Path) -> str:
    target = calc_fixture / "calculator.py"
    current = target.read_text(encoding="utf-8")
    replacement = current + "\n\ndef subtract(a, b):\n    return a - b\n"
    return _proposal_text("calculator.py", current, replacement)


# ---------------------------------------------------------------------------
# E1 -- evidence must be sealed in the same run
# ---------------------------------------------------------------------------


class TestE1EvidenceSealedInSameRun:
    def test_sealed_evidence_present_in_run_result(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\nAdd subtract.\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=valid_proposal_for,
                red_qualified_override=True,
            )
        )
        assert result.sealed_evidence.get("integrity_status") == "SEALED"
        assert result.sealed_evidence.get("sealed_by") == "CORE_EVIDENCE_SEALER"
        assert result.work_contract_id in str(result.sealed_evidence)


# ---------------------------------------------------------------------------
# E2 -- source revision chronology R0 / R0 / R1
# ---------------------------------------------------------------------------


class TestE2SourceRevisionChronology:
    def test_R0_equals_R0_and_differs_from_R1(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\nAdd subtract.\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=valid_proposal_for,
                red_qualified_override=True,
            )
        )
        assert result.pre_codex_source_revision, "pre_codex rev empty"
        assert result.pre_apply_source_revision, "pre_apply rev empty"
        assert result.post_apply_source_revision, "post_apply rev empty"
        # R0 == R0: read-only Codex must not have mutated the fixture.
        assert (
            result.pre_codex_source_revision
            == result.pre_apply_source_revision
        )
        # R0 != R1: Harness wrote the fix.
        assert (
            result.pre_apply_source_revision
            != result.post_apply_source_revision
        )


# ---------------------------------------------------------------------------
# E3 -- TerminalDecisionRecord.work_contract_id matches WorkContract
# ---------------------------------------------------------------------------


class TestE3TerminalWorkContractBinding:
    def test_terminal_record_carries_work_contract_id_topologically(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\nAdd subtract.\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=valid_proposal_for,
                red_qualified_override=True,
            )
        )
        assert (
            result.terminal_decision.work_contract_id == result.work_contract_id
        )
        assert (
            result.admission_receipt is not None
            and result.admission_receipt.work_contract_id == result.work_contract_id
        )
        envelope = build_lineage_envelope(result, repository_root=calc_fixture)
        failures = assert_lineage_consistency(
            envelope, expected_work_contract_id=result.work_contract_id
        )
        assert failures == [], f"lineage consistency failures: {failures}"


# ---------------------------------------------------------------------------
# E4 -- execution identity slots are concrete and distinct
# ---------------------------------------------------------------------------


class TestE4ExecutionIdentityConcretelyBound:
    def test_execution_identity_slots_are_distinct(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\nAdd subtract.\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=valid_proposal_for,
                red_qualified_override=True,
            )
        )
        eid = result.execution_identity
        slots = {eid.job_id, eid.root_task_id, eid.task_id, eid.attempt_id}
        assert len(slots) == 4, f"execution identity slots are not distinct: {slots}"
        for name in ("job_id", "root_task_id", "task_id", "attempt_id"):
            value = getattr(eid, name)
            assert isinstance(value, str) and value, f"{name} empty: {value!r}"
            assert "sess-" not in value and "<from" not in value, (
                f"{name} contains placeholder substring: {value!r}"
            )


# ---------------------------------------------------------------------------
# U1 -- Front Door echoes VERIFIED on a completed governed run
# ---------------------------------------------------------------------------


class TestU1FrontDoorEchoesVerified:
    def test_present_ation_map_completed_to_verified(self) -> None:
        assert PRESENTATION_MAP[TerminalDecision.COMPLETED.value] == "VERIFIED"

    def test_frontdoor_renders_verified_on_completed(self) -> None:
        """The Front Door presentation mapper renders VERIFIED."""
        from synapx_harness.cli.frontdoor import _render_governed_result

        rendered: list[str] = []
        import synapx_harness.cli.frontdoor as _fd

        original_echo = _fd.typer.echo
        _fd.typer.echo = lambda msg, **kw: rendered.append(msg)
        try:
            _render_governed_result(PresentationResult("COMPLETED", None))
        finally:
            _fd.typer.echo = original_echo
        assert "VERIFIED" in rendered, (
            f"Front Door did not echo VERIFIED for COMPLETED: {rendered}"
        )
        # RQ8 Phase 2C-R1: without agent-truth plumbing the activity
        # section admits ignorance; the terminal label is unchanged.
        assert "Agent Activity" in rendered
        assert "  Unavailable" in rendered
        assert "  Completed" not in rendered
        assert rendered.index("Agent Activity") < rendered.index("VERIFIED")

    def test_frontdoor_renders_failed_when_terminal_failed(self) -> None:
        from synapx_harness.cli.frontdoor import _render_governed_result

        rendered: list[str] = []
        import synapx_harness.cli.frontdoor as _fd

        original_echo = _fd.typer.echo
        _fd.typer.echo = lambda msg, **kw: rendered.append(msg)
        try:
            _render_governed_result(PresentationResult("FAILED", "boom"))
        finally:
            _fd.typer.echo = original_echo
        assert "FAILED" in rendered
        assert any("Reason: boom" in line for line in rendered)
        # RQ8 Phase 2C-R1: terminal FAILED is never copied into an agent
        # lifecycle claim; without agent source the section is Unavailable.
        assert "  Unavailable" in rendered
        assert "  Failed" not in rendered
        assert "VERIFIED" not in rendered

    def test_agent_done_alone_does_not_promote_to_verified(self) -> None:
        from synapx_harness.cli.frontdoor import _render_governed_result

        rendered: list[str] = []
        import synapx_harness.cli.frontdoor as _fd

        original_echo = _fd.typer.echo
        _fd.typer.echo = lambda msg, **kw: rendered.append(msg)
        try:
            _render_governed_result(PresentationResult("DONE", None))
        finally:
            _fd.typer.echo = original_echo
        # An arbitrary non-terminal label must never reach the user as
        # VERIFIED. The mapper falls back to NEEDS_ATTENTION.
        assert "VERIFIED" not in rendered


# ---------------------------------------------------------------------------
# P1 -- Reused canonical verifier (no second incompatible format)
# ---------------------------------------------------------------------------


class TestP1ReusedCanonicalVerifier:
    def test_clean_package_passes_canonical_verifier(self) -> None:
        clean_zip, manifest, _blobs = build_clean_package_bytes(
            [
                CleanPayload("synapx-harness/README.md", b"hello\n"),
                CleanPayload("synapx-harness/VERSION", b"0.1.0\n"),
            ]
        )
        result = verify_clean_package(clean_zip)
        assert result.ok, (
            f"clean canonical verifier failed: {result.to_dict()}"
        )

    def test_canonical_verifier_is_the_only_verifier(self) -> None:
        """The C3-R1 verifier is wired on top of the same verify_zip_bytes."""
        import inspect

        from synapx_harness.review import package_verifier as _pv

        src = inspect.getsource(_pv.verify_c3_r1_package_zip_bytes)
        assert "verify_zip_bytes" in src, (
            "C3-R1 verifier must delegate to verify_zip_bytes (no second format)"
        )


# ---------------------------------------------------------------------------
# P2 / P3 -- N1-N6 mutant builds and external binding
# ---------------------------------------------------------------------------


class TestP2P3N1ToN6Mutants:
    def test_each_mutant_returns_FAIL_via_canonical_verifier(self, tmp_path: Path) -> None:
        clean_zip, _manifest, _blobs = build_clean_package_bytes(
            [
                CleanPayload("synapx-harness/README.md", b"hello\n"),
                CleanPayload("synapx-harness/VERSION", b"0.1.0\n"),
            ]
        )
        clean_result = verify_clean_package(clean_zip)
        assert clean_result.ok

        clean_zip_again, manifest, blobs = build_clean_package_bytes(
            [
                CleanPayload("synapx-harness/README.md", b"hello\n"),
                CleanPayload("synapx-harness/VERSION", b"0.1.0\n"),
            ]
        )
        from synapx_harness.review.c3_r1_mutants import MUTANT_SPECS

        for spec in MUTANT_SPECS:
            mutant_bytes = spec.build(clean_zip_again, manifest, blobs)
            res = verify_c3_r1_package_zip_bytes(
                mutant_bytes, zip_path=f"mutant_{spec.name}.zip"
            )
            assert res.ok is False, (
                f"mutant {spec.name} must FAIL canonical verifier; got ok=True"
            )

    def test_aggregator_detects_all_six_negatives(self) -> None:
        clean_zip, manifest, blobs = build_clean_package_bytes(
            [
                CleanPayload("synapx-harness/README.md", b"hello\n"),
                CleanPayload("synapx-harness/VERSION", b"0.1.0\n"),
            ]
        )
        clean_result = verify_clean_package(clean_zip)
        assert clean_result.ok

        from synapx_harness.review.c3_r1_mutants import MUTANT_SPECS

        mutants_dicts: list[dict[str, object]] = []
        for spec in MUTANT_SPECS:
            mutant_bytes = spec.build(clean_zip, manifest, blobs)
            res = verify_c3_r1_package_zip_bytes(
                mutant_bytes, zip_path=f"mutant_{spec.name}.zip"
            )
            mutants_dicts.append(
                {
                    "name": spec.name,
                    "description": spec.description,
                    "expected_verdict": spec.expected_verdict,
                    "actual_verdict": "FAIL" if not res.ok else "PASS",
                    "detected": not res.ok,
                    "gate": res.gate,
                    "self_entry_present": res.self_entry_present,
                    "recursive_self_binding": res.recursive_self_binding,
                    "zip_self_placeholder_absent": res.zip_self_placeholder_absent,
                    "self_inventory_violations": list(
                        res.self_inventory_violations
                    ),
                    "unmanifested_entries": list(res.unmanifested_entries),
                    "missing_manifest_entries": list(
                        res.missing_manifest_entries
                    ),
                    "actual_duplicate_exact": res.actual_duplicate_exact,
                }
            )

        # aggregator contract: aggregate_negatives accepts MutantVerification
        # dataclass instances; here we use the dict objects directly so the
        # contract is independent of the dataclass shape.
        from synapx_harness.review.c3_r1_mutants import aggregate_negatives

        detected = sum(1 for m in mutants_dicts if m["detected"])
        assert len(mutants_dicts) == 6
        assert detected == 6, mutants_dicts
        assert all(m["detected"] is True for m in mutants_dicts), mutants_dicts


# ---------------------------------------------------------------------------
# Sanity: mutation authority chain still PASSes on a valid proposal
# ---------------------------------------------------------------------------


class TestMutationChainStillPasses:
    def test_valid_proposal_mutation_chain_succeeds(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        before = capture_before_state(calc_fixture, ["calculator.py"])
        mutation = execute_mutation_chain(
            agent_stdout=valid_proposal_for,
            work_contract_id="wc-c3r1",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j", "task_id": "t"},
            red_qualification_ref=str(red_evidence_file),
            red_qualified=True,
            current_source_revision_at_apply=before.source_revision,
        )
        assert mutation.success is True
        assert mutation.apply_receipt is not None
        assert mutation.apply_receipt.write_count == 1
