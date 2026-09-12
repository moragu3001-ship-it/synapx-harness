"""RQ8-P1-R3-R1 authority binding tests (bounded, test-first).

Covers RQ8-P1-R3-R1 Sec 25 pre-repair failures (F1-F5), Sec 6/7 binding
invariants, Sec 9-12 controlled observation, Sec 15/16 sealed and receipt
bindings, and Sec 18 non-bypass pins.

Import discipline: this file imports ONLY pre-existing modules so it
collects both pre-repair (e684cf20) and post-repair. New R3-R1 names are
resolved with explicit getattr gates whose assertion messages name the
missing authority piece; pre-repair they FAIL (never collection-error),
post-repair they pass.
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
        "expectation_id": "test/r3r1/expectation/v1",
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


def _run(repo: Path, *, proposal: str):  # -> GovernedExecutionResult
    return run_governed_execution(
        GovernedExecutionRequest(
            workspace_root=repo,
            task=CALC_TASK,
            verification_command=list(VERIFICATION_COMMAND),
            codex_stdout_override=proposal,
        )
    )


def _wc_model_fields() -> dict[str, object]:
    from synapx_harness.contracts.runtime_models import WorkContract

    fields = getattr(WorkContract, "model_fields", None)
    assert isinstance(fields, dict), "F1: WorkContract has no model_fields"
    assert "red_policy" in fields, "F1: WorkContract lacks red_policy"
    assert "red_expectation" in fields, (
        "F1: WorkContract lacks red_expectation binding"
    )
    return fields


# ---------------------------------------------------------------------------
# F1 -- WorkContract binding (Sec 6/7)
# ---------------------------------------------------------------------------


class TestWorkContractBinding:
    def test_binding_fields_exist(self) -> None:
        _wc_model_fields()

    def test_builder_binds_staged_expectation(self, tmp_path: Path) -> None:
        import synapx_harness.kernel.governed_execution as gov

        build = getattr(
            gov, "build_first_slice_work_contract", None
        )
        assert callable(build), "F1: builder missing"
        repo = _write_calc_repo(tmp_path / "b", broken=True)
        staged = _stage_expectation(
            repo, fingerprint=_fp(VERIFICATION_COMMAND)
        )
        blob = staged.read_bytes()
        wc: Any = None
        try:
            wc = build(
                work_contract_id="wc-bind",
                task=CALC_TASK,
                allowed_write_paths=["calculator.py"],
                execution_identity=_identity(),
                source_revision="rev",
                shared_understanding=_shared(repo),
                red_expectation_binding=_binding_dict(staged, blob),
            )
        except TypeError as exc:
            pytest.fail(f"F1: builder accepts no expectation binding: {exc}")
        assert wc is not None
        assert wc.red_policy == "RED_REQUIRED"
        assert wc.red_expectation is not None
        assert wc.red_expectation.expectation_sha256 == hashlib.sha256(
            blob
        ).hexdigest()

    def test_cross_workcontract_reuse_denied(self, tmp_path: Path) -> None:
        """Sec 7: WC-A binds E; the same bytes presented without WC-B's
        binding must NOT authorize (scripted staging-after-build)."""
        import synapx_harness.kernel.governed_execution as gov

        reader = getattr(gov, "_read_expectation_bytes", None)
        assert callable(reader), "F1: no single expectation reader to script"
        repo = _write_calc_repo(tmp_path / "xwc", broken=True)
        staged = _stage_expectation(
            repo, fingerprint=_fp(VERIFICATION_COMMAND)
        )
        blob = staged.read_bytes()
        calls: list[str] = []
        real_reader: Any = reader

        def scripted(path: Path) -> bytes:
            calls.append(str(path))
            if len(calls) == 1:
                raise FileNotFoundError(str(path))
            result_bytes: bytes = real_reader(path)
            return result_bytes

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(gov, "_read_expectation_bytes", scripted)
        try:
            result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))
        finally:
            monkeypatch.undo()
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert len(calls) >= 1
        assert blob == staged.read_bytes()

    def test_post_build_modification_denied(self, tmp_path: Path) -> None:
        """Sec 6: bytes differing from the bound hash (changed after build
        or swapped file) DENY via the binding check."""
        import synapx_harness.kernel.governed_execution as gov

        reader = getattr(gov, "_read_expectation_bytes", None)
        assert callable(reader), "F1: no single expectation reader to script"
        repo = _write_calc_repo(tmp_path / "swap", broken=True)
        staged = _stage_expectation(
            repo, fingerprint=_fp(VERIFICATION_COMMAND)
        )
        assert staged.is_file()
        real_reader: Any = reader

        def scripted(path: Path) -> bytes:
            raw: bytes = real_reader(path)
            data = json.loads(raw.decode("utf-8"))
            data["required_failed_test_ids"] = ["tests/test_x.py::test_y"]
            return json.dumps(data).encode("utf-8")

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(gov, "_read_expectation_bytes", scripted)
        try:
            result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))
        finally:
            monkeypatch.undo()
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert "None" not in str(result.errors[0])


def _identity():  # -> ExecutionIdentity
    from synapx_harness.contracts.runtime_models import ExecutionIdentity

    return ExecutionIdentity(
        job_id="job-t",
        task_id="task-t",
        root_task_id="root-t",
        attempt_id="att-t",
    )


def _shared(repo: Path):  # -> SharedUnderstandingContext
    from synapx_harness.context.models import RepositoryBinding, SharedUnderstandingContext

    return SharedUnderstandingContext(
        repository=RepositoryBinding(repository_id="test-repo"),
    )


def _binding_dict(path: Path, blob: bytes) -> dict[str, object]:
    data = json.loads(blob.decode("utf-8"))
    return {
        "expectation_id": data["expectation_id"],
        "expectation_version": data["expectation_version"],
        "expectation_ref": path.as_posix(),
        "expectation_sha256": hashlib.sha256(blob).hexdigest(),
    }


# ---------------------------------------------------------------------------
# F2 -- controlled observation receipt (Sec 9-12)
# ---------------------------------------------------------------------------


def _r2_mismatch_run(tmp_path, name="mm"):
    """R3-R2 helper: qualified expectation + actual TEST_FAILURE with
    wrong IDs so the comparator runs, produces mismatch evidence, and
    admission DENYs (Sec 5/7/14)."""
    repo = _write_calc_repo(tmp_path / name, broken=True)
    _stage_expectation(
        repo,
        fingerprint=_fp(VERIFICATION_COMMAND),
        failed_ids=["tests/test_other.py::test_elsewhere"],
    )
    return _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))


class TestControlledObservation:
    def test_observation_references_command_receipt(
        self, tmp_path: Path
    ) -> None:
        """F2: positive-run evidence carries a controlled command receipt
        binding (receipt id + refs), not a bare subprocess outcome."""
        repo = _write_calc_repo(tmp_path / "obs", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))
        evidence = getattr(result, "red_qualification_evidence", None)
        assert evidence is not None, "F2: no qualification evidence produced"
        receipt_id = getattr(evidence, "command_receipt_id", "")
        assert isinstance(receipt_id, str) and receipt_id, (
            "F2: evidence carries no command receipt binding"
        )
        assert result.terminal_decision.decision == "COMPLETED"

    def test_observation_denied_without_command_authority(
        self, tmp_path: Path
    ) -> None:
        """Missing controlled command authority -> OBSERVATION NOT_RUN ->
        DENY. A scope without the verifier tool must refuse."""
        from synapx_harness.evidence.command_runner import run_controlled

        repo = _write_calc_repo(tmp_path / "noauth", broken=True)
        bare_contract = {
            "work_contract_id": "wc-noauth",
            "risk_class": "R0",
            "issuer": "HARNESS_CORE_ADMISSION",
            "scope": ["phase:public_governed", "tool:something-else"],
        }
        with pytest.raises(ValueError, match="work contract|admitted|scope"):
            run_controlled(
                "uv run pytest -q",
                bare_contract,
                cwd=repo,
                timeout=60,
            )

    def test_r3r2_mismatch_evidence_on_result(self, tmp_path):
        """R3-R2 Sec 4/5: mismatch evidence stays on the runtime result."""
        result = _r2_mismatch_run(tmp_path)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.red_qualification_evidence is not None
        assert result.red_qualification_evidence.match_result is False

    def test_r3r2_mismatch_evidence_sealed(self, tmp_path):
        """R3-R2 Sec 4/5/12: mismatch evidence is sealed under one identity."""
        result = _r2_mismatch_run(tmp_path)
        sealed = result.sealed_evidence
        assert isinstance(sealed, dict) and sealed
        qualification = sealed.get("red_qualification")
        assert isinstance(qualification, dict)
        assert (
            qualification.get("qualification_id")
            == result.red_qualification_evidence.qualification_id
        )

    def test_r3r2_mismatch_evidence_in_receipt(self, tmp_path):
        """R3-R2 Sec 4/13: same-run receipt projects mismatch evidence."""
        result = _r2_mismatch_run(tmp_path)
        projected = result.to_dict().get("red_qualification_evidence")
        assert isinstance(projected, dict)
        assert (
            projected.get("qualification_id")
            == result.red_qualification_evidence.qualification_id
        )

    def test_r3r2_mismatch_truth_chain(self, tmp_path):
        """R3-R2 Sec 7/17: first-failure truth with evidence preserved."""
        result = _r2_mismatch_run(tmp_path)
        assert result.mutation_attempted is False
        assert result.verification_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert result.errors
        assert result.errors[0] == result.primary_failure_message
        assert "None" not in str(result.errors[0])

    def test_r3r2_mismatch_receipt_sealed(self, tmp_path):
        """R3-R2 Sec 8/11/12: actual controlled receipt is sealed and
        carries the same command identity as the qualification."""
        result = _r2_mismatch_run(tmp_path, "mmr")
        sealed = result.sealed_evidence
        receipt = sealed.get("red_observation_receipt")
        assert isinstance(receipt, dict)
        evidence = result.red_qualification_evidence
        assert (
            receipt.get("command_id") == evidence.command_receipt_id
        )
        assert receipt.get("command_id")

    def test_r3r2_receipt_hashes_match_persisted_files(self, tmp_path):
        """R3-R2 Sec 9/16: sealed stdout/stderr sha equals persisted
        file bytes (the observer hashed at write time)."""
        import hashlib as _hashlib

        result = _r2_mismatch_run(tmp_path, "mmh")
        sealed = result.sealed_evidence
        receipt = sealed.get("red_observation_receipt")
        assert isinstance(receipt, dict)
        for stream in ("stdout_artifact", "stderr_artifact"):
            artifact = receipt.get(stream)
            assert isinstance(artifact, dict), f"missing {stream}"
            ref = artifact.get("ref")
            assert isinstance(ref, str) and ref
            data = Path(ref).read_bytes()
            assert _hashlib.sha256(data).hexdigest() == artifact.get(
                "sha256"
            ), f"Sec 9: {stream} sha does not match persisted file"
            assert artifact.get("size_bytes") == len(data)

    def test_r3r2_positive_receipt_sealed(self, tmp_path):
        """R3-R2 Sec 13: positive run also seals the actual receipt."""
        repo = _write_calc_repo(tmp_path / "pr", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))
        assert result.terminal_decision.decision == "COMPLETED"
        sealed = result.sealed_evidence
        receipt = sealed.get("red_observation_receipt")
        assert isinstance(receipt, dict)
        evidence = result.red_qualification_evidence
        assert (
            receipt.get("command_id") == evidence.command_receipt_id
        )
        projected = result.to_dict().get("red_observation_receipt")
        assert isinstance(projected, dict)
        assert projected.get("command_id") == evidence.command_receipt_id


# ---------------------------------------------------------------------------
# F3/F4 -- sealed envelope and same-run receipt (Sec 15/16)
# ---------------------------------------------------------------------------


class TestSealedAndReceiptBinding:
    def _positive(self, tmp_path: Path):  # -> GovernedExecutionResult
        repo = _write_calc_repo(tmp_path / "seal", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))
        assert result.terminal_decision.decision == "COMPLETED"
        return result

    def test_f3_sealed_envelope_carries_qualification(
        self, tmp_path: Path
    ) -> None:
        """F3: sealed evidence embeds the qualification under one identity."""
        result = self._positive(tmp_path)
        sealed = result.sealed_evidence
        assert isinstance(sealed, dict) and sealed, "F3: no sealed evidence"
        qualification = sealed.get("red_qualification")
        assert isinstance(qualification, dict), (
            "F3: sealed evidence carries no red_qualification"
        )
        evidence = result.red_qualification_evidence
        assert (
            qualification.get("qualification_id")
            == evidence.qualification_id
        ), "F3: sealed/envelope identity mismatch"

    def test_f4_same_run_receipt_carries_qualification(
        self, tmp_path: Path
    ) -> None:
        """F4: to_dict projects the same qualification identity (no replay)."""
        result = self._positive(tmp_path)
        projected = result.to_dict().get("red_qualification_evidence")
        assert isinstance(projected, dict), (
            "F4: same-run receipt carries no red qualification projection"
        )
        assert (
            projected.get("qualification_id")
            == result.red_qualification_evidence.qualification_id
        ), "F4: receipt/runtime identity mismatch"
        assert projected.get("match_result") is True


# ---------------------------------------------------------------------------
# F5 -- seed provenance correction (Sec 20)
# ---------------------------------------------------------------------------


class TestSeedProvenanceCorrection:
    def test_f5_patch_hash_never_binds_revision(self) -> None:
        """F5: informational seed-artifact fields must neither satisfy nor
        disturb the revision binding. A payload carrying ONLY a patch
        hash (no source_revision) must reject; extras alongside a proper
        binding must load untouched."""
        try:
            from synapx_harness.kernel.red_qualification import (
                ExpectationError,
                QualifiedRedExpectation,
            )
        except ImportError:
            pytest.fail("F5: comparator module absent pre-repair")
        base: dict[str, object] = {
            "expectation_id": "x",
            "expectation_version": 1,
            "status": "QUALIFIED",
            "source_type": "BENCHMARK_FIXTURE",
            "verification_command_fingerprint": "f" * 64,
            "expected_exit_code": 1,
            "match_rule": "EXACT_FAILED_TEST_IDS",
            "required_failed_test_ids": ["tests/test_a.py::test_1"],
            "provenance": {"source_ref": "r", "source_sha256": "s"},
        }
        patch_only = dict(base)
        patch_only["seed_artifact_sha256"] = "1" * 64
        with pytest.raises(ExpectationError):
            QualifiedRedExpectation.from_dict(patch_only)
        bound = dict(base)
        bound["source_revision"] = "r" * 64
        bound["seed_artifact_sha256"] = "1" * 64
        loaded = QualifiedRedExpectation.from_dict(bound)
        assert loaded.source_revision == "r" * 64


# ---------------------------------------------------------------------------
# Schema/code drift pin (Sec 24)
# ---------------------------------------------------------------------------


class TestWorkContractSchemaAlignment:
    def test_bound_contract_validates_against_schema(
        self, tmp_path: Path
    ) -> None:
        """A first-slice WorkContract carrying the RED binding validates
        against work_contract.schema.json (schema never weaker than code)."""
        import synapx_harness.kernel.governed_execution as gov
        from synapx_harness.validators.schema_validator import (
            validate_payload,
        )

        build = getattr(gov, "build_first_slice_work_contract", None)
        assert callable(build), "builder missing"
        repo = _write_calc_repo(tmp_path / "schema", broken=True)
        staged = _stage_expectation(
            repo, fingerprint=_fp(VERIFICATION_COMMAND)
        )
        wc: Any = build(
            work_contract_id="wc-schema",
            task=CALC_TASK,
            allowed_write_paths=["calculator.py"],
            execution_identity=_identity(),
            source_revision="rev",
            shared_understanding=_shared(repo),
            red_expectation_binding=_binding_dict(
                staged, staged.read_bytes()
            ),
        )
        core_root = Path(__file__).resolve().parents[2]
        report = validate_payload(
            package_root=core_root,
            schema_relative_path="runtime/work_contract.schema.json",
            payload=wc.model_dump(mode="json"),
        )
        assert report.ok, report.errors
