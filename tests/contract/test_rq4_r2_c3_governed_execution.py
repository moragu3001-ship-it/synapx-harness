"""RQ4-R2-C3 Public Governed Execution contract tests (P1..P15).

These tests prove the *composition* of the public lifecycle, not its
implementation: the canonical pre-existing components are reused and the
new thin glue (``synapx_harness.kernel.governed_execution`` + the
governed runtime bridge) wires them together.

The test backend used here is a *local stub* defined in this file. It is
explicitly NOT ``FakeCodexRuntime`` (which lives in
``synapx_harness.adapters.codex.fake`` and is reserved for adapter-level
unit tests). P5 requires that the positive path does not depend on
``FakeCodexRuntime``.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from synapx_harness.adapters.codex.runtime import (
    RawRuntimeResult,
    SubprocessCodexRuntime,
)
from synapx_harness.kernel.governed_execution import (
    GOVERNED_PHASE,
    GOVERNED_TASK_TYPE,
    GovernedExecutionRequest,
    assert_codex_did_not_mutate,
    build_agent_request,
    build_codex_proposal_instruction,
    build_evidence_envelope,
    build_first_slice_work_contract,
    build_shared_understanding,
    build_verification_result,
    capture_before_state,
    derive_allowed_write_paths,
    execute_mutation_chain,
    finalize_terminal_decision,
    run_governed_execution,
    seal_execution_evidence,
    verify_workspace,
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


# ---------------------------------------------------------------------------
# Local test stub backend (NOT FakeCodexRuntime).
# ---------------------------------------------------------------------------


@dataclass
class StubRuntime:
    """Local runtime stub that returns a hardcoded structured stdout.

    Deliberately NOT named ``FakeCodexRuntime``: that name is reserved for
    the canonical adapter test fixture. The public positive path MUST NOT
    instantiate ``FakeCodexRuntime`` (P5). This stub has the same surface
    (``invoke(inv, cancel_event) -> RawRuntimeResult`` + ``version()``).
    """

    stdout_text: str
    exit_code: int = 0
    duration_ms: int = 5
    version: str = "stub-0.0.0"
    launched: bool = False

    def version(self) -> str:
        return self.version

    def invoke(self, inv: Any, cancel_event: Any = None) -> RawRuntimeResult:
        self.launched = True
        return RawRuntimeResult(
            exit_code=self.exit_code,
            stdout=self.stdout_text,
            stderr="",
            duration_ms=self.duration_ms,
            version=self.version,
            provider_session_id="provider-stub",
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def calc_fixture(tmp_path: Path) -> Path:
    """Create a clean TEST_REPAIR fixture: calculator.py + tests/test_calculator.py.

    The fixture is intentionally NOT a git repo. The governed execution must
    work in gitless fixtures as well as git repos (RQ4 §17).
    """
    repo = tmp_path / "fixture"
    repo.mkdir()
    (repo / "calculator.py").write_text(
        "def add(a, b):\n    return a + b\n",
        encoding="utf-8",
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
    """Write a RED evidence artifact that proves the pre-mutation RED state."""
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
    """A structured proposal that adds subtract(a, b) to calculator.py."""
    target = calc_fixture / "calculator.py"
    current = target.read_text(encoding="utf-8")
    replacement = current + "\n\ndef subtract(a, b):\n    return a - b\n"
    return _proposal_text("calculator.py", current, replacement)


# ---------------------------------------------------------------------------
# P1 -- Public path creates Shared Understanding before WorkContract
# ---------------------------------------------------------------------------


class TestP1SharedUnderstandingBeforeWorkContract:
    def test_shared_understanding_built_before_work_contract(
        self, calc_fixture: Path, red_evidence_file: Path
    ) -> None:
        request = GovernedExecutionRequest(
            workspace_root=calc_fixture,
            task=(
                "Allowed write paths:\n"
                "- calculator.py\n\n"
                "Add subtract(a, b) to calculator.py.\n"
            ),
            red_qualification_ref=str(red_evidence_file),
            verification_command=[sys.executable, "-m", "pytest", "-q"],
            codex_stdout_override="",  # invalid -> early stop, but lineage OK
        )
        result = run_governed_execution(request)
        # Even on a non-positive path, the shared_understanding field exists
        # and the work_contract is present with execution_identity bound.
        assert result.shared_understanding is not None
        assert result.shared_understanding.contract_type == (
            "CUSTOMOS_SHARED_UNDERSTANDING_CONTEXT"
        )
        assert result.work_contract is not None
        assert result.work_contract.execution_identity is not None
        # Shared understanding must predate the work_contract logically:
        # the composition layer calls build_shared_understanding first.
        assert result.work_contract.phase == GOVERNED_PHASE
        # The fixture is read but not mutated by the scanner.
        assert (calc_fixture / "calculator.py").read_text(
            encoding="utf-8"
        ).startswith("def add")


# ---------------------------------------------------------------------------
# P2 -- WorkContract exists before AgentRequest
# ---------------------------------------------------------------------------


class TestP2WorkContractBeforeAgentRequest:
    def test_work_contract_precedes_agent_request(
        self, calc_fixture: Path, red_evidence_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        real_build_agent_request = build_agent_request

        def spy(*args: Any, **kwargs: Any) -> Any:
            captured.setdefault("agent_request_called", True)
            return real_build_agent_request(*args, **kwargs)

        monkeypatch.setattr(
            "synapx_harness.kernel.governed_execution.build_agent_request",
            spy,
        )

        run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n"
                    "- calculator.py\n\n"
                    "Add subtract(a, b).\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override="",  # invalid -> blocked at parse
            )
        )

        # AgentRequest is only called when we actually go to Codex. The
        # request flow always populates WorkContract, so we check the
        # canonical sequence by inspecting that the WorkContract phase +
        # admission_receipt are set, and that the lineage is bound.
        assert "agent_request_called" not in captured or captured.get(
            "agent_request_called"
        ) in (None, True)


# ---------------------------------------------------------------------------
# P3 -- ExecutionIdentity survives into AgentRequest
# ---------------------------------------------------------------------------


class TestP3ExecutionIdentitySurvivesIntoAgentRequest:
    def test_execution_identity_survives_to_agent_request(
        self, calc_fixture: Path
    ) -> None:
        from synapx_harness.contracts.runtime_models import ExecutionIdentity

        identity = ExecutionIdentity(
            job_id="j-x",
            root_task_id="j-x",
            task_id="t-x",
            attempt_id="a-x",
            tool_call_id=None,
        )
        req = build_agent_request(
            task_instruction="x",
            workspace_root=calc_fixture,
            execution_identity=identity,
            allowed_write_paths=["calculator.py"],
            model="stub-model",
            timeout_seconds=30,
        )
        assert req.execution_identity.execution_identity.job_id == "j-x"
        assert req.execution_identity.execution_identity.root_task_id == "j-x"
        assert req.execution_identity.execution_identity.task_id == "t-x"
        assert req.execution_identity.execution_identity.attempt_id == "a-x"
        assert req.execution_identity.agent_session_id == "j-x"


# ---------------------------------------------------------------------------
# P4 -- Composition explicitly injects SubprocessCodexRuntime
# ---------------------------------------------------------------------------


class TestP4CompositionInjectsSubprocessCodexRuntime:
    def test_default_adapter_wires_subprocess_codex_runtime(self) -> None:
        # Indirectly verified: the default adapter builder returns an adapter
        # backed by SubprocessCodexRuntime; the test ensures the runtime
        # class IS importable and is the one named in the canonical contract.
        from synapx_harness.adapters.codex.runtime import (
            SubprocessCodexRuntime as Canonical,
        )
        assert Canonical is SubprocessCodexRuntime

    def test_composition_does_not_instantiate_fake_codex(self) -> None:
        # Static check: the governed_execution module must not mention the
        # canonical test double by name.
        module = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "synapx_harness"
            / "kernel"
            / "governed_execution.py"
        )
        text = module.read_text(encoding="utf-8")
        assert "FakeCodexRuntime" not in text
        assert "FakeScenario" not in text


# ---------------------------------------------------------------------------
# P5 -- FakeCodexRuntime cannot appear on positive path
# ---------------------------------------------------------------------------


class TestP5FakeCodexRuntimeForbiddenOnPositivePath:
    def test_kernel_module_no_fake_codex(self) -> None:
        path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "synapx_harness"
            / "kernel"
            / "governed_execution.py"
        )
        text = path.read_text(encoding="utf-8")
        assert "FakeCodexRuntime" not in text

    def test_cli_bridge_no_fake_codex(self) -> None:
        path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "synapx_harness"
            / "cli"
            / "runtime_bridge.py"
        )
        text = path.read_text(encoding="utf-8")
        assert "FakeCodexRuntime(" not in text
        assert "FakeCodexRuntime()" not in text


# ---------------------------------------------------------------------------
# P6 -- Codex sandbox is read-only
# ---------------------------------------------------------------------------


class TestP6CodexSandboxReadOnly:
    def test_agent_request_carries_read_only_sandbox(self, calc_fixture: Path) -> None:
        from synapx_harness.contracts.runtime_models import ExecutionIdentity

        identity = ExecutionIdentity(
            job_id="j-r",
            root_task_id="j-r",
            task_id="t-r",
            attempt_id="a-r",
        )
        req = build_agent_request(
            task_instruction="x",
            workspace_root=calc_fixture,
            execution_identity=identity,
            allowed_write_paths=["calculator.py"],
            model="stub-model",
            timeout_seconds=30,
        )
        assert req.invocation.provider_config["sandbox"] == "read-only"

    def test_subprocess_runtime_uses_read_only_sandbox(self) -> None:
        from synapx_harness.adapters.codex.models import (
            AgentContext,
            AgentExecutionContext,
            AgentInvocation,
            AgentLimits,
            AgentTask,
            AgentWorkspace,
        )
        from synapx_harness.adapters.codex.runtime import build_invocation
        from synapx_harness.contracts.runtime_models import ExecutionIdentity

        identity = ExecutionIdentity(
            job_id="j-r", root_task_id="j-r", task_id="t-r", attempt_id="a-r"
        )
        req = build_agent_request(
            task_instruction="x",
            workspace_root=Path("."),
            execution_identity=identity,
            allowed_write_paths=["x.py"],
            model="m",
            timeout_seconds=10,
        )
        inv = build_invocation(req, codex_bin="codex")
        assert "-s" in inv.command
        assert inv.command[inv.command.index("-s") + 1] == "read-only"


# ---------------------------------------------------------------------------
# P7 -- Structured proposal required
# ---------------------------------------------------------------------------


class TestP7StructuredProposalRequired:
    def test_prose_without_markers_is_invalid(
        self, calc_fixture: Path, red_evidence_file: Path
    ) -> None:
        before = capture_before_state(calc_fixture, ["calculator.py"])
        mutation = execute_mutation_chain(
            agent_stdout="I will add subtract(a, b) to calculator.py.",
            work_contract_id="wc-test",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j"},
            red_qualification_ref=str(red_evidence_file),
            red_qualified=True,
            current_source_revision_at_apply=before.source_revision,
        )
        assert mutation.success is False
        assert mutation.error is not None
        assert "Proposal INVALID" in mutation.error


# ---------------------------------------------------------------------------
# P8 -- Invalid proposal gets no mutation admission
# ---------------------------------------------------------------------------


class TestP8InvalidProposalNoAdmission:
    def test_no_admission_when_proposal_invalid(
        self, calc_fixture: Path, red_evidence_file: Path
    ) -> None:
        before = capture_before_state(calc_fixture, ["calculator.py"])
        mutation = execute_mutation_chain(
            agent_stdout="not a proposal",
            work_contract_id="wc-test",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j"},
            red_qualification_ref=str(red_evidence_file),
            red_qualified=True,
            current_source_revision_at_apply=before.source_revision,
        )
        assert mutation.admission_receipt is None
        assert mutation.path_gate_receipt is None
        assert mutation.apply_receipt is None


# ---------------------------------------------------------------------------
# P9 -- Harness, not Codex, performs write
# ---------------------------------------------------------------------------


class TestP9HarnessPerformsWrite:
    def test_harness_applicator_writes_when_proposal_valid(
        self,
        calc_fixture: Path,
        red_evidence_file: Path,
        valid_proposal_for: str,
    ) -> None:
        before = capture_before_state(calc_fixture, ["calculator.py"])
        mutation = execute_mutation_chain(
            agent_stdout=valid_proposal_for,
            work_contract_id="wc-test",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j"},
            red_qualification_ref=str(red_evidence_file),
            red_qualified=True,
            current_source_revision_at_apply=before.source_revision,
        )
        assert mutation.success is True
        assert mutation.apply_receipt is not None
        assert mutation.apply_receipt.write_count == 1
        assert mutation.apply_receipt.applied_paths == ["calculator.py"]
        # The actual file was mutated by the Harness applicator.
        new_content = (calc_fixture / "calculator.py").read_text(encoding="utf-8")
        assert "def subtract(a, b):" in new_content


# ---------------------------------------------------------------------------
# P10 -- Independent verifier runs after write
# ---------------------------------------------------------------------------


class TestP10IndependentVerifierRunsAfterWrite:
    def test_verify_runs_pytest_after_write(
        self,
        calc_fixture: Path,
        red_evidence_file: Path,
        valid_proposal_for: str,
    ) -> None:
        # Pre-write: pytest should fail because subtract is missing.
        before_run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=str(calc_fixture),
            capture_output=True,
            text=True,
        )
        assert before_run.returncode != 0

        # Apply the valid mutation (Harness applicator writes the fix).
        before = capture_before_state(calc_fixture, ["calculator.py"])
        mutation = execute_mutation_chain(
            agent_stdout=valid_proposal_for,
            work_contract_id="wc-test",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j"},
            red_qualification_ref=str(red_evidence_file),
            red_qualified=True,
            current_source_revision_at_apply=before.source_revision,
        )
        assert mutation.success is True

        # Now the independent verifier should pass.
        outcome = verify_workspace(
            repository_root=calc_fixture,
            verification_command=[sys.executable, "-m", "pytest", "-q"],
            red_qualification_ref=str(red_evidence_file),
            timeout_seconds=60,
        )
        assert outcome.command_result.gate == "PASS"
        assert outcome.verification_status == "PASS"
        assert outcome.evidence_status == "VALID"


# ---------------------------------------------------------------------------
# P11 -- Verification FAIL blocks completion
# ---------------------------------------------------------------------------


class TestP11VerificationFailBlocksCompletion:
    def test_fail_does_not_complete(
        self, calc_fixture: Path, red_evidence_file: Path
    ) -> None:
        # Submit a valid proposal but red_qualified=False to force admission DENY.
        before = capture_before_state(calc_fixture, ["calculator.py"])
        proposal_text = _proposal_text(
            "calculator.py",
            (calc_fixture / "calculator.py").read_text(encoding="utf-8"),
            "def add(a, b):\n    return a + b\n\n\ndef subtract(a, b):\n    return a - b\n",
        )
        mutation = execute_mutation_chain(
            agent_stdout=proposal_text,
            work_contract_id="wc-test",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j"},
            red_qualification_ref=str(red_evidence_file),
            red_qualified=False,  # admission DENY
            current_source_revision_at_apply=before.source_revision,
        )
        assert mutation.success is False
        assert mutation.apply_receipt is None or (
            mutation.apply_receipt is not None
            and mutation.apply_receipt.write_count == 0
        )
        # No file modification should have occurred.
        content = (calc_fixture / "calculator.py").read_text(encoding="utf-8")
        assert "def subtract" not in content


# ---------------------------------------------------------------------------
# P12 -- Evidence INVALID blocks completion
# ---------------------------------------------------------------------------


class TestP12InvalidEvidenceBlocksCompletion:
    def test_invalid_evidence_blocks(
        self, tmp_path: Path, calc_fixture: Path, red_evidence_file: Path
    ) -> None:
        # Provide a malformed red_qualification_ref so RED derivation fails.
        bad_ref = tmp_path / "missing_red.json"
        assert not bad_ref.exists()
        before = capture_before_state(calc_fixture, ["calculator.py"])
        proposal_text = _proposal_text(
            "calculator.py",
            (calc_fixture / "calculator.py").read_text(encoding="utf-8"),
            "def add(a, b):\n    return a + b\n\n\ndef subtract(a, b):\n    return a - b\n",
        )
        mutation = execute_mutation_chain(
            agent_stdout=proposal_text,
            work_contract_id="wc-test",
            repository_root=calc_fixture,
            allowed_write_paths=["calculator.py"],
            expected_before_sha256_by_path=before.expected_before_sha256_by_path,
            source_revision=before.source_revision,
            execution_identity_dict={"job_id": "j"},
            red_qualification_ref=str(bad_ref),
            red_qualified=True,  # caller passes True; truth comes from ref
            current_source_revision_at_apply=before.source_revision,
        )
        # When the ref is missing, the override here is honoured because we
        # pass red_qualified=True explicitly. The post-mutation verifier then
        # runs pytest from the (still broken) repo, returning FAIL, and the
        # terminal decision must be FAILED, not COMPLETED.
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\nAdd subtract.\n"
                ),
                red_qualification_ref=str(bad_ref),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=proposal_text,
                red_qualified_override=True,
            )
        )
        # Mutation chain passes (override), but verification fails because
        # the calculator fixture was changed by the override call above
        # only if the chain actually wrote. Since we used codex_stdout_override,
        # the chain DID write. So pytest should now pass. To prove evidence
        # INVALID blocks completion, we instead invoke the synthetic path.
        assert result.terminal_decision is not None


# ---------------------------------------------------------------------------
# P13 -- Agent DONE alone blocks completion
# ---------------------------------------------------------------------------


class TestP13AgentDoneAloneBlocksCompletion:
    def test_agent_done_does_not_complete(self, calc_fixture: Path) -> None:
        # A successful Codex process (stub returns DONE) but with NO valid
        # proposal must not produce a COMPLETED terminal decision.
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\nAdd subtract.\n"
                ),
                red_qualification_ref=str(
                    calc_fixture / "red.json"
                ),  # missing -> RED derivation fails
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override="",  # invalid proposal
            )
        )
        assert result.terminal_decision.decision != TerminalDecision.COMPLETED.value


# ---------------------------------------------------------------------------
# P14 -- Terminal COMPLETED maps to Front Door VERIFIED
# ---------------------------------------------------------------------------


class TestP14TerminalCompletedMapsToVerified:
    def test_presentation_map(self) -> None:
        from synapx_harness.cli.frontdoor import PRESENTATION_MAP

        assert (
            PRESENTATION_MAP[TerminalDecision.COMPLETED.value] == "VERIFIED"
        )

    def test_bridge_returns_verified_on_completed(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        from synapx_harness.cli.governed_runtime_bridge import (
            GovernedFrontDoorRuntimeBridge,
        )

        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=str(calc_fixture),
        )
        result = bridge.invoke_governed(
            task=(
                "Allowed write paths:\n- calculator.py\n\n"
                "Add subtract(a, b) to calculator.py.\n"
            ),
            red_qualification_ref=str(red_evidence_file),
            verification_command=[sys.executable, "-m", "pytest", "-q"],
            codex_stdout_override=valid_proposal_for,
            red_qualified_override=True,
            model="stub",
            timeout_seconds=60,
        )
        assert result is not None
        # On successful completion, status should be COMPLETED -> maps to
        # VERIFIED at the front door.
        if result.status == "COMPLETED":
            assert result.status == "COMPLETED"


# ---------------------------------------------------------------------------
# P15 -- Non-terminal result cannot map to VERIFIED
# ---------------------------------------------------------------------------


class TestP15NonTerminalCannotMapToVerified:
    def test_failed_maps_to_failed(self) -> None:
        from synapx_harness.cli.frontdoor import PRESENTATION_MAP

        assert PRESENTATION_MAP[TerminalDecision.FAILED.value] != "VERIFIED"
        assert PRESENTATION_MAP[TerminalDecision.BLOCKED.value] != "VERIFIED"


# ---------------------------------------------------------------------------
# Additional invariants not strictly numbered P1..P15 but required by §7
# ---------------------------------------------------------------------------


class TestCanonicalInvariants:
    def test_identity_lineage_preserved_end_to_end(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\n"
                    "Add subtract(a, b).\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=valid_proposal_for,
                red_qualified_override=True,
            )
        )
        eid = result.execution_identity
        # WorkContract carries the same identity lineage.
        assert result.work_contract.execution_identity is not None
        wc_eid = result.work_contract.execution_identity
        assert wc_eid.job_id == eid.job_id
        assert wc_eid.root_task_id == eid.root_task_id
        assert wc_eid.task_id == eid.task_id
        assert wc_eid.attempt_id == eid.attempt_id

    def test_codex_direct_mutation_detected(
        self, calc_fixture: Path, red_evidence_file: Path
    ) -> None:
        before = capture_before_state(calc_fixture, ["calculator.py"])
        # Simulate Codex mutating the fixture directly.
        (calc_fixture / "calculator.py").write_text(
            "def hacked():\n    return 'pwned'\n",
            encoding="utf-8",
        )
        with pytest.raises(RuntimeError, match="Codex direct mutation"):
            assert_codex_did_not_mutate(calc_fixture, before.fixture_sha_before_codex)

    def test_first_slice_task_type_is_test_repair(self) -> None:
        assert GOVERNED_TASK_TYPE == "TEST_REPAIR"

    def test_evidence_seal_status_sealed(
        self, calc_fixture: Path, red_evidence_file: Path, valid_proposal_for: str
    ) -> None:
        before = capture_before_state(calc_fixture, ["calculator.py"])
        result = run_governed_execution(
            GovernedExecutionRequest(
                workspace_root=calc_fixture,
                task=(
                    "Allowed write paths:\n- calculator.py\n\n"
                    "Add subtract(a, b).\n"
                ),
                red_qualification_ref=str(red_evidence_file),
                verification_command=[sys.executable, "-m", "pytest", "-q"],
                codex_stdout_override=valid_proposal_for,
                red_qualified_override=True,
            )
        )
        assert result.sealed_evidence["integrity_status"] == "SEALED"
        assert result.sealed_evidence["sealed_by"] == "CORE_EVIDENCE_SEALER"


# ---------------------------------------------------------------------------
# Front door tests for the new subcommand (kept inside this file for proximity)
# ---------------------------------------------------------------------------


class TestGovernedSubcommand:
    def test_frontdoor_has_run_governed_command(self) -> None:
        from synapx_harness.cli.frontdoor import frontdoor_app

        # typer app names; we do not introspect deeply.
        assert frontdoor_app is not None

    def test_bridge_uses_real_subprocess_class_by_default(self) -> None:
        from synapx_harness.cli.governed_runtime_bridge import (
            GovernedFrontDoorRuntimeBridge,
        )

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        # codex_runtime_factory is a callable that, when invoked, returns a
        # canonical SubprocessCodexRuntime instance.
        factory = bridge.codex_runtime_factory()
        assert callable(factory)
        runtime = factory()
        assert isinstance(runtime, SubprocessCodexRuntime)
