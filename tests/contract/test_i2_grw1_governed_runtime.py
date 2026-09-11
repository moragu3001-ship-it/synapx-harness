"""I2-GRW1-R2 Governed Runtime Integration Tests.

Real semantic mutation negatives with runtime binding verification.
All tests use deterministic fake workers (no real Codex required).

Authority semantics:
  - Agent DONE ≠ Verification PASS (VerificationPort is independent)
  - Provider returns terminal vocabulary (COMPLETED/FAILED/BLOCKED)
  - Presentation mapping (COMPLETED→VERIFIED) is Lane A Front Door only
  - Shared Understanding is SHA-bound via explicit re-hash (no assert)
  - AgentResult identity is bound to provider-issued identity
  - RUN_STORAGE_ACTIVE=true → REJECT
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
import typer

from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario
from synapx_harness.adapters.codex.models import (
    AgentContext,
    AgentExecutionContext,
    AgentInvocation,
    AgentLimits,
    AgentOutput,
    AgentRequest,
    AgentResult,
    AgentStatus,
    ProcessResult,
    ProviderMeta,
)
from synapx_harness.cli.frontdoor import PresentationResult, _map_to_presentation, run
from synapx_harness.context.models import (
    AssertionRecord,
    RepositoryBinding,
    SharedUnderstandingContext,
    UnknownRecord,
)
from synapx_harness.contracts.runtime_models import (
    ExecutionIdentity,
    VerificationResult,
    build_execution_identity,
)
from synapx_harness.evidence.evidence_validator import (
    CORE_EVIDENCE_SEALER,
    seal_as_terminal_decision,
    seal_evidence,
)
from synapx_harness.kernel.governed_runtime_provider import (
    FailClosedVerificationPort,
    FakeVerificationPort,
    GovernedRuntimeProvider,
    _canonical_json_bytes,
    _sha256_hex,
    verify_agent_result_identity,
    verify_shared_context_binding,
)
from synapx_harness.kernel.terminal_finalizer import (
    FORBIDDEN_TERMINAL_ISSUERS,
    TERMINAL_FINALIZER_ISSUER,
    advance_agent_claim,
    finalize,
    finalize_from_agent_done,
    finalize_from_sealed_evidence,
    issue_terminal_decision,
)
from synapx_harness.kernel.verification_planner import (
    classify_admission_outcome,
    plan,
    promote_pass_to_completed,
)

CORE_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_identity(
    job_id: str = "job/test",
    task_id: str = "task/test",
    root_task_id: str = "root/test",
    attempt_id: str = "attempt/test",
) -> ExecutionIdentity:
    return build_execution_identity(
        job_id=job_id,
        task_id=task_id,
        root_task_id=root_task_id,
        attempt_id=attempt_id,
    )


def _make_agent_result(
    status: AgentStatus = AgentStatus.DONE,
    identity: ExecutionIdentity | None = None,
    stdout: str = "ok",
    exit_code: int = 0,
) -> AgentResult:
    if identity is None:
        identity = _make_identity()
    return AgentResult(
        status=status,
        execution_identity=AgentExecutionContext(
            execution_identity=identity,
            agent_session_id="session/test",
        ),
        provider=ProviderMeta(name="fake", model="fake"),
        process=ProcessResult(exit_code=exit_code, duration_ms=10),
        output=AgentOutput(stdout=stdout, stderr=""),
    )


def _make_sealed_evidence(work_contract_id: str = "WC-TEST") -> dict[str, object]:
    envelope: dict[str, object] = {
        "contract_type": "CUSTOMOS_EVIDENCE_ENVELOPE",
        "schema_version": "0.1.0",
        "work_contract_id": work_contract_id,
        "integrity_status": "ADMITTED",
    }
    return seal_evidence(
        envelope=envelope,
        sealer=CORE_EVIDENCE_SEALER,
        redaction_applied=True,
    )


def _make_work_contract_dict(
    work_contract_id: str = "WC-TEST",
    attempt_index: int = 0,
) -> dict[str, object]:
    return {
        "contract_type": "CUSTOMOS_WORK_CONTRACT",
        "schema_version": "0.2.0",
        "work_contract_id": work_contract_id,
        "phase": "TEST",
        "risk_class": "R0",
        "objective": "test",
        "scope": ["test"],
        "attempt_index": attempt_index,
    }


def _make_shared_context() -> SharedUnderstandingContext:
    return SharedUnderstandingContext(
        repository=RepositoryBinding(repository_id="test"),
        facts=[],
        assertions=[
            AssertionRecord(
                key="test_key",
                value="test_value",
                source="test",
                provenance="test",
                repository_revision="rev",
            ),
        ],
        unknowns=[
            UnknownRecord(
                key="unknown_key",
                reason="NOT_OBSERVED",
                source="test",
                provenance="test",
                repository_revision="rev",
            ),
        ],
    )


def _make_agent_request_with_context(
    identity: ExecutionIdentity,
    shared_context: SharedUnderstandingContext,
) -> AgentRequest:
    from synapx_harness.adapters.codex.models import (
        AgentInvocation,
        AgentLimits,
        AgentTask,
        AgentWorkspace,
    )

    canonical_dict = shared_context.model_dump(mode="json")
    canonical_bytes = _canonical_json_bytes(canonical_dict)
    context_sha256 = _sha256_hex(canonical_bytes)

    return AgentRequest(
        execution_identity=AgentExecutionContext(
            execution_identity=identity,
            agent_session_id=f"session/{identity.attempt_id}",
        ),
        workspace=AgentWorkspace(root="/tmp"),
        task=AgentTask(instruction="test"),
        context=AgentContext(
            canonical_context_ref=f"sha256:{context_sha256}",
            optional_payload={
                "shared_understanding": canonical_dict,
                "sha256": context_sha256,
            },
        ),
        limits=AgentLimits(timeout_seconds=30),
        invocation=AgentInvocation(provider="fake", model="fake"),
    )


# ---------------------------------------------------------------------------
# P01 — Positive Runtime Trace (Front Door E2E)
# ---------------------------------------------------------------------------


class TestP01PositiveRuntimeTrace:
    """Full governed runtime path via Front Door E2E."""

    def test_frontdoor_e2e_produces_verified(self, tmp_path: Path, capsys) -> None:
        """Actual frontdoor.run() with provider → VERIFIED in stdout."""
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(verification_status="PASS"),
        )
        try:
            run(task="test task", runtime=provider)
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "VERIFIED" in output

    def test_provider_returns_terminal_vocabulary(self, tmp_path: Path) -> None:
        """Provider returns COMPLETED (not VERIFIED) — Lane A maps it."""
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(verification_status="PASS"),
        )
        result = provider.invoke("test task")
        assert isinstance(result, PresentationResult)
        assert result.status == "COMPLETED"
        assert result.status != "VERIFIED"

    def test_lane_a_maps_presentation_result_to_verified(self) -> None:
        """Frozen Lane A mapping: PresentationResult(COMPLETED) → VERIFIED."""
        assert _map_to_presentation(PresentationResult("COMPLETED")) == "VERIFIED"

    def test_raw_string_not_mapped_to_verified(self) -> None:
        """Raw string is not a PresentationResult → NEEDS_ATTENTION."""
        assert _map_to_presentation("COMPLETED") == "NEEDS_ATTENTION"

    def test_fail_closed_without_verifier(self, tmp_path: Path) -> None:
        """No verifier → FAIL CLOSED → BLOCKED (active_blocker)."""
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=None,
        )
        result = provider.invoke("test")
        assert result is not None
        assert result.status == "BLOCKED"


# ---------------------------------------------------------------------------
# N01 — Agent DONE without independent VerificationPort
# ---------------------------------------------------------------------------


class TestN01AgentDoneWithoutVerification:
    """AgentResult DONE + no VerificationPort → NOT VERIFIED."""

    def test_fail_closed_verifier_rejects_done(self) -> None:
        verifier = FailClosedVerificationPort()
        agent_result = _make_agent_result(status=AgentStatus.DONE)
        wc = _make_work_contract_dict()
        context = _make_shared_context()
        result = verifier.verify(wc, agent_result, context)
        assert result.verification_status == "FAIL"
        assert result.evidence_status == "INVALID"
        assert result.active_blocker_count == 1

    def test_done_not_directly_promoted_to_pass(self) -> None:
        agent_result = _make_agent_result(status=AgentStatus.DONE)
        assert agent_result.status == AgentStatus.DONE
        verifier = FailClosedVerificationPort()
        wc = _make_work_contract_dict()
        context = _make_shared_context()
        vr = verifier.verify(wc, agent_result, context)
        assert vr.verification_status != "PASS"

    def test_done_cannot_finalize_to_terminal(self) -> None:
        with pytest.raises(ValueError, match="agent done claim cannot be finalized"):
            finalize_from_agent_done("WC-TEST", {"claim_type": "AGENT_DONE_CLAIM"})


# ---------------------------------------------------------------------------
# N02 — Codex exit 0 with VerificationPort FAIL
# ---------------------------------------------------------------------------


class TestN02Exit0VerificationFail:
    """exit_code=0 but VerificationPort returns FAIL → Terminal FAILED."""

    def test_verification_fail_produces_failed_terminal(self) -> None:
        verification = plan(
            work_contract_id="WC-TEST",
            verification_status="FAIL",
            evidence_status="INVALID",
            active_blocker_count=0,
        )
        terminal = finalize(verification)
        assert terminal.decision == "FAILED"

    def test_provider_with_failing_verifier(self, tmp_path: Path) -> None:
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(
                verification_status="FAIL",
                evidence_status="INVALID",
            ),
        )
        result = provider.invoke("test")
        assert result is not None
        assert result.status == "FAILED"


# ---------------------------------------------------------------------------
# N03 — Malformed AgentResult
# ---------------------------------------------------------------------------


class TestN03MalformedAgentResult:
    """Malformed AgentResult → NEEDS_ATTENTION / fail closed."""

    def test_malformed_result_rejected(self) -> None:
        with pytest.raises(ValueError):
            AgentResult(
                status=cast(Any, "NOT_A_REAL_STATUS"),
                execution_identity=AgentExecutionContext(
                    execution_identity=_make_identity(),
                    agent_session_id="s",
                ),
                provider=ProviderMeta(name="x", model="y"),
                output=AgentOutput(stdout="", stderr=""),
            )

    def test_none_result_maps_to_attention(self) -> None:
        result = _map_to_presentation(None)
        assert result == "NEEDS_ATTENTION"


# ---------------------------------------------------------------------------
# N04 — ASSERTION → AUTHORITY injection (real payload mutation)
# ---------------------------------------------------------------------------


class TestN04AssertionAuthorityInjection:
    """ASSERTION with authority field injection → context binding mismatch.

    Real mutation: modify AgentRequest.context.payload after construction,
    keeping embedded SHA unchanged. verify_shared_context_binding re-hashes
    the actual payload and detects the mismatch.
    """

    def test_control_binding_passes(self) -> None:
        context = _make_shared_context()
        identity = _make_identity()
        request = _make_agent_request_with_context(identity, context)
        sha = verify_shared_context_binding(context, request)
        assert isinstance(sha, str) and len(sha) == 64

    def test_mutation_assertion_to_fact_rejected(self) -> None:
        """Mutate assertion kind to FACT in payload, keep embedded SHA."""
        context = _make_shared_context()
        identity = _make_identity()
        request = _make_agent_request_with_context(identity, context)

        # Mutate: change assertion kind to FACT
        payload = request.context.optional_payload
        shared = dict(payload["shared_understanding"])
        mutated_assertions = [dict(a) for a in shared["assertions"]]
        mutated_assertions[0]["kind"] = "FACT"
        shared["assertions"] = mutated_assertions
        payload["shared_understanding"] = shared
        # Keep payload["sha256"] unchanged

        with pytest.raises(ValueError, match="CONTEXT_BINDING_MISMATCH"):
            verify_shared_context_binding(context, request)

    def test_mutation_authority_field_injection_rejected(self) -> None:
        """Inject authority field into assertion, keep embedded SHA."""
        context = _make_shared_context()
        identity = _make_identity()
        request = _make_agent_request_with_context(identity, context)

        # Mutate: add authority field to assertion
        payload = request.context.optional_payload
        shared = dict(payload["shared_understanding"])
        mutated_assertions = [dict(a) for a in shared["assertions"]]
        mutated_assertions[0]["authority"] = "INJECTED"
        shared["assertions"] = mutated_assertions
        payload["shared_understanding"] = shared

        with pytest.raises(ValueError, match="CONTEXT_BINDING_MISMATCH"):
            verify_shared_context_binding(context, request)


# ---------------------------------------------------------------------------
# N05 — UNKNOWN → FACT promotion (real payload mutation)
# ---------------------------------------------------------------------------


class TestN05UnknownToFactPromotion:
    """UNKNOWN record promoted to FACT in payload → context binding mismatch."""

    def test_control_binding_passes(self) -> None:
        context = _make_shared_context()
        identity = _make_identity()
        request = _make_agent_request_with_context(identity, context)
        sha = verify_shared_context_binding(context, request)
        assert isinstance(sha, str)

    def test_mutation_unknown_to_fact_rejected(self) -> None:
        """Move UNKNOWN to facts list in payload, keep embedded SHA."""
        context = _make_shared_context()
        identity = _make_identity()
        request = _make_agent_request_with_context(identity, context)

        # Mutate: move unknown to facts
        payload = request.context.optional_payload
        shared = dict(payload["shared_understanding"])
        unknown = shared["unknowns"][0]
        shared["facts"] = list(shared.get("facts", [])) + [
            {"kind": "FACT", "key": unknown["key"], "value": None,
             "source": unknown["source"], "provenance": unknown["provenance"],
             "repository_revision": unknown["repository_revision"]}
        ]
        shared["unknowns"] = []
        payload["shared_understanding"] = shared

        with pytest.raises(ValueError, match="CONTEXT_BINDING_MISMATCH"):
            verify_shared_context_binding(context, request)


# ---------------------------------------------------------------------------
# N06 — Evidence missing
# ---------------------------------------------------------------------------


class TestN06EvidenceMissing:
    """Verification PASS but evidence missing → NOT COMPLETED."""

    def test_missing_evidence_blocks_finalization(self) -> None:
        terminalization_input: dict[str, object] = {
            "execution_identity": _make_identity().model_dump(mode="json"),
            "work_contract_id": "WC-TEST",
            "verification_admission_receipt": {},
            "sealed_evidence": {},
            "source_revision_ref": {},
            "active_blocker_count": 0,
            "proposed_outcome": "COMPLETED",
        }
        with pytest.raises(ValueError, match="sealed evidence required"):
            finalize_from_sealed_evidence(
                sealed_evidence={"integrity_status": "ADMITTED"},
                terminalization_input=terminalization_input,
            )


# ---------------------------------------------------------------------------
# N07 — Evidence malformed
# ---------------------------------------------------------------------------


class TestN07EvidenceMalformed:
    """Evidence malformed → NOT COMPLETED."""

    def test_malformed_evidence_rejected(self) -> None:
        with pytest.raises(ValueError, match="envelope must be a dict"):
            seal_evidence(
                envelope=cast(Any, "not a dict"),
                sealer=CORE_EVIDENCE_SEALER,
                redaction_applied=True,
            )

    def test_unsealed_evidence_not_terminal(self) -> None:
        with pytest.raises(ValueError, match="sealed evidence is not a terminal"):
            seal_as_terminal_decision(
                {"integrity_status": "SEALED", "data": "test"}
            )


# ---------------------------------------------------------------------------
# N08 — Raw/non-conforming injection into Front Door
# ---------------------------------------------------------------------------


class TestN08RawInjection:
    """Raw string/dict injection into Front Door → NEEDS_ATTENTION.

    Actual frontdoor.run() with a fake runtime returning non-PresentationResult.
    """

    def test_raw_string_via_frontdoor(self, tmp_path: Path, capsys) -> None:
        """Fake runtime returns raw string → NEEDS_ATTENTION."""

        class RawStringRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str):
                return "COMPLETED"

        try:
            run(task="test", runtime=cast(Any, RawStringRuntime()))
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "NEEDS_ATTENTION" in output

    def test_dict_via_frontdoor(self, tmp_path: Path, capsys) -> None:
        """Fake runtime returns dict → NEEDS_ATTENTION."""

        class DictRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str):
                return {"decision": "COMPLETED"}

        try:
            run(task="test", runtime=cast(Any, DictRuntime()))
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "NEEDS_ATTENTION" in output

    def test_governed_provider_completes_maps_to_verified(self) -> None:
        result = _map_to_presentation(PresentationResult("COMPLETED"))
        assert result == "VERIFIED"


# ---------------------------------------------------------------------------
# N09 — _runs authority isolation (storage API poison test)
# ---------------------------------------------------------------------------


class TestN09RunsAuthorityIsolation:
    """_runs storage API must NOT be consulted during governed runtime.

    Monkeypatch storage census API to raise AssertionError.
    If provider calls it, test fails. If not, terminal COMPLETED.
    """

    def test_storage_api_not_consulted(self, tmp_path: Path) -> None:
        """Provider must not consult _runs storage API."""
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(verification_status="PASS"),
        )

        # Poison: if storage census is called, it will raise
        with patch(
            "synapx_harness.storage.census.build_catalog",
            side_effect=AssertionError("_runs must not be consulted"),
        ):
            result = provider.invoke("test")

        assert result is not None
        assert result.status == "COMPLETED"

    def test_terminal_authority_source_is_finalizer(self) -> None:
        """Terminal authority source is always TERMINAL_FINALIZER."""
        terminal = issue_terminal_decision(
            work_contract_id="WC-TEST",
            decision="COMPLETED",
            issued_by=TERMINAL_FINALIZER_ISSUER,
            terminalization_input={
                "execution_identity": _make_identity().model_dump(mode="json"),
                "work_contract_id": "WC-TEST",
                "verification_admission_receipt": {},
                "sealed_evidence": _make_sealed_evidence(),
                "source_revision_ref": {},
                "active_blocker_count": 0,
                "proposed_outcome": "COMPLETED",
            },
        )
        assert terminal["issued_by"] == TERMINAL_FINALIZER_ISSUER

    def test_forbidden_issuers_rejected(self) -> None:
        for issuer in FORBIDDEN_TERMINAL_ISSUERS:
            with pytest.raises(ValueError, match="forbidden"):
                issue_terminal_decision(
                    work_contract_id="WC-TEST",
                    decision="COMPLETED",
                    issued_by=issuer,
                )


# ---------------------------------------------------------------------------
# N10 — RUN_STORAGE_ACTIVE=true
# ---------------------------------------------------------------------------


class TestN10RunStorageActiveReject:
    """RUN_STORAGE_ACTIVE=true → REJECT at construction time."""

    def test_run_storage_active_true_rejects(self, tmp_path: Path) -> None:
        """Actual RUN_STORAGE_ACTIVE=true → ValueError."""
        with pytest.raises(ValueError, match="RUN_STORAGE_ACTIVE_NOT_AUTHORIZED"):
            GovernedRuntimeProvider(
                tmp_path,
                run_storage_active=True,
            )

    def test_run_storage_active_false_allows(self, tmp_path: Path) -> None:
        """RUN_STORAGE_ACTIVE=false (default) → provider works."""
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(verification_status="PASS"),
        )
        result = provider.invoke("test")
        assert result is not None
        assert result.status == "COMPLETED"

    def test_default_run_storage_is_false(self, tmp_path: Path) -> None:
        """Default constructor has run_storage_active=False."""
        provider = GovernedRuntimeProvider(tmp_path)
        assert provider is not None


# ---------------------------------------------------------------------------
# N11 — AgentResult identity mismatch
# ---------------------------------------------------------------------------


class TestN11AgentResultIdentityMismatch:
    """AgentResult identity != provider-issued identity → REJECT.

    Real mutation: monkeypatch adapter to return AgentResult with
    different attempt_id. verify_agent_result_identity rejects
    BEFORE VerificationPort is called.
    """

    def test_control_identity_binding_passes(self) -> None:
        identity = _make_identity(attempt_id="attempt/A")
        result = _make_agent_result(identity=identity)
        verify_agent_result_identity(identity, result)

    def test_attempt_id_mismatch_rejected(self) -> None:
        expected = _make_identity(attempt_id="attempt/A")
        actual_result = _make_agent_result(
            identity=_make_identity(attempt_id="attempt/B")
        )
        with pytest.raises(ValueError, match="AGENT_RESULT_IDENTITY_MISMATCH"):
            verify_agent_result_identity(expected, actual_result)

    def test_job_id_mismatch_rejected(self) -> None:
        expected = _make_identity(job_id="job/A")
        actual_result = _make_agent_result(
            identity=_make_identity(job_id="job/B")
        )
        with pytest.raises(ValueError, match="AGENT_RESULT_IDENTITY_MISMATCH"):
            verify_agent_result_identity(expected, actual_result)

    def test_identity_mismatch_blocks_verification(self, tmp_path: Path) -> None:
        """Identity mismatch → VerificationPort never called."""
        call_count = 0

        class CountingVerificationPort:
            def verify(self, work_contract, agent_result, shared_context):
                nonlocal call_count
                call_count += 1
                return VerificationResult(
                    work_contract_id="WC-TEST",
                    verification_status="PASS",
                    evidence_status="VALID",
                    active_blocker_count=0,
                )

        # Create a backend that returns mismatched identity

        class MismatchBackend:
            def version(self):
                return "fake"

            def invoke(self, inv, cancel_event):
                from synapx_harness.adapters.codex.runtime import RawRuntimeResult

                return RawRuntimeResult(
                    exit_code=0,
                    stdout="ok",
                    stderr="",
                    duration_ms=10,
                )

        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=MismatchBackend(),
            verifier=CountingVerificationPort(),
        )

        # The provider-issued identity will have a different attempt_id
        # than what we'd expect, but the adapter returns the provider's
        # own identity. The mismatch test needs a different approach:
        # monkeypatch the adapter to return a different identity.
        original_execute = provider._adapter.execute

        def patched_execute(request):
            result = original_execute(request)
            # Return a new result with different attempt_id
            return AgentResult(
                status=result.status,
                execution_identity=AgentExecutionContext(
                    execution_identity=_make_identity(attempt_id="attempt/TAMPERED"),
                    agent_session_id="session/tampered",
                ),
                provider=result.provider,
                process=result.process,
                output=result.output,
                failure=result.failure,
            )

        provider._adapter.execute = patched_execute

        with pytest.raises(ValueError, match="AGENT_RESULT_IDENTITY_MISMATCH"):
            provider.invoke("test")

        assert call_count == 0


# ---------------------------------------------------------------------------
# Authority boundary tests
# ---------------------------------------------------------------------------


class TestAuthorityBoundary:
    """Authority isolation verification."""

    def test_frontdoor_no_terminal_imports(self) -> None:
        frontdoor_path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py"
        content = frontdoor_path.read_text(encoding="utf-8")
        assert "terminal_finalizer" not in content
        assert "build_terminal_decision" not in content

    def test_terminal_finalizer_sole_issuer(self) -> None:
        with pytest.raises(ValueError, match="not the terminal finalizer"):
            issue_terminal_decision(
                work_contract_id="WC-TEST",
                decision="COMPLETED",
                issued_by="NotTerminalFinalizer",
            )

    def test_verification_pass_not_direct_to_terminal(self) -> None:
        with pytest.raises(ValueError, match="PASS cannot be promoted"):
            promote_pass_to_completed("PASS", "VALID", 0)

    def test_direct_pass_classification_rejected(self) -> None:
        with pytest.raises(ValueError, match="direct PASS classification"):
            classify_admission_outcome("PASS", "VALID", 0)

    def test_agent_claim_only_to_verifying(self) -> None:
        claim: dict[str, object] = {"claim_type": "AGENT_DONE_CLAIM", "state": "DONE"}
        with pytest.raises(ValueError, match="may only transition to VERIFYING"):
            advance_agent_claim(claim, "COMPLETED")

    def test_evidence_sealer_not_terminal(self) -> None:
        with pytest.raises(ValueError, match="sealer must be"):
            seal_evidence(
                envelope={"integrity_status": "ADMITTED"},
                sealer="TERMINAL_FINALIZER",
                redaction_applied=True,
            )

    def test_redaction_required_before_seal(self) -> None:
        with pytest.raises(ValueError, match="redaction must be applied"):
            seal_evidence(
                envelope={"integrity_status": "ADMITTED"},
                sealer=CORE_EVIDENCE_SEALER,
                redaction_applied=False,
            )

    def test_provider_returns_terminal_not_presentation(self, tmp_path: Path) -> None:
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(verification_status="PASS"),
        )
        result = provider.invoke("test")
        assert result is not None
        assert result.status in ("COMPLETED", "FAILED", "BLOCKED")
        assert result.status != "VERIFIED"


# ---------------------------------------------------------------------------
# I3-D2 — Configured Real-Worker Routing through GovernedRuntimeProvider
#
# RED (before repair): these tests FAIL because GRP hard-codes
# provider="fake-provider", model="fake-model" and drops provider_config /
# limits (I3_D2_01_R1_DEFECT_DISCLOSURE: ACTUAL_GRP_INVOKE_BYPASSED).
# GREEN (after repair): lossless propagation of the configured invocation.
# ---------------------------------------------------------------------------


class _SpyBackend:
    """Observation-only wrapper (spy): records RuntimeInvocation, never
    changes the execution path."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.invocations: list = []

    def invoke(self, inv, cancel_event):
        self.invocations.append(inv)
        return self.inner.invoke(inv, cancel_event)

    def version(self):
        return self.inner.version()


def _make_configured_invocation() -> AgentInvocation:
    return AgentInvocation(
        provider="beellama-i3",
        model="qwen3.8-27b",
        provider_config={"profile": "i3-qwen", "sandbox": "read-only"},
    )


class TestD2ConfiguredRealWorkerRouting:
    """Configured real-worker routing: GRP -> AgentRequest.invocation
    -> CodexAdapter/build_invocation, lossless."""

    def _provider(
        self,
        tmp_path: Path,
        spy: _SpyBackend,
        invocation: AgentInvocation | None = None,
        limits: AgentLimits | None = None,
    ) -> GovernedRuntimeProvider:
        return GovernedRuntimeProvider(
            tmp_path,
            backend=spy,
            verifier=FakeVerificationPort(verification_status="PASS"),
            invocation=invocation,
            limits=limits,
        )

    def test_r01_configured_provider_propagates(self, tmp_path: Path) -> None:
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = self._provider(tmp_path, spy, invocation=_make_configured_invocation())
        provider.invoke("test task")
        assert spy.invocations, "Codex invocation must be captured"
        assert spy.invocations[0].provider == "beellama-i3"

    def test_r02_configured_model_propagates(self, tmp_path: Path) -> None:
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = self._provider(tmp_path, spy, invocation=_make_configured_invocation())
        provider.invoke("test task")
        assert spy.invocations[0].model == "qwen3.8-27b"

    def test_r03_profile_propagates(self, tmp_path: Path) -> None:
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = self._provider(tmp_path, spy, invocation=_make_configured_invocation())
        provider.invoke("test task")
        assert spy.invocations[0].provider_config.get("profile") == "i3-qwen"

    def test_r04_sandbox_propagates(self, tmp_path: Path) -> None:
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = self._provider(tmp_path, spy, invocation=_make_configured_invocation())
        provider.invoke("test task")
        assert spy.invocations[0].provider_config.get("sandbox") == "read-only"

    def test_r05_profile_in_invocation_argv(self, tmp_path: Path) -> None:
        """GRP-produced invocation argv must contain --profile <configured>."""
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = self._provider(tmp_path, spy, invocation=_make_configured_invocation())
        provider.invoke("test task")
        argv = spy.invocations[0].command
        assert "--profile" in argv
        assert "i3-qwen" in argv
        assert "qwen3.8-27b" in argv
        assert "read-only" in argv

    def test_r06_configured_limits_propagate(self, tmp_path: Path) -> None:
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = self._provider(
            tmp_path,
            spy,
            invocation=_make_configured_invocation(),
            limits=AgentLimits(timeout_seconds=900),
        )
        provider.invoke("test task")
        assert spy.invocations[0].timeout_seconds == 900


class TestD2NoProductHardcoding:
    """G06-G09: no I3-specific values may be hard-coded in product source."""

    _GRP_SOURCE = CORE_ROOT / "src" / "synapx_harness" / "kernel" / "governed_runtime_provider.py"

    def test_g06_no_i3_qwen_hardcoded(self) -> None:
        src = self._GRP_SOURCE.read_text(encoding="utf-8")
        assert "i3-qwen" not in src

    def test_g07_no_beellama_hardcoded(self) -> None:
        src = self._GRP_SOURCE.read_text(encoding="utf-8")
        assert "beellama-i3" not in src

    def test_g08_no_qwen_model_hardcoded(self) -> None:
        src = self._GRP_SOURCE.read_text(encoding="utf-8")
        assert "qwen3.8-27b" not in src

    def test_g09_no_endpoint_hardcoded(self) -> None:
        src = self._GRP_SOURCE.read_text(encoding="utf-8")
        assert "192.168.0.216" not in src


class TestD2BackwardCompatibility:
    """G10: default Fake path must remain fully compatible."""

    def test_g10_default_fake_path_completes(self, tmp_path: Path) -> None:
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS),
            verifier=FakeVerificationPort(verification_status="PASS"),
        )
        result = provider.invoke("test")
        assert result is not None
        assert result.status == "COMPLETED"

    def test_g10b_default_fake_uses_fake_provider(self, tmp_path: Path) -> None:
        spy = _SpyBackend(FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
        provider = GovernedRuntimeProvider(
            tmp_path,
            backend=spy,
            verifier=FakeVerificationPort(verification_status="PASS"),
        )
        provider.invoke("test")
        assert spy.invocations[0].provider == "fake-provider"
        assert spy.invocations[0].model == "fake-model"
