"""Governed Runtime Provider (I2-GRW1-R2).

Main-owned integration orchestrator that wires the full governed runtime
path from Front Door to Terminal Finalizer. This is the SOLE integration
owned module; lane implementations are NOT modified.

Canonical path:
  Admission → Execution Identity → Shared Understanding → Work Input
  → Codex Adapter → AgentResult → Identity Binding → VerificationPort
  → Evidence → Terminal Finalizer → Presentation Projection

Authority separation:
  - Agent DONE ≠ Verification PASS (VerificationPort is independent)
  - Terminal outcome is DERIVED, not hardcoded
  - Provider returns terminal vocabulary (COMPLETED/FAILED/BLOCKED),
    NOT presentation vocabulary (VERIFIED). Presentation mapping
    is performed by frozen Lane A Front Door only.
  - Shared Understanding bytes are SHA-bound to AgentRequest.context
    via explicit re-hash verification (not Python assert)
  - AgentResult identity is bound to provider-issued identity
  - RUN_STORAGE_ACTIVE gate: true → REJECT (fail-closed)

Lane B _runs is NOT used as terminal authority.
RUN_STORAGE_ACTIVE = false (default, enforced).
"""
from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Protocol

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario
from synapx_harness.adapters.codex.models import (
    AgentContext,
    AgentExecutionContext,
    AgentInvocation,
    AgentLimits,
    AgentRequest,
    AgentResult,
    AgentTask,
    AgentWorkspace,
)
from synapx_harness.cli.frontdoor import PresentationResult
from synapx_harness.context.models import SharedUnderstandingContext
from synapx_harness.context.scanner import DeterministicRepositoryScanner
from synapx_harness.contracts.runtime_models import (
    ExecutionIdentity,
    VerificationResult,
    build_execution_identity,
    compute_content_tree_hash,
)
from synapx_harness.evidence.evidence_validator import (
    CORE_EVIDENCE_SEALER,
    seal_evidence,
)
from synapx_harness.kernel.terminal_finalizer import (
    finalize_terminal_chain,
)
from synapx_harness.kernel.verification_planner import (
    admit_verification_result,
)
from synapx_harness.kernel.work_contract_builder import (
    build,
    make_default_admission_receipt,
)

RUNTIME_PROVIDER_VERSION = "0.1.2"


def _now_iso() -> str:
    return _datetime.datetime.now(_datetime.UTC).isoformat()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# Context Binding Verification (R2: explicit re-hash, no Python assert)
# ---------------------------------------------------------------------------


def verify_shared_context_binding(
    source_context: SharedUnderstandingContext,
    agent_request: AgentRequest,
) -> str:
    """Verify that AgentRequest.context matches source SharedUnderstanding.

    Independently computes three values:
      A. source context canonical SHA
      B. AgentRequest payload canonical SHA (re-hash actual payload)
      C. AgentRequest embedded SHA

    A == B == C must hold. Otherwise CONTEXT_BINDING_MISMATCH.

    Returns the verified SHA on success.
    """
    # A: source context canonical SHA
    source_dict = source_context.model_dump(mode="json")
    source_sha = _sha256_hex(_canonical_json_bytes(source_dict))

    # B: actual payload canonical SHA (re-hash, don't trust embedded)
    payload = agent_request.context.optional_payload
    actual_shared = payload.get("shared_understanding")
    if actual_shared is None:
        raise ValueError(
            "CONTEXT_BINDING_MISMATCH: missing shared_understanding in payload"
        )
    actual_sha = _sha256_hex(_canonical_json_bytes(actual_shared))

    # C: embedded SHA
    embedded_sha = payload.get("sha256")
    if not isinstance(embedded_sha, str):
        raise ValueError(
            "CONTEXT_BINDING_MISMATCH: missing or non-string sha256 in payload"
        )

    # A == B == C
    if source_sha != actual_sha:
        raise ValueError(
            f"CONTEXT_BINDING_MISMATCH: source={source_sha} "
            f"actual_payload={actual_sha}"
        )
    if source_sha != embedded_sha:
        raise ValueError(
            f"CONTEXT_BINDING_MISMATCH: source={source_sha} "
            f"embedded={embedded_sha}"
        )

    return source_sha


# ---------------------------------------------------------------------------
# AgentResult Identity Binding (R2)
# ---------------------------------------------------------------------------


def verify_agent_result_identity(
    expected: ExecutionIdentity,
    actual: AgentResult,
) -> None:
    """Verify AgentResult identity matches provider-issued identity.

    Checked BEFORE VerificationPort invocation.
    Fail-closed on mismatch: AGENT_RESULT_IDENTITY_MISMATCH.
    """
    actual_ident = actual.execution_identity.execution_identity
    if actual_ident.job_id != expected.job_id:
        raise ValueError(
            f"AGENT_RESULT_IDENTITY_MISMATCH: job_id "
            f"expected={expected.job_id} actual={actual_ident.job_id}"
        )
    if actual_ident.task_id != expected.task_id:
        raise ValueError(
            f"AGENT_RESULT_IDENTITY_MISMATCH: task_id "
            f"expected={expected.task_id} actual={actual_ident.task_id}"
        )
    if actual_ident.attempt_id != expected.attempt_id:
        raise ValueError(
            f"AGENT_RESULT_IDENTITY_MISMATCH: attempt_id "
            f"expected={expected.attempt_id} actual={actual_ident.attempt_id}"
        )


# ---------------------------------------------------------------------------
# VerificationPort — independent verification authority
# ---------------------------------------------------------------------------


class VerificationPort(Protocol):
    """Independent verification authority.

    AgentResult.status == DONE means ONLY that the Codex runtime returned
    successfully. It is NOT verification. The VerificationPort decides
    verification outcome independently of the worker result.
    """

    def verify(
        self,
        work_contract: dict[str, object],
        agent_result: AgentResult,
        shared_context: SharedUnderstandingContext,
    ) -> VerificationResult:
        """Produce an independent VerificationResult."""
        ...


class FailClosedVerificationPort:
    """Default verifier: no independent verification → FAIL CLOSED.

    When no authoritative verifier is configured, verification FAILS.
    Codex DONE does NOT imply Verification PASS.
    """

    def verify(
        self,
        work_contract: dict[str, object],
        agent_result: AgentResult,
        shared_context: SharedUnderstandingContext,
    ) -> VerificationResult:
        work_contract_id = str(work_contract.get("work_contract_id", "unknown"))
        return VerificationResult(
            work_contract_id=work_contract_id,
            verification_status="FAIL",
            evidence_status="INVALID",
            active_blocker_count=1,
        )


class FakeVerificationPort:
    """Deterministic test double for VerificationPort.

    Returns configurable verification outcome independent of worker result.
    """

    def __init__(
        self,
        *,
        verification_status: str = "PASS",
        evidence_status: str = "VALID",
        active_blocker_count: int = 0,
    ) -> None:
        self._verification_status = verification_status
        self._evidence_status = evidence_status
        self._active_blocker_count = active_blocker_count

    def verify(
        self,
        work_contract: dict[str, object],
        agent_result: AgentResult,
        shared_context: SharedUnderstandingContext,
    ) -> VerificationResult:
        work_contract_id = str(work_contract.get("work_contract_id", "unknown"))
        return VerificationResult(
            work_contract_id=work_contract_id,
            verification_status=self._verification_status,  # type: ignore[arg-type]
            evidence_status=self._evidence_status,  # type: ignore[arg-type]
            active_blocker_count=self._active_blocker_count,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_admission_receipt(work_contract_id: str) -> dict[str, object]:
    return make_default_admission_receipt(
        receipt_id=f"rct/{work_contract_id}",
        admitted_at=_now_iso(),
    )


def _build_source_ref(repository_root: Path, repository_id: str) -> dict[str, object]:
    """Build a real CONTENT_TREE_HASH source revision from the repository."""
    content_hash = compute_content_tree_hash(repository_root)
    return {
        "repository_id": repository_id,
        "revision_kind": "CONTENT_TREE_HASH",
        "revision_value": content_hash,
    }


def _build_agent_request(
    task: str,
    execution_identity: ExecutionIdentity,
    workspace_root: str,
    shared_context: SharedUnderstandingContext,
    *,
    invocation: AgentInvocation | None = None,
    limits: AgentLimits | None = None,
) -> AgentRequest:
    """Build AgentRequest with Shared Understanding injected into context.

    I3-D2: an optional configured ``invocation`` (provider/model/provider_config)
    and ``limits`` are propagated losslessly into the AgentRequest. When absent,
    the deterministic fake default is used (backward compatible).
    """
    canonical_dict = shared_context.model_dump(mode="json")
    canonical_bytes = _canonical_json_bytes(canonical_dict)
    context_sha256 = _sha256_hex(canonical_bytes)

    return AgentRequest(
        execution_identity=AgentExecutionContext(
            execution_identity=execution_identity,
            agent_session_id=f"session/{execution_identity.attempt_id}",
        ),
        workspace=AgentWorkspace(root=workspace_root),
        task=AgentTask(instruction=task),
        context=AgentContext(
            canonical_context_ref=f"sha256:{context_sha256}",
            optional_payload={
                "shared_understanding": canonical_dict,
                "sha256": context_sha256,
            },
        ),
        limits=limits or AgentLimits(timeout_seconds=30),
        invocation=invocation
        or AgentInvocation(
            provider="fake-provider",
            model="fake-model",
        ),
    )


def _derive_proposed_outcome(
    verification_status: str,
    evidence_status: str,
    active_blocker_count: int,
) -> str:
    """Derive terminal outcome from verification result.

    NOT hardcoded — the terminal decision authority remains with
    Terminal Finalizer, but the proposed outcome is derived from
    the independent verification result.
    """
    if active_blocker_count > 0:
        return "BLOCKED"
    if verification_status == "PASS" and evidence_status == "VALID":
        return "COMPLETED"
    return "FAILED"


def _build_sealed_evidence(
    work_contract_id: str,
    verification_admission: dict[str, object],
    agent_result: AgentResult,
    context_sha256: str,
    source_revision_ref: dict[str, object],
) -> dict[str, object]:
    """Build and seal an evidence envelope through the canonical seal chain."""
    envelope: dict[str, object] = {
        "contract_type": "CUSTOMOS_EVIDENCE_ENVELOPE",
        "schema_version": "0.1.0",
        "work_contract_id": work_contract_id,
        "integrity_status": "ADMITTED",
        "verification_admission_ref": verification_admission.get(
            "contract_type", "UNKNOWN"
        ),
        "agent_result_status": agent_result.status.value,
        "agent_result_identity": {
            "job_id": agent_result.execution_identity.execution_identity.job_id,
            "task_id": agent_result.execution_identity.execution_identity.task_id,
            "attempt_id": agent_result.execution_identity.execution_identity.attempt_id,
        },
        "context_sha256": context_sha256,
        "source_revision_ref": source_revision_ref,
        "sealed_by": None,
        "sealed_at": None,
    }
    sealed = seal_evidence(
        envelope=envelope,
        sealer=CORE_EVIDENCE_SEALER,
        redaction_applied=True,
    )
    return sealed


# ---------------------------------------------------------------------------
# GovernedRuntimeProvider
# ---------------------------------------------------------------------------


class GovernedRuntimeProvider:
    """Main-owned governed runtime orchestrator.

    Implements RuntimePort for Lane A Front Door injection.
    Wires: Admission → Identity → Shared Understanding → Worker
    → Identity Binding → VerificationPort → Evidence → Terminal.

    Returns terminal vocabulary (COMPLETED/FAILED/BLOCKED).
    Presentation mapping is performed by frozen Lane A Front Door.

    R2 gates:
      - verify_shared_context_binding: explicit re-hash (no assert)
      - verify_agent_result_identity: before VerificationPort
      - run_storage_active: true → REJECT
    """

    def __init__(
        self,
        repository_root: str | Path,
        *,
        repository_id: str = "default-repository",
        backend: Any | None = None,
        verifier: VerificationPort | None = None,
        run_storage_active: bool = False,
        invocation: AgentInvocation | None = None,
        limits: AgentLimits | None = None,
    ) -> None:
        self._repository_root = Path(repository_root).resolve()
        self._repository_id = repository_id
        if run_storage_active:
            raise ValueError(
                "RUN_STORAGE_ACTIVE_NOT_AUTHORIZED: Lane B _runs is not "
                "terminal authority in I2 phase"
            )
        if backend is None:
            backend = FakeCodexRuntime(
                scenario=FakeScenario.SUCCESS,
                stdout="ok",
                exit_code=0,
            )
        self._adapter = CodexAdapter(backend=backend)
        if verifier is None:
            verifier = FailClosedVerificationPort()
        self._verifier = verifier
        # I3-D2: optional configured real-worker routing. When provided, the
        # AgentInvocation (provider/model/provider_config) and AgentLimits are
        # propagated losslessly into the AgentRequest the adapter consumes.
        # When absent, the deterministic fake default path is preserved.
        self._invocation = invocation
        self._limits = limits

    def is_available(self) -> bool:
        return True

    def invoke(self, task: str) -> PresentationResult | None:
        """Execute the full governed runtime path.

        Returns PresentationResult with terminal vocabulary.
        All authority flows through existing kernel components.
        """
        # 1. Admission
        work_contract_id = f"WC-GRW-{uuid.uuid4().hex[:12]}"
        admission_receipt = _build_admission_receipt(work_contract_id)
        source_ref = _build_source_ref(self._repository_root, self._repository_id)

        identity = build_execution_identity(
            job_id=f"job/{work_contract_id}",
            task_id=f"task/{work_contract_id}",
            root_task_id=f"root/{work_contract_id}",
            attempt_id=f"attempt/{work_contract_id}",
            tool_call_id=None,
        )

        work_contract = build(
            work_contract_id=work_contract_id,
            phase="GOVERNED_RUNTIME",
            risk_class="R0",
            objective=task,
            scope=["runtime"],
            issuer="HARNESS_CORE_ADMISSION",
            admission_receipt=admission_receipt,
            permission_receipt_ref=f"perm/{work_contract_id}",
            eligibility_receipt_ref=f"elig/{work_contract_id}",
            execution_receipt_ref=f"exec/{work_contract_id}",
            source_revision_ref=source_ref,
            task_type="TEST_REPAIR",
            execution_identity=identity,
        )

        # 2. Execution Identity (already issued via build)

        # 3. Shared Understanding acquisition
        scanner = DeterministicRepositoryScanner(
            self._repository_root,
            repository_id=self._repository_id,
        )
        shared_context = scanner.scan()

        # 4. Work Input / Context Construction (with Shared Understanding injected)
        agent_request = _build_agent_request(
            task=task,
            execution_identity=identity,
            workspace_root=str(self._repository_root),
            shared_context=shared_context,
            invocation=self._invocation,
            limits=self._limits,
        )

        # R2: Context binding verification (explicit re-hash, no assert)
        context_sha256 = verify_shared_context_binding(
            source_context=shared_context,
            agent_request=agent_request,
        )

        # 5. Codex Adapter Invocation
        agent_result = self._adapter.execute(agent_request)

        # 6. R2: AgentResult identity binding (before VerificationPort)
        verify_agent_result_identity(
            expected=identity,
            actual=agent_result,
        )

        # 7. Verification — INDEPENDENT of AgentResult
        #    Agent DONE ≠ Verification PASS.
        #    The VerificationPort decides verification outcome.
        work_contract_dict = work_contract.model_dump(mode="json")
        work_contract_dict["attempt_index"] = 0

        verification_result = self._verifier.verify(
            work_contract=work_contract_dict,
            agent_result=agent_result,
            shared_context=shared_context,
        )

        verification_result_dict = verification_result.model_dump(mode="json")
        verification_result_dict["schema_version"] = "0.2.0"
        verification_result_dict["evidence_timestamp"] = _now_iso()

        verification_admission = admit_verification_result(
            work_contract=work_contract_dict,
            verification_result=verification_result_dict,
        )

        # I5-R1 repair: surface verification_result invariants into the
        # terminalization input so that ``finalize_terminal_chain``'s new
        # verification-status guard can evaluate them. ``admit_verification_result``
        # does NOT round-trip ``verification_status``/``evidence_status``/
        # ``active_blocker_count``. Without this propagation, the terminal
        # chain guard would observe ``verification_status=''`` and falsely
        # reject the completion even when verification PASSes.
        enriched_verification_receipt = dict(verification_admission)
        enriched_verification_receipt["verification_status"] = (
            verification_result.verification_status
        )
        enriched_verification_receipt["evidence_status"] = (
            verification_result.evidence_status
        )
        enriched_verification_receipt["active_blocker_count"] = (
            verification_result.active_blocker_count
        )

        # 8. Evidence (derived from admitted verification)
        sealed_evidence = _build_sealed_evidence(
            work_contract_id,
            verification_admission,
            agent_result,
            context_sha256,
            source_ref,
        )

        # 9. Terminal Finalizer — outcome DERIVED from verification
        proposed_outcome = _derive_proposed_outcome(
            verification_result.verification_status,
            verification_result.evidence_status,
            verification_result.active_blocker_count,
        )

        terminalization_input: dict[str, object] = {
            "execution_identity": identity.model_dump(mode="json"),
            "work_contract_id": work_contract_id,
            "verification_admission_receipt": enriched_verification_receipt,
            "sealed_evidence": sealed_evidence,
            "source_revision_ref": source_ref,
            "active_blocker_count": verification_result.active_blocker_count,
            "proposed_outcome": proposed_outcome,
            "reason": f"verification={verification_result.verification_status}",
            "input_ref": f"input/{work_contract_id}",
        }
        terminal_decision = finalize_terminal_chain(
            work_contract_id=work_contract_id,
            sealed_evidence=sealed_evidence,
            terminalization_input=terminalization_input,
        )

        # 10. Presentation Projection
        # Provider returns TERMINAL vocabulary (COMPLETED/FAILED/BLOCKED).
        # Presentation mapping (COMPLETED→VERIFIED) is performed by
        # frozen Lane A Front Door only.
        return PresentationResult(
            status=terminal_decision.decision,
            reason=f"terminal={terminal_decision.decision}",
        )


__all__ = [
    "FailClosedVerificationPort",
    "FakeVerificationPort",
    "GovernedRuntimeProvider",
    "RUNTIME_PROVIDER_VERSION",
    "VerificationPort",
    "verify_agent_result_identity",
    "verify_shared_context_binding",
]
