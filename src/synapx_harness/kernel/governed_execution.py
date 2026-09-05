"""RQ4-R2-C3 Public Governed Execution Composition (thin glue).

RQ4 §6-§22. This module does **not** introduce any new authority. It composes
the canonical C2 mutation substrate with the canonical pre-existing Lane C
Shared Understanding scanner, Lane C WorkContract builder, Lane D CodexAdapter,
Lane C terminal finalizer, and Lane C evidence sealer. The chain is:

    build_shared_understanding
        -> derive_allowed_write_paths
        -> capture_before_state
        -> build_first_slice_work_contract
        -> build_agent_request (canonical AgentRequest)
        -> adapter.execute (REAL CodexAdapter; SubprocessCodexRuntime by default)
        -> parse_structured (canonical decoder; free-form prose is rejected)
        -> validate_mutation_proposal (deterministic; bound to before-hash + subset)
        -> derive_red_qualification_from_evidence (from real RED artifact)
        -> MutationAdmissionGate.admit
        -> ExactPathMutationGate.check
        -> ControlledPatchApplicator.apply
        -> verify_workspace (independent verifier; subprocess owned by Harness)
        -> seal_execution_evidence (CORE_EVIDENCE_SEALER)
        -> finalize_terminal_decision (TERMINAL_FINALIZER chain)

Invariants
----------
* AI PROPOSES / HARNESS MUTATES / HARNESS VERIFIES / HARNESS DECIDES COMPLETION.
* Agent DONE != Harness COMPLETED.
* Verification FAIL OR evidence INVALID OR active blockers > 0 -> NOT COMPLETED.
* Codex remains READ-ONLY: the Fixture / Sandbox is the proposal stream only;
  no path mutation happens inside the Codex process.
* The same ExecutionIdentity (job_id, root_task_id, task_id, attempt_id,
  agent_session_id) survives into WorkContract -> AgentRequest -> proposal ->
  mutation -> verification -> evidence -> terminal decision.

Forbidden here
--------------
* A new policy engine, evidence platform, terminal finalizer, agent provider
  (no Codex SDK / OpenCode / CodeBuddy / Kiro adapter), or multi-path mutation
  path. RQ4 stays single-file TEST_REPAIR first-slice.

Tests
-----
The contract tests live in ``tests/contract/test_rq4_r2_c3_governed_execution.py``
and reference every seam by name so the production wiring cannot drift
silently.
"""
from __future__ import annotations

import datetime as _datetime
import hashlib
import json
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.models import (
    AGENT_RUNTIME_SCHEMA_VERSION,
    AgentContext,
    AgentExecutionContext,
    AgentInvocation,
    AgentLimits,
    AgentRequest,
    AgentResult,
    AgentTask,
    AgentWorkspace,
    DEFAULT_MAX_OUTPUT_BYTES,
)
from synapx_harness.adapters.codex.runtime import SubprocessCodexRuntime
from synapx_harness.contracts.runtime_models import (
    ExecutionIdentity,
    SourceRevisionRef,
    VerificationResult,
    WorkContract,
    build_source_revision_ref,
    build_verification_result,
)
from synapx_harness.context.models import (
    CONTEXT_CONTRACT_TYPE,
    CONTEXT_SCHEMA_VERSION,
    SharedUnderstandingContext,
)
from synapx_harness.context.scanner import DeterministicRepositoryScanner
from synapx_harness.evidence.command_runner import (
    CommandResult,
    normalize_write_token_path,
    run_command,
)
from synapx_harness.evidence.evidence_validator import (
    CORE_EVIDENCE_SEALER,
    seal_evidence,
)
from synapx_harness.kernel.mutation_authority import (
    AdmissionReceipt,
    ApplyReceipt,
    ControlledPatchApplicator,
    ExactPathMutationGate,
    MutationAdmissionGate,
    MutationExecutionResult,
    PatchProposal,
    PatchProposalParser,
    PathGateReceipt,
    derive_red_qualification_from_evidence,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    build_proposal_instruction,
    parse_allowed_write_paths,
    validate_mutation_proposal,
)
from synapx_harness.kernel.terminal_finalizer import (
    TERMINAL_FINALIZER_ISSUER,
    TerminalDecision,
    finalize_from_sealed_evidence,
)
from synapx_harness.kernel.work_contract_builder import (
    CANONICAL_SCHEMA_VERSION,
    FIRST_SLICE_ADMISSIBLE_TASK_TYPES,
    HARNESS_CORE_ADMISSION,
    build as build_work_contract_fn,
    make_default_admission_receipt,
)

# ---------------------------------------------------------------------------
# Public composition seams (re-used by tests + the public CLI bridge).
# ---------------------------------------------------------------------------


GOVERNED_PHASE: str = "RQ4-R2-C3-PUBLIC-GOVERNED"
GOVERNED_RISK_CLASS: str = "R0"
GOVERNED_TASK_TYPE: str = "TEST_REPAIR"
CODEX_PROVIDER: str = "codex"
CODEX_SANDBOX: str = "read-only"

# Bounded codex invocation defaults for the public path.
DEFAULT_TIMEOUT_SECONDS: int = 120
DEFAULT_MAX_OUTPUT_BYTES_LOCAL: int = DEFAULT_MAX_OUTPUT_BYTES


def _now_iso() -> str:
    return _datetime.datetime.now(_datetime.UTC).isoformat()


def _canonical_path_bytes(rel: str) -> bytes:
    """Hash repository-relative paths identically to mutation_proposal_contract.

    Kept as a tiny local helper so before-hash capture survives CRLF
    normalisation in the same way validation does.
    """
    return rel.replace("\\", "/").encode("utf-8")


# ---------------------------------------------------------------------------
# Stage 1 -- Minimum Shared Understanding
# ---------------------------------------------------------------------------


def build_shared_understanding(
    repository_root: Path,
    *,
    repository_id: str = "synapx-rq4-c3",
) -> SharedUnderstandingContext:
    """Build a deterministic Shared Understanding context for the workspace.

    RQ4 §10: the public execution MUST consume the existing Minimum Shared
    Understanding representation before WorkContract generation. This wraps the
    canonical ``DeterministicRepositoryScanner`` (read-only, root-bounded,
    gitless-friendly) and emits a typed :class:`SharedUnderstandingContext`.
    """
    root = Path(repository_root).resolve()
    scanner = DeterministicRepositoryScanner(
        repository_root=root,
        repository_id=repository_id,
    )
    return scanner.scan()


# ---------------------------------------------------------------------------
# Stage 2 -- Allowed write path extraction
# ---------------------------------------------------------------------------


def derive_allowed_write_paths(task_text: str) -> list[str]:
    """Deterministically extract the explicit allowed write paths from the task.

    RQ4 §11: semantic inference is never performed. Either the user declared
    the paths under an ``Allowed write paths:`` header, or there is no write
    set.
    """
    return list(parse_allowed_write_paths(task_text or ""))


# ---------------------------------------------------------------------------
# Stage 3 -- Before-state capture (per-path binding)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BeforeState:
    """Snapshot of the repository state captured BEFORE Codex runs.

    The composition layer captures this just-in-time so the mutation chain
    can prove the Codex process did not modify the workspace (RQ4 §14)
    AND so the per-path before-hash binding matches what the applicator
    will see at apply-time (RQ4-R2-C2 strict).
    """

    source_revision: str
    expected_before_sha256_by_path: dict[str, str]
    fixture_sha_before_codex: str

    def to_dict(self) -> dict[str, object]:
        return {
            "source_revision": self.source_revision,
            "expected_before_sha256_by_path": dict(
                self.expected_before_sha256_by_path
            ),
            "fixture_sha_before_codex": self.fixture_sha_before_codex,
        }


def _resolve_canonical_sha(target: Path) -> str:
    raw = target.read_bytes()
    normalised = raw.replace(b"\r\n", b"\n")
    return hashlib.sha256(normalised).hexdigest()


def capture_before_state(
    repository_root: Path,
    allowed_write_paths: list[str],
) -> BeforeState:
    """Capture source revision + per-path before SHA + fixture SHA.

    RQ4 §14 invariant: the same fixture SHA is captured here so it can be
    re-checked immediately after Codex returns to prove the Codex process
    did NOT modify the workspace directly.

    The ``source_revision`` is computed via the same canonical helper that
    the composition layer uses at apply-time (``_fixture_root_sha``). No
    suffix is appended: the revision IS the fixture SHA. The per-path
    binding is carried separately in ``expected_before_sha256_by_path``.
    """
    root = repository_root.resolve()
    expected: dict[str, str] = {}
    for rel in allowed_write_paths:
        try:
            normalized = normalize_write_token_path(rel)
        except ValueError as exc:
            raise ValueError(
                f"allowed write path {rel!r} is invalid: {exc}"
            ) from exc
        target = (root / normalized).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"allowed write path {normalized!r} escapes repository root"
            ) from exc
        if not target.is_file():
            raise ValueError(
                f"allowed write path {normalized!r} is not an existing file"
            )
        expected[normalized] = _resolve_canonical_sha(target)

    fixture_sha = _fixture_root_sha(root)
    return BeforeState(
        source_revision=fixture_sha,
        expected_before_sha256_by_path=expected,
        fixture_sha_before_codex=fixture_sha,
    )


def _compute_agent_session_id() -> str:
    """Allocate a fresh agent-session identifier.

    RQ4-R2-C3-R1 (E4 hardening): the agent session is material and
    independent of the harness-side ``job_id``. This makes the
    agent-session lineage traceable even when the harness's job_id and
    the agent's session identifier happen to collide in a reuse path.
    """
    return f"agent-{uuid.uuid4().hex}"


def _sha256_text(text: str | None) -> str:
    """Stable SHA-256 over a (possibly empty) text payload."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _fixture_root_sha(repository_root: Path) -> str:
    """Compute a deterministic snapshot hash of the fixture root.

    Provider-neutral: walks the root and concatenates relative path +
    byte content (CRLF normalised) into a SHA-256. This is NOT git, so it
    survives fixtures that are not git repos (the real Codex E2E fixture
    is a fresh git repo and also has this property).

    Cache / VCS directories that external tools (Codex, pytest, Python)
    may create mid-run, plus internal SynapX run-state artifacts
    (``.fixture_sha_before.json``, ``.synapx_red_evidence.json``, etc.),
    are skipped deterministically so the SHA stays stable across the
    run lifecycle and does not depend on when the artifact was written.
    """
    skip_dirs = frozenset(
        {
            ".git",
            "__pycache__",
            ".venv",
            "node_modules",
            "dist",
            "build",
            ".ruff_cache",
            ".pytest_cache",
            ".mypy_cache",
            ".tox",
        }
    )
    skip_file_prefixes = (".fixture_sha_", ".synapx_", ".synapx-cache-")

    digest = hashlib.sha256()
    root = repository_root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for fname in sorted(filenames):
            if fname.startswith(skip_file_prefixes):
                continue
            full = Path(dirpath) / fname
            try:
                rel = full.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
            digest.update(rel.encode("utf-8"))
            digest.update(b"\x00")
            try:
                data = full.read_bytes()
            except OSError:
                continue
            digest.update(data.replace(b"\r\n", b"\n"))
            digest.update(b"\x00")
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Stage 4 -- WorkContract construction
# ---------------------------------------------------------------------------


def _generate_execution_identity(
    repository_root: Path,
) -> ExecutionIdentity:
    """Allocate a fresh canonical ExecutionIdentity for this run.

    RQ4-R2-C3-R1 (E4 hardening): every lineage slot is allocated from a
    distinct ``uuid4`` so the canonical (job_id, root_task_id, task_id,
    attempt_id) four-tuple is materially concrete. No two slots share a
    value; the lineage survives verbatim into WorkContract -> AgentRequest
    -> proposal -> mutation -> verification -> evidence -> terminal decision.
    """
    job_uuid = uuid.uuid4().hex
    root_uuid = uuid.uuid4().hex
    task_uuid = uuid.uuid4().hex
    attempt_uuid = uuid.uuid4().hex
    return ExecutionIdentity(
        job_id=f"job-{job_uuid}",
        root_task_id=f"root-{root_uuid}",
        task_id=f"task-{task_uuid}",
        attempt_id=f"att-{attempt_uuid}",
        tool_call_id=None,
    )


def build_first_slice_work_contract(
    *,
    work_contract_id: str,
    task: str,
    allowed_write_paths: list[str],
    execution_identity: ExecutionIdentity,
    source_revision: str,
    shared_understanding: SharedUnderstandingContext,
) -> WorkContract:
    """Build a canonical first-slice WorkContract (schema 0.2.0, R0, TEST_REPAIR)."""
    if task_type := GOVERNED_TASK_TYPE:
        if task_type not in FIRST_SLICE_ADMISSIBLE_TASK_TYPES:
            raise ValueError(
                f"first-slice task_type={task_type!r} is not admissible "
                f"(required: {sorted(FIRST_SLICE_ADMISSIBLE_TASK_TYPES)})"
            )

    repo_id = (
        shared_understanding.repository.repository_id or "synapx-rq4-c3"
    )
    source_revision_ref = build_source_revision_ref(
        repository_id=repo_id,
        revision_kind="CONTENT_TREE_HASH",
        revision_value=source_revision,
    )

    scope: list[str] = [
        "phase:public_governed",
        f"path:{repo_id}",
        f"tool:{CODEX_PROVIDER}",
        "tool:pytest",
    ]
    for rel in allowed_write_paths:
        scope.append(f"write:{rel}")

    admitted_at = _now_iso()
    admission_receipt = make_default_admission_receipt(
        receipt_id=f"rct/{work_contract_id}/admission",
        admitted_at=admitted_at,
        classification_receipt=f"rct/{work_contract_id}/classification",
        risk_classification_receipt=f"rct/{work_contract_id}/risk",
        revision_verification_receipt=f"rct/{work_contract_id}/revision",
    )

    return build_work_contract_fn(
        work_contract_id=work_contract_id,
        phase=GOVERNED_PHASE,
        risk_class=GOVERNED_RISK_CLASS,
        objective=task.strip(),
        scope=scope,
        success_criteria=[
            "tests/test_calculator.py remains byte-identical",
            "calculator.py passes the declared pytest suite",
            "structured proposal is the only allowed mutation source",
            "Codex process did not modify the workspace",
            "verification_status=PASS, evidence_status=VALID, active_blocker_count=0",
        ],
        issuer=HARNESS_CORE_ADMISSION,
        admission_receipt=admission_receipt,
        receipt_refs={
            "permission_receipt_ref": f"rct/{work_contract_id}/permission",
            "eligibility_receipt_ref": f"rct/{work_contract_id}/eligibility",
            "execution_receipt_ref": f"rct/{work_contract_id}/execution",
        },
        source_revision_ref=source_revision_ref,
        task_type=GOVERNED_TASK_TYPE,
        execution_identity=execution_identity,
    )


# ---------------------------------------------------------------------------
# Stage 5 -- Canonical AgentRequest construction
# ---------------------------------------------------------------------------


def build_agent_request(
    *,
    task_instruction: str,
    workspace_root: Path,
    execution_identity: ExecutionIdentity,
    allowed_write_paths: list[str],
    model: str,
    timeout_seconds: int,
    canonical_context_ref: str | None = None,
    agent_session_id: str | None = None,
) -> AgentRequest:
    """Build a canonical AgentRequest preserving the execution lineage."""
    if not task_instruction or not task_instruction.strip():
        raise ValueError("task_instruction must be a non-empty string")
    if not workspace_root:
        raise ValueError("workspace_root must be a non-empty string")
    if not allowed_write_paths:
        raise ValueError(
            "allowed_write_paths must be a non-empty list (no semantic inference)"
        )

    effective_agent_session_id = (
        agent_session_id
        if agent_session_id is not None
        else execution_identity.job_id
    )
    agent_context = AgentExecutionContext(
        execution_identity=execution_identity,
        agent_session_id=effective_agent_session_id,
    )
    workspace = AgentWorkspace(
        root=str(Path(workspace_root).resolve()),
        revision=execution_identity.root_task_id,
    )
    task = AgentTask(instruction=task_instruction.strip())
    limits = AgentLimits(
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=DEFAULT_MAX_OUTPUT_BYTES_LOCAL,
        max_stderr_bytes=DEFAULT_MAX_OUTPUT_BYTES_LOCAL,
    )
    invocation = AgentInvocation(
        provider=CODEX_PROVIDER,
        model=model,
        provider_config={
            "sandbox": CODEX_SANDBOX,
            "phase": GOVERNED_PHASE,
        },
    )
    context = AgentContext(
        canonical_context_ref=canonical_context_ref,
        optional_payload={
            "shared_understanding_contract_type": CONTEXT_CONTRACT_TYPE,
            "shared_understanding_schema_version": CONTEXT_SCHEMA_VERSION,
            "allowed_write_paths": list(allowed_write_paths),
        },
    )
    return AgentRequest(
        contract_type="CUSTOMOS_AGENT_REQUEST",
        schema_version=AGENT_RUNTIME_SCHEMA_VERSION,
        execution_identity=agent_context,
        workspace=workspace,
        task=task,
        context=context,
        limits=limits,
        invocation=invocation,
    )


def build_codex_proposal_instruction(
    *,
    task: str,
    allowed_write_paths: list[str],
    repository_root: Path,
) -> str:
    """Build the canonical Codex instruction carrying the structured contract."""
    return build_proposal_instruction(
        task=task,
        allowed_write_paths=list(allowed_write_paths),
        repository_root=Path(repository_root).resolve(),
    )


# ---------------------------------------------------------------------------
# Stage 6 -- Codex process: real on positive path
# ---------------------------------------------------------------------------


def _default_adapter(
    *,
    codex_runtime_factory: Callable[[], Any] | None,
) -> CodexAdapter:
    """Construct the canonical CodexAdapter.

    RQ4 §13: the positive path MUST use ``SubprocessCodexRuntime`` (the real
    Codex CLI). For tests we accept an injected factory that returns a
    runtime with the same ``invoke(inv, cancel_event)`` surface.
    """
    if codex_runtime_factory is None:
        backend: Any = SubprocessCodexRuntime()
        return CodexAdapter(backend=backend)
    backend = codex_runtime_factory()
    return CodexAdapter(backend=backend)


def assert_codex_did_not_mutate(
    repository_root: Path,
    fixture_sha_before: str,
) -> str:
    """Prove Codex did not write to the workspace (RQ4 §14).

    Returns the after-SHA. Raises :class:`RuntimeError` if it differs.
    """
    after = _fixture_root_sha(Path(repository_root).resolve())
    if after != fixture_sha_before:
        raise RuntimeError(
            "Codex direct mutation detected: "
            f"fixture SHA before={fixture_sha_before[:12]}... "
            f"after={after[:12]}... "
            "(RQ4_R2_C3_CODEX_DIRECT_MUTATION)"
        )
    return after


# ---------------------------------------------------------------------------
# Stage 7 -- Mutation authority chain
# ---------------------------------------------------------------------------


def _default_mutation_chain() -> tuple[
    MutationAdmissionGate,
    ExactPathMutationGate,
    ControlledPatchApplicator,
    PatchProposalParser,
]:
    return (
        MutationAdmissionGate(),
        ExactPathMutationGate(),
        ControlledPatchApplicator(),
        PatchProposalParser(),
    )


def execute_mutation_chain(
    *,
    agent_stdout: str,
    work_contract_id: str,
    repository_root: Path,
    allowed_write_paths: list[str],
    expected_before_sha256_by_path: dict[str, str],
    source_revision: str,
    execution_identity_dict: dict[str, object],
    red_qualification_ref: str,
    red_qualified: bool,
    current_source_revision_at_apply: str,
    admission_gate: MutationAdmissionGate | None = None,
    path_gate: ExactPathMutationGate | None = None,
    applicator: ControlledPatchApplicator | None = None,
    parser: PatchProposalParser | None = None,
) -> MutationExecutionResult:
    """Run the canonical mutation chain.

    Mirrors :class:`GovernedMutationExecutor.execute` but kept as a free
    function so the composition layer can stay thin and so the chain is
    testable seam by seam.
    """
    if admission_gate is None or path_gate is None or applicator is None or parser is None:
        (
            default_admission,
            default_path_gate,
            default_applicator,
            default_parser,
        ) = _default_mutation_chain()
        admission_gate = admission_gate or default_admission
        path_gate = path_gate or default_path_gate
        applicator = applicator or default_applicator
        parser = parser or default_parser

    proposal = parser.parse_structured(agent_stdout)
    if not proposal.valid:
        return MutationExecutionResult(
            success=False,
            work_contract_id=work_contract_id,
            admission_receipt=None,
            path_gate_receipt=None,
            apply_receipt=None,
            proposal=proposal,
            validation_blockers=[],
            error=f"Proposal INVALID: {proposal.parse_error}",
        )

    blockers = validate_mutation_proposal(
        proposal,
        repository_root=Path(repository_root).resolve(),
        allowed_write_paths=allowed_write_paths,
        expected_before_sha256_by_path=expected_before_sha256_by_path,
    )
    if blockers:
        return MutationExecutionResult(
            success=False,
            work_contract_id=work_contract_id,
            admission_receipt=None,
            path_gate_receipt=None,
            apply_receipt=None,
            proposal=proposal,
            validation_blockers=blockers,
            error="Proposal validation FAILED: " + "; ".join(blockers),
        )

    admission = admission_gate.admit(
        work_contract_id=work_contract_id,
        red_qualified=red_qualified,
        red_qualification_ref=red_qualification_ref,
        source_revision=source_revision,
        execution_identity=execution_identity_dict,
        allowed_write_paths=allowed_write_paths,
    )
    if admission.admission_decision != "ALLOW":
        return MutationExecutionResult(
            success=False,
            work_contract_id=work_contract_id,
            admission_receipt=admission,
            path_gate_receipt=None,
            apply_receipt=None,
            proposal=proposal,
            validation_blockers=[],
            error=f"Admission DENIED: {admission.denied_reason}",
        )

    path_receipt = path_gate.check(
        proposal=proposal,
        allowed_write_paths=allowed_write_paths,
        source_revision=source_revision,
        admission_receipt_id=admission.receipt_id,
    )
    if path_receipt.gate_decision != "ALLOW":
        return MutationExecutionResult(
            success=False,
            work_contract_id=work_contract_id,
            admission_receipt=admission,
            path_gate_receipt=path_receipt,
            apply_receipt=None,
            proposal=proposal,
            validation_blockers=[],
            error=f"PathGate DENIED: {path_receipt.reason}",
        )

    apply_receipt = applicator.apply(
        proposal=proposal,
        path_gate_receipt=path_receipt,
        admission_receipt=admission,
        repository_root=Path(repository_root).resolve(),
        expected_before_sha256_by_path=expected_before_sha256_by_path,
        current_source_revision_at_apply=current_source_revision_at_apply,
    )
    if apply_receipt.write_count == 0:
        return MutationExecutionResult(
            success=False,
            work_contract_id=work_contract_id,
            admission_receipt=admission,
            path_gate_receipt=path_receipt,
            apply_receipt=apply_receipt,
            proposal=proposal,
            validation_blockers=[],
            error=f"Apply failed: write_count = 0 "
            f"({apply_receipt.denied_reason})",
        )

    return MutationExecutionResult(
        success=True,
        work_contract_id=work_contract_id,
        admission_receipt=admission,
        path_gate_receipt=path_receipt,
        apply_receipt=apply_receipt,
        proposal=proposal,
        validation_blockers=[],
    )


# ---------------------------------------------------------------------------
# Stage 8 -- Independent verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationOutcome:
    """Independent verification outcome (Harness-owned, never Agent DONE)."""

    verification_status: str  # PASS / FAIL / PENDING
    evidence_status: str  # VALID / INVALID / PENDING
    active_blocker_count: int
    command_result: CommandResult
    red_qualified: bool
    red_qualification_ref: str

    def to_dict(self) -> dict[str, object]:
        return {
            "verification_status": self.verification_status,
            "evidence_status": self.evidence_status,
            "active_blocker_count": self.active_blocker_count,
            "red_qualified": self.red_qualified,
            "red_qualification_ref": self.red_qualification_ref,
            "command_result": self.command_result.to_dict(),
        }


def verify_workspace(
    *,
    repository_root: Path,
    verification_command: list[str],
    red_qualification_ref: str,
    timeout_seconds: int = 120,
) -> VerificationOutcome:
    """Run the canonical independent verification command.

    The verifier is owned by the Harness. Agent DONE / Codex stdout / proposal
    validity are NEVER verification.

    For first-slice TEST_REPAIR the verification command is expected to be
    ``[sys.executable, "-m", "pytest", "-q"]``; the exit code drives the
    PASS / FAIL status. ``red_qualification_ref`` must point at a JSON file
    capturing the pre-mutation RED state; ``red_qualified`` is derived from
    that artifact (RQ4-R2-C2-R1 Repair A).
    """
    cmd_str = subprocess.list2cmdline(verification_command)
    cmd_result = run_command(
        cmd_str,
        cwd=Path(repository_root).resolve(),
        timeout=timeout_seconds,
    )

    try:
        red_qualified = derive_red_qualification_from_evidence(
            red_qualification_ref
        )
    except Exception:
        red_qualified = False

    if cmd_result.exit_code == 0:
        verification_status = "PASS"
        evidence_status = "VALID"
        blockers = 0
    else:
        verification_status = "FAIL"
        evidence_status = "INVALID"
        blockers = 1

    return VerificationOutcome(
        verification_status=verification_status,
        evidence_status=evidence_status,
        active_blocker_count=blockers,
        command_result=cmd_result,
        red_qualified=red_qualified,
        red_qualification_ref=red_qualification_ref,
    )


def build_verification_result(
    work_contract_id: str,
    outcome: VerificationOutcome,
) -> VerificationResult:
    """Wrap the VerificationOutcome into the canonical VerificationResult."""
    return build_verification_result(
        work_contract_id=work_contract_id,
        verification_status=outcome.verification_status,
        evidence_status=outcome.evidence_status,
        active_blocker_count=outcome.active_blocker_count,
        checks=[
            {
                "check_type": "INDEPENDENT_PYTEST",
                "exit_code": outcome.command_result.exit_code,
                "stdout_sha256": outcome.command_result.stdout_sha256,
                "stderr_sha256": outcome.command_result.stderr_sha256,
                "gate": outcome.command_result.gate,
            }
        ],
    )


# ---------------------------------------------------------------------------
# Stage 9 -- Evidence seal + Terminal finalizer
# ---------------------------------------------------------------------------


def build_evidence_envelope(
    *,
    work_contract_id: str,
    execution_identity: ExecutionIdentity,
    proposal: PatchProposal | None,
    apply_receipt: ApplyReceipt | None,
    verification: VerificationOutcome,
    source_revision: str,
) -> dict[str, object]:
    """Build an ADMITTED evidence envelope (still pre-seal)."""
    envelope: dict[str, object] = {
        "contract_type": "CUSTOMOS_GOVERNED_EXECUTION_ENVELOPE",
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "work_contract_id": work_contract_id,
        "execution_identity": execution_identity.model_dump(mode="json"),
        "source_revision": source_revision,
        "verification": verification.to_dict(),
        "integrity_status": "ADMITTED",
    }
    if proposal is not None:
        envelope["proposal"] = {
            "valid": proposal.valid,
            "paths": list(proposal.paths),
            "sha256": proposal.sha256,
            "canonical_patch_sha256": proposal.canonical_patch_sha256,
            "raw_input_sha256": proposal.raw_input_sha256,
        }
    if apply_receipt is not None:
        envelope["apply_receipt"] = {
            "applied_paths": list(apply_receipt.applied_paths),
            "before_sha256": apply_receipt.before_sha256,
            "after_sha256": apply_receipt.after_sha256,
            "patch_sha256": apply_receipt.patch_sha256,
            "canonical_patch_sha256": apply_receipt.canonical_patch_sha256,
            "write_count": apply_receipt.write_count,
            "apply_started_at": apply_receipt.apply_started_at,
            "apply_completed_at": apply_receipt.apply_completed_at,
            "authorization_ref": apply_receipt.authorization_ref,
        }
    return envelope


def seal_execution_evidence(envelope: dict[str, object]) -> dict[str, object]:
    """Apply the canonical CORE_EVIDENCE_SEALER (RQ4 §23)."""
    redacted = _redact_envelope(envelope)
    return seal_evidence(
        envelope=redacted,
        sealer=CORE_EVIDENCE_SEALER,
        redaction_applied=True,
    )


def _redact_envelope(envelope: dict[str, object]) -> dict[str, object]:
    """Deterministic redaction pass on free-text fields.

    The mutation chain already operates on canonical structured fields only;
    this pass only strips obvious secret shapes from any human-provided
    metadata. It is invoked before sealing so the sealer sees a redacted
    envelope (INV-RPR-001).
    """
    secret_re = _REDACT_PATTERN
    redacted = json.loads(json.dumps(envelope))
    _redact_recursive(redacted, secret_re)
    return redacted


_REDACT_PATTERN = re_compile_secrets = __import__(
    "re"
).compile(r"(?i)(api[_-]?key|token|password|secret|auth)\s*[=:]\s*\S+")


def _redact_recursive(node: object, secret_re: Any) -> None:
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if isinstance(value, str) and secret_re.search(value):
                node[key] = "[REDACTED]"
            else:
                _redact_recursive(value, secret_re)
    elif isinstance(node, list):
        for item in node:
            _redact_recursive(item, secret_re)


def finalize_terminal_decision(
    *,
    work_contract_id: str,
    sealed_evidence: dict[str, object],
    verification: VerificationOutcome,
    execution_identity: ExecutionIdentity,
    proposed_outcome: str | None = None,
) -> tuple[Any, dict[str, object]]:
    """Issue the canonical TerminalDecisionRecord via finalize_from_sealed_evidence.

    Returns ``(TerminalDecisionRecord, terminalization_input_dict)``.
    """
    if proposed_outcome is None:
        proposed_outcome = TerminalDecision.COMPLETED.value

    terminalization_input: dict[str, object] = {
        "work_contract_id": work_contract_id,
        "execution_identity": execution_identity.model_dump(mode="json"),
        "verification_admission_receipt": {
            "verification_status": verification.verification_status,
            "evidence_status": verification.evidence_status,
            "active_blocker_count": verification.active_blocker_count,
            "red_qualified": verification.red_qualified,
            "red_qualification_ref": verification.red_qualification_ref,
        },
        "sealed_evidence": sealed_evidence,
        "source_revision_ref": sealed_evidence.get("source_revision"),
        "active_blocker_count": verification.active_blocker_count,
        "proposed_outcome": proposed_outcome,
        "reason": (
            "all invariants satisfied"
            if verification.verification_status == "PASS"
            else f"verification_status={verification.verification_status}"
        ),
        "input_ref": sealed_evidence.get("integrity_status"),
    }
    record = finalize_from_sealed_evidence(
        sealed_evidence=sealed_evidence,
        terminalization_input=terminalization_input,
    )
    return record, terminalization_input


# ---------------------------------------------------------------------------
# Stage 10 -- Top-level orchestration
# ---------------------------------------------------------------------------


@dataclass
class GovernedExecutionResult:
    """End-to-end result of one public governed run.

    This is a presentation-friendly view object, NOT a terminal authority
    on its own. The terminal authority is the embedded
    ``terminal_decision`` (a :class:`TerminalDecisionRecord`).

    RQ4-R2-C3-R1 lineage slots: ``pre_codex_source_revision`` (R0, captured
    before Codex), ``pre_apply_source_revision`` (R0, re-captured at apply
    time), ``post_apply_source_revision`` (R1, captured after Harness
    write). The three values are required to be material, NOT placeholder
    strings. ``work_contract_id`` and ``execution_identity`` survive the
    run verbatim into the lineage.
    """

    success: bool
    work_contract_id: str
    execution_identity: ExecutionIdentity
    shared_understanding: SharedUnderstandingContext
    work_contract: WorkContract
    source_revision: str
    pre_codex_source_revision: str = ""
    pre_apply_source_revision: str = ""
    post_apply_source_revision: str = ""
    agent_session_id: str = ""
    codex_process_exit_code: int | None = None
    codex_process_version: str | None = None
    agent_stdout_sha256: str | None = None
    agent_stderr_sha256: str | None = None
    allowed_write_paths: list[str] = field(default_factory=list)
    proposal: PatchProposal | None = None
    admission_receipt: AdmissionReceipt | None = None
    path_gate_receipt: PathGateReceipt | None = None
    apply_receipt: ApplyReceipt | None = None
    verification: VerificationOutcome | None = None
    sealed_evidence: dict[str, object] = field(default_factory=dict)
    terminal_decision: Any = None
    terminalization_input: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "work_contract_id": self.work_contract_id,
            "execution_identity": self.execution_identity.model_dump(mode="json"),
            "shared_understanding": self.shared_understanding.model_dump(mode="json"),
            "work_contract": self.work_contract.model_dump(mode="json"),
            "source_revision": self.source_revision,
            "pre_codex_source_revision": self.pre_codex_source_revision,
            "pre_apply_source_revision": self.pre_apply_source_revision,
            "post_apply_source_revision": self.post_apply_source_revision,
            "agent_session_id": self.agent_session_id,
            "codex_process_exit_code": self.codex_process_exit_code,
            "codex_process_version": self.codex_process_version,
            "agent_stdout_sha256": self.agent_stdout_sha256,
            "agent_stderr_sha256": self.agent_stderr_sha256,
            "allowed_write_paths": list(self.allowed_write_paths),
            "proposal": (
                None
                if self.proposal is None
                else {
                    "valid": self.proposal.valid,
                    "paths": list(self.proposal.paths),
                    "sha256": self.proposal.sha256,
                    "canonical_patch_sha256": self.proposal.canonical_patch_sha256,
                    "raw_input_sha256": self.proposal.raw_input_sha256,
                }
            ),
            "admission_receipt": (
                None
                if self.admission_receipt is None
                else {
                    "receipt_id": self.admission_receipt.receipt_id,
                    "admission_decision": self.admission_receipt.admission_decision,
                    "work_contract_id": self.admission_receipt.work_contract_id,
                    "source_revision": self.admission_receipt.source_revision,
                }
            ),
            "path_gate_receipt": (
                None
                if self.path_gate_receipt is None
                else {
                    "gate_decision": self.path_gate_receipt.gate_decision,
                    "apply_authority": self.path_gate_receipt.apply_authority,
                    "proposal_paths": list(self.path_gate_receipt.proposal_paths),
                    "source_revision": self.path_gate_receipt.source_revision,
                }
            ),
            "apply_receipt": (
                None
                if self.apply_receipt is None
                else {
                    "applied_paths": list(self.apply_receipt.applied_paths),
                    "before_sha256": self.apply_receipt.before_sha256,
                    "after_sha256": self.apply_receipt.after_sha256,
                    "write_count": self.apply_receipt.write_count,
                    "source_revision": self.apply_receipt.source_revision,
                    "admission_receipt_id": self.apply_receipt.admission_receipt_id,
                    "path_gate_receipt_id": self.apply_receipt.path_gate_receipt_id,
                }
            ),
            "verification": (
                self.verification.to_dict()
                if self.verification is not None
                else {}
            ),
            "sealed_evidence": self.sealed_evidence,
            "terminal_decision": (
                self.terminal_decision.model_dump(mode="json")
                if hasattr(self.terminal_decision, "model_dump")
                else self.terminal_decision
            ),
            "errors": list(self.errors),
        }


@dataclass
class GovernedExecutionRequest:
    """Inputs for a single governed execution run.

    The composition layer is intentionally pure: every dependency is either
    canonical (default) or injected (for tests). The public CLI bridge fills
    in the defaults from the workspace + environment.
    """

    workspace_root: Path
    task: str
    model: str = "gpt-5.6-luna"
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    red_qualification_ref: str | None = None
    verification_command: list[str] | None = None
    adapter: CodexAdapter | None = None
    codex_runtime_factory: Callable[[], Any] | None = None
    repository_id: str = "synapx-rq4-c3"
    work_contract_id: str | None = None
    red_qualified_override: bool | None = None
    expected_before_sha256_by_path: dict[str, str] | None = None
    source_revision: str | None = None
    codex_proposal_instruction_override: str | None = None
    codex_stdout_override: str | None = None


def run_governed_execution(
    request: GovernedExecutionRequest,
) -> GovernedExecutionResult:
    """Run the full public-governed lifecycle (RQ4 §6).

    This is the single entry point that the public CLI bridge calls.
    """
    workspace_root = Path(request.workspace_root).resolve()
    task_text = (request.task or "").strip()
    if not task_text:
        return _block(
            request=request,
            workspace_root=workspace_root,
            reason="empty task is not allowed",
        )

    allowed_write_paths = derive_allowed_write_paths(task_text)
    if not allowed_write_paths:
        return _block(
            request=request,
            workspace_root=workspace_root,
            reason="task does not declare an explicit allowed write set",
        )

    execution_identity = _generate_execution_identity(workspace_root)
    agent_session_id = _compute_agent_session_id()
    work_contract_id = (
        request.work_contract_id
        or f"wc-{execution_identity.root_task_id}"
    )

    shared_understanding = build_shared_understanding(
        workspace_root,
        repository_id=request.repository_id,
    )

    # ----- Before-state capture -----
    try:
        if (
            request.expected_before_sha256_by_path is not None
            and request.source_revision is not None
        ):
            # Caller pre-computed the before state (tests).
            before = BeforeState(
                source_revision=request.source_revision,
                expected_before_sha256_by_path=dict(
                    request.expected_before_sha256_by_path
                ),
                fixture_sha_before_codex=_fixture_root_sha(workspace_root),
            )
        else:
            before = capture_before_state(workspace_root, allowed_write_paths)
    except ValueError as exc:
        return _block(
            request=request,
            workspace_root=workspace_root,
            reason=str(exc),
            execution_identity=execution_identity,
            agent_session_id=agent_session_id,
            work_contract_id=work_contract_id,
            shared_understanding=shared_understanding,
            pre_codex_source_revision=before.source_revision
            if "before" in locals()
            else "",
        )

    work_contract = build_first_slice_work_contract(
        work_contract_id=work_contract_id,
        task=task_text,
        allowed_write_paths=allowed_write_paths,
        execution_identity=execution_identity,
        source_revision=before.source_revision,
        shared_understanding=shared_understanding,
    )

    # ----- Codex process -----
    fixture_sha_before = before.fixture_sha_before_codex
    pre_codex_source_revision = fixture_sha_before
    agent_stderr_text: str = ""

    if request.codex_stdout_override is not None:
        agent_stdout = request.codex_stdout_override
        codex_version: str | None = "test-override"
        agent_result_status = "DONE"
        codex_process_exit_code = 0
    else:
        adapter = request.adapter or _default_adapter(
            codex_runtime_factory=request.codex_runtime_factory,
        )
        proposal_instruction = (
            request.codex_proposal_instruction_override
            if request.codex_proposal_instruction_override is not None
            else build_codex_proposal_instruction(
                task=task_text,
                allowed_write_paths=allowed_write_paths,
                repository_root=workspace_root,
            )
        )
        agent_request = build_agent_request(
            task_instruction=proposal_instruction,
            workspace_root=workspace_root,
            execution_identity=execution_identity,
            allowed_write_paths=allowed_write_paths,
            model=request.model,
            timeout_seconds=request.timeout_seconds,
            canonical_context_ref=shared_understanding.contract_type,
            agent_session_id=agent_session_id,
        )
        agent_result = adapter.execute(agent_request)
        agent_stdout = agent_result.output.stdout
        agent_stderr_text = agent_result.output.stderr or ""
        codex_version = agent_result.provider.version
        agent_result_status = agent_result.status.value
        codex_process_exit_code = (
            agent_result.process.exit_code
            if agent_result.process is not None
            else -1
        )

    agent_stdout_sha256 = _sha256_text(agent_stdout)
    agent_stderr_sha256 = _sha256_text(agent_stderr_text)

    # ----- Codex read-only proof (RQ4 §14) -----
    try:
        assert_codex_did_not_mutate(workspace_root, fixture_sha_before)
    except RuntimeError as exc:
        return _block(
            request=request,
            workspace_root=workspace_root,
            reason=str(exc),
            execution_identity=execution_identity,
            agent_session_id=agent_session_id,
            work_contract_id=work_contract_id,
            shared_understanding=shared_understanding,
            work_contract=work_contract,
            pre_codex_source_revision=pre_codex_source_revision,
            codex_process_exit_code=codex_process_exit_code,
            codex_process_version=codex_version,
            agent_stdout_sha256=agent_stdout_sha256,
            agent_stderr_sha256=agent_stderr_sha256,
        )

    # ----- RED qualification (RQ4-R2-C2-R1 Repair A) -----
    if request.red_qualification_ref is None:
        red_qualification_ref = (
            workspace_root / ".synapx_red_evidence.json"
        ).as_posix()
    else:
        red_qualification_ref = request.red_qualification_ref

    if request.red_qualified_override is not None:
        red_qualified = bool(request.red_qualified_override)
    else:
        try:
            red_qualified = derive_red_qualification_from_evidence(
                red_qualification_ref
            )
        except Exception:
            red_qualified = False

    # ----- Mutation chain -----
    pre_apply_source_revision = _fixture_root_sha(workspace_root)
    mutation = execute_mutation_chain(
        agent_stdout=agent_stdout,
        work_contract_id=work_contract_id,
        repository_root=workspace_root,
        allowed_write_paths=allowed_write_paths,
        expected_before_sha256_by_path=before.expected_before_sha256_by_path,
        source_revision=before.source_revision,
        execution_identity_dict=execution_identity.model_dump(mode="json"),
        red_qualification_ref=red_qualification_ref,
        red_qualified=red_qualified,
        current_source_revision_at_apply=pre_apply_source_revision,
    )

    # ----- Post-apply source revision (R1) -----
    # RQ4-R2-C3-R1 §5: after the Harness write the source revision must be
    # re-captured. The Harness writes are the only legal mutations between
    # pre_apply and post_apply; if Codex had mutated the fixture the
    # Codex read-only proof above would already have failed.
    if mutation.success and mutation.apply_receipt is not None:
        post_apply_source_revision = _fixture_root_sha(workspace_root)
    else:
        post_apply_source_revision = pre_apply_source_revision

    if not mutation.success:
        verification = verify_workspace(
            repository_root=workspace_root,
            verification_command=list(
                request.verification_command or _default_verification_command()
            ),
            red_qualification_ref=red_qualification_ref,
            timeout_seconds=request.timeout_seconds,
        )
        sealed = seal_execution_evidence(
            build_evidence_envelope(
                work_contract_id=work_contract_id,
                execution_identity=execution_identity,
                proposal=mutation.proposal,
                apply_receipt=mutation.apply_receipt,
                verification=verification,
                source_revision=before.source_revision,
            )
        )
        decision, terminalization_input = finalize_terminal_decision(
            work_contract_id=work_contract_id,
            sealed_evidence=sealed,
            verification=verification,
            execution_identity=execution_identity,
            proposed_outcome=TerminalDecision.FAILED.value,
        )
        return GovernedExecutionResult(
            success=False,
            work_contract_id=work_contract_id,
            execution_identity=execution_identity,
            shared_understanding=shared_understanding,
            work_contract=work_contract,
            source_revision=before.source_revision,
            pre_codex_source_revision=pre_codex_source_revision,
            pre_apply_source_revision=pre_apply_source_revision,
            post_apply_source_revision=post_apply_source_revision,
            agent_session_id=agent_session_id,
            codex_process_exit_code=codex_process_exit_code,
            codex_process_version=codex_version,
            agent_stdout_sha256=agent_stdout_sha256,
            agent_stderr_sha256=agent_stderr_sha256,
            allowed_write_paths=list(allowed_write_paths),
            proposal=mutation.proposal,
            admission_receipt=mutation.admission_receipt,
            path_gate_receipt=mutation.path_gate_receipt,
            apply_receipt=mutation.apply_receipt,
            verification=verification,
            sealed_evidence=sealed,
            terminal_decision=decision,
            terminalization_input=terminalization_input,
            errors=[mutation.error or "mutation failed"]
            + list(mutation.validation_blockers),
        )

    # ----- Independent verification (RQ4 §20) -----
    verification = verify_workspace(
        repository_root=workspace_root,
        verification_command=list(
            request.verification_command or _default_verification_command()
        ),
        red_qualification_ref=red_qualification_ref,
        timeout_seconds=request.timeout_seconds,
    )

    # ----- Evidence seal + terminal decision (RQ4 §22) -----
    sealed = seal_execution_evidence(
        build_evidence_envelope(
            work_contract_id=work_contract_id,
            execution_identity=execution_identity,
            proposal=mutation.proposal,
            apply_receipt=mutation.apply_receipt,
            verification=verification,
            source_revision=before.source_revision,
        )
    )
    decision, terminalization_input = finalize_terminal_decision(
        work_contract_id=work_contract_id,
        sealed_evidence=sealed,
        verification=verification,
        execution_identity=execution_identity,
        proposed_outcome=(
            TerminalDecision.COMPLETED.value
            if verification.verification_status == "PASS"
            else TerminalDecision.FAILED.value
        ),
    )

    return GovernedExecutionResult(
        success=bool(decision.decision == TerminalDecision.COMPLETED.value),
        work_contract_id=work_contract_id,
        execution_identity=execution_identity,
        shared_understanding=shared_understanding,
        work_contract=work_contract,
        source_revision=before.source_revision,
        pre_codex_source_revision=pre_codex_source_revision,
        pre_apply_source_revision=pre_apply_source_revision,
        post_apply_source_revision=post_apply_source_revision,
        agent_session_id=agent_session_id,
        codex_process_exit_code=codex_process_exit_code,
        codex_process_version=codex_version,
        agent_stdout_sha256=agent_stdout_sha256,
        agent_stderr_sha256=agent_stderr_sha256,
        allowed_write_paths=list(allowed_write_paths),
        proposal=mutation.proposal,
        admission_receipt=mutation.admission_receipt,
        path_gate_receipt=mutation.path_gate_receipt,
        apply_receipt=mutation.apply_receipt,
        verification=verification,
        sealed_evidence=sealed,
        terminal_decision=decision,
        terminalization_input=terminalization_input,
        errors=[],
    )


def _block(
    *,
    request: GovernedExecutionRequest,
    workspace_root: Path,
    reason: str,
    execution_identity: ExecutionIdentity | None = None,
    agent_session_id: str | None = None,
    work_contract_id: str | None = None,
    shared_understanding: SharedUnderstandingContext | None = None,
    work_contract: WorkContract | None = None,
    pre_codex_source_revision: str = "",
    pre_apply_source_revision: str = "",
    post_apply_source_revision: str = "",
    codex_process_exit_code: int | None = None,
    codex_process_version: str | None = None,
    agent_stdout_sha256: str | None = None,
    agent_stderr_sha256: str | None = None,
) -> GovernedExecutionResult:
    """Build a BLOCKED GovernedExecutionResult for fail-closed paths.

    The Front Door never sees Agent DONE -- this is a presentation-time
    construction that emits a synthetic sealed envelope and a BLOCKED
    terminal decision so evidence lineage is preserved.
    """
    identity = execution_identity or _generate_execution_identity(workspace_root)
    session_id = agent_session_id or _compute_agent_session_id()
    wcid = work_contract_id or f"wc-{identity.root_task_id}"
    su = shared_understanding or build_shared_understanding(
        workspace_root, repository_id=request.repository_id
    )
    wc = work_contract
    if wc is None:
        wc = build_first_slice_work_contract(
            work_contract_id=wcid,
            task=request.task,
            allowed_write_paths=derive_allowed_write_paths(request.task),
            execution_identity=identity,
            source_revision="BLOCKED",
            shared_understanding=su,
        )

    red_ref = (
        request.red_qualification_ref
        or (workspace_root / ".synapx_red_evidence.json").as_posix()
    )
    verification = VerificationOutcome(
        verification_status="FAIL",
        evidence_status="INVALID",
        active_blocker_count=1,
        command_result=CommandResult(
            command_id="blocked-0",
            sanitized_command="blocked",
            working_directory=str(workspace_root),
            started_at=_now_iso(),
            finished_at=_now_iso(),
            exit_code=-1,
            stdout_path="",
            stderr_path="",
            stdout_sha256="",
            stderr_sha256="",
            stdout_size=0,
            stderr_size=0,
            gate="FAIL",
        ),
        red_qualified=False,
        red_qualification_ref=red_ref,
    )
    sealed = seal_execution_evidence(
        build_evidence_envelope(
            work_contract_id=wcid,
            execution_identity=identity,
            proposal=None,
            apply_receipt=None,
            verification=verification,
            source_revision="BLOCKED",
        )
    )
    decision, terminalization_input = finalize_terminal_decision(
        work_contract_id=wcid,
        sealed_evidence=sealed,
        verification=verification,
        execution_identity=identity,
        proposed_outcome=TerminalDecision.BLOCKED.value,
    )
    return GovernedExecutionResult(
        success=False,
        work_contract_id=wcid,
        execution_identity=identity,
        shared_understanding=su,
        work_contract=wc,
        source_revision="BLOCKED",
        pre_codex_source_revision=pre_codex_source_revision,
        pre_apply_source_revision=pre_apply_source_revision,
        post_apply_source_revision=post_apply_source_revision,
        agent_session_id=session_id,
        codex_process_exit_code=codex_process_exit_code,
        codex_process_version=codex_process_version,
        agent_stdout_sha256=agent_stdout_sha256,
        agent_stderr_sha256=agent_stderr_sha256,
        allowed_write_paths=list(derive_allowed_write_paths(request.task)),
        proposal=None,
        admission_receipt=None,
        path_gate_receipt=None,
        apply_receipt=None,
        verification=verification,
        sealed_evidence=sealed,
        terminal_decision=decision,
        terminalization_input=terminalization_input,
        errors=[reason],
    )


def _default_verification_command() -> list[str]:
    """Return the canonical first-slice verification command (pytest -q)."""
    import sys as _sys

    return [_sys.executable, "-m", "pytest", "-q"]


__all__ = [
    "CODEX_PROVIDER",
    "CODEX_SANDBOX",
    "DEFAULT_TIMEOUT_SECONDS",
    "GOVERNED_PHASE",
    "GOVERNED_RISK_CLASS",
    "GOVERNED_TASK_TYPE",
    "BeforeState",
    "GovernedExecutionRequest",
    "GovernedExecutionResult",
    "VerificationOutcome",
    "assert_codex_did_not_mutate",
    "build_agent_request",
    "build_codex_proposal_instruction",
    "build_evidence_envelope",
    "build_first_slice_work_contract",
    "build_shared_understanding",
    "build_verification_result",
    "capture_before_state",
    "derive_allowed_write_paths",
    "execute_mutation_chain",
    "finalize_terminal_decision",
    "run_governed_execution",
    "seal_execution_evidence",
    "verify_workspace",
]
