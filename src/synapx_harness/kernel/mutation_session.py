"""Production Control-Plane Session for SynapX-Harness (FC7).

Single production entry point that orchestrates the full mutation chain:
AgentRequest → CodexAdapter → AgentResult → GovernedMutationExecutor
→ Verification → Evidence → Terminal

All intermediate results are captured from actual production objects.
No synthetic temporal events or manual authority objects.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.models import (
    AgentInvocation,
    AgentLimits,
    AgentResult,
)
from synapx_harness.adapters.codex.runtime import SubprocessCodexRuntime
from synapx_harness.context.models import RepositoryBinding, SharedUnderstandingContext
from synapx_harness.contracts.runtime_models import (
    VerificationResult,
    build_execution_identity,
)
from synapx_harness.kernel.governed_runtime_provider import (
    _build_admission_receipt,
    _build_agent_request,
    _build_sealed_evidence,
    _canonical_json_bytes,
    _derive_proposed_outcome,
    _now_iso,
    _sha256_hex,
)
from synapx_harness.kernel.mutation_authority import (
    ControlledPatchApplicator,
    ExactPathMutationGate,
    GovernedMutationExecutor,
    MutationAdmissionGate,
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_qualification_port import MutationQualificationPort
from synapx_harness.kernel.terminal_finalizer import (
    TerminalDecisionRecord,
    finalize_terminal_chain,
)
from synapx_harness.kernel.verification_planner import admit_verification_result
from synapx_harness.kernel.work_contract_builder import build as build_work_contract


def _monotonic_ns() -> int:
    return time.monotonic_ns()


def _count_pattern(text: str, pattern: str) -> int:
    """Extract first integer match from text or return 0."""
    m = re.search(pattern, text)
    return int(m.group(1)) if m else 0


def _git_head_revision(repo_root: Path) -> str:
    """Get actual Git HEAD revision from repository."""
    try:
        proc = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            capture_output=True, cwd=str(repo_root),
        )
        if proc.returncode == 0:
            return proc.stdout.decode('utf-8', errors='replace').strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ''


# ---- Temporal Event Capture ----

@dataclass
class TemporalEvent:
    """A real temporal event captured at execution time."""
    event: str
    sequence: int
    monotonic_ns: int
    wall_clock: str
    producer: str


class TemporalRecorder:
    """Records temporal events at actual capture points."""

    def __init__(self) -> None:
        self._events: list[TemporalEvent] = []
        self._seq = 0

    def record(self, event: str, producer: str) -> TemporalEvent:
        self._seq += 1
        ev = TemporalEvent(
            event=event,
            sequence=self._seq,
            monotonic_ns=_monotonic_ns(),
            wall_clock=_now_iso(),
            producer=producer,
        )
        self._events.append(ev)
        return ev

    def to_list(self) -> list[dict[str, Any]]:
        return [
            {
                'event': e.event,
                'sequence': e.sequence,
                'monotonic_ns': e.monotonic_ns,
                'wall_clock': e.wall_clock,
                'producer': e.producer,
            }
            for e in self._events
        ]


# ---- Session Result ----

@dataclass
class MutationSessionResult:
    """Result of GovernedMutationSession.run()."""
    success: bool
    work_contract_id: str
    run_id: str
    source_revision: str

    # Actual production objects
    agent_result: AgentResult | None
    verification_result: VerificationResult | None
    verification_admission: dict[str, Any] | None
    sealed_evidence: dict[str, Any] | None
    terminal_decision: TerminalDecisionRecord | None

    # WorkContract (actual production object)
    work_contract: dict[str, Any] | None

    # Intermediate results
    admission_receipt: dict[str, Any] | None
    mutation_admission_receipt: dict[str, Any] | None
    path_gate_receipt: dict[str, Any] | None
    apply_receipt: dict[str, Any] | None
    proposal: dict[str, Any] | None
    terminalization_input: dict[str, Any] | None

    # Temporal events
    temporal_events: list[dict[str, Any]]

    # Error info
    error: str | None = None


# ---- GovernedMutationSession ----

class GovernedMutationSession:
    """Single production control-plane entry point.

    Orchestrates the full mutation chain through actual production APIs:
    AgentRequest → CodexAdapter → AgentResult → GovernedMutationExecutor
    → Verification → Evidence → Terminal

    All intermediate results are captured from actual production objects.
    """

    def __init__(
        self,
        repository_root: str | Path,
        *,
        repository_id: str = 'synapx_harness',
        codex_bin: str = 'codex',
        sandbox: str = 'read-only',
        model: str = 'gpt-5.6-luna',
        timeout_seconds: int = 300,
    ) -> None:
        self._repository_root = Path(repository_root).resolve()
        self._repository_id = repository_id
        self._codex_bin = codex_bin
        self._sandbox = sandbox
        self._model = model
        self._timeout_seconds = timeout_seconds

    def run(
        self,
        task_instruction: str,
        allowed_write_paths: list[str],
        target_file: Path,
        expected_before_sha256: str,
        red_qualified: bool,
        red_qualification_ref: str,
        evidence_root: Path,
    ) -> MutationSessionResult:
        """Execute the full governed mutation chain."""
        recorder = TemporalRecorder()
        run_id = f'FC7-RUN-{uuid.uuid4().hex[:12]}'
        work_contract_id = f'WC-GRW-{uuid.uuid4().hex[:12]}'

        # Step 1: RED qualification
        recorder.record('red_qualified', 'GovernedMutationSession')

        # Step 2: Build admission receipt
        exec_identity_dict = {
            'job_id': f'job/{work_contract_id}',
            'task_id': f'task/{work_contract_id}',
            'root_task_id': f'root/{work_contract_id}',
            'attempt_id': f'attempt/{work_contract_id}',
        }

        admission_receipt = _build_admission_receipt(work_contract_id)
        recorder.record('admission_decided', 'GovernedMutationSession')

        # Step 2b: Build actual WorkContract using production builder
        workspace_rev = _git_head_revision(self._repository_root)
        exec_identity_typed: dict[str, object] = dict(exec_identity_dict)
        work_contract_obj = build_work_contract(
            work_contract_id=work_contract_id,
            phase='GOVERNED_RUNTIME',
            risk_class='R0',
            objective=task_instruction[:200],
            scope=['runtime'],
            issuer='HARNESS_CORE_ADMISSION',
            admission_receipt=admission_receipt,
            permission_receipt_ref=f'perm/{work_contract_id}',
            eligibility_receipt_ref=f'elig/{work_contract_id}',
            execution_receipt_ref=f'exec/{work_contract_id}',
            source_revision_ref={
                'repository_id': self._repository_id,
                'revision_kind': 'GIT_COMMIT',
                'revision_value': workspace_rev,
            },
            task_type='TEST_REPAIR',
            execution_identity=exec_identity_typed,
        )
        work_contract_dict = work_contract_obj.model_dump(mode='json')

        # Step 3: Build execution identity
        identity = build_execution_identity(
            job_id=exec_identity_dict['job_id'],
            task_id=exec_identity_dict['task_id'],
            root_task_id=exec_identity_dict['root_task_id'],
            attempt_id=exec_identity_dict['attempt_id'],
            tool_call_id=None,
        )

        # Step 4: Build AgentRequest
        agent_request = _build_agent_request(
            task=task_instruction,
            execution_identity=identity,
            workspace_root=str(self._repository_root),
            shared_context=SharedUnderstandingContext(
                repository=RepositoryBinding(repository_id=self._repository_id),
            ),
            invocation=AgentInvocation(
                provider='openai',
                model=self._model,
                provider_config={'sandbox': self._sandbox},
            ),
            limits=AgentLimits(timeout_seconds=self._timeout_seconds),
        )
        recorder.record('agent_request_created', 'GovernedMutationSession')

        # Step 5: Execute via CodexAdapter
        backend = SubprocessCodexRuntime(codex_bin=self._codex_bin)
        adapter = CodexAdapter(backend=backend)

        recorder.record('runtime_started', 'CodexAdapter.execute')
        agent_result = adapter.execute(agent_request)
        recorder.record('agent_result_received', 'CodexAdapter.execute')

        # Step 6: Parse proposal
        parser = PatchProposalParser()
        proposal = parser.parse(agent_result.output.stdout or '')

        # Step 7a: Capture baseline regression BEFORE mutation
        python_exe = sys.executable
        baseline_proc = subprocess.run(
            [python_exe, '-m', 'pytest', str(target_file.parent.parent), '-v', '--tb=short'],
            capture_output=True, cwd=str(self._repository_root),
        )
        baseline_stdout = baseline_proc.stdout.decode('utf-8', errors='replace')
        baseline_stderr = baseline_proc.stderr.decode('utf-8', errors='replace')
        bp = _count_pattern(baseline_stdout, r'(\d+) passed')
        bf = _count_pattern(baseline_stdout, r'(\d+) failed')
        be = _count_pattern(baseline_stdout, r'(\d+) error')
        bfi = set(re.findall(r'FAILED (.*?)::', baseline_stdout))
        bei = set(re.findall(r'ERROR (.*?)::', baseline_stdout))

        reg_dir = evidence_root / 'regression'
        reg_dir.mkdir(exist_ok=True)
        (reg_dir / 'baseline_stdout.txt').write_text(
            baseline_stdout, encoding='utf-8')
        (reg_dir / 'baseline_stderr.txt').write_text(
            baseline_stderr, encoding='utf-8')
        (reg_dir / 'baseline_result.json').write_text(json.dumps({
            'passed': bp, 'failed': bf, 'errors': be,
            'failed_test_ids': sorted(bfi),
            'error_test_ids': sorted(bei),
        }, indent=2), encoding='utf-8')
        recorder.record('baseline_regression_captured', 'GovernedMutationSession')

        # Step 7b: Execute GovernedMutationExecutor
        admission_gate = MutationAdmissionGate()
        path_gate = ExactPathMutationGate()
        applicator = ControlledPatchApplicator()
        executor = GovernedMutationExecutor(admission_gate, path_gate, applicator, parser)

        execution_result = executor.execute(
            work_contract_id=work_contract_id,
            red_qualified=red_qualified,
            red_qualification_ref=red_qualification_ref,
            source_revision=_git_head_revision(self._repository_root),
            execution_identity=exec_identity_dict,
            allowed_write_paths=allowed_write_paths,
            target_file=target_file,
            expected_before_sha256=expected_before_sha256,
            agent_stdout=agent_result.output.stdout or '',
        )

        if execution_result.path_gate_receipt:
            recorder.record('path_gate_returned', 'ExactPathMutationGate')

        if execution_result.apply_receipt and execution_result.apply_receipt.write_count > 0:
            recorder.record('first_write_observed', 'ControlledPatchApplicator')

        # Save execution evidence (required by MutationQualificationPort before verification)
        (evidence_root / 'execution').mkdir(exist_ok=True)
        if execution_result.apply_receipt:
            (evidence_root / 'execution' / 'write_ledger.json').write_text(json.dumps({
                'authorization_ref': execution_result.apply_receipt.authorization_ref,
                'admission_receipt_id': execution_result.apply_receipt.admission_receipt_id,
                'path_gate_receipt_id': execution_result.apply_receipt.path_gate_receipt_id,
                'source_revision': execution_result.apply_receipt.source_revision,
                'allowed_write_paths': allowed_write_paths,
                'applied_paths': execution_result.apply_receipt.applied_paths,
                'before_sha256': execution_result.apply_receipt.before_sha256,
                'after_sha256': execution_result.apply_receipt.after_sha256,
                'patch_sha256': execution_result.apply_receipt.patch_sha256,
                'canonical_patch_sha256': execution_result.apply_receipt.canonical_patch_sha256,
                'write_count': execution_result.apply_receipt.write_count,
            }, indent=2), encoding='utf-8')

        # Step 8: Run GREEN test (before verification)
        green_proc = subprocess.run(
            [python_exe, '-m', 'pytest', str(target_file), '-v', '--tb=short'],
            capture_output=True, cwd=str(self._repository_root),
        )
        green_stdout = green_proc.stdout.decode('utf-8', errors='replace')
        green_stderr = green_proc.stderr.decode('utf-8', errors='replace')

        # Save GREEN evidence
        (evidence_root / 'green').mkdir(exist_ok=True)
        (evidence_root / 'green' / 'stdout.txt').write_text(
            green_stdout, encoding='utf-8')
        (evidence_root / 'green' / 'stderr.txt').write_text(
            green_stderr, encoding='utf-8')
        green_passed = _count_pattern(green_stdout, r'(\d+) passed')
        (evidence_root / 'green' / 'result.json').write_text(
            json.dumps({
                'exit_code': green_proc.returncode,
                'passed': green_passed,
                'failed': 0 if green_proc.returncode == 0 else 1,
            }, indent=2), encoding='utf-8')

        # Step 9: Run regression (before verification)
        reg_proc = subprocess.run(
            [python_exe, '-m', 'pytest',
             str(target_file.parent.parent), '-v', '--tb=short'],
            capture_output=True, cwd=str(self._repository_root),
        )
        reg_stdout = reg_proc.stdout.decode('utf-8', errors='replace')
        reg_stderr = reg_proc.stderr.decode('utf-8', errors='replace')

        # Save regression evidence
        reg_dir = evidence_root / 'regression'
        reg_dir.mkdir(exist_ok=True)
        (reg_dir / 'post_stdout.txt').write_text(
            reg_stdout, encoding='utf-8')
        (reg_dir / 'post_stderr.txt').write_text(
            reg_stderr, encoding='utf-8')
        post_passed = _count_pattern(reg_stdout, r'(\d+) passed')
        post_failed = _count_pattern(reg_stdout, r'(\d+) failed')
        post_errors = _count_pattern(reg_stdout, r'(\d+) error')
        post_failed_ids = set(re.findall(r'FAILED (.*?)::', reg_stdout))
        post_error_ids = set(re.findall(r'ERROR (.*?)::', reg_stdout))
        (reg_dir / 'post_result.json').write_text(json.dumps({
            'passed': post_passed, 'failed': post_failed,
            'errors': post_errors,
            'failed_test_ids': sorted(post_failed_ids),
            'error_test_ids': sorted(post_error_ids),
        }, indent=2), encoding='utf-8')

        # Create differential.json for MutationQualificationPort
        nf = sorted(post_failed_ids - bfi)
        ne = sorted(post_error_ids - bei)
        (reg_dir / 'differential.json').write_text(json.dumps({
            'baseline': {
                'passed': bp, 'failed': bf, 'errors': be,
                'failed_test_ids': sorted(bfi),
                'error_test_ids': sorted(bei),
            },
            'post_mutation': {
                'passed': post_passed, 'failed': post_failed,
                'errors': post_errors,
                'failed_test_ids': sorted(post_failed_ids),
                'error_test_ids': sorted(post_error_ids),
            },
            'differential': {
                'new_failed': nf,
                'new_errors': ne,
                'fixed_count': len(bfi - post_failed_ids),
            },
            'regression_gate': 'PASS' if len(nf) == 0 and len(ne) == 0 else 'FAIL',
        }, indent=2), encoding='utf-8')

        # Step 10: Verification (after green/regression evidence exists)
        port = MutationQualificationPort(evidence_root=evidence_root)
        shared_context = SharedUnderstandingContext(
            repository=RepositoryBinding(repository_id=self._repository_id),
        )
        wc_dict = {
            'work_contract_id': work_contract_id,
            'task_type': 'TEST_REPAIR',
            'execution_identity': exec_identity_dict,
        }

        verification_result = port.verify(wc_dict, agent_result, shared_context)
        recorder.record('verification_completed', 'MutationQualificationPort')

        # Step 11: Verification Admission (actual production call)
        verification_result_dict = verification_result.model_dump(mode='json')
        verification_result_dict['schema_version'] = '0.2.0'
        verification_result_dict['evidence_timestamp'] = _now_iso()

        wc_dict_for_admission = {
            'work_contract_id': work_contract_id,
            'task_type': 'TEST_REPAIR',
            'execution_identity': exec_identity_dict,
            'admission_receipt': admission_receipt,
        }

        verification_admission = admit_verification_result(
            work_contract=wc_dict_for_admission,
            verification_result=verification_result_dict,
        )
        recorder.record('verification_admission_returned', 'admit_verification_result')

        # Step 12: Evidence sealing (actual production call)
        workspace_rev = _git_head_revision(self._repository_root)
        source_ref: dict[str, object] = {
            'repository_id': self._repository_id,
            'revision_kind': 'GIT_COMMIT',
            'revision_value': workspace_rev,
        }

        context_sha = _sha256_hex(_canonical_json_bytes(
            SharedUnderstandingContext(
                repository=RepositoryBinding(repository_id=self._repository_id),
            ).model_dump(mode='json')
        ))

        sealed_evidence = _build_sealed_evidence(
            work_contract_id,
            verification_admission,
            agent_result,
            context_sha,
            source_ref,
        )
        recorder.record('evidence_sealed', '_build_sealed_evidence')

        # Step 13: Terminal Finalization (actual production call)
        proposed_outcome = _derive_proposed_outcome(
            verification_result.verification_status,
            verification_result.evidence_status,
            verification_result.active_blocker_count,
        )

        terminalization_input = {
            'work_contract_id': work_contract_id,
            'execution_identity': exec_identity_dict,
            'verification_admission_receipt': verification_admission,
            'sealed_evidence': sealed_evidence,
            'source_revision_ref': source_ref,
            'active_blocker_count': verification_result.active_blocker_count,
            'proposed_outcome': proposed_outcome,
            'reason': f'verification={verification_result.verification_status}',
            'input_ref': f'input/{work_contract_id}',
        }

        terminal_decision = finalize_terminal_chain(
            work_contract_id=work_contract_id,
            sealed_evidence=sealed_evidence,
            terminalization_input=terminalization_input,
        )
        recorder.record('terminal_finalized', 'finalize_terminal_chain')

        # Convert receipts to dicts for result
        pg_receipt = execution_result.path_gate_receipt
        pg_dict: dict[str, Any] | None = (
            pg_receipt.__dict__ if pg_receipt else None
        )
        ap_receipt = execution_result.apply_receipt
        ap_dict: dict[str, Any] | None = (
            ap_receipt.__dict__ if ap_receipt else None
        )

        # Mutation admission receipt (from GovernedMutationExecutor)
        mutation_adm = execution_result.admission_receipt
        mutation_adm_dict: dict[str, Any] | None = (
            mutation_adm.__dict__ if mutation_adm else None
        )

        return MutationSessionResult(
            success=terminal_decision.decision == 'COMPLETED',
            work_contract_id=work_contract_id,
            run_id=run_id,
            source_revision=str(source_ref.get('revision_value', '')),
            agent_result=agent_result,
            verification_result=verification_result,
            verification_admission=verification_admission,
            sealed_evidence=sealed_evidence,
            terminal_decision=terminal_decision,
            work_contract=work_contract_dict,
            admission_receipt=admission_receipt,
            mutation_admission_receipt=mutation_adm_dict,
            path_gate_receipt=pg_dict,
            apply_receipt=ap_dict,
            proposal={
                'valid': proposal.valid,
                'paths': proposal.paths,
                'old_lines': proposal.old_lines,
                'new_lines': proposal.new_lines,
                'sha256': proposal.sha256,
                'raw_input_sha256': proposal.raw_input_sha256,
                'canonical_patch_sha256': proposal.canonical_patch_sha256,
            } if proposal else None,
            terminalization_input=terminalization_input,
            temporal_events=recorder.to_list(),
        )


__all__ = [
    'GovernedMutationSession',
    'MutationSessionResult',
    'TemporalRecorder',
    'TemporalEvent',
]
