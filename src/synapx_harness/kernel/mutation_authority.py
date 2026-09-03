"""Production Mutation Authority for SynapX-Harness (FC6).

Implements the production capabilities required for controlled mutation:
1. PatchProposalParser - parses agent output to extract patch proposal
2. MutationAdmissionGate - pre-write RED qualification gate
3. ExactPathMutationGate - validates patch paths against allowlist
4. ControlledPatchApplicator - applies validated patch with full authority chain
5. GovernedMutationExecutor - orchestrates the full mutation chain

Invariant: Agent proposes. Harness parses. Harness authorizes. Harness applies.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_patch_bytes(paths: list[str], old_lines: list[str], new_lines: list[str]) -> bytes:
    """Generate canonical patch bytes for consistent SHA computation."""
    return f"{':'.join(paths)}|{':'.join(old_lines)}|{':'.join(new_lines)}".encode()


# ---- PatchProposalParser ----

@dataclass
class PatchHunk:
    """A single hunk in a parsed patch proposal."""
    file_path: str
    old_lines: list[str]
    new_lines: list[str]
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


@dataclass
class PatchProposal:
    """Result of parsing a patch proposal from agent output."""
    valid: bool
    paths: list[str]
    hunks: list[PatchHunk]
    old_lines: list[str]
    new_lines: list[str]
    sha256: str
    raw_input_sha256: str
    canonical_patch_sha256: str
    parse_error: str | None = None


class PatchProposalParser:
    """Parses agent output to extract a structured patch proposal.

    Input: RawRuntimeResult.stdout or AgentOutput.stdout
    Output: PatchProposal with paths, hunks, old/new lines, sha256

    Handles:
    - Unified diff format
    - "Change X to Y" format
    - Code block format with before/after
    """

    def parse(self, stdout: str) -> PatchProposal:
        """Parse agent stdout to extract patch proposal."""
        raw_sha = hashlib.sha256(stdout.encode('utf-8')).hexdigest()

        if not stdout or not stdout.strip():
            return PatchProposal(
                valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
                sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
                parse_error='Empty stdout',
            )

        # Try unified diff format first
        proposal = self._parse_unified_diff(stdout, raw_sha)
        if proposal.valid:
            return proposal

        # Try "change X to Y" format
        proposal = self._parse_change_format(stdout, raw_sha)
        if proposal.valid:
            return proposal

        # Try code block format
        proposal = self._parse_code_block(stdout, raw_sha)
        if proposal.valid:
            return proposal

        return PatchProposal(
            valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
            sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
            parse_error='No valid patch proposal found in output',
        )

    def _parse_unified_diff(self, stdout: str, raw_sha: str) -> PatchProposal:
        """Parse unified diff format."""
        file_pattern = re.compile(r'(?:^|\n)--- a/(.+?)$', re.MULTILINE)
        new_file_pattern = re.compile(r'(?:^|\n)\+\+\+ b/(.+?)$', re.MULTILINE)

        files = file_pattern.findall(stdout)
        new_files = new_file_pattern.findall(stdout)

        if not files and not new_files:
            old_lines = re.findall(r'^- (.+)$', stdout, re.MULTILINE)
            new_lines = re.findall(r'^\+ (.+)$', stdout, re.MULTILINE)

            if old_lines and new_lines:
                path_match = re.search(r'(?:^|\s)([\w/]+\.py)', stdout)
                path = path_match.group(1) if path_match else 'unknown'

                hunk = PatchHunk(
                    file_path=path,
                    old_lines=[line.strip() for line in old_lines],
                    new_lines=[line.strip() for line in new_lines],
                )
                canonical = _canonical_patch_bytes([path], old_lines, new_lines)
                proposal_sha = hashlib.sha256(canonical).hexdigest()
                return PatchProposal(
                    valid=True, paths=[path], hunks=[hunk],
                    old_lines=[line.strip() for line in old_lines],
                    new_lines=[line.strip() for line in new_lines],
                    sha256=proposal_sha, raw_input_sha256=raw_sha,
                    canonical_patch_sha256=proposal_sha,
                )
            return PatchProposal(
                valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
                sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
            )

        paths = list(set(files + new_files))
        old_lines = [
            line.strip()
            for line in re.findall(r'^- (.+)$', stdout, re.MULTILINE)
            if not line.startswith('---')
        ]
        new_lines = [
            line.strip()
            for line in re.findall(r'^\+ (.+)$', stdout, re.MULTILINE)
            if not line.startswith('+++')
        ]

        if old_lines and new_lines:
            hunks = [PatchHunk(
                file_path=paths[0] if paths else 'unknown',
                old_lines=old_lines,
                new_lines=new_lines,
            )]
            canonical = _canonical_patch_bytes(paths, old_lines, new_lines)
            proposal_sha = hashlib.sha256(canonical).hexdigest()
            return PatchProposal(
                valid=True, paths=paths, hunks=hunks,
                old_lines=old_lines, new_lines=new_lines,
                sha256=proposal_sha, raw_input_sha256=raw_sha,
                canonical_patch_sha256=proposal_sha,
            )

        return PatchProposal(
            valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
            sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
        )

    def _parse_change_format(self, stdout: str, raw_sha: str) -> PatchProposal:
        """Parse 'change X to Y' or 'from: X to: Y' format."""
        from_pattern = re.compile(
            r'(?:from|old|current).*?:\s*(.+?)(?:\n|$)', re.IGNORECASE
        )
        to_pattern = re.compile(
            r'(?:to|new|change to|replace with).*?:\s*(.+?)(?:\n|$)', re.IGNORECASE
        )

        from_matches = from_pattern.findall(stdout)
        to_matches = to_pattern.findall(stdout)

        if from_matches and to_matches:
            old_line = from_matches[0].strip().strip('`\'"')
            new_line = to_matches[0].strip().strip('`\'"')

            if old_line and new_line and old_line != new_line:
                path_match = re.search(
                    r'(?:file|path|in)\s+[\w/]*?([\w]+\.py)', stdout, re.IGNORECASE
                )
                path = path_match.group(0).split()[-1] if path_match else 'unknown'

                hunk = PatchHunk(
                    file_path=path,
                    old_lines=[old_line],
                    new_lines=[new_line],
                )
                canonical = _canonical_patch_bytes([path], [old_line], [new_line])
                proposal_sha = hashlib.sha256(canonical).hexdigest()
                return PatchProposal(
                    valid=True, paths=[path], hunks=[hunk],
                    old_lines=[old_line], new_lines=[new_line],
                    sha256=proposal_sha, raw_input_sha256=raw_sha,
                    canonical_patch_sha256=proposal_sha,
                )

        return PatchProposal(
            valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
            sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
        )

    def _parse_code_block(self, stdout: str, raw_sha: str) -> PatchProposal:
        """Parse code block format with before/after."""
        before_pattern = re.compile(r'(?:before|old|current).*?```(?:\w+)?\s*\n(.+?)```',
                                    re.IGNORECASE | re.DOTALL)
        after_pattern = re.compile(r'(?:after|new|result).*?```(?:\w+)?\s*\n(.+?)```',
                                   re.IGNORECASE | re.DOTALL)

        before_matches = before_pattern.findall(stdout)
        after_matches = after_pattern.findall(stdout)

        if before_matches and after_matches:
            old_lines = [
                line.strip()
                for line in before_matches[0].strip().split('\n')
                if line.strip()
            ]
            new_lines = [
                line.strip()
                for line in after_matches[0].strip().split('\n')
                if line.strip()
            ]

            if old_lines and new_lines:
                path_match = re.search(
                    r'(?:file|path|in)\s+[\w/]*?([\w]+\.py)', stdout, re.IGNORECASE
                )
                path = path_match.group(0).split()[-1] if path_match else 'unknown'

                hunk = PatchHunk(
                    file_path=path,
                    old_lines=old_lines,
                    new_lines=new_lines,
                )
                canonical = _canonical_patch_bytes([path], old_lines, new_lines)
                proposal_sha = hashlib.sha256(canonical).hexdigest()
                return PatchProposal(
                    valid=True, paths=[path], hunks=[hunk],
                    old_lines=old_lines, new_lines=new_lines,
                    sha256=proposal_sha, raw_input_sha256=raw_sha,
                    canonical_patch_sha256=proposal_sha,
                )

        return PatchProposal(
            valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
            sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
        )


# ---- MutationAdmissionGate ----

@dataclass
class AdmissionReceipt:
    """Receipt from MutationAdmissionGate."""
    receipt_id: str
    admission_decision: str  # ALLOW or DENY
    work_contract_id: str
    red_qualified: bool
    red_qualification_ref: str
    source_revision: str
    execution_identity: dict[str, Any]
    mutation_authority: dict[str, Any]
    admitted_at: str
    denied_reason: str | None = None


class MutationAdmissionGate:
    """Pre-write RED qualification gate.

    Checks RED qualification before allowing mutation.
    If RED is not qualified, mutation is DENIED.
    """

    def admit(
        self,
        work_contract_id: str,
        red_qualified: bool,
        red_qualification_ref: str,
        source_revision: str,
        execution_identity: dict[str, Any],
        allowed_write_paths: list[str],
        denied_reason: str | None = None,
    ) -> AdmissionReceipt:
        """Check RED qualification and issue admission receipt."""
        decision = 'ALLOW' if red_qualified and not denied_reason else 'DENY'

        return AdmissionReceipt(
            receipt_id=f'rct/{work_contract_id}',
            admission_decision=decision,
            work_contract_id=work_contract_id,
            red_qualified=red_qualified,
            red_qualification_ref=red_qualification_ref,
            source_revision=source_revision,
            execution_identity=execution_identity,
            mutation_authority={
                'mode': 'EXACT_PATHS',
                'allowed_write_paths': allowed_write_paths,
            },
            admitted_at=_now_iso(),
            denied_reason=denied_reason,
        )


# ---- ExactPathMutationGate ----

@dataclass
class PathGateReceipt:
    """Receipt from ExactPathMutationGate (FC6 enhanced)."""
    gate_decision: str  # ALLOW or DENY
    apply_authority: str  # ISSUED or NOT_ISSUED
    proposal_sha256: str
    canonical_patch_sha256: str
    authorized_paths: list[str]
    proposal_paths: list[str]
    source_revision: str
    admission_receipt_id: str
    reason: str | None = None


class ExactPathMutationGate:
    """Validates patch proposal paths against allowed paths.

    Only issues apply authority when proposal paths exactly match allowed paths.
    FC6: includes proposal SHA, source revision, and admission receipt binding.
    """

    def check(
        self,
        proposal: PatchProposal,
        allowed_write_paths: list[str],
        source_revision: str,
        admission_receipt_id: str,
    ) -> PathGateReceipt:
        """Validate proposal paths against allowlist."""
        proposal_set = set(proposal.paths)
        allowed_set = set(allowed_write_paths)

        if proposal_set == allowed_set:
            return PathGateReceipt(
                gate_decision='ALLOW',
                apply_authority='ISSUED',
                proposal_sha256=proposal.sha256,
                canonical_patch_sha256=proposal.canonical_patch_sha256,
                authorized_paths=allowed_write_paths,
                proposal_paths=proposal.paths,
                source_revision=source_revision,
                admission_receipt_id=admission_receipt_id,
            )
        else:
            unauthorized = proposal_set - allowed_set
            return PathGateReceipt(
                gate_decision='DENY',
                apply_authority='NOT_ISSUED',
                proposal_sha256=proposal.sha256,
                canonical_patch_sha256=proposal.canonical_patch_sha256,
                authorized_paths=allowed_write_paths,
                proposal_paths=proposal.paths,
                source_revision=source_revision,
                admission_receipt_id=admission_receipt_id,
                reason=f'Unauthorized paths: {sorted(unauthorized)}',
            )


# ---- ControlledPatchApplicator ----

@dataclass
class ApplyReceipt:
    """Receipt from ControlledPatchApplicator (FC6 enhanced)."""
    applied_paths: list[str]
    before_sha256: str
    after_sha256: str
    patch_sha256: str
    canonical_patch_sha256: str
    write_count: int
    apply_started_at: str
    apply_completed_at: str
    authorization_ref: str
    admission_receipt_id: str
    path_gate_receipt_id: str
    source_revision: str


class ControlledPatchApplicator:
    """Applies validated patch to target files (FC6 enhanced).

    Validates full authority chain before applying:
    - Admission == ALLOW
    - PathGate == ALLOW
    - apply_authority == ISSUED
    - proposal.paths == PathGate.authorized_paths
    - proposal.sha256 == PathGate.patch_sha256
    - source_revision == Admission.source_revision
    - actual before hash == expected_before_sha256

    If any check fails, write_count = 0.
    """

    def apply(
        self,
        target_file: Path,
        proposal: PatchProposal,
        path_gate_receipt: PathGateReceipt,
        admission_receipt: AdmissionReceipt,
        expected_before_sha256: str,
        normalize_line_endings: bool = True,
    ) -> ApplyReceipt:
        """Apply the validated patch with full authority chain validation."""
        apply_started = _now_iso()

        # ---- Authority chain validation ----
        # Check admission
        if admission_receipt.admission_decision != 'ALLOW':
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id='',
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='Admission DENIED',
            )

        # Check path gate
        if path_gate_receipt.gate_decision != 'ALLOW':
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='PathGate DENIED',
            )

        # Check apply authority
        if path_gate_receipt.apply_authority != 'ISSUED':
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='Apply authority NOT ISSUED',
            )

        # Check proposal paths == authorized paths
        if set(proposal.paths) != set(path_gate_receipt.authorized_paths):
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='Proposal paths != authorized paths',
            )

        # Check proposal SHA == path gate SHA
        if proposal.sha256 != path_gate_receipt.proposal_sha256:
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='Proposal SHA mismatch',
            )

        # Check source revision
        if admission_receipt.source_revision != path_gate_receipt.source_revision:
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='Source revision mismatch',
            )

        # ---- Apply the patch ----
        before_bytes = target_file.read_bytes()
        before_sha = hashlib.sha256(before_bytes).hexdigest()

        # Check expected before hash
        if before_sha != expected_before_sha256:
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason=(
                    f'Before hash mismatch: expected '
                    f'{expected_before_sha256[:12]}..., got {before_sha[:12]}...'
                ),
            )

        # Get old/new content from proposal
        old_content = proposal.old_lines[0] if proposal.old_lines else ''
        new_content = proposal.new_lines[0] if proposal.new_lines else ''

        old_bytes = old_content.encode('utf-8')
        new_bytes = new_content.encode('utf-8')

        if old_bytes not in before_bytes:
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason='Old content not found in target file',
            )

        # Apply the change
        after_bytes = before_bytes.replace(old_bytes, new_bytes)

        # Normalize line endings if needed
        if normalize_line_endings and b'\r\n' in after_bytes:
            after_bytes = after_bytes.replace(b'\r\n', b'\n')

        # Write after state
        target_file.write_bytes(after_bytes)

        after_sha = hashlib.sha256(after_bytes).hexdigest()
        apply_completed = _now_iso()

        repo_root_for_relative = target_file.parent.parent.parent.parent
        applied_path = str(target_file.relative_to(repo_root_for_relative)).replace(
            '\\', '/'
        )
        return ApplyReceipt(
            applied_paths=[applied_path],
            before_sha256=before_sha,
            after_sha256=after_sha,
            patch_sha256=proposal.sha256,
            canonical_patch_sha256=proposal.canonical_patch_sha256,
            write_count=1,
            apply_started_at=apply_started,
            apply_completed_at=apply_completed,
            authorization_ref=admission_receipt.receipt_id,
            admission_receipt_id=admission_receipt.receipt_id,
            path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
            source_revision=admission_receipt.source_revision,
        )

    def _empty_receipt(
        self,
        authorization_ref: str,
        admission_receipt_id: str,
        path_gate_receipt_id: str,
        source_revision: str,
        apply_started: str,
        reason: str,
    ) -> ApplyReceipt:
        """Return an empty receipt when validation fails."""
        return ApplyReceipt(
            applied_paths=[],
            before_sha256='',
            after_sha256='',
            patch_sha256='',
            canonical_patch_sha256='',
            write_count=0,
            apply_started_at=apply_started,
            apply_completed_at=_now_iso(),
            authorization_ref=authorization_ref,
            admission_receipt_id=admission_receipt_id,
            path_gate_receipt_id=path_gate_receipt_id,
            source_revision=source_revision,
        )


# ---- GovernedMutationExecutor ----

@dataclass
class MutationExecutionResult:
    """Result of GovernedMutationExecutor.execute()."""
    success: bool
    work_contract_id: str
    admission_receipt: AdmissionReceipt | None
    path_gate_receipt: PathGateReceipt | None
    apply_receipt: ApplyReceipt | None
    proposal: PatchProposal | None
    error: str | None = None


class GovernedMutationExecutor:
    """Orchestrates the full mutation chain with fail-closed semantics.

    Invariant:
    RED Qualification
    -> MutationAdmissionGate ALLOW
    -> CodexAdapter read-only
    -> PatchProposalParser
    -> ExactPathMutationGate ALLOW
    -> ControlledPatchApplicator

    If any step fails, applicator is not reached.
    """

    def __init__(
        self,
        admission_gate: MutationAdmissionGate,
        path_gate: ExactPathMutationGate,
        applicator: ControlledPatchApplicator,
        parser: PatchProposalParser,
    ) -> None:
        self._admission_gate = admission_gate
        self._path_gate = path_gate
        self._applicator = applicator
        self._parser = parser

    def execute(
        self,
        work_contract_id: str,
        red_qualified: bool,
        red_qualification_ref: str,
        source_revision: str,
        execution_identity: dict[str, Any],
        allowed_write_paths: list[str],
        target_file: Path,
        expected_before_sha256: str,
        agent_stdout: str,
    ) -> MutationExecutionResult:
        """Execute the full mutation chain."""
        # Step 1: Admission
        admission = self._admission_gate.admit(
            work_contract_id=work_contract_id,
            red_qualified=red_qualified,
            red_qualification_ref=red_qualification_ref,
            source_revision=source_revision,
            execution_identity=execution_identity,
            allowed_write_paths=allowed_write_paths,
        )

        if admission.admission_decision != 'ALLOW':
            return MutationExecutionResult(
                success=False,
                work_contract_id=work_contract_id,
                admission_receipt=admission,
                path_gate_receipt=None,
                apply_receipt=None,
                proposal=None,
                error=f'Admission DENIED: {admission.denied_reason}',
            )

        # Step 2: Parse proposal
        proposal = self._parser.parse(agent_stdout)
        if not proposal.valid:
            return MutationExecutionResult(
                success=False,
                work_contract_id=work_contract_id,
                admission_receipt=admission,
                path_gate_receipt=None,
                apply_receipt=None,
                proposal=proposal,
                error=f'Proposal INVALID: {proposal.parse_error}',
            )

        # Step 3: Path gate
        path_gate = self._path_gate.check(
            proposal=proposal,
            allowed_write_paths=allowed_write_paths,
            source_revision=source_revision,
            admission_receipt_id=admission.receipt_id,
        )

        if path_gate.gate_decision != 'ALLOW':
            return MutationExecutionResult(
                success=False,
                work_contract_id=work_contract_id,
                admission_receipt=admission,
                path_gate_receipt=path_gate,
                apply_receipt=None,
                proposal=proposal,
                error=f'PathGate DENIED: {path_gate.reason}',
            )

        # Step 4: Apply
        apply_receipt = self._applicator.apply(
            target_file=target_file,
            proposal=proposal,
            path_gate_receipt=path_gate,
            admission_receipt=admission,
            expected_before_sha256=expected_before_sha256,
        )

        if apply_receipt.write_count == 0:
            return MutationExecutionResult(
                success=False,
                work_contract_id=work_contract_id,
                admission_receipt=admission,
                path_gate_receipt=path_gate,
                apply_receipt=apply_receipt,
                proposal=proposal,
                error='Apply failed: write_count = 0',
            )

        return MutationExecutionResult(
            success=True,
            work_contract_id=work_contract_id,
            admission_receipt=admission,
            path_gate_receipt=path_gate,
            apply_receipt=apply_receipt,
            proposal=proposal,
        )


__all__ = [
    'PatchProposalParser', 'PatchProposal', 'PatchHunk',
    'MutationAdmissionGate', 'AdmissionReceipt',
    'ExactPathMutationGate', 'PathGateReceipt',
    'ControlledPatchApplicator', 'ApplyReceipt',
    'GovernedMutationExecutor', 'MutationExecutionResult',
]
