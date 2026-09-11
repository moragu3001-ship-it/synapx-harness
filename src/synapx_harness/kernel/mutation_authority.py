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

from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)


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

    # -- RQ4-R2 strict canonical decoder ---------------------------------
    # The three heuristic strategies above exist for legacy compatibility.
    # They accept free-form prose, and RQ4-R2 §5 forbids applying free-form
    # prose as code. ``parse_structured`` is the ONLY decoder used on the
    # governed public path: it accepts exactly one deterministic encoding of
    # the SAME canonical ``PatchProposal`` contract and nothing else.

    def parse_structured(self, stdout: str) -> PatchProposal:
        """Decode the canonical structured proposal encoding.

        Returns a canonical :class:`PatchProposal`. On any deviation from the
        encoding the returned proposal has ``valid=False`` and a deterministic
        ``parse_error``; it is never partially applied.

        RQ4-R2-C2 strictness: ``stdout.strip()`` must equal exactly one
        complete framed proposal. Any leading/trailing prose, multiple
        proposal blocks, or extra content is rejected. Whitespace-only
        framing around the proposal is allowed (it is stripped before the
        equality check). Codex must comply with the contract; the decoder
        does NOT loosen the contract to accommodate model verbosity.
        """
        raw_sha = hashlib.sha256((stdout or '').encode('utf-8')).hexdigest()

        def invalid(error: str) -> PatchProposal:
            return PatchProposal(
                valid=False, paths=[], hunks=[], old_lines=[], new_lines=[],
                sha256='', raw_input_sha256=raw_sha, canonical_patch_sha256='',
                parse_error=error,
            )

        if not stdout or not stdout.strip():
            return invalid('Empty stdout')

        stripped = stdout.strip()
        begin_idx = stripped.find(PROPOSAL_BEGIN)
        if begin_idx < 0:
            return invalid('Missing structured proposal begin marker')
        if stripped.find(PROPOSAL_BEGIN, begin_idx + 1) >= 0:
            return invalid('Multiple structured proposal begin markers')
        end_idx = stripped.find(PROPOSAL_END, begin_idx + len(PROPOSAL_BEGIN))
        if end_idx < 0:
            return invalid('Missing structured proposal end marker')
        if stripped.find(PROPOSAL_END, end_idx + len(PROPOSAL_END)) >= 0:
            return invalid('Multiple structured proposal end markers')
        prefix = stripped[:begin_idx]
        suffix = stripped[end_idx + len(PROPOSAL_END):]
        if prefix.strip() != '':
            return invalid('Leading prose before structured proposal')
        if suffix.strip() != '':
            return invalid('Trailing prose after structured proposal')

        body = stripped[begin_idx + len(PROPOSAL_BEGIN):end_idx]

        hunks: list[PatchHunk] = []
        seen_paths: set[str] = set()
        current_path: str | None = None
        old_lines: list[str] = []
        new_lines: list[str] = []
        state: str | None = None  # None | 'OLD' | 'NEW'

        def close_hunk() -> str | None:
            if current_path is None:
                return None
            old_text = '\n'.join(old_lines)
            new_text = '\n'.join(new_lines)
            if not old_text.strip():
                return f'empty OLD block for {current_path}'
            if not new_text.strip():
                return f'empty NEW block for {current_path}'
            if old_text == new_text:
                return f'OLD equals NEW for {current_path}'
            hunks.append(
                PatchHunk(
                    file_path=current_path,
                    old_lines=[old_text],
                    new_lines=[new_text],
                )
            )
            return None

        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith('FILE:'):
                if state is not None:
                    return invalid('FILE marker inside an OLD/NEW block')
                error = close_hunk()
                if error is not None:
                    return invalid(error)
                path_value = stripped[len('FILE:'):].strip()
                if not path_value:
                    return invalid('FILE marker with empty path')
                if path_value in seen_paths:
                    return invalid(f'duplicate FILE section: {path_value}')
                seen_paths.add(path_value)
                current_path = path_value
                old_lines = []
                new_lines = []
                continue
            if stripped == '<<<< OLD':
                if current_path is None:
                    return invalid('OLD block before any FILE marker')
                if state is not None:
                    return invalid('nested OLD/NEW block')
                state = 'OLD'
                continue
            if stripped == '>>>> OLD':
                if state != 'OLD':
                    return invalid('unmatched OLD terminator')
                state = None
                continue
            if stripped == '<<<< NEW':
                if current_path is None:
                    return invalid('NEW block before any FILE marker')
                if state is not None:
                    return invalid('nested OLD/NEW block')
                if not old_lines:
                    return invalid(f'NEW block before OLD block for {current_path}')
                state = 'NEW'
                continue
            if stripped == '>>>> NEW':
                if state != 'NEW':
                    return invalid('unmatched NEW terminator')
                state = None
                continue
            if stripped in ('<<<<<<<<', '>>>>>>>>'):
                return invalid(f'conflict marker in proposal: {stripped}')
            if state == 'OLD':
                old_lines.append(line)
            elif state == 'NEW':
                new_lines.append(line)
            elif stripped:
                return invalid(f'unrecognized line outside OLD/NEW: {stripped!r}')

        if state is not None:
            return invalid('unterminated OLD/NEW block')
        error = close_hunk()
        if error is not None:
            return invalid(error)
        if not hunks:
            return invalid('structured proposal declares no FILE sections')

        paths = [h.file_path for h in hunks]
        old_blocks = [h.old_lines[0] for h in hunks]
        new_blocks = [h.new_lines[0] for h in hunks]
        canonical = _canonical_patch_bytes(paths, old_blocks, new_blocks)
        proposal_sha = hashlib.sha256(canonical).hexdigest()
        return PatchProposal(
            valid=True, paths=paths, hunks=hunks,
            old_lines=old_blocks, new_lines=new_blocks,
            sha256=proposal_sha, raw_input_sha256=raw_sha,
            canonical_patch_sha256=proposal_sha,
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

class RedQualificationDerivationError(ValueError):
    """Raised when RED qualification cannot be derived from an evidence
    artifact (missing file, malformed JSON, or non-conforming payload)."""


def derive_red_qualification_from_evidence(red_qualification_ref: str) -> bool:
    """Derive the boolean ``red_qualified`` flag from the actual RED
    evidence artifact identified by ``red_qualification_ref``.

    RQ4-R2-C2-R1 Repair A: the positive proof must not pass
    ``red_qualified=True`` literally. The Harness must READ the actual
    ``red/result.json`` (or equivalent) and compute the boolean from its
    deterministic contents.

    Required derivation (per Owner ruling):

        red_qualified = (
            red_result["exit_code"] == 1
            and red_result["failure_reason_matches_intended_defect"] is True
        )

    The function does not interpret prose. It only inspects the
    deterministic JSON fields. Any deviation raises
    :class:`RedQualificationDerivationError` rather than silently
    returning ``True``.

    Parameters
    ----------
    red_qualification_ref:
        Filesystem path to the RED evidence JSON. May be a relative
        path; resolved against the current working directory.

    Returns
    -------
    bool
        True iff the artifact proves pytest exit-code 1 AND the intended
        defect signature was matched.
    """
    if not isinstance(red_qualification_ref, str) or not red_qualification_ref.strip():
        raise RedQualificationDerivationError(
            f"red_qualification_ref must be a non-empty path string; "
            f"got {red_qualification_ref!r}"
        )

    path = Path(red_qualification_ref)
    if not path.is_file():
        raise RedQualificationDerivationError(
            f"RED evidence artifact not found: {red_qualification_ref}"
        )

    import json as _json
    try:
        payload = _json.loads(path.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError) as exc:
        raise RedQualificationDerivationError(
            f"RED evidence artifact unreadable / not JSON: "
            f"{red_qualification_ref}: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise RedQualificationDerivationError(
            f"RED evidence artifact must be a JSON object; "
            f"got {type(payload).__name__}"
        )

    try:
        exit_code = payload["exit_code"]
        matches = payload["failure_reason_matches_intended_defect"]
    except KeyError as exc:
        raise RedQualificationDerivationError(
            f"RED evidence artifact missing required field {exc}: "
            f"{red_qualification_ref}"
        ) from exc

    if not isinstance(exit_code, int):
        raise RedQualificationDerivationError(
            f"RED evidence artifact exit_code must be int; "
            f"got {type(exit_code).__name__}"
        )
    if not isinstance(matches, bool):
        raise RedQualificationDerivationError(
            f"RED evidence artifact failure_reason_matches_intended_defect "
            f"must be bool; got {type(matches).__name__}"
        )

    return exit_code == 1 and matches is True


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

    Issues apply authority only when the proposal paths are a NON-EMPTY
    SUBSET of the allowed paths.

    RQ4-R2 §12 contract-semantics decision
    --------------------------------------
    This gate previously used set **equality**. That is inconsistent with the
    canonical contract: the canonical verification gate
    (:class:`~synapx_harness.kernel.mutation_qualification_port.MutationQualificationPort`
    check "exact_write_path") already applies **subset** semantics
    (``actual.issubset(authorized)``). Under equality a legitimate proposal
    that touches only one of two declared paths would be denied, while the
    verifier would have accepted it. The canonical contract therefore
    requires subset, and the gate is repaired accordingly. An empty proposal
    path set is still denied.
    """

    def check(
        self,
        proposal: PatchProposal,
        allowed_write_paths: list[str],
        source_revision: str,
        admission_receipt_id: str,
    ) -> PathGateReceipt:
        """Validate proposal paths against allowlist (subset semantics)."""
        proposal_set = set(proposal.paths)
        allowed_set = set(allowed_write_paths)

        if proposal_set and proposal_set.issubset(allowed_set):
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
    denied_reason: str | None = None


class ControlledPatchApplicator:
    """Applies a validated single-file mutation with full authority chain.

    RQ4-R2-C2 single-file first-slice contract:

    * the proposal declares exactly one path;
    * the proposal path equals an authorized path;
    * the proposal path resolves inside the supplied ``repository_root``;
    * the proposal SHA equals the path-gate SHA;
    * the path-gate source revision equals the admission source revision
      AND equals the ``current_source_revision_at_apply`` supplied by the
      composition layer (which computed it from disk just-in-time);
    * the current SHA of the target file equals the Harness-captured
      ``expected_before_sha256`` (per-path binding);
    * the proposal's ``OLD`` block occurs exactly once in the current
      target bytes.

    If ANY precondition fails, ``write_count == 0``, ``applied_paths`` is
    empty, and the target bytes are not modified.
    """

    def apply(
        self,
        proposal: PatchProposal,
        path_gate_receipt: PathGateReceipt,
        admission_receipt: AdmissionReceipt,
        *,
        repository_root: Path,
        expected_before_sha256_by_path: dict[str, str],
        current_source_revision_at_apply: str,
        normalize_line_endings: bool = True,
    ) -> ApplyReceipt:
        """Apply the validated single-file mutation.

        All preconditions are evaluated BEFORE any byte is written. On
        failure the function returns an empty ``ApplyReceipt`` without
        touching the target file.
        """
        apply_started = _now_iso()

        def empty(reason: str) -> ApplyReceipt:
            return self._empty_receipt(
                authorization_ref=admission_receipt.receipt_id,
                admission_receipt_id=admission_receipt.receipt_id,
                path_gate_receipt_id=path_gate_receipt.admission_receipt_id,
                source_revision=admission_receipt.source_revision,
                apply_started=apply_started,
                reason=reason,
            )

        # ---- Authority chain validation ----
        if admission_receipt.admission_decision != 'ALLOW':
            return empty('Admission DENIED')
        if path_gate_receipt.gate_decision != 'ALLOW':
            return empty('PathGate DENIED')
        if path_gate_receipt.apply_authority != 'ISSUED':
            return empty('Apply authority NOT ISSUED')

        if not proposal.paths:
            return empty('Proposal declares no paths')
        if len(proposal.paths) != 1:
            return empty(
                f'Single-file apply requires exactly 1 proposal path; '
                f'got {len(proposal.paths)}'
            )

        target_path = proposal.paths[0]
        authorized_set = set(path_gate_receipt.authorized_paths)
        if target_path not in authorized_set:
            return empty(
                f'Target path {target_path!r} not in authorized set '
                f'{sorted(authorized_set)}'
            )

        if proposal.sha256 != path_gate_receipt.proposal_sha256:
            return empty('Proposal SHA mismatch with PathGate')
        if (
            proposal.canonical_patch_sha256
            != path_gate_receipt.canonical_patch_sha256
        ):
            return empty('Canonical patch SHA mismatch with PathGate')

        if admission_receipt.source_revision != path_gate_receipt.source_revision:
            return empty('Admission/PathGate source revision mismatch')
        if admission_receipt.source_revision != current_source_revision_at_apply:
            return empty(
                'Current source revision at apply != admitted source revision'
            )

        # ---- Resolve target under explicit repository_root ----
        root_resolved = repository_root.resolve()
        target_candidate = (root_resolved / target_path).resolve()
        try:
            target_candidate.relative_to(root_resolved)
        except ValueError:
            return empty(f'Target path escapes repository root: {target_path}')

        if not target_candidate.is_file():
            return empty(f'Target path is not an existing file: {target_path}')

        # ---- Per-path before-hash binding ----
        expected_before = expected_before_sha256_by_path.get(target_path)
        if expected_before is None:
            return empty(
                f'expected_before_sha256_by_path has no entry for '
                f'{target_path}'
            )

        before_bytes = target_candidate.read_bytes()
        if normalize_line_endings:
            before_bytes = before_bytes.replace(b'\r\n', b'\n')
        before_sha = hashlib.sha256(before_bytes).hexdigest()
        if before_sha != expected_before:
            return empty(
                f'Before-hash mismatch for {target_path}: '
                f'expected={expected_before[:12]}... actual={before_sha[:12]}...'
            )

        # ---- OLD block must occur exactly once ----
        if not proposal.old_lines:
            return empty('Proposal has no OLD block')
        if not proposal.new_lines:
            return empty('Proposal has no NEW block')
        old_text = proposal.old_lines[0]
        new_text = proposal.new_lines[0]
        old_bytes = old_text.encode('utf-8')
        new_bytes = new_text.encode('utf-8')
        if not old_bytes:
            return empty('Empty OLD block')
        if not new_bytes:
            return empty('Empty NEW block')
        if old_bytes == new_bytes:
            return empty('OLD equals NEW')
        occurrences = before_bytes.count(old_bytes)
        if occurrences != 1:
            return empty(
                f'OLD block must occur exactly once in current bytes; '
                f'got {occurrences}'
            )

        # ---- Apply ----
        after_bytes = before_bytes.replace(old_bytes, new_bytes)
        if normalize_line_endings and b'\r\n' in after_bytes:
            after_bytes = after_bytes.replace(b'\r\n', b'\n')
        target_candidate.write_bytes(after_bytes)
        after_sha = hashlib.sha256(after_bytes).hexdigest()
        apply_completed = _now_iso()

        return ApplyReceipt(
            applied_paths=[target_path],
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
            denied_reason=reason,
        )


# ---- GovernedMutationExecutor ----

@dataclass
class MutationExecutionResult:
    """Result of GovernedMutationExecutor.execute().

    RQ8-R1-R2-R2-R1 (Q2): ``mutation_attempted`` carries the truthful
    answer to "did the mutation applicator actually run for this run?".
    It is set to ``True`` ONLY when :class:`ControlledPatchApplicator.apply`
    was invoked; any earlier short-circuit (parse failure, validation
    blockers, admission DENY, path-gate DENY) leaves it ``False`` so the
    same-run receipt can prove the applicator was never reached.
    ``proposal_parsing_attempted`` is set to ``True`` whenever the
    structured parser was invoked; a malformed/empty agent stdout still
    counts as a parsing attempt (the parser was called, it just rejected).
    """
    success: bool
    work_contract_id: str
    admission_receipt: AdmissionReceipt | None
    path_gate_receipt: PathGateReceipt | None
    apply_receipt: ApplyReceipt | None
    proposal: PatchProposal | None
    validation_blockers: list[str]
    error: str | None = None
    proposal_parsing_attempted: bool = False
    mutation_attempted: bool = False


class GovernedMutationExecutor:
    """Orchestrates the full mutation chain with fail-closed semantics.

    Invariant (RQ4-R2-C2 strict):
    RED Qualification
    -> MutationAdmissionGate ALLOW
    -> CodexAdapter read-only (outside this class)
    -> PatchProposalParser.parse_structured() (NOT legacy heuristic parse)
    -> validate_mutation_proposal (deterministic validation)
    -> ExactPathMutationGate ALLOW
    -> ControlledPatchApplicator (single-file, all preconditions first)

    If any step fails, the applicator is not reached and the target file
    is not modified.
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
        *,
        repository_root: Path,
        expected_before_sha256_by_path: dict[str, str],
        current_source_revision_at_apply: str,
        agent_stdout: str,
    ) -> MutationExecutionResult:
        """Execute the full mutation chain (RQ4-R2-C2 strict, single-file).

        RQ8-R1-R2-R2-R1 (Q2): ``mutation_attempted`` is set to ``True`` ONLY
        when :class:`ControlledPatchApplicator.apply` is invoked. Any
        earlier short-circuit (parse failure, validation blockers,
        admission DENY, path-gate DENY) leaves it ``False`` so the
        same-run receipt carries truthful stage truth.
        ``proposal_parsing_attempted`` is set to ``True`` as soon as the
        structured parser is invoked, regardless of its verdict.
        """
        # Step 1: STRICT parse (NOT legacy heuristic). Parse must precede
        # admission: an invalid proposal must never produce an admission
        # receipt.
        proposal = self._parser.parse_structured(agent_stdout)
        if not proposal.valid:
            return MutationExecutionResult(
                success=False,
                work_contract_id=work_contract_id,
                admission_receipt=None,
                path_gate_receipt=None,
                apply_receipt=None,
                proposal=proposal,
                validation_blockers=[],
                error=f'Proposal INVALID: {proposal.parse_error}',
                proposal_parsing_attempted=True,
                mutation_attempted=False,
            )

        # Step 2: Deterministic proposal validation. Validation must precede
        # admission: an unauthorized proposal must never produce an
        # admission receipt.
        from synapx_harness.kernel.mutation_proposal_contract import (
            validate_mutation_proposal,
        )
        blockers = validate_mutation_proposal(
            proposal,
            repository_root=repository_root,
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
                error='Proposal validation FAILED: ' + '; '.join(blockers),
                proposal_parsing_attempted=True,
                mutation_attempted=False,
            )

        # Step 3: Admission. Only after the proposal is structurally and
        # semantically valid may an admission receipt be issued.
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
                proposal=proposal,
                validation_blockers=[],
                error=f'Admission DENIED: {admission.denied_reason}',
                proposal_parsing_attempted=True,
                mutation_attempted=False,
            )

        # Step 4: PathGate
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
                validation_blockers=[],
                error=f'PathGate DENIED: {path_gate.reason}',
                proposal_parsing_attempted=True,
                mutation_attempted=False,
            )

        # Step 5: Apply (single-file, all preconditions first).
        # The applicator is the ONLY stage that flips ``mutation_attempted``
        # to ``True`` (Q2 stage truth).
        apply_receipt = self._applicator.apply(
            proposal=proposal,
            path_gate_receipt=path_gate,
            admission_receipt=admission,
            repository_root=repository_root,
            expected_before_sha256_by_path=expected_before_sha256_by_path,
            current_source_revision_at_apply=current_source_revision_at_apply,
        )

        if apply_receipt.write_count == 0:
            return MutationExecutionResult(
                success=False,
                work_contract_id=work_contract_id,
                admission_receipt=admission,
                path_gate_receipt=path_gate,
                apply_receipt=apply_receipt,
                proposal=proposal,
                validation_blockers=[],
                error=f'Apply failed: write_count = 0 ({apply_receipt.denied_reason})',
                proposal_parsing_attempted=True,
                mutation_attempted=True,
            )

        return MutationExecutionResult(
            success=True,
            work_contract_id=work_contract_id,
            admission_receipt=admission,
            path_gate_receipt=path_gate,
            apply_receipt=apply_receipt,
            proposal=proposal,
            validation_blockers=[],
            proposal_parsing_attempted=True,
            mutation_attempted=True,
        )


__all__ = [
    'PatchProposalParser', 'PatchProposal', 'PatchHunk',
    'MutationAdmissionGate', 'AdmissionReceipt',
    'ExactPathMutationGate', 'PathGateReceipt',
    'ControlledPatchApplicator', 'ApplyReceipt',
    'GovernedMutationExecutor', 'MutationExecutionResult',
    'RedQualificationDerivationError',
    'derive_red_qualification_from_evidence',
]
