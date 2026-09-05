"""Canonical structured MutationProposal contract (RQ4-R2).

RQ4-R2 §5 / §6. This module does **not** introduce a competing mutation
schema. The canonical mutation proposal contract remains
:class:`~synapx_harness.kernel.mutation_authority.PatchProposal`; this module
defines only:

*  the deterministic **wire encoding** Codex must use so that its output can
   be decoded into the canonical ``PatchProposal`` (free-form prose is never
   applied as code), and
*  the deterministic **validation** the Harness applies *before* admission
   (RQ4-R2 §5), and
*  the deterministic **explicit write-set extraction** from user-declared
   repository paths (RQ4-R2 §6).

AI PROPOSES / HARNESS MUTATES
-----------------------------
Codex runs read-only and returns text. The Harness decodes that text, rejects
anything that is not exactly the canonical encoding, validates it against the
repository before-state it captured *itself*, and only then writes bytes.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from synapx_harness.evidence.command_runner import normalize_write_token_path

# NOTE: ``PatchProposal`` is imported lazily inside the functions below.
# ``mutation_authority`` imports this module for the wire-encoding markers, so
# a module-level import here would form a cycle.

# ---------------------------------------------------------------------------
# Wire encoding
# ---------------------------------------------------------------------------

PROPOSAL_BEGIN = "--- BEGIN SYNAPX MUTATION PROPOSAL ---"
PROPOSAL_END = "--- END SYNAPX MUTATION PROPOSAL ---"

_FILE_MARKER = "FILE:"
_OLD_BEGIN = "<<<< OLD"
_OLD_END = ">>>> OLD"
_NEW_BEGIN = "<<<< NEW"
_NEW_END = ">>>> NEW"

_BLOCK_MARKERS: tuple[str, ...] = (
    _OLD_BEGIN,
    _OLD_END,
    _NEW_BEGIN,
    _NEW_END,
)


class MutationProposalContractError(ValueError):
    """Raised when a proposed mutation violates the canonical contract."""


# ---------------------------------------------------------------------------
# Explicit write-set extraction (RQ4-R2 §6)
# ---------------------------------------------------------------------------

_WRITE_SET_HEADER_RE = re.compile(
    r"^[ \t]*allowed[ \t]+write[ \t]+paths[ \t]*:?[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
# Path entry line under an "Allowed write paths:" header. The path is the
# remainder of the line after the bullet, with trailing whitespace stripped.
# ``(.+?)`` is lazy and the trailing ``[ \t]*$`` forces the captured group
# to be free of trailing whitespace while permitting interior whitespace,
# parentheses, ``@``, non-ASCII, and any other characters the canonical
# normalizer accepts.
_WRITE_SET_ENTRY_RE = re.compile(r"^[ \t]*[-*][ \t]*(.+?)[ \t]*$")


def _normalize_repo_relative(raw: str) -> str:
    """Normalize and validate a repository-relative write path (RQ4-R2-C2-R2).

    This is a thin wrapper around
    :func:`synapx_harness.evidence.command_runner.normalize_write_token_path`
    so that proposal-side paths and WorkContract write-token paths share
    EXACTLY ONE canonical definition. ``ValueError`` from the canonical
    normalizer is re-raised as :class:`MutationProposalContractError` so
    callers can keep branching on the proposal contract exception type.

    RQ4-R2-C2 §9 invariant: ``valid in WorkContract iff valid in proposal``.
    """
    if not isinstance(raw, str):
        raise MutationProposalContractError(
            f"write path must be a string (INVALID_WRITE_SET_PATH): {raw!r}"
        )
    try:
        return normalize_write_token_path(raw.strip())
    except ValueError as exc:
        raise MutationProposalContractError(str(exc)) from exc


def parse_allowed_write_paths(task_text: str) -> list[str]:
    """Extract the explicit user-declared write set from the task text.

    RQ4-R2 §6: for the mutation-capable first slice the write set MUST be
    deterministically derivable from explicit user-declared repository paths.
    Semantic inference is never performed: either the user declared the paths
    under an ``Allowed write paths:`` header, or there is no write set.

    Returns a de-duplicated, order-preserving list of repository-relative
    paths. Returns an empty list when no explicit write set is declared.

    Raises
    ------
    MutationProposalContractError
        When a declared path is absolute, traverses upwards, or is otherwise
        unsafe. An unsafe declaration is never silently dropped.
    """
    if not isinstance(task_text, str) or not task_text.strip():
        return []

    header = _WRITE_SET_HEADER_RE.search(task_text)
    if header is None:
        return []

    tail = task_text[header.end():]
    paths: list[str] = []
    seen: set[str] = set()
    for line in tail.splitlines():
        stripped = line.strip()
        if not stripped:
            if paths:
                break
            continue
        entry = _WRITE_SET_ENTRY_RE.match(line)
        if entry is None:
            break
        normalized = _normalize_repo_relative(entry.group(1))
        if normalized not in seen:
            seen.add(normalized)
            paths.append(normalized)
    return paths


# ---------------------------------------------------------------------------
# Instruction construction
# ---------------------------------------------------------------------------


def _read_bounded(repository_root: Path, rel_path: str) -> str | None:
    """Read a repository-relative file; ``None`` when it escapes the root."""
    candidate = (repository_root / rel_path).resolve()
    if not candidate.is_relative_to(repository_root.resolve()):
        return None
    if not candidate.is_file():
        return None
    try:
        return candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None


def build_proposal_instruction(
    task: str,
    allowed_write_paths: list[str],
    repository_root: Path | None = None,
) -> str:
    """Build the canonical Codex instruction that requests a structured proposal.

    Codex remains a READ-ONLY proposer: it is instructed to emit the change,
    never to perform it. The current content of every allowed write path is
    supplied verbatim so the proposed ``OLD`` block can be an exact byte
    match rather than a guess.
    """
    lines: list[str] = [task.rstrip(), ""]
    lines.append("You are running inside a READ-ONLY sandbox.")
    lines.append("You MUST NOT modify, create or delete any file.")
    lines.append("Return ONLY a structured mutation proposal and nothing else.")
    lines.append("")
    lines.append("Allowed write paths (repository-relative):")
    for path in allowed_write_paths:
        lines.append(f"- {path}")
    lines.append("")
    lines.append("Reply with exactly one block in this form:")
    lines.append("")
    lines.append(PROPOSAL_BEGIN)
    lines.append("FILE: <repository-relative path>")
    lines.append(_OLD_BEGIN)
    lines.append("<exact current text to be replaced>")
    lines.append(_OLD_END)
    lines.append(_NEW_BEGIN)
    lines.append("<replacement text>")
    lines.append(_NEW_END)
    lines.append(PROPOSAL_END)
    lines.append("")
    lines.append("Rules:")
    lines.append("1. One FILE section per changed file; at most one section per file.")
    lines.append("2. OLD must appear EXACTLY once, verbatim, in the current file.")
    lines.append("3. OLD and NEW must differ.")
    lines.append("4. Use only repository-relative paths from the allowed list.")
    lines.append(
        "5. Preserve indentation exactly; do not add or remove blank lines "
        "inside OLD or NEW except where they are part of the change."
    )

    if repository_root is not None:
        for rel_path in allowed_write_paths:
            content = _read_bounded(repository_root, rel_path)
            if content is None:
                continue
            lines.append("")
            lines.append(f"--- CURRENT CONTENT: {rel_path} ---")
            lines.append(content.rstrip("\n"))
            lines.append(f"--- END CURRENT CONTENT: {rel_path} ---")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Deterministic validation (RQ4-R2 §5)
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_inside(repository_root: Path, rel_path: str) -> Path | None:
    """Resolve a repository-relative path; ``None`` when it escapes the root."""
    root = repository_root.resolve()
    candidate = (root / rel_path).resolve()
    if not candidate.is_relative_to(root):
        return None
    return candidate


def _normalize_line_endings_for_binding(data: bytes) -> bytes:
    """Normalize CRLF -> LF so OLD binding survives Windows text writes.

    The applicator (``ControlledPatchApplicator``) applies the same
    normalization at write time (``normalize_line_endings=True`` default)
    so validation and application see the same canonical byte stream.
    """
    return data.replace(b"\r\n", b"\n")


def validate_mutation_proposal(
    proposal: PatchProposal,
    *,
    repository_root: Path,
    allowed_write_paths: list[str],
    expected_before_sha256_by_path: dict[str, str],
) -> list[str]:
    """Deterministically validate a canonical proposal. Returns blockers.

    An empty list means the proposal satisfies every RQ4-R2 §5 binding:

    *  schema/type validity
    *  repository-relative paths only (no absolute path, no ``..``, no escape)
    *  declared write-set binding (proposal paths are a subset of the
       user-declared allowed write paths)
    *  before-content binding (OLD occurs exactly once in the current bytes,
       after CRLF -> LF normalization that matches applicator write-time
       normalization)
    *  before-hash binding (current file SHA equals the Harness-captured
       pre-agent SHA on the **normalized** byte stream; the harness must
       therefore hash normalized bytes when capturing the pre-image)
    *  proposal hash validation (canonical patch SHA is recomputed)
    """
    from synapx_harness.kernel.mutation_authority import PatchProposal

    blockers: list[str] = []

    if proposal is None or not isinstance(proposal, PatchProposal):
        return ["proposal is not a canonical PatchProposal"]
    if not proposal.valid:
        blockers.append(f"proposal invalid: {proposal.parse_error}")
        return blockers

    allowed_set = set(allowed_write_paths)
    if not allowed_set:
        blockers.append("no explicit allowed write set is bound")

    paths = list(proposal.paths or [])
    if not paths:
        blockers.append("proposal declares no paths")
        return blockers

    if len(paths) != len(set(paths)):
        blockers.append("proposal declares duplicate paths")

    for raw_path in paths:
        try:
            rel_path = _normalize_repo_relative(raw_path)
        except MutationProposalContractError as exc:
            blockers.append(str(exc))
            continue

        if allowed_set and rel_path not in allowed_set:
            blockers.append(
                f"path outside declared write set: {rel_path} "
                f"allowed={sorted(allowed_set)}"
            )
            continue

        target = _resolve_inside(repository_root, rel_path)
        if target is None:
            blockers.append(f"path escapes repository root: {raw_path}")
            continue
        if not target.is_file():
            blockers.append(f"path is not an existing file: {rel_path}")
            continue

        raw_bytes = target.read_bytes()
        normalized_bytes = _normalize_line_endings_for_binding(raw_bytes)
        normalized_sha = sha256_hex(normalized_bytes)

        expected = expected_before_sha256_by_path.get(rel_path)
        if expected is None:
            blockers.append(f"no before-hash binding captured for {rel_path}")
        elif normalized_sha != expected:
            blockers.append(
                f"before-hash mismatch for {rel_path}: "
                f"expected={expected} actual={normalized_sha}"
            )

        hunk = _hunk_for(proposal, raw_path)
        if hunk is None:
            blockers.append(f"proposal has no hunk for {rel_path}")
            continue
        old_text = hunk.old_lines[0] if hunk.old_lines else ""
        new_text = hunk.new_lines[0] if hunk.new_lines else ""
        if not old_text:
            blockers.append(f"empty OLD block for {rel_path}")
            continue
        if not new_text:
            blockers.append(f"empty NEW block for {rel_path}")
            continue
        if old_text == new_text:
            blockers.append(f"OLD equals NEW for {rel_path}")
            continue
        old_normalized = old_text.replace("\r\n", "\n").encode("utf-8")
        occurrences = normalized_bytes.count(old_normalized)
        if occurrences != 1:
            blockers.append(
                f"before-content binding failed for {rel_path}: OLD occurs "
                f"{occurrences} times (exactly 1 required)"
            )

    if proposal.canonical_patch_sha256:
        canonical = _canonical_patch_bytes(proposal.paths, proposal.old_lines, proposal.new_lines)
        recomputed = sha256_hex(canonical)
        if recomputed != proposal.canonical_patch_sha256:
            blockers.append(
                "proposal hash mismatch: "
                f"declared={proposal.canonical_patch_sha256} recomputed={recomputed}"
            )
        if proposal.sha256 and proposal.sha256 != proposal.canonical_patch_sha256:
            blockers.append(
                f"proposal sha256 disagreement: {proposal.sha256} != "
                f"{proposal.canonical_patch_sha256}"
            )
    else:
        blockers.append("proposal carries no canonical patch sha256")

    return blockers


def _hunk_for(proposal: PatchProposal, path: str):
    for hunk in proposal.hunks or []:
        if hunk.file_path == path:
            return hunk
    return None


def _canonical_patch_bytes(
    paths: list[str], old_lines: list[str], new_lines: list[str]
) -> bytes:
    """Canonical patch bytes identical to the canonical mutation authority."""
    from synapx_harness.kernel.mutation_authority import (
        _canonical_patch_bytes as canonical,
    )

    return canonical(paths, old_lines, new_lines)


__all__ = [
    "PROPOSAL_BEGIN",
    "PROPOSAL_END",
    "MutationProposalContractError",
    "build_proposal_instruction",
    "parse_allowed_write_paths",
    "sha256_hex",
    "validate_mutation_proposal",
]
