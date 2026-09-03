r"""Review Root Resolver - canonical path resolution for review packages.

Fail-closed resolver that enforces:
  - Review Root MUST be under Workspace Root/_review/
  - Review Root MUST NOT be under any drive's <drive>:\_review (drive root)
  - No path traversal (..)
  - Same drive as workspace
  - Valid phase string
  - Phase validated before path creation
  - Symlink/Junction resolution followed by re-validation
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

_REVIEW_BASE_DIR_NAME = "_review"


class ResolutionSource(Enum):
    DEFAULT_FROM_WORKSPACE = "DEFAULT_FROM_WORKSPACE"
    EXPLICIT_CANONICAL_ROOT = "EXPLICIT_CANONICAL_ROOT"


class ReviewRootResolutionError(Exception):
    CODE = "REVIEW_ROOT_RESOLUTION_ERROR"

    def __init__(self, message: str, code: str | None = None) -> None:
        self.message = message
        self.code = code or self.CODE
        super().__init__(f"[{self.code}] {message}")


@dataclass(frozen=True)
class ReviewLocation:
    workspace_root: str
    review_base: str
    review_root: str
    phase: str
    within_workspace: bool
    within_review_base: bool
    resolution_source: ResolutionSource


def _is_absolute_path(path: Path) -> bool:
    return path.is_absolute()


def _check_path_traversal(phase: str) -> bool:
    normalized = phase.replace("\\", "/")
    if ".." in normalized.split("/"):
        return True
    if re.match(r"^[A-Za-z]:[/\\]", phase):
        return True
    return False


def _check_valid_phase(phase: str) -> bool:
    if not phase:
        return False
    if "\n" in phase or "\r" in phase or "\t" in phase:
        return False
    if phase != phase.strip():
        return False
    cleaned = phase.replace("/", "").replace("\\", "").strip()
    if not cleaned:
        return False
    return True


def _is_drive_root_review(path: Path) -> bool:
    r"""Check if path is directly under any drive's _review directory.

    This catches paths like D:\_review\PHASE but NOT D:\project\_review\PHASE.
    """
    try:
        parts = path.parts
        if len(parts) >= 2:
            second_part = parts[1]
            second_part_lower = second_part.lower()
            if second_part_lower == "_review":
                return True
        return False
    except Exception:
        return True


def _check_boundary_using_relative(
    child: Path,
    parent: Path,
) -> bool:
    """Check if child is within parent using Path.relative_to().

    Returns True if child is a descendant of parent.
    Raises ReviewRootResolutionError if not.
    """
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _normalize_and_resolve(path: Path) -> Path:
    """Normalize and resolve a path, handling symlinks/junctions."""
    try:
        return path.resolve()
    except Exception as err:
        raise ReviewRootResolutionError(
            "Cannot resolve path",
            code="PATH_RESOLUTION_FAILED",
        ) from err


def resolve_review_root(
    workspace_root: Path,
    phase: str,
    explicit_review_root: Path | None = None,
) -> ReviewLocation:
    """Resolve the canonical review root path.

    Args:
        workspace_root: Absolute path to the workspace root (e.g., D:\\communis)
        phase: Phase identifier (e.g., COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5)
        explicit_review_root: Optional explicit review root path

    Returns:
        ReviewLocation with resolved paths and metadata

    Raises:
        ReviewRootResolutionError: On fail-closed validation failures
    """
    if not _is_absolute_path(workspace_root):
        raise ReviewRootResolutionError(
            "Workspace Root must be an absolute path",
            code="WORKSPACE_ROOT_NOT_ABSOLUTE",
        )

    workspace_resolved = _normalize_and_resolve(workspace_root)

    if not _check_valid_phase(phase):
        raise ReviewRootResolutionError(
            "Phase must be a non-empty string without only path separators",
            code="INVALID_PHASE",
        )

    if _check_path_traversal(phase):
        raise ReviewRootResolutionError(
            "Phase MUST NOT contain path traversal (..)",
            code="PHASE_PATH_TRAVERSAL",
        )

    if explicit_review_root is not None:
        if not _is_absolute_path(explicit_review_root):
            raise ReviewRootResolutionError(
                "Explicit review root must be an absolute path",
                code="EXPLICIT_ROOT_NOT_ABSOLUTE",
            )

        explicit_resolved = _normalize_and_resolve(explicit_review_root)

        if _is_drive_root_review(explicit_resolved):
            raise ReviewRootResolutionError(
                "Review root MUST NOT be directly under any drive's _review directory",
                code="DRIVE_ROOT_REVIEW",
            )

        review_base = workspace_resolved / _REVIEW_BASE_DIR_NAME
        expected_review_root = review_base / phase

        if explicit_resolved != expected_review_root:
            raise ReviewRootResolutionError(
                f"Explicit review root must be exactly {expected_review_root}",
                code="EXPLICIT_ROOT_NOT_CANONICAL",
            )

        if explicit_resolved.drive.lower() != workspace_resolved.drive.lower():
            raise ReviewRootResolutionError(
                "Review root MUST be on the same drive as workspace root",
                code="DRIVE_MISMATCH",
            )

        re_resolved = _normalize_and_resolve(explicit_resolved)
        if _is_drive_root_review(re_resolved):
            raise ReviewRootResolutionError(
                "Review root MUST NOT be directly under any drive's _review directory",
                code="DRIVE_ROOT_REVIEW",
            )

        if not _check_boundary_using_relative(re_resolved, workspace_resolved):
            raise ReviewRootResolutionError(
                "Review root MUST be within workspace root",
                code="OUTSIDE_WORKSPACE",
            )

        review_root = re_resolved
        resolution_source = ResolutionSource.EXPLICIT_CANONICAL_ROOT
    else:
        review_base = workspace_resolved / _REVIEW_BASE_DIR_NAME
        review_root = review_base / phase
        resolution_source = ResolutionSource.DEFAULT_FROM_WORKSPACE

        if review_root.drive.lower() != workspace_resolved.drive.lower():
            raise ReviewRootResolutionError(
                "Review root MUST be on the same drive as workspace root",
                code="DRIVE_MISMATCH",
            )

        re_resolved = _normalize_and_resolve(review_root)
        if _is_drive_root_review(re_resolved):
            raise ReviewRootResolutionError(
                "Review root MUST NOT be directly under any drive's _review directory",
                code="DRIVE_ROOT_REVIEW",
            )

        if not _check_boundary_using_relative(re_resolved, workspace_resolved):
            raise ReviewRootResolutionError(
                "Review root MUST be within workspace root",
                code="OUTSIDE_WORKSPACE",
            )

        review_root = re_resolved

    review_base_path = workspace_resolved / _REVIEW_BASE_DIR_NAME
    within_review_base = _check_boundary_using_relative(review_root, review_base_path)
    within_workspace = _check_boundary_using_relative(review_root, workspace_resolved)

    return ReviewLocation(
        workspace_root=str(workspace_resolved),
        review_base=str(review_base_path),
        review_root=str(review_root),
        phase=phase,
        within_workspace=within_workspace,
        within_review_base=within_review_base,
        resolution_source=resolution_source,
    )


__all__ = [
    "ReviewLocation",
    "ReviewRootResolutionError",
    "ResolutionSource",
    "resolve_review_root",
]
