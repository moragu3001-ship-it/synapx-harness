"""R5 Review Root Resolver Contract Tests.

Tests that enforce the canonical review root resolution contract.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from synapx_harness.review.path_resolver import (
    ResolutionSource,
    ReviewLocation,
    ReviewRootResolutionError,
    resolve_review_root,
)


def test_resolve_review_root_default_from_workspace() -> None:
    workspace = Path("D:/communis")
    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"

    result = resolve_review_root(workspace, phase)

    assert isinstance(result, ReviewLocation)
    assert result.workspace_root == "D:\\communis"
    assert result.review_base == "D:\\communis\\_review"
    assert result.review_root == "D:\\communis\\_review\\COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"
    assert result.phase == phase
    assert result.within_workspace is True
    assert result.within_review_base is True
    assert result.resolution_source == ResolutionSource.DEFAULT_FROM_WORKSPACE


def test_resolve_review_root_explicit_canonical_root() -> None:
    workspace = Path("D:/communis")
    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"
    explicit = Path("D:/communis/_review/COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5")

    result = resolve_review_root(workspace, phase, explicit_review_root=explicit)

    assert isinstance(result, ReviewLocation)
    assert result.review_root == "D:\\communis\\_review\\COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"
    assert result.resolution_source == ResolutionSource.EXPLICIT_CANONICAL_ROOT


def test_resolve_review_root_relative_workspace_fails() -> None:
    workspace = Path("relative/path")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "PHASE")

    assert "absolute path" in str(exc_info.value).lower()


def test_review_root_outside_workspace_fails() -> None:
    workspace = Path("D:/communis")
    explicit = Path("D:/communis/outside/_review/PHASE")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "PHASE", explicit_review_root=explicit)

    assert exc_info.value.code in ("OUTSIDE_WORKSPACE", "EXPLICIT_ROOT_NOT_CANONICAL")


def test_review_root_under_drive_root_fails() -> None:
    workspace = Path("D:/communis")
    explicit = Path("D:/_review/PHASE")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "PHASE", explicit_review_root=explicit)

    assert exc_info.value.code == "DRIVE_ROOT_REVIEW"


def test_phase_with_path_traversal_fails() -> None:
    workspace = Path("D:/communis")
    phase = "../PHASE"

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "MUST NOT contain path traversal" in str(exc_info.value)


def test_phase_with_double_dot_in_subpath_fails() -> None:
    workspace = Path("D:/communis")
    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5/../PHASE"

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "MUST NOT contain path traversal" in str(exc_info.value)


def test_empty_phase_fails() -> None:
    workspace = Path("D:/communis")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "")

    assert "non-empty" in str(exc_info.value).lower()


def test_phase_with_only_separators_fails() -> None:
    workspace = Path("D:/communis")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "///")

    assert "non-empty" in str(exc_info.value).lower() or "must be" in str(exc_info.value).lower()


def test_phase_with_only_backslashes_fails() -> None:
    workspace = Path("D:/communis")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "\\\\")

    assert "non-empty" in str(exc_info.value).lower() or "must be" in str(exc_info.value).lower()


def test_different_drive_fails() -> None:
    workspace = Path("D:/communis")
    explicit = Path("C:/communis/_review/PHASE")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "PHASE", explicit_review_root=explicit)

    assert exc_info.value.code in ("DRIVE_MISMATCH", "EXPLICIT_ROOT_NOT_CANONICAL")


def test_explicit_review_root_not_under_correct_phase_fails() -> None:
    workspace = Path("D:/communis")
    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"
    explicit = Path("D:/communis/_review/WRONG_PHASE")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase, explicit_review_root=explicit)

    assert exc_info.value.code == "EXPLICIT_ROOT_NOT_CANONICAL"
