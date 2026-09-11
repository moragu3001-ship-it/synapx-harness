"""R5 Review Root Escape Negative Tests.

Tests that verify the review root resolver rejects malicious inputs.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from synapx_harness.review.path_resolver import (
    ReviewRootResolutionError,
    resolve_review_root,
)


def test_cwd_at_drive_root_review_root_must_be_workspace_derived() -> None:
    workspace = Path("D:/communis")
    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"

    result = resolve_review_root(workspace, phase)

    assert result.review_root.startswith("D:\\communis\\_review")
    assert not result.review_root.startswith("D:\\_review")


def test_review_root_from_communis_workspace_never_drive_root() -> None:
    workspace = Path("D:/communis")
    explicit = Path("D:/_review/COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, "PHASE", explicit_review_root=explicit)

    assert exc_info.value.code == "DRIVE_ROOT_REVIEW"


def test_path_traversal_with_dot_dot_slash_fails() -> None:
    workspace = Path("D:/communis")
    phase = "../../../etc/passwd"

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "MUST NOT contain path traversal" in str(exc_info.value)


def test_path_traversal_with_dot_dot_backslash_fails() -> None:
    workspace = Path("D:/communis")
    phase = "..\\..\\..\\etc\\passwd"

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "MUST NOT contain path traversal" in str(exc_info.value)


def test_windows_absolute_path_in_phase_fails() -> None:
    workspace = Path("D:/communis")
    phase = "D:\\communis\\_review\\PHASE"

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "MUST NOT contain path traversal" in str(exc_info.value)


def test_explicit_review_root_with_backslash_in_name_fails() -> None:
    workspace = Path("D:/communis")
    explicit = Path("D:\\communis\\_review\\PHASE\\..\\ATTACK")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(
            workspace,
            "PHASE",
            explicit_review_root=explicit,
        )

    assert exc_info.value.code in ("EXPLICIT_ROOT_NOT_CANONICAL", "OUTSIDE_WORKSPACE")


def test_explicit_drive_root_review_root_fails() -> None:
    workspace = Path("D:/communis")
    explicit = Path("D:/_review/PHASE")

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(
            workspace,
            "PHASE",
            explicit_review_root=explicit,
        )

    assert exc_info.value.code == "DRIVE_ROOT_REVIEW"


def test_phase_with_multiline_content_fails() -> None:
    workspace = Path("D:/communis")
    phase = "PHASE\nWITH\nNEWLINES"

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "non-empty" in str(exc_info.value).lower() or "must be" in str(exc_info.value).lower()


def test_phase_with_trailing_whitespace_fails() -> None:
    workspace = Path("D:/communis")
    phase = "PHASE   "

    with pytest.raises(ReviewRootResolutionError) as exc_info:
        resolve_review_root(workspace, phase)

    assert "non-empty" in str(exc_info.value).lower() or "must be" in str(exc_info.value).lower()


def test_review_root_case_sensitivity_on_casefold_duplicate() -> None:
    workspace = Path("D:/communis")
    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5"

    result1 = resolve_review_root(workspace, phase)
    result2 = resolve_review_root(workspace, phase.lower())

    assert result1.review_root != result2.review_root or result1.phase != result2.phase


def test_relative_underscore_review_not_interpreted_as_absolute() -> None:
    workspace = Path("D:/communis")
    phase = "_review/PHASE"

    result = resolve_review_root(workspace, phase)

    assert result.review_root.startswith("D:\\communis\\_review")
    assert not result.review_root.startswith("D:\\_review")
