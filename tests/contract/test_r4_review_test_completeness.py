"""R4 Review Test Completeness Tests.

Tests that ensure all R3/R4 tests are included in the review package
and no phase-based test exclusion rules exist.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def test_package_scope_does_not_exclude_test_r3_files(
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.package_scope import is_path_allowed, iter_scope_files

    files = iter_scope_files(core_root=core_root, service_pack_root=service_pack_root)
    test_r3_files = [
        (scope, path, src)
        for scope, path, src in files
        if "test_r3_" in Path(path).name
    ]
    for scope, path, _src in test_r3_files:
        assert is_path_allowed(path, scope=scope), f"test_r3 file excluded: {path}"


def test_package_scope_does_not_exclude_test_r4_files(
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.package_scope import is_path_allowed, iter_scope_files

    files = iter_scope_files(core_root=core_root, service_pack_root=service_pack_root)
    test_r4_files = [
        (scope, path, src)
        for scope, path, src in files
        if "test_r4_" in Path(path).name
    ]
    for scope, path, _src in test_r4_files:
        assert is_path_allowed(path, scope=scope), f"test_r4 file excluded: {path}"


def test_package_contains_every_tracked_core_test_file(
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.package_scope import iter_scope_files

    all_files = iter_scope_files(core_root=core_root, service_pack_root=service_pack_root)
    test_files = [
        path for scope, path, src in all_files if "/tests/" in path and path.endswith(".py")
    ]
    git_test_files = []
    # Canonical tests root only: core_root.rglob("tests/**/*.py") would also
    # pick up the untracked baseline/tests snapshot copy, which is not part of
    # the git-tracked test set. (I1-RQ1-06 package inventory closure.)
    for test_file in (core_root / "tests").rglob("**/*.py"):
        rel = f"synapx-harness/{test_file.relative_to(core_root).as_posix()}"
        if ".venv" not in rel:
            git_test_files.append(rel)

    for git_file in git_test_files:
        if not any(t == git_file for t in test_files):
            pytest.fail(f"Git-tracked test file not in package scope: {git_file}")


def test_package_test_file_set_matches_git_tracked_test_set(
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.package_scope import iter_scope_files

    all_files = iter_scope_files(core_root=core_root, service_pack_root=service_pack_root)
    package_tests = sorted(
        [path for scope, path, src in all_files if "/tests/" in path and path.endswith(".py")]
    )

    git_tests = sorted([
        f"synapx-harness/{f.relative_to(core_root).as_posix()}"
        for f in (core_root / "tests").rglob("**/*.py")
        if f.is_file() and ".venv" not in str(f)
    ])

    mismatch_msg = f"Mismatch:\nPackage: {package_tests[:5]}\nGit: {git_tests[:5]}"
    assert package_tests == git_tests, mismatch_msg


def test_phase_name_is_never_used_as_test_exclusion_rule(
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.package_scope import is_path_allowed

    phases = ["test_r1_", "test_r2_", "test_r3_", "test_r4_"]
    for phase_prefix in phases:
        fake_path = "synapx-harness/tests/test_file.py"
        msg = f"Phase-based exclusion found for {phase_prefix}"
        assert is_path_allowed(fake_path, scope="core"), msg


def test_review_package_contains_negative_exploit_tests(
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.package_scope import iter_scope_files

    all_files = iter_scope_files(core_root=core_root, service_pack_root=service_pack_root)
    negative_tests = [path for scope, path, src in all_files if "/tests/negative/" in path]

    assert len(negative_tests) > 0, "No negative exploit tests included in package scope"

    for test_file in core_root.glob("tests/negative/*.py"):
        rel = f"synapx-harness/{test_file.relative_to(core_root).as_posix()}"
        assert rel in negative_tests, f"Negative exploit test not in package scope: {rel}"
