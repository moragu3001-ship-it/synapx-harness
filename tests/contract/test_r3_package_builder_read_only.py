"""R7 Package Builder Read-only Tests.

The R7 builder consumes commit-bound snapshot inputs only. It MUST NOT
read repository working trees and MUST NOT write any files into the
core or service-pack trees. These tests enforce those invariants.

H2-I4-A1-J2: the service-pack path is taken from the session-scoped
``service_pack_root`` fixture (git-backed, self-contained fallback)
instead of the hard-coded sibling path, so the suite no longer depends
on host-side ``communis-pilot-service-pack`` presence.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[2]


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _collect_source_inventory(root: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for f in root.rglob("*"):
        if f.is_file():
            rel = str(f.relative_to(root))
            inventory[rel] = _hash_file(f)
    return inventory


def _build_snapshots_from_real_repos(pack_root: Path) -> tuple:
    from synapx_harness.review.git_snapshot import build_git_snapshot

    core_repo = CORE_ROOT

    core_head = subprocess.run(
        ["git", "-C", str(core_repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    pack_head = subprocess.run(
        ["git", "-C", str(pack_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    core_snap = build_git_snapshot(core_repo, core_head, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        pack_root, pack_head, package_prefix="communis-pilot-service-pack"
    )
    return core_snap, pack_snap


def test_builder_does_not_create_gitkeep_in_core(
    service_pack_root: Path, tmp_path: Path
) -> None:
    from synapx_harness.review.package_builder import build_package

    gitkeep_before = set(str(p) for p in CORE_ROOT.rglob(".gitkeep"))

    output_zip = tmp_path / "output.zip"
    core_snap, pack_snap = _build_snapshots_from_real_repos(service_pack_root)
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=output_zip,
    )

    gitkeep_after = set(str(p) for p in CORE_ROOT.rglob(".gitkeep"))
    new_gitkeep = gitkeep_after - gitkeep_before
    assert not new_gitkeep, (
        f"Builder should not create new .gitkeep files in core: {new_gitkeep}"
    )


def test_builder_does_not_create_directories_in_core(
    service_pack_root: Path, tmp_path: Path
) -> None:
    from synapx_harness.review.package_builder import build_package

    dirs_before = set(str(p) for p in CORE_ROOT.rglob("*") if p.is_dir())

    output_zip = tmp_path / "output.zip"
    core_snap, pack_snap = _build_snapshots_from_real_repos(service_pack_root)
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=output_zip,
    )

    dirs_after = set(str(p) for p in CORE_ROOT.rglob("*") if p.is_dir())
    new_dirs = dirs_after - dirs_before
    assert not new_dirs, (
        f"Builder should not create new directories in core: {new_dirs}"
    )


def test_builder_does_not_modify_service_pack(
    service_pack_root: Path, tmp_path: Path
) -> None:
    from synapx_harness.review.package_builder import build_package

    inventory_before = _collect_source_inventory(service_pack_root)

    output_zip = tmp_path / "output.zip"
    core_snap, pack_snap = _build_snapshots_from_real_repos(service_pack_root)
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=output_zip,
    )

    inventory_after = _collect_source_inventory(service_pack_root)
    for path, hash_before in inventory_before.items():
        if path in inventory_after:
            hash_after = inventory_after[path]
            assert hash_before == hash_after, (
                f"Service pack file modified: {path}"
            )


def test_builder_preserves_source_file_inventory(
    service_pack_root: Path, tmp_path: Path
) -> None:
    from synapx_harness.review.package_builder import build_package

    inventory_before = _collect_source_inventory(CORE_ROOT)

    output_zip = tmp_path / "output.zip"
    core_snap, pack_snap = _build_snapshots_from_real_repos(service_pack_root)
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=output_zip,
    )

    inventory_after = _collect_source_inventory(CORE_ROOT)
    assert inventory_before.keys() == inventory_after.keys(), (
        "Source file inventory changed"
    )


def test_builder_preserves_source_hashes(
    service_pack_root: Path, tmp_path: Path
) -> None:
    from synapx_harness.review.package_builder import build_package

    inventory_before = _collect_source_inventory(CORE_ROOT)

    output_zip = tmp_path / "output.zip"
    core_snap, pack_snap = _build_snapshots_from_real_repos(service_pack_root)
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=output_zip,
    )

    inventory_after = _collect_source_inventory(CORE_ROOT)
    for path in inventory_before:
        assert inventory_before[path] == inventory_after[path], (
            f"Source file hash changed: {path}"
        )


def test_build_status_before_equals_after(
    service_pack_root: Path, tmp_path: Path
) -> None:
    from synapx_harness.review.package_builder import build_package

    def get_git_status() -> list[str]:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=CORE_ROOT,
            capture_output=True,
            text=True,
        )
        return (
            result.stdout.strip().split("\n") if result.stdout.strip() else []
        )

    status_before = get_git_status()

    output_zip = tmp_path / "output.zip"
    core_snap, pack_snap = _build_snapshots_from_real_repos(service_pack_root)
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=output_zip,
    )

    status_after = get_git_status()
    assert status_before == status_after, "Git status changed after build"


def test_legacy_working_tree_args_rejected(tmp_path: Path) -> None:
    """core_root/service_pack_root are forbidden and MUST raise TypeError."""

    from synapx_harness.review.package_builder import build_package

    with pytest.raises(TypeError):
        build_package(
            core_root=CORE_ROOT,
            service_pack_root=CORE_ROOT.parent / "communis-pilot-service-pack",
            out_path=tmp_path / "x.zip",
        )


def test_snapshot_missing_raises(tmp_path: Path) -> None:
    """Missing snapshot input MUST raise TypeError before any ZIP write."""

    from synapx_harness.review.package_builder import build_package

    with pytest.raises(TypeError):
        build_package(out_path=tmp_path / "x.zip")
