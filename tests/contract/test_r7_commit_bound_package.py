"""R7 Contract Tests: Commit-bound package semantics.

Tests ensure the package builder consumes the Git snapshot bytes
literally and never falls back to repository working-tree reads.
"""

from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path

import pytest


def _init_temp_git_repo(
    tmp_path: Path,
    files: dict[str, bytes] | None = None,
    *,
    name: str = "repo",
) -> tuple[Path, str]:
    if files is None:
        files = {}
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo), "init", "--quiet"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Tester"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.autocrlf", "false"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "core.quotepath", "off"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.lfs.clean", " "],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.lfs.smudge", " "],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "filter.lfs.required", "false"],
        check=True,
    )
    for rel, data in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--quiet", "-m", "init"],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return repo, head


def test_r7_build_uses_core_ref_bytes(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot
    from synapx_harness.review.package_builder import build_package

    core_repo, head_a = _init_temp_git_repo(tmp_path, {"src/a.txt": b"hello-A"}, name="core")
    pack_repo, pack_head = _init_temp_git_repo(
        tmp_path / "pack", {"tests/x.yaml": b"k: v\n"}, name="pack"
    )

    core_snap = build_git_snapshot(core_repo, head_a, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        pack_repo, pack_head, package_prefix="communis-pilot-service-pack"
    )

    out = tmp_path / "out.zip"
    review_payloads: list[tuple[str, bytes]] = []
    result = build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        review_payloads=review_payloads,
        out_path=out,
        enforce_scope=False,
    )
    assert result.ok
    with zipfile.ZipFile(out, "r") as zf:
        a_bytes = zf.read("synapx-harness/src/a.txt")
    assert a_bytes == b"hello-A", "Package must contain commit-A byte exactly"


def test_r7_uncommitted_file_not_packaged(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot
    from synapx_harness.review.package_builder import build_package

    core_repo, head = _init_temp_git_repo(tmp_path, {"src/a.txt": b"committed"}, name="core")
    (core_repo / "src" / "uncommitted.txt").write_bytes(b"uncommitted-content")
    pack_repo, pack_head = _init_temp_git_repo(
        tmp_path / "pack", {"tests/x.yaml": b"k: v\n"}, name="pack"
    )

    core_snap = build_git_snapshot(core_repo, head, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        pack_repo, pack_head, package_prefix="communis-pilot-service-pack"
    )

    out = tmp_path / "out.zip"
    result = build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        review_payloads=[],
        out_path=out,
        enforce_scope=False,
    )
    assert result.ok
    with zipfile.ZipFile(out, "r") as zf:
        names = zf.namelist()
    assert "synapx-harness/src/uncommitted.txt" not in names, (
        "Uncommitted working-tree file MUST NOT appear in package"
    )
    assert "synapx-harness/src/a.txt" in names, "Committed file must appear in package"


def test_r7_git_snapshot_has_nonzero_files(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot

    repo, head = _init_temp_git_repo(tmp_path, {"a.txt": b"x", "b.txt": b"y"})
    snap = build_git_snapshot(repo, head, package_prefix="synapx-harness")
    assert snap.tracked_file_count > 0
    assert len(snap.files) == snap.tracked_file_count


def test_r7_git_snapshot_preserves_binary_bytes(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot

    blob = bytes(range(256))
    repo, head = _init_temp_git_repo(tmp_path, {"blob.bin": blob})
    snap = build_git_snapshot(repo, head, package_prefix="synapx-harness")
    matched = [f for f in snap.files if f.repository_path == "blob.bin"]
    assert matched, "binary file not in snapshot"
    assert matched[0].size_bytes == 256


def test_r7_invalid_ref_fails(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import GitSnapshotError, build_git_snapshot

    repo, _ = _init_temp_git_repo(tmp_path, {"a.txt": b"x"})
    with pytest.raises(GitSnapshotError):
        build_git_snapshot(repo, "nonexistent-sha-deadbeef", package_prefix="synapx-harness")


def test_r7_different_refs_produce_different_snapshots(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot

    repo, head_a = _init_temp_git_repo(tmp_path, {"a.txt": b"A"})
    (repo / "b.txt").write_bytes(b"B")
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "--quiet", "-m", "second"],
        check=True,
    )
    head_b = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    snap_a = build_git_snapshot(repo, head_a, package_prefix="synapx-harness")
    snap_b = build_git_snapshot(repo, head_b, package_prefix="synapx-harness")
    assert snap_a.commit_sha == head_a
    assert snap_b.commit_sha == head_b
    assert snap_a.tracked_file_count != snap_b.tracked_file_count


def test_r7_snapshot_blob_read_error_fails_closed(tmp_path: Path) -> None:
    """A blob that exists in ls-tree but cannot be cat-file'd must abort."""
    from synapx_harness.review.git_snapshot import GitSnapshotError, build_git_snapshot

    repo, head = _init_temp_git_repo(tmp_path, {"a.txt": b"hello"})
    import synapx_harness.review.git_snapshot as gs

    real_cat_file = gs._cat_file_batch

    def fake_cat_file(repo_root, blob_sha):
        raise GitSnapshotError(f"simulated blob read failure for {blob_sha}")

    gs._cat_file_batch = fake_cat_file
    try:
        with pytest.raises(GitSnapshotError):
            build_git_snapshot(repo, head, package_prefix="synapx-harness")
    finally:
        gs._cat_file_batch = real_cat_file


def test_r7_no_synthetic_placeholder_added(tmp_path: Path) -> None:
    """Snapshot must NOT add synthetic placeholder files."""
    from synapx_harness.review.git_snapshot import build_git_snapshot

    repo, head = _init_temp_git_repo(tmp_path, {"only.txt": b"only"})
    snap = build_git_snapshot(repo, head, package_prefix="synapx-harness")
    assert len(snap.files) == 1
    assert snap.files[0].repository_path == "only.txt"


def test_r7_snapshot_manifest_sha256_matches_zip_payload(tmp_path: Path) -> None:
    from synapx_harness.review.git_snapshot import (
        build_git_snapshot,
        create_snapshot_manifest,
    )
    from synapx_harness.review.package_builder import build_package

    core_repo, head = _init_temp_git_repo(tmp_path, {"src/a.txt": b"hello"}, name="core")
    pack_repo, pack_head = _init_temp_git_repo(
        tmp_path / "pack", {"tests/x.yaml": b"k: v\n"}, name="pack"
    )

    core_snap = build_git_snapshot(core_repo, head, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        pack_repo, pack_head, package_prefix="communis-pilot-service-pack"
    )

    manifest = create_snapshot_manifest(core_snap)
    assert manifest["commit_sha"] == head
    files_list = manifest["files"]
    assert isinstance(files_list, list)
    assert manifest["tracked_file_count"] == len(files_list)

    out = tmp_path / "out.zip"
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        review_payloads=[],
        out_path=out,
        enforce_scope=False,
    )

    with zipfile.ZipFile(out, "r") as zf:
        a_bytes = zf.read("synapx-harness/src/a.txt")
    files_list2 = manifest["files"]
    assert isinstance(files_list2, list)
    declared_sha = next(
        f["package_sha256"]
        for f in files_list2
        if isinstance(f, dict) and f.get("repository_path") == "src/a.txt"
    )
    assert declared_sha == hashlib.sha256(a_bytes).hexdigest()


def test_r7_working_tree_bypass_blocked(tmp_path: Path) -> None:
    """A function-level call to (core_repo/a.txt).read_bytes() must not produce
    working-tree bytes when the snapshot was taken on a previous commit."""
    from synapx_harness.review.git_snapshot import build_git_snapshot
    from synapx_harness.review.package_builder import build_package

    core_repo, head = _init_temp_git_repo(tmp_path, {"src/a.txt": b"original"}, name="core")
    pack_repo, pack_head = _init_temp_git_repo(
        tmp_path / "pack", {"tests/x.yaml": b"k: v\n"}, name="pack"
    )

    (core_repo / "src" / "a.txt").write_bytes(b"changed-in-working-tree")

    core_snap = build_git_snapshot(core_repo, head, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        pack_repo, pack_head, package_prefix="communis-pilot-service-pack"
    )

    out = tmp_path / "out.zip"
    build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        review_payloads=[],
        out_path=out,
        enforce_scope=False,
    )
    with zipfile.ZipFile(out, "r") as zf:
        a_bytes = zf.read("synapx-harness/src/a.txt")
    assert a_bytes == b"original", "Working-tree edit MUST NOT bypass commit-bound snapshot"
