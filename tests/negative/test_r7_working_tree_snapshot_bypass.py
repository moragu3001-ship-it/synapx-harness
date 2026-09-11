"""R7 Negative Tests: working-tree snapshot bypass attempts."""

from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path


def _init_repo(
    tmp_path: Path,
    files: dict[str, bytes],
    *,
    name: str = "repo",
) -> tuple[Path, str]:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(repo), "init", "--quiet"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "x@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "X"],
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
        ["git", "-C", str(repo), "commit", "--quiet", "-m", "c"],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return repo, head


def test_r7_no_working_tree_read_in_snapshot(tmp_path: Path) -> None:
    """Direct working-tree read on core_repo MUST NOT occur in snapshot path.

    We assert by deleting the file in working tree AFTER commit; if the
    snapshot path read working tree, it would either crash or return a
    different SHA.
    """
    from synapx_harness.review.git_snapshot import build_git_snapshot

    repo, head = _init_repo(tmp_path, {"a.txt": b"abc"})
    (repo / "a.txt").unlink()
    snap = build_git_snapshot(repo, head, package_prefix="synapx-harness")
    matched = [f for f in snap.files if f.repository_path == "a.txt"]
    assert matched, "snapshot must contain committed file even if working tree deleted"
    expected_sha = hashlib.sha256(b"abc").hexdigest()
    assert matched[0].package_sha256 == expected_sha, (
        f"package_sha256 must match sha256 of committed bytes: "
        f"expected {expected_sha}, got {matched[0].package_sha256}"
    )


def test_r7_snapshot_file_count_zero_fails(tmp_path: Path) -> None:
    """A snapshot with tracked_file_count == 0 is forbidden."""
    import pytest

    from synapx_harness.review.git_snapshot import GitSnapshotError

    repo = tmp_path / "emptyrepo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "--quiet"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "x@x"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "X"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "commit",
            "--allow-empty",
            "--quiet",
            "-m",
            "empty",
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    with pytest.raises(GitSnapshotError):
        from synapx_harness.review.git_snapshot import build_git_snapshot

        build_git_snapshot(repo, head, package_prefix="synapx-harness")


def test_r7_binary_blob_preserved_byte_for_byte(tmp_path: Path) -> None:
    """NUL and 0xFF bytes survive the snapshot round-trip."""
    from synapx_harness.review.git_snapshot import build_git_snapshot
    from synapx_harness.review.package_builder import build_package

    payload = b"\x00\x01\xfe\xff" * 32
    core_repo, head = _init_repo(tmp_path, {"src/blob.bin": payload}, name="core")
    pack_repo, pack_head = _init_repo(tmp_path / "pack", {"tests/x.yaml": b"k: v\n"}, name="pack")

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
        b = zf.read("synapx-harness/src/blob.bin")
    assert b == payload
