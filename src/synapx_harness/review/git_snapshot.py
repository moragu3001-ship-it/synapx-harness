"""Git Snapshot Provider - commit-bound file access for review packages.

Reads files directly from a Git commit tree without touching the
working tree. The snapshot bytes are the only source of truth for the
review package.

Mandatory invariants:
  - ``git ls-tree -r -z`` for path enumeration (NUL-separated, bytes)
  - ``git cat-file --batch`` for blob retrieval (bytes, no text decode)
  - Any blob read failure aborts the entire snapshot (no skip-on-error)
  - ``tracked_file_count`` MUST be > 0
  - Binary content is preserved byte-for-byte (no latin-1 re-encoding)
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class GitBlobInfo:
    repository_path: str
    package_path: str
    git_blob_sha: str
    package_sha256: str
    size_bytes: int


@dataclass(frozen=True)
class GitSnapshot:
    repository_id: str
    commit_sha: str
    tree_sha: str
    tracked_file_count: int
    files: list[GitBlobInfo] = field(default_factory=list)


class GitSnapshotError(Exception):
    pass


_HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _run_git(repo_root: Path, *args: str) -> bytes:
    """Run a git subcommand, returning raw stdout bytes."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as err:
        stderr = err.stderr.decode("utf-8", errors="replace").strip()
        raise GitSnapshotError(
            f"Git command failed: git {' '.join(args)}: {stderr}"
        ) from err
    except FileNotFoundError as err:
        raise GitSnapshotError("Git command not found") from err
    return result.stdout


def _validate_ref(ref: str) -> None:
    if not isinstance(ref, str) or not ref:
        raise GitSnapshotError("ref must be a non-empty string")
    if "\n" in ref or "\r" in ref:
        raise GitSnapshotError("ref must not contain newline characters")


def _verify_ref_exists(repo_root: Path, ref: str) -> str:
    """Resolve ref to a 40-hex commit SHA. Raises if ref does not exist."""
    _validate_ref(ref)
    raw = _run_git(repo_root, "rev-parse", "--verify", f"{ref}^{{commit}}")
    commit_sha = raw.decode("ascii").strip()
    if not _HEX40.match(commit_sha):
        raise GitSnapshotError(
            f"ref did not resolve to a 40-hex commit SHA: {commit_sha!r}"
        )
    return commit_sha


def _get_tree_sha(repo_root: Path, commit_sha: str) -> str:
    raw = _run_git(repo_root, "rev-parse", f"{commit_sha}^{{tree}}")
    tree_sha = raw.decode("ascii").strip()
    if not _HEX40.match(tree_sha):
        raise GitSnapshotError(f"tree sha not 40-hex: {tree_sha!r}")
    return tree_sha


def _list_tree_objects(repo_root: Path, commit_sha: str) -> list[tuple[str, str]]:
    """Enumerate ``(blob_sha, repo_relative_path)`` pairs from the commit tree.

    Uses ``git ls-tree -r -z`` so paths with spaces or newlines are
    safely delimited by NUL bytes. Any non-blob entries (submodule,
    symlink) are skipped.
    """
    raw = _run_git(repo_root, "ls-tree", "-r", "-z", commit_sha)
    if not raw:
        return []
    parts = raw.split(b"\x00")
    result: list[tuple[str, str]] = []
    for entry in parts:
        if not entry:
            continue
        meta, _, path_bytes = entry.partition(b"\t")
        if not path_bytes:
            continue
        meta_fields = meta.split(b" ", 2)
        if len(meta_fields) < 3:
            continue
        obj_type = meta_fields[1].decode("ascii", errors="replace")
        sha = meta_fields[2].decode("ascii", errors="replace")
        path = path_bytes.decode("utf-8")
        if obj_type != "blob":
            continue
        if not _HEX40.match(sha):
            continue
        result.append((sha, path))
    return result


def _cat_file_batch(repo_root: Path, blob_sha: str) -> bytes:
    """Read a single blob's bytes via ``git cat-file --batch``.

    The batch protocol is invoked with one blob SHA on stdin; the
    response is the literal blob bytes. Any failure aborts.

    Note: the SHA returned by ``ls-tree`` and echoed in the batch
    response is the **git internal blob SHA**, i.e. the SHA-1 of the
    prefixed header (``blob <size>\\0`` + content). We do NOT
    recompute it from the raw content; we trust git's batch response
    and enforce the declared ``size`` against the literal payload.
    """
    if not _HEX40.match(blob_sha):
        raise GitSnapshotError(f"invalid blob SHA: {blob_sha!r}")
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "--batch"],
        input=(blob_sha + "\n").encode("ascii"),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        raise GitSnapshotError(
            f"cat-file --batch failed for {blob_sha}: {stderr}"
        )
    stdout = proc.stdout
    header_end = stdout.find(b"\n")
    if header_end < 0:
        raise GitSnapshotError(
            f"cat-file --batch missing header newline for {blob_sha}"
        )
    header = stdout[:header_end]
    payload = stdout[header_end + 1:]
    if not header:
        raise GitSnapshotError(f"cat-file --batch empty response for {blob_sha}")
    header_parts = header.split(b" ")
    if len(header_parts) < 3:
        raise GitSnapshotError(
            f"cat-file --batch malformed header for {blob_sha}"
        )
    expected_sha = header_parts[0].decode("ascii", errors="replace")
    expected_size = int(header_parts[2])
    if expected_sha != blob_sha:
        raise GitSnapshotError(
            f"cat-file --batch SHA mismatch: header={expected_sha}, "
            f"requested={blob_sha}"
        )
    if len(payload) < expected_size:
        raise GitSnapshotError(
            f"cat-file --batch short payload for {blob_sha}: "
            f"expected {expected_size}, got {len(payload)}"
        )
    return payload[:expected_size]


def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_git_snapshot(
    repository_root: Path,
    revision: str,
    *,
    package_prefix: str,
) -> GitSnapshot:
    """Build a GitSnapshot for ``revision`` using only commit-tree access.

    Raises :class:`GitSnapshotError` if the ref cannot be resolved or
    any blob fails to read. ``tracked_file_count`` is guaranteed > 0.
    """
    repository_root = Path(repository_root)
    commit_sha = _verify_ref_exists(repository_root, revision)
    tree_sha = _get_tree_sha(repository_root, commit_sha)
    tree_objects = _list_tree_objects(repository_root, commit_sha)

    files: list[GitBlobInfo] = []
    for blob_sha, repo_path in tree_objects:
        if not repo_path:
            continue
        blob_data = _cat_file_batch(repository_root, blob_sha)
        file_sha256 = _compute_sha256(blob_data)
        package_path = f"{package_prefix}/{repo_path}"
        files.append(
            GitBlobInfo(
                repository_path=repo_path,
                package_path=package_path,
                git_blob_sha=blob_sha,
                package_sha256=file_sha256,
                size_bytes=len(blob_data),
            )
        )

    if not files:
        raise GitSnapshotError(
            f"snapshot for {commit_sha} has zero tracked files; "
            f"refusing to package"
        )

    return GitSnapshot(
        repository_id=str(repository_root.resolve()),
        commit_sha=commit_sha,
        tree_sha=tree_sha,
        tracked_file_count=len(files),
        files=files,
    )


def create_snapshot_manifest(
    snapshot: GitSnapshot,
    *,
    excluded_snapshot_files: tuple[ExcludedSnapshotFile, ...] = (),
) -> dict[str, object]:
    """Create the snapshot manifest.

    The manifest MUST carry the exact set contract:

      tracked_file_count == included_file_count + excluded_file_count

    Where ``included_file_count`` is the number of files that appear in
    the package and ``excluded_file_count`` is the number of files that
    exist in the commit tree but were excluded from the package. Every
    excluded entry MUST carry a rule, a reason, the git blob SHA, and
    the size in bytes.
    """
    included_files = [
        {
            "repository_path": f.repository_path,
            "package_path": f.package_path,
            "git_blob_sha": f.git_blob_sha,
            "package_sha256": f.package_sha256,
            "size_bytes": f.size_bytes,
        }
        for f in snapshot.files
    ]
    excluded_payload = [
        {
            "repository_path": e.repository_path,
            "exclusion_rule": e.exclusion_rule,
            "exclusion_reason": e.exclusion_reason,
            "git_blob_sha": e.git_blob_sha,
            "size_bytes": e.size_bytes,
        }
        for e in excluded_snapshot_files
    ]
    return {
        "repository_id": snapshot.repository_id,
        "commit_sha": snapshot.commit_sha,
        "tree_sha": snapshot.tree_sha,
        "tracked_file_count": snapshot.tracked_file_count,
        "included_file_count": len(included_files),
        "excluded_file_count": len(excluded_payload),
        "files": included_files,
        "excluded_snapshot_files": excluded_payload,
    }


def serialize_blob_payload(snapshot: GitSnapshot) -> list[tuple[str, bytes]]:
    """Read the live blob bytes for every entry in ``snapshot``.

    Returns ``[(package_path, raw_bytes), ...]``. Used by the package
    builder, which never touches the repository working tree directly.
    """
    repo_root = Path(snapshot.repository_id)
    out: list[tuple[str, bytes]] = []
    for blob in snapshot.files:
        out.append((blob.package_path, _cat_file_batch(repo_root, blob.git_blob_sha)))
    return out


@dataclass(frozen=True)
class ExcludedSnapshotFile:
    """A file that exists in the commit tree but is excluded from the package."""

    repository_path: str
    exclusion_rule: str
    exclusion_reason: str
    git_blob_sha: str
    size_bytes: int


def build_snapshot_manifest_with_exclusions(
    snapshot: GitSnapshot,
    excluded: Iterable[ExcludedSnapshotFile],
) -> dict[str, object]:
    """Convenience wrapper that materialises the exclusion tuple.

    Empty exclusion_rule / exclusion_reason / git_blob_sha / size_bytes
    are rejected — every excluded file MUST carry all four fields.
    """
    excluded_tuple = tuple(excluded)
    for e in excluded_tuple:
        if not e.repository_path:
            raise ValueError("excluded_snapshot_file.repository_path required")
        if not e.exclusion_rule:
            raise ValueError(
                f"excluded_snapshot_file.exclusion_rule required for {e.repository_path}"
            )
        if not e.exclusion_reason:
            raise ValueError(
                f"excluded_snapshot_file.exclusion_reason required for {e.repository_path}"
            )
        if not _HEX40.match(e.git_blob_sha):
            raise ValueError(
                f"excluded_snapshot_file.git_blob_sha invalid for {e.repository_path}"
            )
        if e.size_bytes < 0:
            raise ValueError(
                f"excluded_snapshot_file.size_bytes negative for {e.repository_path}"
            )
    return create_snapshot_manifest(snapshot, excluded_snapshot_files=excluded_tuple)


def verify_snapshot_exact_set(manifest: Mapping[str, object]) -> tuple[bool, list[str]]:
    """Verify the exact set contract on a snapshot manifest.

    Required invariants:
      - tracked_file_count == included_file_count + excluded_file_count
      - Every included file has repository_path / package_path /
        git_blob_sha / package_sha256 / size_bytes
      - Every excluded file has repository_path / exclusion_rule /
        exclusion_reason / git_blob_sha / size_bytes
      - All values are non-empty (empty string for a required field is a violation)
    """
    violations: list[str] = []
    tracked = manifest.get("tracked_file_count")
    included = manifest.get("included_file_count")
    excluded = manifest.get("excluded_file_count")
    if not isinstance(tracked, int) or tracked < 0:
        violations.append("tracked_file_count invalid")
    if not isinstance(included, int) or included < 0:
        violations.append("included_file_count invalid")
    if not isinstance(excluded, int) or excluded < 0:
        violations.append("excluded_file_count invalid")
    if (
        isinstance(tracked, int)
        and isinstance(included, int)
        and isinstance(excluded, int)
        and tracked != included + excluded
    ):
        violations.append(
            f"exact set violation: tracked={tracked} != included+excluded={included + excluded}"
        )
    files = manifest.get("files")
    if not isinstance(files, list):
        violations.append("manifest.files must be a list")
    else:
        for f in files:
            if not isinstance(f, dict):
                violations.append("included file must be an object")
                continue
            for key in (
                "repository_path",
                "package_path",
                "git_blob_sha",
                "package_sha256",
                "size_bytes",
            ):
                if key not in f:
                    violations.append(f"included file missing {key}")
                elif not f.get(key):
                    violations.append(f"included file has empty {key}")
    excluded_list = manifest.get("excluded_snapshot_files")
    if not isinstance(excluded_list, list):
        violations.append("manifest.excluded_snapshot_files must be a list")
    else:
        for e in excluded_list:
            if not isinstance(e, dict):
                violations.append("excluded file must be an object")
                continue
            for key in (
                "repository_path",
                "exclusion_rule",
                "exclusion_reason",
                "git_blob_sha",
                "size_bytes",
            ):
                if key not in e:
                    violations.append(f"excluded file missing {key}")
                elif not e.get(key) and key != "size_bytes":
                    violations.append(
                        f"excluded file has empty {key} for {e.get('repository_path', '?')}"
                    )
                if key == "git_blob_sha":
                    blob_sha = e.get(key)
                    if isinstance(blob_sha, str) and not _HEX40.match(blob_sha):
                        violations.append(
                            f"excluded file git_blob_sha not 40-hex "
                            f"for {e.get('repository_path', '?')}"
                        )
    return (not violations, violations)


__all__ = [
    "ExcludedSnapshotFile",
    "GitBlobInfo",
    "GitSnapshot",
    "GitSnapshotError",
    "build_git_snapshot",
    "build_snapshot_manifest_with_exclusions",
    "create_snapshot_manifest",
    "serialize_blob_payload",
    "verify_snapshot_exact_set",
]
