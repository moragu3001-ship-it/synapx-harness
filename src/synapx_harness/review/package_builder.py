"""Review package builder.

The R7 builder accepts **only** commit-bound snapshot payloads as
input. It MUST NOT read repository working trees, MUST NOT emit
synthetic placeholder files, and MUST produce a strict bijection
between declared payload paths and actual ZIP entries.

Mandatory inputs:
  - :class:`GitSnapshot` for core
  - :class:`GitSnapshot` for service pack
  - iterable of ``(package_relative_path, bytes)`` review payloads

The legacy ``core_root`` / ``service_pack_root`` keyword arguments
are retained as an explicit error: callers MUST migrate to snapshot
inputs. This eliminates the R6 working-tree read path.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.review.git_snapshot import (
    GitSnapshot,
    serialize_blob_payload,
)


@dataclass(frozen=True)
class PackagePayload:
    package_path: str
    payload: bytes


@dataclass(frozen=True)
class PackageBuildResult:
    ok: bool
    zip_path: str = ""
    zip_sha256: str = ""
    entry_count: int = 0
    manifest_path: str = ""
    manifest_sha256: str = ""
    excluded: tuple[str, ...] = field(default_factory=tuple)
    duplicates_exact: int = 0
    duplicates_normalized: int = 0
    duplicates_casefold: int = 0
    backslash_entries: int = 0
    violations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "zip_path": self.zip_path,
            "zip_sha256": self.zip_sha256,
            "entry_count": self.entry_count,
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "excluded": list(self.excluded),
            "duplicates_exact": self.duplicates_exact,
            "duplicates_normalized": self.duplicates_normalized,
            "duplicates_casefold": self.duplicates_casefold,
            "backslash_entries": self.backslash_entries,
            "violations": list(self.violations),
        }


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_path(rel: str) -> str:
    return rel.replace("\\", "/").lstrip("/")


def _collect_snapshot_payloads(
    snapshot: GitSnapshot,
) -> list[tuple[str, bytes]]:
    return serialize_blob_payload(snapshot)


def _is_in_scope(path: str) -> bool:
    """Filter a package path against the scope allowlists."""
    if path.startswith("review/"):
        return True
    from synapx_harness.review.package_scope import is_path_allowed

    if is_path_allowed(path, scope="core"):
        return True
    if is_path_allowed(path, scope="service_pack"):
        return True
    return False


def build_package(
    *,
    core_snapshot: GitSnapshot | None = None,
    service_pack_snapshot: GitSnapshot | None = None,
    review_payloads: Iterable[PackagePayload | tuple[str, bytes]] = (),
    out_path: Path,
    core_root: Path | None = None,
    service_pack_root: Path | None = None,
    enforce_scope: bool = True,
) -> PackageBuildResult:
    """Build the R7 review package from snapshot inputs only.

    The legacy ``core_root`` / ``service_pack_root`` arguments are
    rejected; they were the working-tree source that caused the R6
    rejection. Callers MUST migrate to snapshot inputs.

    Snapshot sources MUST both be provided and MUST each have
    ``tracked_file_count > 0`` (enforced by :class:`GitSnapshot`).

    ``enforce_scope`` defaults to True. When True, paths that fall
    outside the legacy package scope allowlist are excluded from the
    package (this preserves the R2/R3 contract). Tests that don't
    care about the R3 scope allowlist can disable it.
    """
    if core_root is not None or service_pack_root is not None:
        raise TypeError(
            "build_package: core_root/service_pack_root are forbidden; "
            "use core_snapshot/service_pack_snapshot (commit-bound)"
        )
    if core_snapshot is None or service_pack_snapshot is None:
        raise TypeError(
            "build_package: core_snapshot and service_pack_snapshot "
            "are required"
        )
    if core_snapshot.tracked_file_count <= 0:
        raise ValueError("core_snapshot has zero tracked files")
    if service_pack_snapshot.tracked_file_count <= 0:
        raise ValueError("service_pack_snapshot has zero tracked files")

    excluded: list[str] = []
    backslash_entries = 0
    candidates: list[tuple[str, bytes]] = []

    for path, data in _collect_snapshot_payloads(core_snapshot):
        normalized = _normalize_path(path)
        if "\\" in path or normalized != path:
            backslash_entries += 1
            continue
        if enforce_scope and not _is_in_scope(normalized):
            excluded.append(f"out_of_scope: {normalized}")
            continue
        candidates.append((normalized, data))

    for path, data in _collect_snapshot_payloads(service_pack_snapshot):
        normalized = _normalize_path(path)
        if "\\" in path or normalized != path:
            backslash_entries += 1
            continue
        if enforce_scope and not _is_in_scope(normalized):
            excluded.append(f"out_of_scope: {normalized}")
            continue
        candidates.append((normalized, data))

    for item in review_payloads:
        if isinstance(item, PackagePayload):
            rel = item.package_path
            data = item.payload
        elif isinstance(item, tuple) and len(item) == 2:
            rel, data = item
        else:
            excluded.append(
                f"review_payload type invalid: {type(item).__name__}"
            )
            continue
        if not isinstance(rel, str) or not isinstance(data, bytes):
            excluded.append("review_payload rel must be str and data must be bytes")
            continue
        normalized = _normalize_path(rel)
        if "\\" in rel or normalized != rel:
            backslash_entries += 1
            continue
        if enforce_scope and not _is_in_scope(normalized):
            excluded.append(f"out_of_scope: {normalized}")
            continue
        candidates.append((normalized, data))

    seen_exact: set[str] = set()
    seen_normalized: set[str] = set()
    seen_casefold: set[str] = set()
    duplicates_exact = 0
    duplicates_normalized = 0
    duplicates_casefold = 0
    accepted: list[tuple[str, bytes]] = []
    for name, data in candidates:
        norm = _normalize_path(name)
        casefold = norm.casefold()
        if name in seen_exact:
            duplicates_exact += 1
            continue
        seen_exact.add(name)
        if norm in seen_normalized:
            duplicates_normalized += 1
            continue
        seen_normalized.add(norm)
        if casefold in seen_casefold:
            duplicates_casefold += 1
            continue
        seen_casefold.add(casefold)
        accepted.append((name, data))

    manifest_entries = [
        {
            "path": name,
            "sha256": _hash_bytes(data),
            "size_bytes": len(data),
        }
        for name, data in accepted
    ]
    manifest = {
        "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
        "payload_file_count": len(accepted),
        "files": manifest_entries,
    }
    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in accepted:
            zf.writestr(name, data)
        zf.writestr("package_payload_manifest.json", manifest_bytes)
    zip_bytes = zip_buffer.getvalue()
    zip_sha = _hash_bytes(zip_bytes)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(zip_bytes)

    manifest_sha = _hash_bytes(manifest_bytes)

    violations: list[str] = []
    out_of_scope_exclusions = [e for e in excluded if e.startswith("out_of_scope:")]
    true_violations = [e for e in excluded if not e.startswith("out_of_scope:")]
    if true_violations:
        violations.append(f"excluded violations: {true_violations}")
    if out_of_scope_exclusions:
        violations.append(f"out_of_scope: {len(out_of_scope_exclusions)} files")
    if duplicates_exact:
        violations.append(f"duplicate exact {duplicates_exact}")
    if duplicates_normalized:
        violations.append(f"duplicate normalized {duplicates_normalized}")
    if duplicates_casefold:
        violations.append(f"duplicate casefold {duplicates_casefold}")
    if backslash_entries:
        violations.append(f"backslash entries {backslash_entries}")

    ok = (
        not true_violations
        and not duplicates_exact
        and not duplicates_normalized
        and not duplicates_casefold
        and not backslash_entries
    )
    return PackageBuildResult(
        ok=ok,
        zip_path=str(out_path),
        zip_sha256=zip_sha,
        entry_count=len(accepted) + 1,
        manifest_path="package_payload_manifest.json",
        manifest_sha256=manifest_sha,
        excluded=tuple(excluded),
        duplicates_exact=duplicates_exact,
        duplicates_normalized=duplicates_normalized,
        duplicates_casefold=duplicates_casefold,
        backslash_entries=backslash_entries,
        violations=tuple(violations),
    )


__all__ = [
    "PackageBuildResult",
    "PackagePayload",
    "build_package",
]
