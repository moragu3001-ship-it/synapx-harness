"""Test Evidence Manifest — census of raw test artifacts.

The manifest is derived from a directory census, not from a hand-
written JSON file. Each entry references an actual file on disk
with the actual sha256 and actual size_bytes. Any mismatch between
declared and actual bytes fails the semantic verifier.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TestEvidenceEntry:
    path: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class TestEvidenceManifest:
    phase: str
    entries: tuple[TestEvidenceEntry, ...]
    entry_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "entry_count": self.entry_count,
            "entries": [e.to_dict() for e in self.entries],
        }


def _hash_file(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def build_test_evidence_manifest(
    *,
    phase: str,
    test_evidence_dir: Path,
) -> TestEvidenceManifest:
    """Census ``test_evidence_dir`` and emit a manifest.

    Every regular file under the directory becomes one entry. Missing
    files referenced by the manifest are detected by the semantic
    verifier, not here.
    """
    if not test_evidence_dir.is_dir():
        raise FileNotFoundError(f"test_evidence_dir does not exist: {test_evidence_dir}")
    entries: list[TestEvidenceEntry] = []
    for child in sorted(test_evidence_dir.rglob("*")):
        if not child.is_file():
            continue
        rel = child.relative_to(test_evidence_dir).as_posix()
        sha, size = _hash_file(child)
        if not _HEX64.match(sha):
            raise ValueError(f"computed sha256 not 64-hex: {sha!r}")
        entries.append(TestEvidenceEntry(path=rel, sha256=sha, size_bytes=size))
    return TestEvidenceManifest(
        phase=phase,
        entries=tuple(entries),
        entry_count=len(entries),
    )


def write_test_evidence_manifest(
    manifest: TestEvidenceManifest,
    out_path: Path,
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


def load_test_evidence_manifest(path: Path) -> TestEvidenceManifest:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("test_evidence_manifest must be a JSON object")
    phase = data.get("phase")
    if not isinstance(phase, str) or not phase:
        raise ValueError("test_evidence_manifest.phase must be a non-empty string")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raise ValueError("test_evidence_manifest.entries must be a list")
    entries: list[TestEvidenceEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise ValueError("test_evidence_manifest entries must be objects")
        p = raw.get("path")
        sha = raw.get("sha256")
        size = raw.get("size_bytes")
        if not isinstance(p, str) or not p:
            raise ValueError("entry.path must be a non-empty string")
        if not isinstance(sha, str) or not _HEX64.match(sha):
            raise ValueError(f"entry.sha256 not 64-hex: {sha!r}")
        if not isinstance(size, int) or size < 0:
            raise ValueError("entry.size_bytes must be a non-negative int")
        entries.append(TestEvidenceEntry(path=p, sha256=sha, size_bytes=size))
    declared_count = data.get("entry_count")
    if declared_count is not None and declared_count != len(entries):
        raise ValueError(f"declared entry_count={declared_count} != actual={len(entries)}")
    return TestEvidenceManifest(phase=phase, entries=tuple(entries), entry_count=len(entries))


def verify_manifest_against_directory(
    manifest: TestEvidenceManifest,
    test_evidence_dir: Path,
) -> tuple[bool, list[str]]:
    """Strict bijection between manifest entries and actual files."""
    violations: list[str] = []
    actual_set: set[str] = set()
    for child in test_evidence_dir.rglob("*"):
        if child.is_file():
            actual_set.add(child.relative_to(test_evidence_dir).as_posix())
    declared_set = {e.path for e in manifest.entries}
    extra = actual_set - declared_set
    missing = declared_set - actual_set
    if extra:
        violations.append(f"manifest missing entries: {sorted(extra)}")
    if missing:
        violations.append(f"manifest entries not on disk: {sorted(missing)}")
    for entry in manifest.entries:
        on_disk = test_evidence_dir / entry.path
        if not on_disk.is_file():
            continue
        sha, size = _hash_file(on_disk)
        if sha != entry.sha256:
            violations.append(
                f"hash mismatch for {entry.path}: declared={entry.sha256} actual={sha}"
            )
        if size != entry.size_bytes:
            violations.append(
                f"size mismatch for {entry.path}: declared={entry.size_bytes} actual={size}"
            )
    return (not violations, violations)


__all__ = [
    "TestEvidenceEntry",
    "TestEvidenceManifest",
    "build_test_evidence_manifest",
    "load_test_evidence_manifest",
    "verify_manifest_against_directory",
    "write_test_evidence_manifest",
]
