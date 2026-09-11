"""Internal Review Index — last artifact generated.

Every SHA-256 in the index is computed from the actual on-disk
bytes of the artifact it references. The index is generated AFTER
every referenced artifact exists, so its hashes are guaranteed to
match its sources. The semantic verifier checks the inverse: every
hash in the index must match the corresponding on-disk file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_FIELDS: tuple[str, ...] = (
    "review_candidate_state_sha256",
    "review_report_sha256",
    "verification_summary_sha256",
    "gate_summary_sha256",
    "review_decision_sha256",
    "review_location_receipt_sha256",
    "core_scm_provenance_sha256",
    "core_snapshot_manifest_sha256",
    "service_pack_scm_provenance_sha256",
    "service_pack_snapshot_manifest_sha256",
    "test_evidence_manifest_sha256",
    "command_evidence_manifest_sha256",
    "negative_exploit_matrix_sha256",
)


@dataclass(frozen=True)
class InternalReviewIndex:
    phase: str
    hashes: Mapping[str, str]
    hash_chain_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"phase": self.phase}
        for k in REQUIRED_FIELDS:
            payload[k] = self.hashes.get(k, "")
        if self.hash_chain_sha256:
            payload["hash_chain_sha256"] = self.hash_chain_sha256
        return payload


def _hash_file(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"internal_review_index source not found: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_internal_review_index(
    *,
    phase: str,
    artifact_paths: Mapping[str, Path],
) -> InternalReviewIndex:
    """Compute SHA-256 for every required artifact and emit the index.

    ``artifact_paths`` MUST contain a Path for every key in
    :data:`REQUIRED_FIELDS`. Any missing source fails the build.
    """
    missing = [k for k in REQUIRED_FIELDS if k not in artifact_paths]
    if missing:
        raise ValueError(f"internal_review_index missing artifact paths: {missing}")
    extra = [k for k in artifact_paths if k not in REQUIRED_FIELDS]
    if extra:
        raise ValueError(f"internal_review_index unexpected artifact paths: {extra}")
    hashes: dict[str, str] = {}
    for key in REQUIRED_FIELDS:
        sha = _hash_file(artifact_paths[key])
        if not _HEX64.match(sha):
            raise ValueError(f"computed sha256 not 64-hex for {key}: {sha!r}")
        hashes[key] = sha
    payload = {"phase": phase}
    for k in REQUIRED_FIELDS:
        payload[k] = hashes[k]
    chain = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return InternalReviewIndex(phase=phase, hashes=hashes, hash_chain_sha256=chain)


def write_internal_review_index(index: InternalReviewIndex, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(index.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


def load_internal_review_index(path: Path) -> InternalReviewIndex:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("internal_review_index must be a JSON object")
    phase = data.get("phase")
    if not isinstance(phase, str) or not phase:
        raise ValueError("phase must be non-empty string")
    hashes: dict[str, str] = {}
    for k in REQUIRED_FIELDS:
        v = data.get(k)
        if not isinstance(v, str) or not _HEX64.match(v):
            raise ValueError(f"{k} invalid sha256: {v!r}")
        hashes[k] = v
    chain = data.get("hash_chain_sha256", "")
    if chain and not _HEX64.match(chain):
        raise ValueError("hash_chain_sha256 invalid")
    return InternalReviewIndex(phase=phase, hashes=hashes, hash_chain_sha256=chain or "")


def verify_internal_review_index(
    index: InternalReviewIndex,
    artifact_paths: Mapping[str, Path],
) -> tuple[bool, list[str]]:
    """Recompute every SHA from disk and confirm it matches the index."""
    violations: list[str] = []
    for key in REQUIRED_FIELDS:
        declared = index.hashes.get(key, "")
        actual = _hash_file(artifact_paths[key])
        if declared != actual:
            violations.append(f"{key} mismatch: declared={declared} actual={actual}")
    return (not violations, violations)


__all__ = [
    "InternalReviewIndex",
    "REQUIRED_FIELDS",
    "build_internal_review_index",
    "load_internal_review_index",
    "verify_internal_review_index",
    "write_internal_review_index",
]
