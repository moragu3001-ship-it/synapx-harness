"""Review Location Receipt — recount of review artifacts.

The receipt is derived from a real directory census immediately
before package build. No manual artifact_count or total_size_bytes
constants are allowed. The semantic verifier recounts the ZIP and
rejects if the declared numbers no longer match.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

CANONICAL_REVIEW_BASE = Path(r"D:\project\_review")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ReviewLocationReceipt:
    phase: str
    review_root: str
    artifact_count: int
    total_size_bytes: int
    root_sha256: str
    gate: str

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "review_root": self.review_root,
            "artifact_count": self.artifact_count,
            "total_size_bytes": self.total_size_bytes,
            "root_sha256": self.root_sha256,
            "gate": self.gate,
        }


def _census_review_root(review_root: Path) -> tuple[int, int, str]:
    count = 0
    total = 0
    h = hashlib.sha256()
    for child in sorted(review_root.rglob("*")):
        if not child.is_file():
            continue
        rel = child.relative_to(review_root).as_posix().encode("utf-8")
        size = child.stat().st_size
        h.update(rel)
        h.update(b"\x00")
        h.update(str(size).encode("ascii"))
        h.update(b"\x00")
        count += 1
        total += size
    return count, total, h.hexdigest()


def _validate_canonical_review_root(
    *,
    review_root: Path,
    canonical_review_base: Path,
    phase: str,
) -> tuple[bool, str]:
    """Fail-closed exact-path canonical validation.

    Accepts ONLY: ``<canonical_review_base>/<phase>/review``.
    Rejects:
      - non-canonical base (e.g., ``D:\\_review``)
      - duplicate ``_review`` segment (e.g., ``<base>/_review/<phase>/review``)
      - wrong phase segment
      - any extra or missing path segment after ``<phase>``
    """
    resolved = review_root.resolve()
    canonical_base = canonical_review_base.resolve()
    expected = (canonical_base / phase / "review").resolve()
    if resolved != expected:
        return (
            False,
            f"review_root {resolved} != canonical {expected}",
        )
    return True, ""


def build_review_location_receipt(
    *,
    phase: str,
    review_root: Path,
    canonical_review_base: Path,
) -> ReviewLocationReceipt:
    """Recount the review artifact tree and emit a receipt.

    Canonical gate enforcement (CR4):
      review_root.resolve() == canonical_review_base / <PHASE> / "review"

    The receipt's ``gate`` is PASS only when ALL four conditions hold:
      - Canonical Root PASS
      - Phase Path PASS (review_root resolves exactly to base/phase/review)
      - Directory Census PASS
      - Artifact Count > 0
    """
    if not isinstance(phase, str) or not phase:
        raise ValueError("phase must be a non-empty string")
    if not isinstance(canonical_review_base, Path):
        raise TypeError("canonical_review_base must be a Path")
    if not review_root.is_dir():
        raise FileNotFoundError(f"review_root does not exist: {review_root}")
    canonical_root_ok, canonical_root_msg = _validate_canonical_review_root(
        review_root=review_root,
        canonical_review_base=canonical_review_base,
        phase=phase,
    )
    if not canonical_root_ok:
        raise ValueError(f"canonical review root gate failed: {canonical_root_msg}")
    count, total, root_sha = _census_review_root(review_root)
    if not _HEX64.match(root_sha):
        raise ValueError(f"computed root_sha not 64-hex: {root_sha!r}")
    gate = (
        "PASS"
        if (count > 0 and canonical_root_ok)
        else "FAIL"
    )
    return ReviewLocationReceipt(
        phase=phase,
        review_root=str(review_root.resolve()),
        artifact_count=count,
        total_size_bytes=total,
        root_sha256=root_sha,
        gate=gate,
    )


def write_review_location_receipt(receipt: ReviewLocationReceipt, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(receipt.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


def load_review_location_receipt(path: Path) -> ReviewLocationReceipt:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("review_location_receipt must be a JSON object")
    phase = data.get("phase")
    root = data.get("review_root")
    count = data.get("artifact_count")
    total = data.get("total_size_bytes")
    root_sha = data.get("root_sha256")
    gate = data.get("gate")
    if not isinstance(phase, str) or not phase:
        raise ValueError("phase must be non-empty string")
    if not isinstance(root, str) or not root:
        raise ValueError("review_root must be non-empty string")
    if not isinstance(count, int) or count < 0:
        raise ValueError("artifact_count must be a non-negative int")
    if not isinstance(total, int) or total < 0:
        raise ValueError("total_size_bytes must be a non-negative int")
    if not isinstance(root_sha, str) or not _HEX64.match(root_sha):
        raise ValueError(f"root_sha256 invalid: {root_sha!r}")
    if gate not in ("PASS", "FAIL"):
        raise ValueError("gate must be PASS or FAIL")
    return ReviewLocationReceipt(
        phase=phase,
        review_root=root,
        artifact_count=count,
        total_size_bytes=total,
        root_sha256=root_sha,
        gate=gate,
    )


def verify_review_location_receipt(
    receipt: ReviewLocationReceipt,
    review_root: Path,
    *,
    canonical_review_base: Path,
) -> tuple[bool, list[str]]:
    """Recount the tree and compare against the declared receipt."""
    violations: list[str] = []
    canonical_ok, canonical_msg = _validate_canonical_review_root(
        review_root=review_root,
        canonical_review_base=canonical_review_base,
        phase=receipt.phase,
    )
    if not canonical_ok:
        violations.append(f"canonical_review_root_gate: {canonical_msg}")
    count, total, root_sha = _census_review_root(review_root)
    if count != receipt.artifact_count:
        violations.append(
            f"artifact_count mismatch: declared={receipt.artifact_count} actual={count}"
        )
    if total != receipt.total_size_bytes:
        violations.append(
            f"total_size_bytes mismatch: declared={receipt.total_size_bytes} actual={total}"
        )
    if root_sha != receipt.root_sha256:
        violations.append(f"root_sha256 mismatch: declared={receipt.root_sha256} actual={root_sha}")
    return (not violations, violations)


__all__ = [
    "CANONICAL_REVIEW_BASE",
    "ReviewLocationReceipt",
    "build_review_location_receipt",
    "load_review_location_receipt",
    "verify_review_location_receipt",
    "write_review_location_receipt",
]
