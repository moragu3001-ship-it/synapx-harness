"""Run metadata catalog for _runs directory."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class RunStatus(StrEnum):
    """Deterministic run status classification."""

    ACTIVE = "ACTIVE"
    RUNNING = "RUNNING"
    INCOMPLETE = "INCOMPLETE"
    COMPLETE = "COMPLETE"
    UNKNOWN = "UNKNOWN"


class ReferenceState(StrEnum):
    """Reference state from external sources."""

    REFERENCED = "REFERENCED"
    UNREFERENCED = "UNREFERENCED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RunMetadata:
    """Metadata for a single run directory."""

    run_id: str
    path: str
    size_bytes: int
    status: RunStatus
    created_at: str
    last_known_activity_at: str
    pinned: bool = False
    protected: bool = False
    reference_state: ReferenceState = ReferenceState.UNKNOWN
    has_sealed_evidence: bool = False
    has_review_package: bool = False
    has_authority_reference: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "status": self.status.value,
            "created_at": self.created_at,
            "last_known_activity_at": self.last_known_activity_at,
            "pinned": self.pinned,
            "protected": self.protected,
            "reference_state": self.reference_state.value,
            "has_sealed_evidence": self.has_sealed_evidence,
            "has_review_package": self.has_review_package,
            "has_authority_reference": self.has_authority_reference,
        }


@dataclass(frozen=True)
class StorageCatalog:
    """Complete catalog of all runs in _runs directory."""

    runs: tuple[RunMetadata, ...] = field(default_factory=tuple)

    @property
    def total_size_bytes(self) -> int:
        return sum(r.size_bytes for r in self.runs)

    @property
    def run_count(self) -> int:
        return len(self.runs)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_size_bytes": self.total_size_bytes,
            "run_count": self.run_count,
            "runs": [r.to_dict() for r in self.runs],
        }


def compute_run_size(run_path: Path) -> int:
    """Compute total byte size of a run directory."""
    if not run_path.is_dir():
        return 0
    total = 0
    for entry in run_path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total
