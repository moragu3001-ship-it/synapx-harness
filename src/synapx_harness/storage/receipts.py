"""Deletion receipts for GC operations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class DeletionReceipt:
    """Receipt for a single deletion or skip operation."""

    run_id: str
    path: str
    size_bytes_before: int
    classification: str
    reason: str
    policy: dict[str, int]
    deleted_at: str
    delete_result: str  # DELETED | DELETE_FAILED | SKIPPED_PROTECTED | SKIPPED_UNKNOWN
    deletion_trigger: str = "NONE"  # NONE | TTL | QUOTA | TTL_AND_QUOTA

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "path": self.path,
            "size_bytes_before": self.size_bytes_before,
            "classification": self.classification,
            "reason": self.reason,
            "policy": self.policy,
            "deleted_at": self.deleted_at,
            "delete_result": self.delete_result,
            "deletion_trigger": self.deletion_trigger,
        }


def make_receipt(
    run_id: str,
    path: str,
    size_bytes_before: int,
    classification: str,
    reason: str,
    policy_ttl_days: int,
    policy_max_total_bytes: int,
    delete_result: str,
    deletion_trigger: str = "NONE",
) -> DeletionReceipt:
    """Create a deletion receipt."""
    return DeletionReceipt(
        run_id=run_id,
        path=path,
        size_bytes_before=size_bytes_before,
        classification=classification,
        reason=reason,
        policy={
            "ttl_days": policy_ttl_days,
            "max_total_bytes": policy_max_total_bytes,
        },
        deleted_at=datetime.now(tz=UTC).isoformat(),
        delete_result=delete_result,
        deletion_trigger=deletion_trigger,
    )
