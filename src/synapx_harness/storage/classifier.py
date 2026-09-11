"""Safe deletion classification for runs."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from synapx_harness.storage.catalog import ReferenceState, RunMetadata, RunStatus
from synapx_harness.storage.policy import RetentionPolicy


class DeletionClass(StrEnum):
    """Deletion classification for runs."""

    PROTECTED = "PROTECTED"
    KEEP = "KEEP"
    GC_CANDIDATE = "GC_CANDIDATE"


class DeletionTrigger(StrEnum):
    """Why a run was selected for deletion."""

    NONE = "NONE"
    TTL = "TTL"
    QUOTA = "QUOTA"
    TTL_AND_QUOTA = "TTL_AND_QUOTA"


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying a single run."""

    run_id: str
    path: str
    size_bytes: int
    classification: DeletionClass
    reason: str
    retention_basis: str
    reference_state: str
    protection_state: str
    eligible_timestamp: str = ""
    ttl_expired: bool = False
    safe_eligible: bool = False
    deletion_trigger: DeletionTrigger = DeletionTrigger.NONE

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "classification": self.classification.value,
            "reason": self.reason,
            "retention_basis": self.retention_basis,
            "reference_state": self.reference_state,
            "protection_state": self.protection_state,
            "eligible_timestamp": self.eligible_timestamp,
            "ttl_expired": self.ttl_expired,
            "safe_eligible": self.safe_eligible,
            "deletion_trigger": self.deletion_trigger.value,
        }


def _parse_iso(s: str) -> datetime:
    """Parse ISO datetime string to timezone-aware datetime."""

    s_clean = s.replace("Z", "+00:00")
    if "+" not in s_clean and s_clean.endswith("00:00"):
        dt = datetime.fromisoformat(s_clean)
    else:
        dt = datetime.fromisoformat(s_clean)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def classify_run(
    run: RunMetadata,
    policy: RetentionPolicy,
    *,
    now: datetime | None = None,
) -> ClassificationResult:
    """Classify a single run for safe deletion.

    Classification precedence:
      1. PROTECTED: active/running/incomplete, sealed evidence,
         authority/review ref, pinned, protected
      2. KEEP: reference_state=UNKNOWN, or status not terminal
      3. GC_CANDIDATE: terminal + unreferenced + TTL expired + safe
      4. safe_eligible=true but TTL not expired → quota-eligible in gc.py

    UNKNOWN → KEEP: ownership/status cannot be deterministically determined.
    """
    if now is None:
        now = datetime.now(tz=UTC)

    reasons: list[str] = []
    eligible_timestamp = run.last_known_activity_at

    # PROTECTED conditions — checked first, immutable
    if run.status in (RunStatus.ACTIVE, RunStatus.RUNNING, RunStatus.INCOMPLETE):
        reasons.append(f"status={run.status.value}")
        return _make_result(
            run, DeletionClass.KEEP, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    if run.has_sealed_evidence:
        reasons.append("sealed_evidence_present")
        return _make_result(
            run, DeletionClass.PROTECTED, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    if run.has_authority_reference:
        reasons.append("authority_reference_present")
        return _make_result(
            run, DeletionClass.PROTECTED, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    if run.has_review_package:
        reasons.append("review_package_present")
        return _make_result(
            run, DeletionClass.PROTECTED, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    if run.pinned:
        reasons.append("pinned=true")
        return _make_result(
            run, DeletionClass.PROTECTED, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    if run.protected:
        reasons.append("protected=true")
        return _make_result(
            run, DeletionClass.PROTECTED, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    # UNKNOWN → KEEP
    if run.reference_state == ReferenceState.UNKNOWN:
        reasons.append("reference_state=UNKNOWN")
        return _make_result(
            run, DeletionClass.KEEP, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    # Must be COMPLETE + UNREFERENCED to be safe_eligible
    if run.status != RunStatus.COMPLETE:
        reasons.append(f"status={run.status.value}; not terminal")
        return _make_result(
            run, DeletionClass.KEEP, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    if run.reference_state != ReferenceState.UNREFERENCED:
        reasons.append("reference_state=REFERENCED")
        return _make_result(
            run, DeletionClass.KEEP, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    # SafeDeletionEligible — COMPLETE + UNREFERENCED + safe
    # TTL check
    try:
        last_activity = _parse_iso(run.last_known_activity_at)
        age_days = (now - last_activity).days
    except (ValueError, TypeError):
        reasons.append("last_known_activity_at=unparseable")
        return _make_result(
            run, DeletionClass.KEEP, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
        )

    ttl_expired = age_days >= policy.ttl_days

    if ttl_expired:
        reasons.append("status=COMPLETE")
        reasons.append("reference_state=UNREFERENCED")
        reasons.append(f"age={age_days}d >= ttl={policy.ttl_days}d")
        return _make_result(
            run, DeletionClass.GC_CANDIDATE, "; ".join(reasons), policy,
            eligible_timestamp=eligible_timestamp,
            ttl_expired=True,
            safe_eligible=True,
            deletion_trigger=DeletionTrigger.TTL,
        )

    # Safe but TTL not expired — eligible for quota pressure selection
    reasons.append(f"age={age_days}d < ttl={policy.ttl_days}d; safe_eligible=true")
    return _make_result(
        run, DeletionClass.KEEP, "; ".join(reasons), policy,
        eligible_timestamp=eligible_timestamp,
        ttl_expired=False,
        safe_eligible=True,
    )


def _make_result(
    run: RunMetadata,
    classification: DeletionClass,
    reason: str,
    policy: RetentionPolicy,
    *,
    eligible_timestamp: str = "",
    ttl_expired: bool = False,
    safe_eligible: bool = False,
    deletion_trigger: DeletionTrigger = DeletionTrigger.NONE,
) -> ClassificationResult:
    protection_parts: list[str] = []
    if run.pinned:
        protection_parts.append("pinned")
    if run.protected:
        protection_parts.append("protected")
    if run.has_sealed_evidence:
        protection_parts.append("sealed_evidence")
    if run.has_authority_reference:
        protection_parts.append("authority_reference")
    if run.has_review_package:
        protection_parts.append("review_package")
    if run.status in (RunStatus.ACTIVE, RunStatus.RUNNING, RunStatus.INCOMPLETE):
        protection_parts.append(f"status={run.status.value}")

    return ClassificationResult(
        run_id=run.run_id,
        path=run.path,
        size_bytes=run.size_bytes,
        classification=classification,
        reason=reason,
        retention_basis=f"ttl_days={policy.ttl_days}",
        reference_state=run.reference_state.value,
        protection_state="; ".join(protection_parts) if protection_parts else "none",
        eligible_timestamp=eligible_timestamp,
        ttl_expired=ttl_expired,
        safe_eligible=safe_eligible,
        deletion_trigger=deletion_trigger,
    )


def classify_runs(
    runs: Sequence[RunMetadata],
    policy: RetentionPolicy,
    *,
    now: datetime | None = None,
) -> list[ClassificationResult]:
    """Classify all runs for safe deletion."""
    return [classify_run(run, policy, now=now) for run in runs]
