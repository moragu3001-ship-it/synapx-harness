"""Garbage collection for _runs directory."""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from synapx_harness.storage.catalog import StorageCatalog
from synapx_harness.storage.census import (
    _scan_all_external_references,
    build_catalog,
)
from synapx_harness.storage.classifier import (
    ClassificationResult,
    DeletionClass,
    DeletionTrigger,
    classify_runs,
)
from synapx_harness.storage.policy import RetentionPolicy
from synapx_harness.storage.receipts import DeletionReceipt, make_receipt


def _promote_for_quota(c: ClassificationResult) -> ClassificationResult:
    """Promote a safe_eligible run to GC_CANDIDATE with deletion_trigger=QUOTA."""
    if c.ttl_expired:
        trigger = DeletionTrigger.TTL_AND_QUOTA
    else:
        trigger = DeletionTrigger.QUOTA
    return ClassificationResult(
        run_id=c.run_id,
        path=c.path,
        size_bytes=c.size_bytes,
        classification=DeletionClass.GC_CANDIDATE,
        reason=c.reason,
        retention_basis=c.retention_basis,
        reference_state=c.reference_state,
        protection_state=c.protection_state,
        eligible_timestamp=c.eligible_timestamp,
        ttl_expired=c.ttl_expired,
        safe_eligible=c.safe_eligible,
        deletion_trigger=trigger,
    )


@dataclass(frozen=True)
class GCPlan:
    mode: str
    total_runs: int
    protected_runs: int
    unknown_runs: int
    retained_runs: int
    gc_candidates: int
    planned_delete_bytes: int
    projected_total_after: int
    quota_pressure: bool
    quota_unresolved_bytes: int = 0
    candidates: tuple[ClassificationResult, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "total_runs": self.total_runs,
            "protected_runs": self.protected_runs,
            "unknown_runs": self.unknown_runs,
            "retained_runs": self.retained_runs,
            "gc_candidates": self.gc_candidates,
            "planned_delete_bytes": self.planned_delete_bytes,
            "projected_total_after": self.projected_total_after,
            "quota_pressure": self.quota_pressure,
            "quota_unresolved_bytes": self.quota_unresolved_bytes,
            "candidates": [c.to_dict() for c in self.candidates],
        }


@dataclass(frozen=True)
class GCResult:
    plan: GCPlan
    receipts: tuple[DeletionReceipt, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "plan": self.plan.to_dict(),
            "receipts": [r.to_dict() for r in self.receipts],
        }


def _sort_candidates(
    classifications: list[ClassificationResult],
) -> list[ClassificationResult]:
    """Sort GC candidates by (eligible_timestamp ASC, run_id ASC)."""
    gc = [c for c in classifications if c.classification == DeletionClass.GC_CANDIDATE]
    return sorted(gc, key=lambda c: (c.eligible_timestamp, c.run_id))


def _get_quota_eligible(
    classifications: list[ClassificationResult],
) -> list[ClassificationResult]:
    """Get safe_eligible runs (including those with unexpired TTL) for quota pressure."""
    return sorted(
        [c for c in classifications if c.safe_eligible],
        key=lambda c: (c.eligible_timestamp, c.run_id),
    )


def _select_quota_candidates(
    sorted_candidates: list[ClassificationResult],
    total_size: int,
    max_total_bytes: int,
) -> list[ClassificationResult]:
    if total_size <= max_total_bytes:
        return []
    over_by = total_size - max_total_bytes
    selected: list[ClassificationResult] = []
    bytes_freed = 0
    for c in sorted_candidates:
        if bytes_freed >= over_by:
            break
        selected.append(c)
        bytes_freed += c.size_bytes
    return selected


def build_dry_run(
    catalog: StorageCatalog,
    policy: RetentionPolicy,
    *,
    now: datetime | None = None,
    census_complete: bool = True,
) -> GCPlan:
    if now is None:
        now = datetime.now(tz=UTC)

    # Census hard gate: incomplete census → no candidates
    if not census_complete:
        classifications = classify_runs(list(catalog.runs), policy, now=now)
        protected = sum(
            1 for c in classifications if c.classification == DeletionClass.PROTECTED
        )
        unknown = sum(
            1 for c in classifications
            if c.classification == DeletionClass.KEEP
            and c.reference_state == "UNKNOWN"
        )
        retained = sum(
            1 for c in classifications
            if c.classification == DeletionClass.KEEP
            and c.reference_state != "UNKNOWN"
        )
        return GCPlan(
            mode="dry-run",
            total_runs=catalog.run_count,
            protected_runs=protected,
            unknown_runs=unknown,
            retained_runs=retained,
            gc_candidates=0,
            planned_delete_bytes=0,
            projected_total_after=catalog.total_size_bytes,
            quota_pressure=catalog.total_size_bytes > policy.max_total_bytes,
            quota_unresolved_bytes=max(
                0, catalog.total_size_bytes - policy.max_total_bytes
            ),
            candidates=(),
        )

    classifications = classify_runs(list(catalog.runs), policy, now=now)
    ttl_candidates = _sort_candidates(classifications)
    all_safe_eligible = _get_quota_eligible(classifications)
    protected = sum(
        1 for c in classifications if c.classification == DeletionClass.PROTECTED
    )
    total_size = catalog.total_size_bytes
    quota_pressure = total_size > policy.max_total_bytes

    if quota_pressure:
        selected_raw = _select_quota_candidates(
            all_safe_eligible, total_size, policy.max_total_bytes
        )
        selected = [_promote_for_quota(c) for c in selected_raw]
    else:
        selected = ttl_candidates

    # Mutually exclusive diagnostics: compute AFTER selection
    selected_ids = {c.run_id for c in selected}
    unknown = sum(
        1 for c in classifications
        if c.classification == DeletionClass.KEEP
        and c.reference_state == "UNKNOWN"
        and c.run_id not in selected_ids
    )
    retained = sum(
        1 for c in classifications
        if c.classification == DeletionClass.KEEP
        and c.reference_state != "UNKNOWN"
        and c.run_id not in selected_ids
    )

    planned_bytes = sum(c.size_bytes for c in selected)
    projected_total = total_size - planned_bytes
    quota_unresolved = max(0, projected_total - policy.max_total_bytes)

    return GCPlan(
        mode="dry-run",
        total_runs=catalog.run_count,
        protected_runs=protected,
        unknown_runs=unknown,
        retained_runs=retained,
        gc_candidates=len(selected),
        planned_delete_bytes=planned_bytes,
        projected_total_after=projected_total,
        quota_pressure=quota_pressure,
        quota_unresolved_bytes=quota_unresolved,
        candidates=tuple(selected),
    )


def _revalidate_candidate(
    run_path: Path,
    *,
    project_root: Path | None = None,
    policy: RetentionPolicy | None = None,
    now: datetime | None = None,
    original_trigger: DeletionTrigger = DeletionTrigger.NONE,
) -> bool:
    """Re-validate candidate before actual delete using fresh plan re-selection.

    Rebuilds catalog and recomputes the full plan. If the run is still
    selected in the fresh plan, it is still eligible. Any state change
    (activity refresh, reference creation, protection, quota resolution,
    ordering change) causes rejection.
    Fail-closed: any uncertainty → False.
    """
    from synapx_harness.storage.census import (
        _detect_authority_reference,
        _detect_pinned,
        _detect_protected,
        _detect_review_package,
        _detect_sealed_evidence,
        _detect_status,
    )
    status = _detect_status(run_path)
    if status in ("ACTIVE", "RUNNING", "INCOMPLETE"):
        return False
    if _detect_sealed_evidence(run_path):
        return False
    if _detect_authority_reference(run_path):
        return False
    if _detect_review_package(run_path):
        return False
    if _detect_pinned(run_path):
        return False
    if _detect_protected(run_path):
        return False

    # Re-scan external references if project_root available
    if project_root is not None:
        run_id = run_path.name
        ref_states, scan_complete = _scan_all_external_references(
            project_root, {run_id}
        )
        if not scan_complete:
            return False
        ref_state = ref_states.get(run_id)
        if ref_state is None or ref_state.value != "UNREFERENCED":
            return False

    # Fresh plan re-selection: rebuild entire plan, check if still selected
    if policy is not None and now is not None:
        runs_root = run_path.parent
        fresh_census = build_catalog(runs_root, project_root=project_root)
        fresh_plan = build_dry_run(
            fresh_census.catalog, policy,
            now=now,
            census_complete=fresh_census.census_complete,
        )
        selected_ids = {c.run_id for c in fresh_plan.candidates}
        if run_path.name not in selected_ids:
            return False

    return True


def execute_gc(
    runs_root: Path,
    policy: RetentionPolicy,
    *,
    dry_run: bool = True,
    project_root: Path | None = None,
    now: datetime | None = None,
) -> GCResult:
    if now is None:
        now = datetime.now(tz=UTC)
    census_result = build_catalog(runs_root, project_root=project_root)
    catalog = census_result.catalog
    census_complete = census_result.census_complete
    plan = build_dry_run(
        catalog, policy, now=now, census_complete=census_complete
    )
    receipts: list[DeletionReceipt] = []

    for candidate in plan.candidates:
        run_path = Path(candidate.path)
        trigger_val = candidate.deletion_trigger.value
        if dry_run:
            receipts.append(
                make_receipt(
                    run_id=candidate.run_id,
                    path=candidate.path,
                    size_bytes_before=candidate.size_bytes,
                    classification=candidate.classification.value,
                    reason=candidate.reason,
                    policy_ttl_days=policy.ttl_days,
                    policy_max_total_bytes=policy.max_total_bytes,
                    delete_result="DRY_RUN",
                    deletion_trigger=trigger_val,
                )
            )
        else:
            still_eligible = _revalidate_candidate(
                run_path,
                project_root=project_root,
                policy=policy,
                now=now,
                original_trigger=candidate.deletion_trigger,
            )
            if not still_eligible:
                receipts.append(
                    make_receipt(
                        run_id=candidate.run_id,
                        path=candidate.path,
                        size_bytes_before=candidate.size_bytes,
                        classification=candidate.classification.value,
                        reason="revalidation_failed: state_changed",
                        policy_ttl_days=policy.ttl_days,
                        policy_max_total_bytes=policy.max_total_bytes,
                        delete_result="SKIPPED_REVALIDATION_CHANGED",
                        deletion_trigger=trigger_val,
                    )
                )
                continue
            try:
                if run_path.exists() and run_path.is_dir():
                    shutil.rmtree(run_path)
                    receipts.append(
                        make_receipt(
                            run_id=candidate.run_id,
                            path=candidate.path,
                            size_bytes_before=candidate.size_bytes,
                            classification=candidate.classification.value,
                            reason=candidate.reason,
                            policy_ttl_days=policy.ttl_days,
                            policy_max_total_bytes=policy.max_total_bytes,
                            delete_result="DELETED",
                            deletion_trigger=trigger_val,
                        )
                    )
                else:
                    receipts.append(
                        make_receipt(
                            run_id=candidate.run_id,
                            path=candidate.path,
                            size_bytes_before=candidate.size_bytes,
                            classification=candidate.classification.value,
                            reason=candidate.reason,
                            policy_ttl_days=policy.ttl_days,
                            policy_max_total_bytes=policy.max_total_bytes,
                            delete_result="DELETE_FAILED",
                            deletion_trigger=trigger_val,
                        )
                    )
            except OSError:
                receipts.append(
                    make_receipt(
                        run_id=candidate.run_id,
                        path=candidate.path,
                        size_bytes_before=candidate.size_bytes,
                        classification=candidate.classification.value,
                        reason=candidate.reason,
                        policy_ttl_days=policy.ttl_days,
                        policy_max_total_bytes=policy.max_total_bytes,
                        delete_result="DELETE_FAILED",
                        deletion_trigger=trigger_val,
                    )
                )

    all_classified = classify_runs(list(catalog.runs), policy, now=now)
    already_handled = {r.run_id for r in receipts}
    selected_ids = {c.run_id for c in plan.candidates}
    for classification in all_classified:
        if classification.run_id in already_handled:
            continue
        if classification.classification == DeletionClass.PROTECTED:
            receipts.append(
                make_receipt(
                    run_id=classification.run_id,
                    path=classification.path,
                    size_bytes_before=classification.size_bytes,
                    classification=classification.classification.value,
                    reason=classification.reason,
                    policy_ttl_days=policy.ttl_days,
                    policy_max_total_bytes=policy.max_total_bytes,
                    delete_result="SKIPPED_PROTECTED",
                    deletion_trigger="NONE",
                )
            )
        elif classification.classification == DeletionClass.KEEP:
            # Determine accurate skip reason based on actual state
            ref = classification.reference_state
            protection_tokens = {
                t.strip() for t in classification.protection_state.split(";")
            } if classification.protection_state else set()
            nonterminal_tokens = {
                "status=ACTIVE", "status=RUNNING", "status=INCOMPLETE",
            }
            is_nonterminal = bool(protection_tokens & nonterminal_tokens)
            if is_nonterminal:
                # ACTIVE/RUNNING/INCOMPLETE — not terminal, cannot be GC'd
                skip_result = "SKIPPED_PROTECTED"
            elif ref == "REFERENCED":
                skip_result = "SKIPPED_REFERENCED"
            elif (
                classification.safe_eligible
                and not classification.ttl_expired
                and classification.run_id not in selected_ids
            ):
                # Safe but not selected (TTL not expired, quota didn't pick it)
                skip_result = "SKIPPED_RETAINED"
            elif ref == "UNKNOWN":
                skip_result = "SKIPPED_UNKNOWN"
            else:
                skip_result = "SKIPPED_UNKNOWN"
            receipts.append(
                make_receipt(
                    run_id=classification.run_id,
                    path=classification.path,
                    size_bytes_before=classification.size_bytes,
                    classification=classification.classification.value,
                    reason=classification.reason,
                    policy_ttl_days=policy.ttl_days,
                    policy_max_total_bytes=policy.max_total_bytes,
                    delete_result=skip_result,
                    deletion_trigger="NONE",
                )
            )

    return GCResult(plan=plan, receipts=tuple(receipts))
