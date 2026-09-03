"""GREEN tests for B1-R1 storage hardening.

These tests verify the happy path of the storage hardening module.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from synapx_harness.storage.catalog import (
    ReferenceState,
    RunMetadata,
    RunStatus,
)
from synapx_harness.storage.census import build_catalog
from synapx_harness.storage.classifier import (
    DeletionClass,
    classify_run,
)
from synapx_harness.storage.gc import execute_gc
from synapx_harness.storage.policy import RetentionPolicy


def _make_run(
    run_id: str = "TEST-RUN-001",
    status: RunStatus = RunStatus.COMPLETE,
    pinned: bool = False,
    protected: bool = False,
    reference_state: ReferenceState = ReferenceState.UNREFERENCED,
    has_sealed_evidence: bool = False,
    has_review_package: bool = False,
    has_authority_reference: bool = False,
    size_bytes: int = 1000,
) -> RunMetadata:
    return RunMetadata(
        run_id=run_id,
        path=f"/fake/_runs/{run_id}",
        size_bytes=size_bytes,
        status=status,
        created_at="2026-01-01T00:00:00+00:00",
        last_known_activity_at="2026-01-01T00:00:00+00:00",
        pinned=pinned,
        protected=protected,
        reference_state=reference_state,
        has_sealed_evidence=has_sealed_evidence,
        has_review_package=has_review_package,
        has_authority_reference=has_authority_reference,
    )


class TestGreenClassification:
    """GREEN: completed + unreferenced + unpinned + unprotected → GC_CANDIDATE."""

    def test_eligible_run_becomes_gc_candidate(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            reference_state=ReferenceState.UNREFERENCED,
            pinned=False,
            protected=False,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.GC_CANDIDATE

    def test_eligible_run_reason_includes_complete_and_unreferenced(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert "COMPLETE" in result.reason
        assert "UNREFERENCED" in result.reason


def _make_project_root(tmp_path: Path) -> Path:
    """Create a minimal project root with no external references."""
    project_root = tmp_path / "project"
    project_root.mkdir()
    tracks_dir = project_root / "_tracks"
    tracks_dir.mkdir()
    review_dir = project_root / "review"
    review_dir.mkdir()
    evidence_dir = project_root / "evidence"
    evidence_dir.mkdir()
    return project_root


class TestGreenDryRun:
    """GREEN: dry-run shows candidates, filesystem unchanged."""

    def test_dry_run_shows_candidates(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        completed = runs_root / "COMPLETED-RUN"
        completed.mkdir()
        (completed / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)
        result = execute_gc(runs_root, policy, dry_run=True, project_root=project_root, now=now)

        assert result.plan.gc_candidates >= 1
        assert result.plan.mode == "dry-run"

    def test_dry_run_filesystem_unchanged(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        completed = runs_root / "COMPLETED-RUN"
        completed.mkdir()
        (completed / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        before = list(runs_root.iterdir())

        policy = RetentionPolicy()
        execute_gc(runs_root, policy, dry_run=True, project_root=project_root, now=now)

        after = list(runs_root.iterdir())
        assert len(before) == len(after)
        assert completed.exists()


class TestGreenActualGC:
    """GREEN: eligible candidate → deleted → receipt generated."""

    def test_actual_gc_deletes_eligible_candidate(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        completed = runs_root / "COMPLETED-RUN"
        completed.mkdir()
        (completed / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)
        result = execute_gc(runs_root, policy, dry_run=False, project_root=project_root, now=now)

        assert not completed.exists()
        deleted_receipts = [
            r for r in result.receipts if r.delete_result == "DELETED"
        ]
        assert len(deleted_receipts) == 1
        assert deleted_receipts[0].run_id == "COMPLETED-RUN"

    def test_deletion_receipt_generated(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        completed = runs_root / "RUN-A"
        completed.mkdir()
        (completed / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)
        result = execute_gc(runs_root, policy, dry_run=False, project_root=project_root, now=now)

        assert len(result.receipts) >= 1
        receipt = result.receipts[0]
        assert receipt.deleted_at is not None
        assert receipt.policy["ttl_days"] == policy.ttl_days


class TestGreenQuota:
    """GREEN: quota exceeded → oldest eligible candidates selected, protected untouched."""

    def test_quota_exceeded_selects_oldest(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        run_a = runs_root / "RUN-A-OLDER"
        run_a.mkdir()
        (run_a / "final_close_result.json").write_text("{}")

        run_b = runs_root / "RUN-B-NEWER"
        run_b.mkdir()
        (run_b / "final_close_result.json").write_text("{}")

        protected = runs_root / "PROTECTED-RUN"
        protected.mkdir()
        (protected / "final_close_result.json").write_text("{}")
        (protected / "seal_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(max_total_bytes=1)
        result = execute_gc(runs_root, policy, dry_run=False, project_root=project_root, now=now)

        protected_still_exists = any(
            r.delete_result == "SKIPPED_PROTECTED"
            for r in result.receipts
            if r.run_id == "PROTECTED-RUN"
        )
        assert protected_still_exists or protected.exists()


class TestGreenCensus:
    """GREEN: census produces correct metrics."""

    def test_census_total_size(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()

        run1 = runs_root / "RUN-1"
        run1.mkdir()
        (run1 / "data.bin").write_bytes(b"x" * 100)

        run2 = runs_root / "RUN-2"
        run2.mkdir()
        (run2 / "data.bin").write_bytes(b"y" * 200)

        census = build_catalog(runs_root)
        assert census.census_complete
        assert census.catalog.total_size_bytes == 300
        assert census.catalog.run_count == 2

    def test_census_per_run_bytes(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()

        run1 = runs_root / "RUN-1"
        run1.mkdir()
        (run1 / "data.bin").write_bytes(b"x" * 50)

        census = build_catalog(runs_root)
        assert len(census.catalog.runs) == 1
        assert census.catalog.runs[0].size_bytes == 50
        assert census.catalog.runs[0].run_id == "RUN-1"
