"""RED tests for B1-R1 storage hardening repair."""
from __future__ import annotations

import pathlib
import time
from datetime import UTC, datetime, timedelta
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
from synapx_harness.storage.gc import build_dry_run, execute_gc
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
    days_old: int = 100,
) -> RunMetadata:
    now = datetime.now(tz=UTC)
    last_activity = (now - timedelta(days=days_old)).isoformat()
    return RunMetadata(
        run_id=run_id,
        path=f"/fake/_runs/{run_id}",
        size_bytes=size_bytes,
        status=status,
        created_at=last_activity,
        last_known_activity_at=last_activity,
        pinned=pinned,
        protected=protected,
        reference_state=reference_state,
        has_sealed_evidence=has_sealed_evidence,
        has_review_package=has_review_package,
        has_authority_reference=has_authority_reference,
    )


def _make_project_root(tmp_path: Path) -> Path:
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "_tracks").mkdir()
    (project_root / "review").mkdir()
    (project_root / "evidence").mkdir()
    return project_root


class TestREDB1R1N01:
    def test_census_no_mutation(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "RUN-1"
        r.mkdir()
        (r / "data.bin").write_bytes(b"x" * 100)
        before = list(runs_root.rglob("*"))
        _ = build_catalog(runs_root)
        after = list(runs_root.rglob("*"))
        assert len(before) == len(after)


class TestREDB1R1N02:
    def test_gc_without_apply_no_mutation(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "RUN-1"
        r.mkdir()
        (r / "data.bin").write_bytes(b"x" * 100)
        policy = RetentionPolicy(ttl_days=90)
        _ = execute_gc(runs_root, policy, dry_run=True)
        assert r.exists()


class TestREDB1R1N03:
    def test_gc_apply_deletes(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)
        r = runs_root / "OLD-RUN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        time.sleep(0.15)
        policy = RetentionPolicy(ttl_days=0)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=False, project_root=project_root, now=now)
        deleted = [rx for rx in result.receipts if rx.delete_result == "DELETED"]
        assert len(deleted) >= 1


class TestREDB1R1N04:
    def test_ttl_blocks_recent_run(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            reference_state=ReferenceState.UNREFERENCED,
            days_old=10,
        )
        policy = RetentionPolicy(ttl_days=90)
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.KEEP


class TestREDB1R1N05:
    def test_ttl_expired_makes_candidate(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            reference_state=ReferenceState.UNREFERENCED,
            days_old=100,
        )
        policy = RetentionPolicy(ttl_days=90)
        now = datetime.now(tz=UTC)
        result = classify_run(run, policy, now=now)
        assert result.classification == DeletionClass.GC_CANDIDATE


class TestREDB1R1N06:
    def test_no_pressure_no_candidates(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "NEW-RUN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        policy = RetentionPolicy(ttl_days=90, max_total_bytes=10 * 1024 * 1024)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=True, now=now)
        assert result.plan.gc_candidates == 0


class TestREDB1R1N07:
    def test_quota_selects_candidates(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        for name in ["RUN-A", "RUN-B", "RUN-C"]:
            r = runs_root / name
            r.mkdir()
            (r / "final_close_result.json").write_text("{}")
        policy = RetentionPolicy(ttl_days=0, max_total_bytes=1)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=True, now=now)
        assert result.plan.quota_pressure is True


class TestREDB1R1N08:
    def test_protected_not_deleted_for_quota(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        protected = runs_root / "PROTECTED-RUN"
        protected.mkdir()
        (protected / "final_close_result.json").write_text("{}")
        (protected / "seal_result.json").write_text("{}")
        policy = RetentionPolicy(ttl_days=0, max_total_bytes=1)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=True, now=now)
        protected_skipped = [
            r for r in result.receipts
            if r.run_id == "PROTECTED-RUN" and r.delete_result == "SKIPPED_PROTECTED"
        ]
        assert len(protected_skipped) >= 1


class TestREDB1R1N09:
    def test_deterministic_plan(self, tmp_path: Path) -> None:
        for idx in range(2):
            root = tmp_path / f"runs_{idx}"
            root.mkdir()
            for name in ["RUN-A", "RUN-B"]:
                r = root / name
                r.mkdir()
                (r / "final_close_result.json").write_text("{}")
        policy = RetentionPolicy(ttl_days=0)
        fixed_now = datetime(2026, 1, 1, tzinfo=UTC)
        cat1 = build_catalog(tmp_path / "runs_0")
        cat2 = build_catalog(tmp_path / "runs_1")
        p1 = build_dry_run(cat1.catalog, policy, now=fixed_now)
        p2 = build_dry_run(cat2.catalog, policy, now=fixed_now)
        assert p1.to_dict() == p2.to_dict()


class TestREDB1R1N10:
    def test_worker_report_not_complete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "WORKER-ONLY"
        r.mkdir()
        (r / "worker_report.json").write_text("{}")
        policy = RetentionPolicy(ttl_days=0)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=True, now=now)
        assert result.plan.gc_candidates == 0


class TestREDB1R1N11:
    def test_running_signal_overrides(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "RUNNING-RUN"
        r.mkdir()
        (r / "worker_report.json").write_text("{}")
        (r / "running_flag.txt").write_text("running")
        policy = RetentionPolicy(ttl_days=0)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=True, now=now)
        assert result.plan.gc_candidates == 0


class TestREDB1R1N12:
    def test_missing_scan_roots_gives_unknown(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "SCAN-MISSING"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        project_root = tmp_path / "project"
        project_root.mkdir()
        census_result = build_catalog(runs_root, project_root=project_root)
        assert census_result.catalog.runs[0].reference_state == ReferenceState.UNKNOWN


class TestREDB1R1N13:
    def test_no_project_root_gives_unknown(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "NO-ROOT"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        census_result = build_catalog(runs_root, project_root=None)
        assert census_result.catalog.runs[0].reference_state == ReferenceState.UNKNOWN


class TestREDB1R1N14:
    def test_skip_ref_scan_gives_unknown(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "SKIP-SCAN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        _ = _make_project_root(tmp_path)
        census_result = build_catalog(runs_root, project_root=None)
        assert census_result.catalog.runs[0].reference_state == ReferenceState.UNKNOWN


class TestREDB1R1N15:
    def test_revalidation_prevents_stale_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)
        r = runs_root / "STALE-RUN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        time.sleep(0.15)
        policy = RetentionPolicy(ttl_days=0)
        now = datetime.now(tz=UTC)
        result = execute_gc(runs_root, policy, dry_run=True, project_root=project_root, now=now)
        assert result.plan.gc_candidates >= 1
        (r / ".pinned").write_text("true")
        result2 = execute_gc(runs_root, policy, dry_run=False, project_root=project_root, now=now)
        deleted = [rx for rx in result2.receipts if rx.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestREDB1R1N16:
    def test_protected_before_delete_prevents(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "PROTECT-BEFORE"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        policy = RetentionPolicy(ttl_days=0)
        now = datetime.now(tz=UTC)
        (r / ".protected").write_text("true")
        result = execute_gc(runs_root, policy, dry_run=False, now=now)
        deleted = [rx for rx in result.receipts if rx.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestREDB1R1N17:
    def test_delete_failure_receipt(self, tmp_path: Path) -> None:
        from synapx_harness.storage.receipts import make_receipt
        receipt = make_receipt(
            run_id="FAIL-RUN",
            path=str(tmp_path / "nonexistent"),
            size_bytes_before=0,
            classification="GC_CANDIDATE",
            reason="test",
            policy_ttl_days=90,
            policy_max_total_bytes=5000000000,
            delete_result="DELETE_FAILED",
        )
        assert receipt.delete_result == "DELETE_FAILED"
        assert receipt.delete_result != "DELETED"


class TestREDB1R1N18:
    def test_dry_run_inventory_unchanged(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "INV-RUN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        before_size = sum(f.stat().st_size for f in runs_root.rglob("*") if f.is_file())
        policy = RetentionPolicy(ttl_days=0)
        now = datetime.now(tz=UTC)
        execute_gc(runs_root, policy, dry_run=True, now=now)
        after_size = sum(f.stat().st_size for f in runs_root.rglob("*") if f.is_file())
        assert before_size == after_size


class TestREDB1R1N19:
    def test_sealed_evidence_blocks_deletion(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            has_sealed_evidence=True,
            reference_state=ReferenceState.UNREFERENCED,
            days_old=200,
        )
        policy = RetentionPolicy(ttl_days=0)
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.PROTECTED


class TestREDB1R1N20:
    def test_dry_run_no_mutation_portable(self, tmp_path: pathlib.Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        # Create a terminal run
        r = runs_root / "test-run-001"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")

        before_count = sum(1 for _ in runs_root.iterdir())
        policy = RetentionPolicy(ttl_days=90)
        _ = execute_gc(runs_root, policy, dry_run=True)
        after_count = sum(1 for _ in runs_root.iterdir())
        assert before_count == after_count
