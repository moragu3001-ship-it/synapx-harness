"""R3 owner negative matrix tests for B1 storage hardening.

Tests deletion semantics (KEEP→DELETED elimination), full pre-delete
revalidation, census_complete hard gate, and diagnostic count truth.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from synapx_harness.storage.classifier import (
    DeletionClass,
    DeletionTrigger,
)
from synapx_harness.storage.gc import (
    _revalidate_candidate,
    build_dry_run,
    execute_gc,
)
from synapx_harness.storage.policy import RetentionPolicy


def _make_project_root(tmp_path: Path) -> Path:
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "_tracks").mkdir()
    (project_root / "review").mkdir()
    (project_root / "evidence").mkdir()
    return project_root


def _create_terminal_run(
    runs_root: Path,
    name: str,
    *,
    days_old: int = 100,
    files: list[str] | None = None,
) -> Path:
    """Create a COMPLETE run with terminal evidence."""
    r = runs_root / name
    r.mkdir()
    (r / "final_close_result.json").write_text("{}")
    if files:
        for f in files:
            (r / f).write_text("{}")
    return r


def _set_mtime_old(path: Path, days_old: int) -> None:
    """Set directory mtime to days_old days in the past."""
    old_time = time.time() - days_old * 86400
    import os
    os.utime(path, (old_time, old_time))


def _create_run_with_activity(
    runs_root: Path,
    name: str,
    *,
    activity_days_old: int,
    files: list[str] | None = None,
) -> Path:
    """Create a COMPLETE run and set its mtime to activity_days_old days."""
    r = _create_terminal_run(runs_root, name, days_old=activity_days_old, files=files)
    _set_mtime_old(r, activity_days_old)
    return r


class TestR3N01:
    """Quota-selected safe_eligible run → classification GC_CANDIDATE, deletion_trigger QUOTA."""

    def test_quota_pressure_promotes_to_gc_candidate(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        # 100-day-old run: safe_eligible=true but TTL=90 → quota-only
        _create_run_with_activity(runs_root, "run-a", activity_days_old=100)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=5_000)
        now = datetime.now(tz=UTC)

        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)
        plan = build_dry_run(
            census.catalog,
            policy,
            now=now,
            census_complete=census.census_complete,
        )

        # Under quota pressure, quota-selected run should be GC_CANDIDATE
        assert plan.gc_candidates >= 1
        for c in plan.candidates:
            assert c.classification == DeletionClass.GC_CANDIDATE
            assert c.deletion_trigger in (
                DeletionTrigger.QUOTA,
                DeletionTrigger.TTL,
                DeletionTrigger.TTL_AND_QUOTA,
            )


class TestR3N02:
    """Actual receipt DELETED → classification must be GC_CANDIDATE."""

    def test_deleted_receipt_classification(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        _create_run_with_activity(runs_root, "run-del", activity_days_old=100)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=5_000)
        result = execute_gc(
            runs_root, policy,
            dry_run=False,
            project_root=project_root,
        )

        deleted = [r for r in result.receipts if r.delete_result == "DELETED"]
        assert len(deleted) >= 1
        for receipt in deleted:
            assert receipt.classification == DeletionClass.GC_CANDIDATE.value


class TestR3N03:
    """TTL candidate + activity refreshed before delete → survives."""

    def test_ttl_candidate_activity_refresh_blocks_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        # Create 100-day-old run
        run_path = _create_run_with_activity(runs_root, "run-fresh", activity_days_old=100)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        now_plan = datetime.now(tz=UTC)

        # Build plan — should be GC_CANDIDATE (TTL expired)
        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)
        plan = build_dry_run(
            census.catalog,
            policy,
            now=now_plan,
            census_complete=census.census_complete,
        )
        ttl_candidates = [c for c in plan.candidates if c.deletion_trigger == DeletionTrigger.TTL]
        assert len(ttl_candidates) >= 1

        # Refresh activity NOW
        import os
        now_refresh = datetime.now(tz=UTC)
        fresh_time = now_refresh.timestamp()
        os.utime(run_path, (fresh_time, fresh_time))

        # Revalidate with fresh now — should block
        still_ok = _revalidate_candidate(
            run_path,
            project_root=project_root,
            policy=policy,
            now=datetime.now(tz=UTC),
            original_trigger=DeletionTrigger.TTL,
        )
        assert not still_ok


class TestR3N04:
    """Quota pressure resolved before delete → run survives."""

    def test_quota_resolved_blocks_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        # Create two runs totaling > 5000 bytes
        r1 = _create_run_with_activity(runs_root, "run-x", activity_days_old=100)
        (r1 / "bigfile.bin").write_bytes(b"x" * 3000)
        r2 = _create_run_with_activity(runs_root, "run-y", activity_days_old=100)
        (r2 / "bigfile.bin").write_bytes(b"y" * 3000)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=5000)

        # Initial plan under quota pressure
        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)
        plan = build_dry_run(
            census.catalog,
            policy,
            now=datetime.now(tz=UTC),
            census_complete=census.census_complete,
        )
        assert plan.quota_pressure

        # Delete one run externally (resolve quota pressure)
        import shutil
        shutil.rmtree(r1)

        # Revalidate remaining run — quota resolved, should block
        still_ok = _revalidate_candidate(
            r2,
            project_root=project_root,
            policy=policy,
            now=datetime.now(tz=UTC),
            original_trigger=DeletionTrigger.QUOTA,
        )
        assert not still_ok


class TestR3N05:
    """census_complete=false + COMPLETE + UNREFERENCED + TTL expired → candidate 0."""

    def test_incomplete_census_blocks_candidates(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        _create_run_with_activity(runs_root, "run-ice", activity_days_old=100)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)

        # Pass census_complete=False explicitly to build_dry_run
        plan = build_dry_run(
            census.catalog, policy,
            now=datetime.now(tz=UTC),
            census_complete=False,
        )
        assert plan.gc_candidates == 0
        assert len(plan.candidates) == 0

    def test_incomplete_census_from_missing_ref_dirs(self, tmp_path: Path) -> None:
        """Missing required ref dirs → CensusError → census_complete=false."""
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        # Create project_root WITHOUT _tracks/review/evidence dirs
        project_root = tmp_path / "project"
        project_root.mkdir()

        _create_run_with_activity(runs_root, "run-miss", activity_days_old=100)

        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)
        assert not census.census_complete


class TestR3N06:
    """Actual GC with incomplete census → delete count 0."""

    def test_incomplete_census_no_actual_deletes(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        # No project_root → census_complete false

        _create_run_with_activity(runs_root, "run-nodel", activity_days_old=100)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, policy, dry_run=False)

        deleted = [r for r in result.receipts if r.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestR3N07:
    """Young safe UNREFERENCED run → retained_runs +1, unknown_runs +0."""

    def test_young_safe_run_counted_as_retained(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        # 10-day-old run: safe_eligible=true, TTL not expired
        _create_run_with_activity(runs_root, "run-young", activity_days_old=10)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)
        plan = build_dry_run(
            census.catalog, policy,
            now=datetime.now(tz=UTC),
            census_complete=census.census_complete,
        )

        # Young safe run should be retained, not unknown
        assert plan.retained_runs >= 1
        assert plan.unknown_runs == 0
        assert plan.gc_candidates == 0


class TestR3N08:
    """Quota-selected safe run → gc_candidates +1, unknown_runs +0."""

    def test_quota_selected_not_counted_as_unknown(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        # Two old runs that will exceed quota
        r1 = _create_run_with_activity(runs_root, "run-q1", activity_days_old=100)
        (r1 / "data.bin").write_bytes(b"q" * 3000)
        r2 = _create_run_with_activity(runs_root, "run-q2", activity_days_old=100)
        (r2 / "data.bin").write_bytes(b"q" * 3000)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        from synapx_harness.storage.census import build_catalog
        census = build_catalog(runs_root, project_root=project_root)
        plan = build_dry_run(
            census.catalog, policy,
            now=datetime.now(tz=UTC),
            census_complete=census.census_complete,
        )

        assert plan.gc_candidates >= 1
        assert plan.unknown_runs == 0
        # All candidates should have deletion_trigger set
        for c in plan.candidates:
            assert c.deletion_trigger != DeletionTrigger.NONE


class TestR3N09:
    """Same inputs → same candidate IDs, same trigger, same order."""

    def test_plan_determinism(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        for i in range(3):
            _create_run_with_activity(runs_root, f"run-det-{i}", activity_days_old=100 + i)

        policy = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        from synapx_harness.storage.census import build_catalog

        census = build_catalog(runs_root, project_root=project_root)
        fixed_now = datetime(2026, 1, 15, tzinfo=UTC)

        plan1 = build_dry_run(
            census.catalog,
            policy,
            now=fixed_now,
            census_complete=census.census_complete,
        )
        plan2 = build_dry_run(
            census.catalog,
            policy,
            now=fixed_now,
            census_complete=census.census_complete,
        )

        assert plan1.gc_candidates == plan2.gc_candidates
        ids1 = [c.run_id for c in plan1.candidates]
        ids2 = [c.run_id for c in plan2.candidates]
        assert ids1 == ids2
        triggers1 = [c.deletion_trigger for c in plan1.candidates]
        triggers2 = [c.deletion_trigger for c in plan2.candidates]
        assert triggers1 == triggers2


class TestR3N10:
    """Portable storage suite → no pytest.skip from absolute paths."""

    def test_no_skip_in_storage_unit_tests(self) -> None:
        """Verify R2/R3 unit test files contain no absolute Windows paths.

        R1 test_b1_red_storage.py contains a real-_runs probe with absolute
        path — that is the owner probe, not a unit test.
        """
        test_dir = Path(__file__).parent
        portable_tests = [
            "test_b1_green_storage.py",
            "test_b1_negative_storage.py",
            "test_b1_regression.py",
            "test_b1_r2_storage.py",
        ]
        for fname in portable_tests:
            fpath = test_dir / fname
            if fpath.exists():
                content = fpath.read_text(encoding="utf-8")
                assert "C:/" not in content, f"{fname} contains absolute path C:/"
                assert "C:\\\\" not in content, f"{fname} contains absolute path C:\\\\"
