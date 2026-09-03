"""R2 owner negative matrix tests for B1 storage hardening.

Tests P0-01 (external ref revalidation), P0-02 (oldest-first ordering),
P0-03 (TTL/quota separation), P1-01 (census completeness).
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from synapx_harness.storage.catalog import (
    ReferenceState,
)
from synapx_harness.storage.census import build_catalog
from synapx_harness.storage.classifier import (
    DeletionClass,
)
from synapx_harness.storage.gc import (
    _sort_candidates,
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


def _set_run_age(run_path: Path, days_old: int) -> None:
    """Set a run directory's mtime to days_old days in the past."""
    import os
    past = datetime.now(tz=UTC) - timedelta(days=days_old)
    ts = past.timestamp()
    os.utime(run_path, (ts, ts))


class TestR2N01:
    """candidate selected → external review ref created → run remains."""

    def test_external_review_ref_prevents_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        _create_terminal_run(runs_root, "OLD-RUN", days_old=200)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)

        result1 = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result1.plan.gc_candidates >= 1

        ref_file = project_root / "review" / "new_ref.md"
        ref_file.write_text("reference to OLD-RUN")

        result2 = execute_gc(
            runs_root, policy, dry_run=False,
            project_root=project_root, now=now,
        )
        deleted = [r for r in result2.receipts if r.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestR2N02:
    """candidate selected → external authority ref created → run remains."""

    def test_external_authority_ref_prevents_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        _create_terminal_run(runs_root, "OLD-RUN", days_old=200)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)

        result1 = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result1.plan.gc_candidates >= 1

        ref_file = project_root / "_tracks" / "authority.json"
        ref_file.write_text('{"run_id": "OLD-RUN"}')

        result2 = execute_gc(
            runs_root, policy, dry_run=False,
            project_root=project_root, now=now,
        )
        deleted = [r for r in result2.receipts if r.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestR2N03:
    """reference scan becomes incomplete before delete → UNKNOWN → KEEP."""

    def test_incomplete_scan_prevents_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        _create_terminal_run(runs_root, "OLD-RUN", days_old=200)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)

        result1 = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result1.plan.gc_candidates >= 1

        import shutil
        shutil.rmtree(project_root / "review")

        result2 = execute_gc(
            runs_root, policy, dry_run=False,
            project_root=project_root, now=now,
        )
        deleted = [r for r in result2.receipts if r.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestR2N04:
    """Z-OLD older than A-NEW → quota needs one deletion → selected Z-OLD."""

    def test_oldest_first_quota_ordering(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        z_old = _create_terminal_run(runs_root, "Z-OLD", days_old=200)
        (z_old / "data.bin").write_bytes(b"x" * 100)
        _set_run_age(z_old, 200)

        a_new = _create_terminal_run(runs_root, "A-NEW", days_old=100)
        (a_new / "data.bin").write_bytes(b"y" * 100)
        _set_run_age(a_new, 100)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0, max_total_bytes=100)

        result = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result.plan.gc_candidates >= 1
        assert result.plan.candidates[0].run_id == "Z-OLD"


class TestR2N05:
    """same eligible_timestamp → run_id lexicographic tie-break."""

    def test_same_timestamp_tie_break_by_run_id(self) -> None:
        from synapx_harness.storage.classifier import ClassificationResult

        ts = "2026-01-01T00:00:00+00:00"
        results = [
            ClassificationResult(
                run_id="RUN-C", path="/fake/C", size_bytes=100,
                classification=DeletionClass.GC_CANDIDATE,
                reason="test", retention_basis="ttl_days=0",
                reference_state="UNREFERENCED", protection_state="none",
                eligible_timestamp=ts, ttl_expired=True, safe_eligible=True,
            ),
            ClassificationResult(
                run_id="RUN-A", path="/fake/A", size_bytes=100,
                classification=DeletionClass.GC_CANDIDATE,
                reason="test", retention_basis="ttl_days=0",
                reference_state="UNREFERENCED", protection_state="none",
                eligible_timestamp=ts, ttl_expired=True, safe_eligible=True,
            ),
            ClassificationResult(
                run_id="RUN-B", path="/fake/B", size_bytes=100,
                classification=DeletionClass.GC_CANDIDATE,
                reason="test", retention_basis="ttl_days=0",
                reference_state="UNREFERENCED", protection_state="none",
                eligible_timestamp=ts, ttl_expired=True, safe_eligible=True,
            ),
        ]
        sorted_candidates = _sort_candidates(results)
        ids = [c.run_id for c in sorted_candidates]
        assert ids == ["RUN-A", "RUN-B", "RUN-C"]


class TestR2N06:
    """quota not exceeded + TTL not expired → 0 candidate."""

    def test_no_pressure_no_ttl_no_candidates(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        r = runs_root / "YOUNG-RUN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=90, max_total_bytes=10 * 1024 * 1024)

        result = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result.plan.gc_candidates == 0
        assert result.plan.quota_pressure is False


class TestR2N07:
    """quota exceeded + TTL not expired + safe runs exist → oldest safe selected."""

    def test_quota_pressure_selects_safe_run(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        z_old = _create_terminal_run(runs_root, "Z-OLD", days_old=200)
        (z_old / "data.bin").write_bytes(b"x" * 100)
        _set_run_age(z_old, 200)

        a_new = _create_terminal_run(runs_root, "A-NEW", days_old=100)
        (a_new / "data.bin").write_bytes(b"y" * 100)
        _set_run_age(a_new, 100)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=90, max_total_bytes=100)

        result = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result.plan.quota_pressure is True
        assert result.plan.gc_candidates >= 1
        assert result.plan.candidates[0].run_id == "Z-OLD"


class TestR2N08:
    """quota exceeded + only protected/UNKNOWN → deletion 0, quota_unresolved > 0."""

    def test_quota_pressure_no_safe_runs(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()

        r1 = runs_root / "PROTECTED-RUN"
        r1.mkdir()
        (r1 / "final_close_result.json").write_text("{}")
        (r1 / "seal_result.json").write_text("{}")

        r2 = runs_root / "UNKNOWN-RUN"
        r2.mkdir()
        (r2 / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0, max_total_bytes=1)

        result = execute_gc(
            runs_root, policy, dry_run=True, now=now,
        )
        assert result.plan.quota_pressure is True
        assert result.plan.gc_candidates == 0
        assert result.plan.quota_unresolved_bytes > 0


class TestR2N09:
    """missing required reference dirs → census_complete=false, reference UNKNOWN."""

    def test_missing_ref_dirs_incomplete_census(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = tmp_path / "project"
        project_root.mkdir()

        _create_terminal_run(runs_root, "OLD-RUN", days_old=200)

        census = build_catalog(runs_root, project_root=project_root)
        assert census.census_complete is False
        assert census.catalog.runs[0].reference_state == ReferenceState.UNKNOWN


class TestR2N10:
    """same catalog + same policy + same now → exact selected IDs/order identical."""

    def test_deterministic_plan(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        for name in ["RUN-A", "RUN-B", "RUN-C"]:
            _create_terminal_run(runs_root, name, days_old=100)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)

        result1 = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        result2 = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        ids1 = [c.run_id for c in result1.plan.candidates]
        ids2 = [c.run_id for c in result2.plan.candidates]
        assert ids1 == ids2
        assert result1.plan.to_dict() == result2.plan.to_dict()


class TestR2N11:
    """actual GC revalidation → no-longer-eligible run remains."""

    def test_revalidation_prevents_stale_delete(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        r = runs_root / "STALE-RUN"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)

        result1 = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        assert result1.plan.gc_candidates >= 1

        (r / ".pinned").write_text("true")

        result2 = execute_gc(
            runs_root, policy, dry_run=False,
            project_root=project_root, now=now,
        )
        deleted = [rx for rx in result2.receipts if rx.delete_result == "DELETED"]
        assert len(deleted) == 0


class TestR2N12:
    """dry-run and apply candidate policy equivalent except revalidation changes."""

    def test_dry_run_apply_equivalence(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        project_root = _make_project_root(tmp_path)

        _create_terminal_run(runs_root, "RUN-A", days_old=100)
        _create_terminal_run(runs_root, "RUN-B", days_old=200)

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy(ttl_days=0)

        result_dry = execute_gc(
            runs_root, policy, dry_run=True,
            project_root=project_root, now=now,
        )
        result_apply = execute_gc(
            runs_root, policy, dry_run=False,
            project_root=project_root, now=now,
        )

        dry_ids = [c.run_id for c in result_dry.plan.candidates]
        apply_ids = [
            r.run_id for r in result_apply.receipts
            if r.delete_result == "DELETED"
        ]
        assert dry_ids == apply_ids
