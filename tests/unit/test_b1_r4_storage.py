"""R4 owner negative matrix tests — pure QUOTA apply and evidence closure."""
from __future__ import annotations

import os
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

from synapx_harness.storage.classifier import DeletionClass, DeletionTrigger
from synapx_harness.storage.gc import (
    _revalidate_candidate,
    build_dry_run,
    execute_gc,
)
from synapx_harness.storage.policy import RetentionPolicy


def _make_project_root(tmp_path: Path) -> Path:
    p = tmp_path / "project"
    p.mkdir()
    (p / "_tracks").mkdir()
    (p / "review").mkdir()
    (p / "evidence").mkdir()
    return p


def _mk(runs_root: Path, name: str, *, days_old: int, extra: int = 0) -> Path:
    r = runs_root / name
    r.mkdir()
    (r / "final_close_result.json").write_text("{}")
    t = time.time() - days_old * 86400
    os.utime(r, (t, t))
    if extra > 0:
        (r / "payload.bin").write_bytes(b"x" * extra)
    return r


class TestR4N01:
    def test_pure_quota_plan(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "q1", days_old=10, extra=3000)
        _mk(rr, "q2", days_old=10, extra=3000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        from synapx_harness.storage.census import build_catalog
        c = build_catalog(rr, project_root=pr)
        plan = build_dry_run(
            c.catalog, pol,
            now=datetime.now(tz=UTC),
            census_complete=c.census_complete,
        )
        assert plan.quota_pressure
        assert plan.gc_candidates >= 1
        for x in plan.candidates:
            assert x.classification == DeletionClass.GC_CANDIDATE
            assert x.deletion_trigger in (DeletionTrigger.QUOTA, DeletionTrigger.TTL_AND_QUOTA)


class TestR4N02:
    def test_pure_quota_actual_delete(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "dq", days_old=10, extra=3000)
        _mk(rr, "do", days_old=10, extra=3000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        res = execute_gc(rr, pol, dry_run=False, project_root=pr)
        dl = [r for r in res.receipts if r.delete_result == "DELETED"]
        assert len(dl) >= 1


class TestR4N03:
    def test_deleted_receipt_has_trigger(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "rt", days_old=10, extra=3000)
        _mk(rr, "ro", days_old=10, extra=3000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        res = execute_gc(rr, pol, dry_run=False, project_root=pr)
        dl = [r for r in res.receipts if r.delete_result == "DELETED"]
        assert len(dl) >= 1
        for rec in dl:
            assert rec.classification == DeletionClass.GC_CANDIDATE.value
            assert rec.deletion_trigger in ("QUOTA", "TTL", "TTL_AND_QUOTA")
            assert rec.deletion_trigger != "NONE"


class TestR4N04:
    def test_ttl_still_valid_deletes(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "ttlok", days_old=100)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        res = execute_gc(rr, pol, dry_run=False, project_root=pr)
        dl = [r for r in res.receipts if r.delete_result == "DELETED"]
        assert len(dl) == 1
        assert dl[0].deletion_trigger in ("TTL", "TTL_AND_QUOTA")


class TestR4N05:
    def test_ttl_activity_refresh_skips(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        rp = _mk(rr, "refresh", days_old=100)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        ft = datetime.now(tz=UTC).timestamp()
        os.utime(rp, (ft, ft))
        ok = _revalidate_candidate(rp, project_root=pr, policy=pol,
                                   now=datetime.now(tz=UTC),
                                   original_trigger=DeletionTrigger.TTL)
        assert not ok


class TestR4N06:
    def test_quota_resolved_skips(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        r1 = _mk(rr, "qr1", days_old=10, extra=3000)
        r2 = _mk(rr, "qr2", days_old=10, extra=3000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        shutil.rmtree(r1)
        ok = _revalidate_candidate(r2, project_root=pr, policy=pol,
                                   now=datetime.now(tz=UTC),
                                   original_trigger=DeletionTrigger.QUOTA)
        assert not ok


class TestR4N07:
    def test_candidate_change_skips(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        ra = _mk(rr, "ao", days_old=10, extra=2000)
        _mk(rr, "bm", days_old=10, extra=2000)
        _mk(rr, "cn", days_old=10, extra=2000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        (ra / ".protected").write_text("")
        ok = _revalidate_candidate(ra, project_root=pr, policy=pol,
                                   now=datetime.now(tz=UTC),
                                   original_trigger=DeletionTrigger.QUOTA)
        assert not ok


class TestR4N08:
    def test_diagnostic_mutex(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "young", days_old=10, extra=1000)
        _mk(rr, "old", days_old=100, extra=4000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        from synapx_harness.storage.census import build_catalog
        c = build_catalog(rr, project_root=pr)
        plan = build_dry_run(
            c.catalog, pol,
            now=datetime.now(tz=UTC),
            census_complete=c.census_complete,
        )
        total = plan.protected_runs + plan.unknown_runs + plan.retained_runs + plan.gc_candidates
        assert total == plan.total_runs


class TestR4N09:
    def test_diagnostic_sum(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "s1", days_old=10, extra=1000)
        _mk(rr, "s2", days_old=100, extra=4000)
        rp = _mk(rr, "sp", days_old=50)
        (rp / ".protected").write_text("")
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        from synapx_harness.storage.census import build_catalog
        c = build_catalog(rr, project_root=pr)
        plan = build_dry_run(
            c.catalog, pol,
            now=datetime.now(tz=UTC),
            census_complete=c.census_complete,
        )
        total = plan.protected_runs + plan.unknown_runs + plan.retained_runs + plan.gc_candidates
        assert total == plan.total_runs


class TestR4N10:
    def test_census_incomplete_no_delete(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        _mk(rr, "ice2", days_old=100)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        res = execute_gc(rr, pol, dry_run=False)
        dl = [r for r in res.receipts if r.delete_result == "DELETED"]
        assert len(dl) == 0


class TestR4N11:
    def test_dry_run_no_filesystem_mutation(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "inv1", days_old=10, extra=1000)
        _mk(rr, "inv2", days_old=100, extra=4000)
        before = sorted(x.name for x in rr.iterdir())
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        from synapx_harness.storage.census import build_catalog
        c = build_catalog(rr, project_root=pr)
        build_dry_run(c.catalog, pol, now=datetime.now(tz=UTC), census_complete=c.census_complete)
        after = sorted(x.name for x in rr.iterdir())
        assert before == after


class TestR4N12:
    def test_deleted_must_have_gc_candidate_and_trigger(self, tmp_path: Path) -> None:
        rr = tmp_path / "_runs"
        rr.mkdir()
        pr = _make_project_root(tmp_path)
        _mk(rr, "v1", days_old=10, extra=3000)
        _mk(rr, "v2", days_old=10, extra=3000)
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        res = execute_gc(rr, pol, dry_run=False, project_root=pr)
        for rec in res.receipts:
            if rec.delete_result == "DELETED":
                assert rec.classification == "GC_CANDIDATE"
                assert rec.deletion_trigger != "NONE"
