"""Negative tests for B1 storage hardening.

These tests verify edge cases and error conditions.
"""
from __future__ import annotations

from pathlib import Path

import pytest

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


class TestNegativeUnknownPolicy:
    """UNKNOWN → KEEP: unknown reference state must never be deleted."""

    def test_unknown_reference_kept(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            reference_state=ReferenceState.UNKNOWN,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.KEEP
        assert result.classification != DeletionClass.GC_CANDIDATE

    def test_unknown_with_all_else_eligible_still_kept(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            reference_state=ReferenceState.UNKNOWN,
            pinned=False,
            protected=False,
            has_sealed_evidence=False,
            has_review_package=False,
            has_authority_reference=False,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.KEEP


class TestNegativeProtectionCascade:
    """Multiple protection flags should all prevent deletion."""

    def test_pinned_and_protected双重保护(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            pinned=True,
            protected=True,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.PROTECTED

    def test_sealed_evidence_overrides_complete_status(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            has_sealed_evidence=True,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.PROTECTED

    def test_authority_reference_overrides_complete_status(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            has_authority_reference=True,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.PROTECTED

    def test_review_package_overrides_complete_status(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            has_review_package=True,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy()
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.PROTECTED


class TestNegativeTTLExpiry:
    """TTL expiry alone should not cause deletion."""

    def test_ttl_zero_does_not_override_protection(self) -> None:
        run = _make_run(
            status=RunStatus.COMPLETE,
            protected=True,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy(ttl_days=0)
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.PROTECTED

    def test_ttl_expired_but_incomplete_still_kept(self) -> None:
        run = _make_run(
            status=RunStatus.INCOMPLETE,
            reference_state=ReferenceState.UNREFERENCED,
        )
        policy = RetentionPolicy(ttl_days=0)
        result = classify_run(run, policy)
        assert result.classification == DeletionClass.KEEP


class TestNegativePolicyValidation:
    """Invalid policy values should raise errors."""

    def test_negative_ttl_days(self) -> None:
        with pytest.raises(ValueError, match="ttl_days"):
            RetentionPolicy(ttl_days=-1)

    def test_negative_max_total_bytes(self) -> None:
        with pytest.raises(ValueError, match="max_total_bytes"):
            RetentionPolicy(max_total_bytes=-1)


class TestNegativeEmptyRuns:
    """Empty _runs directory should produce empty catalog."""

    def test_empty_runs_root(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        census = build_catalog(runs_root)
        assert census.catalog.run_count == 0
        assert census.catalog.total_size_bytes == 0
        assert census.census_complete

    def test_nonexistent_runs_root(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "nonexistent"
        census = build_catalog(runs_root)
        assert census.catalog.run_count == 0
        assert census.catalog.total_size_bytes == 0


class TestNegativeReceiptIntegrity:
    """Delete failure must not claim DELETED."""

    def test_receipt_for_failed_delete(self, tmp_path: Path) -> None:
        from synapx_harness.storage.receipts import make_receipt

        receipt = make_receipt(
            run_id="FAILED-RUN",
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

    def test_receipt_for_skipped_protected(self) -> None:
        from synapx_harness.storage.receipts import make_receipt

        receipt = make_receipt(
            run_id="PROTECTED-RUN",
            path="/fake/path",
            size_bytes_before=1000,
            classification="PROTECTED",
            reason="status=ACTIVE",
            policy_ttl_days=90,
            policy_max_total_bytes=5000000000,
            delete_result="SKIPPED_PROTECTED",
        )
        assert receipt.delete_result == "SKIPPED_PROTECTED"
        assert receipt.delete_result != "DELETED"


# --- R5: Skip receipt evidence truth tests ---


class TestR5SkipReceiptTruth:
    """R5-N01~N10: Skip receipts must accurately reflect actual run state."""

    def _get_skip_receipts(self, tmp_path, project_root=None):
        """Helper: create runs and execute GC, return skip receipts."""
        import os
        import time

        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        if project_root is None:
            project_root = tmp_path / "project"
            project_root.mkdir()
            (project_root / "_tracks").mkdir()
            (project_root / "review").mkdir()
            (project_root / "evidence").mkdir()

        # UNKNOWN ref run (no external refs)
        r_unk = runs_root / "run-unknown"
        r_unk.mkdir()
        (r_unk / "final_close_result.json").write_text("{}")

        # REFERENCED run (add review reference)
        r_ref = runs_root / "run-referenced"
        r_ref.mkdir()
        (r_ref / "final_close_result.json").write_text("{}")
        rev_dir = project_root / "review"
        (rev_dir / "ref_run-referenced.md").write_text("run-referenced")

        # Young safe retained run (10 days, TTL 90)
        r_ret = runs_root / "run-retained"
        r_ret.mkdir()
        (r_ret / "final_close_result.json").write_text("{}")
        t = time.time() - 10 * 86400
        os.utime(r_ret, (t, t))

        # Protected run
        r_prot = runs_root / "run-protected"
        r_prot.mkdir()
        (r_prot / "final_close_result.json").write_text("{}")
        (r_prot / ".protected").write_text("")

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(
            runs_root, pol,
            dry_run=False,
            project_root=project_root,
        )
        return {r.run_id: r for r in result.receipts}

    def test_r5_n01_unknown_skipped_unknown(self, tmp_path):
        """R5-N01: reference_state=UNKNOWN → SKIPPED_UNKNOWN."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        # No project_root → census_complete=false → reference_state=UNKNOWN
        r_unk = runs_root / "run-unknown"
        r_unk.mkdir()
        (r_unk / "final_close_result.json").write_text("{}")

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False)
        by_id = {r.run_id: r for r in result.receipts}
        r = by_id["run-unknown"]
        assert r.delete_result == "SKIPPED_UNKNOWN"
        assert r.deletion_trigger == "NONE"

    def test_r5_n02_referenced_skipped_referenced(self, tmp_path):
        """R5-N02: reference_state=REFERENCED → SKIPPED_REFERENCED."""
        receipts = self._get_skip_receipts(tmp_path)
        r = receipts["run-referenced"]
        assert r.delete_result == "SKIPPED_REFERENCED"
        assert r.deletion_trigger == "NONE"

    def test_r5_n03_retained_skipped_retained(self, tmp_path):
        """R5-N03: safe_eligible, TTL not expired, not selected → SKIPPED_RETAINED."""
        receipts = self._get_skip_receipts(tmp_path)
        r = receipts["run-retained"]
        assert r.delete_result == "SKIPPED_RETAINED"
        assert r.deletion_trigger == "NONE"

    def test_r5_n04_active_not_skipped_unknown(self, tmp_path):
        """R5-N04: ACTIVE run must not get SKIPPED_UNKNOWN."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r_act = runs_root / "run-active"
        r_act.mkdir()
        (r_act / "active_marker.json").write_text("{}")

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False)
        by_id = {r.run_id: r for r in result.receipts}
        r = by_id["run-active"]
        assert r.delete_result != "SKIPPED_UNKNOWN"

    def test_r5_n05_incomplete_not_skipped_unknown(self, tmp_path):
        """R5-N05: INCOMPLETE run must not get SKIPPED_UNKNOWN."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r_inc = runs_root / "run-incomplete"
        r_inc.mkdir()
        (r_inc / "worker_report.json").write_text("{}")

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False)
        by_id = {r.run_id: r for r in result.receipts}
        r = by_id["run-incomplete"]
        assert r.delete_result != "SKIPPED_UNKNOWN"

    def test_r5_n06_protected_skipped_protected(self, tmp_path):
        """R5-N06: PROTECTED/sealed → SKIPPED_PROTECTED."""
        receipts = self._get_skip_receipts(tmp_path)
        r = receipts["run-protected"]
        assert r.delete_result == "SKIPPED_PROTECTED"
        assert r.deletion_trigger == "NONE"

    def test_r5_n07_pure_quota_regression(self, tmp_path):
        """R5-N07: Pure QUOTA apply still works after R5 changes."""
        import os
        import time

        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        pr = tmp_path / "project"
        pr.mkdir()
        (pr / "_tracks").mkdir()
        (pr / "review").mkdir()
        (pr / "evidence").mkdir()

        # Two young runs exceeding quota
        for name in ("qa", "qb"):
            r = runs_root / name
            r.mkdir()
            (r / "final_close_result.json").write_text("{}")
            (r / "payload.bin").write_bytes(b"x" * 3000)
            t = time.time() - 10 * 86400
            os.utime(r, (t, t))

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=5000)
        result = execute_gc(runs_root, pol, dry_run=False, project_root=pr)
        deleted = [r for r in result.receipts if r.delete_result == "DELETED"]
        assert len(deleted) >= 1
        for rec in deleted:
            assert rec.classification == "GC_CANDIDATE"
            assert rec.deletion_trigger in ("QUOTA", "TTL_AND_QUOTA")

    def test_r5_n08_ttl_delete_regression(self, tmp_path):
        """R5-N08: TTL delete still works after R5 changes."""
        import os
        import time

        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        pr = tmp_path / "project"
        pr.mkdir()
        (pr / "_tracks").mkdir()
        (pr / "review").mkdir()
        (pr / "evidence").mkdir()

        r = runs_root / "run-ttl"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        t = time.time() - 100 * 86400
        os.utime(r, (t, t))

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False, project_root=pr)
        deleted = [r for r in result.receipts if r.delete_result == "DELETED"]
        assert len(deleted) == 1
        assert deleted[0].deletion_trigger in ("TTL", "TTL_AND_QUOTA")

    def test_r5_n09_reason_matches_result(self, tmp_path):
        """R5-N09: receipt reason must not contradict delete_result."""
        receipts = self._get_skip_receipts(tmp_path)
        for _rid, rec in receipts.items():
            if rec.delete_result == "SKIPPED_REFERENCED":
                assert "REFERENCED" in rec.reason or "reference" in rec.reason.lower()
            elif rec.delete_result == "SKIPPED_RETAINED":
                assert "safe_eligible" in rec.reason or "ttl" in rec.reason.lower()
            elif rec.delete_result == "SKIPPED_PROTECTED":
                assert rec.deletion_trigger == "NONE"

    def test_r5_n10_all_receipts_have_trigger(self, tmp_path):
        """R5-N10: every receipt has deletion_trigger field."""
        receipts = self._get_skip_receipts(tmp_path)
        for _rid, rec in receipts.items():
            assert hasattr(rec, "deletion_trigger")
            assert rec.deletion_trigger is not None


# --- R6: Composite protection receipt truth tests ---


class TestR6CompositeProtectionReceipt:
    """R6-N01~N10: Composite ACTIVE/INCOMPLETE + protection → SKIPPED_PROTECTED."""

    def _make_run_receipt(self, tmp_path, run_id, signals):
        """Create a run with specific filesystem signals and get its receipt."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / run_id
        r.mkdir()
        for sig in signals:
            (r / sig).write_text("{}")
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False)
        by_id = {rec.run_id: rec for rec in result.receipts}
        return by_id[run_id]

    def test_r6_n01_active_only(self, tmp_path):
        """R6-N01: ACTIVE only → SKIPPED_PROTECTED."""
        rec = self._make_run_receipt(tmp_path, "a1", ["active_marker.json"])
        assert rec.delete_result == "SKIPPED_PROTECTED"

    def test_r6_n02_active_pinned(self, tmp_path):
        """R6-N02: ACTIVE + pinned → SKIPPED_PROTECTED."""
        rec = self._make_run_receipt(tmp_path, "a2", ["active_marker.json", ".pinned"])
        assert rec.delete_result == "SKIPPED_PROTECTED"

    def test_r6_n03_active_sealed(self, tmp_path):
        """R6-N03: ACTIVE + sealed evidence → SKIPPED_PROTECTED."""
        rec = self._make_run_receipt(
            tmp_path, "a3", ["active_marker.json", "seal_result.json"]
        )
        assert rec.delete_result == "SKIPPED_PROTECTED"

    def test_r6_n04_running_protected(self, tmp_path):
        """R6-N04: RUNNING + protected → SKIPPED_PROTECTED."""
        rec = self._make_run_receipt(
            tmp_path, "r1", ["running_signal.json", ".protected"]
        )
        assert rec.delete_result == "SKIPPED_PROTECTED"

    def test_r6_n05_incomplete_authority(self, tmp_path):
        """R6-N05: INCOMPLETE + authority reference → SKIPPED_PROTECTED."""
        rec = self._make_run_receipt(
            tmp_path, "i1", ["worker_report.json", "authority_ref.json"]
        )
        assert rec.delete_result == "SKIPPED_PROTECTED"

    def test_r6_n06_incomplete_review(self, tmp_path):
        """R6-N06: INCOMPLETE + review package → SKIPPED_PROTECTED."""
        import zipfile
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "i2"
        r.mkdir()
        (r / "worker_report.json").write_text("{}")
        # Create a review ZIP
        zf_path = r / "review_package.zip"
        with zipfile.ZipFile(zf_path, "w") as zf:
            zf.writestr("review.md", "review content")
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        from synapx_harness.storage.gc import execute_gc
        result = execute_gc(runs_root, pol, dry_run=False)
        by_id = {rec.run_id: rec for rec in result.receipts}
        rec = by_id["i2"]
        assert rec.delete_result == "SKIPPED_PROTECTED"

    def test_r6_n07_no_unknown_for_protected(self, tmp_path):
        """R6-N07: All ACTIVE/INCOMPLETE runs → zero SKIPPED_UNKNOWN."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        # ACTIVE + pinned
        r1 = runs_root / "ap"
        r1.mkdir()
        (r1 / "active_marker.json").write_text("{}")
        (r1 / ".pinned").write_text("")
        # INCOMPLETE + authority
        r2 = runs_root / "ia"
        r2.mkdir()
        (r2 / "worker_report.json").write_text("{}")
        (r2 / "authority_ref.json").write_text("{}")

        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False)
        for rec in result.receipts:
            if rec.run_id in ("ap", "ia"):
                assert rec.delete_result != "SKIPPED_UNKNOWN"

    def test_r6_n08_unknown_still_works(self, tmp_path):
        """R6-N08: pure UNKNOWN → SKIPPED_UNKNOWN (no regression)."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        r = runs_root / "unk"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False)
        by_id = {rec.run_id: rec for rec in result.receipts}
        rec = by_id["unk"]
        assert rec.delete_result == "SKIPPED_UNKNOWN"

    def test_r6_n09_referenced_still_works(self, tmp_path):
        """R6-N09: REFERENCED → SKIPPED_REFERENCED (no regression)."""
        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        pr = tmp_path / "project"
        pr.mkdir()
        (pr / "_tracks").mkdir()
        (pr / "review").mkdir()
        (pr / "evidence").mkdir()
        r = runs_root / "ref"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        (pr / "review" / "ref_ref.md").write_text("ref")
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False, project_root=pr)
        by_id = {rec.run_id: rec for rec in result.receipts}
        rec = by_id["ref"]
        assert rec.delete_result == "SKIPPED_REFERENCED"

    def test_r6_n10_retained_still_works(self, tmp_path):
        """R6-N10: RETAINED → SKIPPED_RETAINED (no regression)."""
        import os
        import time

        from synapx_harness.storage.gc import execute_gc

        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        pr = tmp_path / "project"
        pr.mkdir()
        (pr / "_tracks").mkdir()
        (pr / "review").mkdir()
        (pr / "evidence").mkdir()
        r = runs_root / "ret"
        r.mkdir()
        (r / "final_close_result.json").write_text("{}")
        t = time.time() - 10 * 86400
        os.utime(r, (t, t))
        pol = RetentionPolicy(ttl_days=90, max_total_bytes=1_000_000_000)
        result = execute_gc(runs_root, pol, dry_run=False, project_root=pr)
        by_id = {rec.run_id: rec for rec in result.receipts}
        rec = by_id["ret"]
        assert rec.delete_result == "SKIPPED_RETAINED"
