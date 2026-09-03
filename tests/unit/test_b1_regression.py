"""Regression tests for B1 storage hardening.

Ensures existing tests continue to pass and new storage module
does not break existing functionality.
"""
from __future__ import annotations

from datetime import UTC
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
from synapx_harness.storage.gc import build_dry_run
from synapx_harness.storage.policy import RetentionPolicy


class TestRegressionCatalogInvariant:
    """Catalog invariants must hold under all conditions."""

    def test_catalog_always_returns_tuple(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()
        census = build_catalog(runs_root)
        assert isinstance(census.catalog.runs, tuple)

    def test_catalog_total_matches_sum_of_runs(self, tmp_path: Path) -> None:
        runs_root = tmp_path / "_runs"
        runs_root.mkdir()

        for i in range(5):
            r = runs_root / f"RUN-{i}"
            r.mkdir()
            (r / "data.bin").write_bytes(b"x" * (i * 100 + 50))

        census = build_catalog(runs_root)
        catalog = census.catalog
        assert catalog.total_size_bytes == sum(r.size_bytes for r in catalog.runs)
        assert catalog.run_count == len(catalog.runs)


class TestRegressionClassificationExhaustive:
    """Every run must be classified as exactly one class."""

    def test_all_runs_classified(self) -> None:
        statuses = [
            RunStatus.ACTIVE, RunStatus.RUNNING, RunStatus.INCOMPLETE,
            RunStatus.COMPLETE, RunStatus.UNKNOWN,
        ]
        ref_states = [
            ReferenceState.REFERENCED, ReferenceState.UNREFERENCED,
            ReferenceState.UNKNOWN,
        ]
        bool_flags = [True, False]

        policy = RetentionPolicy()

        for status in statuses:
            for ref in ref_states:
                for pinned in bool_flags:
                    for protected in bool_flags:
                        for sealed in bool_flags:
                            for review in bool_flags:
                                for auth in bool_flags:
                                    run = RunMetadata(
                                        run_id="X",
                                        path="/fake/X",
                                        size_bytes=0,
                                        status=status,
                                        created_at="2026-01-01T00:00:00+00:00",
                                        last_known_activity_at="2026-01-01T00:00:00+00:00",
                                        pinned=pinned,
                                        protected=protected,
                                        reference_state=ref,
                                        has_sealed_evidence=sealed,
                                        has_review_package=review,
                                        has_authority_reference=auth,
                                    )
                                    result = classify_run(run, policy)
                                    assert result.classification in (
                                        DeletionClass.PROTECTED,
                                        DeletionClass.KEEP,
                                        DeletionClass.GC_CANDIDATE,
                                    ), (
                                        f"Unclassified: status={status}, "
                                        f"ref={ref}, pinned={pinned}, "
                                        f"protected={protected}, "
                                        f"sealed={sealed}, "
                                        f"review={review}, auth={auth}"
                                    )

    def test_classification_is_deterministic(self) -> None:
        run = RunMetadata(
            run_id="DETERMINISTIC-RUN",
            path="/fake/DETERMINISTIC-RUN",
            size_bytes=500,
            status=RunStatus.COMPLETE,
            created_at="2026-01-01T00:00:00+00:00",
            last_known_activity_at="2026-01-01T00:00:00+00:00",
            pinned=False,
            protected=False,
            reference_state=ReferenceState.UNREFERENCED,
            has_sealed_evidence=False,
            has_review_package=False,
            has_authority_reference=False,
        )
        policy = RetentionPolicy()
        r1 = classify_run(run, policy)
        r2 = classify_run(run, policy)
        assert r1.classification == r2.classification
        assert r1.reason == r2.reason


class TestRegressionGCDeterminism:
    """GC plan must be identical for identical inputs."""

    def test_identical_inputs_produce_identical_plans(self, tmp_path: Path) -> None:
        import time
        from datetime import datetime

        for run_idx in range(2):
            runs_root = tmp_path / f"runs_{run_idx}"
            runs_root.mkdir()

            for name in ["RUN-A", "RUN-B", "RUN-C"]:
                r = runs_root / name
                r.mkdir()
                (r / "final_close_result.json").write_text("{}")

        time.sleep(0.15)
        now = datetime.now(tz=UTC)
        policy = RetentionPolicy()
        cat1 = build_catalog(tmp_path / "runs_0").catalog
        cat2 = build_catalog(tmp_path / "runs_1").catalog
        plan1 = build_dry_run(cat1, policy, now=now)
        plan2 = build_dry_run(cat2, policy, now=now)

        assert plan1.to_dict() == plan2.to_dict()


class TestRegressionReceiptStructure:
    """Receipts must have all required fields."""

    def test_receipt_has_all_fields(self) -> None:
        from synapx_harness.storage.receipts import make_receipt

        receipt = make_receipt(
            run_id="TEST",
            path="/fake/TEST",
            size_bytes_before=100,
            classification="GC_CANDIDATE",
            reason="test",
            policy_ttl_days=90,
            policy_max_total_bytes=5000000000,
            delete_result="DELETED",
        )
        d = receipt.to_dict()
        required = [
            "run_id", "path", "size_bytes_before", "classification",
            "reason", "policy", "deleted_at", "delete_result",
        ]
        for field in required:
            assert field in d, f"Missing field: {field}"
        assert isinstance(d["policy"], dict)
        assert "ttl_days" in d["policy"]
        assert "max_total_bytes" in d["policy"]
