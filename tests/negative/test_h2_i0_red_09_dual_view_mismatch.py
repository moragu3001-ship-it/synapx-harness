"""RED-I0-09 — dual-view mismatch (X3-N09).

Legacy 스키마(0.1.x)와 Canonical 스키마(0.2.0+) 간 매핑/해석 불일치
(dual-view mismatch)가 검출되면 반드시 거부되어야 한다.

Oracle: I1 은 validate_dual_view_consistency(legacy_view, canonical_view)
시그니처를 제공하고 뷰 간 불일치를 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import verification_planner

RED_ID = "RED-I0-09"
INVARIANT_REFS = ["X3-N09"]
GUARDED_TASKS = ["T08", "T09"]


def test_dual_view_semantic_mismatch_is_rejected(h2_i0_require_signature) -> None:
    """legacy PASS/active_blocker=0 vs canonical FAILED → 불일치 거부."""
    validate = h2_i0_require_signature(
        verification_planner,
        "validate_dual_view_consistency",
        params=("legacy_view", "canonical_view"),
    )
    with pytest.raises((ValueError, RuntimeError), match="view|consisten|canonical"):
        validate(
            legacy_view={"verification_status": "PASS", "active_blocker_count": 0},
            canonical_view={"verification_status": "FAILED", "active_blocker_count": 1},
        )


def test_legacy_only_view_is_rejected_after_schema_bump(h2_i0_require_signature) -> None:
    """canonical 뷰 부재(legacy 단독) → 거부."""
    validate = h2_i0_require_signature(
        verification_planner,
        "validate_dual_view_consistency",
        params=("legacy_view", "canonical_view"),
    )
    with pytest.raises((ValueError, RuntimeError), match="canonical|view"):
        validate(
            legacy_view={"verification_status": "PASS", "active_blocker_count": 0},
            canonical_view=None,
        )
