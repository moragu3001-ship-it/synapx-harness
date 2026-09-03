"""RED-I0-08 — attempt/revision mismatch (X3-N08).

VerificationResult 의 attempt_index / source_revision 이 WorkContract 의
값과 불일치하면 반드시 거부되어야 한다.

Oracle: I1 은 admit_verification_result(work_contract, verification_result)
시그니처를 제공하고 교차 대조 불일치를 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import verification_planner

RED_ID = "RED-I0-08"
INVARIANT_REFS = ["X3-N08"]
GUARDED_TASKS = ["T01", "T02", "T07", "T08", "T09"]


def test_attempt_index_mismatch_is_rejected(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """contract attempt_index=1 vs result attempt_index=2 → 거부."""
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    mismatch = load_h2_i0_fixture("invalid/h2_i0_mismatch_attempt_revision.json")
    with pytest.raises((ValueError, RuntimeError), match="attempt"):
        admit(
            work_contract={
                "work_contract_id": "wc-mismatch",
                "attempt_index": 1,
            },
            verification_result=mismatch,
        )


def test_source_revision_mismatch_is_rejected(h2_i0_require_signature) -> None:
    """contract CONTENT_TREE_HASH vs result 다른 revision → 거부."""
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    with pytest.raises((ValueError, RuntimeError), match="revision|source"):
        admit(
            work_contract={
                "work_contract_id": "wc-mismatch",
                "attempt_index": 1,
                "source_revision_ref": {
                    "revision_kind": "CONTENT_TREE_HASH",
                    "revision_value": "a" * 64,
                },
            },
            verification_result={
                "work_contract_id": "wc-mismatch",
                "attempt_index": 1,
                "source_binding": {
                    "source_revision": {
                        "revision_kind": "CONTENT_TREE_HASH",
                        "revision_value": "c" * 64,
                    },
                    "source_snapshot_id": "snap-h2-i0-valid-001",
                    "repository_id": "repo-h2-i0",
                },
            },
        )


def test_snapshot_mismatch_is_rejected(h2_i0_require_signature) -> None:
    """source_snapshot_id 불일치 → 거부."""
    admit = h2_i0_require_signature(
        verification_planner,
        "admit_verification_result",
        params=("work_contract", "verification_result"),
    )
    with pytest.raises((ValueError, RuntimeError), match="snapshot|source"):
        admit(
            work_contract={
                "work_contract_id": "wc-mismatch",
                "attempt_index": 1,
                "source_snapshot_id": "snap-a",
            },
            verification_result={
                "work_contract_id": "wc-mismatch",
                "attempt_index": 1,
                "source_binding": {
                    "source_revision": {
                        "revision_kind": "CONTENT_TREE_HASH",
                        "revision_value": "a" * 64,
                    },
                    "source_snapshot_id": "snap-b",
                    "repository_id": "repo-h2-i0",
                },
            },
        )
