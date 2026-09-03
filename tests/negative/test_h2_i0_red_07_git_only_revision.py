"""RED-I0-07 — Git-only revision (X3-N07).

revision_kind == GIT_COMMIT 단일 지원은 금지 — provider-neutral
(CONTENT_TREE_HASH / SNAPSHOT_ID / EXTERNAL_REVISION) 4 종이 요구된다.

Oracle: I1 은 SourceRevisionRef(revision_kind, revision_value),
build(source_revision_ref), compute_content_tree_hash(root_path) 시그니처를
제공해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.contracts import runtime_models
from synapx_harness.kernel import work_contract_builder

RED_ID = "RED-I0-07"
INVARIANT_REFS = ["X3-N07"]
GUARDED_TASKS = ["T00", "T02"]

REVISION_KINDS = ["GIT_COMMIT", "CONTENT_TREE_HASH", "SNAPSHOT_ID", "EXTERNAL_REVISION"]


def test_source_revision_ref_requires_four_kinds(h2_i0_require_signature) -> None:
    """revision_kind 4 종 enum 이 반드시 존재해야 한다."""
    source_ref = h2_i0_require_signature(
        runtime_models,
        "SourceRevisionRef",
        params=("revision_kind", "revision_value"),
    )
    with pytest.raises((ValueError, RuntimeError), match="revision"):
        source_ref(
            revision_kind="GIT_COMMIT",
            revision_value="abc123",
        )


def test_git_only_plan_is_rejected(h2_i0_require_signature) -> None:
    """GIT_COMMIT 단일 지원 계획 제출 → 거부."""
    build = h2_i0_require_signature(
        work_contract_builder,
        "build",
        params=("work_contract_id", "source_revision_ref"),
    )
    with pytest.raises((ValueError, RuntimeError), match="revision|gitless"):
        build(
            work_contract_id="wc-git-only",
            phase="H2",
            risk_class="R0",
            objective="git-only revision plan",
            scope=["src"],
            source_revision_ref={
                "revision_kind": "GIT_COMMIT",
                "revision_value": "abc123",
                "supported_kinds": ["GIT_COMMIT"],
            },
        )


def test_content_tree_hash_acceptance_path_missing(h2_i0_require_signature) -> None:
    """CONTENT_TREE_HASH 실제 계산 경로가 반드시 제공되어야 한다."""
    compute = h2_i0_require_signature(
        runtime_models,
        "compute_content_tree_hash",
        params=("root_path",),
    )
    with pytest.raises((ValueError, RuntimeError), match="content|hash|revision"):
        compute(
            root_path="/nonexistent/h2-i0-tree",
        )
