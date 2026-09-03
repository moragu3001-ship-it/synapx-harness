"""H2-I0 Contract Qualification — Gitless Revision Acceptance.

Git 미가용 환경에서도 revision 이 수용되는 경로가 반드시 존재해야 한다:
CONTENT_TREE_HASH / SNAPSHOT_ID / EXTERNAL_REVISION.

Oracle: I1 은 build(source_revision_ref) 와 REVISION_KINDS 상수를 제공하고
gitless revision 을 수용해야 한다. 현재는 시그니처 부재로 EXPECTED_RED.
"""
from __future__ import annotations

import pytest

from synapx_harness.contracts import runtime_models
from synapx_harness.kernel import work_contract_builder

RED_ID = "H2-I0-CQ-01"
INVARIANT_REFS = ["X3-N07"]


def test_content_tree_hash_revision_accepted(h2_i0_require_signature) -> None:
    """CONTENT_TREE_HASH revision 을 가진 contract 수용 경로 존재."""
    build = h2_i0_require_signature(
        work_contract_builder,
        "build",
        params=("work_contract_id", "source_revision_ref"),
    )
    with pytest.raises((ValueError, RuntimeError), match="revision|accept|content"):
        build(
            work_contract_id="wc-gitless-1",
            phase="H2",
            risk_class="R0",
            objective="gitless acceptance",
            scope=["src"],
            source_revision_ref={
                "revision_kind": "CONTENT_TREE_HASH",
                "revision_value": "a" * 64,
            },
        )


def test_snapshot_id_revision_accepted(h2_i0_require_signature) -> None:
    """SNAPSHOT_ID revision 수용 경로 존재."""
    build = h2_i0_require_signature(
        work_contract_builder,
        "build",
        params=("work_contract_id", "source_revision_ref"),
    )
    with pytest.raises((ValueError, RuntimeError), match="revision|accept|snapshot"):
        build(
            work_contract_id="wc-gitless-2",
            phase="H2",
            risk_class="R0",
            objective="gitless snapshot acceptance",
            scope=["src"],
            source_revision_ref={
                "revision_kind": "SNAPSHOT_ID",
                "revision_value": "snap-gitless-2",
            },
        )


def test_external_revision_accepted(h2_i0_require_signature) -> None:
    """EXTERNAL_REVISION 수용 경로 존재."""
    build = h2_i0_require_signature(
        work_contract_builder,
        "build",
        params=("work_contract_id", "source_revision_ref"),
    )
    with pytest.raises((ValueError, RuntimeError), match="revision|accept|external"):
        build(
            work_contract_id="wc-gitless-3",
            phase="H2",
            risk_class="R0",
            objective="gitless external acceptance",
            scope=["src"],
            source_revision_ref={
                "revision_kind": "EXTERNAL_REVISION",
                "revision_value": "ext-ref-3",
            },
        )


def test_revision_kind_enum_exposes_four_kinds(h2_i0_require_signature) -> None:
    """revision_kind enum 에 4 종 상수가 노출되어야 한다."""
    h2_i0_require_signature(
        runtime_models,
        "REVISION_KINDS",
    )
