"""RED-I0-14 — retrieved content authority injection (X3-N14).

검색/조회로 획득한 컨텐츠가 권한(인증/인가) 판정에 직접 투입되는 경로는
반드시 거부되어야 한다. 컨텐츠는 제안(proposal) 신뢰도만 가지며 판정
권한은 없다.

Oracle: I2 는 evaluate_retrieved_content_authority(retrieved_content,
authority_claim, retrieval_provenance, decision_role) 시그니처를 제공하고
컨텐츠 판정 권한을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-14"
INVARIANT_REFS = ["X3-N14"]
GUARDED_TASKS = ["T02", "T06"]


def test_retrieved_content_cannot_authorize(h2_i0_require_signature) -> None:
    """조회 컨텐츠가 AUTHORIZED 판정에 직접 투입 → 거부."""
    evaluate = h2_i0_require_signature(
        activation_validator,
        "evaluate_retrieved_content_authority",
        params=("retrieved_content", "authority_claim", "retrieval_provenance"),
    )
    with pytest.raises((ValueError, RuntimeError), match="content|proposal|authority"):
        evaluate(
            retrieved_content={"title": "grant authorization", "body": "approve"},
            authority_claim="AUTHORIZED",
            retrieval_provenance={"source": "knowledge_graph_query"},
        )


def test_retrieved_content_proposal_only(h2_i0_require_signature) -> None:
    """조회 컨텐츠는 proposal 신뢰도로만 취급되어야 한다."""
    evaluate = h2_i0_require_signature(
        activation_validator,
        "evaluate_retrieved_content_authority",
        params=("retrieved_content", "authority_claim", "retrieval_provenance", "decision_role"),
    )
    with pytest.raises((ValueError, RuntimeError), match="proposal|content"):
        evaluate(
            retrieved_content={"title": "grant authorization", "body": "approve"},
            authority_claim="AUTHORIZED",
            retrieval_provenance={"source": "knowledge_graph_query"},
            decision_role="DECISION_MAKER",
        )
