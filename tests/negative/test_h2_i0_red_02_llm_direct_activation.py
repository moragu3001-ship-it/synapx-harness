"""RED-I0-02 — LLM direct activation (X3-N02).

LLM/semantic selector 가 Semantic 선택만으로 skill 을 직접 활성화하는 경로는
Core Admission 검증 생략이므로 반드시 거부되어야 한다.

Oracle: I2 는 evaluate_semantic_activation 에 selector/evidence/skill_activation_contract
시그니처를 추가하고 LLM 활성화 판정을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-02"
INVARIANT_REFS = ["X3-N02"]
GUARDED_TASKS = ["T03", "T06"]


def test_llm_semantic_selection_cannot_activate_skill(h2_i0_require_signature) -> None:
    """Semantic selector 가 활성화 판정을 내리는 경로 거부."""
    evaluate = h2_i0_require_signature(
        activation_validator,
        "evaluate_semantic_activation",
        params=("selector", "skill_id", "evidence"),
    )
    with pytest.raises((ValueError, RuntimeError), match="proposal|activation"):
        evaluate(
            selector="LLM_SEMANTIC_SELECTOR",
            skill_id="skill-x",
            evidence={"semantic_match_score": 0.99},
        )


def test_llm_activation_without_skill_activation_contract_is_rejected(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """SkillActivationContract 부재 상태에서 활성화 주장 → 거부."""
    evaluate = h2_i0_require_signature(
        activation_validator,
        "evaluate_semantic_activation",
        params=("selector", "skill_id", "evidence", "skill_activation_contract"),
    )
    activation = load_h2_i0_fixture("valid/h2_i0_skill_activation_valid.json")
    with pytest.raises((ValueError, RuntimeError), match="contract|activation"):
        evaluate(
            selector="LLM_SEMANTIC_SELECTOR",
            skill_id=activation["extension_id"],
            evidence={"semantic_match_score": 0.99},
            skill_activation_contract=None,
        )
