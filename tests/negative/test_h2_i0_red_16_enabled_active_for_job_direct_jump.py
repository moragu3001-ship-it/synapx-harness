"""RED-I0-16 — ENABLED -> ACTIVE_FOR_JOB direct jump (X4-D02).

ENABLED → ACTIVE_FOR_JOB 직접 점프는 중간 승인/계약 단계를 생략하므로
반드시 거부되어야 한다.

Oracle: I2 는 transition_activation_state(extension_id, from_state, to_state,
activation_contract, authorization_proof) 시그니처를 제공하고 중간 단계
생략 전이를 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-16"
INVARIANT_REFS = ["X4-D02.ENABLED_TO_ACTIVE_FOR_JOB_DIRECT_JUMP=false"]
GUARDED_TASKS = ["T06"]


def test_enabled_to_active_for_job_direct_jump_is_rejected(h2_i0_require_signature) -> None:
    """ENABLED → ACTIVE_FOR_JOB 직접 점프 → 거부."""
    transition = h2_i0_require_signature(
        activation_validator,
        "transition_activation_state",
        params=("extension_id", "from_state", "to_state", "activation_contract"),
    )
    with pytest.raises((ValueError, RuntimeError), match="transition|authorized|contract"):
        transition(
            extension_id="ext-x",
            from_state="ENABLED",
            to_state="ACTIVE_FOR_JOB",
            activation_contract={"skill_activation_id": "act-x"},
        )


def test_missing_intermediate_authorization_is_rejected(h2_i0_require_signature) -> None:
    """AUTHORIZED 승인 단계가 없으면 ACTIVE_FOR_JOB 불가."""
    transition = h2_i0_require_signature(
        activation_validator,
        "transition_activation_state",
        params=(
            "extension_id",
            "from_state",
            "to_state",
            "activation_contract",
            "authorization_proof",
        ),
    )
    with pytest.raises((ValueError, RuntimeError), match="authorized|transition"):
        transition(
            extension_id="ext-x",
            from_state="ENABLED",
            to_state="ACTIVE_FOR_JOB",
            activation_contract={"skill_activation_id": "act-x"},
            authorization_proof=None,
        )
