"""RED-I0-11 — ACTIVE_FOR_JOB without ActivationContract (X3-N11).

SkillActivationContract 부재 상태에서 skill 이 ACTIVE_FOR_JOB 으로 선언되는
경로는 반드시 거부되어야 한다.

Oracle: I2 는 transition_activation_state(extension_id, from_state, to_state,
activation_contract) 시그니처를 제공하고 계약 부재 전이를 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-11"
INVARIANT_REFS = ["X3-N11"]
GUARDED_TASKS = ["T06"]


def test_active_for_job_without_activation_contract_is_rejected(
    h2_i0_require_signature,
) -> None:
    """ActivationContract 없이 ACTIVE_FOR_JOB 선언 → 거부."""
    transition = h2_i0_require_signature(
        activation_validator,
        "transition_activation_state",
        params=("extension_id", "from_state", "to_state", "activation_contract"),
    )
    with pytest.raises((ValueError, RuntimeError), match="contract|activation"):
        transition(
            extension_id="ext-x",
            from_state="ENABLED",
            to_state="ACTIVE_FOR_JOB",
            activation_contract=None,
        )


def test_activation_contract_required_for_job_state(h2_i0_require_signature) -> None:
    """ACTIVE_FOR_JOB 진입에는 activation_contract 파라미터 필수."""
    transition = h2_i0_require_signature(
        activation_validator,
        "transition_activation_state",
        params=("extension_id", "from_state", "to_state", "activation_contract"),
    )
    with pytest.raises((ValueError, RuntimeError), match="contract|activation"):
        transition(
            extension_id="ext-x",
            from_state="ENABLED",
            to_state="ACTIVE_FOR_JOB",
        )
