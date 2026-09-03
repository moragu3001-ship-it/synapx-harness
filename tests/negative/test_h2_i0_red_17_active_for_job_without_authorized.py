"""RED-I0-17 — ACTIVE_FOR_JOB without authoritative authorization (X4-D02).

SkillActivationContract 가 존재해도 authoritative authorization (Core
Admission 검증을 거친 AUTHORIZED) 증명이 없으면 ACTIVE_FOR_JOB 진입은
반드시 거부되어야 한다.

Oracle: I2 는 validate_activation_authorization(extension_id,
activation_contract, authorization_proof) 시그니처를 제공하고 권위적 인가
증명 부재/비권위 발급자를 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-17"
INVARIANT_REFS = ["X4-D02.ACTIVE_FOR_JOB_REQUIRES_AUTHORITATIVE_ACTIVATION=true"]
GUARDED_TASKS = ["T06"]


def test_contract_without_authorization_proof_is_rejected(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """ActivationContract 존재 + authorization proof 부재 → 거부."""
    validate = h2_i0_require_signature(
        activation_validator,
        "validate_activation_authorization",
        params=("extension_id", "activation_contract", "authorization_proof"),
    )
    activation = load_h2_i0_fixture("valid/h2_i0_skill_activation_valid.json")
    with pytest.raises((ValueError, RuntimeError), match="authoriz|proof|contract"):
        validate(
            extension_id="ext-x",
            activation_contract=activation,
            authorization_proof=None,
        )


def test_contract_with_non_authoritative_proof_is_rejected(h2_i0_require_signature) -> None:
    """비권위 발급자(LLM/Scheduler)의 authorization proof → 거부."""
    validate = h2_i0_require_signature(
        activation_validator,
        "validate_activation_authorization",
        params=("extension_id", "activation_contract", "authorization_proof"),
    )
    with pytest.raises((ValueError, RuntimeError), match="authoriz|issuer|admission"):
        validate(
            extension_id="ext-x",
            activation_contract={"skill_activation_id": "act-x"},
            authorization_proof={"issued_by": "Scheduler", "authority_level": "AUTHORIZED"},
        )


def test_contract_issuer_must_be_core_admission(h2_i0_require_signature) -> None:
    """ActivationContract 발급자는 CORE_ADMISSION 단일이어야 한다."""
    validate = h2_i0_require_signature(
        activation_validator,
        "validate_activation_authorization",
        params=("extension_id", "activation_contract", "authorization_proof"),
    )
    with pytest.raises((ValueError, RuntimeError), match="issuer|admission"):
        validate(
            extension_id="ext-x",
            activation_contract={
                "skill_activation_id": "act-x",
                "issuer": "PROVIDER",
                "activation_status": "ACTIVE_FOR_JOB",
            },
            authorization_proof={"issued_by": "CORE_ADMISSION", "authority_level": "AUTHORIZED"},
        )
