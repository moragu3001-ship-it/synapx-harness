"""RED-I0-13 — Registry -> AUTHORIZED (X3-N13).

Registry 주체가 권한을 AUTHORIZED 로 승격시키는 경로는 반드시 거부되어야
한다. Registry 는 등록/해제 관리만 수행한다.

Oracle: I2 는 grant_activation_authority 시그니처를 제공하고 Registry 의
AUTHORIZED 승격을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-13"
INVARIANT_REFS = ["X3-N13"]
GUARDED_TASKS = ["T06"]


def test_registry_cannot_grant_authorized(h2_i0_require_signature) -> None:
    """Registry 발급 AUTHORIZED → 거부."""
    grant = h2_i0_require_signature(
        activation_validator,
        "grant_activation_authority",
        params=("extension_id", "issued_by", "authority_level"),
    )
    with pytest.raises((ValueError, RuntimeError), match="authority|registry|issuer"):
        grant(
            extension_id="ext-x",
            issued_by="Registry",
            authority_level="AUTHORIZED",
        )


def test_registry_limited_to_registration_actions(h2_i0_require_signature) -> None:
    """Registry 는 REGISTERED/UNREGISTERED 전이만 허용되어야 한다."""
    grant = h2_i0_require_signature(
        activation_validator,
        "grant_activation_authority",
        params=("extension_id", "issued_by", "authority_level", "permitted_transitions"),
    )
    with pytest.raises((ValueError, RuntimeError), match="register|authority|issuer"):
        grant(
            extension_id="ext-x",
            issued_by="Registry",
            authority_level="AUTHORIZED",
            permitted_transitions=["REGISTERED", "UNREGISTERED"],
        )
