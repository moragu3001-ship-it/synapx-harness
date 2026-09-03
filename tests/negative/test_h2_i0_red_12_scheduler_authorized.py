"""RED-I0-12 — Scheduler -> AUTHORIZED (X3-N12).

Scheduler 주체가 권한을 AUTHORIZED 로 승격시키는 경로는 반드시 거부되어야
한다. 권한 부여는 Core Admission 단일 경로를 통해서만 가능하다.

Oracle: I2 는 grant_activation_authority(extension_id, issued_by,
authority_level, permitted_transitions) 시그니처를 제공하고 Scheduler 의
AUTHORIZED 승격을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.validators import activation_validator

RED_ID = "RED-I0-12"
INVARIANT_REFS = ["X3-N12"]
GUARDED_TASKS = ["T06"]


def test_scheduler_cannot_grant_authorized(h2_i0_require_signature) -> None:
    """Scheduler 발급 AUTHORIZED → 거부."""
    grant = h2_i0_require_signature(
        activation_validator,
        "grant_activation_authority",
        params=("extension_id", "issued_by", "authority_level"),
    )
    with pytest.raises((ValueError, RuntimeError), match="authority|scheduler|issuer"):
        grant(
            extension_id="ext-x",
            issued_by="Scheduler",
            authority_level="AUTHORIZED",
        )


def test_scheduler_can_only_dispatch_not_authorize(h2_i0_require_signature) -> None:
    """Scheduler 는 DISPATCHED 이하 전이만 허용되어야 한다."""
    grant = h2_i0_require_signature(
        activation_validator,
        "grant_activation_authority",
        params=("extension_id", "issued_by", "authority_level", "permitted_transitions"),
    )
    with pytest.raises((ValueError, RuntimeError), match="dispatch|authority|issuer"):
        grant(
            extension_id="ext-x",
            issued_by="Scheduler",
            authority_level="AUTHORIZED",
            permitted_transitions=["DISPATCHED"],
        )
