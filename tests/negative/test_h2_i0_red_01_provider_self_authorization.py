"""RED-I0-01 — Provider self authorization (X3-N01).

Provider 가 자신의 WorkContract/권한을 스스로 발급하는 경로는 Core Admission
우회로 반드시 거부되어야 한다.

Oracle: I1 은 build() 에 issuer/admission_receipt 시그니처를 추가하고
PROVIDER 발급 + receipt 부재를 거부해야 한다. 현재는 시그니처 부재로
EXPECTED_RED.
"""
from __future__ import annotations

import pytest

from synapx_harness.kernel import work_contract_builder

RED_ID = "RED-I0-01"
INVARIANT_REFS = ["X3-N01"]
GUARDED_TASKS = ["T03", "T04", "T05", "T06"]


def test_provider_self_authorization_is_rejected(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """Provider 발급자 + admission receipt 부재 → Core Admission 우회 거부."""
    build = h2_i0_require_signature(
        work_contract_builder,
        "build",
        params=("work_contract_id", "issuer", "admission_receipt"),
    )
    work_contract = load_h2_i0_fixture("valid/h2_i0_work_contract_valid.json")
    with pytest.raises((ValueError, RuntimeError), match="admission|issuer"):
        build(
            work_contract_id=work_contract["work_contract_id"],
            phase="H2",
            risk_class="R0",
            objective="provider self authorization attempt",
            scope=["src"],
            issuer="PROVIDER",
            admission_receipt=None,
        )


def test_provider_cannot_forge_work_contract_without_receipts(h2_i0_require_signature) -> None:
    """3 receipts (permission/eligibility/execution) 부재 시 수용 거부."""
    build = h2_i0_require_signature(
        work_contract_builder,
        "build",
        params=(
            "work_contract_id",
            "permission_receipt_ref",
            "eligibility_receipt_ref",
            "execution_receipt_ref",
        ),
    )
    with pytest.raises((ValueError, RuntimeError), match="receipt"):
        build(
            work_contract_id="wc-provider-forge",
            phase="H2",
            risk_class="R1",
            objective="forge attempt",
            scope=["src"],
            issuer="PROVIDER",
            permission_receipt_ref=None,
            eligibility_receipt_ref=None,
            execution_receipt_ref=None,
        )
