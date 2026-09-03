"""RED-I0-15 — namespace flatten/collision (X3-N15).

State namespace 가 flatten 되어 동일 문자열이 다른 상태를 참조하는
collision 이 발생하면 반드시 거부되어야 한다 (fully-qualified 참조 강제).

Oracle: I1 은 resolve_state_reference(state_name, namespace, allow_ambiguous)
와 StateRef(state, namespace) 시그니처를 제공하고 충돌을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.contracts import runtime_models

RED_ID = "RED-I0-15"
INVARIANT_REFS = ["X3-N15"]
GUARDED_TASKS = ["T10", "T11"]


def test_flattened_namespace_collision_is_rejected(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """flatten 상태 참조로 인한 collision → 거부."""
    resolve = h2_i0_require_signature(
        runtime_models,
        "resolve_state_reference",
        params=("state_name", "namespace"),
    )
    collision = load_h2_i0_fixture("invalid/h2_i0_namespace_collision.json")
    flattened = collision["collision"]["flattened_attempt"]
    with pytest.raises((ValueError, RuntimeError), match="namespace|qualif|collision"):
        resolve(
            state_name=flattened["SEALED"],
            namespace="flattened",
        )


def test_fully_qualified_reference_required(h2_i0_require_signature) -> None:
    """충돌 유발 상태는 fully-qualified 참조가 강제되어야 한다."""
    resolve = h2_i0_require_signature(
        runtime_models,
        "resolve_state_reference",
        params=("state_name", "namespace", "allow_ambiguous"),
    )
    with pytest.raises((ValueError, RuntimeError), match="qualif|namespace"):
        resolve(
            state_name="SEALED",
            namespace="evidence.envelope",
            allow_ambiguous=True,
        )


def test_namespace_identity_preserved(h2_i0_require_signature) -> None:
    """state 가 namespace 정보를 유지하지 않으면 거부되어야 한다."""
    state_ref = h2_i0_require_signature(
        runtime_models,
        "StateRef",
        params=("state", "namespace"),
    )
    with pytest.raises((ValueError, RuntimeError), match="namespace|state"):
        state_ref(
            state="SEALED",
        )
