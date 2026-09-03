"""RED-I0-05 — Evidence SEALED -> COMPLETED (X3-N05).

Evidence Seal(SEALED) 자체를 Terminal Decision 으로 취급하는 경로는 Seal 을
판정으로 오인하므로 반드시 거부되어야 한다.

Oracle: I3 은 seal_as_terminal_decision / finalize_from_sealed_evidence /
seal_evidence 시그니처를 추가하고 Seal → 판정 직접 전환을 거부해야 한다.
"""
from __future__ import annotations

import pytest

from synapx_harness.evidence import evidence_validator
from synapx_harness.kernel import terminal_finalizer

RED_ID = "RED-I0-05"
INVARIANT_REFS = ["X3-N05"]
GUARDED_TASKS = ["T09", "T10", "T11", "T12", "T13"]


def test_sealed_evidence_is_not_terminal_decision(
    h2_i0_require_signature, load_h2_i0_fixture
) -> None:
    """SEALED 상태를 COMPLETED 판정으로 취급 → 거부."""
    seal_to_terminal = h2_i0_require_signature(
        evidence_validator,
        "seal_as_terminal_decision",
        params=("evidence",),
    )
    envelope = load_h2_i0_fixture("valid/h2_i0_evidence_envelope_valid.json")
    with pytest.raises((ValueError, RuntimeError), match="seal|terminal"):
        seal_to_terminal(
            evidence=envelope,
        )


def test_terminalization_requires_input_not_seal(h2_i0_require_signature) -> None:
    """TerminalizationInput 을 거치지 않은 Seal → COMPLETED 강제 거부."""
    finalize = h2_i0_require_signature(
        terminal_finalizer,
        "finalize_from_sealed_evidence",
        params=("sealed_evidence", "terminalization_input"),
    )
    with pytest.raises((ValueError, RuntimeError), match="terminal"):
        finalize(
            sealed_evidence={"integrity_status": "SEALED"},
            terminalization_input=None,
        )


def test_supplementary_red_i0_seal01_sealer_neq_finalizer(h2_i0_require_signature) -> None:
    """RED-I0-SEAL01 — EvidenceSealer 가 TerminalFinalizer 와 동일 → 거부."""
    seal = h2_i0_require_signature(
        evidence_validator,
        "seal_evidence",
        params=("envelope", "sealer", "redaction_applied"),
    )
    with pytest.raises((ValueError, RuntimeError), match="sealer|finaliz"):
        seal(
            envelope={"integrity_status": "ADMITTED"},
            sealer="TERMINAL_FINALIZER",
            redaction_applied=True,
        )
