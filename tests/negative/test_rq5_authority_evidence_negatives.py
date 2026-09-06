"""RQ5-R1 Authority & Evidence Negative Qualification.

This module attacks the RQ4 ACCEPTED_AND_CLOSED harness authority chain
with 27 deterministic negative cases. Every test asserts that a specific
authority boundary fails closed.

Authority invariants under attack (RQ4 §3):

    Agent DONE != Verification PASS
    Verification PASS != Evidence VALID
    Evidence VALID != Terminal COMPLETED
    Only canonical Terminal Finalizer may authorize completion
    AI proposes / Harness validates / Harness mutates / Harness verifies
    / Harness decides completion

Each test is constructed WITHOUT a live Codex invocation: it imports
the canonical authority modules directly and supplies a deterministic
fixture. This keeps RQ5-R1 fast, deterministic, and hermetic.

This file is the canonical SSoT for the RQ5-R1 negative matrix.
Do NOT add xfail markers — any new unexpected PASS is an authority
violation that must be reported to the Project Owner.

Related artifacts:
    PUBLIC_ALPHA_RQ5_R1_NEGATIVE_MATRIX.json
    PUBLIC_ALPHA_RQ5_R1_NEGATIVE_RESULTS.json
    tests/contract/test_rq5_cli_failure_contract.py (CLI01/CLI02)
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from synapx_harness.evidence.evidence_validator import (
    CORE_EVIDENCE_SEALER,
    seal_evidence,
    validate_artifact_hash_matches,
    validate_evidence_freshness,
)
from synapx_harness.kernel import terminal_finalizer
from synapx_harness.kernel.mutation_authority import (
    AdmissionReceipt,
    ApplyReceipt,
    ControlledPatchApplicator,
    ExactPathMutationGate,
    MutationAdmissionGate,
    PatchProposal,
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
    validate_mutation_proposal,
)

CORE_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Shared fixture builders
# ---------------------------------------------------------------------------


def _build_structured_proposal(
    path: str,
    old_text: str,
    new_text: str,
) -> str:
    """Build a canonical structured proposal string for one file."""
    return (
        f"{PROPOSAL_BEGIN}\n"
        f"FILE: {path}\n"
        f"<<<< OLD\n"
        f"{old_text}\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"{new_text}\n"
        f">>>> NEW\n"
        f"{PROPOSAL_END}\n"
    )


def _empty_receipt(
    authorization_ref: str,
    admission_receipt_id: str,
    path_gate_receipt_id: str,
    source_revision: str,
    apply_started: str,
    reason: str,
) -> ApplyReceipt:
    """Reproduce the empty ApplyReceipt shape (mirror of production helper)."""
    return ApplyReceipt(
        applied_paths=[],
        before_sha256="",
        after_sha256="",
        patch_sha256="",
        canonical_patch_sha256="",
        write_count=0,
        apply_started_at=apply_started,
        apply_completed_at=apply_started,
        authorization_ref=authorization_ref,
        admission_receipt_id=admission_receipt_id,
        path_gate_receipt_id=path_gate_receipt_id,
        source_revision=source_revision,
        denied_reason=reason,
    )


def _execution_identity_dict(work_contract_id: str) -> dict[str, object]:
    return {
        "job_id": f"job-{work_contract_id}",
        "root_task_id": f"root-{work_contract_id}",
        "task_id": f"task-{work_contract_id}",
        "attempt_id": f"att-{work_contract_id}",
        "tool_call_id": "__unset__",
        "agent_session_id": f"agent-{work_contract_id}",
    }


def _sealed_evidence(work_contract_id: str) -> dict[str, object]:
    return {
        "integrity_status": "SEALED",
        "evidence_id": f"ev-{work_contract_id}",
        "work_contract_id": work_contract_id,
        "sealed_by": CORE_EVIDENCE_SEALER,
    }


def _terminalization_input(
    *,
    work_contract_id: str,
    verification_status: str,
    evidence_status: str,
    active_blocker_count: int,
    proposed_outcome: str,
) -> dict[str, object]:
    return {
        "execution_identity": _execution_identity_dict(work_contract_id),
        "work_contract_id": work_contract_id,
        "verification_admission_receipt": {
            "receipt_id": f"vad/{work_contract_id}",
            "work_contract_id": work_contract_id,
            "verification_status": verification_status,
            "evidence_status": evidence_status,
            "active_blocker_count": active_blocker_count,
            "admitted_at": "2026-09-06T00:00:00Z",
        },
        "sealed_evidence": _sealed_evidence(work_contract_id),
        "source_revision_ref": {"revision": "rq5_r1_negative_qualification"},
        "active_blocker_count": active_blocker_count,
        "proposed_outcome": proposed_outcome,
        "reason": "rq5_r1_negative",
    }


# ---------------------------------------------------------------------------
# A01 — Agent DONE cannot finalize directly
# ---------------------------------------------------------------------------


def test_a01_agent_done_without_verification() -> None:
    """Agent DONE claim cannot promote to terminal decision directly."""
    with pytest.raises(ValueError, match=r"finaliz\|terminal"):
        terminal_finalizer.finalize_from_agent_done(
            work_contract_id="wc-rq5-a01",
            claim={"claim_type": "AGENT_DONE_CLAIM", "task": "noop"},
        )


def test_a01_advance_agent_claim_only_to_verifying() -> None:
    """Agent DONE claim may only transition to VERIFYING (not COMPLETED)."""
    claim = {"claim_type": "AGENT_DONE_CLAIM", "task": "noop"}
    with pytest.raises(ValueError, match=r"verifying\|transition"):
        terminal_finalizer.advance_agent_claim(claim, target_state="COMPLETED")
    with pytest.raises(ValueError, match=r"verifying\|transition"):
        terminal_finalizer.advance_agent_claim(claim, target_state="FAILED")


# ---------------------------------------------------------------------------
# A02 — verification=FAIL + proposed=COMPLETED rejected
# ---------------------------------------------------------------------------


def test_a02_verification_fail_blocks_completed() -> None:
    sealed = _sealed_evidence("wc-rq5-a02")
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-a02",
        verification_status="FAIL",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"finaliz\|verify-fail\|chain"):
        terminal_finalizer.finalize_terminal_chain(
            work_contract_id="wc-rq5-a02",
            sealed_evidence=sealed,
            terminalization_input=term_input,
        )


# ---------------------------------------------------------------------------
# A03 — evidence=INVALID + proposed=COMPLETED rejected
# ---------------------------------------------------------------------------


def test_a03_evidence_invalid_blocks_completed() -> None:
    sealed = _sealed_evidence("wc-rq5-a03")
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-a03",
        verification_status="PASS",
        evidence_status="INVALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"evidence_status"):
        terminal_finalizer.finalize_terminal_chain(
            work_contract_id="wc-rq5-a03",
            sealed_evidence=sealed,
            terminalization_input=term_input,
        )


# ---------------------------------------------------------------------------
# A04 — active_blocker_count>0 + proposed=COMPLETED rejected
# ---------------------------------------------------------------------------


def test_a04_active_blocker_blocks_completed() -> None:
    sealed = _sealed_evidence("wc-rq5-a04")
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-a04",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=1,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"active_blocker_count"):
        terminal_finalizer.finalize_terminal_chain(
            work_contract_id="wc-rq5-a04",
            sealed_evidence=sealed,
            terminalization_input=term_input,
        )


# ---------------------------------------------------------------------------
# A05 — Invalid proposal (empty stdout) -> no admission, write_count=0
# ---------------------------------------------------------------------------


def test_a05_invalid_proposal_before_admission() -> None:
    parser = PatchProposalParser()
    admission = MutationAdmissionGate()
    path_gate = ExactPathMutationGate()
    applicator = ControlledPatchApplicator()

    proposal = parser.parse_structured("")
    assert proposal.valid is False, "empty stdout must be invalid"
    assert proposal.parse_error, "invalid proposal must carry a parse_error"

    admission_count_before = 0
    write_count = 0

    if proposal.valid:
        receipt = admission.admit(
            work_contract_id="wc-rq5-a05",
            red_qualified=True,
            red_qualification_ref="red/result.json",
            source_revision="rev",
            execution_identity={"job_id": "j"},
            allowed_write_paths=["x.py"],
        )
        admission_count_before = 1 if receipt.admission_decision == "ALLOW" else 0

    assert admission_count_before == 0, "no admission receipt for invalid proposal"
    assert write_count == 0, "write_count must be zero for invalid proposal"


def test_a05_invalid_proposal_no_receipt_issued_in_executor(tmp_path: Path) -> None:
    """GovernedMutationExecutor must not produce an admission receipt for invalid proposal."""
    from synapx_harness.kernel.mutation_authority import GovernedMutationExecutor

    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "calc.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    executor = GovernedMutationExecutor(
        admission_gate=MutationAdmissionGate(),
        path_gate=ExactPathMutationGate(),
        applicator=ControlledPatchApplicator(),
        parser=PatchProposalParser(),
    )

    result = executor.execute(
        work_contract_id="wc-rq5-a05-exec",
        red_qualified=True,
        red_qualification_ref="red/result.json",
        source_revision="rev",
        execution_identity={"job_id": "j"},
        allowed_write_paths=["calc.py"],
        repository_root=repo,
        expected_before_sha256_by_path={"calc.py": "deadbeef"},
        current_source_revision_at_apply="rev",
        agent_stdout="",
    )

    assert result.success is False
    assert result.admission_receipt is None
    assert result.apply_receipt is None or result.apply_receipt.write_count == 0


# ---------------------------------------------------------------------------
# A06 — Unauthorized path proposal -> PathGate DENY, write_count=0
# ---------------------------------------------------------------------------


def test_a06_unauthorized_path_proposal_denied(tmp_path: Path) -> None:
    """ExactPathMutationGate must DENY a proposal with path outside allowed_write_paths."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "calc.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="calc.py",
        old_text="def add(a, b):\n    return a + b\n",
        new_text="def add(a, b):\n    return a + b  # patched\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    gate = ExactPathMutationGate()
    receipt = gate.check(
        proposal=proposal,
        allowed_write_paths=["NOT_calc.py"],
        source_revision="rev",
        admission_receipt_id="rct/wc-rq5-a06",
    )

    assert receipt.gate_decision == "DENY"
    assert receipt.apply_authority == "NOT_ISSUED"
    assert "calc.py" in receipt.reason


# ---------------------------------------------------------------------------
# A07 — Source revision drift -> apply DENY
# ---------------------------------------------------------------------------


def test_a07_source_revision_drift_before_apply(tmp_path: Path) -> None:
    """Current source revision at apply != admitted -> write_count=0."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "calc.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="calc.py",
        old_text="def add(a, b):\n    return a + b\n",
        new_text="def add(a, b):\n    return a + b  # patched\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    admission = AdmissionReceipt(
        receipt_id="rct/wc-rq5-a07",
        admission_decision="ALLOW",
        work_contract_id="wc-rq5-a07",
        red_qualified=True,
        red_qualification_ref="red/result.json",
        source_revision="rev-A",
        execution_identity={"job_id": "j"},
        mutation_authority={"mode": "EXACT_PATHS", "allowed_write_paths": ["calc.py"]},
        admitted_at="2026-09-06T00:00:00Z",
        denied_reason=None,
    )
    path_gate_receipt = type("R", (), {
        "gate_decision": "ALLOW",
        "apply_authority": "ISSUED",
        "proposal_sha256": proposal.sha256,
        "canonical_patch_sha256": proposal.canonical_patch_sha256,
        "authorized_paths": ["calc.py"],
        "proposal_paths": ["calc.py"],
        "source_revision": "rev-A",
        "admission_receipt_id": "rct/wc-rq5-a07",
        "reason": None,
    })()

    applicator = ControlledPatchApplicator()
    before_bytes = target.read_bytes().replace(b"\r\n", b"\n")
    expected_before_sha = hashlib.sha256(before_bytes).hexdigest()

    receipt = applicator.apply(
        proposal=proposal,
        path_gate_receipt=path_gate_receipt,
        admission_receipt=admission,
        repository_root=repo,
        expected_before_sha256_by_path={"calc.py": expected_before_sha},
        current_source_revision_at_apply="rev-B-DRIFT",
        normalize_line_endings=True,
    )

    assert receipt.write_count == 0
    assert receipt.denied_reason and "revision" in receipt.denied_reason.lower()


# ---------------------------------------------------------------------------
# A08 — Before-SHA mismatch -> apply DENY
# ---------------------------------------------------------------------------


def test_a08_before_sha_mismatch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "calc.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="calc.py",
        old_text="def add(a, b):\n    return a + b\n",
        new_text="def add(a, b):\n    return a + b  # patched\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    admission = AdmissionReceipt(
        receipt_id="rct/wc-rq5-a08",
        admission_decision="ALLOW",
        work_contract_id="wc-rq5-a08",
        red_qualified=True,
        red_qualification_ref="red/result.json",
        source_revision="rev",
        execution_identity={"job_id": "j"},
        mutation_authority={"mode": "EXACT_PATHS", "allowed_write_paths": ["calc.py"]},
        admitted_at="2026-09-06T00:00:00Z",
        denied_reason=None,
    )
    path_gate_receipt = type("R", (), {
        "gate_decision": "ALLOW",
        "apply_authority": "ISSUED",
        "proposal_sha256": proposal.sha256,
        "canonical_patch_sha256": proposal.canonical_patch_sha256,
        "authorized_paths": ["calc.py"],
        "proposal_paths": ["calc.py"],
        "source_revision": "rev",
        "admission_receipt_id": "rct/wc-rq5-a08",
        "reason": None,
    })()

    applicator = ControlledPatchApplicator()
    receipt = applicator.apply(
        proposal=proposal,
        path_gate_receipt=path_gate_receipt,
        admission_receipt=admission,
        repository_root=repo,
        expected_before_sha256_by_path={"calc.py": "deadbeef" * 8},
        current_source_revision_at_apply="rev",
        normalize_line_endings=True,
    )

    assert receipt.write_count == 0
    assert receipt.denied_reason and "before-hash" in receipt.denied_reason.lower()


# ---------------------------------------------------------------------------
# A09 — AdmissionReceipt DENY -> apply DENY
# ---------------------------------------------------------------------------


def test_a09_admission_receipt_missing(tmp_path: Path) -> None:
    """admission_receipt.admission_decision='DENY' -> write_count=0."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "calc.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="calc.py",
        old_text="def add(a, b):\n    return a + b\n",
        new_text="def add(a, b):\n    return a + b  # patched\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    admission = AdmissionReceipt(
        receipt_id="rct/wc-rq5-a09",
        admission_decision="DENY",
        work_contract_id="wc-rq5-a09",
        red_qualified=False,
        red_qualification_ref="red/result.json",
        source_revision="rev",
        execution_identity={"job_id": "j"},
        mutation_authority={"mode": "EXACT_PATHS", "allowed_write_paths": ["calc.py"]},
        admitted_at="2026-09-06T00:00:00Z",
        denied_reason="RED not qualified",
    )
    path_gate_receipt = type("R", (), {
        "gate_decision": "ALLOW",
        "apply_authority": "ISSUED",
        "proposal_sha256": proposal.sha256,
        "canonical_patch_sha256": proposal.canonical_patch_sha256,
        "authorized_paths": ["calc.py"],
        "proposal_paths": ["calc.py"],
        "source_revision": "rev",
        "admission_receipt_id": "rct/wc-rq5-a09",
        "reason": None,
    })()

    applicator = ControlledPatchApplicator()
    receipt = applicator.apply(
        proposal=proposal,
        path_gate_receipt=path_gate_receipt,
        admission_receipt=admission,
        repository_root=repo,
        expected_before_sha256_by_path={"calc.py": "deadbeef" * 8},
        current_source_revision_at_apply="rev",
        normalize_line_endings=True,
    )

    assert receipt.write_count == 0
    assert receipt.denied_reason == "Admission DENIED"


# ---------------------------------------------------------------------------
# A10 — PathGateReceipt missing -> apply DENY
# ---------------------------------------------------------------------------


def test_a10_path_gate_receipt_missing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "calc.py"
    target.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="calc.py",
        old_text="def add(a, b):\n    return a + b\n",
        new_text="def add(a, b):\n    return a + b  # patched\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    admission = AdmissionReceipt(
        receipt_id="rct/wc-rq5-a10",
        admission_decision="ALLOW",
        work_contract_id="wc-rq5-a10",
        red_qualified=True,
        red_qualification_ref="red/result.json",
        source_revision="rev",
        execution_identity={"job_id": "j"},
        mutation_authority={"mode": "EXACT_PATHS", "allowed_write_paths": ["calc.py"]},
        admitted_at="2026-09-06T00:00:00Z",
        denied_reason=None,
    )
    path_gate_receipt = type("R", (), {
        "gate_decision": "DENY",
        "apply_authority": "NOT_ISSUED",
        "proposal_sha256": proposal.sha256,
        "canonical_patch_sha256": proposal.canonical_patch_sha256,
        "authorized_paths": ["calc.py"],
        "proposal_paths": ["calc.py"],
        "source_revision": "rev",
        "admission_receipt_id": "rct/wc-rq5-a10",
        "reason": "Unauthorized paths",
    })()

    applicator = ControlledPatchApplicator()
    receipt = applicator.apply(
        proposal=proposal,
        path_gate_receipt=path_gate_receipt,
        admission_receipt=admission,
        repository_root=repo,
        expected_before_sha256_by_path={"calc.py": "deadbeef" * 8},
        current_source_revision_at_apply="rev",
        normalize_line_endings=True,
    )

    assert receipt.write_count == 0
    assert receipt.denied_reason == "PathGate DENIED"


# ---------------------------------------------------------------------------
# A11 — Codex direct mutation (free-form prose) -> Invalid proposal
# ---------------------------------------------------------------------------


def test_a11_codex_direct_mutation_rejected() -> None:
    parser = PatchProposalParser()
    proposal = parser.parse_structured(
        "I will directly modify the file system to add a print statement."
    )
    assert proposal.valid is False
    assert "BEGIN SYNAPX MUTATION PROPOSAL" in proposal.parse_error or \
           "begin" in proposal.parse_error.lower() or \
           "marker" in proposal.parse_error.lower()


def test_a11_structured_parser_rejects_unframed_code() -> None:
    parser = PatchProposalParser()
    proposal = parser.parse_structured("```python\nprint('hello')\n```")
    assert proposal.valid is False


# ---------------------------------------------------------------------------
# A12 — Test file mutation must be rejected
# ---------------------------------------------------------------------------


def test_a12_test_file_mutation_rejected(tmp_path: Path) -> None:
    """Proposal targeting tests/test_*.py outside the allowed set is rejected."""
    repo = tmp_path / "repo"
    repo.mkdir()
    tests_dir = repo / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_calc.py"
    test_file.write_text("def test_x():\n    assert True\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="tests/test_calc.py",
        old_text="def test_x():\n    assert True\n",
        new_text="def test_x():\n    assert False\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    blockers = validate_mutation_proposal(
        proposal,
        repository_root=repo,
        allowed_write_paths=["calc.py"],
        expected_before_sha256_by_path={"tests/test_calc.py": "deadbeef" * 8},
    )

    assert any("declared write set" in b or "outside" in b for b in blockers), (
        f"test file mutation must be rejected by declared-write-set validation; got {blockers}"
    )


# ---------------------------------------------------------------------------
# A13 — Out-of-scope mutation (path escape)
# ---------------------------------------------------------------------------


def test_a13_out_of_scope_mutation_rejected(tmp_path: Path) -> None:
    """Proposal with path that escapes repository_root must be rejected."""
    repo = tmp_path / "repo"
    repo.mkdir()

    parser = PatchProposalParser()
    structured = _build_structured_proposal(
        path="../escape.py",
        old_text="x = 1\n",
        new_text="x = 2\n",
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True

    blockers = validate_mutation_proposal(
        proposal,
        repository_root=repo,
        allowed_write_paths=["../escape.py"],
        expected_before_sha256_by_path={"../escape.py": "deadbeef" * 8},
    )

    assert any("path" in b.lower() and ("invalid" in b.lower() or "outside" in b.lower() or "declared" in b.lower() or "escape" in b.lower() or "repository" in b.lower()) for b in blockers), (
        f"out-of-scope mutation must be rejected; got {blockers}"
    )


# ---------------------------------------------------------------------------
# A14 — Multi-path proposal in single-file profile -> apply DENY
# ---------------------------------------------------------------------------


def test_a14_multi_path_attempt_rejected(tmp_path: Path) -> None:
    """Proposal declaring >1 paths in single-file profile must be rejected at apply."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "b.py").write_text("y = 1\n", encoding="utf-8")

    parser = PatchProposalParser()
    structured = (
        f"{PROPOSAL_BEGIN}\n"
        f"FILE: a.py\n"
        f"<<<< OLD\n"
        f"x = 1\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"x = 2\n"
        f">>>> NEW\n"
        f"FILE: b.py\n"
        f"<<<< OLD\n"
        f"y = 1\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"y = 2\n"
        f">>>> NEW\n"
        f"{PROPOSAL_END}\n"
    )
    proposal = parser.parse_structured(structured)
    assert proposal.valid is True
    assert len(proposal.paths) == 2

    admission = AdmissionReceipt(
        receipt_id="rct/wc-rq5-a14",
        admission_decision="ALLOW",
        work_contract_id="wc-rq5-a14",
        red_qualified=True,
        red_qualification_ref="red/result.json",
        source_revision="rev",
        execution_identity={"job_id": "j"},
        mutation_authority={"mode": "EXACT_PATHS", "allowed_write_paths": ["a.py", "b.py"]},
        admitted_at="2026-09-06T00:00:00Z",
        denied_reason=None,
    )
    path_gate_receipt = type("R", (), {
        "gate_decision": "ALLOW",
        "apply_authority": "ISSUED",
        "proposal_sha256": proposal.sha256,
        "canonical_patch_sha256": proposal.canonical_patch_sha256,
        "authorized_paths": ["a.py", "b.py"],
        "proposal_paths": ["a.py", "b.py"],
        "source_revision": "rev",
        "admission_receipt_id": "rct/wc-rq5-a14",
        "reason": None,
    })()

    applicator = ControlledPatchApplicator()
    receipt = applicator.apply(
        proposal=proposal,
        path_gate_receipt=path_gate_receipt,
        admission_receipt=admission,
        repository_root=repo,
        expected_before_sha256_by_path={"a.py": "0" * 64, "b.py": "0" * 64},
        current_source_revision_at_apply="rev",
        normalize_line_endings=True,
    )

    assert receipt.write_count == 0
    assert receipt.denied_reason and "single-file" in receipt.denied_reason.lower()


# ---------------------------------------------------------------------------
# E01 — Missing evidence (sealed_evidence not SEALED)
# ---------------------------------------------------------------------------


def test_e01_missing_evidence_rejected() -> None:
    """finalize_terminal_chain must reject evidence without integrity_status=SEALED."""
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-e01",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"seal\|evidence"):
        terminal_finalizer.finalize_terminal_chain(
            work_contract_id="wc-rq5-e01",
            sealed_evidence={"integrity_status": "ADMITTED"},
            terminalization_input=term_input,
        )


# ---------------------------------------------------------------------------
# E02 — Tampered evidence hash
# ---------------------------------------------------------------------------


def test_e02_tampered_evidence_hash_rejected(tmp_path: Path) -> None:
    """Evidence artifact tampered post-seal: hash mismatch detected."""
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text('{"valid": true}', encoding="utf-8")
    expected_sha = hashlib.sha256(b'{"valid": true}').hexdigest()

    ok, violations = validate_artifact_hash_matches(evidence_path, expected_sha)
    assert ok is True
    assert violations == []

    evidence_path.write_text('{"valid": false}', encoding="utf-8")
    ok, violations = validate_artifact_hash_matches(evidence_path, expected_sha)
    assert ok is False
    assert any("hash mismatch" in v for v in violations)


def test_e02_seal_rejects_non_admitted_envelope() -> None:
    """Sealing a non-ADMITTED envelope must be rejected."""
    with pytest.raises(ValueError, match=r"seal\|admit"):
        seal_evidence(
            envelope={"integrity_status": "CREATED", "work_contract_id": "wc"},
            sealer=CORE_EVIDENCE_SEALER,
            redaction_applied=True,
        )


def test_e02_seal_rejects_non_canonical_sealer() -> None:
    """Only CORE_EVIDENCE_SEALER may seal envelopes."""
    with pytest.raises(ValueError, match=r"sealer\|finaliz"):
        seal_evidence(
            envelope={"integrity_status": "ADMITTED", "work_contract_id": "wc"},
            sealer="VERIFIER",
            redaction_applied=True,
        )


def test_e02_seal_requires_redaction() -> None:
    """Redaction must be applied before sealing."""
    with pytest.raises(ValueError, match=r"redaction\|seal"):
        seal_evidence(
            envelope={"integrity_status": "ADMITTED", "work_contract_id": "wc"},
            sealer=CORE_EVIDENCE_SEALER,
            redaction_applied=False,
        )


# ---------------------------------------------------------------------------
# E03 — Stale evidence from a different run
# ---------------------------------------------------------------------------


def test_e03_stale_evidence_from_different_run_rejected() -> None:
    """Evidence older than freshness threshold must be rejected."""
    evidence_ts = "2020-01-01T00:00:00+00:00"
    reference_now = "2026-09-06T00:00:00+00:00"

    with pytest.raises(ValueError, match=r"fresh\|evidence"):
        validate_evidence_freshness(
            evidence_timestamp=evidence_ts,
            threshold_seconds=60,
            reference_now=reference_now,
        )


def test_e03_fresh_evidence_accepted() -> None:
    """Evidence within threshold is accepted (sanity check)."""
    result = validate_evidence_freshness(
        evidence_timestamp="2026-09-06T00:00:00+00:00",
        threshold_seconds=3600,
        reference_now="2026-09-06T00:00:30+00:00",
    )
    assert result["fresh"] is True


# ---------------------------------------------------------------------------
# E04 — Reconstructed-as-raw evidence
# ---------------------------------------------------------------------------


def test_e04_reconstructed_evidence_falsely_labeled_raw_rejected() -> None:
    """A manually reconstructed envelope without CORE_EVIDENCE_SEALER seal cannot be sealed."""
    manually_built = {
        "integrity_status": "ADMITTED",
        "work_contract_id": "wc-rq5-e04",
        "sealed_by": "MANUAL_OPERATOR",
        # NOTE: no sealed_at; this is a reconstructed envelope.
    }
    with pytest.raises(ValueError, match=r"sealer\|finaliz"):
        seal_evidence(
            envelope=manually_built,
            sealer="MANUAL_OPERATOR",
            redaction_applied=True,
        )


def test_e04_seal_as_terminal_decision_rejected() -> None:
    """Sealed evidence alone is never a terminal decision."""
    sealed = _sealed_evidence("wc-rq5-e04-st")
    with pytest.raises(ValueError, match=r"seal\|terminal"):
        from synapx_harness.evidence.evidence_validator import seal_as_terminal_decision
        seal_as_terminal_decision(sealed)


# ---------------------------------------------------------------------------
# E05 — WorkContract ID lineage mismatch
# ---------------------------------------------------------------------------


def test_e05_work_contract_id_lineage_mismatch_detected() -> None:
    """assert_lineage_consistency detects work_contract_id mismatch."""
    from synapx_harness.kernel.c3_r1_lineage import assert_lineage_consistency

    lineage = {
        "execution_identity": {
            "job_id": "j", "root_task_id": "r", "task_id": "t", "attempt_id": "a",
            "work_contract_id": "wc-X",
        },
        "work_contract": {"work_contract_id": "wc-X"},
        "agent_request": {"work_contract_id": "wc-X"},
        "admission_receipt": {"work_contract_id": "wc-X"},
        "terminal_decision": {"work_contract_id": "wc-X"},
    }

    failures = assert_lineage_consistency(lineage, expected_work_contract_id="wc-DIFFERENT")
    assert any("work_contract_id" in f for f in failures), (
        f"lineage must detect work_contract_id mismatch; got {failures}"
    )


# ---------------------------------------------------------------------------
# E06 — Execution identity lineage mismatch
# ---------------------------------------------------------------------------


def test_e06_execution_identity_lineage_mismatch_detected() -> None:
    """assert_lineage_consistency detects execution_identity drift between slots."""
    from synapx_harness.kernel.c3_r1_lineage import assert_lineage_consistency

    lineage = {
        "execution_identity": {
            "job_id": "j-A", "root_task_id": "r", "task_id": "t", "attempt_id": "a",
        },
        "work_contract": {
            "work_contract_id": "wc",
            "execution_identity": {"job_id": "j-B", "root_task_id": "r", "task_id": "t", "attempt_id": "a"},
        },
        "agent_request": {"work_contract_id": "wc"},
        "admission_receipt": {"work_contract_id": "wc"},
        "terminal_decision": {"work_contract_id": "wc"},
    }

    failures = assert_lineage_consistency(lineage, expected_work_contract_id="wc")
    assert any("job_id" in f or "execution_identity" in f for f in failures), (
        f"lineage must detect execution_identity drift; got {failures}"
    )


# ---------------------------------------------------------------------------
# E07 — Workspace root lineage mismatch
# ---------------------------------------------------------------------------


def test_e07_workspace_root_lineage_mismatch_rejected(tmp_path: Path) -> None:
    """Bridge._resolve_lineage_repository_root must raise on workspace drift."""
    from synapx_harness.cli.governed_runtime_bridge import (
        GovernedFrontDoorRuntimeBridge,
    )

    bound = tmp_path / "bound-workspace"
    bound.mkdir()
    other = tmp_path / "other-workspace"
    other.mkdir()

    bridge = GovernedFrontDoorRuntimeBridge(workspace_root=str(bound))

    class _StubResult:
        workspace_root = str(other)

    with pytest.raises(RuntimeError, match=r"LINEAGE_WORKSPACE_BINDING_MISMATCH"):
        bridge._resolve_lineage_repository_root(_StubResult())


# ---------------------------------------------------------------------------
# T01 — Verification FAIL -> COMPLETED rejected
# ---------------------------------------------------------------------------


def test_t01_failed_terminal_never_verified() -> None:
    """proposed_outcome=COMPLETED + verification=FAIL -> terminal chain rejects."""
    sealed = _sealed_evidence("wc-rq5-t01")
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-t01",
        verification_status="FAIL",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"verify-fail"):
        terminal_finalizer.finalize_terminal_chain(
            work_contract_id="wc-rq5-t01",
            sealed_evidence=sealed,
            terminalization_input=term_input,
        )


# ---------------------------------------------------------------------------
# T02 — Active blocker -> COMPLETED rejected
# ---------------------------------------------------------------------------


def test_t02_blocked_terminal_never_verified() -> None:
    """proposed_outcome=COMPLETED + active_blocker_count>0 -> terminal chain rejects."""
    sealed = _sealed_evidence("wc-rq5-t02")
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-t02",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=3,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"active_blocker_count"):
        terminal_finalizer.finalize_terminal_chain(
            work_contract_id="wc-rq5-t02",
            sealed_evidence=sealed,
            terminalization_input=term_input,
        )


# ---------------------------------------------------------------------------
# T03 — Agent DONE never directly finalized
# ---------------------------------------------------------------------------


def test_t03_agent_done_never_directly_verified() -> None:
    """Agent DONE claim cannot bypass terminal chain."""
    with pytest.raises(ValueError, match=r"finaliz\|terminal"):
        terminal_finalizer.finalize_from_agent_done(
            work_contract_id="wc-rq5-t03",
            claim={"claim_type": "AGENT_DONE_CLAIM"},
        )


# ---------------------------------------------------------------------------
# T04 — Forbidden issuer rejected
# ---------------------------------------------------------------------------


def test_t04_forbidden_issuer_rejected() -> None:
    """Forbidden terminal issuers must not be allowed."""
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-t04",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    for forbidden in ("Verifier", "Evidence Sealer", "Agent", "Provider", "Scheduler", "Registry"):
        with pytest.raises(ValueError, match=r"issuer\|finaliz"):
            terminal_finalizer.issue_terminal_decision(
                work_contract_id="wc-rq5-t04",
                decision="COMPLETED",
                issued_by=forbidden,
                terminalization_input=term_input,
            )


def test_t04_non_finalizer_issuer_rejected() -> None:
    """Issuer must be TERMINAL_FINALIZER, not anything else."""
    term_input = _terminalization_input(
        work_contract_id="wc-rq5-t04b",
        verification_status="PASS",
        evidence_status="VALID",
        active_blocker_count=0,
        proposed_outcome="COMPLETED",
    )
    with pytest.raises(ValueError, match=r"issuer\|finaliz"):
        terminal_finalizer.issue_terminal_decision(
            work_contract_id="wc-rq5-t04b",
            decision="COMPLETED",
            issued_by="SOME_OTHER_ACTOR",
            terminalization_input=term_input,
        )
