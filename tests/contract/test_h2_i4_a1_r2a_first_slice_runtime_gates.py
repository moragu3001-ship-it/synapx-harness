"""H2-I4-A1-R2A-S1 — first-slice runtime gates (RED before implementation).

Adds the canonical fail-closed gates that close the runtime gaps
discovered by the R2 capability census:

* S2 Core Admission RED Proof Gate:
  - R2A-R01 BUG_FIX + red_receipt_ref missing       -> RED_PROOF_REQUIRED
  - R2A-R02 BUG_FIX + red_receipt_ref=""           -> RED_PROOF_REQUIRED
  - R2A-R03 BUG_FIX + red_receipt_ref="   "        -> RED_PROOF_REQUIRED
  - R2A-R04 BUG_FIX + valid red_receipt_ref        -> PASS

* S2 Verification Admission Defense-in-Depth:
  - R2A-R05 BUG_FIX contract without RED           -> RED_PROOF_REQUIRED
  - R2A-R06 BUG_FIX contract with valid RED        -> ADMITTED_PASS (18)

* S3 Exact Write-Set Mutation Gate:
  - R2A-R07 mutation contract has no write:*       -> EXACT_WRITE_SET_REQUIRED
  - R2A-R08 mutation path exactly declared         -> PASS
  - R2A-R09 one mutation path outside declared set -> WRITE_SET_VIOLATION
  - R2A-R10 write:../outside.py                    -> INVALID_WRITE_SET_PATH

Forbid list (per R2A-S1 instruction):
  - runtime_models.py not modified
  - terminal_finalizer.py not modified
  - schemas/** not modified
  - frozen test files except the owner-thawed J1 admit test
"""
from __future__ import annotations

import datetime as _dt

import pytest

from synapx_harness.evidence.command_runner import (
    assert_mutation_paths_allowed,
)
from synapx_harness.kernel import work_contract_builder
from synapx_harness.kernel.verification_planner import (
    admit_verification_result,
)

RED_ID = "H2-I4-A1-R2A-S1"

_BASE_ADMISSION = {
    "receipt_id": "rec-r2a-red",
    "admitted_at": "2026-08-17T00:00:00Z",
    "admitted_by": "HARNESS_CORE_ADMISSION",
}
_BASE_RECEIPT_REFS = {
    "permission_receipt_ref": "perm-r2a",
    "eligibility_receipt_ref": "elig-r2a",
    "execution_receipt_ref": "exec-r2a",
}


def _build_kwargs(*, red_receipt_ref: str) -> dict[str, object]:
    kwargs: dict[str, object] = {}
    kwargs["work_contract_id"] = "wc-r2a-red"
    kwargs["phase"] = "H2-I4-A1-R2A-S1"
    kwargs["risk_class"] = "R2"
    kwargs["objective"] = "R2A-S1 first-slice runtime gate"
    kwargs["scope"] = ["tool:python"]
    kwargs["issuer"] = "HARNESS_CORE_ADMISSION"
    kwargs["admission_receipt"] = {
        **_BASE_ADMISSION,
        "red_receipt_ref": red_receipt_ref,
    }
    kwargs["receipt_refs"] = dict(_BASE_RECEIPT_REFS)
    kwargs["task_type"] = "BUG_FIX"
    return kwargs


def test_r2a_r01_bug_fix_missing_red_receipt_ref_rejected() -> None:
    """BUG_FIX without red_receipt_ref must be rejected at Core Admission."""
    kwargs = _build_kwargs(red_receipt_ref="ignore")
    kwargs["admission_receipt"] = dict(_BASE_ADMISSION)
    with pytest.raises(ValueError, match="RED_PROOF_REQUIRED"):
        work_contract_builder.build(**kwargs)  # type: ignore[arg-type]


def test_r2a_r02_bug_fix_empty_red_receipt_ref_rejected() -> None:
    """BUG_FIX with empty-string red_receipt_ref must be rejected."""
    with pytest.raises(ValueError, match="RED_PROOF_REQUIRED"):
        work_contract_builder.build(**_build_kwargs(red_receipt_ref=""))  # type: ignore[arg-type]


def test_r2a_r03_bug_fix_whitespace_red_receipt_ref_rejected() -> None:
    """BUG_FIX with whitespace-only red_receipt_ref must be rejected."""
    with pytest.raises(ValueError, match="RED_PROOF_REQUIRED"):
        work_contract_builder.build(**_build_kwargs(red_receipt_ref="   "))  # type: ignore[arg-type]


def test_r2a_r04_bug_fix_valid_red_receipt_ref_admitted() -> None:
    """BUG_FIX with valid red_receipt_ref must be admitted by Core Admission."""
    valid_ref = "evidence://h2-i4/a1/r2a/red-001"
    contract = work_contract_builder.build(**_build_kwargs(red_receipt_ref=valid_ref))  # type: ignore[arg-type]
    assert contract.admission_receipt is not None
    assert contract.admission_receipt["red_receipt_ref"] == valid_ref
    assert contract.task_type == "BUG_FIX"


def _verification_result_dict(work_contract_id: str = "wc-r2a-red") -> dict[str, object]:
    return {
        "work_contract_id": work_contract_id,
        "schema_version": "0.2.0",
        "verification_status": "PASS",
        "evidence_status": "VALID",
        "active_blocker_count": 0,
        "evidence_timestamp": _dt.datetime.now(_dt.UTC).isoformat(),
        "attempt_index": 0,
        "requested_checks": list(range(1, 19)),
        "source_binding": {
            "source_revision": {},
            "source_snapshot_id": "",
        },
    }


def test_r2a_r05_verification_admission_bug_fix_without_red_rejected() -> None:
    """Verification admission RED gate catches BUG_FIX without RED (defense-in-depth)."""
    work_contract = {
        "work_contract_id": "wc-r2a-red",
        "task_type": "BUG_FIX",
        "admission_receipt": dict(_BASE_ADMISSION),
    }
    with pytest.raises(ValueError, match="RED_PROOF_REQUIRED"):
        admit_verification_result(work_contract, _verification_result_dict())


def test_r2a_r06_verification_admission_bug_fix_with_red_admitted() -> None:
    """Verification admission admits BUG_FIX with valid RED, 18 checks verified."""
    work_contract = {
        "work_contract_id": "wc-r2a-red",
        "task_type": "BUG_FIX",
        "admission_receipt": {
            **_BASE_ADMISSION,
            "red_receipt_ref": "evidence://h2-i4/a1/r2a/red-verif-001",
        },
    }
    receipt = admit_verification_result(work_contract, _verification_result_dict())
    assert receipt["outcome"] == "ADMITTED_PASS"
    assert receipt["checks_verified"] == 18


def test_r2a_r07_mutation_contract_without_write_set_required() -> None:
    """Mutation gate refuses contracts without any write:* token."""
    work_contract = {"work_contract_id": "wc-r2a-w", "scope": ["tool:python"]}
    with pytest.raises(ValueError, match="EXACT_WRITE_SET_REQUIRED"):
        assert_mutation_paths_allowed(work_contract, ["src/foo.py"])


def test_r2a_r08_mutation_path_exact_pass() -> None:
    """Mutation gate passes when all observed paths are within declared write set."""
    work_contract = {
        "work_contract_id": "wc-r2a-w",
        "scope": ["tool:python", "write:src/foo.py"],
    }
    out = assert_mutation_paths_allowed(work_contract, ["src/foo.py"])
    assert out["allowed"] is True
    assert out["outside_write_set"] == []
    assert out["declared_write_set"] == ["src/foo.py"]


def test_r2a_r09_mutation_path_outside_write_set_violation() -> None:
    """Mutation gate rejects observation with a path outside the declared write set."""
    work_contract = {
        "work_contract_id": "wc-r2a-w",
        "scope": ["tool:python", "write:src/foo.py"],
    }
    with pytest.raises(ValueError, match="WRITE_SET_VIOLATION"):
        assert_mutation_paths_allowed(work_contract, ["src/foo.py", "src/bar.py"])


def test_r2a_r10_write_token_traversal_invalid_write_set_path() -> None:
    """Mutation gate rejects write tokens with parent-directory traversal."""
    work_contract = {
        "work_contract_id": "wc-r2a-w",
        "scope": ["write:../outside.py"],
    }
    with pytest.raises(ValueError, match="INVALID_WRITE_SET_PATH"):
        assert_mutation_paths_allowed(work_contract, ["outside.py"])
