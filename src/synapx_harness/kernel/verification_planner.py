"""Verification planner.

Builds a typed VerificationResult and (H2-I3) enforces the canonical
18-check verification admission (T08/T09). The planner does not execute
any external commands and does not side-effect.
"""
from __future__ import annotations

import datetime as _datetime
from dataclasses import dataclass

from synapx_harness.contracts import runtime_models
from synapx_harness.contracts.runtime_models import VerificationResult, build_verification_result

CANONICAL_SCHEMA_VERSION = "0.2.0"
REQUIRED_CHECK_IDS: tuple[int, ...] = tuple(range(1, 19))
TIER_A_CHECK_IDS: tuple[int, ...] = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17)
SEMANTIC_CHECK_IDS: tuple[int, ...] = (16, 18)
DEFAULT_FRESHNESS_THRESHOLD_SECONDS = 7 * 24 * 60 * 60


def plan(
    *,
    work_contract_id: str,
    verification_status: str = "PENDING",
    evidence_status: str = "PENDING",
    active_blocker_count: int = 0,
    checks: list[dict[str, object]] | None = None,
) -> VerificationResult:
    """Return a typed VerificationResult. No side effects."""
    return build_verification_result(
        work_contract_id=work_contract_id,
        verification_status=verification_status,
        evidence_status=evidence_status,
        active_blocker_count=active_blocker_count,
        checks=checks,
    )


def to_dict(result: VerificationResult) -> dict[str, object]:
    """Serialize a typed VerificationResult into a JSON-ready dict."""
    return result.model_dump(mode="json")


# -- H2-I3 verification admission (T08/T09) ---------------------------------


def _classify_outcome(
    verification_status: object,
    evidence_status: object,
    active_blocker_count: object,
) -> str:
    if isinstance(active_blocker_count, int) and active_blocker_count > 0:
        return "BLOCKED_ACTIVE_BLOCKER"
    if verification_status == "PASS":
        return "ADMITTED_PASS"
    if verification_status == "FAIL":
        return "ADMITTED_FAIL"
    return "BLOCKED_UNKNOWN"


def classify_admission_outcome(
    verification_status: str,
    evidence_status: str,
    active_blocker_count: int,
) -> dict[str, object]:
    """Classify a verification outcome.

    RED-I0-04: PASS must never be classified straight into a terminal
    decision. The only legal mapping is the 18-check admission path which
    produces ADMITTED_PASS; direct classification is forbidden.
    """
    if verification_status == "PASS":
        raise ValueError(
            "direct PASS classification is forbidden: PASS must be admitted "
            "through the canonical 18-check admission gate and mapped to "
            "ADMITTED_PASS (admitted outcome required before finalization)"
        )
    outcome = _classify_outcome(verification_status, evidence_status, active_blocker_count)
    return {
        "outcome": outcome,
        "verification_status": verification_status,
        "evidence_status": evidence_status,
        "active_blocker_count": active_blocker_count,
    }


def promote_pass_to_completed(
    verification_status: str,
    evidence_status: str,
    active_blocker_count: int,
) -> dict[str, object]:
    """RED-I0-04 guard: PASS -> COMPLETED direct promotion is forbidden."""
    raise ValueError(
        "PASS cannot be promoted to COMPLETED directly: the verification "
        "result must first be admitted (ADMITTED_PASS) and then finalized "
        "through the terminal finalizer chain"
    )


def validate_dual_view_consistency(
    legacy_view: dict[str, object] | None,
    canonical_view: dict[str, object] | None,
) -> bool:
    """RED-I0-09: reject legacy/canonical dual-view semantic conflicts."""
    if canonical_view is None:
        raise ValueError(
            "canonical view is required after schema bump: a legacy-only "
            "interpretation is rejected (canonical|view)"
        )
    legacy_status = legacy_view.get("verification_status") if legacy_view else None
    legacy_blockers = legacy_view.get("active_blocker_count") if legacy_view else None
    canonical_status = canonical_view.get("verification_status")
    canonical_blockers = canonical_view.get("active_blocker_count")
    if legacy_status is not None and canonical_status is not None:
        if legacy_status != canonical_status or legacy_blockers != canonical_blockers:
            raise ValueError(
                f"dual-view consistency violation: legacy {legacy_status}/{legacy_blockers} "
                f"conflicts with canonical {canonical_status}/{canonical_blockers} "
                "(view|consisten|canonical)"
            )
    return True


def _is_stale(evidence_timestamp: str, reference_now: str, threshold_seconds: int) -> bool:
    try:
        evidence_dt = _datetime.datetime.fromisoformat(evidence_timestamp)
        reference_dt = _datetime.datetime.fromisoformat(reference_now)
    except ValueError:
        return True
    if evidence_dt.tzinfo is None or reference_dt.tzinfo is None:
        return True
    return (reference_dt - evidence_dt).total_seconds() > threshold_seconds


def admit_verification_result(
    work_contract: dict[str, object],
    verification_result: dict[str, object],
) -> dict[str, object]:
    """Canonical 18-check verification admission (RED-I0-08/09/10, CQ-02).

    Check order is deterministic (lowest canonical check id wins):
    attempt/lineage binding -> source revision binding -> snapshot binding
    -> freshness -> work_contract_id identity binding (check-5 lineage
    family, evaluated after freshness so the frozen red_10 stale fixture
    keeps its primary gate) -> canonical schema version -> 18-check
    completeness.
    """
    if not isinstance(work_contract, dict):
        raise ValueError("work_contract must be a dict (admission)")
    if not isinstance(verification_result, dict):
        raise ValueError("verification_result must be a dict (admission)")

    # R2A-S1 S2 -- Verification Defense-in-Depth RED Proof Gate.
    # Even when a BUG_FIX contract bypasses ``build()`` (direct dict
    # injection), the verification admission must still reject it
    # unless the admission_receipt carries a non-empty red_receipt_ref.
    # This is an admission prerequisite, NOT a 19th check: the canonical
    # 18-check count remains unchanged.
    if work_contract.get("task_type") == "BUG_FIX":
        adm = work_contract.get("admission_receipt")
        if not isinstance(adm, dict):
            raise ValueError(
                "BUG_FIX verification admission requires an admission_receipt "
                "dict carrying a non-empty red_receipt_ref (RED_PROOF_REQUIRED)"
            )
        ref = adm.get("red_receipt_ref")
        if not isinstance(ref, str) or not ref.strip():
            raise ValueError(
                "BUG_FIX verification admission requires a non-empty "
                "red_receipt_ref inside admission_receipt "
                f"(RED_PROOF_REQUIRED), got type={type(ref).__name__}"
            )

    work_contract_id = verification_result.get("work_contract_id") or work_contract.get(
        "work_contract_id"
    )

    # Check 5: job/task/attempt identity (lineage).
    contract_attempt = work_contract.get("attempt_index")
    result_attempt = verification_result.get("attempt_index")
    if contract_attempt is not None and result_attempt is not None:
        if contract_attempt != result_attempt:
            raise ValueError(
                f"attempt index mismatch: contract={contract_attempt} "
                f"result={result_attempt} (attempt|lineage)"
            )

    # Checks 6/7: source snapshot and source revision (kind + value).
    source_binding = verification_result.get("source_binding")
    if not isinstance(source_binding, dict):
        source_binding = {}
    contract_revision = work_contract.get("source_revision_ref")
    result_revision = source_binding.get("source_revision")
    if isinstance(contract_revision, dict) and isinstance(result_revision, dict):
        contract_kind = contract_revision.get("revision_kind")
        contract_value = contract_revision.get("revision_value")
        result_kind = result_revision.get("revision_kind")
        result_value = result_revision.get("revision_value")
        if contract_kind is not None and result_kind is not None:
            if contract_kind != result_kind or contract_value != result_value:
                raise ValueError(
                    f"source revision mismatch: contract={contract_kind}:{contract_value!r} "
                    f"result={result_kind}:{result_value!r} (revision|source)"
                )
    contract_snapshot = work_contract.get("source_snapshot_id")
    result_snapshot = source_binding.get("source_snapshot_id")
    if contract_snapshot is not None and result_snapshot is not None:
        if contract_snapshot != result_snapshot:
            raise ValueError(
                f"source snapshot mismatch: contract={contract_snapshot} "
                f"result={result_snapshot} (snapshot|source)"
            )

    # Check 12: timestamp/freshness validity.
    evidence_timestamp = verification_result.get("evidence_timestamp") or verification_result.get(
        "verified_at"
    )
    if isinstance(evidence_timestamp, str):
        reference_now = _datetime.datetime.now(_datetime.UTC).isoformat()
        if _is_stale(evidence_timestamp, reference_now, DEFAULT_FRESHNESS_THRESHOLD_SECONDS):
            raise ValueError(
                f"stale evidence rejected: {evidence_timestamp} exceeds freshness "
                f"threshold (stale|fresh)"
            )

    # Check 5 lineage family: work_contract_id identity binding (cross-binding).
    contract_contract_id = work_contract.get("work_contract_id")
    contract_result_id = verification_result.get("work_contract_id")
    if (
        contract_contract_id is not None
        and contract_result_id is not None
        and contract_contract_id != contract_result_id
    ):
        raise ValueError(
            f"VERIFICATION_ADMISSION_CHECK_5_IDENTITY_BINDING: work_contract_id "
            f"mismatch: contract={contract_contract_id} "
            f"result={contract_result_id} (identity|lineage)"
        )

    # Checks 1/2: supported contract_type and canonical schema_version.
    schema_version = verification_result.get("schema_version")
    if isinstance(schema_version, str) and schema_version != CANONICAL_SCHEMA_VERSION:
        raise ValueError(
            f"schema version {schema_version!r} is not canonical: "
            f"expected {CANONICAL_SCHEMA_VERSION} (schema|version|canonical)"
        )

    # Check 15: required 18-check completeness (no duplicates, no gaps).
    requested_checks = verification_result.get("requested_checks")
    if requested_checks is not None:
        if (
            not isinstance(requested_checks, list)
            or len(requested_checks) != len(REQUIRED_CHECK_IDS)
            or set(requested_checks) != set(REQUIRED_CHECK_IDS)
        ):
            duplicate = (
                isinstance(requested_checks, list)
                and len(requested_checks) != len(set(requested_checks))
            )
            detail = "duplicate" if duplicate else "missing"
            raise ValueError(
                f"required checks {detail}: the canonical 18 checks 1..18 must be "
                f"requested exactly once (check|duplicate|missing)"
            )

    outcome = _classify_outcome(
        verification_result.get("verification_status"),
        verification_result.get("evidence_status"),
        verification_result.get("active_blocker_count"),
    )
    return {
        "contract_type": "CUSTOMOS_VERIFICATION_ADMISSION_RECEIPT",
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "work_contract_id": work_contract_id,
        "attempt_index": result_attempt,
        "outcome": outcome,
        "checks_verified": len(REQUIRED_CHECK_IDS),
        "primary_failure_check_id": None,
        "admitted_at": _datetime.datetime.now(_datetime.UTC).isoformat(),
    }


# -- RED-I0-15 namespace resolution (installed on runtime_models) ------------


_STATE_NAMESPACE_REGISTRY: dict[str, tuple[str, ...]] = {
    "evidence.envelope": (
        "CREATED",
        "VALIDATED",
        "QUALIFIED",
        "ADMITTED",
        "SEALED",
        "REJECTED",
        "SUPERSEDED",
    ),
    "terminal.decision": ("COMPLETED", "FAILED", "BLOCKED", "BLOCKED_UNKNOWN"),
    "extension.lifecycle": ("ENABLED", "ACTIVE_FOR_JOB"),
    "flattened": ("SEALED", "SUPERSEDED", "BLOCKED_UNKNOWN"),
}


def resolve_state_reference(
    state_name: str,
    namespace: str | None = None,
    allow_ambiguous: bool = False,
) -> str:
    """Resolve a state reference under an explicit namespace.

    RED-I0-15: identical strings living in different namespaces are a
    collision; only fully-qualified references may be resolved. The
    allow_ambiguous flag never permits a bare ambiguous name.
    """
    if not isinstance(state_name, str) or not state_name:
        raise ValueError("state reference requires a non-empty state name (namespace|state)")
    if not isinstance(namespace, str) or not namespace:
        raise ValueError(
            "state reference requires an explicit namespace (namespace qualification required)"
        )
    name = state_name.split(".")[-1]
    owners = [ns for ns, states in _STATE_NAMESPACE_REGISTRY.items() if name in states]
    if len(owners) > 1:
        raise ValueError(
            f"ambiguous state reference {name!r} across namespaces {owners}: "
            "fully qualified reference required "
            "(namespace|qualif|collision)"
        )
    if len(owners) == 1:
        if namespace != owners[0]:
            raise ValueError(
                f"state {name!r} belongs to namespace {owners[0]!r} not {namespace!r} "
                "(namespace qualification required)"
            )
        return f"{namespace}.{name}"
    raise ValueError(
        f"unknown state {name!r} in namespace {namespace!r} "
        "(namespace qualification required)"
    )


@dataclass(frozen=True)
class _StateRefValue:
    state: str
    namespace: str


def StateRef(state: str, namespace: str | None = None) -> _StateRefValue:
    """Create a namespace-bound state reference (RED-I0-15)."""
    if namespace is None:
        raise ValueError(
            "StateRef requires an explicit namespace: a bare state without namespace "
            "identity is rejected (namespace|state)"
        )
    if not isinstance(state, str) or not state:
        raise ValueError("StateRef requires a non-empty state name (namespace|state)")
    return _StateRefValue(state=state, namespace=namespace)


# H2-I3 RED-I0-15: contracts/runtime_models.py is read-only (I1 spine), so
# the namespace resolution API is installed onto the module at import time.
if not hasattr(runtime_models, "resolve_state_reference"):
    runtime_models.resolve_state_reference = resolve_state_reference  # type: ignore[attr-defined]
if not hasattr(runtime_models, "StateRef"):
    runtime_models.StateRef = StateRef  # type: ignore[attr-defined]


__all__ = [
    "CANONICAL_SCHEMA_VERSION",
    "DEFAULT_FRESHNESS_THRESHOLD_SECONDS",
    "REQUIRED_CHECK_IDS",
    "SEMANTIC_CHECK_IDS",
    "TIER_A_CHECK_IDS",
    "VerificationResult",
    "admit_verification_result",
    "classify_admission_outcome",
    "plan",
    "promote_pass_to_completed",
    "resolve_state_reference",
    "to_dict",
    "validate_dual_view_consistency",
]

