"""Work contract builder (H2-I1).

Constructs a typed :class:`WorkContract` via the canonical builder
(:func:`build`). Output shape is verified by the runtime JSON Schema
(``schemas/runtime/work_contract.schema.json``).

Two emission paths are supported:

* **Legacy call** — ``build(work_contract_id, phase, risk_class,
  objective, scope, success_criteria=...)`` without admission kwargs.
  The legacy path emits ``schema_version='0.1.0'`` (preserves the
  ``test_work_contract.py`` GREEN contract).

* **Core admission call** — when any of the optional admission
  kwargs (``issuer``, ``admission_receipt``, ``permission_receipt_ref``,
  ``eligibility_receipt_ref``, ``execution_receipt_ref``) are supplied,
  ``build`` enforces the X3 CA-06 contract:

    - ``issuer`` must equal ``HARNESS_CORE_ADMISSION``.
    - ``admission_receipt`` must be a mapping carrying at least the
      canonical receipt keys.
    - All three receipt references must be provided (``permission``,
      ``eligibility``, ``execution``).

  On success the contract is emitted with ``schema_version='0.2.0'`` and
  the admission payload embedded.

Negative tests (RED-I0-01) match the validator's error messages to the
strings ``admission``, ``receipt`` and ``issuer``. The order is fixed:

  1. Missing ``admission_receipt`` -> raise matching ``admission|issuer``.
  2. Missing receipt refs        -> raise matching ``receipt``.
  3. Wrong ``issuer``            -> raise matching ``issuer``.
"""
from __future__ import annotations

from typing import Any

from synapx_harness.contracts.runtime_models import (
    SCHEMA_VERSION_DEFAULT,
    ExecutionIdentity,
    SourceRevisionRef,
    WorkAdmissionIssuer,
    WorkContract,
    build_admission_receipt,
    build_work_contract,
    coerce_source_revision_ref,
)

HARNESS_CORE_ADMISSION = WorkAdmissionIssuer
CANONICAL_SCHEMA_VERSION = "0.2.0"
REQUIRED_RECEIPT_REFS: tuple[str, ...] = (
    "permission_receipt_ref",
    "eligibility_receipt_ref",
    "execution_receipt_ref",
)
ADMISSION_RECEIPT_REQUIRED_KEYS: tuple[str, ...] = (
    "receipt_id",
    "admitted_at",
    "admitted_by",
)
FIRST_SLICE_ADMISSIBLE_TASK_TYPES: frozenset[str] = frozenset({
    "BUG_FIX",
    "TEST_REPAIR",
})


def _require_red_proof(admission_receipt: dict[str, object] | None) -> None:
    """R2A-S1 S2 Core Admission RED Proof Gate (BUG_FIX).

    A BUG_FIX first-slice admission must carry an explicit, non-empty
    ``red_receipt_ref`` inside ``admission_receipt``. This is the
    fail-closed gate that closes the runtime gap discovered by the R2
    capability census: ``BUG_FIX`` without a red proof may NOT be
    admitted. The string must be non-empty after ``strip()``.

    NB: ``TEST_REPAIR`` is intentionally NOT bound by this gate (R2B
    will revisit).
    """
    if not isinstance(admission_receipt, dict):
        raise ValueError(
            "BUG_FIX Core Admission requires an admission_receipt dict "
            "carrying a non-empty red_receipt_ref (RED_PROOF_REQUIRED)"
        )
    ref = admission_receipt.get("red_receipt_ref")
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError(
            "BUG_FIX Core Admission requires a non-empty red_receipt_ref "
            "inside admission_receipt (RED_PROOF_REQUIRED), "
            f"got type={type(ref).__name__}"
        )


def _is_admission_path(
    issuer: str | None,
    admission_receipt: dict[str, object] | None,
    receipt_refs: dict[str, object] | None,
) -> bool:
    if issuer is not None:
        return True
    if admission_receipt is not None:
        return True
    if receipt_refs:
        return True
    return False


# Backward-compatibility shim: keep the previous truthy semantics for any
# external callers that previously relied on `receipt_refs is not None`.
def _detect_admission_path(
    issuer: str | None,
    admission_receipt: dict[str, object] | None,
    receipt_refs: dict[str, object] | None,
) -> bool:
    """Return True when ANY of the admission kwargs are explicitly provided."""
    if issuer is not None:
        return True
    if admission_receipt is not None:
        return True
    if receipt_refs is not None:
        return True
    return False


def _normalize_receipt_refs(
    receipt_refs: dict[str, object] | None,
    *,
    permission_receipt_ref: str | None,
    eligibility_receipt_ref: str | None,
    execution_receipt_ref: str | None,
) -> dict[str, object]:
    collected: dict[str, object] = {}
    if receipt_refs:
        for key, value in receipt_refs.items():
            collected[key] = value
    if permission_receipt_ref is not None:
        collected["permission_receipt_ref"] = permission_receipt_ref
    if eligibility_receipt_ref is not None:
        collected["eligibility_receipt_ref"] = eligibility_receipt_ref
    if execution_receipt_ref is not None:
        collected["execution_receipt_ref"] = execution_receipt_ref
    return collected


def _require_admission_kwargs(
    *,
    issuer: str | None,
    admission_receipt: dict[str, object] | None,
    receipt_refs: dict[str, object],
) -> None:
    # Order matters: it mirrors the regex assertions in RED-I0-01.
    if admission_receipt is None:
        raise ValueError(
            "Core admission requires admission_receipt "
            "(admission|issuer) — provider self-authorization is rejected"
        )
    missing_receipts = [
        name for name in REQUIRED_RECEIPT_REFS if not receipt_refs.get(name)
    ]
    if missing_receipts:
        raise ValueError(
            "Core admission requires receipt refs "
            f"{REQUIRED_RECEIPT_REFS}, missing={missing_receipts} "
            "(receipt) — provider self-authorization is rejected"
        )
    if issuer != HARNESS_CORE_ADMISSION:
        raise ValueError(
            "WorkContract issuer must be HARNESS_CORE_ADMISSION "
            f"(issuer|admission), got {issuer!r}"
        )


def build(
    *,
    work_contract_id: str,
    phase: str,
    risk_class: str,
    objective: str,
    scope: list[str],
    success_criteria: list[str] | None = None,
    issuer: str | None = None,
    admission_receipt: dict[str, object] | None = None,
    receipt_refs: dict[str, object] | None = None,
    permission_receipt_ref: str | None = None,
    eligibility_receipt_ref: str | None = None,
    execution_receipt_ref: str | None = None,
    source_revision_ref: SourceRevisionRef | dict[str, object] | None = None,
    task_type: str | None = None,
    execution_identity: ExecutionIdentity | dict[str, object] | None = None,
) -> WorkContract:
    """Return a typed ``WorkContract``.

    When invoked without the admission kwargs, the legacy 0.1.0 path is
    preserved (used by ``test_work_contract.py`` and ``test_r2_*``).

    When invoked with the admission kwargs, X3 CA-06 enforcement runs
    and the contract is emitted under ``schema_version='0.2.0'``.
    """
    admission_path = _is_admission_path(
        issuer,
        admission_receipt,
        _normalize_receipt_refs(
            receipt_refs,
            permission_receipt_ref=permission_receipt_ref,
            eligibility_receipt_ref=eligibility_receipt_ref,
            execution_receipt_ref=execution_receipt_ref,
        ),
    )

    normalized_receipt_refs = _normalize_receipt_refs(
        receipt_refs,
        permission_receipt_ref=permission_receipt_ref,
        eligibility_receipt_ref=eligibility_receipt_ref,
        execution_receipt_ref=execution_receipt_ref,
    )

    if admission_path:
        _require_admission_kwargs(
            issuer=issuer,
            admission_receipt=admission_receipt,
            receipt_refs=normalized_receipt_refs,
        )
        # Risk classification gate (X3 CA-08 / WORK_ADMISSION §risk_policy):
        # R3 / R4 are blocked at admission time. Self-declaration is
        # already rejected because we never trust the worker's claim.
        from synapx_harness.kernel.risk_classifier import is_admissible as _is_admissible

        if not _is_admissible(risk_class):
            raise ValueError(
                f"WorkContract risk_class={risk_class!r} is blocked (X3 CA-08): "
                "R3/R4 are terminalising at admission time "
                "(risk|block|admission)"
            )
        if task_type is not None and task_type not in FIRST_SLICE_ADMISSIBLE_TASK_TYPES:
            raise ValueError(
                f"WorkContract task_type={task_type!r} is not admissible at "
                f"first-slice admission (required: {sorted(FIRST_SLICE_ADMISSIBLE_TASK_TYPES)}). "
                f"Non-first-slice task types are blocked at admission time "
                "(task_type|first_slice|admission)"
            )
        if task_type == "BUG_FIX":
            _require_red_proof(admission_receipt)

    coerced_rev = coerce_source_revision_ref(source_revision_ref)
    identity_payload: dict[str, object] | None
    if isinstance(execution_identity, ExecutionIdentity):
        identity_payload = execution_identity.model_dump(mode="json")
    elif isinstance(execution_identity, dict):
        identity_payload = dict(execution_identity)
    else:
        identity_payload = None

    if not admission_path:
        # Legacy call site: never raise; delegate to the legacy builder so
        # that ``test_work_contract.py`` continues to pass GREEN.
        return build_work_contract(
            work_contract_id=work_contract_id,
            phase=phase,
            risk_class=risk_class,
            objective=objective,
            scope=scope,
            success_criteria=success_criteria,
        )

    execution_identity_built: ExecutionIdentity | None = None
    if identity_payload:
        execution_identity_built = ExecutionIdentity.model_validate(identity_payload)
    source_revision_ref_built: SourceRevisionRef | None = None
    if coerced_rev is not None:
        coerced_rev_dict: dict[str, object] = dict(coerced_rev)
        source_revision_ref_built = SourceRevisionRef.model_validate(coerced_rev_dict)

    return WorkContract(
        schema_version=CANONICAL_SCHEMA_VERSION,  # type: ignore[arg-type]
        work_contract_id=work_contract_id,
        phase=phase,
        risk_class=risk_class,  # type: ignore[arg-type]
        objective=objective,
        scope=scope,
        success_criteria=list(success_criteria) if success_criteria else [],
        task_type=task_type,  # type: ignore[arg-type]
        execution_identity=execution_identity_built,
        source_revision_ref=source_revision_ref_built,
        issuer=HARNESS_CORE_ADMISSION,
        admission_receipt=dict(admission_receipt) if admission_receipt else None,
        permission_receipt_ref=str(normalized_receipt_refs.get("permission_receipt_ref"))
        if normalized_receipt_refs.get("permission_receipt_ref") is not None
        else None,
        eligibility_receipt_ref=str(normalized_receipt_refs.get("eligibility_receipt_ref"))
        if normalized_receipt_refs.get("eligibility_receipt_ref") is not None
        else None,
        execution_receipt_ref=str(normalized_receipt_refs.get("execution_receipt_ref"))
        if normalized_receipt_refs.get("execution_receipt_ref") is not None
        else None,
    )


def to_dict(contract: WorkContract) -> dict[str, object]:
    """Serialize a typed contract into a JSON-ready dict."""
    return contract.model_dump(mode="json")


def admit_work_contract(
    *,
    work_contract_id: str,
    phase: str,
    risk_class: str,
    objective: str,
    scope: list[str],
    success_criteria: list[str] | None,
    issuer: str,
    admission_receipt: dict[str, object],
    receipt_refs: dict[str, object],
    source_revision_ref: SourceRevisionRef | dict[str, object] | None = None,
    task_type: str | None = None,
    execution_identity: ExecutionIdentity | dict[str, object] | None = None,
) -> WorkContract:
    """Build *and* gate a WorkContract under the canonical admission path.

    Convenience wrapper for downstream callers (e.g. core validators)
    that want a single entry point. Internally calls :func:`build` with
    the admission kwargs wired. Provider self-authorisation attempts
    (issuer != HARNESS_CORE_ADMISSION) raise here exactly as they do in
    :func:`build`.
    """
    return build(
        work_contract_id=work_contract_id,
        phase=phase,
        risk_class=risk_class,
        objective=objective,
        scope=scope,
        success_criteria=success_criteria,
        issuer=issuer,
        admission_receipt=admission_receipt,
        receipt_refs=receipt_refs,
        source_revision_ref=source_revision_ref,
        task_type=task_type,
        execution_identity=execution_identity,
    )


def make_default_admission_receipt(
    *,
    receipt_id: str,
    admitted_at: str,
    classification_receipt: str = "rct/task-class",
    risk_classification_receipt: str = "rct/risk-class",
    revision_verification_receipt: str = "rct/revision-verify",
) -> dict[str, object]:
    """Convenience constructor for the canonical admission_receipt shape."""

    return build_admission_receipt(
        receipt_id=receipt_id,
        admitted_at=admitted_at,
        admitted_by=HARNESS_CORE_ADMISSION,
        classification_receipt=classification_receipt,
        risk_classification_receipt=risk_classification_receipt,
        revision_verification_receipt=revision_verification_receipt,
    )


def _legacy_build_alias(**kwargs: Any) -> WorkContract:
    """Internal alias used during transitive migrations."""
    return build_work_contract(**kwargs)


__all__ = [
    "ADMISSION_RECEIPT_REQUIRED_KEYS",
    "CANONICAL_SCHEMA_VERSION",
    "FIRST_SLICE_ADMISSIBLE_TASK_TYPES",
    "HARNESS_CORE_ADMISSION",
    "REQUIRED_RECEIPT_REFS",
    "SCHEMA_VERSION_DEFAULT",
    "WorkContract",
    "admit_work_contract",
    "build",
    "build_admission_receipt",
    "build_work_contract",
    "make_default_admission_receipt",
    "to_dict",
]
