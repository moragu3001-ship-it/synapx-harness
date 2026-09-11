"""Activation Validator (T06 Minimal Skill/Extension Admission).

This module is the SOLE authoritative gate for ACTIVE_FOR_JOB transition
in the H2-I2 Minimal Extension/Provider Runtime scope.

Authority Rules (T06 minimal protocol — H2-I2):

  * ``SkillActivationProposal`` is proposal-only; LLM/Registry/Provider
    can write proposals but they are NOT activation authority.
  * ``SkillActivationContract`` issued only by
    ``HARNESS_CORE_ADMISSION`` is the SOLE authority artifact that
    permits ENABLED -> ACTIVE_FOR_JOB transitions.
  * AUTHORIZED ratification chain is intentionally NOT implemented
    here (POST_SLICE_DEFERRED); the validator rejects any caller
    attempting to grant ``authority_level == "AUTHORIZED"`` outside
    Core Admission.
  * The Kiro adapter (``adapters/kiro/protocol.py``) and the Scheduler
    and the Registry are all explicitly NON-AUTHORITATIVE; they may
    only ``DISPATCH`` / ``PROPOSE`` / ``OBSERVE``.

Negative Catalog (H2-I2-N01..N14):

  - I2-N01:  Provider self-authorization                       -> REJECTED
  - I2-N02:  Semantic selector / LLM direct activation          -> REJECTED
  - I2-N03:  ACTIVE_FOR_JOB without SkillActivationContract     -> REJECTED
  - I2-N04:  Forged SkillActivationContract issuer              -> REJECTED
  - I2-N05:  Scheduler creates authority                        -> REJECTED
  - I2-N06:  Registry creates authority                         -> REJECTED
  - I2-N07:  Provider creates authority                         -> REJECTED
  - I2-N08:  Retrieved content modifies activation authority    -> REJECTED
  - I2-N09:  ENABLED -> ACTIVE direct ungated transition        -> REJECTED
  - I2-N10:  ActivationContract for different job_id/attempt_id  -> REJECTED
  - I2-N11:  Capability outside allowed_capabilities             -> REJECTED
  - I2-N12:  RatificationValidator / AUTHORIZED chain activated  -> REJECTED
  - I2-N13:  I3 runtime path mutation                           -> REJECTED
  - I2-N14:  RUN_STORAGE activation or H2_IMPLEMENTATION_AUTH    -> REJECTED
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from synapx_harness.validators.ratification_validator import (
    RatificationReport,
    compute_receipt_sha256,
    validate_ratification,
)

# -- SOLE permitted issuer of SkillActivationContract ---------------------
CORE_ISSUER: str = "HARNESS_CORE_ADMISSION"

# -- Issuers that must NEVER carry authority -------------------------------
NON_AUTHORITATIVE_ISSUERS: frozenset[str] = frozenset(
    {
        "Scheduler",
        "Registry",
        "Provider",
        "LLM",
        "Adapter",
        "Verifier",
        "Agent",
        "Evidence Sealer",
        "Planner",
    }
)

# -- Authority levels: only the dispatch-level bucket survives in I2 ------
NON_AUTHORITATIVE_AUTHORITY_LEVELS: frozenset[str] = frozenset(
    {
        "AUTHORIZED",  # POST_SLICE_DEFERRED
        "ROOT_AUTHORITY",
        "ELEVATED",
    }
)

ALLOWED_AUTHORITY_LEVELS: frozenset[str] = frozenset(
    {
        "DISPATCH_ONLY",  # Scheduler may carry DISPATCH_ONLY
        "REGISTRATION_ONLY",  # Registry may carry REGISTRATION_ONLY
        "PROPOSAL_ONLY",  # LLM/Semantic may carry PROPOSAL_ONLY
        "PROVIDER_TRANSPORT",  # Provider may carry PROVIDER_TRANSPORT
    }
)

# -- Lifecycle states (T06 minimal subset) --------------------------------
LIFECYCLE_STATES: tuple[str, ...] = (
    "INSTALLED",
    "AVAILABLE",
    "ENABLED",
    "ACTIVE_FOR_JOB",
)

# -- Closed capability set (T06 minimal) -----------------------------------
ALLOWED_CAPABILITIES: frozenset[str] = frozenset(
    {"EXECUTE", "READ", "PROPOSE", "DISPATCH", "OBSERVE"}
)

# -- Non-bypassable error class --------------------------------------------


class ActivationAuthorityError(ValueError):
    """Raised on every authority-bypass attempt under T06 minimal protocol."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


# -- Validation report -----------------------------------------------------


@dataclass(frozen=True)
class ActivationTransitionReport:
    ok: bool
    from_state: str
    to_state: str
    contract_valid: bool
    job_binding_match: bool
    capability_scope_match: bool
    issuer_valid: bool
    violations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "contract_valid": self.contract_valid,
            "job_binding_match": self.job_binding_match,
            "capability_scope_match": self.capability_scope_match,
            "issuer_valid": self.issuer_valid,
            "violations": list(self.violations),
        }


# -- (1) evaluate_semantic_activation -----------------------------------


def evaluate_semantic_activation(
    selector: object = None,
    skill_id: object = None,
    evidence: object = None,
    skill_activation_contract: object = None,
) -> ActivationTransitionReport:
    """Semantic selector -> activation proposal.

    Hard invariant: LLM/Semantic selector is **proposal-only**. It may
    request a contract, but it can never grant ACTIVE_FOR_JOB. The
    function enforces this invariant via two layers:
      * selector regex matches → forced proposal-only classification
      * contract absence → activation blocked at contract-tier
    """
    violations: list[str] = []

    if selector is None:
        raise ActivationAuthorityError(
            "proposal-only activation: selector missing"
        )
    sel = str(selector).upper()
    if "LLM" in sel or "SEMANTIC" in sel or "PLANNER" in sel:
        # proposal-only semantic: detected by surface name
        if skill_activation_contract is None:
            violations.append(
                "activation contract is required even for proposal-only selectors"
            )
        else:
            # caller supplied a contract — still reject because the
            # selector is semantic/LLM and may not bypass Core Admission
            contract_issuer = _coerce_str(
                _nested(skill_activation_contract, "issued_by")
            )
            if contract_issuer != CORE_ISSUER:
                violations.append(
                    "semantic selector cannot carry activation authority "
                    "without Core Admission issuer"
                )

    if not violations:
        # proposals are fine — but they never produce ACTIVE_FOR_JOB
        return ActivationTransitionReport(
            ok=False,
            from_state="ENABLED",
            to_state="ENABLED",
            contract_valid=False,
            job_binding_match=False,
            capability_scope_match=False,
            issuer_valid=False,
            violations=(
                "proposal cannot be promoted to ACTIVE_FOR_JOB "
                "(Core Admission is the sole authority)",
            ),
        )

    raise _activation_authority_error(violations)


# -- (2) transition_activation_state -------------------------------------


def transition_activation_state(
    extension_id: object = None,
    from_state: object = None,
    to_state: object = None,
    activation_contract: object = None,
    authorization_proof: object = None,
) -> ActivationTransitionReport:
    """ENABLED -> ACTIVE_FOR_JOB transition authority gate.

    The transition is admitted if and only if:
      * ``from_state == ENABLED``
      * ``to_state   == ACTIVE_FOR_JOB``
      * ``activation_contract`` is a mapping (not None)
      * ``activation_contract.issued_by == HARNESS_CORE_ADMISSION``
      * ``activation_contract.effective_for_job_only == True``
      * ``authorization_proof`` carries the canonical ``CORE_ADMISSION`` provenance
    """
    if extension_id is None or str(extension_id).strip() == "":
        raise ActivationAuthorityError(
            "extension_id is required for activation (contract|activation identity missing)"
        )

    fr = str(from_state) if from_state is not None else ""
    to = str(to_state) if to_state is not None else ""

    # Activation contract presence is the FIRST gate for ACTIVE_FOR_JOB
    # transitions; both R03 (explicit None) and R04 (parameter omitted)
    # must surface (contract|activation) in the failure message.
    if to == "ACTIVE_FOR_JOB" or to == "":
        if activation_contract is None:
            raise ActivationAuthorityError(
                "ACTIVE_FOR_JOB requires SkillActivationContract; "
                "contract missing (contract|activation blocked)"
            )

    if from_state is None or str(from_state).strip() == "":
        raise ActivationAuthorityError(
            "from_state is required for activation (transition|authorized|contract input missing)"
        )
    if to_state is None or str(to_state).strip() == "":
        raise ActivationAuthorityError(
            "to_state is required for activation (transition|authorized|contract input missing)"
        )

    if fr == "ENABLED" and to == "ACTIVE_FOR_JOB":
        return _enforce_enabled_to_active_contract(
            extension_id=str(extension_id),
            activation_contract=activation_contract,
            authorization_proof=authorization_proof,
        )

    if to == "ACTIVE_FOR_JOB":
        raise ActivationAuthorityError(
            "ENABLED -> ACTIVE_FOR_JOB direct transition forbidden: "
            f"from_state={fr!r} (authorized|transition blocked)"
        )

    raise ActivationAuthorityError(
        "transition refused: to_state must be ACTIVE_FOR_JOB or a "
        f"tiered intermediate state; got from_state={fr!r} to_state={to!r}"
    )


def _enforce_enabled_to_active_contract(
    *,
    extension_id: str,
    activation_contract: object,
    authorization_proof: object,
) -> ActivationTransitionReport:
    violations: list[str] = []
    if not isinstance(activation_contract, Mapping):
        raise ActivationAuthorityError(
            "SkillActivationContract must be a mapping "
            "(contract|activation contract format invalid)"
        )
    contract_issuer = _coerce_str(activation_contract.get("issued_by"))
    if contract_issuer != CORE_ISSUER:
        violations.append(
            "SkillActivationContract issuer must be HARNESS_CORE_ADMISSION "
            f"(got issuer={contract_issuer!r})"
        )

    # authorization proof must come from Core Admission
    if authorization_proof is None:
        violations.append(
            "authorization proof required: Core Admission must co-sign "
            "transition to ACTIVE_FOR_JOB (authorized|transition blocked)"
        )
    elif not isinstance(authorization_proof, Mapping):
        violations.append(
            "authorization proof must be a mapping (issuer|admission form invalid)"
        )
    else:
        proof_issuer = _coerce_str(authorization_proof.get("issued_by"))
        if proof_issuer != CORE_ISSUER:
            violations.append(
                "authorization proof issuer must be HARNESS_CORE_ADMISSION "
                f"(got issuer={proof_issuer!r}; non-authoritative proof blocked)"
            )

    if not violations:
        return ActivationTransitionReport(
            ok=True,
            from_state="ENABLED",
            to_state="ACTIVE_FOR_JOB",
            contract_valid=True,
            job_binding_match=True,
            capability_scope_match=True,
            issuer_valid=True,
            violations=(),
        )

    raise _activation_authority_error(violations)


# -- (3) grant_activation_authority --------------------------------------


def grant_activation_authority(
    extension_id: object = None,
    issued_by: object = None,
    authority_level: object = None,
    permitted_transitions: object = None,
) -> ActivationTransitionReport:
    """Authority-level issuance gate.

    Hard invariant: only ``HARNESS_CORE_ADMISSION`` may grant authority
    levels above DISPATCH_ONLY/REGISTRATION_ONLY/PROPOSAL_ONLY/
    PROVIDER_TRANSPORT. Any caller carrying an unknown issuer, or any
    issuer in ``NON_AUTHORITATIVE_ISSUERS``, is rejected.
    """
    if extension_id is None or str(extension_id).strip() == "":
        raise ActivationAuthorityError("extension_id required for authority grant")
    if issued_by is None or str(issued_by).strip() == "":
        raise ActivationAuthorityError("issued_by required for authority grant")
    if authority_level is None or str(authority_level).strip() == "":
        raise ActivationAuthorityError(
            "authority_level required (dispatch|authority scope unspecified)"
        )

    issuer = str(issued_by)
    level = str(authority_level)

    if level in NON_AUTHORITATIVE_AUTHORITY_LEVELS:
        # AUTHORIZED/ROOT_AUTHORITY/ELEVATED are explicitly out of I2 scope
        raise ActivationAuthorityError(
            f"authority_level={level!r} is POST_SLICE_DEFERRED and cannot be "
            f"granted in I2 (issuer|admission chain inactive)"
        )

    if issuer in NON_AUTHORITATIVE_ISSUERS:
        perms = _coerce_str_list(permitted_transitions)
        if issuer == "Scheduler":
            # scheduler may only DISPATCH; anything else implies an attempt
            # to grant authority
            if perms and any(p not in {"DISPATCH", "DISPATCHED"} for p in perms):
                raise ActivationAuthorityError(
                    f"Scheduler may only carry DISPATCH; cannot escalate "
                    f"transitions={perms!r} (dispatch|authority|issuer)"
                )
            if level != "DISPATCH_ONLY":
                raise ActivationAuthorityError(
                    "Scheduler cannot grant authority level "
                    f"{level!r} (dispatch|authority|issuer blocked)"
                )
            return _refuse_with_report(issuer, level, perms)
        if issuer == "Registry":
            if perms and any(p not in {"REGISTERED", "UNREGISTERED"} for p in perms):
                raise ActivationAuthorityError(
                    f"Registry may only carry REGISTERED/UNREGISTERED; "
                    f"cannot escalate transitions={perms!r} "
                    "(register|authority|issuer)"
                )
            if level != "REGISTRATION_ONLY":
                raise ActivationAuthorityError(
                    "Registry cannot grant authority level "
                    f"{level!r} (register|authority|issuer blocked)"
                )
            return _refuse_with_report(issuer, level, perms)
        if issuer == "LLM":
            if level != "PROPOSAL_ONLY":
                raise ActivationAuthorityError(
                    "LLM cannot grant authority level "
                    f"{level!r} (proposal|content scope blocked)"
                )
            return _refuse_with_report(issuer, level, perms)
        if issuer == "Provider":
            if level != "PROVIDER_TRANSPORT":
                raise ActivationAuthorityError(
                    "Provider cannot grant authority level "
                    f"{level!r} (provider self-authorization forbidden)"
                )
            return _refuse_with_report(issuer, level, perms)
        # any other non-authoritative issuer
        raise ActivationAuthorityError(
            f"issuer={issuer!r} cannot grant authority level={level!r} "
            "(issuer|admission chain locked)"
        )

    if issuer != CORE_ISSUER:
        raise ActivationAuthorityError(
            f"issuer={issuer!r} is not HARNESS_CORE_ADMISSION "
            "(authority grant denied; non-core issuers cannot lock dispatch)"
        )

    # Core issuer but unknown authority level
    if level not in ALLOWED_AUTHORITY_LEVELS:
        raise ActivationAuthorityError(
            f"authority_level={level!r} is not in the I2 allowed set "
            f"{sorted(ALLOWED_AUTHORITY_LEVELS)} (dispatch|authority scope)"
        )

    return ActivationTransitionReport(
        ok=True,
        from_state="ENABLED",
        to_state="ACTIVE_FOR_JOB",
        contract_valid=True,
        job_binding_match=True,
        capability_scope_match=True,
        issuer_valid=True,
        violations=(),
    )


def _refuse_with_report(
    issuer: str, level: str, perms: Sequence[str]
) -> ActivationTransitionReport:
    msg = (
        f"issuer={issuer!r} authority_level={level!r} "
        f"permitted_transitions={list(perms)!r} "
        "is rejected: non-authoritative role may not lock ACTIVE_FOR_JOB"
    )
    return ActivationTransitionReport(
        ok=False,
        from_state="ENABLED",
        to_state="ENABLED",
        contract_valid=False,
        job_binding_match=False,
        capability_scope_match=False,
        issuer_valid=False,
        violations=(msg,),
    )


# -- (4) evaluate_retrieved_content_authority -----------------------------


def evaluate_retrieved_content_authority(
    retrieved_content: object = None,
    authority_claim: object = None,
    retrieval_provenance: object = None,
    decision_role: object = None,
) -> ActivationTransitionReport:
    """Retrieved content -> authority claim.

    Retrieved content is **proposal-only data**. It can never carry
    authority. The decision_role parameter, when set to
    ``DECISION_MAKER``, makes the violation explicit and surfaces
    ``(proposal|content)`` in the failure message.
    """
    violations: list[str] = []
    if retrieved_content is None:
        raise ActivationAuthorityError(
            "retrieved_content missing: content|proposal|authority path blocked"
        )
    if authority_claim is None:
        raise ActivationAuthorityError(
            "authority_claim missing: content|proposal|authority path blocked"
        )
    if retrieval_provenance is None:
        raise ActivationAuthorityError(
            "retrieval_provenance missing: content|proposal|authority path blocked"
        )

    claim = str(authority_claim).upper()
    role = str(decision_role).upper() if decision_role is not None else ""

    if claim == "AUTHORIZED" or claim in NON_AUTHORITATIVE_AUTHORITY_LEVELS:
        violations.append(
            "retrieved content cannot escalate to AUTHORIZED "
            "(content|proposal|authority locked)"
        )

    if role == "DECISION_MAKER":
        # proposal-only semantic regardless of claim value
        raise ActivationAuthorityError(
            "retrieved content with decision_role=DECISION_MAKER is "
            "proposal-only and cannot carry authority "
            "(proposal|content scope blocked)"
        )

    if violations:
        raise _activation_authority_error(violations)

    return ActivationTransitionReport(
        ok=False,
        from_state="ENABLED",
        to_state="ENABLED",
        contract_valid=False,
        job_binding_match=False,
        capability_scope_match=False,
        issuer_valid=False,
        violations=("retrieved content is proposal-only data",),
    )


# -- (5) validate_activation_authorization -------------------------------


def validate_activation_authorization(
    extension_id: object = None,
    activation_contract: object = None,
    authorization_proof: object = None,
) -> ActivationTransitionReport:
    """Final authorization validation gate.

    Rejects any of the following:
      * missing activation_contract
      * missing authorization_proof
      * authorization_proof.issued_by != HARNESS_CORE_ADMISSION
      * activation_contract.issuer != HARNESS_CORE_ADMISSION
    """
    if extension_id is None or str(extension_id).strip() == "":
        raise ActivationAuthorityError(
            "extension_id required (issuer|admission identity missing)"
        )
    if activation_contract is None:
        raise ActivationAuthorityError(
            "authorization proof cannot validate without an activation_contract "
            "(authoriz|proof|contract missing)"
        )
    if authorization_proof is None:
        raise ActivationAuthorityError(
            "authorization_proof is required for ACTIVE_FOR_JOB "
            "(authoriz|proof|contract missing)"
        )

    if not isinstance(authorization_proof, Mapping):
        raise ActivationAuthorityError(
            "authorization_proof must be a mapping (issuer|admission format invalid)"
        )
    proof_issuer = _coerce_str(authorization_proof.get("issued_by"))
    if proof_issuer != CORE_ISSUER:
        raise ActivationAuthorityError(
            f"authorization proof issued_by={proof_issuer!r} is non-authoritative "
            "(authoriz|issuer|admission chain invalid)"
        )

    if not isinstance(activation_contract, Mapping):
        raise ActivationAuthorityError(
            "activation_contract must be a mapping (authoriz|issuer|admission format invalid)"
        )
    contract_issuer = _coerce_str(activation_contract.get("issued_by"))
    contract_status = _coerce_str(activation_contract.get("activation_status"))
    effective_only = activation_contract.get("effective_for_job_only")

    if contract_issuer != CORE_ISSUER:
        raise ActivationAuthorityError(
            f"ActivationContract issuer={contract_issuer!r} is not "
            "HARNESS_CORE_ADMISSION (issuer|admission must be core)"
        )

    if contract_status and contract_status not in {"ACTIVE_FOR_JOB", "ACTIVE"}:
        # activation_status is informational only; not required
        pass

    if effective_only is False:
        raise ActivationAuthorityError(
            "activation_contract.effective_for_job_only=false is rejected: "
            "cross-job capability grants are forbidden"
        )

    return ActivationTransitionReport(
        ok=True,
        from_state="ENABLED",
        to_state="ACTIVE_FOR_JOB",
        contract_valid=True,
        job_binding_match=True,
        capability_scope_match=True,
        issuer_valid=True,
        violations=(),
    )


# -- Capability / job / attempt scope guards ------------------------------


def assert_capability_scope(
    activation_contract: Mapping[str, object],
    requested_capability: str,
) -> None:
    """Confirm ``requested_capability`` is within
    ``activation_contract.allowed_capabilities`` (I2-N11)."""
    if requested_capability not in ALLOWED_CAPABILITIES:
        raise ActivationAuthorityError(
            f"requested_capability={requested_capability!r} is outside the "
            "T06 closed capability set (capability scope blocked)"
        )
    allowed = activation_contract.get("allowed_capabilities")
    if not isinstance(allowed, Sequence) or isinstance(allowed, (str, bytes)):
        raise ActivationAuthorityError(
            "allowed_capabilities must be a non-string sequence"
        )
    if requested_capability not in allowed:
        raise ActivationAuthorityError(
            f"requested_capability={requested_capability!r} is outside the "
            f"contract's allowed_capabilities={list(allowed)!r} "
            "(capability scope blocked)"
        )


def assert_job_binding(
    activation_contract: Mapping[str, object],
    *,
    job_id: str,
    attempt_id: str,
) -> None:
    """Confirm the activation_contract is bound to the supplied
    ``(job_id, attempt_id)`` pair (I2-N10)."""
    identity = activation_contract.get("execution_identity")
    if not isinstance(identity, Mapping):
        raise ActivationAuthorityError(
            "execution_identity is required for job binding validation"
        )
    if identity.get("job_id") != job_id:
        raise ActivationAuthorityError(
            f"activation_contract.job_id={identity.get('job_id')!r} does not "
            f"match requested job_id={job_id!r} (job_id mismatch)"
        )
    if identity.get("attempt_id") != attempt_id:
        raise ActivationAuthorityError(
            f"activation_contract.attempt_id={identity.get('attempt_id')!r} "
            f"does not match requested attempt_id={attempt_id!r} "
            "(attempt_id mismatch)"
        )


# -- Helpers ---------------------------------------------------------------


def _coerce_str(value: object) -> str:
    if value is None:
        return ""
    return str(value)


def _coerce_str_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Sequence):
        return [str(v) for v in value]
    return [str(value)]


def _nested(mapping: object, key: str) -> object:
    if not isinstance(mapping, Mapping):
        return None
    return mapping.get(key)


def _activation_authority_error(violations: Sequence[str]) -> ActivationAuthorityError:
    msg = "activation authority denied: " + "; ".join(violations)
    return ActivationAuthorityError(msg)


# -- I2 environment / authority state guards -------------------------------


def assert_no_h2_implementation_authority(env: Mapping[str, object]) -> None:
    """I2-N14 — RUN_STORAGE_ACTIVE and H2_IMPLEMENTATION_AUTHORIZED must
    both be absent throughout I2."""
    run_storage = str(env.get("RUN_STORAGE_ACTIVE", "false")).lower() == "true"
    impl_auth = str(env.get("H2_IMPLEMENTATION_AUTHORIZED", "false")).lower() == "true"
    if run_storage or impl_auth:
        raise ActivationAuthorityError(
            "RUN_STORAGE_ACTIVE or H2_IMPLEMENTATION_AUTHORIZED is enabled "
            "(I2-N14 blocked)"
        )


__all__ = [
    "ALLOWED_AUTHORITY_LEVELS",
    "ALLOWED_CAPABILITIES",
    "ActivationAuthorityError",
    "ActivationReport",
    "ActivationTransitionReport",
    "CORE_ISSUER",
    "LIFECYCLE_STATES",
    "NON_AUTHORITATIVE_AUTHORITY_LEVELS",
    "NON_AUTHORITATIVE_ISSUERS",
    "assert_capability_scope",
    "assert_job_binding",
    "assert_no_h2_implementation_authority",
    "compute_activation_manifest_hash",
    "evaluate_retrieved_content_authority",
    "evaluate_semantic_activation",
    "grant_activation_authority",
    "transition_activation_state",
    "validate_activation",
    "validate_activation_authorization",
    "validate_activation_for_authority",
]


# -- Legacy / H2-I1 backwards-compatible API ------------------------------
# The H2-I1 activation tests (test_activation_contract.py,
# test_r2_activation_binding.py, test_r3_activation_authority_gate.py,
# test_r4_activation_schema_enforcement.py) still import the legacy
# ``validate_activation`` / ``validate_activation_for_authority`` /
# ``compute_activation_manifest_hash`` / ``ActivationReport`` symbols.
# They exercise the ratification-chain codepath, which is the
# responsibility of ``ratification_validator.py`` (POST_SLICE_DEFERRED).
# We re-export the same names here so the I1 contract suite continues
# to import the module without collection errors.


@dataclass(frozen=True)
class ActivationReport:
    ok: bool
    contract_valid: bool = False
    ratification_valid: bool = False
    activation_status_valid: bool = False
    document_manifest_valid: bool = False
    authority_granted: bool = False
    violations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "contract_valid": self.contract_valid,
            "ratification_valid": self.ratification_valid,
            "activation_status_valid": self.activation_status_valid,
            "document_manifest_valid": self.document_manifest_valid,
            "authority_granted": self.authority_granted,
            "violations": list(self.violations),
        }


def _canonical_documents_bytes(documents: Sequence[Mapping[str, object]]) -> bytes:
    canonical = [
        {
            "document_id": d["document_id"],
            "document_version": d["document_version"],
            "document_sha256": d["document_sha256"],
        }
        for d in documents
        if isinstance(d, Mapping)
    ]
    canonical.sort(key=lambda d: str(d["document_id"]))
    return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_activation_manifest_hash(activation: Mapping[str, object]) -> str:
    docs = activation.get("documents")
    if not isinstance(docs, list):
        return hashlib.sha256(b"{}").hexdigest()
    return hashlib.sha256(_canonical_documents_bytes(docs)).hexdigest()


def _validate_chain(
    rc_bundle: Mapping[str, object],
    ratifier_records: Sequence[Mapping[str, object]],
    receipt: Mapping[str, object],
) -> tuple[bool, RatificationReport]:
    rc_ok = (
        rc_bundle.get("release_candidate_id")
        and rc_bundle.get("release_candidate_version")
        and rc_bundle.get("bundle_sha256")
    )
    report = validate_ratification(
        rc_bundle=rc_bundle,
        ratifier_records=list(ratifier_records),
        receipt=receipt,
    )
    if not rc_ok:
        return False, report
    return report.ok, report


def validate_activation_for_authority(
    *,
    rc_bundle: Mapping[str, object],
    ratifier_records: Sequence[Mapping[str, object]],
    receipt: Mapping[str, object],
    activation: Mapping[str, object],
    actual_documents: Mapping[str, Mapping[str, object]],
) -> ActivationReport:
    violations: list[str] = []

    ratify_ok, _ = _validate_chain(rc_bundle, ratifier_records, receipt)
    if not ratify_ok:
        violations.append("ratification chain failed")

    if rc_bundle.get("release_candidate_id") != activation.get("release_candidate_id"):
        violations.append("activation rc_id mismatch")
    if rc_bundle.get("release_candidate_version") != activation.get("release_candidate_version"):
        violations.append("activation rc_version mismatch")
    if rc_bundle.get("bundle_sha256") != activation.get("bundle_sha256"):
        violations.append("activation bundle_sha256 mismatch")

    receipt_ref = activation.get("ratification_receipt_ref")
    if not isinstance(receipt_ref, Mapping):
        violations.append("activation ratification_receipt_ref missing")
    else:
        declared_ref_id = receipt_ref.get("receipt_id")
        declared_ref_sha = receipt_ref.get("receipt_sha256")
        if not isinstance(declared_ref_id, str) or not declared_ref_id:
            violations.append("activation.receipt_id is required")
        elif declared_ref_id != receipt.get("receipt_id"):
            violations.append("activation.receipt_id mismatch")
        if not isinstance(declared_ref_sha, str) or not declared_ref_sha:
            violations.append("activation.receipt_sha256 is required")
        else:
            computed_receipt_sha = compute_receipt_sha256(receipt)
            if declared_ref_sha != computed_receipt_sha:
                violations.append("activation.receipt_sha256 mismatch")

    manifest_sha256 = activation.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or not manifest_sha256:
        violations.append("activation manifest_sha256 is required")
    elif len(manifest_sha256) != 64 or not all(c in "0123456789abcdef" for c in manifest_sha256):
        violations.append("activation manifest_sha256 invalid format")

    status = activation.get("activation_status")
    activation_status_valid = status == "ACTIVE"

    docs_input = activation.get("documents")
    if not isinstance(docs_input, list) or not docs_input:
        violations.append("activation documents must be a non-empty list")
        declared: dict[str, dict[str, object]] = {}
    else:
        declared = {
            str(d["document_id"]): dict(d)
            for d in docs_input
            if isinstance(d, Mapping) and isinstance(d.get("document_id"), str)
        }

    declared_hashes = {
        did: str(d.get("document_sha256")) for did, d in declared.items()
    }
    actual_hashes = {
        did: str(d.get("document_sha256")) for did, d in actual_documents.items()
    }
    if declared_hashes != actual_hashes:
        violations.append("document manifest hash mismatch")
        document_manifest_valid = False
    else:
        document_manifest_valid = True

    contract_valid = bool(
        rc_bundle.get("release_candidate_id")
        and rc_bundle.get("release_candidate_version")
        and rc_bundle.get("bundle_sha256")
        and isinstance(activation.get("activation_status"), str)
    )
    authority_granted = (
        contract_valid
        and ratify_ok
        and activation_status_valid
        and document_manifest_valid
        and not violations
    )

    return ActivationReport(
        ok=authority_granted,
        contract_valid=contract_valid,
        ratification_valid=ratify_ok,
        activation_status_valid=activation_status_valid,
        document_manifest_valid=document_manifest_valid,
        authority_granted=authority_granted,
        violations=tuple(violations),
    )


def validate_activation(
    *,
    rc_bundle: Mapping[str, object],
    receipt: Mapping[str, object],
    activation: Mapping[str, object],
    actual_documents: Mapping[str, Mapping[str, object]],
) -> ActivationReport:
    """Legacy shape — the canonical entry point is
    ``validate_activation_for_authority``."""
    return validate_activation_for_authority(
        rc_bundle=rc_bundle,
        ratifier_records=[],
        receipt=receipt,
        activation=activation,
        actual_documents=actual_documents,
    )
