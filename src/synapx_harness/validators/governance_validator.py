"""Governance Validator (deterministic, fail-closed).

Validates governance policy files against the registered contract
schemas. This implementation rejects the previous "field presence only"
behaviour: it validates that the field VALUES are admissible
(`registry_state=DRAFT`, `authority=NON_AUTHORITATIVE`,
`analysis_mode=READ_ONLY`, `ratifiers_required=4`, etc.) and that the
document honours the contract schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from ruamel.yaml import YAML

from synapx_harness.contracts.registry import REGISTRY
from synapx_harness.contracts.registry import get as get_descriptor
from synapx_harness.validators.schema_validator import load_schema

REQUIRED_FIELDS: tuple[str, ...] = ("contract_type", "schema_version")

CORE_ADMISSION_ISSUER: str = "HARNESS_CORE_ADMISSION"

CORE_ADMISSION_REQUIRED_RECEIPT_KEYS: tuple[str, ...] = (
    "receipt_id",
    "admitted_at",
    "admitted_by",
)

CORE_ADMISSION_REQUIRED_RECEIPT_REFS: tuple[str, ...] = (
    "permission_receipt_ref",
    "eligibility_receipt_ref",
    "execution_receipt_ref",
)


@dataclass(frozen=True)
class GovernanceValidationReport:
    ok: bool
    missing_fields: tuple[str, ...]
    files: tuple[str, ...] = ()
    failed_files: tuple[str, ...] = ()
    errors: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "missing_fields": list(self.missing_fields),
            "files": list(self.files),
            "failed_files": list(self.failed_files),
            "errors": list(self.errors),
        }


def _load_yaml(path: Path) -> Any:
    yaml = YAML(typ="safe")
    with path.open("r", encoding="utf-8") as fh:
        return yaml.load(fh)


def _walk_yaml(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    yamls: list[Path] = list(root.rglob("*.yaml"))
    yamls.extend(root.rglob("*.yml"))
    return sorted(yamls)


def _yaml_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    yamls: list[Path] = list(root.rglob("*.yaml"))
    yamls.extend(root.rglob("*.yml"))
    return yamls


def _find_contract_descriptor(name: str, kind: str) -> str | None:
    for cid, desc in REGISTRY.items():
        if desc.contract_type == name and desc.kind == kind:
            return cid
    return None


def _validate_value_invariants(
    contract_type: str,
    data: dict[str, object],
    errors: list[str],
) -> None:
    """Hard-coded invariants that mirror the policy schema guards."""
    schema_version = data.get("schema_version")
    if contract_type.startswith("COMMUNIS_") or contract_type.startswith("CUSTOMOS_"):
        if schema_version != "0.1.0":
            errors.append(
                f"schema_version must be '0.1.0' (got {schema_version!r})"
            )
    if contract_type == "COMMUNIS_REPOSITORY_REGISTRY":
        state = data.get("registry_state")
        if state and state != "DRAFT":
            errors.append(f"registry_state must be DRAFT (got {state!r})")
        repos_obj = data.get("repositories", []) or []
        repos_list: list[object] = list(repos_obj) if isinstance(repos_obj, list) else []
        for repo in repos_list:
            if not isinstance(repo, dict):
                continue
            auth = repo.get("authority")
            if auth and auth != "NON_AUTHORITATIVE":
                errors.append(f"repository authority must be NON_AUTHORITATIVE (got {auth!r})")
            mode = repo.get("analysis_mode")
            if mode and mode != "READ_ONLY":
                errors.append(f"repository analysis_mode must be READ_ONLY (got {mode!r})")
    if contract_type == "COMMUNIS_RATIFICATION_POLICY":
        rr = data.get("ratifiers_required")
        if rr is not None and rr != 4:
            errors.append(f"ratifiers_required must be 4 (got {rr!r})")
        rule = data.get("approval_rule")
        if rule and rule != "UNANIMOUS":
            errors.append(f"approval_rule must be UNANIMOUS (got {rule!r})")
        approvers = data.get("approval_count_required")
        if approvers is not None and approvers != 4:
            errors.append(f"approval_count_required must be 4 (got {approvers!r})")
        blocking = data.get("blocking_issue_count_required")
        if blocking is not None and blocking != 0:
            errors.append(f"blocking_issue_count_required must be 0 (got {blocking!r})")


def _validate_against_schema(
    schemas_root: Path,
    contract_type: str,
    data: Any,
    errors: list[str],
) -> None:
    cid = _find_contract_descriptor(contract_type, "governance")
    if cid is None:
        # Unknown contract type
        errors.append(f"unknown contract_type {contract_type!r}")
        return
    descriptor = get_descriptor(cid)
    schema_name = _contract_filename_for(descriptor.contract_type)
    schema = load_schema(schemas_root, f"governance/{schema_name}.schema.json")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        errors.append(f"schema invalid: {exc.message}")
        return
    validator = Draft202012Validator(schema)
    for err in validator.iter_errors(data):
        path = ".".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"{contract_type}: {path}: {err.message}")


def _contract_filename_for(contract_type: str) -> str:
    mapping = {
        "COMMUNIS_DOCUMENT_PROFILE": "communis_document_profile",
        "COMMUNIS_KNOWLEDGE_ITEM": "knowledge_item",
        "COMMUNIS_REPOSITORY_REGISTRY": "repository_registry",
        "COMMUNIS_SOURCE_SNAPSHOT": "source_snapshot",
        "COMMUNIS_RC_BUNDLE": "release_candidate_bundle",
        "COMMUNIS_RATIFICATION_RECEIPT": "ratification_receipt",
        "COMMUNIS_ACTIVATION_MANIFEST": "activation_manifest",
        "COMMUNIS_RATIFICATION_POLICY": "policy",
        "COMMUNIS_ACTIVATION_POLICY": "policy",
        "COMMUNIS_KNOWLEDGE_AUTHORITY_POLICY": "policy",
        "COMMUNIS_PILOT_RISK_POLICY": "policy",
        "COMMUNIS_AS_IS_PROFILE": "profile",
        "COMMUNIS_SERVICE_PACK_MANIFEST": "service_pack_manifest",
        "COMMUNIS_SOURCE_READ_ONLY_POLICY": "policy",
    }
    return mapping.get(contract_type, "communis_document_profile")


def validate_governance(
    roots: list[Path],
    *,
    schemas_root: Path | None = None,
) -> GovernanceValidationReport:
    """Walk governance roots and validate every YAML file.

    The validator is fail-closed: empty roots, malformed YAML, and
    schema mismatches all yield ``ok=False``.
    """
    if not roots:
        return GovernanceValidationReport(
            ok=False,
            missing_fields=(),
            files=(),
            failed_files=(),
            errors=("no governance roots supplied",),
        )

    if schemas_root is None:
        from synapx_harness.validators.schema_validator import (
            DEFAULT_SCHEMAS_ROOT,
            _resolve_schemas_root,
        )

        schemas_root = _resolve_schemas_root(Path.cwd() / DEFAULT_SCHEMAS_ROOT)

    files: list[str] = []
    failed_files: list[str] = []
    errors: list[str] = []
    missing: list[str] = []

    for root in roots:
        if not root.is_dir():
            errors.append(f"governance root missing: {root}")
            failed_files.append(str(root))
            continue
        yaml_paths = _walk_yaml(root)
        if not yaml_paths:
            failed_files.append(str(root))
            errors.append(f"governance root contains no yaml files: {root}")
            continue
        for path in yaml_paths:
            files.append(str(path))
            try:
                data = _load_yaml(path)
            except Exception as exc:
                failed_files.append(str(path))
                errors.append(f"{path}: malformed yaml: {exc}")
                continue
            if not isinstance(data, dict):
                failed_files.append(str(path))
                errors.append(f"{path}: not a mapping")
                continue
            contract_type = data.get("contract_type")
            schema_version = data.get("schema_version")
            if not isinstance(contract_type, str):
                missing.append(f"{path}: missing contract_type")
                continue
            if not isinstance(schema_version, str):
                missing.append(f"{path}: missing schema_version")
                continue
            _validate_value_invariants(contract_type, dict(data), errors)
            file_errors_before = len(errors)
            _validate_against_schema(schemas_root, contract_type, data, errors)
            if len(errors) > file_errors_before:
                failed_files.append(str(path))

    ok = (not missing) and (not errors) and (not failed_files)
    return GovernanceValidationReport(
        ok=ok,
        missing_fields=tuple(missing),
        files=tuple(files),
        failed_files=tuple(failed_files),
        errors=tuple(errors),
    )


__all__ = [
    "CORE_ADMISSION_ISSUER",
    "CORE_ADMISSION_REQUIRED_RECEIPT_KEYS",
    "CORE_ADMISSION_REQUIRED_RECEIPT_REFS",
    "REQUIRED_FIELDS",
    "GovernanceValidationReport",
    "admit_work_contract",
    "validate_core_work_admission",
    "validate_governance",
]


def validate_core_work_admission(
    work_contract: dict[str, object],
    issuer: str,
    admission_receipt: dict[str, object],
    receipt_refs: dict[str, object],
) -> GovernanceValidationReport:
    """Enforce the X3 CA-06 Core Admission gate.

    The function returns a :class:`GovernanceValidationReport` to remain
    consistent with the existing governance contract surface. Provider
    self-authorization attempts (issuer != HARNESS_CORE_ADMISSION) raise
    :class:`ValueError` to mirror the runtime rejection path.

    Order of validation:

      1. issuer mismatch (raises ValueError)
      2. admission_receipt missing required keys (raises ValueError)
      3. receipt_refs missing required refs (raises ValueError)
    """
    errors: list[str] = []
    missing_fields: list[str] = []

    if issuer != CORE_ADMISSION_ISSUER:
        raise ValueError(
            "Core WorkAdmission requires issuer="
            f"{CORE_ADMISSION_ISSUER!r} (issuer|admission), got {issuer!r}"
        )

    if not isinstance(admission_receipt, dict):
        missing_fields.append("admission_receipt: must be a mapping")
    else:
        missing = [
            key
            for key in CORE_ADMISSION_REQUIRED_RECEIPT_KEYS
            if not admission_receipt.get(key)
        ]
        if missing:
            missing_fields.append(
                f"admission_receipt missing required keys {missing} (admission|issuer)"
            )

    if not isinstance(receipt_refs, dict):
        missing_fields.append("receipt_refs: must be a mapping")
    else:
        missing_refs = [
            key
            for key in CORE_ADMISSION_REQUIRED_RECEIPT_REFS
            if not receipt_refs.get(key)
        ]
        if missing_refs:
            missing_fields.append(
                f"receipt_refs missing required refs {missing_refs} (receipt)"
            )

    if not isinstance(work_contract, dict):
        missing_fields.append("work_contract: must be a mapping")
    elif not work_contract.get("work_contract_id"):
        missing_fields.append("work_contract.work_contract_id: required")

    ok = not errors and not missing_fields
    return GovernanceValidationReport(
        ok=ok,
        missing_fields=tuple(missing_fields),
        files=(),
        failed_files=(),
        errors=tuple(errors),
    )


def admit_work_contract(
    work_contract: dict[str, object],
    issuer: str,
    admission_receipt: dict[str, object],
    receipt_refs: dict[str, object],
) -> GovernanceValidationReport:
    """Convenience wrapper that mirrors the runtime admission signature."""
    return validate_core_work_admission(
        work_contract,
        issuer,
        admission_receipt,
        receipt_refs,
    )
