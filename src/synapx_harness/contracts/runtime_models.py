"""Typed Runtime Models (Pydantic v2).

These models produce JSON payloads whose shape is verified by the
runtime JSON Schemas in ``synapx_harness/_schemas/runtime/``. Every
model MUST declare `contract_type` and `schema_version`, and
`model_dump(mode="json")` MUST validate against the matching schema.

H2-I1 Core Authority Spine (T00/T01/T02/T05):
  - ``schema_version`` is now an enum literal of ``0.1.0`` and ``0.2.0``.
    New contracts choose ``0.2.0``; the legacy builder still emits
    ``0.1.0`` for backward compatibility.
  - ``ExecutionIdentity`` (CA-01) carries the (job_id, task_id, attempt_id,
    tool_call_id) four-tuple. ``attempt_id`` is the canonical 1:1 pairing
    for the legacy ``attempt_index``.
  - ``SourceRevisionRef`` (ODC-H1-10) is provider-neutral; it is NOT a
    Git SHA alias. ``revision_kind`` belongs to ``REVISION_KINDS``; the
    pair ``(revision_kind, revision_value)`` is mandatory.
  - ``compute_content_tree_hash`` derives a deterministic, byte-stable
    hex hash from a file tree (NO git requirement). Missing/unreadable
    paths are rejected explicitly to keep the gate fail-closed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

RUNTIME_SCHEMA_VERSION = "0.1.0"
RUNTIME_SCHEMA_VERSION_2 = "0.2.0"
RUNTIME_SCHEMA_VERSIONS: tuple[str, ...] = (
    RUNTIME_SCHEMA_VERSION,
    RUNTIME_SCHEMA_VERSION_2,
)
SCHEMA_VERSION_DEFAULT = RUNTIME_SCHEMA_VERSION

REVISION_KINDS: tuple[str, ...] = (
    "GIT_COMMIT",
    "CONTENT_TREE_HASH",
    "SNAPSHOT_ID",
    "EXTERNAL_REVISION",
)

EXECUTION_IDENTITY_TOOL_CALL_NONE_PLACEHOLDER = "__unset__"

WorkAdmissionIssuer: Literal["HARNESS_CORE_ADMISSION"] = "HARNESS_CORE_ADMISSION"


class _StrictModel(BaseModel):
    """Base model: forbids extras, validates assignment, populates by name."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
    )


class ExecutionIdentity(_StrictModel):
    """Canonical execution identity (CA-01 / CA-02).

    root_task_id is non-nullable: every ExecutionIdentity must carry an
    explicit lineage root. tool_call_id may be None (signaling no
    tool call) or a non-empty sentinel string; the validator below
    enforces both invariants.
    """

    job_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    root_task_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    tool_call_id: str | None = None

    @model_validator(mode="after")
    def _validate_identity_separation(self) -> ExecutionIdentity:
        # CA-02: attempt_id != task_id; tool_call_id != attempt_id.
        if self.attempt_id == self.task_id:
            raise ValueError(
                "attempt_id must differ from task_id (CA-02 attempt_neq_task)"
            )
        if (
            self.tool_call_id is not None
            and self.tool_call_id != EXECUTION_IDENTITY_TOOL_CALL_NONE_PLACEHOLDER
            and self.tool_call_id == self.attempt_id
        ):
            raise ValueError(
                "tool_call_id must differ from attempt_id (CA-02 tool_call_neq_attempt)"
            )
        return self


class SourceRevisionRef(_StrictModel):
    """Provider-neutral source revision reference (ODC-H1-10)."""

    repository_id: str = Field(min_length=1)
    revision_kind: Literal[
        "GIT_COMMIT",
        "CONTENT_TREE_HASH",
        "SNAPSHOT_ID",
        "EXTERNAL_REVISION",
    ]
    revision_value: str = Field(min_length=1)
    working_delta_id: str | None = None

    @model_validator(mode="after")
    def _validate_kind_value_pair(self) -> SourceRevisionRef:
        if not self.revision_value:
            raise ValueError(
                "revision_value must be non-empty (kind/value pair invariant)"
            )
        if self.revision_kind not in REVISION_KINDS:
            raise ValueError(
                f"revision_kind must be one of {REVISION_KINDS} "
                f"(got {self.revision_kind!r})"
            )
        return self


class WorkContract(_StrictModel):
    contract_type: Literal["CUSTOMOS_WORK_CONTRACT"] = "CUSTOMOS_WORK_CONTRACT"
    schema_version: Literal["0.1.0", "0.2.0"] = SCHEMA_VERSION_DEFAULT
    work_contract_id: str = Field(min_length=1)
    phase: str = Field(min_length=1)
    risk_class: Literal["R0", "R1", "R2", "R3", "R4"]
    objective: str = Field(min_length=1)
    scope: list[str] = Field(min_length=1)
    success_criteria: list[str] = Field(default_factory=list)
    task_type: (
        Literal[
            "BUG_FIX",
            "TEST_REPAIR",
            "DOC_FIX",
            "REVIEW_FIX",
            "WORK_ADMISSION",
            "SCHEMA_REVISION",
            "ADAPTER_FIX",
            "INFRA_FIX",
            "LOG_FIX",
            "NAMESPACE_REPAIR",
            "GOVERNANCE_FIX",
            "REVISION_BINDING",
            "SOURCE_BINDING",
            "GUARDRAIL_TRIM",
            "DOCS_TRIM",
        ]
        | None
    ) = None
    execution_identity: ExecutionIdentity | None = None
    source_revision_ref: SourceRevisionRef | None = None
    issuer: Literal["HARNESS_CORE_ADMISSION"] | None = None
    admission_receipt: dict[str, object] | None = None
    permission_receipt_ref: str | None = None
    eligibility_receipt_ref: str | None = None
    execution_receipt_ref: str | None = None


class VerificationResult(_StrictModel):
    contract_type: Literal["CUSTOMOS_VERIFICATION_RESULT"] = "CUSTOMOS_VERIFICATION_RESULT"
    schema_version: Literal["0.1.0"] = RUNTIME_SCHEMA_VERSION
    work_contract_id: str = Field(min_length=1)
    verification_status: Literal["PASS", "FAIL", "PENDING"]
    evidence_status: Literal["VALID", "INVALID", "PENDING"]
    active_blocker_count: Annotated[int, Field(ge=0)]
    checks: list[dict[str, object]] = Field(default_factory=list)


class TerminalDecisionRecord(_StrictModel):
    contract_type: Literal["CUSTOMOS_TERMINAL_DECISION"] = "CUSTOMOS_TERMINAL_DECISION"
    schema_version: Literal["0.1.0"] = RUNTIME_SCHEMA_VERSION
    work_contract_id: str = Field(min_length=1)
    decision: Literal["COMPLETED", "FAILED", "BLOCKED"]
    reason: str = Field(min_length=1)


def _walk_tree(root: Path) -> list[tuple[str, list[str], list[str]]]:
    """Yield (dirpath, dirnames, filenames) tuples via os.walk (sorted)."""
    out: list[tuple[str, list[str], list[str]]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        filenames.sort()
        out.append((dirpath, dirnames, filenames))
    return out


def _safe_relative(file_path: Path, base: Path) -> str:
    rel = file_path.resolve().relative_to(base.resolve())
    return rel.as_posix()


def compute_content_tree_hash(
    root_path: str | Path,
    *,
    base_path: str | Path | None = None,
) -> str:
    """Deterministically hash a directory tree (provider-neutral).

    Parameters
    ----------
    root_path:
        Filesystem path to the directory tree whose content hash is
        requested. The function does NOT consult git.
    base_path:
        Optional base used to compute relative paths. When omitted,
        ``root_path`` itself is used as the base.

    Returns
    -------
    str
        Lower-case hex digest (SHA-256).

    Raises
    ------
    ValueError
        When the path does not exist, is not a directory, or contains
        a node that cannot be read.
    """
    root = Path(root_path)
    if not root.exists():
        raise ValueError(
            f"compute_content_tree_hash: root path does not exist "
            f"(content|hash|revision): {root!s}"
        )
    if root.is_file():
        root = root.parent
    if not root.is_dir():
        raise ValueError(
            f"compute_content_tree_hash: root is not a directory "
            f"(content|hash|revision): {root!s}"
        )
    base = Path(base_path) if base_path is not None else root

    digest = hashlib.sha256()
    nodes: list[Path] = []
    for dirpath, _dirnames, filenames in _walk_tree(root):
        for filename in filenames:
            nodes.append(Path(dirpath) / filename)
    for file_path in sorted(nodes):
        rel = _safe_relative(file_path, base)
        digest.update(rel.encode("utf-8"))
        digest.update(b"\x00")
        try:
            data = file_path.read_bytes()
        except OSError as exc:
            raise ValueError(
                f"compute_content_tree_hash: unreadable file {file_path!s} "
                f"(content|hash|revision): {exc}"
            ) from exc
        digest.update(data)
        digest.update(b"\x00")
    return digest.hexdigest()


def _validate_source_revision_ref_payload(payload: dict[str, object]) -> None:
    """Fail-closed validation for a SourceRevisionRef dict payload."""
    required_fields = ("repository_id", "revision_kind", "revision_value")
    missing = [name for name in required_fields if payload.get(name) in (None, "")]
    if missing:
        raise ValueError(
            "source_revision_ref requires "
            f"{required_fields}, missing={missing} "
            "(revision|accept|content|snapshot|external)"
        )
    kind = payload.get("revision_kind")
    if kind not in REVISION_KINDS:
        raise ValueError(
            "source_revision_ref.revision_kind must be one of "
            f"{list(REVISION_KINDS)} (got {kind!r}); "
            "git-only revision rejected "
            "(revision|accept|content|snapshot|external)"
        )


def build_work_contract(
    *,
    work_contract_id: str,
    phase: str,
    risk_class: str,
    objective: str,
    scope: list[str],
    success_criteria: list[str] | None = None,
) -> WorkContract:
    risk: Any = risk_class
    return WorkContract(
        work_contract_id=work_contract_id,
        phase=phase,
        risk_class=risk,  # type: ignore[arg-type]
        objective=objective,
        scope=scope,
        success_criteria=success_criteria or [],
    )


def build_verification_result(
    *,
    work_contract_id: str,
    verification_status: str,
    evidence_status: str,
    active_blocker_count: int,
    checks: list[dict[str, object]] | None = None,
) -> VerificationResult:
    vs: Any = verification_status
    es: Any = evidence_status
    return VerificationResult(
        work_contract_id=work_contract_id,
        verification_status=vs,  # type: ignore[arg-type]
        evidence_status=es,  # type: ignore[arg-type]
        active_blocker_count=active_blocker_count,
        checks=checks or [],
    )


def build_terminal_decision(
    *,
    work_contract_id: str,
    decision: str,
    reason: str,
) -> TerminalDecisionRecord:
    dec: Any = decision
    return TerminalDecisionRecord(
        work_contract_id=work_contract_id,
        decision=dec,  # type: ignore[arg-type]
        reason=reason,
    )


def build_execution_identity(
    *,
    job_id: str,
    task_id: str,
    root_task_id: str,
    attempt_id: str,
    tool_call_id: str | None = None,
) -> ExecutionIdentity:
    if not root_task_id:
        raise ValueError(
            "ExecutionIdentity.root_task_id is required and must be a non-empty string "
            "(canonical identity lineage; see 03C_R3 defect R2-D-05)"
        )
    return ExecutionIdentity(
        job_id=job_id,
        task_id=task_id,
        root_task_id=root_task_id,
        attempt_id=attempt_id,
        tool_call_id=tool_call_id,
    )


def build_source_revision_ref(
    *,
    repository_id: str,
    revision_kind: str,
    revision_value: str,
    working_delta_id: str | None = None,
) -> SourceRevisionRef:
    return SourceRevisionRef(
        repository_id=repository_id,
        revision_kind=revision_kind,  # type: ignore[arg-type]
        revision_value=revision_value,
        working_delta_id=working_delta_id,
    )


def coerce_source_revision_ref(
    value: SourceRevisionRef | dict[str, object] | None,
    *,
    supported_kinds: list[str] | tuple[str, ...] | None = None,
) -> dict[str, object] | None:
    """Convert a SourceRevisionRef-shaped value into a JSON-safe dict."""
    if value is None:
        return None
    if isinstance(value, SourceRevisionRef):
        payload = value.model_dump(mode="json")
    elif isinstance(value, dict):
        payload = dict(value)
    else:
        raise ValueError("source_revision_ref must be a SourceRevisionRef or dict")
    _validate_source_revision_ref_payload(payload)
    if supported_kinds is not None:
        kinds = list(supported_kinds)
        if set(kinds) == {"GIT_COMMIT"}:
            raise ValueError(
                "GIT_COMMIT-only supported_kinds bound rejected by fail-closed: "
                "provider-neutral revision required (revision|gitless)"
            )
    return payload


def build_admission_receipt(
    *,
    receipt_id: str,
    admitted_at: str,
    admitted_by: str = "HARNESS_CORE_ADMISSION",
    classification_receipt: str = "",
    risk_classification_receipt: str = "",
    revision_verification_receipt: str = "",
) -> dict[str, object]:
    return {
        "receipt_id": receipt_id,
        "admitted_at": admitted_at,
        "admitted_by": admitted_by,
        "classification_receipt": classification_receipt,
        "risk_classification_receipt": risk_classification_receipt,
        "revision_verification_receipt": revision_verification_receipt,
    }


__all__ = [
    "EXECUTION_IDENTITY_TOOL_CALL_NONE_PLACEHOLDER",
    "ExecutionIdentity",
    "REVISION_KINDS",
    "RUNTIME_SCHEMA_VERSION",
    "RUNTIME_SCHEMA_VERSION_2",
    "RUNTIME_SCHEMA_VERSIONS",
    "SCHEMA_VERSION_DEFAULT",
    "SourceRevisionRef",
    "TerminalDecisionRecord",
    "VerificationResult",
    "WorkAdmissionIssuer",
    "WorkContract",
    "build_admission_receipt",
    "build_execution_identity",
    "build_source_revision_ref",
    "build_terminal_decision",
    "build_verification_result",
    "build_work_contract",
    "coerce_source_revision_ref",
    "compute_content_tree_hash",
]
