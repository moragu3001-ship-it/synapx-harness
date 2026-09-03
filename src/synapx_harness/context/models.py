"""Lane C — Minimum Shared Understanding context models.

Canonical classification:
  FACT      - deterministically observed, source identifiable, revision bound
  ASSERTION - semantic/descriptive interpretation (non-authoritative)
  UNKNOWN   - insufficient / conflicting / absent evidence (first-class)

Structural authority isolation:
  Records carry no authority / policy / verification / terminal fields.
  ``extra="forbid"`` rejects any injected control-plane field.

Canonical JSON value contract (R1, CANONICAL_JSON_VALUE_TYPE_GAP closure):
  Record values are bound to the recursive JSON-safe type ``JsonValue``
  (strict mode). Arbitrary Python objects (``object()``, ``Path``,
  ``set``, ``bytes``, custom classes, functions, nested non-JSON values)
  are rejected at model construction, so model acceptance and
  ``model_dump(mode="json")`` serializability are one and the same.

The canonical context is provider-neutral: no Codex/agent-specific field
exists anywhere in the schema.
"""
from __future__ import annotations

from typing import Literal, TypeAliasType

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from synapx_harness.contracts.runtime_models import SourceRevisionRef

CONTEXT_CONTRACT_TYPE = "CUSTOMOS_SHARED_UNDERSTANDING_CONTEXT"
CONTEXT_SCHEMA_VERSION = "0.2.0"

UNKNOWN_REASONS: tuple[str, ...] = (
    "NOT_OBSERVED",
    "NO_EXPLICIT_SIGNAL",
    "CONFLICTING_SIGNALS",
    "UNSUPPORTED_FORMAT",
    "OUT_OF_SCOPE",
    "NOT_DETERMINISTICALLY_RESOLVABLE",
)

UNKNOWN_REASON_LITERALS = Literal[
    "NOT_OBSERVED",
    "NO_EXPLICIT_SIGNAL",
    "CONFLICTING_SIGNALS",
    "UNSUPPORTED_FORMAT",
    "OUT_OF_SCOPE",
    "NOT_DETERMINISTICALLY_RESOLVABLE",
]

QUALIFICATIONS: tuple[str, ...] = ("UNQUALIFIED",)

QUALIFICATION_LITERALS = Literal["UNQUALIFIED"]

JsonScalar = str | bool | int | float | None
JsonValue = TypeAliasType(  # noqa: UP040 — PEP 695 `type` needs 3.12+; fresh-extract interpreters may be 3.11
    "JsonValue",
    JsonScalar | list["JsonValue"] | dict[str, "JsonValue"],
)


def _assert_json_safe(value: object, *, path: str = "$") -> None:
    """Reject any Python object outside the recursive JSON domain."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_json_safe(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"non-string key {key!r} at {path} "
                    "(canonical JSON value contract)"
                )
            _assert_json_safe(item, path=f"{path}.{key}")
        return
    raise ValueError(
        f"non-JSON value at {path}: {type(value).__name__} "
        "(canonical JSON value contract)"
    )


class _StrictModel(BaseModel):
    """Base model: forbids extras, validates assignment, populates by name."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
    )


class FactRecord(_StrictModel):
    """Deterministic evidence-only fact.

    ``value`` is bound to the recursive JSON-safe type ``JsonValue`` and
    guarded by a pre-validation check: any Python object outside the JSON
    domain (``object()``, ``Path``, ``set``, ``bytes``, custom classes,
    functions, nested non-JSON values) is rejected at construction AND at
    assignment, guaranteeing canonical JSON serializability.
    """

    kind: Literal["FACT"] = "FACT"
    key: str = Field(min_length=1)
    value: JsonValue = None
    source: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    repository_revision: str = Field(min_length=1)

    @field_validator("value", mode="before")
    @classmethod
    def _reject_non_json_value(cls, value: object) -> object:
        _assert_json_safe(value)
        return value


class AssertionRecord(_StrictModel):
    """Non-authoritative semantic interpretation.

    ``confidence`` is a descriptive qualification only. It never grants
    authority: a confidence of 1.0 is still an ASSERTION. ``value`` uses
    the same JSON-safe boundary as facts.
    """

    kind: Literal["ASSERTION"] = "ASSERTION"
    key: str = Field(min_length=1)
    value: JsonValue = None
    source: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    repository_revision: str = Field(min_length=1)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    qualification: QUALIFICATION_LITERALS = "UNQUALIFIED"

    @field_validator("value", mode="before")
    @classmethod
    def _reject_non_json_value(cls, value: object) -> object:
        _assert_json_safe(value)
        return value


class UnknownRecord(_StrictModel):
    """First-class UNKNOWN with a preserved reason.

    ``value`` is always None: an UNKNOWN carries no invented value.
    """

    kind: Literal["UNKNOWN"] = "UNKNOWN"
    key: str = Field(min_length=1)
    value: None = None
    reason: UNKNOWN_REASON_LITERALS
    source: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    repository_revision: str = Field(min_length=1)


class RepositoryBinding(_StrictModel):
    """Repository identity and revision binding (provider-neutral)."""

    repository_id: str = Field(min_length=1)
    revision: SourceRevisionRef | None = None


class SharedUnderstandingContext(_StrictModel):
    """Canonical Shared Understanding context (provider-neutral).

    Context data only — never a control-plane authority. It cannot
    modify WorkContract, policy, authority, or terminal state.
    """

    contract_type: Literal["CUSTOMOS_SHARED_UNDERSTANDING_CONTEXT"] = (
        CONTEXT_CONTRACT_TYPE
    )
    schema_version: Literal["0.1.0", "0.2.0"] = CONTEXT_SCHEMA_VERSION
    repository: RepositoryBinding
    facts: list[FactRecord] = Field(default_factory=list)
    assertions: list[AssertionRecord] = Field(default_factory=list)
    unknowns: list[UnknownRecord] = Field(default_factory=list)


__all__ = [
    "AssertionRecord",
    "CONTEXT_CONTRACT_TYPE",
    "CONTEXT_SCHEMA_VERSION",
    "FactRecord",
    "JsonScalar",
    "JsonValue",
    "QUALIFICATIONS",
    "RepositoryBinding",
    "SharedUnderstandingContext",
    "UNKNOWN_REASONS",
    "UnknownRecord",
]
