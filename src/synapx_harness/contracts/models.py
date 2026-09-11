"""Contract models for SynapX-Harness.

Contains lightweight enums and dataclasses for OKF, Governance, and
Runtime contracts. The Core does not yet validate contracts; it only
exposes the public names required by the CLI and tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DocumentState(StrEnum):
    """Allowed document state values."""

    INBOX = "INBOX"
    RAW = "RAW"
    DRAFT = "DRAFT"
    REVIEW_CANDIDATE = "REVIEW_CANDIDATE"
    RELEASE_CANDIDATE = "RELEASE_CANDIDATE"
    RATIFIED = "RATIFIED"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETIRED = "RETIRED"


class KnowledgeClass(StrEnum):
    STRUCTURAL_FACT = "STRUCTURAL_FACT"
    SEMANTIC_ASSERTION = "SEMANTIC_ASSERTION"
    DECISION_CANDIDATE = "DECISION_CANDIDATE"
    UNKNOWN = "UNKNOWN"


class Authority(StrEnum):
    SOURCE_DERIVED = "SOURCE_DERIVED"
    NON_AUTHORITATIVE = "NON_AUTHORITATIVE"
    RATIFIED = "RATIFIED"
    ACTIVE_CANONICAL = "ACTIVE_CANONICAL"


class PilotRisk(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


EXECUTION_NEGATIVE_STATES: frozenset[DocumentState] = frozenset(
    {
        DocumentState.RAW,
        DocumentState.DRAFT,
        DocumentState.REVIEW_CANDIDATE,
        DocumentState.RELEASE_CANDIDATE,
    }
)


@dataclass(frozen=True)
class ContractDescriptor:
    """Static descriptor for a contract schema."""

    contract_type: str
    schema_version: str
    kind: str


__all__ = [
    "Authority",
    "ContractDescriptor",
    "DocumentState",
    "EXECUTION_NEGATIVE_STATES",
    "KnowledgeClass",
    "PilotRisk",
]
