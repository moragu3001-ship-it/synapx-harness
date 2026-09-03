"""Protocol-only placeholder for the future Kiro adapter.

This module defines the Kiro adapter boundary under the T06 Minimal
Skill/Extension Admission protocol (H2-I2). The Kiro adapter is
**strictly transport-only**:

  * request/proposal transport (no authority)
  * activation contract consumption (read-only consumption)
  * job-bound activation dispatch (no escalation of authority)
  * result/status projection (no authority claim)

The adapter MUST NOT:

  * self-authorize (I2-N01)
  * generate an ``SkillActivationContract`` (I2-N04)
  * generate an ``AUTHORIZED`` state (I2-N05 / X4-D02)
  * be the source of an ``ACTIVE_FOR_JOB`` transition authority
    (the only authoritative issuer is ``HARNESS_CORE_ADMISSION``).

The concrete Kiro hook surface remains intentionally empty — only a
``Protocol`` class is exported. Implementations are injected by the
caller.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

# T06 minimal protocol: the only authoritative issuer.
CORE_ISSUER: str = "HARNESS_CORE_ADMISSION"

# Issuers that the Kiro adapter is NOT permitted to masquerade as.
NON_AUTHORITATIVE_ISSUERS: frozenset[str] = frozenset(
    {"Scheduler", "Registry", "Provider", "LLM", "Adapter", "Agent"}
)


class KiroActivationAuthorityError(ValueError):
    """Raised when the Kiro adapter attempts an authority-bearing action."""


@dataclass(frozen=True)
class KiroTransportReceipt:
    """A neutral transport receipt.

    This receipt is a pure transport attestation: it is NEVER an
    authority artifact. Issuance does not promote any skill to
    ``ACTIVE_FOR_JOB``. The only authoritative issuer remains
    ``HARNESS_CORE_ADMISSION``.
    """

    receipt_id: str
    job_id: str
    attempt_id: str
    extension_id: str
    skill_id: str
    transport_kind: str
    source_revision_provenance: str

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "attempt_id": self.attempt_id,
            "extension_id": self.extension_id,
            "skill_id": self.skill_id,
            "transport_kind": self.transport_kind,
            "source_revision_provenance": self.source_revision_provenance,
        }


class KiroAdapterProtocol(Protocol):
    """Placeholder Protocol for Kiro adapter.

    The actual method surface is intentionally narrow. Any concrete
    implementation MUST NOT be added in this phase beyond the transport
    primitives below.
    """

    def adapter_id(self) -> str:
        """Return a stable identifier for the adapter."""
        ...

    def transport_proposal(
        self,
        *,
        proposal_payload: Mapping[str, object],
        job_id: str,
        attempt_id: str,
        extension_id: str,
        skill_id: str,
    ) -> KiroTransportReceipt:
        """Forward a SkillActivationProposal to the next layer.

        The proposal is data-only; the adapter MUST NOT generate an
        ``SkillActivationContract`` from it. The returned receipt is
        evidence of *transport*, not of authority.
        """
        ...

    def consume_activation_contract(
        self,
        *,
        activation_contract: Mapping[str, object],
    ) -> bool:
        """Confirm the contract is consumable in job-bound transport.

        The adapter reads ``activation_contract.issued_by``; it MUST
        verify that the value equals ``HARNESS_CORE_ADMISSION``. Any
        other value is rejected without writing transport state.
        """
        ...


# -- Transport-only helpers (no authority bearing) ------------------------


def assert_kiro_transport_only(
    *,
    activation_contract: Mapping[str, object] | None,
) -> str:
    """Enforce the strict fail-closed transport boundary (H2-I2-R1).

    Hard rules — every non-HARNESS_CORE_ADMISSION issuer is rejected:

      * ``activation_contract is None``                                 -> REJECT
      * ``"issued_by"`` key missing                                      -> REJECT
      * ``"issued_by"`` is ``None``                                     -> REJECT
      * ``"issued_by"`` is empty string                                 -> REJECT
      * ``"issued_by"`` is any of {Provider, Scheduler, Registry, LLM}  -> REJECT
      * ``"issued_by"`` is anything else other than HARNESS_CORE_ADMISSION -> REJECT

    The transport adapter MUST NOT normalize authorities. There is no
    "pending core issuance" exception. The contract carrier is either
    core-issued or rejected.
    """
    if activation_contract is None:
        raise KiroActivationAuthorityError(
            "Kiro transport requires a non-null activation_contract; "
            "the adapter cannot generate one (R1-N01 / I2-N04)."
        )
    if not isinstance(activation_contract, Mapping):
        raise KiroActivationAuthorityError(
            "Kiro transport requires a mapping-shaped contract "
            "(R1-N01 / adapter contract format invalid)."
        )
    if "issued_by" not in activation_contract:
        raise KiroActivationAuthorityError(
            "Kiro transport requires the contract to declare "
            "'issued_by'; missing key (R1-N01)."
        )
    raw = activation_contract["issued_by"]
    if raw is None:
        raise KiroActivationAuthorityError(
            "Kiro transport requires 'issued_by' to be a non-null value "
            "(R1-N02)."
        )
    issuer = str(raw)
    if issuer == "":
        raise KiroActivationAuthorityError(
            "Kiro transport rejects 'issued_by' empty-string; "
            "no normalization (R1-N02)."
        )
    if issuer != CORE_ISSUER:
        raise KiroActivationAuthorityError(
            f"Kiro transport rejects 'issued_by'={issuer!r}; "
            "the adapter consumes only HARNESS_CORE_ADMISSION "
            "(R1-N03 / I2-N04)."
        )
    return CORE_ISSUER


def build_kiro_transport_receipt(
    *,
    receipt_id: str,
    job_id: str,
    attempt_id: str,
    extension_id: str,
    skill_id: str,
    transport_kind: str,
    source_revision_provenance: str,
) -> KiroTransportReceipt:
    """Build a transport receipt for the Kiro adapter.

    The receipt is intentionally an audit artifact — it does NOT
    confer authority and the adapter MUST NOT use it as activation
    proof.
    """
    if not receipt_id or not receipt_id.strip():
        raise KiroActivationAuthorityError("receipt_id missing")
    if not job_id or not attempt_id:
        raise KiroActivationAuthorityError("job binding missing")
    if not extension_id or not skill_id:
        raise KiroActivationAuthorityError("extension/skill identity missing")
    return KiroTransportReceipt(
        receipt_id=receipt_id,
        job_id=job_id,
        attempt_id=attempt_id,
        extension_id=extension_id,
        skill_id=skill_id,
        transport_kind=transport_kind,
        source_revision_provenance=source_revision_provenance,
    )


__all__ = [
    "CORE_ISSUER",
    "KiroActivationAuthorityError",
    "KiroAdapterProtocol",
    "KiroTransportReceipt",
    "NON_AUTHORITATIVE_ISSUERS",
    "assert_kiro_transport_only",
    "build_kiro_transport_receipt",
]
