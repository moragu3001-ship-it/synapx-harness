"""Contract registry for SynapX-Harness.

Registers contract descriptors by kind. The registry is loaded
statically from the schemas directory layout; it does not read
documents from disk.
"""
from __future__ import annotations

from synapx_harness.contracts.models import ContractDescriptor


def _make_descriptors() -> dict[str, ContractDescriptor]:
    descriptors = {
        "okf_concept": ContractDescriptor(
            contract_type="OKF_CONCEPT",
            schema_version="0.1.0",
            kind="okf",
        ),
        "communis_document_profile": ContractDescriptor(
            contract_type="COMMUNIS_DOCUMENT_PROFILE",
            schema_version="0.1.0",
            kind="governance",
        ),
        "knowledge_item": ContractDescriptor(
            contract_type="COMMUNIS_KNOWLEDGE_ITEM",
            schema_version="0.1.0",
            kind="governance",
        ),
        "repository_registry": ContractDescriptor(
            contract_type="COMMUNIS_REPOSITORY_REGISTRY",
            schema_version="0.1.0",
            kind="governance",
        ),
        "source_snapshot": ContractDescriptor(
            contract_type="COMMUNIS_SOURCE_SNAPSHOT",
            schema_version="0.1.0",
            kind="governance",
        ),
        "release_candidate_bundle": ContractDescriptor(
            contract_type="COMMUNIS_RC_BUNDLE",
            schema_version="0.1.0",
            kind="governance",
        ),
        "ratification_receipt": ContractDescriptor(
            contract_type="COMMUNIS_RATIFICATION_RECEIPT",
            schema_version="0.1.0",
            kind="governance",
        ),
        "activation_manifest": ContractDescriptor(
            contract_type="COMMUNIS_ACTIVATION_MANIFEST",
            schema_version="0.1.0",
            kind="governance",
        ),
        "work_contract": ContractDescriptor(
            contract_type="CUSTOMOS_WORK_CONTRACT",
            schema_version="0.2.0",
            kind="runtime",
        ),
        "verification_result": ContractDescriptor(
            contract_type="CUSTOMOS_VERIFICATION_RESULT",
            schema_version="0.1.0",
            kind="runtime",
        ),
        "terminal_decision": ContractDescriptor(
            contract_type="CUSTOMOS_TERMINAL_DECISION",
            schema_version="0.1.0",
            kind="runtime",
        ),
    }
    # Allow governance policies / manifests to be schema-checked even when
    # no dedicated schema file exists. They are validated against the
    # ratification_receipt / activation_manifest / knowledge_item /
    # document_profile contract skeletons (the closest shape), with the
    # additional invariants enforced by `validate_governance`.
    extras = {
        "service_pack_manifest": ContractDescriptor(
            contract_type="COMMUNIS_SERVICE_PACK_MANIFEST",
            schema_version="0.1.0",
            kind="governance",
        ),
        "source_read_only_policy": ContractDescriptor(
            contract_type="COMMUNIS_SOURCE_READ_ONLY_POLICY",
            schema_version="0.1.0",
            kind="governance",
        ),
        "knowledge_authority_policy": ContractDescriptor(
            contract_type="COMMUNIS_KNOWLEDGE_AUTHORITY_POLICY",
            schema_version="0.1.0",
            kind="governance",
        ),
        "ratification_policy": ContractDescriptor(
            contract_type="COMMUNIS_RATIFICATION_POLICY",
            schema_version="0.1.0",
            kind="governance",
        ),
        "activation_policy": ContractDescriptor(
            contract_type="COMMUNIS_ACTIVATION_POLICY",
            schema_version="0.1.0",
            kind="governance",
        ),
        "pilot_risk_policy": ContractDescriptor(
            contract_type="COMMUNIS_PILOT_RISK_POLICY",
            schema_version="0.1.0",
            kind="governance",
        ),
        "as_is_profile": ContractDescriptor(
            contract_type="COMMUNIS_AS_IS_PROFILE",
            schema_version="0.1.0",
            kind="governance",
        ),
    }
    descriptors.update(extras)
    return descriptors


REGISTRY: dict[str, ContractDescriptor] = _make_descriptors()


def get(contract_id: str) -> ContractDescriptor:
    """Return the descriptor for a contract_id.

    Raises
    ------
    KeyError
        If the contract_id is not registered.
    """
    return REGISTRY[contract_id]


__all__ = ["REGISTRY", "get"]
