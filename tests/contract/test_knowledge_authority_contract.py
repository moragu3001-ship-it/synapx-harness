"""Knowledge authority contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.contracts.models import EXECUTION_NEGATIVE_STATES, DocumentState
from synapx_harness.validators.knowledge_authority_validator import (
    validate_knowledge_authority,
)
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_structural_fact_can_be_source_derived() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/knowledge_item.schema.json",
        payload={
            "contract_type": "COMMUNIS_KNOWLEDGE_ITEM",
            "schema_version": "0.1.0",
            "knowledge_class": "STRUCTURAL_FACT",
            "authority": "SOURCE_DERIVED",
        },
    )
    assert report.ok, report.errors


def test_semantic_assertion_is_non_authoritative_by_default() -> None:
    """SEMANTIC_ASSERTION items must default to NON_AUTHORITATIVE; ACTIVE_CANONICAL is rejected."""
    payload = {
        "contract_type": "COMMUNIS_KNOWLEDGE_ITEM",
        "schema_version": "0.1.0",
        "knowledge_class": "SEMANTIC_ASSERTION",
        "authority": "ACTIVE_CANONICAL",
    }
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/knowledge_item.schema.json",
        payload=payload,
    )
    # The schema's allOf rule rejects ACTIVE_CANONICAL when knowledge_class is SEMANTIC_ASSERTION.
    assert not schema_report.ok, schema_report.errors
    auth_report = validate_knowledge_authority(payload)
    assert not auth_report.ok


def test_raw_document_has_no_execution_authority() -> None:
    assert DocumentState.RAW in EXECUTION_NEGATIVE_STATES


def test_draft_document_has_no_execution_authority() -> None:
    assert DocumentState.DRAFT in EXECUTION_NEGATIVE_STATES


def test_release_candidate_has_no_execution_authority() -> None:
    assert DocumentState.RELEASE_CANDIDATE in EXECUTION_NEGATIVE_STATES


def test_company_contract_requires_contract_type() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload={"schema_version": "0.1.0"},
    )
    assert not report.ok, report.errors


def test_company_contract_requires_schema_version() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload={"contract_type": "X"},
    )
    assert not report.ok, report.errors
