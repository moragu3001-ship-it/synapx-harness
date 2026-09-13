"""R2 Knowledge Authority enforcement tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.knowledge_authority_validator import (
    validate_knowledge_authority,
)
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_semantic_assertion_active_canonical_is_rejected() -> None:
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
    assert not schema_report.ok, schema_report.errors
    auth_report = validate_knowledge_authority(payload)
    assert not auth_report.ok


def test_semantic_assertion_defaults_to_non_authoritative() -> None:
    payload = {
        "contract_type": "COMMUNIS_KNOWLEDGE_ITEM",
        "schema_version": "0.1.0",
        "knowledge_class": "SEMANTIC_ASSERTION",
        "authority": "NON_AUTHORITATIVE",
    }
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/knowledge_item.schema.json",
        payload=payload,
    )
    assert report.ok, report.errors
    auth_report = validate_knowledge_authority(payload)
    assert auth_report.ok


def test_raw_document_execution_authority_true_is_rejected() -> None:
    payload = {
        "contract_type": "COMMUNIS_DOCUMENT_PROFILE",
        "schema_version": "0.1.0",
        "document_state": "RAW",
        "execution_authority": True,
    }
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload=payload,
    )
    assert not schema_report.ok, schema_report.errors
    auth_report = validate_knowledge_authority(payload)
    assert not auth_report.ok


def test_draft_document_execution_authority_true_is_rejected() -> None:
    payload = {
        "contract_type": "COMMUNIS_DOCUMENT_PROFILE",
        "schema_version": "0.1.0",
        "document_state": "DRAFT",
        "execution_authority": True,
    }
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload=payload,
    )
    assert not schema_report.ok, schema_report.errors


def test_review_candidate_execution_authority_true_is_rejected() -> None:
    payload = {
        "contract_type": "COMMUNIS_DOCUMENT_PROFILE",
        "schema_version": "0.1.0",
        "document_state": "REVIEW_CANDIDATE",
        "execution_authority": True,
    }
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload=payload,
    )
    assert not schema_report.ok, schema_report.errors


def test_release_candidate_execution_authority_true_is_rejected() -> None:
    payload = {
        "contract_type": "COMMUNIS_DOCUMENT_PROFILE",
        "schema_version": "0.1.0",
        "document_state": "RELEASE_CANDIDATE",
        "execution_authority": True,
    }
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload=payload,
    )
    assert not schema_report.ok, schema_report.errors


def test_active_canonical_requires_activation_reference() -> None:
    payload = {
        "contract_type": "COMMUNIS_DOCUMENT_PROFILE",
        "schema_version": "0.1.0",
        "authority": "ACTIVE_CANONICAL",
    }
    auth_report = validate_knowledge_authority(payload)
    assert not auth_report.ok


def test_unknown_authority_field_is_rejected() -> None:
    payload = {
        "contract_type": "COMMUNIS_DOCUMENT_PROFILE",
        "schema_version": "0.1.0",
        "authority": "GHOST_AUTHORITY",
    }
    schema_report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="governance/communis_document_profile.schema.json",
        payload=payload,
    )
    assert not schema_report.ok, schema_report.errors
