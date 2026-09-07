"""OKF base contract tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_okf_concept_requires_type() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="okf/okf_concept.schema.json",
        payload={"title": "x"},
    )
    assert not report.ok, report.errors


def test_okf_concept_accepts_minimal_payload() -> None:
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="okf/okf_concept.schema.json",
        payload={"type": "concept"},
    )
    assert report.ok, report.errors


def test_okf_concept_rejects_company_fields() -> None:
    """Company-specific fields must not be declared as OKF required fields."""
    schema_path = (
        CORE_ROOT / "src" / "synapx_harness" / "_schemas" / "okf" / "okf_concept.schema.json"
    )
    schema = schema_path.read_text(encoding="utf-8")
    for company_field in (
        "document_state",
        "ratification",
        "activation",
        "content_hash",
        "execution_authority",
        "work_contract",
        "terminal_decision",
    ):
        assert company_field not in schema, f"forbidden OKF field: {company_field}"
