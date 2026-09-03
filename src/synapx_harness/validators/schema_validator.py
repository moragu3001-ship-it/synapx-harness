"""Schema validator.

Validates the ContractSpec/WorkContract JSON schema. Used by the Contracted Admission gate.

The validator loads JSON Schema files from the on-disk `schemas/` tree
and validates a Python dict against a chosen schema by relative path.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

SCHEMAS_ROOT_ENV = "SYNAPX_HARNESS_SCHEMAS_ROOT"
DEFAULT_SCHEMAS_ROOT = "schemas"


@dataclass(frozen=True)
class SchemaValidationReport:
    ok: bool
    errors: tuple[str, ...]
    schema_path: str

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "schema_path": self.schema_path,
        }


def _resolve_schemas_root(package_root: Path) -> Path:
    candidate = package_root / DEFAULT_SCHEMAS_ROOT
    if candidate.is_dir():
        return candidate
    raise FileNotFoundError(f"schemas not found at {candidate}")


def load_schema(schemas_root: Path, relative_path: str) -> dict[str, object]:
    schema_path = schemas_root / relative_path
    if not schema_path.is_file():
        raise FileNotFoundError(f"schema not found: {schema_path}")
    with schema_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_payload(
    *,
    package_root: Path,
    schema_relative_path: str,
    payload: object,
) -> SchemaValidationReport:
    """Validate a payload against a JSON Schema 2020-12 file."""
    schemas_root = _resolve_schemas_root(package_root)
    schema = load_schema(schemas_root, schema_relative_path)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        return SchemaValidationReport(
            ok=False,
            errors=(f"schema invalid: {exc.message}",),
            schema_path=schema_relative_path,
        )
    validator = Draft202012Validator(schema)
    json_payload: Any = json.loads(json.dumps(payload))
    errors = tuple(
        f"{'.'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(json_payload)
    )
    return SchemaValidationReport(
        ok=not errors,
        errors=errors,
        schema_path=schema_relative_path,
    )


__all__ = ["SchemaValidationReport", "load_schema", "validate_payload"]
