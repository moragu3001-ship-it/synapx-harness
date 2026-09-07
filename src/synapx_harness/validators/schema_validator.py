"""Schema validator.

Validates the ContractSpec/WorkContract JSON schema. Used by the Contracted Admission gate.

The validator loads JSON Schema files from the authoritative packaged
schema set shipped with the distribution (``synapx_harness._schemas``).
This works identically in source checkout and installed wheel because the
schemas live inside the Python package and are auto-included by uv_build.

For test/back-compat callers that already hold a :class:`pathlib.Path`,
:func:`load_schema` still accepts either a Path or any Traversable. The
canonical installed-wheel-safe path is :func:`load_schema_from_package`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

PACKAGED_SCHEMAS_PACKAGE = "synapx_harness._schemas"

DEFAULT_SCHEMAS_ROOT = "schemas"

SchemasRoot = Union[Path, "Traversable"]  # type: ignore[name-defined]


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


def packaged_schemas_root():
    """Return the package resource root for the packaged schemas.

    Uses :func:`importlib.resources.files` so that the returned Traversable
    resolves identically in source checkout (regular directory Traversable)
    and installed wheel (zip-namespace Traversable). Callers should join
    a relative schema path with ``/`` and use :func:`load_schema` (or the
    dedicated :func:`load_schema_from_package`) to read.

    Returns:
        The package resource root as a Traversable.

    Raises:
        FileNotFoundError: If the packaged schemas package cannot be
            resolved. This is the fail-closed behaviour for a broken or
            mis-packaged distribution: the validator refuses to fall back
            to any developer-machine or sibling-repository schema set.
    """
    from importlib.resources import files

    traversable = files(PACKAGED_SCHEMAS_PACKAGE)
    if traversable is None:
        raise FileNotFoundError(
            f"packaged schemas package {PACKAGED_SCHEMAS_PACKAGE!r} not found"
        )
    return traversable


def load_schema_from_package(relative_path: str) -> dict[str, object]:
    """Load a schema from the packaged schemas (installed-wheel-safe).

    This is the canonical loader for the SynapX-Harness distribution.
    Both source checkout and installed wheel resolve to the same
    authoritative schema set because the schemas are part of the Python
    package.

    Args:
        relative_path: Path relative to the schemas root, e.g.
            ``"governance/policy.schema.json"``.

    Returns:
        Parsed JSON Schema document as a dict.

    Raises:
        FileNotFoundError: If the schema file is not present in the
            packaged resource. This is fail-closed: there is no fallback
            to other repositories, environment variables, or absolute
            developer paths.
    """
    root = packaged_schemas_root()
    schema_resource = root.joinpath(relative_path)
    if not schema_resource.is_file():
        raise FileNotFoundError(
            f"schema not found in package {PACKAGED_SCHEMAS_PACKAGE!r}: "
            f"{relative_path!r}"
        )
    with schema_resource.open("r", encoding="utf-8") as fh:
        result: dict[str, object] = json.load(fh)
    return result


def load_schema(schemas_root: SchemasRoot, relative_path: str) -> dict[str, object]:
    """Load a schema from an explicit on-disk root (test/back-compat).

    ``schemas_root`` may be a :class:`pathlib.Path` (legacy / on-disk
    fixtures) or any Traversable such as the package resource root
    returned by :func:`packaged_schemas_root`.

    Args:
        schemas_root: Directory containing the schema tree.
        relative_path: Path relative to ``schemas_root``.

    Returns:
        Parsed JSON Schema document as a dict.

    Raises:
        FileNotFoundError: If the schema file is not present.
    """
    schema_path = schemas_root / relative_path
    if not schema_path.is_file():
        raise FileNotFoundError(f"schema not found: {schema_path}")
    with schema_path.open("r", encoding="utf-8") as fh:
        result: dict[str, object] = json.load(fh)
    return result


def _resolve_schemas_root(package_root: Path) -> Path:
    """Backward-compat resolver for callers that pass a package directory.

    Used by the legacy :func:`validate_payload` signature that takes a
    ``package_root`` and expects to find a ``schemas`` subdirectory
    beneath it. New code should call :func:`packaged_schemas_root` or
    :func:`load_schema_from_package` directly.
    """
    candidate = package_root / DEFAULT_SCHEMAS_ROOT
    if candidate.is_dir():
        return candidate
    raise FileNotFoundError(f"schemas not found at {candidate}")


def validate_payload(
    *,
    package_root: Path,
    schema_relative_path: str,
    payload: object,
) -> SchemaValidationReport:
    """Validate a payload against a JSON Schema 2020-12 file.

    This legacy API is kept for back-compat with callers that already hold
    a ``package_root`` Path. It still goes through the packaged schema
    set, so installed wheels work correctly. For new code, prefer
    :func:`load_schema_from_package` followed by direct
    :class:`jsonschema.Draft202012Validator` invocation.
    """
    schema = load_schema_from_package(schema_relative_path)
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


__all__ = [
    "DEFAULT_SCHEMAS_ROOT",
    "PACKAGED_SCHEMAS_PACKAGE",
    "SchemaValidationReport",
    "load_schema",
    "load_schema_from_package",
    "packaged_schemas_root",
    "validate_payload",
]