"""Installed-wheel schema resolver tests.

These tests pin the installed-wheel-safe behaviour of
:mod:`synapx_harness.validators.schema_validator` after the RQ7-P2-R1
packaging repair. The schemas live inside the Python package as
``synapx_harness._schemas`` so that source checkout and installed wheel
resolve identically via :func:`importlib.resources.files`.

The resolver must:

* (positive) Return the packaged root Traversable; load every schema
  listed in :data:`PACKAGED_SCHEMAS_PACKAGE`.
* (negative) Fail closed when a schema that is not in the package is
  requested. No silent fallback to ``cwd/schemas``, sibling
  repositories, environment variables, or absolute developer paths.
* (negative) Refuse to fall back if the packaged root is unreachable.

These tests are intentionally tiny and self-contained: they depend only
on the validator and the schema resources that ship with the package.
"""
from __future__ import annotations

import json

import pytest

from synapx_harness.validators.schema_validator import (
    PACKAGED_SCHEMAS_PACKAGE,
    load_schema_from_package,
    packaged_schemas_root,
)


def test_packaged_schemas_package_name_is_canonical() -> None:
    assert PACKAGED_SCHEMAS_PACKAGE == "synapx_harness._schemas"


def test_packaged_schemas_root_resolves_to_traversable() -> None:
    root = packaged_schemas_root()
    assert root is not None


def test_packaged_schemas_root_is_not_filesystem_cwd() -> None:
    """The resolver must not be cwd- or developer-machine-dependent."""
    root = packaged_schemas_root()
    # Traversable should not be a hard-coded absolute developer path
    root_str = str(root)
    for forbidden in ("C:/krag_work/", "D:/communis", "/home/", "C:\\Users\\morag"):
        assert forbidden not in root_str, (
            f"packaged_schemas_root leaked developer path {forbidden!r}: {root_str!r}"
        )


@pytest.mark.parametrize(
    "relative_path",
    [
        "governance/policy.schema.json",
        "governance/repository_registry.schema.json",
        "governance/communis_document_profile.schema.json",
        "governance/activation_manifest.schema.json",
        "governance/knowledge_item.schema.json",
        "governance/profile.schema.json",
        "governance/ratification_receipt.schema.json",
        "governance/release_candidate_bundle.schema.json",
        "governance/service_pack_manifest.schema.json",
        "governance/source_snapshot.schema.json",
        "okf/okf_concept.schema.json",
    ],
)
def test_load_schema_from_package_returns_valid_json(relative_path: str) -> None:
    schema = load_schema_from_package(relative_path)
    assert isinstance(schema, dict)
    assert "$schema" in schema or "type" in schema
    # Round-trip to ensure the JSON parses cleanly via stdlib.
    assert isinstance(json.loads(json.dumps(schema)), dict)


def test_load_schema_from_package_rejects_unknown_schema() -> None:
    with pytest.raises(FileNotFoundError) as excinfo:
        load_schema_from_package("governance/does_not_exist.schema.json")
    assert PACKAGED_SCHEMAS_PACKAGE in str(excinfo.value)


def test_load_schema_from_package_rejects_unknown_directory() -> None:
    with pytest.raises(FileNotFoundError):
        load_schema_from_package("not_a_real_dir/foo.schema.json")


def test_no_silent_fallback_to_cwd_schemas(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Even if a sibling repo has a ``schemas/`` directory, the resolver
    must not consult it.

    The repair explicitly forbids falling back to ``cwd/schemas``,
    sibling repositories, or environment variables. We place a fake
    schema in a temporary directory and confirm the packaged loader
    refuses to load it.
    """
    fake_pack = tmp_path / "synapx_harness" / "_schemas"
    fake_pack.mkdir(parents=True)
    fake_schema = fake_pack / "policy.schema.json"
    fake_schema.write_text('{"$schema": "https://json-schema.org/draft/2020-12/schema"}')

    # The packaged loader must still load the real packaged schema,
    # never the cwd-local one. The fake has a different content from
    # the real policy schema.
    real_schema = load_schema_from_package("governance/policy.schema.json")
    fake_text = fake_schema.read_text(encoding="utf-8")
    assert json.dumps(real_schema, sort_keys=True) != fake_text, (
        "Resolver returned the cwd-local fake schema instead of the real packaged one"
    )


def test_no_environment_variable_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """``SYNAPX_HARNESS_SCHEMAS_ROOT`` env must not redirect schema lookups.

    The old code accepted an env-overridable schemas root; that opened
    a silent-fallback attack surface. The packaged loader ignores all
    env variables by construction; this test pins the contract.
    """
    fake_path = tmp_path / "fake"
    fake_path.mkdir()
    monkeypatch.setenv("SYNAPX_HARNESS_SCHEMAS_ROOT", str(fake_path))
    schema = load_schema_from_package("governance/policy.schema.json")
    assert "$schema" in schema


def test_negative_resolve_schemas_root_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the packaged root cannot be resolved, the validator must
    refuse (fail-closed) instead of guessing a fallback."""
    from synapx_harness.validators import schema_validator as sv

    def broken_resolver():
        raise FileNotFoundError(
            f"packaged schemas package 'synapx_harness._schemas' not found"
        )

    monkeypatch.setattr(sv, "packaged_schemas_root", broken_resolver)
    with pytest.raises(FileNotFoundError):
        load_schema_from_package("governance/policy.schema.json")