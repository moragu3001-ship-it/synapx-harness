"""R3 Portable Test Environment (no pytest.skip, deterministic).

The R3 portable suite removes every :func:`pytest.skip` call so the
test results are deterministic on every host. The temporary service
pack fixture creates a self-contained layout under ``tmp_path`` and
the suite verifies each rule without consulting the host.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.conftest import (
    _resolve_service_pack_root,
    make_temporary_service_pack,
)

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_no_contract_test_contains_pytest_skip() -> None:
    """No ``tests/contract/*.py`` may contain ``pytest.skip``."""
    contract_dir = CORE_ROOT / "tests" / "contract"
    offenders: list[Path] = []
    here = Path(__file__).resolve()
    for path in contract_dir.rglob("*.py"):
        if path.resolve() == here:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "pytest.skip" in text:
            offenders.append(path)
    assert not offenders, f"contract tests with pytest.skip: {offenders}"


def test_no_negative_test_contains_pytest_skip() -> None:
    """No ``tests/negative/*.py`` may contain ``pytest.skip``."""
    negative_dir = CORE_ROOT / "tests" / "negative"
    offenders: list[Path] = []
    here = Path(__file__).resolve()
    for path in negative_dir.rglob("*.py"):
        if path.resolve() == here:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "pytest.skip" in text:
            offenders.append(path)
    assert not offenders, f"negative tests with pytest.skip: {offenders}"


def test_sibling_resolution_uses_temporary_layout(tmp_path: Path) -> None:
    """Sibling resolution succeeds against an isolated ``tmp_path``.

    Builds a temporary core/service-pack pair *without* using the
    on-disk ``D:/communis`` paths and exercises the portable resolver.
    """
    pack = make_temporary_service_pack(tmp_path / "fixture")
    os.environ["SYNAPX_HARNESS_SERVICE_PACK_ROOT"] = str(pack)
    resolved = _resolve_service_pack_root(CORE_ROOT)
    assert resolved == pack.resolve()


def test_missing_pack_fails_deterministically(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Missing service pack root raises pytest.fail (not skip)."""
    missing_root = tmp_path / "missing_pack_dir"
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(missing_root))
    with pytest.raises(pytest.fail.Exception):
        _resolve_service_pack_root(CORE_ROOT)


def test_temporary_service_pack_is_self_contained(tmp_path: Path) -> None:
    """The fixture produces every required directory and policy."""
    pack = make_temporary_service_pack(tmp_path / "self")
    expected_dirs = {
        "repository-registry",
        "profiles",
        "policies",
        ".kiro",
        "llm-wiki",
        "governance",
        "integrations",
        "tests",
        "evidence",
    }
    missing = [name for name in expected_dirs if not (pack / name).is_dir()]
    assert not missing, f"missing fixture dirs: {missing}"
    expected_files = {
        "repository-registry/repositories.yaml",
        "policies/source_read_only_policy.yaml",
        "policies/knowledge_authority_policy.yaml",
        "policies/ratification_policy.yaml",
        "policies/activation_policy.yaml",
        "policies/pilot_risk_policy.yaml",
        "profiles/x.yaml",
    }
    missing_files = [name for name in expected_files if not (pack / name).is_file()]
    assert not missing_files, f"missing fixture files: {missing_files}"


def test_resolve_uses_env_when_provided(
    monkeypatch: pytest.MonkeyPatch, temporary_service_pack_root: Path
) -> None:
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(temporary_service_pack_root))
    resolved = _resolve_service_pack_root(CORE_ROOT)
    assert resolved == temporary_service_pack_root.resolve()
