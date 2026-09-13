"""R2 Isolation Validator coverage tests."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from synapx_harness.validators.isolation_validator import (
    FORBIDDEN_PACKAGE_NAMES,
    validate_isolation,
    validate_package_scope,
)

CORE_ROOT = Path(__file__).resolve().parents[2]


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def _make_directory_link(target: Path, link: Path) -> None:
    """Create a directory link — symlink preferred, junction fallback.

    Windows without developer mode raises OSError 1314 on symlink
    creation; ``cmd /c mklink /J`` creates a junction without elevated
    privilege. The isolation validator's ``_is_reparse_point`` detects
    both (verified: junction yields is_symlink=False, is_junction=True).
    """
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        pass
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"symlink/junction creation not permitted: {result.stderr}")


def test_forbidden_reference_inside_json_is_detected(tmp_path: Path) -> None:
    _write(
        tmp_path / "src" / "forbidden.json",
        '{"ref": "kilo-pre-communis-customos-20260723\\scripts"}',
    )
    report = validate_isolation(core_root=tmp_path)
    assert not report.ok


def test_forbidden_reference_inside_yaml_is_detected(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "x.yaml", 'ref: "kilo-pre-communis-customos-20260723\\scripts"')
    report = validate_isolation(core_root=tmp_path)
    assert not report.ok


def test_forbidden_reference_inside_markdown_is_detected(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "x.md", 'see kilo-pre-communis-customos-20260723\\wiki for legacy')
    report = validate_isolation(core_root=tmp_path)
    assert not report.ok


def test_service_pack_policies_are_scanned(service_pack_root: Path, tmp_path: Path) -> None:
    _write(
        service_pack_root / "policies" / "x.yaml",
        'ref: "kilo-pre-communis-customos-20260723\\scripts"\n',
    )
    try:
        report = validate_isolation(
            core_root=tmp_path,
            service_pack_root=service_pack_root,
        )
        assert not report.ok
    finally:
        (service_pack_root / "policies" / "x.yaml").unlink()


def test_service_pack_profiles_are_scanned(service_pack_root: Path, tmp_path: Path) -> None:
    _write(
        service_pack_root / "profiles" / "x.yaml",
        'ref: "kilo-pre-communis-customos-20260723\\wiki"\n',
    )
    try:
        report = validate_isolation(
            core_root=tmp_path,
            service_pack_root=service_pack_root,
        )
        assert not report.ok
    finally:
        (service_pack_root / "profiles" / "x.yaml").unlink()


def test_repository_registry_is_scanned(service_pack_root: Path, tmp_path: Path) -> None:
    _write(
        service_pack_root / "repository-registry" / "x.yaml",
        'ref: "kilo-pre-communis-customos-20260723\\scripts"\n',
    )
    try:
        report = validate_isolation(
            core_root=tmp_path,
            service_pack_root=service_pack_root,
        )
        assert not report.ok
    finally:
        (service_pack_root / "repository-registry" / "x.yaml").unlink()


def test_integrations_directory_is_scanned(service_pack_root: Path, tmp_path: Path) -> None:
    _write(
        service_pack_root / "integrations" / "x.md",
        'see kilo-pre-communis-customos-20260723\\scripts\n',
    )
    try:
        report = validate_isolation(
            core_root=tmp_path,
            service_pack_root=service_pack_root,
        )
        assert not report.ok
    finally:
        (service_pack_root / "integrations" / "x.md").unlink()


def test_directory_symlink_is_detected(tmp_path: Path) -> None:
    """Create a directory symlink (junction fallback on Windows without
    the symlink privilege) and assert that the isolation validator
    rejects it. The test fails (not skips) when link creation is
    unavailable so that the suite can detect the platform gap."""
    real = tmp_path / "real"
    real.mkdir()
    (real / "src").mkdir()
    target = tmp_path / "linked"
    _make_directory_link(real, target)
    report = validate_isolation(core_root=target)
    assert not report.ok


def test_reference_exception_is_narrow_and_explicit() -> None:
    """The forbidden packages list must include the explicitly forbidden names."""
    assert "company_customos" in FORBIDDEN_PACKAGE_NAMES


def test_package_scope_rejects_pyc() -> None:
    report = validate_package_scope(["synapx-harness/foo.pyc"])
    assert not report.ok


def test_package_scope_rejects_pycache() -> None:
    report = validate_package_scope(["synapx-harness/__pycache__/foo.pyc"])
    assert not report.ok


def test_package_scope_rejects_venv() -> None:
    report = validate_package_scope(["synapx-harness/.venv/foo.py"])
    assert not report.ok


def test_package_scope_rejects_node_modules() -> None:
    report = validate_package_scope(["synapx-harness/node_modules/foo.js"])
    assert not report.ok
