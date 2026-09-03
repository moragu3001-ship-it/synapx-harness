"""Negative environment isolation tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.isolation_validator import (
    BACKUP_DIR_NAME,
    FORBIDDEN_PACKAGE_NAMES,
    validate_isolation,
    validate_package_scope,
)

CORE_ROOT = Path(__file__).resolve().parents[2]
SERVICE_PACK_ROOT = Path(__file__).resolve().parents[2].parent / "communis-pilot-service-pack"
NEW_KILO_ROOT = Path(__file__).resolve().parents[2].parent / ".kilo"


def test_backup_marker_is_canonical() -> None:
    assert BACKUP_DIR_NAME == "kilo-pre-communis-customos-20260723"


def test_forbidden_package_names_listed() -> None:
    assert "company_customos" in FORBIDDEN_PACKAGE_NAMES


def test_environment_isolation_pass(service_pack_root: Path) -> None:
    kilo = NEW_KILO_ROOT if NEW_KILO_ROOT.is_dir() else None
    report = validate_isolation(
        core_root=CORE_ROOT,
        service_pack_root=service_pack_root,
        kilo_root=kilo,
    )
    assert report.gate == "PASS", report.violations
    assert report.synapx_runtime_import_count == 0
    assert report.legacy_kilo_runtime_dependency_count == 0
    assert report.legacy_wiki_copy_count == 0
    assert report.legacy_script_copy_count == 0
    assert report.reference_symlink_count == 0
    assert report.forbidden_package_name_count == 0


def test_legacy_kilo_backup_is_not_imported() -> None:
    src_dir = CORE_ROOT / "src"
    for path in src_dir.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        assert "kilo-pre-communis-customos-20260723\\scripts" not in text
        assert "kilo-pre-communis-customos-20260723\\wiki" not in text


def test_legacy_kilo_backup_is_not_symlinked() -> None:
    for root in (CORE_ROOT, CORE_ROOT / "schemas", CORE_ROOT / "tests"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_symlink() or path.is_junction():
                target = str(path.resolve())
                assert "kilo-pre-communis-customos-20260723" not in target


def test_package_scope_rejects_pyc() -> None:
    report = validate_package_scope(["synapx-harness/src/synapx_harness/foo.pyc"])
    assert not report.ok
    assert any("foo.pyc" in p for p in report.excluded_paths)


def test_package_scope_rejects_pycache() -> None:
    report = validate_package_scope(["synapx-harness/__pycache__/foo.pyc"])
    assert not report.ok


def test_package_scope_rejects_duplicate_exact() -> None:
    report = validate_package_scope(
        ["synapx-harness/src/foo.py", "synapx-harness/src/foo.py"]
    )
    assert not report.ok


def test_package_scope_rejects_casefold_duplicate() -> None:
    report = validate_package_scope(
        ["synapx-harness/src/Foo.py", "synapx-harness/src/foo.py"]
    )
    assert not report.ok


def test_package_scope_rejects_backslash_path() -> None:
    report = validate_package_scope(["synapx-harness\\src\\foo.py"])
    assert report.ok, "backslashes are normalized to forward slashes"
