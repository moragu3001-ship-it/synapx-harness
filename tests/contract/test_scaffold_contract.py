"""Scaffold contract tests.

These tests verify that the synapx-harness and service-pack scaffolds
satisfy the structural contract required by the bootstrap phase.
"""
from __future__ import annotations

from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]


def test_synapx_harness_required_directories_exist(core_root: Path) -> None:
    expected = [
        core_root / "src" / "synapx_harness",
        core_root / "src" / "synapx_harness" / "cli",
        core_root / "src" / "synapx_harness" / "contracts",
        core_root / "src" / "synapx_harness" / "kernel",
        core_root / "src" / "synapx_harness" / "validators",
        core_root / "src" / "synapx_harness" / "adapters" / "kiro",
        core_root / "src" / "synapx_harness" / "_schemas" / "okf",
        core_root / "src" / "synapx_harness" / "_schemas" / "governance",
        core_root / "src" / "synapx_harness" / "_schemas" / "runtime",
        core_root / "tests" / "unit",
        core_root / "tests" / "contract",
        core_root / "tests" / "negative",
        core_root / "tests" / "fixtures" / "valid",
        core_root / "tests" / "fixtures" / "invalid",
    ]
    missing = [str(p) for p in expected if not p.is_dir()]
    assert not missing, f"missing directories: {missing}"


def test_service_pack_required_directories_exist(service_pack_root: Path) -> None:
    expected = [
        "repository-registry",
        "profiles",
        "policies",
        ".kiro",
        "llm-wiki",
        "governance",
        "integrations",
        "tests",
        "evidence",
    ]
    missing = [name for name in expected if not (service_pack_root / name).is_dir()]
    assert not missing, f"missing directories: {missing}"


def test_package_name_is_synapx_harness() -> None:
    pyproject = (CORE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "synapx-harness"' in pyproject
    assert "synapx_harness" in pyproject


def test_company_customos_package_does_not_exist() -> None:
    forbidden = [
        CORE_ROOT / "src" / "company_customos",
        CORE_ROOT / "src" / "company_customos_core",
        CORE_ROOT / "src" / "company-customos",
        CORE_ROOT / "src" / "company-customos-core",
    ]
    for path in forbidden:
        assert not path.exists(), f"forbidden package path exists: {path}"


def test_kiro_adapter_is_protocol_placeholder_only() -> None:
    kiro_dir = CORE_ROOT / "src" / "synapx_harness" / "adapters" / "kiro"
    files = sorted(p.name for p in kiro_dir.iterdir() if p.is_file())
    assert files == ["README.md", "__init__.py", "protocol.py"], files


def test_kilo_runtime_adapter_does_not_exist() -> None:
    forbidden = [
        CORE_ROOT / "src" / "synapx_harness" / "adapters" / "kilo",
        CORE_ROOT / "src" / "synapx_harness" / "adapters" / "kilo_runtime",
    ]
    for path in forbidden:
        assert not path.exists(), f"forbidden adapter: {path}"


def test_legacy_kilo_backup_is_not_imported() -> None:
    """No product code path may reference the backup path."""
    src_dir = CORE_ROOT / "src"
    forbidden_substrings = [
        "kilo-pre-communis-customos-20260723\\scripts",
        "kilo-pre-communis-customos-20260723\\wiki",
    ]
    for path in src_dir.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in forbidden_substrings:
            assert needle not in text, f"backup path leaked into {path}"


def test_legacy_kilo_backup_is_not_symlinked() -> None:
    """No symlink or junction may point at the backup path."""
    schemas_root = CORE_ROOT / "src" / "synapx_harness" / "_schemas"
    for root in (CORE_ROOT, schemas_root, CORE_ROOT / "tests"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_symlink() or path.is_junction():
                target = str(path.resolve())
                assert "kilo-pre-communis-customos-20260723" not in target, (
                    f"reparse point at backup: {path}"
                )


def test_phase_cannot_create_active_documents() -> None:
    """No ACTIVE_MANIFEST.json / OKF_ACTIVATION_MANIFEST.json may exist."""
    forbidden = [
        CORE_ROOT / "ACTIVE_MANIFEST.json",
        CORE_ROOT / "OKF_ACTIVATION_MANIFEST.json",
        CORE_ROOT / "ratification_receipt.json",
        CORE_ROOT / "release_candidate_bundle.json",
    ]
    for path in forbidden:
        assert not path.exists(), f"forbidden activation artifact: {path}"


def test_phase_cannot_create_activation_manifest() -> None:
    """No activation manifest directory."""
    forbidden = [
        CORE_ROOT / "active",
        CORE_ROOT / "activation",
        CORE_ROOT / "release_candidates",
    ]
    for path in forbidden:
        assert not path.exists(), f"forbidden manifest directory: {path}"
