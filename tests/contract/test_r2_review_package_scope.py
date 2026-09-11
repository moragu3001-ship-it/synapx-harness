"""R2 Review Package scope tests."""
from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from synapx_harness.review.package_builder import build_package
from synapx_harness.review.package_scope import (
    is_excluded,
    is_path_allowed,
    normalize_path,
)
from synapx_harness.review.package_verifier import verify_package
from synapx_harness.validators.isolation_validator import validate_package_scope


def test_review_zip_rejects_pycache(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/__pycache__/foo.pyc"])
    assert not report.ok
    assert any("__pycache__" in p for p in report.excluded_paths)


def test_review_zip_rejects_pyc(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/src/foo.pyc"])
    assert not report.ok
    assert any(p.endswith(".pyc") for p in report.excluded_paths)


def test_review_zip_rejects_venv(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/.venv/foo.py"])
    assert not report.ok


def test_review_zip_rejects_node_modules(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/node_modules/foo.js"])
    assert not report.ok


def test_review_zip_rejects_pytest_cache(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/.pytest_cache/foo"])
    assert not report.ok


def test_review_zip_rejects_ruff_cache(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/.ruff_cache/foo"])
    assert not report.ok


def test_zip_paths_use_forward_slashes() -> None:
    """`normalize_path` collapses backslashes to forward slashes."""
    assert normalize_path("synapx-harness\\src\\foo.py") == "synapx-harness/src/foo.py"


def test_casefold_duplicate_paths_are_rejected() -> None:
    report = validate_package_scope(
        ["synapx-harness/src/Foo.py", "synapx-harness/src/foo.py"]
    )
    assert not report.ok


def test_normalized_duplicate_paths_are_rejected() -> None:
    report = validate_package_scope(
        ["synapx-harness/src/foo.py", "synapx-harness/src/./foo.py"]
    )
    assert not report.ok


def test_manifest_contains_only_allowed_payload(
    core_root: Path,
    service_pack_root: Path,
    tmp_path: Path,
) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot

    out = tmp_path / "pkg.zip"
    core_head = subprocess.run(
        ["git", "-C", str(core_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    pack_head = subprocess.run(
        ["git", "-C", str(service_pack_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    core_snap = build_git_snapshot(core_root, core_head, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        service_pack_root,
        pack_head,
        package_prefix="communis-pilot-service-pack",
    )
    result = build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        out_path=out,
    )
    assert not result.duplicates_exact
    assert not result.duplicates_normalized
    assert not result.duplicates_casefold
    assert not result.backslash_entries
    with zipfile.ZipFile(out, "r") as zf:
        manifest = json.loads(zf.read("package_payload_manifest.json"))
    allowed_paths = {e["path"] for e in manifest["files"]}
    for path in allowed_paths:
        ok = is_path_allowed(path, scope="core") or is_path_allowed(
            path, scope="service_pack"
        )
        assert ok, f"disallowed path in manifest: {path}"


def test_package_gate_fails_when_excluded_file_is_present(tmp_path: Path) -> None:
    report = validate_package_scope(["synapx-harness/__pycache__/foo.pyc"])
    assert report.gate == "FAIL"


def test_build_package_rejects_pyc(
    tmp_path: Path,
    core_root: Path,
    service_pack_root: Path,
) -> None:
    from synapx_harness.review.git_snapshot import build_git_snapshot

    pyc = core_root / "src" / "synapx_harness" / "foo.pyc"
    pyc.parent.mkdir(parents=True, exist_ok=True)
    pyc.write_bytes(b"x")
    try:
        out = tmp_path / "pkg.zip"
        core_head = subprocess.run(
            ["git", "-C", str(core_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        pack_head = subprocess.run(
            ["git", "-C", str(service_pack_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        core_snap = build_git_snapshot(core_root, core_head, package_prefix="synapx-harness")
        pack_snap = build_git_snapshot(
            service_pack_root,
            pack_head,
            package_prefix="communis-pilot-service-pack",
        )
        result = build_package(
            core_snapshot=core_snap,
            service_pack_snapshot=pack_snap,
            out_path=out,
        )
        assert not result.duplicates_exact
        assert not result.duplicates_normalized
        assert not result.duplicates_casefold
        assert not result.backslash_entries
        with zipfile.ZipFile(out, "r") as zf:
            names = zf.namelist()
        offenders = [n for n in names if n.endswith(".pyc") or "__pycache__" in n]
        assert not offenders, f"pyc/cache in package: {offenders[:5]}"
        verify = verify_package(out)
        assert verify.ok
    finally:
        if pyc.exists():
            pyc.unlink()


def test_is_excluded_matches_pycache() -> None:
    assert is_excluded("synapx-harness/__pycache__/x.pyc")


def test_is_excluded_matches_dotenv() -> None:
    assert is_excluded("synapx-harness/.env")
