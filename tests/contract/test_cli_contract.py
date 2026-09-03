"""CLI contract tests.

These tests invoke the CLI as a subprocess and verify that all
required subcommands exist and exit non-zero on validation failure.

The R3 portable variant builds a temporary service pack under
``tmp_path`` and resolves it via ``SYNAPX_HARNESS_SERVICE_PACK_ROOT``. No
literal ``D:/communis/communis-pilot-service-pack`` paths are used.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import (
    _resolve_service_pack_root,
    make_temporary_service_pack,
)

CORE_ROOT = Path(__file__).resolve().parents[2]


def _run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "synapx_harness.cli.main", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or CORE_ROOT),
        check=False,
    )


def _build_temp_pack(tmp_path: Path) -> Path:
    pack = make_temporary_service_pack(tmp_path / "cli_pack")
    return pack


def test_cli_reports_version() -> None:
    result = _run_cli("--version")
    assert result.returncode == 0, result.stderr
    assert "synapx-harness" in result.stdout
    assert "0.1.0-dev" in result.stdout


def test_cli_validates_service_pack_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = _build_temp_pack(tmp_path / "scaffold")
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(pack))
    result = _run_cli("scaffold", "validate", "--root", str(pack))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True


def test_cli_contract_validate_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = _build_temp_pack(tmp_path / "contract")
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(pack))
    result = _run_cli("contract", "validate", "--root", str(pack))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True


def test_cli_repository_list_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = _build_temp_pack(tmp_path / "repo")
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(pack))
    result = _run_cli("repository", "list", "--root", str(pack))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert isinstance(payload["repositories"], list)
    assert len(payload["repositories"]) >= 1


def test_cli_policy_validate_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pack = _build_temp_pack(tmp_path / "policy")
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(pack))
    result = _run_cli("policy", "validate", "--root", str(pack))
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True


def test_cli_scaffold_validate_exits_nonzero_on_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(tmp_path / "missing"))
    missing_root = tmp_path / "missing"
    result = _run_cli("scaffold", "validate", "--root", str(missing_root))
    assert result.returncode != 0, "non-zero exit required on validation failure"


def test_resolve_service_pack_root_prefers_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, temporary_service_pack_root: Path
) -> None:
    monkeypatch.setenv("SYNAPX_HARNESS_SERVICE_PACK_ROOT", str(temporary_service_pack_root))
    resolved = _resolve_service_pack_root(CORE_ROOT)
    assert resolved == temporary_service_pack_root.resolve()
