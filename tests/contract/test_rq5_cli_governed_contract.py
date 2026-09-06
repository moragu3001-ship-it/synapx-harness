"""RQ5-R2 Governed Front Door CLI Exit-Contract Tests.

RQ5-R1 §11 — the governed ``run`` subcommand has the SAME process-exit
contract as the legacy default ``synapx`` entry:

    GCLI01 governed COMPLETED -> presentation VERIFIED -> exit 0
    GCLI02 governed FAILED    -> presentation FAILED    -> exit non-zero
    GCLI03 governed BLOCKED   -> presentation NEEDS_ATTENTION -> exit non-zero
    GCLI04 governed UNKNOWN   -> presentation NEEDS_ATTENTION -> exit non-zero

The repair (RQ5-R2) added ``_enforce_public_exit_contract`` to the governed
callback so a FAILED / BLOCKED / UNKNOWN presentation is surfaced as a
non-zero process exit.

These tests invoke the real ``frontdoor_app`` via Typer's ``CliRunner`` and
only monkeypatch ``_build_governed_runtime`` to a deterministic fake so no
live Codex / filesystem state is consulted. No production test hook is added.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from synapx_harness.cli import frontdoor


class _FakeGovernedRuntime:
    """Duck-typed governed runtime returning a deterministic presentation."""

    def __init__(self, status: str, reason: str | None = None) -> None:
        self._status = status
        self._reason = reason

    def is_available(self) -> bool:
        return True

    def invoke(self, task: str) -> frontdoor.PresentationResult:
        return frontdoor.PresentationResult(self._status, self._reason)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return tmp_path


def _invoke_governed(
    runner: CliRunner,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    reason: str | None = None,
):
    """Invoke the governed ``run`` subcommand with a fake runtime."""
    fake_runtime = _FakeGovernedRuntime(status, reason)
    monkeypatch.setattr(
        frontdoor, "_build_governed_runtime", lambda _ws: fake_runtime
    )
    return runner.invoke(
        frontdoor.frontdoor_app,
        ["run", "--workspace", str(workspace), "--task", "some task"],
    )


def test_gcli01_governed_completed_exits_zero(
    runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCLI01: governed COMPLETED -> VERIFIED -> exit 0."""
    result = _invoke_governed(runner, workspace, monkeypatch, "COMPLETED")
    assert result.exit_code == 0, (
        f"governed COMPLETED must exit 0; got {result.exit_code}"
    )
    assert "VERIFIED" in result.output


def test_gcli02_governed_failed_exits_non_zero(
    runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCLI02: governed FAILED -> presentation FAILED -> exit non-zero."""
    result = _invoke_governed(
        runner, workspace, monkeypatch, "FAILED", reason="synthetic failure"
    )
    assert result.exit_code != 0, (
        f"governed FAILED must exit non-zero; got {result.exit_code}"
    )
    assert "FAILED" in result.output


def test_gcli03_governed_blocked_exits_non_zero(
    runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCLI03: governed BLOCKED -> NEEDS_ATTENTION -> exit non-zero."""
    result = _invoke_governed(
        runner, workspace, monkeypatch, "BLOCKED", reason="synthetic blocker"
    )
    assert result.exit_code != 0, (
        f"governed BLOCKED must exit non-zero; got {result.exit_code}"
    )
    assert "NEEDS_ATTENTION" in result.output


def test_gcli04_governed_unknown_presentation_exits_non_zero(
    runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GCLI04: unknown presentation -> NEEDS_ATTENTION -> exit non-zero.

    RQ5-R2 §12 unknown-state fail-closed. Proves a future enum/state value
    cannot silently succeed with exit 0.
    """
    result = _invoke_governed(
        runner, workspace, monkeypatch, "UNKNOWN", reason="unmapped state"
    )
    assert result.exit_code != 0, (
        f"governed UNKNOWN must exit non-zero; got {result.exit_code}"
    )
    assert "NEEDS_ATTENTION" in result.output


def test_gcli_unknown_legacy_run_exits_non_zero(
    runner: CliRunner, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RQ5-R2 §12: legacy run() with UNKNOWN presentation must exit non-zero.

    The legacy default path maps unknown status to NEEDS_ATTENTION and must
    enforce the exit contract via ``_enforce_public_exit_contract``.
    """
    fake_runtime = _FakeGovernedRuntime("UNKNOWN", reason="unmapped state")
    monkeypatch.setattr(frontdoor, "_build_runtime", lambda _ws: fake_runtime)
    result = runner.invoke(
        frontdoor.frontdoor_app,
        ["--workspace", str(workspace), "--task", "some task"],
    )
    assert result.exit_code != 0, (
        f"legacy UNKNOWN must exit non-zero; got {result.exit_code}"
    )
    assert "NEEDS_ATTENTION" in result.output
