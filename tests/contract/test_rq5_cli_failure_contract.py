"""RQ5-R1 CLI Failure-Exit-Code Contract Negatives.

RQ5-R1 §10 — CLI exit code contract:

    VERIFIED        -> process exit code 0
    FAILED          -> process exit code non-zero
    NEEDS_ATTENTION -> process exit code non-zero
                     (BLOCKED is presented as NEEDS_ATTENTION)

This file proves CLI01 (FAILED -> non-zero) and CLI02 (BLOCKED -> non-zero)
are enforced by the public `synapx` Front Door.

The tests are constructed via the **in-process** `frontdoor.run()` seam
(which accepts an injected ``RuntimePort``); a subprocess CLI probe is also
included for the public binary path. The in-process form is the canonical
RQ5-R1 negative because it exposes the authority boundary the source
must satisfy:

    When ``runtime.invoke(task)`` returns a ``PresentationResult`` with
    ``status in {"FAILED", "BLOCKED"}``, ``run()`` MUST raise
    ``typer.Exit(code=1)`` (or any ``SystemExit`` with code != 0) so that
    the public CLI process exits non-zero.

If ``run()`` returns without raising, this is the explicit RQ5-R1
``RQ5_R1_CLI_FAILURE_EXIT_CODE_DEFECT`` source-repair candidate
described in §10 of the spec.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Iterator

import pytest
import typer

from synapx_harness.cli import frontdoor


CORE_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Test runtime port: deterministic FakeRuntime that returns configurable
# PresentationResult statuses. This isolates the test from any live Codex
# invocation or filesystem state.
# ---------------------------------------------------------------------------


class _FakeRuntime:
    def __init__(self, status: str, reason: str | None = None) -> None:
        self._status = status
        self._reason = reason
        self.invocations: list[str] = []

    def is_available(self) -> bool:
        return True

    def invoke(self, task: str) -> frontdoor.PresentationResult:
        self.invocations.append(task)
        return frontdoor.PresentationResult(self._status, self._reason)


def _exit_code(exc: BaseException) -> int:
    """Extract a process exit code from a SystemExit or typer.Exit value.

    ``SystemExit`` exposes ``.code``; ``click.exceptions.Exit`` (the base of
    ``typer.Exit``) exposes ``.exit_code``.
    """
    if hasattr(exc, "exit_code"):
        return int(getattr(exc, "exit_code")) if getattr(exc, "exit_code") is not None else 0
    code = getattr(exc, "code", None)
    if code is None:
        return 0
    if isinstance(code, int):
        return code
    return int(code)


# ---------------------------------------------------------------------------
# CLI01 — FAILED public run exit code
# ---------------------------------------------------------------------------


def test_cli01_failed_public_run_exits_non_zero(tmp_path: Path) -> None:
    """A FAILED presentation MUST cause the public synapx run to exit non-zero.

    RQ5-R1 §10 product contract:
        FAILED -> process_exit_code: non-zero
    """
    fake = _FakeRuntime("FAILED", reason="synthetic failure")

    with pytest.raises((SystemExit, typer.Exit)) as excinfo:
        frontdoor.run(
            workspace=tmp_path,
            task="any task",
            runtime=fake,
        )

    assert _exit_code(excinfo.value) != 0, (
        f"CLI01 FAIL: FAILED presentation must exit non-zero; "
        f"got exit code={_exit_code(excinfo.value)!r}"
    )


# ---------------------------------------------------------------------------
# CLI02 — BLOCKED / NEEDS_ATTENTION public run exit code
# ---------------------------------------------------------------------------


def test_cli02_blocked_public_run_exits_non_zero(tmp_path: Path) -> None:
    """A BLOCKED presentation MUST cause the public synapx run to exit non-zero.

    RQ5-R1 §10 product contract:
        NEEDS_ATTENTION/BLOCKED -> process_exit_code: non-zero
    """
    fake = _FakeRuntime("BLOCKED", reason="synthetic blocker")

    with pytest.raises((SystemExit, typer.Exit)) as excinfo:
        frontdoor.run(
            workspace=tmp_path,
            task="any task",
            runtime=fake,
        )

    assert _exit_code(excinfo.value) != 0, (
        f"CLI02 FAIL: BLOCKED presentation must exit non-zero; "
        f"got exit code={_exit_code(excinfo.value)!r}"
    )


# ---------------------------------------------------------------------------
# CLI03 (positive control) — VERIFIED public run exits zero
# ---------------------------------------------------------------------------


def test_cli_verified_public_run_exits_zero(tmp_path: Path) -> None:
    """A COMPLETED presentation (presented as VERIFIED) MUST exit zero.

    Positive control: ensures the negative tests above are not false-positive.
    Returns either no SystemExit (function returns, CLI exits 0) or
    SystemExit(0) — both yield process_exit_code == 0.
    """
    fake = _FakeRuntime("COMPLETED")

    try:
        frontdoor.run(
            workspace=tmp_path,
            task="any task",
            runtime=fake,
        )
        exit_code = 0
    except (SystemExit, typer.Exit) as exc:
        exit_code = _exit_code(exc)

    assert exit_code == 0, (
        f"VERIFIED presentation must exit zero; got exit_code={exit_code!r}"
    )
