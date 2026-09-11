"""Deterministic fake Codex runtime for Lane D adapter tests (A4 / R1).

:class:`FakeCodexRuntime` is a test double that reproduces every raw runtime
condition the error-normalization matrix must handle, WITHOUT touching the
network or a real Codex account:

* SUCCESS          -> normal exit 0
* FAILURE          -> non-zero exit
* TIMEOUT          -> Harness timer expired
* CANCEL           -> runtime cancellation confirmed
* CANCEL_RACE      -> waits for the cancel event; returns confirmed CANCELLED
                     if the event fires, otherwise a late DONE (for concurrency
                     execute()/cancel() tests)
* MALFORMED_OUTPUT -> runtime returned but output unusable
* LAUNCH_ERROR     -> process could not be started

It shares the exact ``invoke`` surface of
:class:`~synapx_harness.adapters.codex.runtime.SubprocessCodexRuntime`, so the
adapter normalizes both backends through one code path. Bounded capture is
applied identically so truncation metadata is deterministic in tests.
"""
from __future__ import annotations

import io
import threading
from dataclasses import dataclass
from enum import StrEnum

from synapx_harness.adapters.codex.runtime import (
    RawRuntimeResult,
    RuntimeInvocation,
    _bounded_read_bytes,
)


class FakeScenario(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    TIMEOUT = "TIMEOUT"
    CANCEL = "CANCEL"
    CANCEL_RACE = "CANCEL_RACE"
    CANCEL_IGNORED = "CANCEL_IGNORED"
    CANCEL_CONFIRMED_LATE_DONE = "CANCEL_CONFIRMED_LATE_DONE"
    TIMEOUT_LATE_DONE = "TIMEOUT_LATE_DONE"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    LAUNCH_ERROR = "LAUNCH_ERROR"


@dataclass
class FakeCodexRuntime:
    """Deterministic, side-effect-free Codex runtime stand-in."""

    scenario: FakeScenario = FakeScenario.SUCCESS
    stdout: str = "ok"
    stderr: str = ""
    exit_code: int = 0
    malformed: bool = False
    provider_session_id: str | None = "fake-provider-session"
    fake_version: str | None = "fake-codex-1.0"
    duration_ms: int = 10
    launch_error_message: str = "fake launch failure"
    # Window (seconds) the CANCEL* scenarios wait for the cancel event.
    race_window: float = 1.0

    def version(self) -> str | None:
        return self.fake_version

    def _bound(self, text: str, max_bytes: int) -> tuple[str, int, int, bool]:
        """Binary bounded capture (R2-02): returns the decoded string plus the
        exact original byte count and the bounded captured byte count."""
        captured, total, truncated = _bounded_read_bytes(
            io.BytesIO(text.encode("utf-8")), max_bytes
        )
        return captured.decode("utf-8", "replace"), total, len(captured), truncated

    def invoke(
        self,
        inv: RuntimeInvocation,
        cancel_event: threading.Event | None,
    ) -> RawRuntimeResult:
        if self.scenario == FakeScenario.LAUNCH_ERROR:
            return RawRuntimeResult(
                exit_code=-1,
                stdout="",
                stderr="",
                duration_ms=0,
                launch_error=True,
                launch_error_message=self.launch_error_message,
                process_started=False,
                failure_class="PROCESS_LAUNCH_ERROR",
            )
        if self.scenario == FakeScenario.TIMEOUT:
            return RawRuntimeResult(
                exit_code=-1,
                stdout="",
                stderr="",
                duration_ms=inv.timeout_seconds * 1000,
                timed_out=True,
            )
        if self.scenario == FakeScenario.TIMEOUT_LATE_DONE:
            # Timeout fired, but a late DONE later arrived. TIMEOUT must win.
            return RawRuntimeResult(
                exit_code=0,
                stdout=self.stdout,
                stderr=self.stderr,
                duration_ms=inv.timeout_seconds * 1000,
                timed_out=True,
            )
        if self.scenario == FakeScenario.CANCEL:
            if cancel_event is not None:
                cancel_event.wait(timeout=inv.timeout_seconds)
            return RawRuntimeResult(
                exit_code=-1,
                stdout="",
                stderr="",
                duration_ms=self.duration_ms,
                cancelled=True,
            )
        if self.scenario == FakeScenario.CANCEL_IGNORED:
            # Backend ignores the cancel signal and returns a normal success.
            # R2-CANCEL-02: unconfirmed cancel -> FAILED + cancellation_uncertain.
            if cancel_event is not None:
                cancel_event.wait(timeout=self.race_window)
            out, out_orig, out_cap, out_trunc = self._bound(
                self.stdout, inv.max_stdout_bytes
            )
            err, err_orig, err_cap, err_trunc = self._bound(
                self.stderr, inv.max_stderr_bytes
            )
            return RawRuntimeResult(
                exit_code=0,
                stdout=out,
                stderr=err,
                duration_ms=self.duration_ms,
                stdout_original_bytes=out_orig,
                stderr_original_bytes=err_orig,
                stdout_captured_bytes=out_cap,
                stderr_captured_bytes=err_cap,
                truncated=out_trunc or err_trunc,
                provider_session_id=self.provider_session_id,
                version=self.fake_version,
            )
        if self.scenario == FakeScenario.CANCEL_CONFIRMED_LATE_DONE:
            # Confirmed cancel, but a late DONE arrived anyway. CANCELLED must win.
            if cancel_event is not None:
                cancel_event.wait(timeout=self.race_window)
            out, out_orig, out_cap, out_trunc = self._bound(
                self.stdout, inv.max_stdout_bytes
            )
            err, err_orig, err_cap, err_trunc = self._bound(
                self.stderr, inv.max_stderr_bytes
            )
            return RawRuntimeResult(
                exit_code=0,
                stdout=out,
                stderr=err,
                duration_ms=self.duration_ms,
                cancelled=True,
                stdout_original_bytes=out_orig,
                stderr_original_bytes=err_orig,
                stdout_captured_bytes=out_cap,
                stderr_captured_bytes=err_cap,
                truncated=out_trunc or err_trunc,
                provider_session_id=self.provider_session_id,
                version=self.fake_version,
            )
        if self.scenario == FakeScenario.CANCEL_RACE:
            fired = False
            if cancel_event is not None:
                fired = cancel_event.wait(timeout=self.race_window)
            if fired:
                return RawRuntimeResult(
                    exit_code=-1,
                    stdout="",
                    stderr="",
                    duration_ms=self.duration_ms,
                    cancelled=True,
                )
            # Cancel never fired: process produced a late DONE.
            out, out_orig, out_cap, out_trunc = self._bound(
                self.stdout, inv.max_stdout_bytes
            )
            err, err_orig, err_cap, err_trunc = self._bound(
                self.stderr, inv.max_stderr_bytes
            )
            return RawRuntimeResult(
                exit_code=0,
                stdout=out,
                stderr=err,
                duration_ms=self.duration_ms,
                stdout_original_bytes=out_orig,
                stderr_original_bytes=err_orig,
                stdout_captured_bytes=out_cap,
                stderr_captured_bytes=err_cap,
                truncated=out_trunc or err_trunc,
                provider_session_id=self.provider_session_id,
                version=self.fake_version,
            )
        if self.scenario == FakeScenario.MALFORMED_OUTPUT:
            out, out_orig, out_cap, out_trunc = self._bound(
                self.stdout, inv.max_stdout_bytes
            )
            err, err_orig, err_cap, err_trunc = self._bound(
                self.stderr, inv.max_stderr_bytes
            )
            return RawRuntimeResult(
                exit_code=0,
                stdout=out,
                stderr=err,
                duration_ms=self.duration_ms,
                malformed=True,
                stdout_original_bytes=out_orig,
                stderr_original_bytes=err_orig,
                stdout_captured_bytes=out_cap,
                stderr_captured_bytes=err_cap,
                truncated=out_trunc or err_trunc,
            )
        if self.scenario == FakeScenario.FAILURE:
            out, out_orig, out_cap, out_trunc = self._bound(
                self.stdout, inv.max_stdout_bytes
            )
            err, err_orig, err_cap, err_trunc = self._bound(
                self.stderr, inv.max_stderr_bytes
            )
            return RawRuntimeResult(
                exit_code=self.exit_code or 1,
                stdout=out,
                stderr=err,
                duration_ms=self.duration_ms,
                stdout_original_bytes=out_orig,
                stderr_original_bytes=err_orig,
                stdout_captured_bytes=out_cap,
                stderr_captured_bytes=err_cap,
                truncated=out_trunc or err_trunc,
                provider_session_id=self.provider_session_id,
                version=self.fake_version,
            )
        # SUCCESS
        out, out_orig, out_cap, out_trunc = self._bound(
            self.stdout, inv.max_stdout_bytes
        )
        err, err_orig, err_cap, err_trunc = self._bound(
            self.stderr, inv.max_stderr_bytes
        )
        return RawRuntimeResult(
            exit_code=0,
            stdout=out,
            stderr=err,
            duration_ms=self.duration_ms,
            stdout_original_bytes=out_orig,
            stderr_original_bytes=err_orig,
            stdout_captured_bytes=out_cap,
            stderr_captured_bytes=err_cap,
            truncated=out_trunc or err_trunc,
            provider_session_id=self.provider_session_id,
            version=self.fake_version,
            process_started=True,
            failure_class="PROCESS_SUCCESS",
        )


__all__ = ["FakeCodexRuntime", "FakeScenario"]
