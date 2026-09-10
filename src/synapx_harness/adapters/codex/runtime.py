"""Runtime backend primitives for the Codex adapter (Lane D / R2).

This module is intentionally provider-aware but isolated: it is the ONLY place
that knows how to launch the ``codex`` headless CLI. The adapter normalizes the
result into the provider-neutral :class:`AgentResult`.

Two backends implement the same surface:

* :class:`SubprocessCodexRuntime` -- invokes ``codex exec`` for real.
* :class:`FakeCodexRuntime` (see ``fake.py``) -- deterministic test double.

Both yield a :class:`RawRuntimeResult`, which the adapter normalizes through a
single error-normalization matrix (see ``contract.py``).

R2-02 runtime truth
-------------------
* Capture is **binary** (no ``text=True``) and counted in exact **bytes**.
* ``stdout``/``stderr`` are drained **concurrently** by two reader threads so a
  large output can never deadlock the OS pipe buffer.
* A hard byte cap bounds memory; once the cap is exceeded we stop *appending*
  but keep *counting to EOF* so ``*_original_bytes`` is always exact.
* Decode / redaction happens *after* capture, in byte order.

RQ8-R1-R2-R2 (D1) process transport
-----------------------------------
* Large Codex instructions MUST NOT depend on OS argv capacity. Windows
  CreateProcess has a hard argv ceiling (WinError 206 -- "The filename or
  extension is too long"). The canonical transport is the Codex-official
  stdin transport (``codex exec ... -`` reads the initial instruction from
  stdin when the positional ``PROMPT`` is ``-``).
* :class:`InvocationTransport` makes the choice explicit. The default is
  :attr:`InvocationTransport.STDIN`; the instruction is carried in
  :attr:`RuntimeInvocation.stdin_payload` and never embedded in
  :attr:`RuntimeInvocation.command`.
* :attr:`RuntimeInvocation.command` always carries ONLY fixed CLI tokens
  (binary path + options); the instruction is NOT one of them.
* :attr:`RawRuntimeResult.process_started` and
  :attr:`RawRuntimeResult.failure_class` preserve the authoritative launch
  outcome so downstream stages can short-circuit on launch failure (D2 / D4).
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from synapx_harness.adapters.codex.models import AgentRequest


# Process failure classification (RQ8-R1-R2-R2 D2 -- launch failure truth).
# These strings are stable, provider-neutral, and never inferred from hashes.
PROCESS_LAUNCH_ERROR: str = "PROCESS_LAUNCH_ERROR"
PROCESS_STARTED_EXIT_NONZERO: str = "PROCESS_STARTED_EXIT_NONZERO"
PROCESS_TIMEOUT: str = "PROCESS_TIMEOUT"
PROCESS_SUCCESS: str = "PROCESS_SUCCESS"

# Secret patterns that must be scrubbed from captured stdout/stderr before they
# become evidence. Conservative: only obvious credential shapes are masked.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9]{8,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"(?i)(api[_-]?key|token|password|secret|auth)\s*[=:]\s*\S+"),
)

_REDACTED = "[REDACTED]"

# External-dependency markers for probe classification (R1-07 / R2-05).
# NOTE: local probe preconditions (trusted directory / git-repo-check / local
# config) are deliberately NOT here -- a local invocation failure must be
# classified as REPAIR_REQUIRED, never as an external dependency.
_EXTERNAL_MARKERS: tuple[str, ...] = (
    "not logged in",
    "login",
    "unauthorized",
    "unauthenticated",
    "auth",
    "api key",
    "invalid api",
    "model",
    "quota",
    "rate limit",
    "rate-limit",
    "network",
    "connection",
    "timeout",
    "timed out",
    "401",
    "403",
    "429",
)


def redact_secrets(text: str) -> str:
    """Return ``text`` with obvious secret shapes masked (NEG-D-06)."""
    if not text:
        return text
    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(_REDACTED, out)
    return out


def classify_probe_outcome(*, status: str, stderr: str, stdout: str) -> str:
    """Classify a real Codex probe result (R1-07 / R2-05).

    * ``DONE`` runtime -> ``ADAPTER_RUNTIME_PROBE_PASS``.
    * External dependency failure (auth/model/network/quota/...) with evidence
      -> ``BLOCKED_EXTERNAL_DEPENDENCY``.
    * Local invocation precondition failure (trusted directory / repo check /
      local config) -> ``REPAIR_REQUIRED`` (NOT external).
    * Anything else (adapter/normalization/identity defect) -> ``REPAIR_REQUIRED``.

    A non-DONE runtime is NEVER promoted to ``ADAPTER_RUNTIME_PROBE_PASS``.
    """
    if status == "DONE":
        return "ADAPTER_RUNTIME_PROBE_PASS"
    lowered = f"{stderr}\n{stdout}".lower()
    if any(marker in lowered for marker in _EXTERNAL_MARKERS):
        return "BLOCKED_EXTERNAL_DEPENDENCY"
    return "REPAIR_REQUIRED"


class InvocationTransport(StrEnum):
    """How the Codex instruction is delivered to the ``codex exec`` process.

    * ``STDIN`` -- the instruction is written to the Codex process's stdin
      via a real OS pipe (``stdin=subprocess.PIPE``). Codex's CLI accepts a
      positional ``-`` argument as the PROMPT slot to mean "read from
      stdin"; this is the Codex-official transport for large instructions.
    * ``ARGV`` -- the instruction is embedded as the final element of
      ``RuntimeInvocation.command`` after a ``--`` separator. This is
      preserved for test seams and short-instruction compatibility but is
      NOT used by the public governed path because OS argv limits (Windows
      WinError 206) can hard-fail large instructions.
    * ``INPUT_FILE`` -- reserved for a future Codex-official ``@file``
      reference. Not currently emitted by :func:`build_invocation`; kept as
      a stable enum value so contract surfaces can mention it without
      churn.
    """

    STDIN = "STDIN"
    ARGV = "ARGV"
    INPUT_FILE = "INPUT_FILE"


@dataclass
class RuntimeInvocation:
    """Provider-neutral description of a single Codex invocation.

    RQ8-R1-R2-R2 (D1): ``command`` MUST NOT carry the user instruction; the
    instruction lives in ``stdin_payload`` and is delivered via the chosen
    ``transport``. The default transport is :attr:`InvocationTransport.STDIN`
    (Codex-official stdin transport) so instruction size cannot be bounded by
    OS argv limits. ``ARGV`` is preserved as a deterministic opt-in for tests
    and special callers; the public governed path never uses it.
    """

    command: list[str]
    cwd: str
    timeout_seconds: int
    model: str
    provider: str
    max_stdout_bytes: int
    max_stderr_bytes: int
    provider_config: dict[str, Any] = field(default_factory=dict)
    transport: InvocationTransport = InvocationTransport.STDIN
    stdin_payload: str | None = None


@dataclass
class RawRuntimeResult:
    """Raw, un-normalized runtime outcome (backend-internal, never Trust Core).

    RQ8-R1-R2-R2 (D2): ``process_started`` and ``failure_class`` carry the
    authoritative launch/process outcome so downstream stages can short-circuit
    on launch failure without inferring state from hashes. ``process_started``
    is ``False`` iff ``subprocess.Popen`` raised (Windows ``WinError 206``
    "filename too long", file-not-found, etc.). ``failure_class`` is one of
    :data:`PROCESS_LAUNCH_ERROR`, :data:`PROCESS_TIMEOUT`,
    :data:`PROCESS_STARTED_EXIT_NONZERO`, :data:`PROCESS_SUCCESS`, or
    ``None`` when not yet classified.
    """

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    cancelled: bool = False
    launch_error: bool = False
    launch_error_message: str = ""
    malformed: bool = False
    provider_session_id: str | None = None
    version: str | None = None
    # Exact byte accounting (R2-02). ``*_original_bytes`` is the total bytes
    # read to EOF; ``*_captured_bytes`` is the bounded head actually kept.
    stdout_original_bytes: int = 0
    stderr_original_bytes: int = 0
    stdout_captured_bytes: int = 0
    stderr_captured_bytes: int = 0
    truncated: bool = False
    # RQ8-R1-R2-R2 (D2): authoritative process-start truth.
    process_started: bool = True
    failure_class: str | None = None


def detect_codex_version(codex_bin: str = "codex") -> str | None:
    """Detect the installed ``codex`` CLI version (best-effort)."""
    try:
        proc = subprocess.run(
            [codex_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    for token in proc.stdout.split():
        if token[0].isdigit() and "." in token:
            return token
    return (proc.stdout.strip() or None) or None


def build_invocation(
    request: AgentRequest,
    codex_bin: str = "codex",
    *,
    transport: InvocationTransport | None = None,
) -> RuntimeInvocation:
    """Translate a canonical ``AgentRequest`` into a ``codex exec`` invocation.

    R2-05: the bounded headless probe applies Codex's explicit repo-check bypass
    (``--skip-git-repo-check``) so a local trusted-directory precondition does
    not block reaching the actual runtime/model stage. The read-only sandbox is
    preserved.

    I3-D1: ``provider_config["profile"]`` is forwarded as ``--profile`` to the
    Codex CLI when present.  This enables qualified profile binding without
    hard-coding any provider-specific value in the adapter.

    RQ8-R1-R2-R2 (D1): the user instruction is NEVER embedded in argv. By
    default the canonical Codex stdin transport is used: a positional ``-``
    argument is passed as the PROMPT slot so Codex reads the initial
    instruction from stdin; the instruction itself lives in
    :attr:`RuntimeInvocation.stdin_payload`. This eliminates the Windows
    ``WinError 206`` (filename/extension too long) failure mode that occurs
    when a 34K+ proposal instruction is packed into argv.

    Callers that explicitly opt into ``InvocationTransport.ARGV`` (e.g. test
    seams) get the legacy argv behaviour where the instruction is the final
    command element after ``--``.
    """
    cfg = request.invocation.provider_config or {}
    sandbox = str(cfg.get("sandbox", "read-only"))
    profile = cfg.get("profile")
    effective_transport = (
        transport if transport is not None else InvocationTransport.STDIN
    )
    command: list[str] = [
        codex_bin,
        "exec",
    ]
    if profile is not None:
        command.extend(["--profile", str(profile)])
    command.extend([
        "-m",
        request.invocation.model,
        "-C",
        request.workspace.root,
        "-s",
        sandbox,
        "--skip-git-repo-check",
    ])
    if effective_transport == InvocationTransport.ARGV:
        # Legacy/test seam: instruction embedded in argv after ``--``.
        command.extend(["--", request.task.instruction])
        stdin_payload: str | None = None
    else:
        # Canonical Codex stdin transport: positional ``-`` reads from stdin.
        command.extend(["--", "-"])
        stdin_payload = request.task.instruction

    return RuntimeInvocation(
        command=command,
        cwd=request.workspace.root,
        timeout_seconds=request.limits.timeout_seconds,
        model=request.invocation.model,
        provider=request.invocation.provider,
        max_stdout_bytes=request.limits.max_stdout_bytes,
        max_stderr_bytes=request.limits.max_stderr_bytes,
        provider_config=cfg,
        transport=effective_transport,
        stdin_payload=stdin_payload,
    )


def _bounded_read_bytes(stream, max_bytes: int) -> tuple[bytes, int, bool]:
    """Binary bounded read (R2-02).

    Returns ``(captured, total_bytes, truncated)``.

    * ``captured`` -- the first ``min(total, max_bytes)`` bytes.
    * ``total_bytes`` -- the EXACT number of bytes read to EOF (always accurate,
      even far beyond the cap).
    * ``truncated`` -- ``total_bytes > max_bytes``.

    Overflow stops *appending* but never stops *counting*: the stream is drained
    to EOF so the reported original size is truthful and memory stays bounded.
    """
    buf = bytearray()
    total = 0
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if len(buf) < max_bytes:
            buf.extend(chunk[: max_bytes - len(buf)])
        # else: keep counting, stop appending
    return bytes(buf), total, total > max_bytes


def _drain(holder: dict, key: str, stream, max_bytes: int) -> None:
    """Thread target: binary bounded drain of one stream into ``holder[key]``."""
    captured, total, truncated = _bounded_read_bytes(stream, max_bytes)
    holder[key] = {
        "captured": captured,
        "total": total,
        "truncated": truncated,
    }


def _kill(proc: subprocess.Popen) -> None:
    """Best-effort terminate/kill of a running subprocess."""
    try:
        proc.kill()
    except OSError:
        pass


class SubprocessCodexRuntime:
    """Real backend: launches ``codex exec`` with a Harness-owned timer and
    cancellation event. Output is captured under a finite byte cap with exact
    byte accounting and concurrent pipe draining (R2-02)."""

    def __init__(self, codex_bin: str = "codex") -> None:
        self.codex_bin = codex_bin
        self._version_cache: str | None = None

    def version(self) -> str | None:
        if self._version_cache is None:
            self._version_cache = detect_codex_version(self.codex_bin)
        return self._version_cache

    def invoke(
        self,
        inv: RuntimeInvocation,
        cancel_event: threading.Event | None,
    ) -> RawRuntimeResult:
        start = time.monotonic()
        popen_kwargs: dict[str, Any] = {
            "cwd": inv.cwd,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        # RQ8-R1-R2-R2 (D1): stdin transport requires a real stdin pipe so the
        # instruction payload can be written without relying on argv.
        if inv.stdin_payload is not None:
            popen_kwargs["stdin"] = subprocess.PIPE
        try:
            proc = subprocess.Popen(inv.command, **popen_kwargs)
        except (OSError, ValueError) as exc:
            # RQ8-R1-R2-R2 (D2): Popen failure is NEVER a normal process exit.
            # We preserve the authoritative launch failure with explicit
            # ``process_started=False`` and ``failure_class=PROCESS_LAUNCH_ERROR``
            # so downstream stages can short-circuit.
            winerror = getattr(exc, "winerror", None)
            message = str(exc)
            if winerror is not None:
                message = f"{message} (winerror={winerror})"
            return RawRuntimeResult(
                exit_code=-1,
                stdout="",
                stderr="",
                duration_ms=int((time.monotonic() - start) * 1000),
                launch_error=True,
                launch_error_message=message,
                process_started=False,
                failure_class=PROCESS_LAUNCH_ERROR,
            )

        # RQ8-R1-R2-R2 (D1): write the stdin payload BEFORE draining stdout/
        # stderr so the Codex process can begin reading immediately. The pipe
        # is closed after write to signal EOF; a BrokenPipeError means the
        # Codex process exited before consuming stdin (treat as launch-stage
        # failure classification, not normal completion).
        stdin_stream = proc.stdin
        if inv.stdin_payload is not None and stdin_stream is not None:
            try:
                stdin_stream.write(inv.stdin_payload.encode("utf-8", "replace"))
                stdin_stream.close()
            except (BrokenPipeError, OSError):
                try:
                    stdin_stream.close()
                except OSError:
                    pass

        # Concurrent drain: two reader threads keep both pipes moving so a large
        # output can never stall on the OS pipe buffer (R2-02).
        out_holder: dict = {}
        err_holder: dict = {}
        out_t = threading.Thread(
            target=_drain,
            args=(out_holder, "out", proc.stdout, inv.max_stdout_bytes),
            daemon=True,
        )
        err_t = threading.Thread(
            target=_drain,
            args=(err_holder, "err", proc.stderr, inv.max_stderr_bytes),
            daemon=True,
        )
        out_t.start()
        err_t.start()

        deadline = start + inv.timeout_seconds
        timed_out = False
        cancelled = False
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
                break
            if time.monotonic() > deadline:
                timed_out = True
                break
            time.sleep(0.02)

        if cancelled or timed_out:
            _kill(proc)

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill(proc)

        out_t.join()
        err_t.join()

        out = out_holder.get("out", {"captured": b"", "total": 0, "truncated": False})
        err = err_holder.get("err", {"captured": b"", "total": 0, "truncated": False})

        # Decode AFTER capture, in byte order; then redact (R2-02).
        stdout_str = out["captured"].decode("utf-8", "replace")
        stderr_str = err["captured"].decode("utf-8", "replace")

        duration_ms = int((time.monotonic() - start) * 1000)
        exit_code = proc.returncode if proc.returncode is not None else -1

        return RawRuntimeResult(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_ms=duration_ms,
            timed_out=timed_out,
            cancelled=cancelled,
            stdout_original_bytes=out["total"],
            stderr_original_bytes=err["total"],
            stdout_captured_bytes=len(out["captured"]),
            stderr_captured_bytes=len(err["captured"]),
            truncated=out["truncated"] or err["truncated"],
            version=self.version(),
            process_started=True,
            failure_class=(
                PROCESS_TIMEOUT
                if timed_out
                else (
                    PROCESS_STARTED_EXIT_NONZERO
                    if exit_code != 0
                    else PROCESS_SUCCESS
                )
            ),
        )


__all__ = [
    "PROCESS_LAUNCH_ERROR",
    "PROCESS_STARTED_EXIT_NONZERO",
    "PROCESS_SUCCESS",
    "PROCESS_TIMEOUT",
    "InvocationTransport",
    "RawRuntimeResult",
    "RuntimeInvocation",
    "SubprocessCodexRuntime",
    "build_invocation",
    "classify_probe_outcome",
    "detect_codex_version",
    "redact_secrets",
]
