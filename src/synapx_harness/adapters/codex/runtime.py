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
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from synapx_harness.adapters.codex.models import AgentRequest

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


@dataclass
class RuntimeInvocation:
    """Provider-neutral description of a single Codex invocation."""

    command: list[str]
    cwd: str
    timeout_seconds: int
    model: str
    provider: str
    max_stdout_bytes: int
    max_stderr_bytes: int
    provider_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class RawRuntimeResult:
    """Raw, un-normalized runtime outcome (backend-internal, never Trust Core)."""

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


def build_invocation(request: AgentRequest, codex_bin: str = "codex") -> RuntimeInvocation:
    """Translate a canonical ``AgentRequest`` into a ``codex exec`` invocation.

    R2-05: the bounded headless probe applies Codex's explicit repo-check bypass
    (``--skip-git-repo-check``) so a local trusted-directory precondition does
    not block reaching the actual runtime/model stage. The read-only sandbox is
    preserved.

    I3-D1: ``provider_config["profile"]`` is forwarded as ``--profile`` to the
    Codex CLI when present.  This enables qualified profile binding without
    hard-coding any provider-specific value in the adapter.
    """
    cfg = request.invocation.provider_config or {}
    sandbox = str(cfg.get("sandbox", "read-only"))
    profile = cfg.get("profile")
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
        "--",
        request.task.instruction,
    ])
    return RuntimeInvocation(
        command=command,
        cwd=request.workspace.root,
        timeout_seconds=request.limits.timeout_seconds,
        model=request.invocation.model,
        provider=request.invocation.provider,
        max_stdout_bytes=request.limits.max_stdout_bytes,
        max_stderr_bytes=request.limits.max_stderr_bytes,
        provider_config=cfg,
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
        try:
            proc = subprocess.Popen(
                inv.command,
                cwd=inv.cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (OSError, ValueError) as exc:
            return RawRuntimeResult(
                exit_code=-1,
                stdout="",
                stderr="",
                duration_ms=int((time.monotonic() - start) * 1000),
                launch_error=True,
                launch_error_message=str(exc),
            )

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
        )


__all__ = [
    "RawRuntimeResult",
    "RuntimeInvocation",
    "SubprocessCodexRuntime",
    "build_invocation",
    "classify_probe_outcome",
    "detect_codex_version",
    "redact_secrets",
]
