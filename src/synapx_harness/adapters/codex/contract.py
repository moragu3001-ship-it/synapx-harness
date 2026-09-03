"""CodexAdapterContract v1 and the concrete CodexAdapter (Lane D / R1).

The adapter owns exactly the span:

    AgentRequest -> Codex invocation -> AgentResult

It does NOT self-authorize verification, evidence sufficiency, or terminal
completion. ``AgentResult.status == DONE`` means ONLY that the Codex runtime
returned successfully (RED-D-01). All status decisions flow through a single
:func:`CodexAdapter._normalize` implementation of the error-normalization
matrix, so the real subprocess backend and the fake backend share identical
semantics.

R1 repairs
----------
* R1-03 Interface truth: only ``OFFICIAL_HEADLESS_CLI`` is accepted. Both
  ``INTERACTIVE_TUI`` and ``OFFICIAL_SDK_API`` are rejected (no SDK backend
  exists).
* R1-04 Capability truth: ``capabilities()`` reports real, supported
  capabilities only -- never ``FakeScenario`` test doubles.
* R1-06 Cancellation fail-closed: confirmed cancellation -> CANCELLED;
  cancellation *requested* but not confirmed -> FAILED with
  ``cancellation_uncertain=True``. A late DONE after confirmed cancellation
  stays CANCELLED (never DONE). Timeout stays TIMEOUT (never DONE).
"""
from __future__ import annotations

import hashlib
import threading
from enum import StrEnum
from typing import Any, Protocol

from synapx_harness.adapters.codex.models import (
    AgentFailure,
    AgentOutput,
    AgentRequest,
    AgentResult,
    AgentStatus,
    FailureCategory,
    ProcessResult,
    ProviderMeta,
)
from synapx_harness.adapters.codex.runtime import (
    RawRuntimeResult,
    RuntimeInvocation,
    SubprocessCodexRuntime,
    build_invocation,
    redact_secrets,
)


class CodexInterface(StrEnum):
    """Selected Codex programmable interface.

    Only ``OFFICIAL_HEADLESS_CLI`` is authoritative in Public Alpha v1.
    Interactive TUI scraping and an (unimplemented) SDK API are both rejected.
    """

    OFFICIAL_HEADLESS_CLI = "OFFICIAL_HEADLESS_CLI"
    OFFICIAL_SDK_API = "OFFICIAL_SDK_API"
    INTERACTIVE_TUI = "INTERACTIVE_TUI"


# Frozen selection for Lane D: headless CLI only.
SELECTED_INTERFACE: CodexInterface = CodexInterface.OFFICIAL_HEADLESS_CLI
INTERACTIVE_TUI_AUTHORITATIVE: bool = False
# No SDK backend exists; SDK_API is unsupported (not merely unselected).
SDK_API_SUPPORTED: bool = False


class CodexAdapterContract(Protocol):
    """Provider-neutral contract the Codex adapter must satisfy."""

    def capabilities(self) -> dict[str, Any]:
        """Return the adapter capability descriptor."""
        ...

    def execute(self, request: AgentRequest) -> AgentResult:
        """Execute a canonical request and return a normalized result."""
        ...

    def cancel(
        self, *, job_id: str, task_id: str, attempt_id: str
    ) -> bool:
        """Request cancellation of a running attempt. Returns True if a
        cancel signal was registered for the attempt."""
        ...


class CodexAdapter:
    """Concrete Codex adapter.

    Parameters
    ----------
    backend:
        A runtime backend exposing ``invoke(inv, cancel_event)`` and
        ``version()``. Defaults to :class:`SubprocessCodexRuntime`.
    interface:
        Must be ``OFFICIAL_HEADLESS_CLI``. ``INTERACTIVE_TUI`` and
        ``OFFICIAL_SDK_API`` are rejected (R1-03).
    codex_bin:
        Executable name/path for the headless CLI.
    """

    def __init__(
        self,
        backend: Any | None = None,
        *,
        interface: CodexInterface = SELECTED_INTERFACE,
        codex_bin: str = "codex",
    ) -> None:
        if interface in (
            CodexInterface.INTERACTIVE_TUI,
            CodexInterface.OFFICIAL_SDK_API,
        ):
            raise ValueError(
                f"interface {interface.value!r} is not supported in Lane D v1 "
                "(only OFFICIAL_HEADLESS_CLI is authoritative; RED-D-10 / R1-03)"
            )
        self.interface = interface
        if backend is None:
            backend = SubprocessCodexRuntime(codex_bin=codex_bin)
        self._backend = backend
        self._cancel_flags: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    # -- CodexAdapterContract ------------------------------------------------

    def capabilities(self) -> dict[str, Any]:
        return {
            "interface": str(self.interface),
            "interactive_tui_authoritative": INTERACTIVE_TUI_AUTHORITATIVE,
            "sdk_api_supported": SDK_API_SUPPORTED,
            "selected": str(SELECTED_INTERFACE),
            "codex_version": self._backend.version(),
            "supports": {
                "prompt": True,
                "stdin": True,
                "cwd": True,
                "model_selection": True,
                "timeout": True,
                "cancel": True,
            },
        }

    def execute(self, request: AgentRequest) -> AgentResult:
        if not isinstance(request, AgentRequest):
            raise ValueError("execute requires a valid AgentRequest (REJECT)")
        attempt_id = request.execution_identity.execution_identity.attempt_id
        task_id = request.execution_identity.execution_identity.task_id
        job_id = request.execution_identity.execution_identity.job_id

        cancel_event = self._ensure_cancel_event(
            job_id=job_id, task_id=task_id, attempt_id=attempt_id
        )
        # R2-04: snapshot cancellation BOTH before and after the backend call.
        # A cancel that lands mid-flight (between the two snapshots) must still
        # be honoured as "requested but unconfirmed" -> FAILED + uncertain.
        cancel_before = cancel_event.is_set()

        inv: RuntimeInvocation = build_invocation(request, self._backend_bin())
        raw = self._backend.invoke(inv, cancel_event)

        cancel_after = cancel_event.is_set()
        cancel_requested = cancel_before or cancel_after

        return self._normalize(raw, request, cancel_requested=cancel_requested)

    def cancel(
        self, *, job_id: str, task_id: str, attempt_id: str
    ) -> bool:
        event = self._ensure_cancel_event(
            job_id=job_id, task_id=task_id, attempt_id=attempt_id
        )
        event.set()
        return True

    # -- internals -----------------------------------------------------------

    def _backend_bin(self) -> str:
        return getattr(self._backend, "codex_bin", "codex")

    def _ensure_cancel_event(
        self, *, job_id: str, task_id: str, attempt_id: str
    ) -> threading.Event:
        with self._lock:
            event = self._cancel_flags.get(attempt_id)
            if event is None:
                event = threading.Event()
                self._cancel_flags[attempt_id] = event
            return event

    # -- Error Normalization Matrix (LANE_D_05 / R1-06) ----------------------
    #
    # Raw condition                     -> AgentResult
    # normal successful process         -> DONE
    # non-zero execution/process error  -> FAILED
    # configured timeout exceeded       -> TIMEOUT
    # confirmed Harness cancellation    -> CANCELLED
    # cancellation requested but
    #   termination unconfirmed         -> FAILED + cancellation_uncertain
    # launch failure                    -> FAILED
    # malformed runtime output          -> FAILED
    # missing required identity         -> invocation REJECT (pydantic, pre-exec)
    # unsupported interface             -> invocation REJECT (constructor)

    def _normalize(
        self,
        raw: RawRuntimeResult,
        request: AgentRequest,
        *,
        cancel_requested: bool,
    ) -> AgentResult:
        ident = request.execution_identity
        provider_name = request.invocation.provider
        provider_model = request.invocation.model

        status: AgentStatus
        failure: AgentFailure | None = None
        cancellation_uncertain = False

        if raw.launch_error:
            status = AgentStatus.FAILED
            failure = AgentFailure(
                category=FailureCategory.LAUNCH_ERROR,
                message=raw.launch_error_message or "runtime launch failed",
            )
        elif raw.malformed:
            status = AgentStatus.FAILED
            failure = AgentFailure(
                category=FailureCategory.MALFORMED_OUTPUT,
                message="runtime produced malformed/unusable output",
            )
        elif raw.timed_out:
            status = AgentStatus.TIMEOUT
            failure = AgentFailure(
                category=FailureCategory.TIMEOUT,
                message="configured harness timeout exceeded",
            )
        elif raw.cancelled:
            # Confirmed cancellation: status is CANCELLED; never upgraded.
            status = AgentStatus.CANCELLED
            failure = AgentFailure(
                category=FailureCategory.CANCELLATION_ERROR,
                message="harness cancellation confirmed",
            )
        elif cancel_requested:
            # Requested but termination NOT confirmed -> fail-closed.
            status = AgentStatus.FAILED
            cancellation_uncertain = True
            failure = AgentFailure(
                category=FailureCategory.CANCELLATION_ERROR,
                message="cancellation requested; termination unconfirmed",
            )
        elif raw.exit_code == 0:
            status = AgentStatus.DONE
        else:
            status = AgentStatus.FAILED
            failure = AgentFailure(
                category=FailureCategory.PROCESS_ERROR,
                message=f"process exited with code {raw.exit_code}",
            )

        provider = ProviderMeta(
            name=provider_name,
            model=provider_model,
            version=raw.version,
            provider_session_id=raw.provider_session_id,
        )
        process = ProcessResult(
            exit_code=raw.exit_code, duration_ms=raw.duration_ms
        )
        stdout_red = redact_secrets(raw.stdout)
        stderr_red = redact_secrets(raw.stderr)
        output = AgentOutput(
            stdout=stdout_red,
            stderr=stderr_red,
            truncated=raw.truncated,
            stdout_original_bytes=raw.stdout_original_bytes,
            stderr_original_bytes=raw.stderr_original_bytes,
            stdout_captured_bytes=raw.stdout_captured_bytes,
            stderr_captured_bytes=raw.stderr_captured_bytes,
            content_sha256=hashlib.sha256(stdout_red.encode("utf-8", "replace")).hexdigest(),
        )

        try:
            return AgentResult(
                status=status,
                execution_identity=ident,
                provider=provider,
                process=process,
                output=output,
                failure=failure,
                cancellation_uncertain=cancellation_uncertain,
            )
        except ValueError as exc:
            # e.g. NEG-D-01 identity collision surfaces here as a REJECT.
            raise ValueError(f"AgentResult normalization rejected: {exc}") from exc


__all__ = [
    "CodexAdapter",
    "CodexAdapterContract",
    "CodexInterface",
    "INTERACTIVE_TUI_AUTHORITATIVE",
    "SDK_API_SUPPORTED",
    "SELECTED_INTERFACE",
]
