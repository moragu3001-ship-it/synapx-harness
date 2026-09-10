"""Provider-neutral Agent Runtime contract models for the Codex adapter (Lane D / R1).

R1 repairs
----------
* R1-01 Canonical identity: the canonical execution lineage is the existing
  Core :class:`~synapx_harness.contracts.runtime_models.ExecutionIdentity`
  (job_id, task_id, root_task_id, attempt_id, tool_call_id). The adapter
  composes it instead of competing with a weaker duplicate. The SynapX-owned
  ``agent_session_id`` is carried separately and MUST be allocated before the
  Codex runtime is invoked.
* R1-02 Provider-neutral naming: contract types are ``CUSTOMOS_AGENT_REQUEST`` /
  ``CUSTOMOS_AGENT_RESULT``. Codex is only an ``invocation.provider`` value.
* R1-05 Bounded capture: ``AgentLimits`` carries finite ``max_stdout_bytes`` /
  ``max_stderr_bytes``; ``AgentOutput`` reports truncation metadata.
"""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from synapx_harness.contracts.runtime_models import ExecutionIdentity

AGENT_RUNTIME_SCHEMA_VERSION: Literal["0.2.0"] = "0.2.0"

# Finite default capture ceiling (bytes). Never unbounded / None.
DEFAULT_MAX_OUTPUT_BYTES: int = 1_000_000

# A real SHA-256 is exactly 64 lowercase hex characters. A 40-char Git object
# hash (git hash-object) is explicitly NOT a SHA-256 (R1-09 / BLOCKER #1).
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _StrictModel(BaseModel):
    """Strict base: forbid extras, validate assignment (mirrors runtime_models)."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        populate_by_name=True,
    )


class AgentStatus(StrEnum):
    """Canonical agent execution status (NOT a verification/terminal authority)."""

    DONE = "DONE"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class FailureCategory(StrEnum):
    """Normalized failure classification (never leaks provider internals)."""

    LAUNCH_ERROR = "LAUNCH_ERROR"
    PROCESS_ERROR = "PROCESS_ERROR"
    TIMEOUT = "TIMEOUT"
    CANCELLATION_ERROR = "CANCELLATION_ERROR"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class AgentExecutionContext(_StrictModel):
    """SynapX-owned execution context.

    The canonical lineage is the Core ``ExecutionIdentity`` (its ``root_task_id``
    requirement and CA-02 invariant are intentionally preserved). The adapter
    adds ``agent_session_id`` as a separate, SynapX-owned identifier allocated
    BEFORE invocation. The adapter MUST NOT mint any of these.
    """

    execution_identity: ExecutionIdentity
    agent_session_id: str = Field(min_length=1)


class AgentWorkspace(_StrictModel):
    """Workspace the agent operates within."""

    root: str = Field(min_length=1)
    revision: str | None = None


class AgentTask(_StrictModel):
    """The bounded instruction for the agent."""

    instruction: str = Field(min_length=1)


class AgentContext(_StrictModel):
    """Optional canonical context reference (consumed, never generated)."""

    canonical_context_ref: str | None = None
    optional_payload: dict[str, Any] = Field(default_factory=dict)


class AgentLimits(_StrictModel):
    """Harness-enforced finite limits."""

    timeout_seconds: int = Field(ge=1)
    max_stdout_bytes: int = Field(ge=1, default=DEFAULT_MAX_OUTPUT_BYTES)
    max_stderr_bytes: int = Field(ge=1, default=DEFAULT_MAX_OUTPUT_BYTES)


class AgentInvocation(_StrictModel):
    """Provider-neutral invocation descriptor (no Codex objects allowed)."""

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    provider_config: dict[str, Any] = Field(default_factory=dict)


class AgentRequest(_StrictModel):
    """Canonical, provider-neutral AgentRequest v1."""

    contract_type: Literal["CUSTOMOS_AGENT_REQUEST"] = "CUSTOMOS_AGENT_REQUEST"
    schema_version: Literal["0.2.0"] = AGENT_RUNTIME_SCHEMA_VERSION
    execution_identity: AgentExecutionContext
    workspace: AgentWorkspace
    task: AgentTask
    context: AgentContext = Field(default_factory=AgentContext)
    limits: AgentLimits
    invocation: AgentInvocation


class ProviderMeta(_StrictModel):
    """Provider metadata. ``provider_session_id`` is EXTERNAL provider metadata
    and MUST NEVER equal the SynapX ``agent_session_id`` (NEG-D-01)."""

    name: str
    model: str
    version: str | None = None
    provider_session_id: str | None = None


class ProcessResult(_StrictModel):
    """Process-level outcome (deterministic, not semantic).

    RQ8-R1-R2-R2 (D2): ``process_started`` is ``False`` iff
    ``subprocess.Popen`` raised before the process started. ``failure_class``
    carries the authoritative runtime classification (one of
    ``PROCESS_LAUNCH_ERROR``, ``PROCESS_TIMEOUT``,
    ``PROCESS_STARTED_EXIT_NONZERO``, ``PROCESS_SUCCESS``). Both fields are
    optional with safe defaults so existing call sites remain compatible.
    """

    exit_code: int
    duration_ms: int = Field(ge=0)
    process_started: bool = True
    failure_class: str | None = None


class AgentOutput(_StrictModel):
    """Bounded captured output (evidence input, never authority)."""

    stdout: str
    stderr: str
    truncated: bool = False
    stdout_original_bytes: int = 0
    stderr_original_bytes: int = 0
    stdout_captured_bytes: int = 0
    stderr_captured_bytes: int = 0
    content_sha256: str | None = Field(
        default=None,
        description="SHA-256 (64 lowercase hex) of the captured stdout. "
        "Integrity proof; a 40-char Git object hash is rejected (R1-09).",
    )

    @field_validator("content_sha256")
    @classmethod
    def _validate_content_sha256(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _SHA256_RE.match(v):
            raise ValueError(
                "content_sha256 must be a 64-char lowercase hex SHA-256, "
                "not a 40-char Git object hash"
            )
        return v


class AgentFailure(_StrictModel):
    """Normalized failure description."""

    category: FailureCategory
    message: str


class AgentResult(_StrictModel):
    """Canonical, provider-neutral AgentResult v1.

    ``status == DONE`` means ONLY that the Codex runtime returned
    successfully. It is NOT verification, evidence sufficiency, or terminal
    completion (RED-D-01). ``provider_session_id`` must remain distinct from
    the SynapX ``agent_session_id`` (NEG-D-01).
    """

    contract_type: Literal["CUSTOMOS_AGENT_RESULT"] = "CUSTOMOS_AGENT_RESULT"
    schema_version: Literal["0.2.0"] = AGENT_RUNTIME_SCHEMA_VERSION
    status: AgentStatus
    execution_identity: AgentExecutionContext
    provider: ProviderMeta
    process: ProcessResult | None = None
    output: AgentOutput
    failure: AgentFailure | None = None
    cancellation_uncertain: bool = False

    @model_validator(mode="after")
    def _distinct_session_identities(self) -> AgentResult:
        pid = self.provider.provider_session_id
        if pid is not None and pid == self.execution_identity.agent_session_id:
            raise ValueError(
                "provider_session_id MUST NOT equal agent_session_id "
                "(identity separation violation; NEG-D-01)"
            )
        return self


__all__ = [
    "AGENT_RUNTIME_SCHEMA_VERSION",
    "AgentContext",
    "AgentExecutionContext",
    "AgentFailure",
    "AgentInvocation",
    "AgentLimits",
    "AgentOutput",
    "AgentRequest",
    "AgentResult",
    "AgentStatus",
    "AgentTask",
    "AgentWorkspace",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "FailureCategory",
    "ProcessResult",
    "ProviderMeta",
]
