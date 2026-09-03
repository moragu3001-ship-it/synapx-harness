"""Codex adapter package (Lane D / R1).

Provider-neutral AgentRequest / AgentResult boundary plus the CodexAdapter that
invokes the headless ``codex exec`` CLI. The adapter owns only the span
``AgentRequest -> Codex invocation -> AgentResult`` and never self-authorizes
verification, evidence sufficiency, or terminal completion.
"""
from synapx_harness.adapters.codex.contract import (
    INTERACTIVE_TUI_AUTHORITATIVE,
    SDK_API_SUPPORTED,
    SELECTED_INTERFACE,
    CodexAdapter,
    CodexAdapterContract,
    CodexInterface,
)
from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario
from synapx_harness.adapters.codex.models import (
    DEFAULT_MAX_OUTPUT_BYTES,
    AgentContext,
    AgentExecutionContext,
    AgentFailure,
    AgentInvocation,
    AgentLimits,
    AgentOutput,
    AgentRequest,
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentWorkspace,
    FailureCategory,
    ProcessResult,
    ProviderMeta,
)
from synapx_harness.adapters.codex.runtime import (
    RuntimeInvocation,
    SubprocessCodexRuntime,
)

__all__ = [
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
    "CodexAdapter",
    "CodexAdapterContract",
    "CodexInterface",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "FailureCategory",
    "FakeCodexRuntime",
    "FakeScenario",
    "INTERACTIVE_TUI_AUTHORITATIVE",
    "RuntimeInvocation",
    "SubprocessCodexRuntime",
    "ProcessResult",
    "ProviderMeta",
    "SDK_API_SUPPORTED",
    "SELECTED_INTERFACE",
]
