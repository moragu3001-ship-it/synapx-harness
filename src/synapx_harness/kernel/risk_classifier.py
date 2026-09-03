"""Risk classifier (H2-I1).

Two layers are exposed:

* **Legacy PilotRisk-backed helpers** (``classify``, ``is_blocked_in_pilot``).
  They remain stable so that prior governance contracts keep parsing.
* **Canonical string-backed helpers** (``classify_str``,
  ``is_admissible``, ``classify_task``). The canonical helpers are used
  by the core admission pipeline (X3 CA-08) and obey:

    - R0, R1, R2 are admissible (admit).
    - R3, R4 are blocked (terminalising → BLOCKED).
    - Self-declaration of risk is forbidden (RiskPolicy invariant).

The classifier does NOT make admission decisions in isolation. It only
returns the policy token; the gate is the caller's responsibility.
"""
from __future__ import annotations

from typing import Any

from synapx_harness.contracts.models import PilotRisk

R0_POLICY = "AUTO_ADMIT"
R1_POLICY = "DOCUMENT_OR_TEST_SCOPE"
R2_POLICY = "EXPLICIT_MUTATION_POLICY_AND_HITL"
R3_POLICY = "BLOCKED"
R4_POLICY = "BLOCKED"

ADMISSIBLE_RISKS: tuple[str, ...] = ("R0", "R1", "R2")
BLOCKED_RISKS: tuple[str, ...] = ("R3", "R4")

TASK_TYPE_BUG_FIX = "BUG_FIX"
TASK_TYPE_TEST_REPAIR = "TEST_REPAIR"
TASK_TYPE_DOC_FIX = "DOC_FIX"
TASK_TYPE_REVIEW_FIX = "REVIEW_FIX"
TASK_TYPE_WORK_ADMISSION = "WORK_ADMISSION"
TASK_TYPE_SCHEMA_REVISION = "SCHEMA_REVISION"
TASK_TYPE_ADAPTER_FIX = "ADAPTER_FIX"
TASK_TYPE_INFRA_FIX = "INFRA_FIX"
TASK_TYPE_LOG_FIX = "LOG_FIX"
TASK_TYPE_NAMESPACE_REPAIR = "NAMESPACE_REPAIR"
TASK_TYPE_GOVERNANCE_FIX = "GOVERNANCE_FIX"
TASK_TYPE_REVISION_BINDING = "REVISION_BINDING"
TASK_TYPE_SOURCE_BINDING = "SOURCE_BINDING"
TASK_TYPE_GUARDRAIL_TRIM = "GUARDRAIL_TRIM"
TASK_TYPE_DOCS_TRIM = "DOCS_TRIM"

_RISK_POLICY: dict[PilotRisk, str] = {
    PilotRisk.R0: R0_POLICY,
    PilotRisk.R1: R1_POLICY,
    PilotRisk.R2: R2_POLICY,
    PilotRisk.R3: R3_POLICY,
    PilotRisk.R4: R4_POLICY,
}

TASK_TYPE_TO_DEFAULT_RISK: dict[str, str] = {
    TASK_TYPE_BUG_FIX: "R2",
    TASK_TYPE_TEST_REPAIR: "R1",
    TASK_TYPE_DOC_FIX: "R1",
    TASK_TYPE_REVIEW_FIX: "R1",
    TASK_TYPE_WORK_ADMISSION: "R0",
    TASK_TYPE_SCHEMA_REVISION: "R2",
    TASK_TYPE_ADAPTER_FIX: "R2",
    TASK_TYPE_INFRA_FIX: "R3",
    TASK_TYPE_LOG_FIX: "R1",
    TASK_TYPE_NAMESPACE_REPAIR: "R2",
    TASK_TYPE_GOVERNANCE_FIX: "R2",
    TASK_TYPE_REVISION_BINDING: "R0",
    TASK_TYPE_SOURCE_BINDING: "R0",
    TASK_TYPE_GUARDRAIL_TRIM: "R1",
    TASK_TYPE_DOCS_TRIM: "R1",
}


def classify(risk: PilotRisk) -> str:
    """Return the policy token for a Pilot Risk class (legacy)."""
    return _RISK_POLICY[risk]


def is_blocked_in_pilot(risk: PilotRisk) -> bool:
    """Return True if the risk class is blocked in the pilot (legacy)."""
    return risk in {PilotRisk.R3, PilotRisk.R4}


def _pilot_from_str(risk_class: str) -> PilotRisk:
    if risk_class == "R0":
        return PilotRisk.R0
    if risk_class == "R1":
        return PilotRisk.R1
    if risk_class == "R2":
        return PilotRisk.R2
    if risk_class == "R3":
        return PilotRisk.R3
    if risk_class == "R4":
        return PilotRisk.R4
    raise ValueError(f"risk_class must be one of R0..R4 (got {risk_class!r})")


def classify_str(risk_class: str) -> str:
    """Canonical helper: map the canonical risk_class string to a policy."""
    return _RISK_POLICY[_pilot_from_str(risk_class)]


def is_admissible(risk_class: str) -> bool:
    """Canonical helper: True when R0..R2, False for R3..R4."""
    _pilot_from_str(risk_class)
    return risk_class in ADMISSIBLE_RISKS


def classify_task(
    task_payload: dict[str, Any] | None,
    *,
    default_risk: str = "R1",
) -> tuple[str, str]:
    """Return (task_type, risk_class) for an incoming work request.

    The helper never makes the final admission decision; it only maps
    the proposal payload onto a (task_type, risk_class) pair. Pass
    ``task_payload['task_type']`` to override the default ``BUG_FIX``
    policy derived at run-time.

    The function itself does NOT raise on missing fields: missing
    task_type falls back to ``BUG_FIX``. Provider-declared risk is
    *never* honoured; we always re-derive from the task_type so the
    RiskPolicy self-declaration invariant is enforced.
    """
    if task_payload is None:
        task_payload = {}
    raw_task_type = task_payload.get("task_type")
    if isinstance(raw_task_type, str) and raw_task_type in TASK_TYPE_TO_DEFAULT_RISK:
        task_type = raw_task_type
    else:
        task_type = TASK_TYPE_BUG_FIX
    risk_class = TASK_TYPE_TO_DEFAULT_RISK.get(task_type, default_risk)
    if risk_class not in ADMISSIBLE_RISKS + BLOCKED_RISKS:
        risk_class = default_risk
    return task_type, risk_class


__all__ = [
    "ADMISSIBLE_RISKS",
    "BLOCKED_RISKS",
    "R0_POLICY",
    "R1_POLICY",
    "R2_POLICY",
    "R3_POLICY",
    "R4_POLICY",
    "TASK_TYPE_ADAPTER_FIX",
    "TASK_TYPE_BUG_FIX",
    "TASK_TYPE_DOC_FIX",
    "TASK_TYPE_DOCS_TRIM",
    "TASK_TYPE_GOVERNANCE_FIX",
    "TASK_TYPE_GUARDRAIL_TRIM",
    "TASK_TYPE_INFRA_FIX",
    "TASK_TYPE_LOG_FIX",
    "TASK_TYPE_NAMESPACE_REPAIR",
    "TASK_TYPE_REVIEW_FIX",
    "TASK_TYPE_REVISION_BINDING",
    "TASK_TYPE_SCHEMA_REVISION",
    "TASK_TYPE_SOURCE_BINDING",
    "TASK_TYPE_TEST_REPAIR",
    "TASK_TYPE_WORK_ADMISSION",
    "TASK_TYPE_TO_DEFAULT_RISK",
    "classify",
    "classify_str",
    "classify_task",
    "is_admissible",
    "is_blocked_in_pilot",
]
