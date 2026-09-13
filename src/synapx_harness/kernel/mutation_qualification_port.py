"""Production VerificationPort capable of qualifying a bounded TEST_REPAIR mutation.

FC3 Case A repair
-----------------
The default :class:`FailClosedVerificationPort` is intentionally fail-closed
and can never qualify a successful mutation (it always returns FAIL/INVALID
with one active blocker). This module adds the minimal production verification
capability required to qualify an I4 Tiny Mutation, bounded strictly to the
six criteria allowed by the FC3 repair contract:

1. RED qualified          - red/result.json exists, exit_code != 0,
                            failure_reason_matches_intended_defect == true
2. exact write path       - execution/write_ledger.json actual_changed_paths
                            is a subset of authorized_paths
3. AgentResult DONE       - agent_result.status == DONE
4. targeted GREEN         - green/result.json exists, exit_code == 0
5. regression no-new-fail - regression/differential.json has new_failed == []
                            and new_errors == []
6. identity binding       - agent_result.execution_identity equals the
                            work_contract execution identity

This is a production port: it is instantiated with an evidence root and reads
the actual evidence artifacts at verification time. It never fabricates PASS.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from synapx_harness.adapters.codex.models import AgentResult
from synapx_harness.context.models import SharedUnderstandingContext
from synapx_harness.contracts.runtime_models import VerificationResult
from synapx_harness.kernel.governed_runtime_provider import VerificationPort

MUTATION_QUALIFICATION_PORT_VERSION = "0.1.0"


class MutationQualificationPort(VerificationPort):
    """Production verification port for bounded TEST_REPAIR mutations.

    Reads the actual evidence artifacts under ``evidence_root`` and verifies
    the six I4 qualification criteria. Fail-closed: any missing artifact,
    mismatched identity, or failing criterion produces FAIL.
    """

    def __init__(self, evidence_root: str | Path) -> None:
        self._evidence_root = Path(evidence_root)
        if not self._evidence_root.is_dir():
            raise ValueError(
                f"MutationQualificationPort: evidence_root is not a directory: "
                f"{self._evidence_root}"
            )

    def _read_json(self, rel_path: str) -> dict[str, Any] | None:
        path = self._evidence_root / rel_path
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def verify(
        self,
        work_contract: dict[str, object],
        agent_result: AgentResult,
        shared_context: SharedUnderstandingContext,
    ) -> VerificationResult:
        work_contract_id = str(work_contract.get("work_contract_id", "unknown"))
        checks: list[dict[str, object]] = []
        blockers: list[str] = []

        # 1. AgentResult DONE
        status_ok = agent_result.status.value == "DONE"
        checks.append(
            {
                "check": "agent_result_done",
                "passed": status_ok,
                "actual": agent_result.status.value,
            }
        )
        if not status_ok:
            blockers.append("agent_result.status != DONE")

        # 2. Identity binding
        wc_identity = work_contract.get("execution_identity")
        if wc_identity is not None and hasattr(wc_identity, "model_dump"):
            wc_identity = cast(Any, wc_identity).model_dump(mode="json")
        if not isinstance(wc_identity, dict):
            wc_identity = {}
        result_identity = agent_result.execution_identity.execution_identity
        identity_ok = (
            wc_identity.get("job_id") == result_identity.job_id
            and wc_identity.get("task_id") == result_identity.task_id
            and wc_identity.get("attempt_id") == result_identity.attempt_id
        )
        checks.append(
            {
                "check": "identity_binding",
                "passed": identity_ok,
                "wc_attempt": wc_identity.get("attempt_id"),
                "result_attempt": result_identity.attempt_id,
            }
        )
        if not identity_ok:
            blockers.append("agent_result identity != work_contract identity")

        # 3. RED qualified
        red = self._read_json("red/result.json")
        red_ok = (
            red is not None
            and red.get("exit_code") == 1
            and red.get("failure_reason_matches_intended_defect") is True
        )
        checks.append({"check": "red_qualified", "passed": red_ok})
        if not red_ok:
            blockers.append("RED not qualified (missing or exit_code != 1)")

        # 4. Targeted GREEN
        green = self._read_json("green/result.json")
        green_ok = green is not None and green.get("exit_code") == 0
        checks.append({"check": "targeted_green", "passed": green_ok})
        if not green_ok:
            blockers.append("GREEN not qualified (missing or exit_code != 0)")

        # 5. Regression no new failure
        differential = self._read_json("regression/differential.json")
        if differential is not None:
            diff = differential.get("differential", {})
            new_failed = diff.get("new_failed", [])
            new_errors = diff.get("new_errors", [])
            regression_ok = len(new_failed) == 0 and len(new_errors) == 0
        else:
            regression_ok = False
        checks.append(
            {
                "check": "regression_no_new_failure",
                "passed": regression_ok,
            }
        )
        if not regression_ok:
            blockers.append("regression new failure/error detected")

        # 6. Exact write path
        ledger = self._read_json("execution/write_ledger.json")
        if ledger is not None:
            # Support both authorized_paths and allowed_write_paths
            authorized = set(ledger.get("authorized_paths", ledger.get("allowed_write_paths", [])))
            # Support both actual_changed_paths and applied_paths
            actual = set(ledger.get("actual_changed_paths", ledger.get("applied_paths", [])))
            write_ok = actual.issubset(authorized) and bool(actual)
        else:
            write_ok = False
        checks.append({"check": "exact_write_path", "passed": write_ok})
        if not write_ok:
            blockers.append("write boundary violated or ledger missing")

        verification_status = "PASS" if not blockers else "FAIL"
        evidence_status = "VALID" if not blockers else "INVALID"
        return VerificationResult(
            work_contract_id=work_contract_id,
            verification_status=verification_status,  # type: ignore[arg-type]
            evidence_status=evidence_status,  # type: ignore[arg-type]
            active_blocker_count=len(blockers),
            checks=checks,
        )


__all__ = [
    "MUTATION_QUALIFICATION_PORT_VERSION",
    "MutationQualificationPort",
]
