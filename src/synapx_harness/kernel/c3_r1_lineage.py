"""RQ4-R2-C3-R1 execution lineage serializer.

The lineage JSON is the single artifact that binds every RQ4-R2-C3
runtime object to a single canonical envelope (RQ4 §7, §12). It is
materialized directly from the in-memory :class:`GovernedExecutionResult`
returned by :func:`run_governed_execution` -- no field is reconstructed
by reading the filesystem after the run.

Required fields (RQ4 §4): every slot must carry a real value. Placeholder
strings such as ``"<from run>"``, ``"COMPUTED"``, ``"N/A"``, ``"UNKNOWN"``
are forbidden; missing values must surface as ``None`` so the consumer
can detect them.
"""
from __future__ import annotations

import datetime as _datetime
from pathlib import Path
from typing import Any

from synapx_harness.kernel.governed_execution import GovernedExecutionResult


def _now_iso() -> str:
    return _datetime.datetime.now(_datetime.UTC).isoformat()


def _maybe_dict(obj: Any) -> dict[str, object] | None:
    """Return ``obj`` as a dict regardless of pydantic / dataclass / dict shape.

    Adapts to:

    * Pydantic v2 ``BaseModel`` (``model_dump`` / ``model_dump(mode="json")``).
    * Python ``@dataclass`` (``dataclasses.asdict``).
    * Plain dict (passed through).
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return dict(obj)
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(mode="json")
        except Exception:
            try:
                return obj.model_dump()
            except Exception:
                pass
    import dataclasses as _dc

    # is_dataclass() is also True for dataclass *classes*; asdict() needs an
    # instance, so exclude the type case explicitly (truthful narrowing, no
    # runtime behaviour change: callers only pass instances or dicts).
    if _dc.is_dataclass(obj) and not isinstance(obj, type):
        try:
            return _dc.asdict(obj)
        except Exception:
            return None
    return None


def build_lineage_envelope(
    result: GovernedExecutionResult,
    *,
    repository_root: Path,
    head_sha: str | None = None,
    tree_sha: str | None = None,
) -> dict[str, object]:
    """Build the C3-R1 execution lineage JSON envelope.

    The shape follows RQ4 §7. Every field is populated from the
    in-memory runtime objects held in ``result``; no post-hoc
    filesystem reads are performed.

    Parameters
    ----------
    result:
        The :class:`GovernedExecutionResult` returned by
        :func:`run_governed_execution` for the run being evidenced.
    repository_root:
        The repository root passed to ``run_governed_execution``. Stored
        verbatim; not used to read state.
    head_sha, tree_sha:
        Optional bound values (git HEAD/TREE SHA). When ``None``, they
        are serialized as ``None`` so consumers can detect omission.
    """
    execution_identity = result.execution_identity
    agent_request_identity: dict[str, object] = {
        "work_contract_id": result.work_contract_id,
        "agent_session_id": result.agent_session_id,
        "execution_identity": execution_identity.model_dump(mode="json"),
    }

    admission = result.admission_receipt
    path_receipt = result.path_gate_receipt
    apply = result.apply_receipt

    sealed = result.sealed_evidence or {}
    sealed_identity = sealed.get("integrity_status") or sealed.get(
        "sealed_by"
    )

    terminal_record = _maybe_dict(result.terminal_decision) or {}

    lineage: dict[str, object] = {
        # ----- SSoT envelope -----
        "schema": "synapx.rq4.r2.c3.r1.execution_lineage.v1",
        "produced_at": _now_iso(),
        "repository_root": str(Path(repository_root).resolve()),
        # ----- Execution identity (CA-01 / RQ4 §7) -----
        "execution_identity": {
            "job_id": execution_identity.job_id,
            "root_task_id": execution_identity.root_task_id,
            "task_id": execution_identity.task_id,
            "attempt_id": execution_identity.attempt_id,
            "tool_call_id": execution_identity.tool_call_id,
            "agent_session_id": result.agent_session_id,
        },
        # ----- WorkContract lineage -----
        "work_contract": {
            "work_contract_id": result.work_contract_id,
            "execution_identity": execution_identity.model_dump(mode="json"),
        },
        # ----- Agent request lineage -----
        "agent_request": agent_request_identity,
        # ----- Codex process (real run, RQ8-R1-R2-R2 D2 surface) -----
        # The ``process_started`` / ``failure_class`` slots are the
        # authoritative launch/process outcome of the Codex subprocess.
        # Use ``getattr`` so the envelope stays compatible with the
        # historical R2 ``Stub`` test doubles that do not declare these
        # attributes (default ``None`` -> "unknown").
        "codex_process": {
            "version": result.codex_process_version,
            "exit_code": result.codex_process_exit_code,
            "stdout_sha256": result.agent_stdout_sha256,
            "stderr_sha256": result.agent_stderr_sha256,
            "process_started": getattr(result, "process_started", None),
            "failure_class": getattr(result, "failure_class", None),
        },
        # ----- Source revision chronology (RQ4 §5) -----
        "source_revisions": {
            "pre_codex_source_revision": result.pre_codex_source_revision,
            "pre_apply_source_revision": result.pre_apply_source_revision,
            "post_apply_source_revision": result.post_apply_source_revision,
            "head_sha": head_sha,
            "tree_sha": tree_sha,
        },
        # ----- PatchProposal (RQ8-R1-R2-R2-R1 Q2 stage truth) -----
        # ``parsing_attempted`` records whether the structured parser was
        # invoked for this run; ``valid`` carries its verdict. The slot is
        # always a dict so downstream consumers can read
        # ``patch_proposal.parsing_attempted`` uniformly without having to
        # branch on ``None``.
        "patch_proposal": {
            "valid": result.proposal.valid if result.proposal is not None else None,
            "paths": list(result.proposal.paths) if result.proposal is not None else [],
            "sha256": result.proposal.sha256 if result.proposal is not None else None,
            "canonical_patch_sha256": (
                result.proposal.canonical_patch_sha256
                if result.proposal is not None
                else None
            ),
            "raw_input_sha256": (
                result.proposal.raw_input_sha256
                if result.proposal is not None
                else None
            ),
            "parsing_attempted": getattr(result, "proposal_parsing_attempted", False),
        },
        # ----- Mutation receipts (kept at envelope top level for legacy
        # R2 consumers; Q2 stage truth is duplicated in the ``mutation``
        # block below) -----
        "admission_receipt": _maybe_dict(admission),
        "path_gate_receipt": _maybe_dict(path_receipt),
        "apply_receipt": _maybe_dict(apply),
        # ----- Mutation stage truth (Q2) -----
        "mutation": {
            "attempted": getattr(result, "mutation_attempted", False),
        },
        # ----- Verification stage truth + resolver authority -----
        # ``verification_attempted`` is the truthful answer to "did the
        # independent verifier actually run for this run?".
        "verification": (
            None
            if result.verification is None
            else {
                "attempted": getattr(result, "verification_attempted", False),
                "verification_status": result.verification.verification_status,
                "evidence_status": result.verification.evidence_status,
                "active_blocker_count": result.verification.active_blocker_count,
                "red_qualified": result.verification.red_qualified,
                "red_qualification_ref": result.verification.red_qualification_ref,
                "command": (
                    result.verification.command_result.sanitized_command
                    if result.verification.command_result is not None
                    else None
                ),
                "command_source": (
                    "explicit_override"
                    if getattr(result, "verification_command", None)
                    is not None
                    else "resolver"
                ),
            }
        ),
        # ----- Sealed evidence -----
        "sealed_evidence": {
            "integrity_status": sealed.get("integrity_status"),
            "sealed_by": sealed.get("sealed_by"),
            "sealer_id": sealed.get("sealer_id"),
            "sealed_at": sealed.get("sealed_at"),
            "sealed_identity": sealed_identity,
        },
        # ----- Terminal decision (RQ8-R1-R2-R2-R1 D4 primary failure surface) -----
        "terminal_decision": {
            "work_contract_id": terminal_record.get("work_contract_id")
            or result.work_contract_id,
            "decision": terminal_record.get("decision"),
            "reason": terminal_record.get("reason"),
            "primary_failure_stage": getattr(result, "primary_failure_stage", None),
            "primary_failure_class": getattr(result, "primary_failure_class", None),
            "primary_failure_message": getattr(result, "primary_failure_message", None),
        },
        # ----- Errors (kept for transparency; non-empty means non-COMPLETED) -----
        "errors": list(result.errors),
        "success": bool(result.success),
    }
    return lineage


def assert_lineage_consistency(
    lineage: dict[str, object],
    *,
    expected_work_contract_id: str,
) -> list[str]:
    """Run the RQ4 §7 deterministic assertions against a lineage envelope.

    Returns the list of *failures* (empty list == PASS).
    """
    failures: list[str] = []
    eid_obj = lineage.get("execution_identity")
    wc_obj = lineage.get("work_contract")
    agent_req = lineage.get("agent_request")
    admission = lineage.get("admission_receipt")
    terminal = lineage.get("terminal_decision")

    if not isinstance(eid_obj, dict):
        failures.append("execution_identity missing or not a dict")
        return failures
    if not isinstance(wc_obj, dict):
        failures.append("work_contract missing or not a dict")
    if not isinstance(agent_req, dict):
        failures.append("agent_request missing or not a dict")
    if not isinstance(admission, dict):
        failures.append("admission_receipt missing or not a dict")
    if not isinstance(terminal, dict):
        failures.append("terminal_decision missing or not a dict")

    for slot in ("job_id", "root_task_id", "task_id", "attempt_id"):
        val = eid_obj.get(slot)
        if not isinstance(val, str) or not val:
            failures.append(f"execution_identity.{slot} missing or empty")

    if eid_obj.get("work_contract_id") and eid_obj.get("work_contract_id") != expected_work_contract_id:
        failures.append(
            "execution_identity.work_contract_id mismatch "
            f"({eid_obj.get('work_contract_id')!r} != {expected_work_contract_id!r})"
        )
    if (
        isinstance(wc_obj, dict)
        and wc_obj.get("work_contract_id") != expected_work_contract_id
    ):
        failures.append(
            "work_contract.work_contract_id mismatch "
            f"({wc_obj.get('work_contract_id')!r} != {expected_work_contract_id!r})"
        )
    if (
        isinstance(agent_req, dict)
        and agent_req.get("work_contract_id") != expected_work_contract_id
    ):
        failures.append(
            "agent_request.work_contract_id mismatch "
            f"({agent_req.get('work_contract_id')!r} != {expected_work_contract_id!r})"
        )
    if (
        isinstance(admission, dict)
        and admission.get("work_contract_id")
        and admission.get("work_contract_id") != expected_work_contract_id
    ):
        failures.append(
            "admission_receipt.work_contract_id mismatch "
            f"({admission.get('work_contract_id')!r} != {expected_work_contract_id!r})"
        )
    if (
        isinstance(terminal, dict)
        and terminal.get("work_contract_id")
        and terminal.get("work_contract_id") != expected_work_contract_id
    ):
        failures.append(
            "terminal_decision.work_contract_id mismatch "
            f"({terminal.get('work_contract_id')!r} != {expected_work_contract_id!r})"
        )

    eid_inner = (
        wc_obj.get("execution_identity") if isinstance(wc_obj, dict) else None
    )
    if isinstance(eid_inner, dict):
        for slot in ("job_id", "root_task_id", "task_id", "attempt_id"):
            if eid_inner.get(slot) != eid_obj.get(slot):
                failures.append(
                    f"work_contract.execution_identity.{slot} differs from "
                    f"execution_identity.{slot}"
                )

    return failures


__all__ = [
    "assert_lineage_consistency",
    "build_lineage_envelope",
]
