"""Deterministic RED qualification (RQ8-REDQ-001, MODIFIED_OPTION_B).

Three strictly separated data objects:

* :class:`QualifiedRedExpectation` -- what failure would represent the
  intended defect. Staged by whoever holds defect authority (benchmark
  fixture / user / operator / repository evidence); the harness never
  invents it.
* :class:`RedObservation` -- what one actual verifier execution observed
  (exit code, failure kind, failed test IDs, revision and command
  bindings). Built only from a real verifier run, never from agent output.
* :class:`RedQualificationEvidence` -- the verdict of the deterministic
  :func:`compare_red_qualification` comparator, the SOLE producer of the
  authoritative ``failure_reason_matches_intended_defect`` output.

Scope notes (RQ8-P1-R3 Sec 31 justification for a new bounded module):
the handoff concepts do not fit any single existing file without crossing
its boundary (authority stays in ``mutation_authority``, composition in
``governed_execution``, parsing in ``evidence.pytest_result_parser``).
This module is pure (no subprocess, no filesystem, no agent, no LLM) and
imports nothing from the harness so the comparator cannot acquire side
effects through coupling.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

COMPARATOR_VERSION = "1"

RED_EXPECTATION_FILENAME = ".synapx_red_expectation.json"

SUPPORTED_MATCH_RULES: tuple[str, ...] = ("EXACT_FAILED_TEST_IDS",)

AUTHORITATIVE_SOURCE_TYPES: tuple[str, ...] = (
    "BENCHMARK_FIXTURE",
    "USER_DECLARED",
    "OPERATOR_DECLARED",
    "REPOSITORY_EVIDENCE",
)

FAILURE_KINDS: tuple[str, ...] = (
    "TEST_FAILURE",
    "COLLECTION_ERROR",
    "INFRASTRUCTURE_ERROR",
    "UNKNOWN",
)


class ExpectationError(ValueError):
    """Raised when staged expectation content cannot qualify for loading."""


def _require_nonempty_str(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExpectationError(f"{field_name} must be a non-empty string")
    return value


def _require_str_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ExpectationError(f"{field_name} must be a list of strings")
    items: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            raise ExpectationError(
                f"{field_name} must contain only non-empty strings"
            )
        items.append(entry)
    return tuple(items)


@dataclass(frozen=True)
class QualifiedRedExpectation:
    """Staged declaration of what failure represents the intended defect."""

    expectation_id: str
    expectation_version: int
    status: str
    source_type: str
    source_revision: str
    verification_command_fingerprint: str
    expected_exit_code: int
    match_rule: str
    required_failed_test_ids: tuple[str, ...] = field(default_factory=tuple)
    provenance_source_ref: str = ""
    provenance_source_sha256: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> QualifiedRedExpectation:
        """Validate staged content. Only QUALIFIED + authoritative source
        loads; PROPOSED / LLM_PROPOSED / missing provenance / malformed
        content raises :class:`ExpectationError` (fail closed at load)."""
        if not isinstance(data, dict):
            raise ExpectationError("expectation must be a JSON object")
        try:
            status = data["status"]
            source_type = data["source_type"]
            match_rule = data["match_rule"]
            expected_exit_code = data["expected_exit_code"]
            provenance = data["provenance"]
        except KeyError as exc:
            raise ExpectationError(
                f"expectation missing required field {exc}"
            ) from exc
        if status != "QUALIFIED":
            raise ExpectationError(
                f"expectation status must be QUALIFIED (got {status!r})"
            )
        if source_type not in AUTHORITATIVE_SOURCE_TYPES:
            raise ExpectationError(
                f"expectation source_type is not authoritative "
                f"(got {source_type!r})"
            )
        if match_rule not in SUPPORTED_MATCH_RULES:
            raise ExpectationError(
                f"unsupported match_rule {match_rule!r}"
            )
        if not isinstance(expected_exit_code, int) or isinstance(
            expected_exit_code, bool
        ):
            raise ExpectationError("expected_exit_code must be an int")
        if not isinstance(provenance, dict):
            raise ExpectationError("provenance must be an object")
        provenance_source_ref = provenance.get("source_ref")
        provenance_source_sha256 = provenance.get("source_sha256")
        raw_version = data.get("expectation_version")
        if not isinstance(raw_version, int) or isinstance(raw_version, bool):
            raise ExpectationError("expectation_version must be an int")
        # RQ8-P1-R3 Sec 8 vs Sec 21 field-name bridge: the canonical
        # revision field is ``source_revision``; fixture artifacts following
        # Sec 21 may carry it as ``seeded_source_revision``. Both names
        # bind the identical pre-mutation bytes; canonical wins if both
        # are (equally) present.
        revision = data.get("source_revision", data.get("seeded_source_revision"))
        return cls(
            expectation_id=_require_nonempty_str(
                data.get("expectation_id"), "expectation_id"
            ),
            expectation_version=raw_version,
            status=status,
            source_type=source_type,
            source_revision=_require_nonempty_str(
                revision, "source_revision"
            ),
            verification_command_fingerprint=_require_nonempty_str(
                data.get("verification_command_fingerprint"),
                "verification_command_fingerprint",
            ),
            expected_exit_code=expected_exit_code,
            match_rule=match_rule,
            required_failed_test_ids=_require_str_tuple(
                data.get("required_failed_test_ids", []),
                "required_failed_test_ids",
            ),
            provenance_source_ref=_require_nonempty_str(
                provenance_source_ref, "provenance.source_ref"
            ),
            provenance_source_sha256=_require_nonempty_str(
                provenance_source_sha256, "provenance.source_sha256"
            ),
        )


@dataclass(frozen=True)
class RedObservation:
    """What one actual verifier execution observed (built by the runner)."""

    observation_id: str
    source_revision: str
    verification_command: tuple[str, ...]
    verification_command_fingerprint: str
    exit_code: int
    failure_kind: str
    failed_test_ids: tuple[str, ...] = field(default_factory=tuple)
    stdout_sha256: str = ""
    stderr_sha256: str = ""
    job_id: str = ""
    task_id: str = ""
    attempt_id: str = ""

    def __post_init__(self) -> None:
        if self.failure_kind not in FAILURE_KINDS:
            raise ValueError(
                f"failure_kind must be one of {FAILURE_KINDS}"
            )


@dataclass(frozen=True)
class RedQualificationEvidence:
    """Comparator-derived verdict (sole authority for the match output)."""

    qualification_id: str
    expectation_id: str
    expectation_version: int
    observation_id: str
    source_revision: str
    verification_command_fingerprint: str
    comparator_version: str
    expected_exit_code: int
    observed_exit_code: int
    expected_failed_test_ids: tuple[str, ...] = field(default_factory=tuple)
    observed_failed_test_ids: tuple[str, ...] = field(default_factory=tuple)
    match_result: bool = False
    failure_reason_matches_intended_defect: bool = False
    reason: str | None = None
    created_at: str = ""
    # RQ8-P1-R3-R1 identity bindings (Sec 13). Defaulted so previously
    # constructed evidence keeps its meaning; the governed wiring always
    # supplies them.
    work_contract_id: str = ""
    work_contract_schema_version: str = ""
    job_id: str = ""
    task_id: str = ""
    attempt_id: str = ""
    expectation_source_type: str = ""
    expectation_provenance_ref: str = ""
    expectation_provenance_sha256: str = ""
    command_receipt_id: str = ""


def verification_command_fingerprint(command: list[str] | tuple[str, ...]) -> str:
    """Bind a logical verifier command, machine-independently.

    Canonical form is the argv list itself (bare tokens such as
    ``["uv", "run", "pytest", "-q"]``); no host-local absolute path may
    appear in a portable fingerprint. The digest is SHA-256 over the
    minimal JSON encoding of that list.
    """
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("command must be a non-empty argv list")
    for entry in command:
        if not isinstance(entry, str) or not entry:
            raise ValueError("command argv entries must be non-empty strings")
    canonical = json.dumps(
        list(command), separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _qualification_id(
    expectation_id: str, observation_id: str
) -> str:
    seed = "\x00".join((expectation_id, observation_id, COMPARATOR_VERSION))
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def compare_red_qualification(
    expectation: QualifiedRedExpectation,
    observation: RedObservation,
    *,
    created_at: str,
    work_contract_id: str = "",
    work_contract_schema_version: str = "",
    command_receipt_id: str = "",
) -> RedQualificationEvidence:
    """Deterministically compare expectation against observation.

    RQ8 first-slice rule (EXACT_FAILED_TEST_IDS): every condition below
    must hold for the derived ``failure_reason_matches_intended_defect``
    output to be true. The first failing check determines ``reason``; no
    check inspects semantics, tracebacks, or prose.
    """
    expected_ids = tuple(sorted(expectation.required_failed_test_ids))
    observed_ids = tuple(sorted(observation.failed_test_ids))

    def deny(reason: str) -> RedQualificationEvidence:
        return RedQualificationEvidence(
            qualification_id=_qualification_id(
                expectation.expectation_id, observation.observation_id
            ),
            expectation_id=expectation.expectation_id,
            expectation_version=expectation.expectation_version,
            observation_id=observation.observation_id,
            source_revision=observation.source_revision,
            verification_command_fingerprint=(
                observation.verification_command_fingerprint
            ),
            comparator_version=COMPARATOR_VERSION,
            expected_exit_code=expectation.expected_exit_code,
            observed_exit_code=observation.exit_code,
            expected_failed_test_ids=expected_ids,
            observed_failed_test_ids=observed_ids,
            match_result=False,
            failure_reason_matches_intended_defect=False,
            reason=reason,
            created_at=created_at,
            work_contract_id=work_contract_id,
            work_contract_schema_version=work_contract_schema_version,
            job_id=observation.job_id,
            task_id=observation.task_id,
            attempt_id=observation.attempt_id,
            expectation_source_type=expectation.source_type,
            expectation_provenance_ref=expectation.provenance_source_ref,
            expectation_provenance_sha256=(
                expectation.provenance_source_sha256
            ),
            command_receipt_id=command_receipt_id,
        )

    if expectation.match_rule not in SUPPORTED_MATCH_RULES:
        return deny(
            f"unsupported match rule: {expectation.match_rule}",
        )
    if observation.source_revision != expectation.source_revision:
        return deny("source revision mismatch between expectation and observation")
    if (
        observation.verification_command_fingerprint
        != expectation.verification_command_fingerprint
    ):
        return deny("verification command fingerprint mismatch")
    if expectation.expected_exit_code != 1:
        return deny("expected exit code is not 1")
    if observation.exit_code != expectation.expected_exit_code:
        return deny("observed exit code differs from expected exit code")
    if observation.failure_kind != "TEST_FAILURE":
        return deny(
            f"failure kind is not TEST_FAILURE: {observation.failure_kind}",
        )
    if not expected_ids:
        return deny("no required failed test IDs declared")
    if set(observed_ids) != set(expected_ids):
        return deny("observed failed test IDs do not match expected IDs")

    return RedQualificationEvidence(
        qualification_id=_qualification_id(
            expectation.expectation_id, observation.observation_id
        ),
        expectation_id=expectation.expectation_id,
        expectation_version=expectation.expectation_version,
        observation_id=observation.observation_id,
        source_revision=observation.source_revision,
        verification_command_fingerprint=(
            observation.verification_command_fingerprint
        ),
        comparator_version=COMPARATOR_VERSION,
        expected_exit_code=expectation.expected_exit_code,
        observed_exit_code=observation.exit_code,
        expected_failed_test_ids=expected_ids,
        observed_failed_test_ids=observed_ids,
        match_result=True,
        failure_reason_matches_intended_defect=True,
        reason=None,
        created_at=created_at,
        work_contract_id=work_contract_id,
        work_contract_schema_version=work_contract_schema_version,
        job_id=observation.job_id,
        task_id=observation.task_id,
        attempt_id=observation.attempt_id,
        expectation_source_type=expectation.source_type,
        expectation_provenance_ref=expectation.provenance_source_ref,
        expectation_provenance_sha256=expectation.provenance_source_sha256,
        command_receipt_id=command_receipt_id,
    )


def verify_workcontract_expectation_binding(
    bound: dict[str, object] | None,
    loaded_bytes: bytes,
    loaded_path: str,
) -> tuple[dict[str, Any] | None, str | None]:
    """Verify staged bytes against the WorkContract binding (pure).

    Returns ``(parsed_payload, None)`` iff the binding exists and every
    bound field (sha256 over the exact loaded bytes, ref path, id,
    version) matches; otherwise ``(None, cause)`` naming the first
    mismatch. A staged file WITHOUT a binding (staged after the
    WorkContract was built, or bound to another WorkContract) never
    authorizes. JSON parsing happens here so hash/ref mismatches precede
    syntax judgments deterministically.
    """
    if not isinstance(bound, dict) or not bound:
        return None, (
            "staged RED expectation is not WorkContract-bound "
            "(no red_expectation binding on the WorkContract)"
        )
    try:
        bound_id = bound["expectation_id"]
        bound_version = bound["expectation_version"]
        bound_ref = bound["expectation_ref"]
        bound_sha = bound["expectation_sha256"]
    except KeyError as exc:
        return None, f"WorkContract RED binding is incomplete ({exc})"
    if (
        not isinstance(bound_id, str)
        or not bound_id
        or not isinstance(bound_ref, str)
        or not bound_ref
        or not isinstance(bound_sha, str)
        or not bound_sha
        or not isinstance(bound_version, int)
        or isinstance(bound_version, bool)
    ):
        return None, "WorkContract RED binding fields are not well-formed"
    if hashlib.sha256(loaded_bytes).hexdigest() != bound_sha:
        return None, (
            "RED expectation SHA does not match WorkContract binding "
            "(artifact changed after WorkContract creation or swapped file)"
        )
    if loaded_path != bound_ref:
        return None, (
            "RED expectation ref does not match WorkContract binding"
        )
    try:
        payload = json.loads(loaded_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return None, f"malformed QualifiedRedExpectation: {exc}"
    if not isinstance(payload, dict):
        return None, "malformed QualifiedRedExpectation: not a JSON object"
    if payload.get("expectation_id") != bound_id:
        return None, (
            "RED expectation id does not match WorkContract binding"
        )
    if payload.get("expectation_version") != bound_version:
        return None, (
            "RED expectation version does not match WorkContract binding"
        )
    return payload, None


__all__ = [
    "AUTHORITATIVE_SOURCE_TYPES",
    "COMPARATOR_VERSION",
    "FAILURE_KINDS",
    "RED_EXPECTATION_FILENAME",
    "SUPPORTED_MATCH_RULES",
    "ExpectationError",
    "QualifiedRedExpectation",
    "RedObservation",
    "RedQualificationEvidence",
    "compare_red_qualification",
    "verification_command_fingerprint",
    "verify_workcontract_expectation_binding",
]
