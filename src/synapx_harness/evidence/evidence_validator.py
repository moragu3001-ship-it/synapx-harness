"""Evidence Validator for review artifacts.

Validates that all required review artifacts are semantically valid.
"""
from __future__ import annotations

import datetime as _datetime
import hashlib
import json
from pathlib import Path

from synapx_harness.evidence.command_receipt import (
    PLACEHOLDER_HASH,
    validate_command_receipt,
)
from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary

CORE_EVIDENCE_SEALER = "CORE_EVIDENCE_SEALER"
TERMINAL_FINALIZER = "TERMINAL_FINALIZER"
EVIDENCE_ENVELOPE_STATES: tuple[str, ...] = (
    "CREATED",
    "VALIDATED",
    "QUALIFIED",
    "ADMITTED",
    "SEALED",
    "REJECTED",
    "SUPERSEDED",
)


def validate_json_file(path: Path) -> tuple[bool, dict[str, object] | None, list[str]]:
    violations: list[str] = []
    if not path.is_file():
        violations.append(f"file not found: {path}")
        return False, None, violations

    try:
        content = path.read_text(encoding="utf-8")
        data = json.loads(content)
        return True, data, violations
    except json.JSONDecodeError as e:
        violations.append(f"invalid JSON: {e}")
        return False, None, violations


def validate_hash_format(hash_str: str, length: int = 64) -> bool:
    if not isinstance(hash_str, str):
        return False
    if len(hash_str) != length:
        return False
    return all(c in "0123456789abcdef" for c in hash_str)


def validate_required_artifact(path: Path, expected_type: str) -> tuple[bool, list[str]]:
    violations: list[str] = []

    ok, data, read_violations = validate_json_file(path)
    if not ok:
        violations.extend(read_violations)
        return False, violations

    if data is None:
        violations.append("artifact data is None")
        return False, violations

    if expected_type == "command_receipt":
        ok, cv = validate_command_receipt(data)
        if not ok:
            violations.extend(cv)
    elif expected_type == "verification_summary":
        ok, cv = is_valid_verification_summary(data)
        if not ok:
            violations.extend(cv)

    return len(violations) == 0, violations


def validate_artifact_hash_matches(path: Path, expected_sha256: str) -> tuple[bool, list[str]]:
    violations: list[str] = []

    if not path.is_file():
        violations.append(f"file not found: {path}")
        return False, violations

    if not validate_hash_format(expected_sha256):
        violations.append("invalid expected sha256 format")
        return False, violations

    content = path.read_bytes()
    actual_sha = hashlib.sha256(content).hexdigest()

    if actual_sha != expected_sha256:
        violations.append(f"hash mismatch: expected {expected_sha256}, got {actual_sha}")
        return False, violations

    return True, violations


def check_placeholder_hash(hash_str: str) -> bool:
    return hash_str == PLACEHOLDER_HASH


def validate_scoped_manifest_entry(
    entry: dict[str, object],
    actual_content: bytes | None = None,
) -> tuple[bool, list[str]]:
    violations: list[str] = []

    path = entry.get("path")
    if not isinstance(path, str) or not path:
        violations.append("manifest entry missing path")
        return False, violations

    sha256 = entry.get("sha256")
    if not isinstance(sha256, str) or not sha256:
        violations.append("manifest entry missing sha256")
        return False, violations

    if check_placeholder_hash(sha256):
        violations.append("manifest entry sha256 is placeholder")
        return False, violations

    if not validate_hash_format(sha256):
        violations.append("manifest entry sha256 invalid format")
        return False, violations

    size_bytes = entry.get("size_bytes")
    if not isinstance(size_bytes, int) or size_bytes < 0:
        violations.append("manifest entry missing or invalid size_bytes")
        return False, violations

    if actual_content is not None:
        computed_sha = hashlib.sha256(actual_content).hexdigest()
        if computed_sha != sha256:
            violations.append(f"manifest entry sha256 mismatch for {path}")
            return False, violations
        if len(actual_content) != size_bytes:
            violations.append(f"manifest entry size_bytes mismatch for {path}")
            return False, violations

    return True, violations


# -- H2-I3 evidence seal chain (T10/T11) ------------------------------------


def seal_as_terminal_decision(evidence: dict[str, object]) -> dict[str, object]:
    """RED-I0-05: SEALED evidence is never a terminal decision."""
    raise ValueError(
        f"sealed evidence is not a terminal decision: {evidence!r} must be "
        "processed through the terminal finalizer chain (seal|terminal)"
    )


def seal_evidence(
    envelope: dict[str, object],
    sealer: str,
    redaction_applied: bool,
) -> dict[str, object]:
    """Seal an ADMITTED evidence envelope (CORE_EVIDENCE_SEALER only).

    RED-I0-SEAL01: the sealer must never be the TERMINAL_FINALIZER.
    INV-RPR-001: redaction must be applied before sealing.
    """
    if not isinstance(envelope, dict):
        raise ValueError(f"envelope must be a dict; got {envelope!r} (seal|admit)")
    if envelope.get("integrity_status") != "ADMITTED":
        raise ValueError(
            f"envelope must be ADMITTED before sealing; "
            f"got {envelope.get('integrity_status')!r} (seal|admit)"
        )
    if not isinstance(sealer, str) or sealer != CORE_EVIDENCE_SEALER:
        raise ValueError(
            f"sealer must be {CORE_EVIDENCE_SEALER}; {sealer!r} may not seal "
            "(sealer|finaliz)"
        )
    if not redaction_applied:
        raise ValueError(
            "redaction must be applied before evidence sealing (redaction|seal)"
        )
    sealed = dict(envelope)
    sealed["integrity_status"] = "SEALED"
    sealed["sealed_by"] = sealer
    sealed["sealed_at"] = _datetime.datetime.now(_datetime.UTC).isoformat()
    return sealed


def validate_evidence_freshness(
    evidence_timestamp: str,
    threshold_seconds: int,
    reference_now: str,
) -> dict[str, object]:
    """RED-I0-10: reject evidence older than the freshness threshold."""
    try:
        evidence_dt = _datetime.datetime.fromisoformat(str(evidence_timestamp))
        reference_dt = _datetime.datetime.fromisoformat(str(reference_now))
    except ValueError as exc:
        raise ValueError(
            f"unparseable evidence timestamp: {evidence_timestamp!r} / "
            f"{reference_now!r} (fresh|evidence)"
        ) from exc
    if evidence_dt.tzinfo is None or reference_dt.tzinfo is None:
        raise ValueError(
            "evidence freshness requires timezone-aware timestamps (fresh|evidence)"
        )
    age_seconds = (reference_dt - evidence_dt).total_seconds()
    if age_seconds > threshold_seconds:
        raise ValueError(
            f"stale evidence: timestamp {evidence_timestamp} is {age_seconds:.0f}s "
            f"older than threshold {threshold_seconds}s (fresh|evidence)"
        )
    return {"fresh": True, "age_seconds": age_seconds}


__all__ = [
    "CORE_EVIDENCE_SEALER",
    "EVIDENCE_ENVELOPE_STATES",
    "TERMINAL_FINALIZER",
    "check_placeholder_hash",
    "seal_as_terminal_decision",
    "seal_evidence",
    "validate_artifact_hash_matches",
    "validate_evidence_freshness",
    "validate_hash_format",
    "validate_json_file",
    "validate_required_artifact",
    "validate_scoped_manifest_entry",
]
