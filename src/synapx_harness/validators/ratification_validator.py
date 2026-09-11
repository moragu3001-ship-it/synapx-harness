"""Ratification Validator (canonical, fail-closed).

The validator enforces:
  - 4 distinct ratifier ids
  - 4 unanimous APPROVE decisions
  - rc id / version / bundle hash uniform across records and receipt
  - blocking_issues == 0
  - decision == RATIFIED
  - ratifier records IN THE RECEIPT are deep-equal to the supplied
    ratifier records (no ID-only comparison)
  - receipt_id and receipt_sha256 are required and agree with the
    canonical receipt bytes (declared value is **recomputed** for
    comparison; the count of ``ratifiers_approved`` is computed from
    records, never trusted)

Receipt bytes used for hashing exclude ``receipt_sha256`` itself to
avoid the self-referential hash trap.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

EXPECTED_RATIFIERS = 4


@dataclass(frozen=True)
class RatificationReport:
    ok: bool
    violations: tuple[str, ...] = field(default_factory=tuple)
    receipt_sha256: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "violations": list(self.violations),
            "receipt_sha256": self.receipt_sha256,
        }


def canonical_receipt_bytes(payload: Mapping[str, object]) -> bytes:
    """Canonical byte representation for receipt sha256.

    Excludes ``receipt_sha256`` itself to avoid the self-referential
    trap where the receipt content embeds its own hash.
    """
    cleaned = {k: v for k, v in payload.items() if k != "receipt_sha256"}
    canonical = json.dumps(cleaned, sort_keys=True, separators=(",", ":"))
    return canonical.encode("utf-8")


def compute_receipt_sha256(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_receipt_bytes(payload)).hexdigest()


def _records_deep_equal(
    a: Sequence[Mapping[str, object]],
    b: Sequence[Mapping[str, object]],
) -> bool:
    if len(a) != len(b):
        return False
    by_id_a = {str(r["ratifier_id"]): dict(r) for r in a}
    by_id_b = {str(r["ratifier_id"]): dict(r) for r in b}
    if set(by_id_a) != set(by_id_b):
        return False
    for ratifier_id in by_id_a:
        if by_id_a[ratifier_id] != by_id_b[ratifier_id]:
            return False
    return True


def validate_ratification(
    *,
    rc_bundle: Mapping[str, object],
    ratifier_records: Sequence[Mapping[str, object]],
    receipt: Mapping[str, object],
) -> RatificationReport:
    """Validate a Ratification Receipt end-to-end.

    The function does not depend on json schema parsing — it is a
    pure Python validator that fails closed.
    """
    violations: list[str] = []

    if receipt.get("schema_version") != "0.1.0":
        violations.append("schema_version must be 0.1.0")

    if receipt.get("contract_type") != "COMMUNIS_RATIFICATION_RECEIPT":
        violations.append("contract_type must be COMMUNIS_RATIFICATION_RECEIPT")

    if receipt.get("approval_rule") != "UNANIMOUS":
        violations.append(f"approval_rule must be UNANIMOUS (got {receipt.get('approval_rule')!r})")
    if receipt.get("ratifiers_required") != EXPECTED_RATIFIERS:
        violations.append(f"ratifiers_required must be {EXPECTED_RATIFIERS}")
    if receipt.get("blocking_issues") != 0:
        violations.append("blocking_issues must be 0")
    if receipt.get("decision") != "RATIFIED":
        violations.append("decision must be RATIFIED")

    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not receipt_id:
        violations.append("receipt_id is required")

    # RC ID / version / bundle hash uniform across the receipt and the
    # RC bundle.
    rc_id = rc_bundle.get("release_candidate_id")
    rc_version = rc_bundle.get("release_candidate_version")
    rc_hash = rc_bundle.get("bundle_sha256")

    for key, expected in (
        ("release_candidate_id", rc_id),
        ("release_candidate_version", rc_version),
        ("bundle_sha256", rc_hash),
    ):
        if receipt.get(key) != expected:
            violations.append(f"receipt {key} does not match rc_bundle")

    # Ratifier records (input)
    if len(ratifier_records) != EXPECTED_RATIFIERS:
        violations.append(
            f"ratifier_records must contain exactly {EXPECTED_RATIFIERS} items "
            f"(got {len(ratifier_records)})"
        )

    ratifier_ids: list[str] = []
    approved_count = 0
    for i, record in enumerate(ratifier_records):
        if record.get("decision") != "APPROVE":
            violations.append(f"ratifier[{i}]: decision must be APPROVE")
        else:
            approved_count += 1
        for key, expected in (
            ("release_candidate_id", rc_id),
            ("release_candidate_version", rc_version),
            ("bundle_sha256", rc_hash),
        ):
            if record.get(key) != expected:
                violations.append(f"ratifier[{i}]: {key} mismatch")
        rid = record.get("ratifier_id")
        if not isinstance(rid, str) or not rid:
            violations.append(f"ratifier[{i}]: ratifier_id missing")
        else:
            ratifier_ids.append(rid)

        approved_at_val = record.get("approved_at")
        if not isinstance(approved_at_val, str):
            violations.append(f"ratifier[{i}]: approved_at is required")

    distinct_ids = set(ratifier_ids)
    if len(distinct_ids) != EXPECTED_RATIFIERS:
        violations.append(
            f"ratifier_ids must be distinct (got {len(distinct_ids)} "
            f"distinct of {len(ratifier_ids)})"
        )

    receipt_records = receipt.get("ratifiers")
    if not isinstance(receipt_records, list) or len(receipt_records) != EXPECTED_RATIFIERS:
        violations.append("receipt.ratifiers must contain exactly 4 items")
    else:
        receipt_record_mappings = [r for r in receipt_records if isinstance(r, Mapping)]
        if not _records_deep_equal(ratifier_records, receipt_record_mappings):
            violations.append("receipt ratifier records must deep-equal source records")

    declared_approved = receipt.get("ratifiers_approved")
    if declared_approved != approved_count:
        violations.append(
            f"ratifiers_approved ({declared_approved}) does not match "
            f"computed approved count ({approved_count})"
        )

    declared_hash = receipt.get("receipt_sha256")
    computed_hash = compute_receipt_sha256(receipt)
    if not isinstance(declared_hash, str) or not declared_hash:
        violations.append("receipt_sha256 is required")
    elif declared_hash != computed_hash:
        violations.append("receipt_sha256 mismatch (computed hash disagrees)")

    return RatificationReport(
        ok=not violations,
        violations=tuple(violations),
        receipt_sha256=computed_hash,
    )


def invalidate_on_change(
    *,
    receipt: Mapping[str, object],
    new_rc_hash: str | None = None,
    new_rc_version: str | None = None,
) -> bool:
    """Return True if the existing receipt is invalidated by a new hash/version."""
    if new_rc_hash is not None and new_rc_hash != receipt.get("bundle_sha256"):
        return True
    if new_rc_version is not None and new_rc_version != receipt.get("release_candidate_version"):
        return True
    return False


__all__ = [
    "EXPECTED_RATIFIERS",
    "RatificationReport",
    "canonical_receipt_bytes",
    "compute_receipt_sha256",
    "invalidate_on_change",
    "validate_ratification",
]
