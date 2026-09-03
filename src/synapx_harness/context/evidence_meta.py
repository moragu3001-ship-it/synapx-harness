"""Lane C R1 — Evidence metadata truth helpers.

Closes FUTURE_EVIDENCE_TIMESTAMP (P1-03):
  - ``now_utc`` captures the actual UTC moment (no hard-coded times)
  - ``parse_timestamp`` rejects non-ISO / naive timestamps
  - ``is_future_timestamp`` rejects timestamps ahead of the reference
  - ``find_chronology_inversions`` rejects evidence ordering inversions
  - ``has_placeholder`` detects unwritten placeholder timestamps
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

FUTURE_SLACK_SECONDS = 5.0

PLACEHOLDER_MARKERS = (
    "YYYY-MM-DD",
    "TBD",
    "TODO",
    "REPLACE",
    "PLACEHOLDER",
    "__RECORDED_AT__",
)


def now_utc() -> str:
    """Capture the current UTC moment (ISO-8601, aware, second precision)."""
    return datetime.now(UTC).isoformat(timespec="seconds")


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 aware timestamp; reject garbage and naive input."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            f"timestamp is not ISO-8601 parseable: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise ValueError(
            f"timestamp must be timezone-aware (UTC): {value!r}"
        )
    return parsed.astimezone(UTC)


def is_future_timestamp(
    value: str, *, reference: datetime | None = None
) -> bool:
    """True when ``value`` is ahead of the reference (future evidence)."""
    ref = reference or datetime.now(UTC)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=UTC)
    return parse_timestamp(value) > ref + timedelta(
        seconds=FUTURE_SLACK_SECONDS
    )


def find_chronology_inversions(
    records: list[tuple[str, str]],
) -> list[str]:
    """Return descriptions of chronology inversions (later < earlier).

    ``records`` is an ordered sequence of ``(name, timestamp)`` pairs in
    the canonical evidence order. An inversion is a pair where a later
    record's timestamp precedes an earlier record's timestamp.
    """
    parsed: list[tuple[str, datetime]] = [
        (name, parse_timestamp(raw)) for name, raw in records
    ]
    inversions: list[str] = []
    for index in range(1, len(parsed)):
        prev_name, prev_ts = parsed[index - 1]
        name, ts = parsed[index]
        if ts < prev_ts:
            inversions.append(
                f"{name} ({ts.isoformat()}) precedes "
                f"{prev_name} ({prev_ts.isoformat()})"
            )
    return inversions


def has_placeholder(value: str) -> bool:
    """True when the value still contains an unwritten placeholder."""
    return any(marker in value for marker in PLACEHOLDER_MARKERS)


__all__ = [
    "FUTURE_SLACK_SECONDS",
    "PLACEHOLDER_MARKERS",
    "find_chronology_inversions",
    "has_placeholder",
    "is_future_timestamp",
    "now_utc",
    "parse_timestamp",
]
