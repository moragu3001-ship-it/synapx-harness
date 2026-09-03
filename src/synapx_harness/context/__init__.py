"""Lane C — Minimum Shared Understanding (FACT/ASSERTION/UNKNOWN).

Provider-neutral canonical context producer: deterministic repository
scanner, strict classification models, bounded renderer, evidence
metadata truth helpers.
"""
from synapx_harness.context.evidence_meta import (
    find_chronology_inversions,
    has_placeholder,
    is_future_timestamp,
    now_utc,
    parse_timestamp,
)
from synapx_harness.context.models import (
    AssertionRecord,
    FactRecord,
    JsonScalar,
    JsonValue,
    RepositoryBinding,
    SharedUnderstandingContext,
    UnknownRecord,
)
from synapx_harness.context.renderer import render_text, to_canonical_json
from synapx_harness.context.scanner import (
    DeterministicRepositoryScanner,
    ScannerOptions,
    scan_repository,
)

__all__ = [
    "AssertionRecord",
    "DeterministicRepositoryScanner",
    "FactRecord",
    "JsonScalar",
    "JsonValue",
    "RepositoryBinding",
    "ScannerOptions",
    "SharedUnderstandingContext",
    "UnknownRecord",
    "find_chronology_inversions",
    "has_placeholder",
    "is_future_timestamp",
    "now_utc",
    "parse_timestamp",
    "render_text",
    "scan_repository",
    "to_canonical_json",
]
