"""Two-stage Terminal Seal (R7).

The R7 seal:
  - reads the phase from the package's review_candidate_state.json
    (NOT from CLI)
  - reads every internal gate from the package's gate_summary.json
  - reads candidate_status / independent_review / p3_authorized
    from the package's review_candidate_state.json
  - does NOT accept any external CLI value as authoritative
  - emits an external receipt whose SHA-256 derives from the
    package contents

External CLI values may be supplied for comparison purposes only;
mismatches are reported but do not flip the verdict.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from synapx_harness.review.review_phase_contract import (
    GATE_FAIL,
    GATE_PASS,
    PHASE,
)


@dataclass(frozen=True)
class InternalTerminalState:
    phase: str
    structural_pass: bool
    semantic_pass: bool
    candidate_status: str
    independent_review: str
    p3_authorized: bool
    gate_summary: dict[str, object]
    candidate_state: dict[str, object]

    @property
    def phase_matches_contract(self) -> bool:
        return self.phase == PHASE


def read_internal_terminal_state(pkg: Mapping[str, object]) -> InternalTerminalState:
    """Derive the R7 terminal state from the parsed package contents."""
    state_raw = pkg["review_candidate_state"]
    gate_summary_raw = pkg["gate_summary"]
    structural = pkg["structural"]
    semantic = pkg["semantic"]
    state = state_raw if isinstance(state_raw, dict) else {}
    gate_summary = gate_summary_raw if isinstance(gate_summary_raw, dict) else {}

    candidate_status = str(state.get("candidate_status", ""))
    independent_review = str(state.get("independent_review", ""))
    p3_authorized = bool(state.get("p3_authorized", False))
    phase = str(state.get("phase", ""))

    structural_pass = (
        bool(pkg.get("package_structural_gate", "") == GATE_PASS)
        if isinstance(pkg.get("package_structural_gate"), str)
        else False
    )
    semantic_pass = (
        bool(pkg.get("package_semantic_gate", "") == GATE_PASS)
        if isinstance(pkg.get("package_semantic_gate"), str)
        else False
    )
    if not isinstance(structural, str):
        # structural passed key
        structural_pass = pkg.get("structural_ok", False) is True
    if not isinstance(semantic, str):
        semantic_pass = pkg.get("semantic_ok", False) is True

    return InternalTerminalState(
        phase=phase,
        structural_pass=structural_pass,
        semantic_pass=semantic_pass,
        candidate_status=candidate_status,
        independent_review=independent_review,
        p3_authorized=p3_authorized,
        gate_summary=dict(gate_summary),
        candidate_state=dict(state),
    )


def compute_terminal_seal(state: InternalTerminalState) -> dict[str, object]:
    """Compute the R7 terminal verdict from the package-derived state."""
    all_internal_pass = (
        state.structural_pass
        and state.semantic_pass
        and state.candidate_status == "READY_FOR_INDEPENDENT_REVIEW"
        and state.independent_review == "PENDING"
        and not state.p3_authorized
        and state.phase_matches_contract
    )
    terminal_candidate_gate = GATE_PASS if all_internal_pass else GATE_FAIL
    return {
        "phase": state.phase,
        "terminal_candidate_gate": terminal_candidate_gate,
        "candidate_status": state.candidate_status,
        "independent_review": state.independent_review,
        "p3_authorized": state.p3_authorized,
        "structural_pass": state.structural_pass,
        "semantic_pass": state.semantic_pass,
        "phase_matches_contract": state.phase_matches_contract,
        "decided_at": _dt.datetime.now(_dt.UTC).isoformat(),
    }


def build_external_seal_receipt(
    *,
    internal_seal: Mapping[str, object],
    zip_filename: str,
    zip_sha256: str,
    internal_review_index_sha256: str,
    payload_manifest_sha256: str,
    review_candidate_state_sha256: str,
    review_report_sha256: str,
    verification_summary_sha256: str,
    gate_summary_sha256: str,
    core_commit_sha: str,
    core_tree_sha: str,
    pack_commit_sha: str,
    pack_tree_sha: str,
    expected_phase: str | None = None,
    expected_implementation_gate: str | None = None,
    expected_independent_review: str | None = None,
    expected_p3_authorized: bool | None = None,
) -> dict[str, object]:
    """Build the external receipt.

    External CLI inputs (``expected_*``) are compared-only and never
    authoritative. They are recorded in the receipt solely so an
    independent reviewer can confirm the CLI was consistent with the
    package contents.
    """
    receipt_phase = str(internal_seal["phase"])
    terminal_gate = str(internal_seal["terminal_candidate_gate"])
    receipt = {
        "phase": receipt_phase,
        "terminal_candidate_gate": terminal_gate,
        "candidate_status": str(internal_seal["candidate_status"]),
        "independent_review": str(internal_seal["independent_review"]),
        "p3_authorized": bool(internal_seal["p3_authorized"]),
        "zip_filename": zip_filename,
        "zip_sha256": zip_sha256,
        "payload_manifest_sha256": payload_manifest_sha256,
        "internal_review_index_sha256": internal_review_index_sha256,
        "review_candidate_state_sha256": review_candidate_state_sha256,
        "review_report_sha256": review_report_sha256,
        "verification_summary_sha256": verification_summary_sha256,
        "gate_summary_sha256": gate_summary_sha256,
        "core_commit_sha": core_commit_sha,
        "core_tree_sha": core_tree_sha,
        "pack_commit_sha": pack_commit_sha,
        "pack_tree_sha": pack_tree_sha,
        "structural_pass": bool(internal_seal["structural_pass"]),
        "semantic_pass": bool(internal_seal["semantic_pass"]),
        "phase_matches_contract": bool(internal_seal["phase_matches_contract"]),
        "decided_at": str(internal_seal["decided_at"]),
    }
    if expected_phase is not None:
        receipt["expected_phase"] = expected_phase
        receipt["phase_compare_match"] = receipt_phase == expected_phase
    if expected_implementation_gate is not None:
        receipt["expected_implementation_gate"] = expected_implementation_gate
        receipt["implementation_gate_compare_match"] = terminal_gate == expected_implementation_gate
    if expected_independent_review is not None:
        receipt["expected_independent_review"] = expected_independent_review
        receipt["independent_review_compare_match"] = (
            str(internal_seal["independent_review"]) == expected_independent_review
        )
    if expected_p3_authorized is not None:
        receipt["expected_p3_authorized"] = expected_p3_authorized
        receipt["p3_authorized_compare_match"] = (
            bool(internal_seal["p3_authorized"]) == expected_p3_authorized
        )
    return receipt


def receipt_sha256(receipt: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


_HEX64 = __import__("re").compile(r"^[0-9a-f]{64}$")


def write_zip_sha256_sidecar(zip_path: Path) -> Path:
    """Write a SHA-256 sidecar next to ``zip_path`` containing the real hash.

    The sidecar format is the canonical ``<hash>  <filename>`` form used
    by ``sha256sum``. The hash is computed from the actual ZIP bytes
    (never from a shell expression). The filename in the sidecar is the
    bare ``zip_path.name`` (no absolute path).

    Returns the sidecar path. Raises :class:`ValueError` if any
    post-write invariant fails (CR4 strict guard).
    """
    from pathlib import Path as _Path

    zip_path = _Path(zip_path)
    if not zip_path.is_file():
        raise FileNotFoundError(f"zip not found: {zip_path}")
    raw = zip_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not _HEX64.match(digest):
        raise ValueError(f"computed zip hash not 64-hex: {digest!r}")
    sidecar_path = zip_path.with_name(zip_path.name + ".sha256")
    sidecar_text = f"{digest}  {zip_path.name}\n"
    sidecar_path.write_text(sidecar_text, encoding="ascii")
    parsed_hash, parsed_name = parse_zip_sha256_sidecar(sidecar_path)
    if parsed_hash != digest:
        raise ValueError(
            f"sidecar hash mismatch: parsed={parsed_hash} computed={digest}"
        )
    if parsed_name != zip_path.name:
        raise ValueError(
            f"sidecar filename mismatch: parsed={parsed_name!r} actual={zip_path.name!r}"
        )
    if digest == "a" * 64:
        raise ValueError("sidecar hash is the placeholder a*64")
    return sidecar_path


def parse_zip_sha256_sidecar(sidecar_path: Path) -> tuple[str, str]:
    """Parse a sha256 sidecar produced by :func:`write_zip_sha256_sidecar`.

    Returns ``(hash, filename)``. The hash MUST be 64 lowercase hex
    characters; the filename MUST be the bare basename (no path
    separators, no absolute path, no backslash, no ``..``).
    """
    import re as _re

    sidecar_path = Path(sidecar_path)
    if not sidecar_path.is_file():
        raise FileNotFoundError(f"sidecar not found: {sidecar_path}")
    text = sidecar_path.read_text(encoding="ascii")
    tokens = text.strip().split()
    if len(tokens) < 2:
        raise ValueError(f"sidecar malformed (need at least 2 tokens): {text!r}")
    digest = tokens[0]
    filename = tokens[1]
    if not _HEX64.match(digest):
        raise ValueError(f"sidecar hash not 64-hex: {digest!r}")
    if digest == "a" * 64:
        raise ValueError("sidecar hash is the placeholder a*64")
    if "\\" in filename or "/" in filename:
        raise ValueError(f"sidecar filename contains path separator: {filename!r}")
    if Path(filename).is_absolute():
        raise ValueError(f"sidecar filename is absolute: {filename!r}")
    if filename != Path(filename).name:
        raise ValueError(f"sidecar filename is not bare basename: {filename!r}")
    if _re.search(r"[<>|&;`$\\\"']", text):
        raise ValueError(f"sidecar contains shell metacharacters: {text!r}")
    return digest, filename


__all__ = [
    "InternalTerminalState",
    "build_external_seal_receipt",
    "compute_terminal_seal",
    "parse_zip_sha256_sidecar",
    "read_internal_terminal_state",
    "receipt_sha256",
    "write_zip_sha256_sidecar",
]
