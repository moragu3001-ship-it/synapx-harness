"""Two-stage Terminal Seal.

The R3 package has two terminal anchors:

  1. :class:`InternalReviewIndex` lives inside the ZIP. It binds the
     review artefact hashes and excludes the final ZIP SHA to avoid
     self-reference.

  2. :class:`ExternalTerminalReceipt` lives outside the ZIP. It is
     computed only after the ZIP is sealed. It contains the SHA-256 of
     ``InternalReviewIndex`` plus every component hash so the final
     audit can recompute any link independently.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass

REQUIRED_INTERNAL_INDEX_KEYS: tuple[str, ...] = (
    "phase",
    "review_report_sha256",
    "verification_summary_sha256",
    "gate_summary_sha256",
    "core_scm_provenance_sha256",
    "service_pack_scm_provenance_sha256",
    "test_evidence_manifest_sha256",
    "command_evidence_manifest_sha256",
)


@dataclass(frozen=True)
class InternalReviewIndex:
    phase: str
    review_report_sha256: str
    verification_summary_sha256: str
    gate_summary_sha256: str
    core_scm_provenance_sha256: str
    service_pack_scm_provenance_sha256: str
    test_evidence_manifest_sha256: str
    command_evidence_manifest_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "review_report_sha256": self.review_report_sha256,
            "verification_summary_sha256": self.verification_summary_sha256,
            "gate_summary_sha256": self.gate_summary_sha256,
            "core_scm_provenance_sha256": self.core_scm_provenance_sha256,
            "service_pack_scm_provenance_sha256": self.service_pack_scm_provenance_sha256,
            "test_evidence_manifest_sha256": self.test_evidence_manifest_sha256,
            "command_evidence_manifest_sha256": self.command_evidence_manifest_sha256,
        }


@dataclass(frozen=True)
class ExternalTerminalReceipt:
    phase: str
    zip_filename: str
    zip_sha256: str
    payload_manifest_sha256: str
    internal_review_index_sha256: str
    review_candidate_state_sha256: str
    review_report_sha256: str
    verification_summary_sha256: str
    gate_summary_sha256: str
    core_commit_sha: str
    core_tree_sha: str
    pack_commit_sha: str
    pack_tree_sha: str
    implementation_gate: str
    independent_review: str
    p3_authorized: bool
    terminal_gate: str

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "zip_filename": self.zip_filename,
            "zip_sha256": self.zip_sha256,
            "payload_manifest_sha256": self.payload_manifest_sha256,
            "internal_review_index_sha256": self.internal_review_index_sha256,
            "review_candidate_state_sha256": self.review_candidate_state_sha256,
            "review_report_sha256": self.review_report_sha256,
            "verification_summary_sha256": self.verification_summary_sha256,
            "gate_summary_sha256": self.gate_summary_sha256,
            "core_commit_sha": self.core_commit_sha,
            "core_tree_sha": self.core_tree_sha,
            "pack_commit_sha": self.pack_commit_sha,
            "pack_tree_sha": self.pack_tree_sha,
            "implementation_gate": self.implementation_gate,
            "independent_review": self.independent_review,
            "p3_authorized": self.p3_authorized,
            "terminal_gate": self.terminal_gate,
        }


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_json(obj: Mapping[str, object]) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hash_text(payload)


def build_internal_review_index(
    *,
    phase: str,
    review_report_sha256: str,
    verification_summary_sha256: str,
    gate_summary_sha256: str,
    core_scm_provenance_sha256: str,
    service_pack_scm_provenance_sha256: str,
    test_evidence_manifest_sha256: str,
    command_evidence_manifest_sha256: str,
) -> InternalReviewIndex:
    return InternalReviewIndex(
        phase=phase,
        review_report_sha256=review_report_sha256,
        verification_summary_sha256=verification_summary_sha256,
        gate_summary_sha256=gate_summary_sha256,
        core_scm_provenance_sha256=core_scm_provenance_sha256,
        service_pack_scm_provenance_sha256=service_pack_scm_provenance_sha256,
        test_evidence_manifest_sha256=test_evidence_manifest_sha256,
        command_evidence_manifest_sha256=command_evidence_manifest_sha256,
    )


def build_external_terminal_receipt(
    *,
    phase: str,
    zip_filename: str,
    zip_sha256: str,
    payload_manifest_sha256: str,
    internal_review_index_sha256: str,
    review_candidate_state_sha256: str,
    review_report_sha256: str,
    verification_summary_sha256: str,
    gate_summary_sha256: str,
    core_commit_sha: str,
    core_tree_sha: str,
    pack_commit_sha: str,
    pack_tree_sha: str,
    implementation_gate: str,
    independent_review: str,
    p3_authorized: bool,
    terminal_gate: str,
) -> ExternalTerminalReceipt:
    return ExternalTerminalReceipt(
        phase=phase,
        zip_filename=zip_filename,
        zip_sha256=zip_sha256,
        payload_manifest_sha256=payload_manifest_sha256,
        internal_review_index_sha256=internal_review_index_sha256,
        review_candidate_state_sha256=review_candidate_state_sha256,
        review_report_sha256=review_report_sha256,
        verification_summary_sha256=verification_summary_sha256,
        gate_summary_sha256=gate_summary_sha256,
        core_commit_sha=core_commit_sha,
        core_tree_sha=core_tree_sha,
        pack_commit_sha=pack_commit_sha,
        pack_tree_sha=pack_tree_sha,
        implementation_gate=implementation_gate,
        independent_review=independent_review,
        p3_authorized=p3_authorized,
        terminal_gate=terminal_gate,
    )


__all__ = [
    "ExternalTerminalReceipt",
    "InternalReviewIndex",
    "REQUIRED_INTERNAL_INDEX_KEYS",
    "build_external_terminal_receipt",
    "build_internal_review_index",
    "hash_bytes",
    "hash_json",
    "hash_text",
]
