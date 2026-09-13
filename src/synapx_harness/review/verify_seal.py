"""Verify-Seal — full revalidation of a sealed R7 package.

Performs, in order:
  1. ZIP SHA-256 recomputation
  2. Structural verify
  3. Semantic verify
  4. Internal review index hash chain re-hash
  5. Candidate state hash re-hash
  6. Phase derivation (server-side, not CLI)
  7. SCM commit/tree/snapshot triple consistency
  8. Receipt vs internal gate comparison
  9. Terminal verdict recomputation

Existence-only checks of candidate_state file are FORBIDDEN; the
content of every gate is re-evaluated.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.review.candidate_state import (
    verify_candidate_state_consistency,
)
from synapx_harness.review.review_phase_contract import PHASE
from synapx_harness.review.semantic_verifier import verify_review_package_bytes
from synapx_harness.review.terminal_seal import (
    compute_terminal_seal,
    read_internal_terminal_state,
)


@dataclass(frozen=True)
class VerifySealResult:
    ok: bool
    zip_sha256: str
    structural_verify: str
    semantic_verify: str
    seal_verify: str
    terminal_candidate_gate: str
    stage_failures: tuple[str, ...] = field(default_factory=tuple)
    checks: dict[str, dict[str, object]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "zip_sha256": self.zip_sha256,
            "structural_verify": self.structural_verify,
            "semantic_verify": self.semantic_verify,
            "seal_verify": self.seal_verify,
            "terminal_candidate_gate": self.terminal_candidate_gate,
            "stage_failures": list(self.stage_failures),
            "checks": dict(self.checks),
        }


def _read_json_member(zf: zipfile.ZipFile, name: str) -> dict[str, object] | None:
    if name not in zf.namelist():
        return None
    try:
        return json.loads(zf.read(name).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def verify_seal(
    *,
    zip_path: Path,
    receipt: Mapping[str, object],
) -> VerifySealResult:
    """Full revalidation of a sealed R7 package against its receipt."""
    stage_failures: list[str] = []
    checks: dict[str, dict[str, object]] = {}

    if not zip_path.is_file():
        return VerifySealResult(
            ok=False,
            zip_sha256="",
            structural_verify="FAIL",
            semantic_verify="FAIL",
            seal_verify="FAIL",
            terminal_candidate_gate="FAIL",
            stage_failures=("zip file not found",),
        )

    zip_bytes = zip_path.read_bytes()
    zip_sha = hashlib.sha256(zip_bytes).hexdigest()

    # 1. ZIP SHA match
    expected_zip_sha = str(receipt.get("zip_sha256", ""))
    if zip_sha != expected_zip_sha:
        stage_failures.append("zip_sha256_mismatch")
    checks["zip_sha256"] = {"actual": zip_sha, "expected": expected_zip_sha}

    # 2 + 3. Structural + Semantic
    semantic = verify_review_package_bytes(zip_bytes)
    structural_ok = semantic.package_structural_gate == "PASS"
    semantic_ok = semantic.package_semantic_gate == "PASS"
    if not structural_ok:
        stage_failures.append("structural_verify_failed")
    if not semantic_ok:
        stage_failures.append("semantic_verify_failed")
    checks["structural_verify"] = {
        "actual": semantic.package_structural_gate,
        "expected": "PASS",
        "match": structural_ok,
    }
    checks["semantic_verify"] = {
        "actual": semantic.package_semantic_gate,
        "expected": "PASS",
        "match": semantic_ok,
    }

    # 4. Internal review index hash chain
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        idx_data = _read_json_member(zf, "review/internal_review_index.json")
        if idx_data is None:
            stage_failures.append("internal_review_index_missing")
        else:
            from synapx_harness.review.internal_review_index import (
                REQUIRED_FIELDS as _IDX_RF,
            )
            from synapx_harness.review.internal_review_index import (
                InternalReviewIndex,
            )

            idx = InternalReviewIndex(
                phase=str(idx_data["phase"]),
                hashes={k: str(idx_data.get(k, "")) for k in _IDX_RF},
                hash_chain_sha256=str(idx_data.get("hash_chain_sha256", "")),
            )
            for key, declared in idx.hashes.items():
                # Path mapping is the same as in semantic_verifier
                target = _idx_key_to_path(key)
                if not target or target not in zf.namelist():
                    stage_failures.append(f"internal_index_target_missing:{key}")
                    continue
                actual = hashlib.sha256(zf.read(target)).hexdigest()
                if actual != declared:
                    stage_failures.append(f"internal_index_hash_mismatch:{key}")
            chain_declared = idx_data.get("hash_chain_sha256", "")
            if chain_declared:
                payload = {"phase": idx.phase}
                for k in _IDX_RF:
                    payload[k] = idx.hashes[k]
                chain_actual = hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest()
                if chain_actual != chain_declared:
                    stage_failures.append("internal_index_chain_mismatch")

        # 5. Candidate state hash
        state = _read_json_member(zf, "review/review_candidate_state.json")
        declared_state_sha = str(receipt.get("review_candidate_state_sha256", ""))
        if state is None:
            stage_failures.append("candidate_state_missing")
            actual_state_sha = ""
        else:
            state_raw = zf.read("review/review_candidate_state.json")
            actual_state_sha = hashlib.sha256(state_raw).hexdigest()
        if state is not None and declared_state_sha and actual_state_sha != declared_state_sha:
            stage_failures.append("candidate_state_hash_mismatch_receipt")
        checks["candidate_state_hash"] = {
            "actual": actual_state_sha,
            "expected": declared_state_sha,
            "match": actual_state_sha == declared_state_sha,
        }

        # 6. Phase derivation
        derived_phase = str(state.get("phase", "")) if state else ""
        receipt_phase = str(receipt.get("phase", ""))
        checks["phase"] = {
            "actual": derived_phase,
            "expected": str(receipt.get("phase", "")),
        }
        if derived_phase != PHASE:
            stage_failures.append("candidate_phase_mismatch")
        if receipt_phase != PHASE:
            stage_failures.append("receipt_phase_mismatch")
        if derived_phase != receipt_phase:
            stage_failures.append("candidate_receipt_phase_mismatch")

        # 7. SCM commit/tree/snapshot triple
        for repo_key, manifest_key in (
            ("review/scm/core_repository.json", "review/scm/core_snapshot_manifest.json"),
            (
                "review/scm/service_pack_repository.json",
                "review/scm/service_pack_snapshot_manifest.json",
            ),
        ):
            scm = _read_json_member(zf, repo_key)
            manifest = _read_json_member(zf, manifest_key)
            if scm is None or manifest is None:
                stage_failures.append(f"scm_missing:{repo_key}")
                continue
            if scm.get("commit_sha") != manifest.get("commit_sha"):
                stage_failures.append(f"scm_commit_mismatch:{repo_key}")
            if scm.get("tree_sha") != manifest.get("tree_sha"):
                stage_failures.append(f"scm_tree_mismatch:{repo_key}")

        # 8. Receipt vs internal gate comparison
        decision = _read_json_member(zf, "review/review_decision.json")
        gate_summary = _read_json_member(zf, "review/gate_summary.json")
        if state and decision and gate_summary:
            ok, cv = verify_candidate_state_consistency(state, gate_summary, decision)
            if not ok:
                stage_failures.append("candidate_state_contradiction")
                checks["candidate_state_consistency"] = {"violations": cv}

        # 9. Terminal verdict recomputation
        if state and decision:
            pkg = {
                "review_candidate_state": state,
                "gate_summary": gate_summary or {},
                "review_decision": decision,
                "structural": semantic.package_structural_gate,
                "semantic": semantic.package_semantic_gate,
                "package_structural_gate": semantic.package_structural_gate,
                "package_semantic_gate": semantic.package_semantic_gate,
                "structural_ok": structural_ok,
                "semantic_ok": semantic_ok,
            }
            internal_state = read_internal_terminal_state(pkg)
            seal = compute_terminal_seal(internal_state)
            terminal = seal["terminal_candidate_gate"]
            receipt_terminal = str(receipt.get("terminal_candidate_gate", ""))
            if receipt_terminal and receipt_terminal != terminal:
                stage_failures.append("terminal_verdict_mismatch")
            checks["terminal_candidate_gate"] = {
                "actual": terminal,
                "expected": receipt_terminal,
                "match": receipt_terminal == terminal,
            }
        else:
            terminal = "FAIL"
            stage_failures.append("terminal_state_incomplete")

    seal_verify = "PASS" if not stage_failures else "FAIL"
    ok = zip_sha == expected_zip_sha and structural_ok and semantic_ok and not stage_failures
    return VerifySealResult(
        ok=ok,
        zip_sha256=zip_sha,
        structural_verify=semantic.package_structural_gate,
        semantic_verify=semantic.package_semantic_gate,
        seal_verify=seal_verify,
        terminal_candidate_gate=str(terminal),
        stage_failures=tuple(stage_failures),
        checks=checks,
    )


def _idx_key_to_path(key: str) -> str | None:
    mapping = {
        "review_candidate_state_sha256": "review/review_candidate_state.json",
        "review_report_sha256": "review/review_report.md",
        "verification_summary_sha256": "review/verification_summary.json",
        "gate_summary_sha256": "review/gate_summary.json",
        "review_decision_sha256": "review/review_decision.json",
        "review_location_receipt_sha256": "review/review_location_receipt.json",
        "core_scm_provenance_sha256": "review/scm/core_repository.json",
        "core_snapshot_manifest_sha256": "review/scm/core_snapshot_manifest.json",
        "service_pack_scm_provenance_sha256": "review/scm/service_pack_repository.json",
        "service_pack_snapshot_manifest_sha256": "review/scm/service_pack_snapshot_manifest.json",
        "test_evidence_manifest_sha256": "review/test_evidence_manifest.json",
        "command_evidence_manifest_sha256": "review/command_evidence_manifest.json",
        "negative_exploit_matrix_sha256": "review/negative_exploit_matrix.json",
    }
    return mapping.get(key)


__all__ = ["VerifySealResult", "verify_seal"]
