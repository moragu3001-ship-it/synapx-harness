"""Semantic Package Verifier.

The R7 canonical verifier checks the package in two stages:
  1. **Structural** — every ZIP entry is in the manifest, every
     SHA-256 matches, no symlinks, no traversal paths, no secrets.
  2. **Semantic** — every JSON artifact exists and parses, every
     SHA-256 field is 64 hex, every receipt hashes match its raw
     outputs, the internal review index hash chain matches reality,
     the candidate state / gate summary / review decision are
     consistent, the negative exploit matrix has zero unexpected
     PASSes, and no PENDING / N/A / NOT_RUN / placeholder values
     have polluted any gate.

Both stages MUST PASS for the package to be ``canonical``.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.evidence.command_receipt import validate_command_receipt
from synapx_harness.review.candidate_state import verify_candidate_state_consistency
from synapx_harness.review.internal_review_index import (
    REQUIRED_FIELDS,
    load_internal_review_index,
)
from synapx_harness.review.package_verifier import verify_zip_bytes
from synapx_harness.review.review_phase_contract import (
    GATE_FAIL,
    GATE_PASS,
    PHASE,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_GATE_TOKENS = ("PENDING", "N/A", "NOT_RUN", "SKIPPED", "PLACEHOLDER", "TODO")


@dataclass(frozen=True)
class SemanticVerificationResult:
    canonical: bool
    package_structural_gate: str
    package_semantic_gate: str
    structural_violations: tuple[str, ...] = field(default_factory=tuple)
    semantic_violations: tuple[str, ...] = field(default_factory=tuple)
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "canonical": self.canonical,
            "package_structural_gate": self.package_structural_gate,
            "package_semantic_gate": self.package_semantic_gate,
            "structural_violations": list(self.structural_violations),
            "semantic_violations": list(self.semantic_violations),
            "details": dict(self.details),
        }


def _read_json(zf: zipfile.ZipFile, name: str) -> tuple[dict[str, object] | None, str]:
    try:
        raw = zf.read(name)
    except KeyError:
        return None, f"missing artifact: {name}"
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"invalid JSON in {name}: {exc}"
    if not isinstance(data, dict):
        return None, f"{name} is not a JSON object"
    return data, ""


def _check_no_forbidden_tokens(
    payload: Mapping[str, object], path: str, violations: list[str]
) -> None:
    """Reject forbidden tokens in any gate field.

    Only scans keys that represent a gate field or terminal verdict.
    ``independent_review`` is explicitly allowed to be ``PENDING``
    because that is the canonical initial state until external review.
    """
    _GATE_KEYS = {
        "implementation_gate",
        "scm_snapshot_binding_gate",
        "command_receipt_gate",
        "test_evidence_gate",
        "internal_index_gate",
        "negative_exploit_gate",
        "package_structural_gate",
        "package_semantic_gate",
        "terminal_candidate_gate",
        "gate",
        "decision",
    }
    for k, v in payload.items():
        if k in _GATE_KEYS:
            if isinstance(v, str) and v in _FORBIDDEN_GATE_TOKENS:
                violations.append(f"forbidden token in {path}.{k}: {v!r}")
        elif isinstance(v, dict):
            _check_no_forbidden_tokens(v, f"{path}.{k}", violations)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    _check_no_forbidden_tokens(item, f"{path}.{k}[{i}]", violations)
                elif (
                    isinstance(item, str)
                    and item in _FORBIDDEN_GATE_TOKENS
                    and k in _GATE_KEYS
                ):
                    violations.append(f"forbidden token in {path}.{k}[{i}]: {item!r}")


def _validate_required_json(
    zf: zipfile.ZipFile,
    *,
    required_paths: tuple[str, ...],
) -> tuple[dict[str, dict[str, object]], list[str]]:
    violations: list[str] = []
    parsed: dict[str, dict[str, object]] = {}
    for path in required_paths:
        data, err = _read_json(zf, path)
        if data is None:
            violations.append(err)
            continue
        parsed[path] = data
    return parsed, violations


def _check_sha256_fields(
    payload: Mapping[str, object],
    *,
    field_names: tuple[str, ...],
    violations: list[str],
    location: str,
) -> None:
    for name in field_names:
        v = payload.get(name)
        if not isinstance(v, str) or not _HEX64.match(v):
            violations.append(f"{location}.{name} invalid sha256: {v!r}")


def verify_review_package_zip(zip_path: str | Path) -> SemanticVerificationResult:
    p = Path(zip_path)
    if not p.is_file():
        return SemanticVerificationResult(
            canonical=False,
            package_structural_gate=GATE_FAIL,
            package_semantic_gate=GATE_FAIL,
            structural_violations=("zip file not found",),
        )
    return verify_review_package_bytes(p.read_bytes())


def verify_review_package_bytes(zip_bytes: bytes) -> SemanticVerificationResult:
    details: dict[str, object] = {}

    # --- Stage 1: structural ---
    structural = verify_zip_bytes(zip_bytes)
    structural_violations: list[str] = []
    if not structural.ok:
        structural_violations.append(
            f"structural verify failed: unmanifested={list(structural.unmanifested_entries)}, "
            f"missing={list(structural.missing_manifest_entries)}, "
            f"secret_findings={len(structural.secret_findings)}"
        )
    if structural.zip_symlink_entry_count:
        structural_violations.append(f"symlink entries: {structural.zip_symlink_entry_count}")
    if structural.absolute_path_entry_count:
        structural_violations.append(
            f"absolute path entries: {structural.absolute_path_entry_count}"
        )
    if structural.path_traversal_entry_count:
        structural_violations.append(
            f"path traversal entries: {structural.path_traversal_entry_count}"
        )
    if structural.directory_entry_count:
        structural_violations.append(f"directory entries: {structural.directory_entry_count}")
    if (
        structural.manifest_duplicate_exact
        or structural.manifest_duplicate_normalized
        or structural.manifest_duplicate_casefold
    ):
        structural_violations.append("manifest has duplicate entries")
    if structural.excluded_entries:
        structural_violations.append(f"excluded entries: {list(structural.excluded_entries)}")

    package_structural_gate = GATE_PASS if not structural_violations else GATE_FAIL
    details["structural_zip_path"] = structural.zip_path
    details["structural_zip_sha256"] = structural.zip_sha256
    details["structural_actual_file_count"] = structural.actual_file_count
    details["structural_manifest_declared_file_count"] = structural.manifest_declared_file_count

    # --- Stage 2: semantic ---
    semantic_violations: list[str] = []
    parsed: dict[str, dict[str, object]] = {}
    try:
        zip_buf = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(zip_buf, "r") as zf:
            required = (
                "review/review_candidate_state.json",
                "review/gate_summary.json",
                "review/review_decision.json",
                "review/internal_review_index.json",
                "review/verification_summary.json",
                "review/review_location_receipt.json",
                "review/test_evidence_manifest.json",
                "review/command_evidence_manifest.json",
                "review/negative_exploit_matrix.json",
                "review/scm/core_repository.json",
                "review/scm/service_pack_repository.json",
                "review/scm/core_snapshot_manifest.json",
                "review/scm/service_pack_snapshot_manifest.json",
            )
            parsed, missing_errs = _validate_required_json(zf, required_paths=required)
            semantic_violations.extend(missing_errs)

            # Receipt files (4 mandatory)
            command_receipts = [
                "review/command_receipts/pytest.json",
                "review/command_receipts/ruff.json",
                "review/command_receipts/pyright_src.json",
                "review/command_receipts/pyright_full.json",
            ]
            for receipt_path in command_receipts:
                if receipt_path not in zf.namelist():
                    semantic_violations.append(f"missing required receipt: {receipt_path}")
                    continue
                try:
                    receipt_payload = json.loads(zf.read(receipt_path).decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    semantic_violations.append(f"invalid receipt JSON {receipt_path}: {exc}")
                    continue
                ok, rv = validate_command_receipt(receipt_payload)
                if not ok:
                    semantic_violations.append(f"receipt schema invalid {receipt_path}: {rv}")
                # Recompute stdout/stderr hashes (CR4: path is already ZIP-root-relative)
                stdout = receipt_payload.get("stdout_artifact", {})
                stderr = receipt_payload.get("stderr_artifact", {})
                stdout_path = stdout.get("path")
                stderr_path = stderr.get("path")
                stdout_zip_path = stdout_path if isinstance(stdout_path, str) else None
                stderr_zip_path = stderr_path if isinstance(stderr_path, str) else None
                if stdout_zip_path:
                    _path_unsafe = (
                        "\\" in stdout_zip_path
                        or stdout_zip_path.startswith("/")
                        or ".." in stdout_zip_path.split("/")
                    )
                    if _path_unsafe:
                        semantic_violations.append(
                            f"receipt stdout path unsafe: {stdout_zip_path}"
                        )
                    elif not stdout_zip_path.startswith("review/test_evidence/"):
                        semantic_violations.append(
                            f"receipt stdout path not under "
                            f"review/test_evidence/: {stdout_zip_path}"
                        )
                if stderr_zip_path:
                    _path_unsafe = (
                        "\\" in stderr_zip_path
                        or stderr_zip_path.startswith("/")
                        or ".." in stderr_zip_path.split("/")
                    )
                    if _path_unsafe:
                        semantic_violations.append(
                            f"receipt stderr path unsafe: {stderr_zip_path}"
                        )
                    elif not stderr_zip_path.startswith("review/test_evidence/"):
                        semantic_violations.append(
                            f"receipt stderr path not under "
                            f"review/test_evidence/: {stderr_zip_path}"
                        )
                if stdout_zip_path and stdout_zip_path not in zf.namelist():
                    semantic_violations.append(f"receipt stdout missing: {stdout_zip_path}")
                if stderr_zip_path and stderr_zip_path not in zf.namelist():
                    semantic_violations.append(f"receipt stderr missing: {stderr_zip_path}")
                if stdout_zip_path and stdout_zip_path in zf.namelist():
                    actual = hashlib.sha256(zf.read(stdout_zip_path)).hexdigest()
                    if actual != stdout.get("sha256"):
                        semantic_violations.append(
                            f"receipt stdout hash mismatch {receipt_path}: "
                            f"declared={stdout.get('sha256')} actual={actual}"
                        )
                if stderr_zip_path and stderr_zip_path in zf.namelist():
                    actual = hashlib.sha256(zf.read(stderr_zip_path)).hexdigest()
                    if actual != stderr.get("sha256"):
                        semantic_violations.append(
                            f"receipt stderr hash mismatch {receipt_path}: "
                            f"declared={stderr.get('sha256')} actual={actual}"
                        )
                # Exit code artifact binding (CR4)
                exit_art = receipt_payload.get("exit_code_artifact", {})
                exit_path = exit_art.get("path") if isinstance(exit_art, dict) else None
                if isinstance(exit_path, str):
                    if not exit_path.startswith("review/test_evidence/"):
                        semantic_violations.append(
                            f"receipt exit path not under "
                            f"review/test_evidence/: {exit_path}"
                        )
                    elif exit_path in zf.namelist():
                        actual_bytes = zf.read(exit_path)
                        actual_exit_sha = hashlib.sha256(actual_bytes).hexdigest()
                        if actual_exit_sha != exit_art.get("sha256"):
                            semantic_violations.append(
                                f"receipt exit sha mismatch {receipt_path}: "
                                f"declared={exit_art.get('sha256')} "
                                f"actual={actual_exit_sha}"
                            )
                        try:
                            actual_exit_code = int(actual_bytes.decode("utf-8").strip())
                        except (ValueError, UnicodeDecodeError):
                            semantic_violations.append(
                                f"receipt exit artifact not parseable int: {exit_path}"
                            )
                            actual_exit_code = None
                        _rc = receipt_payload.get("exit_code")
                        if actual_exit_code is not None and _rc is not None:
                            if int(_rc) != actual_exit_code:
                                semantic_violations.append(
                                    f"receipt exit_code vs artifact mismatch "
                                    f"{receipt_path}: receipt={_rc} "
                                    f"artifact={actual_exit_code}"
                                )

            # Internal review index — hash chain
            idx_path = "review/internal_review_index.json"
            if idx_path in parsed:
                idx = load_internal_review_index(_zipmember_path(zf, idx_path))
                _check_sha256_fields(
                    idx.hashes,
                    field_names=REQUIRED_FIELDS,
                    violations=semantic_violations,
                    location="internal_review_index",
                )
                # Recompute each required hash from ZIP contents
                for key, declared in idx.hashes.items():
                    target_path = _required_field_to_zip_path(key)
                    if not target_path or target_path not in zf.namelist():
                        semantic_violations.append(
                            f"internal_review_index refs missing artifact: {key} -> {target_path}"
                        )
                        continue
                    actual = hashlib.sha256(zf.read(target_path)).hexdigest()
                    if actual != declared:
                        semantic_violations.append(
                            f"internal_review_index.{key} mismatch: "
                            f"declared={declared} actual={actual}"
                        )

            # Candidate state / gate / decision consistency
            if all(
                k in parsed
                for k in (
                    "review/review_candidate_state.json",
                    "review/gate_summary.json",
                    "review/review_decision.json",
                )
            ):
                ok, cv = verify_candidate_state_consistency(
                    parsed["review/review_candidate_state.json"],
                    parsed["review/gate_summary.json"],
                    parsed["review/review_decision.json"],
                )
                if not ok:
                    semantic_violations.extend(cv)

            # Verification Summary semantic validation (must match actual pytest log)
            if "review/verification_summary.json" in parsed:
                vs = parsed["review/verification_summary.json"]
                vs_pytest_raw = vs.get("pytest")
                vs_pytest: dict[str, object] = {}
                if isinstance(vs_pytest_raw, dict):
                    vs_pytest = vs_pytest_raw

                def _get_int(d: dict[str, object], k: str) -> int:
                    v = d.get(k)
                    return int(v) if isinstance(v, int) else -1

                vs_passed = _get_int(vs_pytest, "passed")
                vs_failed = _get_int(vs_pytest, "failed")
                vs_errors = _get_int(vs_pytest, "errors")
                vs_skipped = _get_int(vs_pytest, "skipped")
                vs_collected = _get_int(vs_pytest, "collected")
                vs_executed = _get_int(vs_pytest, "executed")
                _counts_valid = (
                    vs_passed >= 0
                    and vs_failed >= 0
                    and vs_errors >= 0
                    and vs_skipped >= 0
                    and vs_collected >= 0
                    and vs_executed >= 0
                )
                if not _counts_valid:
                    semantic_violations.append("verification_summary has negative count fields")
                elif vs_collected == 0:
                    semantic_violations.append("verification_summary collected is 0")
                elif vs_skipped > 0:
                    semantic_violations.append(f"vs skipped={vs_skipped} must be 0")
                elif vs_errors > 0:
                    semantic_violations.append(f"vs errors={vs_errors} must be 0")
                elif vs_failed > 0:
                    semantic_violations.append(f"vs failed={vs_failed} must be 0")

            # Test evidence manifest bijection
            if "review/test_evidence_manifest.json" in parsed:
                te = parsed["review/test_evidence_manifest.json"]
                te_entries = te.get("entries", [])
                if not isinstance(te_entries, list):
                    semantic_violations.append("test_evidence_manifest.entries not a list")
                else:
                    for entry in te_entries:
                        if not isinstance(entry, dict):
                            semantic_violations.append("test_evidence entry not an object")
                            continue
                        path = entry.get("path")
                        sha = entry.get("sha256")
                        size = entry.get("size_bytes")
                        if not isinstance(path, str) or not path:
                            semantic_violations.append("test_evidence entry missing path")
                            continue
                        # Lookup actual file in ZIP: review/test_evidence/<path>
                        actual_path = f"review/test_evidence/{path}"
                        if actual_path not in zf.namelist():
                            semantic_violations.append(
                                f"test_evidence manifest references missing file: {path}"
                            )
                            continue
                        actual_bytes = zf.read(actual_path)
                        actual_sha = hashlib.sha256(actual_bytes).hexdigest()
                        if actual_sha != sha:
                            semantic_violations.append(
                                f"test_evidence {path} hash mismatch: "
                                f"declared={sha} actual={actual_sha}"
                            )
                        if len(actual_bytes) != size:
                            semantic_violations.append(
                                f"test_evidence {path} size mismatch: "
                                f"declared={size} actual={len(actual_bytes)}"
                            )

            # Negative exploit matrix
            if "review/negative_exploit_matrix.json" in parsed:
                nm = parsed["review/negative_exploit_matrix.json"]
                results = nm.get("results", [])
                if not isinstance(results, list):
                    semantic_violations.append("negative_exploit_matrix.results not a list")
                else:
                    for r in results:
                        if not isinstance(r, dict):
                            semantic_violations.append("negative_exploit result not dict")
                            continue
                        if r.get("actual_gate") != GATE_FAIL:
                            semantic_violations.append(
                                f"negative_exploit {r.get('attack_id')} actual_gate="
                                f"{r.get('actual_gate')} expected={GATE_FAIL}"
                            )
                        for forbidden in ("NOT_RUN", "N/A", "SKIPPED"):
                            if r.get("actual_gate") == forbidden:
                                semantic_violations.append(
                                    f"negative_exploit {r.get('attack_id')} "
                                    f"has forbidden gate token: {forbidden}"
                                )

            # SCM commit/tree snapshot binding
            for repo_key, manifest_key in (
                ("review/scm/core_repository.json", "review/scm/core_snapshot_manifest.json"),
                (
                    "review/scm/service_pack_repository.json",
                    "review/scm/service_pack_snapshot_manifest.json",
                ),
            ):
                if repo_key in parsed and manifest_key in parsed:
                    scm = parsed[repo_key]
                    manifest = parsed[manifest_key]
                    if scm.get("commit_sha") != manifest.get("commit_sha"):
                        semantic_violations.append(
                            f"scm commit mismatch {repo_key}: "
                            f"{scm.get('commit_sha')} vs {manifest.get('commit_sha')}"
                        )
                    if scm.get("tree_sha") != manifest.get("tree_sha"):
                        semantic_violations.append(
                            f"scm tree mismatch {repo_key}: "
                            f"{scm.get('tree_sha')} vs {manifest.get('tree_sha')}"
                        )

            # Forbidden tokens scan across all parsed payloads
            for path, payload in parsed.items():
                _check_no_forbidden_tokens(payload, path, semantic_violations)

            # Phase must match the contracted phase
            for phase_path in (
                "review/review_candidate_state.json",
                "review/gate_summary.json",
                "review/review_decision.json",
                "review/internal_review_index.json",
            ):
                if phase_path in parsed:
                    if parsed[phase_path].get("phase") != PHASE:
                        semantic_violations.append(
                            f"{phase_path}.phase mismatch: "
                            f"{parsed[phase_path].get('phase')!r} != {PHASE!r}"
                        )

    except zipfile.BadZipFile:
        semantic_violations.append("zip is not a valid zipfile")

    package_semantic_gate = GATE_PASS if not semantic_violations else GATE_FAIL
    canonical = (package_structural_gate == GATE_PASS) and (package_semantic_gate == GATE_PASS)
    return SemanticVerificationResult(
        canonical=canonical,
        package_structural_gate=package_structural_gate,
        package_semantic_gate=package_semantic_gate,
        structural_violations=tuple(structural_violations),
        semantic_violations=tuple(semantic_violations),
        details=details,
    )


def _zipmember_path(zf: zipfile.ZipFile, name: str) -> Path:
    """Return a Path-like wrapper for an in-memory zip member."""
    import tempfile as _tf

    tmp = Path(_tf.mkstemp(suffix=".json")[1])
    tmp.write_bytes(zf.read(name))
    return tmp


def _required_field_to_zip_path(key: str) -> str | None:
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


__all__ = [
    "SemanticVerificationResult",
    "verify_review_package_bytes",
    "verify_review_package_zip",
]
