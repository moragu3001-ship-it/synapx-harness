"""R7-CR4 Contract Tests for CR4 evidence-closure invariants."""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Task 3: Canonical Review Root / Build Location Gate
# ---------------------------------------------------------------------------

def test_build_review_location_rejects_noncanonical_base(tmp_path: Path) -> None:
    """Receipt MUST be rejected when review_root is not under D:\\project\\_review."""
    from synapx_harness.review.review_location_receipt import (
        build_review_location_receipt,
    )

    wrong_base = tmp_path / "wrong_base"
    review_dir = wrong_base / "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7-CR4" / "review"
    review_dir.mkdir(parents=True)
    (review_dir / "a.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="canonical review root gate failed"):
        build_review_location_receipt(
            phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7-CR4",
            review_root=review_dir,
            canonical_review_base=Path(r"D:\project\_review"),
        )


def test_build_review_location_rejects_duplicate_review_segment(tmp_path: Path) -> None:
    """Receipt MUST be rejected when review_root path contains duplicate _review."""
    from synapx_harness.review.review_location_receipt import (
        build_review_location_receipt,
    )

    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7-CR4"
    bad_root = tmp_path / "_review" / "_review" / phase / "review"
    bad_root.mkdir(parents=True)
    (bad_root / "a.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="canonical review root gate failed"):
        build_review_location_receipt(
            phase=phase,
            review_root=bad_root,
            canonical_review_base=tmp_path / "_review",
        )


def test_build_review_location_requires_exact_phase_review_path(tmp_path: Path) -> None:
    """Receipt MUST be rejected when review_root is not exactly <base>/<phase>/review."""
    from synapx_harness.review.review_location_receipt import (
        build_review_location_receipt,
    )

    phase = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7-CR4"
    canonical_base = tmp_path
    wrong_review = canonical_base / phase / "WRONGREVIEW"
    wrong_review.mkdir(parents=True)
    (wrong_review / "a.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="canonical review root gate failed"):
        build_review_location_receipt(
            phase=phase,
            review_root=wrong_review,
            canonical_review_base=canonical_base,
        )


# ---------------------------------------------------------------------------
# Task 5: ZIP SHA Sidecar
# ---------------------------------------------------------------------------

def test_zip_sha_sidecar_contains_actual_64_hex_hash(tmp_path: Path) -> None:
    """Sidecar MUST contain the actual 64-char lowercase hex SHA of the ZIP."""
    from synapx_harness.review.terminal_seal import write_zip_sha256_sidecar

    zip_path = tmp_path / "test.zip"
    zip_path.write_bytes(b"hello world")
    sidecar = write_zip_sha256_sidecar(zip_path)
    digest_from_sidecar, filename = sidecar.read_text(encoding="ascii").strip().split("  ")
    assert len(digest_from_sidecar) == 64
    assert digest_from_sidecar == hashlib.sha256(b"hello world").hexdigest()
    assert filename == "test.zip"


def test_zip_sha_sidecar_rejects_command_expression(tmp_path: Path) -> None:
    """Sidecar MUST NOT contain shell/PowerShell command expressions in filename."""
    from synapx_harness.review.terminal_seal import parse_zip_sha256_sidecar

    bad = tmp_path / "bad.sha256"
    real_hash = hashlib.sha256(b"hello world").hexdigest()
    bad.write_text(real_hash + "  $(echo injected).zip\n", encoding="ascii")
    with pytest.raises(ValueError, match="shell metacharacters"):
        parse_zip_sha256_sidecar(bad)


def test_zip_sha_sidecar_rejects_backslash_in_filename(tmp_path: Path) -> None:
    """Sidecar filename MUST be bare (no backslash)."""
    from synapx_harness.review.terminal_seal import parse_zip_sha256_sidecar

    bad = tmp_path / "bad.sha256"
    real_hash = hashlib.sha256(b"test").hexdigest()
    bad.write_text(real_hash + "  path\\to\\file.zip\n", encoding="ascii")
    with pytest.raises(ValueError, match="path separator"):
        parse_zip_sha256_sidecar(bad)


# ---------------------------------------------------------------------------
# Task 6: Snapshot Exact Set
# ---------------------------------------------------------------------------

def test_verify_snapshot_exact_set_detects_count_mismatch() -> None:
    """verify_snapshot_exact_set MUST fail when tracked != included + excluded."""
    from synapx_harness.review.git_snapshot import verify_snapshot_exact_set

    manifest = {
        "tracked_file_count": 10,
        "included_file_count": 5,
        "excluded_file_count": 4,
        "files": [
            {
                "repository_path": "a",
                "package_path": "p/a",
                "git_blob_sha": "a" * 40,
                "package_sha256": "b" * 64,
                "size_bytes": 1,
            }
        ],
        "excluded_snapshot_files": [],
    }
    ok, violations = verify_snapshot_exact_set(manifest)
    assert not ok
    assert any("tracked=10 != included+excluded=9" in v for v in violations)


def test_verify_snapshot_exact_set_requires_all_excluded_fields() -> None:
    """Every excluded entry MUST have non-empty rule, reason, and valid blob SHA."""
    from synapx_harness.review.git_snapshot import verify_snapshot_exact_set

    manifest = {
        "tracked_file_count": 2,
        "included_file_count": 1,
        "excluded_file_count": 1,
        "files": [
            {
                "repository_path": "a",
                "package_path": "p/a",
                "git_blob_sha": "a" * 40,
                "package_sha256": "b" * 64,
                "size_bytes": 1,
            }
        ],
        "excluded_snapshot_files": [
            {
                "repository_path": "b",
                "exclusion_rule": "",
                "exclusion_reason": "",
                "git_blob_sha": "",
                "size_bytes": 0,
            }
        ],
    }
    ok, violations = verify_snapshot_exact_set(manifest)
    assert not ok
    assert any("empty" in v.lower() or "git_blob_sha" in v for v in violations)


# ---------------------------------------------------------------------------
# Task 8 & 9: Negative Exploit - Receipt Bijection
# ---------------------------------------------------------------------------

def test_negative_exploit_receipts_are_required(tmp_path: Path) -> None:
    """run_all_attacks with persist_dir MUST write 18 receipt JSON files."""
    from synapx_harness.review.negative_exploit import run_all_attacks

    persist = tmp_path / "ne"
    matrix, results = run_all_attacks(tmp_path, persist_dir=persist)
    assert len(results) == 18
    assert matrix.pass_count == 18
    assert matrix.fail_count == 0


def test_negative_exploit_receipt_bijection_all_18_exist(tmp_path: Path) -> None:
    """All 18 attack receipts MUST exist on disk with correct stdout/stderr."""
    from synapx_harness.review.negative_exploit import (
        run_all_attacks,
        verify_negative_exploit_bijection,
    )

    persist = tmp_path / "ne"
    matrix, _ = run_all_attacks(tmp_path, persist_dir=persist)
    ok, violations = verify_negative_exploit_bijection(matrix, persist_dir=persist)
    assert ok, f"Bijection violations: {violations}"


def test_negative_exploit_bijection_no_forbidden_gate_tokens(tmp_path: Path) -> None:
    """No attack may have actual_gate of NOT_RUN/SKIPPED/N/A/PENDING."""
    from synapx_harness.review.negative_exploit import run_all_attacks

    persist = tmp_path / "ne"
    matrix, _ = run_all_attacks(tmp_path, persist_dir=persist)
    for r in matrix.results:
        expected_msg = (
            f"{r.attack_id} has actual_gate={r.actual_gate}, expected FAIL"
        )
        assert r.actual_gate == "FAIL", expected_msg


# ---------------------------------------------------------------------------
# Task 11: Command Receipt Canonical Path
# ---------------------------------------------------------------------------

def test_command_receipt_stdout_path_not_bare_filename(tmp_path: Path) -> None:
    """Command receipt stdout path MUST be under review/test_evidence or review/command_receipts."""
    import io

    from synapx_harness.review.semantic_verifier import verify_review_package_bytes

    PHASE = "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7-CR4"

    state = {
        "phase": PHASE,
        "implementation_gate": "PASS", "scm_snapshot_binding_gate": "PASS",
        "command_receipt_gate": "PASS", "test_evidence_gate": "PASS",
        "internal_index_gate": "PASS", "negative_exploit_gate": "PASS",
        "package_structural_gate": "PASS", "package_semantic_gate": "PASS",
        "candidate_status": "READY_FOR_INDEPENDENT_REVIEW",
        "independent_review": "PENDING", "p3_authorized": False,
    }
    gate_summary = {
        "phase": PHASE, "gates": {k: "PASS" for k in state if k.endswith("_gate")},
        "all_internal_pass": True, "terminal_candidate_gate": "PASS",
    }
    decision = {
        "phase": PHASE, "decision": "PASS",
        "candidate_status": "READY_FOR_INDEPENDENT_REVIEW",
        "independent_review": "PENDING", "p3_authorized": False,
        "rationale": "all gates PASS",
    }
    vs = {
        "phase": PHASE,
        "pytest": {
            "collected": 10,
            "executed": 10,
            "passed": 10,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
        },
        "collected": 10, "executed": 10, "passed": 10, "failed": 0, "errors": 0, "skipped": 0,
        "gate": "PASS", "ruff_exit": 0, "pyright_src_exit": 0, "pyright_full_exit": 0,
        "raw_pytest_log_excerpt_sha256": hashlib.sha256(b"10 passed").hexdigest(),
    }
    rl_receipt = {
        "phase": PHASE, "review_root": str(tmp_path / PHASE / "review"),
        "artifact_count": 4, "total_size_bytes": 100, "root_sha256": "0" * 64, "gate": "PASS",
    }

    te_receipt = {
        "command_id": "pytest",
        "sanitized_command": "pytest",
        "working_directory": str(tmp_path),
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "exit_code": 0,
        "stdout_artifact": {"path": "pytest.stdout.txt", "sha256": "b" * 64, "size_bytes": 6},
        "stderr_artifact": {"path": "pytest.stderr.txt", "sha256": "c" * 64, "size_bytes": 6},
        "exit_code_artifact": {"path": "pytest.exit.txt", "sha256": "d" * 64, "size_bytes": 1},
        "gate": "PASS",
    }
    te_receipt_bytes = json.dumps(te_receipt, sort_keys=True, separators=(",", ":")).encode()
    te_receipt_sha = hashlib.sha256(te_receipt_bytes).hexdigest()

    te_manifest_entries = [
        {"path": "pytest.json", "sha256": te_receipt_sha, "size_bytes": len(te_receipt_bytes)},
        {"path": "pytest.stdout.txt", "sha256": "b" * 64, "size_bytes": 6},
        {"path": "pytest.stderr.txt", "sha256": "c" * 64, "size_bytes": 6},
        {"path": "pytest.exit.txt", "sha256": "d" * 64, "size_bytes": 1},
    ]
    te_manifest = {
        "phase": PHASE, "entry_count": 4, "entries": te_manifest_entries,
    }

    cmd_receipt = {
        "command_id": "pytest",
        "sanitized_command": "pytest",
        "working_directory": str(tmp_path),
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "exit_code": 0,
        "stdout_artifact": {"path": "pytest.stdout.txt", "sha256": "b" * 64, "size_bytes": 6},
        "stderr_artifact": {"path": "pytest.stderr.txt", "sha256": "c" * 64, "size_bytes": 6},
        "exit_code_artifact": {"path": "pytest.exit.txt", "sha256": "d" * 64, "size_bytes": 1},
        "gate": "PASS",
    }
    cmd_receipt_bytes = json.dumps(cmd_receipt, sort_keys=True, separators=(",", ":")).encode()
    cmd_receipt_sha = hashlib.sha256(cmd_receipt_bytes).hexdigest()

    cmd_manifest = {
        "phase": PHASE, "required_receipts": 1, "valid_receipts": 1,
        "missing_receipts": [], "invalid_receipts": [],
        "summaries": [
            {
                "command_id": "pytest",
                "receipt_path": "pytest.json",
                "receipt_sha256": cmd_receipt_sha,
                "stdout_path": "pytest.stdout.txt",
                "stdout_sha256": "b" * 64,
                "stderr_path": "pytest.stderr.txt",
                "stderr_sha256": "c" * 64,
                "exit_code": 0,
                "exit_code_sha256": "d" * 64,
                "gate": "PASS",
            }
        ],
    }

    ne_matrix = {
        "phase": PHASE, "pass_count": 18, "fail_count": 0, "results": [],
    }

    real_hash = "a" * 64
    idx = {
        "phase": PHASE,
        "review_candidate_state_sha256": real_hash,
        "review_report_sha256": real_hash,
        "verification_summary_sha256": real_hash,
        "gate_summary_sha256": real_hash,
        "review_decision_sha256": real_hash,
        "review_location_receipt_sha256": real_hash,
        "core_scm_provenance_sha256": real_hash,
        "core_snapshot_manifest_sha256": real_hash,
        "service_pack_scm_provenance_sha256": real_hash,
        "service_pack_snapshot_manifest_sha256": real_hash,
        "test_evidence_manifest_sha256": real_hash,
        "command_evidence_manifest_sha256": real_hash,
        "negative_exploit_matrix_sha256": real_hash,
    }

    state_bytes = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    gate_bytes = json.dumps(gate_summary, sort_keys=True, separators=(",", ":")).encode()
    decision_bytes = json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()
    vs_bytes = json.dumps(vs, sort_keys=True, separators=(",", ":")).encode()
    rl_bytes = json.dumps(rl_receipt, sort_keys=True, separators=(",", ":")).encode()
    te_manifest_bytes = json.dumps(te_manifest, sort_keys=True, separators=(",", ":")).encode()
    cmd_manifest_bytes = json.dumps(cmd_manifest, sort_keys=True, separators=(",", ":")).encode()
    ne_matrix_bytes = json.dumps(ne_matrix, sort_keys=True, separators=(",", ":")).encode()

    state_sha = hashlib.sha256(state_bytes).hexdigest()
    gate_sha = hashlib.sha256(gate_bytes).hexdigest()
    decision_sha = hashlib.sha256(decision_bytes).hexdigest()
    vs_sha = hashlib.sha256(vs_bytes).hexdigest()
    rl_sha = hashlib.sha256(rl_bytes).hexdigest()
    te_manifest_sha = hashlib.sha256(te_manifest_bytes).hexdigest()
    cmd_manifest_sha = hashlib.sha256(cmd_manifest_bytes).hexdigest()
    ne_matrix_sha = hashlib.sha256(ne_matrix_bytes).hexdigest()
    idx_fixed = dict(idx)
    idx_fixed["review_candidate_state_sha256"] = state_sha
    idx_fixed["verification_summary_sha256"] = vs_sha
    idx_fixed["gate_summary_sha256"] = gate_sha
    idx_fixed["review_decision_sha256"] = decision_sha
    idx_fixed["review_location_receipt_sha256"] = rl_sha
    idx_fixed["test_evidence_manifest_sha256"] = te_manifest_sha
    idx_fixed["command_evidence_manifest_sha256"] = cmd_manifest_sha
    idx_fixed["negative_exploit_matrix_sha256"] = ne_matrix_sha
    idx_bytes_fixed = json.dumps(idx_fixed, sort_keys=True, separators=(",", ":")).encode()

    def make_artifact(name, data):
        return name, data, hashlib.sha256(data).hexdigest()

    files = [
        make_artifact("review/review_candidate_state.json", state_bytes),
        make_artifact("review/gate_summary.json", gate_bytes),
        make_artifact("review/review_decision.json", decision_bytes),
        make_artifact("review/verification_summary.json", vs_bytes),
        make_artifact("review/review_location_receipt.json", rl_bytes),
        make_artifact("review/test_evidence_manifest.json", te_manifest_bytes),
        make_artifact("review/command_evidence_manifest.json", cmd_manifest_bytes),
        make_artifact("review/negative_exploit_matrix.json", ne_matrix_bytes),
        make_artifact("review/scm/core_repository.json", b"{}"),
        make_artifact("review/scm/service_pack_repository.json", b"{}"),
        make_artifact("review/scm/core_snapshot_manifest.json", b"{}"),
        make_artifact("review/scm/service_pack_snapshot_manifest.json", b"{}"),
        make_artifact("review/internal_review_index.json", idx_bytes_fixed),
        make_artifact("review/test_evidence/pytest.json", te_receipt_bytes),
        make_artifact("review/test_evidence/pytest.stdout.txt", b"stdout"),
        make_artifact("review/test_evidence/pytest.stderr.txt", b"stderr"),
        make_artifact("review/test_evidence/pytest.exit.txt", b"0"),
        make_artifact("review/command_receipts/pytest.json", cmd_receipt_bytes),
        make_artifact("review/command_receipts/pytest.stdout.txt", b"stdout"),
        make_artifact("review/command_receipts/pytest.stderr.txt", b"stderr"),
    ]
    manifest_entries = [
        {"path": name, "sha256": sha, "size_bytes": len(data)}
        for name, data, sha in files
    ]
    manifest = {
        "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
        "payload_file_count": len(files),
        "files": manifest_entries,
    }
    manifest_data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, _ in files:
            zf.writestr(name, data)
        zf.writestr("package_payload_manifest.json", manifest_data)

    sem = verify_review_package_bytes(buf.getvalue())
    path_violations = [
        v
        for v in sem.semantic_violations
        if "not under review/test_evidence" in v
        or "not under review/command_receipts" in v
    ]
    assert path_violations, (
        f"Expected path violation for bare stdout, got: {sem.semantic_violations}"
    )
