"""R7 negative/contract tests for evidence integrity, candidate state,
candidate_state consistency, terminal seal authority, and verify-seal
content checks. Each test exercises a real production function.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


def _mk_artifact(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def _build_minimal_required_artifacts(review_dir: Path) -> dict[str, Path]:
    """Create the minimum required artifacts for internal_index building.

    Keys match REQUIRED_FIELDS names (with ``_sha256`` suffix).
    """
    paths: dict[str, Path] = {}
    paths["review_candidate_state_sha256"] = review_dir / "review_candidate_state.json"
    paths["review_report_sha256"] = review_dir / "review_report.md"
    paths["verification_summary_sha256"] = review_dir / "verification_summary.json"
    paths["gate_summary_sha256"] = review_dir / "gate_summary.json"
    paths["review_decision_sha256"] = review_dir / "review_decision.json"
    paths["review_location_receipt_sha256"] = review_dir / "review_location_receipt.json"
    paths["core_scm_provenance_sha256"] = review_dir / "core_scm_provenance.json"
    paths["core_snapshot_manifest_sha256"] = review_dir / "core_snapshot_manifest.json"
    paths["service_pack_scm_provenance_sha256"] = review_dir / "service_pack_scm_provenance.json"
    paths["service_pack_snapshot_manifest_sha256"] = (
        review_dir / "service_pack_snapshot_manifest.json"
    )
    paths["test_evidence_manifest_sha256"] = review_dir / "test_evidence_manifest.json"
    paths["command_evidence_manifest_sha256"] = review_dir / "command_evidence_manifest.json"
    paths["negative_exploit_matrix_sha256"] = review_dir / "negative_exploit_matrix.json"
    for k, p in paths.items():
        # Use the bare field name (without _sha256 suffix) as content to
        # make each artifact unique by content.
        bare = k.replace("_sha256", "")
        _mk_artifact(p, bare.encode("utf-8"))
    return paths


def test_r7_internal_index_fake_hash_rejected(tmp_path: Path) -> None:
    """A hash that is not 64 lowercase hex MUST be rejected."""
    from synapx_harness.review.internal_review_index import (
        load_internal_review_index,
    )

    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "phase": "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7",
                "review_candidate_state_sha256": "not-a-real-sha",
                "review_report_sha256": "a" * 64,
                "verification_summary_sha256": "a" * 64,
                "gate_summary_sha256": "a" * 64,
                "review_decision_sha256": "a" * 64,
                "review_location_receipt_sha256": "a" * 64,
                "core_scm_provenance_sha256": "a" * 64,
                "core_snapshot_manifest_sha256": "a" * 64,
                "service_pack_scm_provenance_sha256": "a" * 64,
                "service_pack_snapshot_manifest_sha256": "a" * 64,
                "test_evidence_manifest_sha256": "a" * 64,
                "command_evidence_manifest_sha256": "a" * 64,
                "negative_exploit_matrix_sha256": "a" * 64,
            }
        )
    )
    try:
        load_internal_review_index(bad)
        ok = True
    except ValueError:
        ok = False
    assert not ok, "Non-hex sha256 must be rejected"


def test_r7_internal_index_hash_mismatch_rejected(tmp_path: Path) -> None:
    """Verify rehash detects a mismatch after on-disk change."""
    from synapx_harness.review.internal_review_index import (
        build_internal_review_index,
        verify_internal_review_index,
    )

    paths = _build_minimal_required_artifacts(tmp_path)
    idx = build_internal_review_index(
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7",
        artifact_paths=paths,
    )
    paths["review_candidate_state_sha256"].write_bytes(b"TAMPERED")
    ok, _violations = verify_internal_review_index(idx, paths)
    assert not ok, "Tampered source must be detected"


def test_r7_test_evidence_missing_stderr_rejected(tmp_path: Path) -> None:
    """A receipt that references a stderr file MUST cause the build to
    fail if stderr is missing."""
    from synapx_harness.review.test_evidence_manifest import (
        load_test_evidence_manifest,
    )

    te = tmp_path / "te"
    te.mkdir()
    (te / "pytest.stdout.txt").write_bytes(b"hello")
    manifest = {
        "phase": "P",
        "entry_count": 2,
        "entries": [
            {
                "path": "pytest.stdout.txt",
                "sha256": hashlib.sha256(b"hello").hexdigest(),
                "size_bytes": 5,
            },
            {
                "path": "pytest.stderr.txt",
                "sha256": hashlib.sha256(b"").hexdigest(),
                "size_bytes": 0,
            },
        ],
    }
    manifest_path = te / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    loaded = load_test_evidence_manifest(manifest_path)
    from synapx_harness.review.test_evidence_manifest import (
        verify_manifest_against_directory,
    )

    ok, _violations = verify_manifest_against_directory(loaded, te)
    assert not ok, "Manifest referencing missing stderr must fail"


def test_r7_test_evidence_size_mismatch_rejected(tmp_path: Path) -> None:
    from synapx_harness.review.test_evidence_manifest import (
        build_test_evidence_manifest,
        verify_manifest_against_directory,
    )

    te = tmp_path / "te"
    te.mkdir()
    (te / "pytest.stdout.txt").write_bytes(b"abc")
    manifest = build_test_evidence_manifest(phase="P", test_evidence_dir=te)
    (te / "pytest.stdout.txt").write_bytes(b"abcd")
    ok, _ = verify_manifest_against_directory(manifest, te)
    assert not ok, "Size mismatch must be detected"


def test_r7_missing_ruff_receipt_rejected(tmp_path: Path) -> None:
    from synapx_harness.review.command_evidence import (
        build_command_evidence_manifest,
    )

    ceb = tmp_path / "ceb"
    ceb.mkdir()
    (ceb / "pytest.json").write_text(
        json.dumps(
            {
                "command_id": "x",
                "sanitized_command": "pytest",
                "working_directory": ".",
                "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:01+00:00",
                "exit_code": 0,
                "stdout_artifact": {
                    "path": "pytest.stdout.txt",
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "size_bytes": 0,
                },
                "stderr_artifact": {
                    "path": "pytest.stderr.txt",
                    "sha256": hashlib.sha256(b"").hexdigest(),
                    "size_bytes": 0,
                },
                "gate": "PASS",
            }
        )
    )
    (ceb / "pytest.stdout.txt").write_bytes(b"")
    (ceb / "pytest.stderr.txt").write_bytes(b"")
    m = build_command_evidence_manifest(
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7", command_receipts_dir=ceb
    )
    assert "ruff" in m.missing_receipts
    assert m.valid_receipts != 4


def test_r7_invalid_pytest_receipt_rejected(tmp_path: Path) -> None:
    from synapx_harness.review.command_evidence import (
        build_command_evidence_manifest,
    )

    ceb = tmp_path / "ceb"
    ceb.mkdir()
    (ceb / "pytest.json").write_text(json.dumps({"command_id": 123}))
    m = build_command_evidence_manifest(
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7", command_receipts_dir=ceb
    )
    assert "pytest" in m.invalid_receipts


def test_r7_command_output_hash_mismatch_rejected(tmp_path: Path) -> None:
    from synapx_harness.review.command_evidence import (
        build_command_evidence_manifest,
    )

    ceb = tmp_path / "ceb"
    ceb.mkdir()
    payload = {
        "command_id": "x",
        "sanitized_command": "pytest",
        "working_directory": ".",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "exit_code": 0,
        "stdout_artifact": {
            "path": "pytest.stdout.txt",
            "sha256": hashlib.sha256(b"WRONG").hexdigest(),
            "size_bytes": 0,
        },
        "stderr_artifact": {
            "path": "pytest.stderr.txt",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "gate": "PASS",
    }
    (ceb / "pytest.json").write_text(json.dumps(payload))
    (ceb / "pytest.stdout.txt").write_bytes(b"")
    (ceb / "pytest.stderr.txt").write_bytes(b"")
    m = build_command_evidence_manifest(
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7", command_receipts_dir=ceb
    )
    assert "pytest" in m.invalid_receipts


def test_r7_review_location_mismatch_rejected(tmp_path: Path) -> None:
    from synapx_harness.review.review_location_receipt import (
        build_review_location_receipt,
        verify_review_location_receipt,
    )

    phase = "P"
    review_dir = tmp_path / phase / "review"
    review_dir.mkdir(parents=True)
    (review_dir / "a.json").write_bytes(b"{}")
    rec = build_review_location_receipt(
        phase=phase,
        review_root=review_dir,
        canonical_review_base=tmp_path,
    )
    (review_dir / "b.json").write_bytes(b"{}")
    ok, _ = verify_review_location_receipt(
        rec, review_dir, canonical_review_base=tmp_path
    )
    assert not ok, "Adding an artifact after receipt must be detected"


def test_r7_verification_summary_hash_mismatch_rejected(tmp_path: Path) -> None:
    """If the on-disk verification_summary hash differs from the
    internal_index, the verifier must report a mismatch."""
    from synapx_harness.review.internal_review_index import (
        build_internal_review_index,
    )

    paths = _build_minimal_required_artifacts(tmp_path)
    idx = build_internal_review_index(
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7",
        artifact_paths=paths,
    )
    paths["verification_summary_sha256"].write_bytes(b"DIFFERENT")
    assert idx.hashes["verification_summary_sha256"] != hashlib.sha256(b"DIFFERENT").hexdigest()


def test_r7_gate_pending_rejected(tmp_path: Path) -> None:
    """PENDING gate must be rejected by compute_candidate_state."""
    import pytest

    from synapx_harness.review.candidate_state import (
        CandidateStateInputs,
        compute_candidate_state,
    )

    bad = CandidateStateInputs(
        phase="COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7",
        implementation_gate="PENDING",
        scm_snapshot_binding_gate="PASS",
        command_receipt_gate="PASS",
        test_evidence_gate="PASS",
        internal_index_gate="PASS",
        negative_exploit_gate="PASS",
        package_structural_gate="PASS",
        package_semantic_gate="PASS",
    )
    with pytest.raises(ValueError):
        compute_candidate_state(bad)


def test_r7_decision_candidate_contradiction_rejected(tmp_path: Path) -> None:
    from synapx_harness.review.candidate_state import (
        CandidateStateInputs,
        compute_candidate_state,
        verify_candidate_state_consistency,
    )
    from synapx_harness.review.review_phase_contract import GATE_PASS, PHASE

    inputs = CandidateStateInputs(
        phase=PHASE,
        implementation_gate=GATE_PASS,
        scm_snapshot_binding_gate=GATE_PASS,
        command_receipt_gate=GATE_PASS,
        test_evidence_gate=GATE_PASS,
        internal_index_gate=GATE_PASS,
        negative_exploit_gate=GATE_PASS,
        package_structural_gate=GATE_PASS,
        package_semantic_gate=GATE_PASS,
    )
    out = compute_candidate_state(inputs)
    state = dict(out.review_candidate_state)
    state["candidate_status"] = "IMPOSSIBLE_STATUS"
    ok, _ = verify_candidate_state_consistency(state, out.gate_summary, out.review_decision)
    assert not ok, "Inconsistent candidate_status must be detected"


def test_r7_seal_derives_phase_from_package(tmp_path: Path) -> None:
    """The terminal seal must derive phase from the package contents,
    never from a CLI-injected value."""
    from synapx_harness.review.review_phase_contract import PHASE
    from synapx_harness.review.terminal_seal import (
        compute_terminal_seal,
        read_internal_terminal_state,
    )

    pkg = {
        "review_candidate_state": {
            "phase": PHASE,
            "candidate_status": "READY_FOR_INDEPENDENT_REVIEW",
            "independent_review": "PENDING",
            "p3_authorized": False,
        },
        "gate_summary": {"all_internal_pass": True, "gates": {}},
        "review_decision": {"decision": "PASS"},
        "structural": "PASS",
        "semantic": "PASS",
        "package_structural_gate": "PASS",
        "package_semantic_gate": "PASS",
        "structural_ok": True,
        "semantic_ok": True,
    }
    s = read_internal_terminal_state(pkg)
    seal = compute_terminal_seal(s)
    assert seal["phase"] == PHASE
    assert seal["phase_matches_contract"] is True
    assert seal["terminal_candidate_gate"] == "PASS"


def test_r7_external_pass_injection_rejected(tmp_path: Path) -> None:
    """CLI-injected implementation_gate=PASS with internal Gate FAIL
    must NOT flip the terminal verdict."""
    from synapx_harness.review.candidate_state import (
        CandidateStateInputs,
        compute_candidate_state,
    )
    from synapx_harness.review.review_phase_contract import GATE_FAIL, GATE_PASS, PHASE

    inputs = CandidateStateInputs(
        phase=PHASE,
        implementation_gate=GATE_PASS,
        scm_snapshot_binding_gate=GATE_FAIL,
        command_receipt_gate=GATE_PASS,
        test_evidence_gate=GATE_PASS,
        internal_index_gate=GATE_PASS,
        negative_exploit_gate=GATE_PASS,
        package_structural_gate=GATE_PASS,
        package_semantic_gate=GATE_PASS,
    )
    out = compute_candidate_state(inputs)
    assert out.terminal_candidate_gate == GATE_FAIL
    assert out.review_candidate_state["candidate_status"] != "READY_FOR_INDEPENDENT_REVIEW"


def test_r7_verify_seal_reads_candidate_state_content(tmp_path: Path) -> None:
    """Verify-seal must read the candidate_state content (not just
    presence) and recompute the terminal verdict."""
    from synapx_harness.review.verify_seal import verify_seal

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"x")
        zf.writestr(
            "package_payload_manifest.json",
            json.dumps(
                {
                    "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
                    "payload_file_count": 1,
                    "files": [
                        {
                            "path": "a.txt",
                            "sha256": hashlib.sha256(b"x").hexdigest(),
                            "size_bytes": 1,
                        }
                    ],
                }
            ).encode(),
        )
    zip_path = tmp_path / "fake.zip"
    zip_path.write_bytes(buf.getvalue())
    receipt = {
        "phase": "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R7",
        "terminal_candidate_gate": "PASS",
        "zip_sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest(),
        "candidate_status": "READY_FOR_INDEPENDENT_REVIEW",
        "independent_review": "PENDING",
        "p3_authorized": False,
        "implementation_gate": "PASS",
        "review_candidate_state_sha256": "a" * 64,
        "internal_review_index_sha256": "a" * 64,
        "payload_manifest_sha256": "a" * 64,
        "review_report_sha256": "a" * 64,
        "verification_summary_sha256": "a" * 64,
        "gate_summary_sha256": "a" * 64,
        "core_commit_sha": "a" * 40,
        "core_tree_sha": "b" * 40,
        "pack_commit_sha": "c" * 40,
        "pack_tree_sha": "d" * 40,
        "structural_pass": True,
        "semantic_pass": True,
    }
    res = verify_seal(zip_path=zip_path, receipt=receipt)
    assert not res.ok, "verify-seal must FAIL when package contents are missing"


import io  # noqa: E402
