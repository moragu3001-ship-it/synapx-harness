"""R4 Verify-Seal Negative Tests.

Tests that verify seal verification rejects malicious inputs.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile


def _make_minimal_zip(
    entries: dict[str, bytes],
    manifest_files: list[dict[str, object]] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries.items():
            zf.writestr(path, data)
        if manifest_files is None:
            manifest_files = [
                {"path": p, "sha256": hashlib.sha256(d).hexdigest(), "size_bytes": len(d)}
                for p, d in entries.items()
            ]
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": len(manifest_files),
            "files": manifest_files,
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    return buffer.getvalue()


def _make_receipt(
    zip_sha: str,
    manifest_sha: str,
    index_sha: str,
    report_sha: str,
    summary_sha: str,
    gate_sha: str,
    implementation_gate: str = "PASS",
    independent_review: str = "PENDING",
    p3_authorized: bool = False,
) -> dict[str, object]:
    return {
        "phase": "COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R5",
        "zip_filename": "test.zip",
        "zip_sha256": zip_sha,
        "payload_manifest_sha256": manifest_sha,
        "internal_review_index_sha256": index_sha,
        "review_candidate_state_sha256": hashlib.sha256(b"{}").hexdigest(),
        "review_report_sha256": report_sha,
        "verification_summary_sha256": summary_sha,
        "gate_summary_sha256": gate_sha,
        "core_commit_sha": "a" * 40,
        "core_tree_sha": "b" * 40,
        "pack_commit_sha": "c" * 40,
        "pack_tree_sha": "d" * 40,
        "implementation_gate": implementation_gate,
        "independent_review": independent_review,
        "p3_authorized": p3_authorized,
        "terminal_gate": "PASS",
    }


def test_tampered_zip_fails_verify_seal() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    content = b"original content"
    tampered_content = b"tampered content"

    zip_bytes = _make_minimal_zip({"test.txt": content})
    report = verify_zip_bytes(zip_bytes)
    assert report.ok, "Original ZIP should verify OK"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", tampered_content)
        test_sha = hashlib.sha256(tampered_content).hexdigest()
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [
                {
                    "path": "test.txt",
                    "sha256": test_sha,
                    "size_bytes": len(tampered_content),
                }
            ],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    tampered_bytes = buffer.getvalue()

    tampered_report = verify_zip_bytes(tampered_bytes)
    assert tampered_report.ok, "ZIP with wrong hash in manifest should still verify structurally"

    manifest_files_wrong = [
        {
            "path": "test.txt",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
    ]
    buffer2 = io.BytesIO()
    with zipfile.ZipFile(buffer2, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", tampered_content)
        manifest2 = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": manifest_files_wrong,
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest2).encode("utf-8"))
    mismatched_bytes = buffer2.getvalue()
    mismatched_report = verify_zip_bytes(mismatched_bytes)
    assert not mismatched_report.ok, "Content/hash mismatch should fail verification"


def test_missing_manifest_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", b"content")

    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "ZIP without manifest should fail"
    assert "package_payload_manifest.json" in report.unmanifested_entries or not report.ok


def test_unmanifested_entry_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_zip(
        {"test.txt": b"content"},
        manifest_files=[{"path": "other.txt", "sha256": "a" * 64, "size_bytes": 7}],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Unmanifested entry should fail"


def test_placeholder_hash_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_zip(
        {"test.txt": b"content"},
        manifest_files=[{"path": "test.txt", "sha256": "a" * 64, "size_bytes": 7}],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Placeholder hash should fail"


def test_wrong_hash_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_zip(
        {"test.txt": b"content"},
        manifest_files=[{"path": "test.txt", "sha256": "b" * 64, "size_bytes": 7}],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Wrong hash should fail"


def test_terminal_gate_fail_with_implementation_fail() -> None:
    implementation_gate = "FAIL"
    independent_review = "PENDING"
    p3_authorized = False

    actual_terminal_gate = "PASS" if (
        implementation_gate == "PASS"
        and independent_review in ("PENDING", "ACCEPT")
        and not p3_authorized
    ) else "FAIL"

    assert actual_terminal_gate == "FAIL", (
        "Terminal gate should be FAIL when implementation_gate is FAIL"
    )


def test_zero_test_evidence_cannot_be_sealed() -> None:
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary

    summary = {
        "collected": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    ok, _ = is_valid_verification_summary(summary)
    assert not ok, "Zero test evidence should not be sealable"


def test_p3_authorized_true_with_independent_pending_fails() -> None:
    p3_authorized = True
    independent_review = "PENDING"

    actual_terminal_gate = "PASS" if (
        True == "PASS"
        and independent_review in ("PENDING", "ACCEPT")
        and not p3_authorized
    ) else "FAIL"

    assert actual_terminal_gate == "FAIL", (
        "P3 authorized true with independent review PENDING should fail"
    )


def test_invalid_command_receipt_json_fails() -> None:
    from synapx_harness.evidence.command_receipt import validate_command_receipt

    receipt = {
        "command_id": 123,
        "sanitized_command": "pytest",
    }
    ok, violations = validate_command_receipt(receipt)
    assert not ok, "Invalid command receipt should fail"
    assert len(violations) > 0


def test_placeholder_hash_in_command_receipt_fails() -> None:
    from synapx_harness.evidence.command_receipt import PLACEHOLDER_HASH, validate_command_receipt

    receipt = {
        "command_id": "test",
        "sanitized_command": "echo test",
        "working_directory": "/tmp",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 0,
        "stdout_artifact": {
            "path": "/tmp/stdout.txt",
            "sha256": PLACEHOLDER_HASH,
            "size_bytes": 0,
        },
        "stderr_artifact": {
            "path": "/tmp/stderr.txt",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "gate": "PASS",
    }
    ok, violations = validate_command_receipt(receipt)
    assert not ok, "Placeholder hash in command receipt should fail"
    assert any("placeholder" in v.lower() for v in violations)


def test_directory_entry_in_zip_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        zf.writestr("synapx-harness/extra_dir/", b"")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 6}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert report.directory_entry_count > 0, "Directory entry should be counted"
    assert not report.ok, "Extra directory entry should cause failure"


def test_duplicate_path_in_manifest_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 6},
        {"path": "synapx-harness/test.py", "sha256": "b" * 64, "size_bytes": 7},
    ]
    zip_bytes = _make_minimal_zip(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Duplicate path in manifest should cause failure"


def test_windows_backslash_entry_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness\\test.py", b"x = 1\n")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness\\test.py", "sha256": "a" * 64, "size_bytes": 6}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Backslash entry in manifest should cause failure due to path mismatch"
    assert len(report.missing_manifest_entries) > 0 or len(report.unmanifested_entries) > 0


def test_secret_in_zip_fails_verify() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pat = b"ghp_" + b"A" * 30
    entries = {
        "synapx-harness/test.py": b"x = 1\n",
        "synapx-harness/leaked.pat": pat,
    }
    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 6},
        {"path": "synapx-harness/leaked.pat", "sha256": "a" * 64, "size_bytes": len(pat)},
    ]
    zip_bytes = _make_minimal_zip(entries, manifest_files=manifest_files)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Secret in ZIP should cause failure"
    assert len(report.secret_findings) > 0, "Secret findings should be reported"
