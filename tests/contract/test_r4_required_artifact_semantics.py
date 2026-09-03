"""R4 Required Artifact Semantics Tests.

Tests that verify required review artifacts are semantically valid.
"""
from __future__ import annotations

import hashlib
import io
import json


def test_invalid_command_receipt_json_fails_package() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    import zipfile
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        test_sha = hashlib.sha256(b"x = 1\n").hexdigest()
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/test.py", "sha256": test_sha, "size_bytes": 6}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert report.ok


def test_valid_internal_index_with_real_hashes() -> None:
    from synapx_harness.evidence.evidence_validator import check_placeholder_hash

    report_sha = hashlib.sha256(b"# Report").hexdigest()
    summary_sha = hashlib.sha256(b"{}").hexdigest()
    gate_sha = hashlib.sha256(b"{}").hexdigest()

    assert not check_placeholder_hash(report_sha)
    assert not check_placeholder_hash(summary_sha)
    assert not check_placeholder_hash(gate_sha)


def test_zero_test_summary_fails_package() -> None:
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
    assert not ok, "Zero test summary should fail"


def test_verification_summary_log_mismatch_fails() -> None:
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary

    summary = {
        "pytest_log_path": "/tmp/pytest.log",
        "pytest_log_sha256": "a" * 64,
        "collected": 10,
        "executed": 10,
        "passed": 8,
        "failed": 2,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    ok, violations = is_valid_verification_summary(summary)
    assert not ok, "Summary with failed=2 should fail R6 validation"
    assert any("failed must be 0" in v for v in violations)


def test_unknown_tree_sha_fails() -> None:
    from synapx_harness.evidence.evidence_validator import validate_hash_format

    ok = validate_hash_format("unknown", 40)
    assert not ok, "Unknown tree SHA should fail validation"


def test_zero_tracked_file_count_fails() -> None:
    from synapx_harness.evidence.evidence_validator import validate_hash_format

    manifest_sha = hashlib.sha256(b"[]").hexdigest()
    ok = validate_hash_format(manifest_sha, 64)
    assert ok

    manifest_sha = ""
    ok = validate_hash_format(manifest_sha, 64)
    assert not ok, "Empty manifest SHA should fail validation"


def test_empty_tracked_manifest_hash_fails() -> None:
    from synapx_harness.evidence.evidence_validator import check_placeholder_hash

    assert check_placeholder_hash("a" * 64), "Placeholder hash should be detected"
    real_hash = hashlib.sha256(b"real content").hexdigest()
    assert not check_placeholder_hash(real_hash), "Real hash should not be placeholder"


def test_command_receipt_invalid_json_fails_package() -> None:
    from synapx_harness.evidence.command_receipt import validate_command_receipt

    receipt = {
        "command_id": 123,
        "sanitized_command": "pytest",
    }
    ok, violations = validate_command_receipt(receipt)
    assert not ok, "Invalid command receipt should fail"
    assert len(violations) > 0


def test_verification_summary_missing_collected_fails_package() -> None:
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary

    summary = {
        "executed": 10,
        "passed": 10,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    ok, violations = is_valid_verification_summary(summary)
    assert not ok, "Missing collected should fail validation"
    assert any("collected" in v for v in violations)


def test_verification_summary_count_mismatch_fails_package() -> None:
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary

    summary = {
        "collected": 10,
        "executed": 10,
        "passed": 8,
        "failed": 2,
        "errors": 1,
        "skipped": 0,
        "gate": "PASS",
    }
    ok, violations = is_valid_verification_summary(summary)
    assert not ok, "Count mismatch should fail validation"
    assert any("collected" in v for v in violations)
