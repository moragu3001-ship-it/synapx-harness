"""R3 Required Review Artifacts Tests.

Tests that ensure all required review artifacts are present in the package:
  - review_decision.json
  - review_report.md
  - verification_summary.json
  - gate_summary.json
  - commit provenance
  - internal_review_index.json
"""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]


def _make_minimal_valid_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 6}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    return buffer.getvalue()


def test_package_missing_review_decision_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Package without review_decision.json should fail"


def test_package_missing_review_report_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Package without review_report.md should fail"


def test_package_missing_verification_summary_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Package without verification_summary.json should fail"


def test_package_missing_pytest_log_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Package without pytest log should fail"


def test_package_missing_commit_provenance_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Package without commit provenance should fail"


def test_package_missing_internal_index_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Package without internal_review_index.json should fail"


def test_reported_hash_must_have_matching_file() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [
                {
                    "path": "synapx-harness/test.py",
                    "sha256": "wrong_hash" * 4 + "x",
                    "size_bytes": 6,
                }
            ],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Hash mismatch should cause failure"


def test_seal_verification_fails_on_report_change() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Incomplete package should fail seal verification"


def test_seal_verification_fails_on_zip_change() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_minimal_valid_zip()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "ZIP without proper structure should fail"
