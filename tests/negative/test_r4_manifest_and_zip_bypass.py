"""R4 Manifest and ZIP Bypass Negative Tests.

Tests that verify manifest and ZIP validation rejects malicious inputs.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Mapping, Sequence


def _make_zip_with_manifest(
    entries: dict[str, bytes],
    manifest_files: Sequence[Mapping[str, object]] | None = None,
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
        zf.writestr(
            "package_payload_manifest.json",
            json.dumps(manifest, indent=2).encode("utf-8"),
        )
    return buffer.getvalue()


def test_missing_sha256_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "size_bytes": 10},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Missing sha256 should cause failure"


def test_missing_size_bytes_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": hashlib.sha256(b"x = 1\n").hexdigest()},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Missing size_bytes should cause failure"


def test_invalid_sha256_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": "invalid", "size_bytes": 6},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Invalid sha256 format should cause failure"


def test_negative_size_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    test_sha = hashlib.sha256(b"x = 1\n").hexdigest()
    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": test_sha, "size_bytes": -1},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Negative size_bytes should cause failure"


def test_duplicate_actual_zip_entry_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        zf.writestr("synapx-harness/test.py", b"y = 2\n")
        test_sha = hashlib.sha256(b"x = 1\n").hexdigest()
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/test.py", "sha256": test_sha, "size_bytes": 6}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Duplicate ZIP entry should cause failure"
    assert report.actual_duplicate_exact > 0


def test_actual_count_manifest_count_mismatch_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    test_sha1 = hashlib.sha256(b"x = 1\n").hexdigest()
    test_sha2 = hashlib.sha256(b"z = 3\n").hexdigest()
    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": test_sha1, "size_bytes": 6},
        {"path": "synapx-harness/extra.py", "sha256": test_sha2, "size_bytes": 6},
    ]
    manifest = {
        "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
        "payload_file_count": 2,
        "files": manifest_files,
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Actual count != manifest count should cause failure"


def test_duplicate_actual_casefold_path_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/Test.py", b"x = 1\n")
        zf.writestr("synapx-harness/test.py", b"y = 2\n")
        test_sha1 = hashlib.sha256(b"x = 1\n").hexdigest()
        test_sha2 = hashlib.sha256(b"y = 2\n").hexdigest()
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 2,
            "files": [
                {"path": "synapx-harness/Test.py", "sha256": test_sha1, "size_bytes": 6},
                {"path": "synapx-harness/test.py", "sha256": test_sha2, "size_bytes": 6},
            ],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Casefold duplicate should cause failure"
    assert report.actual_duplicate_casefold > 0 or report.actual_duplicate_normalized > 0


def test_duplicate_actual_normalized_path_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x = 1\n")
        zf.writestr("synapx-harness/./test.py", b"y = 2\n")
        test_sha1 = hashlib.sha256(b"x = 1\n").hexdigest()
        test_sha2 = hashlib.sha256(b"y = 2\n").hexdigest()
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 2,
            "files": [
                {"path": "synapx-harness/test.py", "sha256": test_sha1, "size_bytes": 6},
                {"path": "synapx-harness/./test.py", "sha256": test_sha2, "size_bytes": 6},
            ],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Normalized duplicate should cause failure"


def test_placeholder_hash_in_manifest_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 6},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Placeholder hash should cause failure"


def test_sha256_hash_mismatch_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    wrong_sha = hashlib.sha256(b"wrong content").hexdigest()
    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": wrong_sha, "size_bytes": 6},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "SHA256 mismatch should cause failure"


def test_size_bytes_mismatch_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    test_sha = hashlib.sha256(b"x = 1\n").hexdigest()
    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": test_sha, "size_bytes": 999},
    ]
    zip_bytes = _make_zip_with_manifest(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Size mismatch should cause failure"
