"""R3 Package Manifest Bijection Tests.

Tests that enforce strict bijection between:
  - Actual ZIP File Entries
  - Manifest.files.path
  - package_payload_manifest.json

Any mismatch must fail closed.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile


def _make_zip_with_files(
    entries: dict[str, bytes],
    manifest_files: list[dict[str, object]] | None = None,
    include_manifest: bool = True,
    manifest_payload_file_count: int | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries.items():
            zf.writestr(path, data)
        if include_manifest:
            if manifest_files is None:
                manifest_files = [
                    {"path": p, "sha256": "a" * 64, "size_bytes": len(d)}
                    for p, d in entries.items()
                ]
            manifest = {
                "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
                "payload_file_count": (
                    manifest_payload_file_count
                    if manifest_payload_file_count is not None
                    else len(manifest_files)
                ),
                "files": manifest_files,
            }
            zf.writestr(
                "package_payload_manifest.json",
                json.dumps(manifest, indent=2).encode("utf-8"),
            )
    return buffer.getvalue()


def test_unmanifested_file_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_zip_with_files(
        {"synapx-harness/test.py": b"print('hello')\n"},
        manifest_files=[],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Unmanifested file should cause failure"


def test_unmanifested_pat_file_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pat_content = b"pat_token_" + b"A" * 30
    zip_bytes = _make_zip_with_files(
        {"synapx-harness/.pat": pat_content},
        manifest_files=[],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Unmanifested PAT file should cause failure"


def test_unmanifested_private_key_file_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pem = b"-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END PRIVATE KEY-----\n"
    zip_bytes = _make_zip_with_files(
        {"synapx-harness/secret.key": pem},
        manifest_files=[],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Unmanifested private key file should cause failure"


def test_manifest_path_missing_from_zip_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_zip_with_files(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=[
            {"path": "synapx-harness/missing.py", "sha256": "b" * 64, "size_bytes": 10}
        ],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Missing manifest path should cause failure"
    assert report.missing_manifest_entries, "Should report missing manifest entries"


def test_actual_zip_file_set_equals_manifest_plus_manifest_file() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    entries = {
        "synapx-harness/test.py": b"x = 1\n",
        "synapx-harness/README.md": b"# Test\n",
    }
    manifest_files = [
        {
            "path": "synapx-harness/test.py",
            "sha256": hashlib.sha256(entries["synapx-harness/test.py"]).hexdigest(),
            "size_bytes": 6,
        },
        {
            "path": "synapx-harness/README.md",
            "sha256": hashlib.sha256(entries["synapx-harness/README.md"]).hexdigest(),
            "size_bytes": 7,
        },
    ]
    zip_bytes = _make_zip_with_files(entries, manifest_files=manifest_files)
    report = verify_zip_bytes(zip_bytes)
    assert report.ok, f"Bijection should pass: {report.to_dict()}"
    assert report.actual_file_count == 2
    assert report.manifest_declared_file_count == 2


def test_security_scan_runs_over_every_actual_zip_file() -> None:
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
    zip_bytes = _make_zip_with_files(entries, manifest_files=manifest_files)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Secret in ZIP should cause failure"
    assert (
        report.all_actual_entries_security_scanned is True
    ), "All entries should be security scanned"


def test_manifest_duplicate_path_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 6},
        {"path": "synapx-harness/test.py", "sha256": "b" * 64, "size_bytes": 7},
    ]
    zip_bytes = _make_zip_with_files(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Duplicate path in manifest should cause failure"


def test_manifest_duplicate_casefold_path_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/Test.py", "sha256": "a" * 64, "size_bytes": 6},
        {"path": "synapx-harness/test.py", "sha256": "b" * 64, "size_bytes": 7},
    ]
    zip_bytes = _make_zip_with_files(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Duplicate casefold path in manifest should cause failure"


def test_manifest_entry_size_mismatch_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    manifest_files = [
        {"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 999},
    ]
    zip_bytes = _make_zip_with_files(
        {"synapx-harness/test.py": b"x = 1\n"},
        manifest_files=manifest_files,
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Size mismatch should cause failure"


def test_extra_directory_entry_is_reported() -> None:
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


def test_zip_symlink_entry_is_rejected() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("synapx-harness/link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"/etc/passwd")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 0,
            "files": [],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Symlink entry should be rejected"
    assert report.zip_symlink_entry_count > 0


def test_windows_absolute_path_is_rejected() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_zip_with_files(
        {"C:/Windows/System32/config/sam": b"data"},
        manifest_files=[],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "Windows absolute path should be rejected"
    assert report.absolute_path_entry_count > 0


def test_unc_path_is_rejected() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_zip_with_files(
        {"//server/share/file.txt": b"data"},
        manifest_files=[],
    )
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok, "UNC path should be rejected"
    assert report.unc_path_entry_count > 0
