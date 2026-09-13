"""R3 Package Security Bypass Negative Tests.

A secret placed in the ZIP but not declared in the manifest must
still fail the package verification. Manifest-driven security scan
is explicitly disallowed.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile


def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_zip_with_files(
    entries: dict[str, bytes],
    manifest_files: list[dict[str, object]] | None = None,
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries.items():
            zf.writestr(path, data)
        if manifest_files is None:
            manifest_files = [
                {"path": p, "sha256": _compute_sha256(d), "size_bytes": len(d)}
                for p, d in entries.items()
            ]
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": len(manifest_files),
            "files": manifest_files,
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest, indent=2).encode("utf-8"))
    return buffer.getvalue()


def _make_zip_with_secret(secret_path: str, secret_bytes: bytes) -> bytes:
    manifest = {
        "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
        "payload_file_count": 0,
        "files": [],
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(secret_path, secret_bytes)
        zf.writestr(
            "package_payload_manifest.json",
            json.dumps(manifest).encode("utf-8"),
        )
    return buffer.getvalue()


def test_secret_in_undeclared_path_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pat = b"fake_pat_" + b"X" * 30
    zip_bytes = _make_zip_with_secret("synapx-harness/leak.md", pat)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok


def test_private_key_in_undeclared_path_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pem = b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
    zip_bytes = _make_zip_with_secret("synapx-harness/secret.pem", pem)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok


def test_dotenv_in_undeclared_path_fails() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    env = b"TOKEN=fake_token_12345678901234567890\n"
    zip_bytes = _make_zip_with_secret("synapx-harness/.env", env)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok


def test_manifest_only_security_scan_fails() -> None:
    """If only manifest files are scanned the undeclared secret slips through."""
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pat = b"github_pat_" + b"X" * 30
    zip_bytes = _make_zip_with_secret("synapx-harness/.envrc", pat)
    report = verify_zip_bytes(zip_bytes)
    assert report.unmanifested_secret_findings
    assert report.all_actual_entries_security_scanned is True


def test_unmanifested_file_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    zip_bytes = _make_zip_with_secret("synapx-harness/orphan.txt", b"orphan content")
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert "synapx-harness/orphan.txt" in report.unmanifested_entries


def test_unmanifested_pat_file_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pat = b"ghp_" + b"A" * 30
    zip_bytes = _make_zip_with_secret("synapx-harness/secrets.pat", pat)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok


def test_unmanifested_private_key_file_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    pem = b"-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END PRIVATE KEY-----\n"
    zip_bytes = _make_zip_with_secret("synapx-harness/id_rsa", pem)
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok


def test_manifest_path_missing_from_zip_causes_failure() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/only.py", b"x=1")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/missing.py", "sha256": "a" * 64, "size_bytes": 10}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert "synapx-harness/missing.py" in report.missing_manifest_entries


def test_actual_zip_file_set_equals_manifest() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    entries = {
        "synapx-harness/a.py": b"a=1",
        "synapx-harness/b.py": b"b=2",
    }
    manifest_files = [
        {
            "path": "synapx-harness/a.py",
            "sha256": _compute_sha256(entries["synapx-harness/a.py"]),
            "size_bytes": 3,
        },
        {
            "path": "synapx-harness/b.py",
            "sha256": _compute_sha256(entries["synapx-harness/b.py"]),
            "size_bytes": 3,
        },
    ]
    zip_bytes = _make_zip_with_files(entries, manifest_files=manifest_files)
    report = verify_zip_bytes(zip_bytes)
    assert report.ok, f"Expected bijection: {report.to_dict()}"


def test_security_scan_runs_over_every_actual_entry() -> None:
    from synapx_harness.review.package_verifier import verify_zip_bytes

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/secret.txt", b"ghp_leak123456789012345678901234")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [
                {
                    "path": "synapx-harness/secret.txt",
                    "sha256": "a" * 64,
                    "size_bytes": 25,
                }
            ],
        }
        zf.writestr(
            "package_payload_manifest.json",
            json.dumps(manifest).encode(),
        )
    zip_bytes = buffer.getvalue()
    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert report.all_actual_entries_security_scanned is True


def test_manifest_duplicate_path_causes_failure() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x=1")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 2,
            "files": [
                {"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 3},
                {"path": "synapx-harness/test.py", "sha256": "b" * 64, "size_bytes": 3},
            ],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert report.manifest_duplicate_exact > 0


def test_manifest_duplicate_casefold_path_causes_failure() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x=1")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 2,
            "files": [
                {"path": "synapx-harness/Test.py", "sha256": "a" * 64, "size_bytes": 3},
                {"path": "synapx-harness/test.py", "sha256": "b" * 64, "size_bytes": 3},
            ],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert report.manifest_duplicate_casefold > 0


def test_manifest_entry_size_mismatch_causes_failure() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x=1")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 9999}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert not report.ok


def test_extra_directory_entry_is_reported() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("synapx-harness/test.py", b"x=1")
        zf.writestr("synapx-harness/__pycache__/", b"")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 1,
            "files": [{"path": "synapx-harness/test.py", "sha256": "a" * 64, "size_bytes": 3}],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert report.directory_entry_count > 0
    assert not report.ok


def test_zip_symlink_entry_is_rejected() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("synapx-harness/symlink")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"/etc/passwd")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 0,
            "files": [],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert report.zip_symlink_entry_count > 0


def test_windows_absolute_path_is_rejected() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("D:/Windows/System32/config/sam", b"data")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 0,
            "files": [],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert report.absolute_path_entry_count > 0


def test_unc_path_is_rejected() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("//server/share/file.txt", b"data")
        manifest = {
            "manifest_scope": "ALL_PAYLOAD_EXCEPT_THIS_MANIFEST",
            "payload_file_count": 0,
            "files": [],
        }
        zf.writestr("package_payload_manifest.json", json.dumps(manifest).encode("utf-8"))
    zip_bytes = buffer.getvalue()
    from synapx_harness.review.package_verifier import verify_zip_bytes

    report = verify_zip_bytes(zip_bytes)
    assert not report.ok
    assert report.unc_path_entry_count > 0
