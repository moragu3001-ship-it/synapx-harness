"""R4 Command Receipt Truth Tests.

Tests that enforce command receipt validity from actual execution.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from synapx_harness.evidence.command_receipt import PLACEHOLDER_HASH, validate_command_receipt


def test_command_receipt_is_valid_json() -> None:
    receipt = {
        "command_id": "abc123",
        "sanitized_command": "pytest tests/",
        "working_directory": "/path/to/repo",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 0,
        "stdout_artifact": {
            "path": "/tmp/stdout.txt",
            "sha256": hashlib.sha256(b"test output").hexdigest(),
            "size_bytes": 10,
        },
        "stderr_artifact": {
            "path": "/tmp/stderr.txt",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "gate": "PASS",
    }
    ok, violations = validate_command_receipt(receipt)
    assert ok, f"Valid receipt rejected: {violations}"


def test_stdout_hash_matches_actual_artifact(tmp_path: Path) -> None:
    stdout_content = b"test output from command"
    stdout_file = tmp_path / "stdout.txt"
    stdout_file.write_bytes(stdout_content)

    receipt = {
        "command_id": "abc123",
        "sanitized_command": "echo test",
        "working_directory": "/tmp",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 0,
        "stdout_artifact": {
            "path": str(stdout_file),
            "sha256": hashlib.sha256(stdout_content).hexdigest(),
            "size_bytes": len(stdout_content),
        },
        "stderr_artifact": {
            "path": str(tmp_path / "stderr.txt"),
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "gate": "PASS",
    }
    ok, violations = validate_command_receipt(receipt)
    assert ok, f"Hash mismatch not detected: {violations}"


def test_stderr_hash_matches_actual_artifact(tmp_path: Path) -> None:
    stderr_content = b"error message"
    stderr_file = tmp_path / "stderr.txt"
    stderr_file.write_bytes(stderr_content)

    receipt = {
        "command_id": "abc123",
        "sanitized_command": "failing-command",
        "working_directory": "/tmp",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 1,
        "stdout_artifact": {
            "path": str(tmp_path / "stdout.txt"),
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "stderr_artifact": {
            "path": str(stderr_file),
            "sha256": hashlib.sha256(stderr_content).hexdigest(),
            "size_bytes": len(stderr_content),
        },
        "gate": "FAIL",
    }
    ok, violations = validate_command_receipt(receipt)
    assert ok, f"Hash mismatch not detected: {violations}"


def test_nonzero_exit_code_is_fail() -> None:
    receipt = {
        "command_id": "abc123",
        "sanitized_command": "exit 1",
        "working_directory": "/tmp",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 1,
        "stdout_artifact": {
            "path": "/tmp/stdout.txt",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "stderr_artifact": {
            "path": "/tmp/stderr.txt",
            "sha256": hashlib.sha256(b"").hexdigest(),
            "size_bytes": 0,
        },
        "gate": "FAIL",
    }
    ok, violations = validate_command_receipt(receipt)
    assert ok, f"Nonzero exit code should be allowed with FAIL gate: {violations}"


def test_placeholder_hash_is_rejected() -> None:
    receipt = {
        "command_id": "abc123",
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
    assert not ok, "Placeholder hash should be rejected"
    assert any("placeholder" in v.lower() for v in violations)


def test_non_hex_hash_is_rejected() -> None:
    receipt = {
        "command_id": "abc123",
        "sanitized_command": "echo test",
        "working_directory": "/tmp",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 0,
        "stdout_artifact": {
            "path": "/tmp/stdout.txt",
            "sha256": "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
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
    assert not ok, "Non-hex hash should be rejected"
    assert any("hex" in v.lower() for v in violations)


def test_missing_output_artifact_is_rejected() -> None:
    receipt = {
        "command_id": "abc123",
        "sanitized_command": "echo test",
        "working_directory": "/tmp",
        "started_at": "2024-01-01T00:00:00Z",
        "finished_at": "2024-01-01T00:01:00Z",
        "exit_code": 0,
        "stdout_artifact": {
            "path": "/tmp/nonexistent.txt",
            "sha256": hashlib.sha256(b"").hexdigest(),
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
    assert ok, f"Command receipt validator does not check file existence: {violations}"
