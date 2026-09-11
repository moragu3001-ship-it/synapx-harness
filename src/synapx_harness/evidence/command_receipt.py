"""Command Receipt Schema and Validation.

Command receipts are generated from actual command execution results.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

PLACEHOLDER_HASH = "a" * 64


@dataclass(frozen=True)
class CommandReceipt:
    command_id: str
    sanitized_command: str
    working_directory: str
    started_at: str
    finished_at: str
    exit_code: int
    stdout_artifact: dict[str, object]
    stderr_artifact: dict[str, object]
    gate: str

    def to_dict(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "sanitized_command": self.sanitized_command,
            "working_directory": self.working_directory,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "stdout_artifact": self.stdout_artifact,
            "stderr_artifact": self.stderr_artifact,
            "gate": self.gate,
        }


def validate_command_receipt(data: dict[str, object]) -> tuple[bool, list[str]]:
    violations: list[str] = []

    if not isinstance(data.get("command_id"), str) or not data["command_id"]:
        violations.append("command_id is required")

    if not isinstance(data.get("sanitized_command"), str) or not data["sanitized_command"]:
        violations.append("sanitized_command is required")

    if not isinstance(data.get("working_directory"), str):
        violations.append("working_directory is required")

    if not isinstance(data.get("started_at"), str):
        violations.append("started_at is required")

    if not isinstance(data.get("finished_at"), str):
        violations.append("finished_at is required")

    if not isinstance(data.get("exit_code"), int):
        violations.append("exit_code is required")

    stdout_art = data.get("stdout_artifact")
    if not isinstance(stdout_art, dict):
        violations.append("stdout_artifact is required")
    else:
        stdout_path = stdout_art.get("path")
        stdout_sha = stdout_art.get("sha256")
        stdout_size = stdout_art.get("size_bytes")

        if not isinstance(stdout_path, str) or not stdout_path:
            violations.append("stdout_artifact.path is required")
        if not isinstance(stdout_sha, str) or not stdout_sha:
            violations.append("stdout_artifact.sha256 is required")
        elif stdout_sha == PLACEHOLDER_HASH:
            violations.append("stdout_artifact.sha256 is placeholder")
        elif not isinstance(stdout_sha, str) or len(stdout_sha) != 64:
            violations.append("stdout_artifact.sha256 must be 64 hex chars")
        elif not all(c in "0123456789abcdef" for c in stdout_sha):
            violations.append("stdout_artifact.sha256 must be lowercase hex")
        if not isinstance(stdout_size, int) or stdout_size < 0:
            violations.append("stdout_artifact.size_bytes must be non-negative integer")

    stderr_art = data.get("stderr_artifact")
    if not isinstance(stderr_art, dict):
        violations.append("stderr_artifact is required")
    else:
        stderr_path = stderr_art.get("path")
        stderr_sha = stderr_art.get("sha256")
        stderr_size = stderr_art.get("size_bytes")

        if not isinstance(stderr_path, str) or not stderr_path:
            violations.append("stderr_artifact.path is required")
        if not isinstance(stderr_sha, str) or not stderr_sha:
            violations.append("stderr_artifact.sha256 is required")
        elif stderr_sha == PLACEHOLDER_HASH:
            violations.append("stderr_artifact.sha256 is placeholder")
        elif not isinstance(stderr_sha, str) or len(stderr_sha) != 64:
            violations.append("stderr_artifact.sha256 must be 64 hex chars")
        elif not all(c in "0123456789abcdef" for c in stderr_sha):
            violations.append("stderr_artifact.sha256 must be lowercase hex")
        if not isinstance(stderr_size, int) or stderr_size < 0:
            violations.append("stderr_artifact.size_bytes must be non-negative integer")

    if data.get("gate") not in ("PASS", "FAIL"):
        violations.append("gate must be PASS or FAIL")

    return len(violations) == 0, violations


def hash_command_receipt(data: dict[str, object]) -> str:
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = [
    "CommandReceipt",
    "PLACEHOLDER_HASH",
    "hash_command_receipt",
    "validate_command_receipt",
]
