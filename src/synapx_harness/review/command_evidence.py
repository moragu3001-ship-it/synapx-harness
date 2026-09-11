"""Command evidence manifest.

Aggregates the 4 required command receipts (pytest, ruff, pyright
src, pyright full) into a single manifest. Every receipt is schema-
validated and its stdout/stderr raw artifacts are SHA-linked.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from synapx_harness.evidence.command_receipt import validate_command_receipt

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_COMMAND_IDS: tuple[str, ...] = (
    "pytest",
    "ruff",
    "pyright_src",
    "pyright_full",
)


@dataclass(frozen=True)
class CommandSummary:
    command_id: str
    receipt_path: str
    receipt_sha256: str
    stdout_path: str
    stdout_sha256: str
    stderr_path: str
    stderr_sha256: str
    exit_code: int
    exit_code_sha256: str
    gate: str

    def to_dict(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "receipt_path": self.receipt_path,
            "receipt_sha256": self.receipt_sha256,
            "stdout_path": self.stdout_path,
            "stdout_sha256": self.stdout_sha256,
            "stderr_path": self.stderr_path,
            "stderr_sha256": self.stderr_sha256,
            "exit_code": self.exit_code,
            "exit_code_sha256": self.exit_code_sha256,
            "gate": self.gate,
        }


@dataclass(frozen=True)
class CommandEvidenceManifest:
    phase: str
    required_receipts: int
    valid_receipts: int
    missing_receipts: tuple[str, ...]
    invalid_receipts: tuple[str, ...]
    summaries: tuple[CommandSummary, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "required_receipts": self.required_receipts,
            "valid_receipts": self.valid_receipts,
            "missing_receipts": list(self.missing_receipts),
            "invalid_receipts": list(self.invalid_receipts),
            "summaries": [s.to_dict() for s in self.summaries],
        }


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensure_file(path: Path) -> None:
    """Ensure a file exists; create empty if absent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(b"")


def run_and_record_command(
    *,
    command_id: str,
    command: str,
    cwd: Path,
    out_dir: Path,
    artifact_root: Path | None = None,
    timeout: int | None = 300,
) -> CommandSummary:
    """Run a shell command and persist stdout/stderr + receipt JSON."""
    import subprocess as _sp
    from datetime import UTC
    from datetime import datetime as _dt

    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{command_id}.stdout.txt"
    stderr_path = out_dir / f"{command_id}.stderr.txt"

    started = _dt.now(UTC).isoformat()
    exit_code = 1
    stdout_data = b""
    stderr_data = b""
    proc: _sp.Popen | None = None
    try:
        proc = _sp.Popen(
            command,
            shell=False,
            cwd=str(cwd),
            stdout=_sp.PIPE,
            stderr=_sp.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
            stdout_data = stdout_bytes or b""
            stderr_data = stderr_bytes or b""
            exit_code = proc.returncode
        except _sp.TimeoutExpired:
            if proc is not None:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except _sp.TimeoutExpired:
                    pass
            stdout_data = b"TIMEOUT: process killed after %d seconds" % timeout
            stderr_data = b"TIMEOUT: process killed after %d seconds" % timeout
            exit_code = -1
    except Exception as exc:
        stderr_data = f"EXCEPTION: {exc}".encode()
        exit_code = -1
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
    finished = _dt.now(UTC).isoformat()

    # Always write actual bytes (even empty).
    stdout_path.write_bytes(stdout_data)
    stderr_path.write_bytes(stderr_data)
    exit_code_path = out_dir / f"{command_id}.exit.txt"
    exit_code_path.write_text(str(exit_code), encoding="utf-8")

    actual_stdout_sha = _hash_file(stdout_path)
    actual_stderr_sha = _hash_file(stderr_path)
    actual_stdout_size = stdout_path.stat().st_size
    actual_stderr_size = stderr_path.stat().st_size

    cmd_id_digest = hashlib.sha256(f"{cwd}:{command}".encode()).hexdigest()[:16]

    # Compute package-relative path (the path under the package root
    # where the stdout/stderr will live). out_dir is the test_evidence
    # directory; artifact_root is the package root (review/).
    # out_dir = review/test_evidence/
    # artifact_root (review/) = out_dir.parent
    try:
        if artifact_root is not None:
            stdout_rel = stdout_path.relative_to(artifact_root).as_posix()
            stderr_rel = stderr_path.relative_to(artifact_root).as_posix()
            stdout_pkg_path = stdout_rel
            stderr_pkg_path = stderr_rel
        else:
            package_root = out_dir.parent.parent
            stdout_pkg_path = stdout_path.relative_to(package_root).as_posix()
            stderr_pkg_path = stderr_path.relative_to(package_root).as_posix()
    except ValueError:
        stdout_pkg_path = stdout_path.name
        stderr_pkg_path = stderr_path.name

    receipt_payload = {
        "command_id": cmd_id_digest,
        "sanitized_command": command,
        "working_directory": str(cwd),
        "started_at": started,
        "finished_at": finished,
        "exit_code": exit_code,
        "stdout_artifact": {
            "path": stdout_pkg_path,
            "sha256": actual_stdout_sha,
            "size_bytes": actual_stdout_size,
        },
        "stderr_artifact": {
            "path": stderr_pkg_path,
            "sha256": actual_stderr_sha,
            "size_bytes": actual_stderr_size,
        },
        "exit_code_artifact": {
            "path": stdout_pkg_path.replace(".stdout.txt", ".exit.txt"),
            "sha256": hashlib.sha256(str(exit_code).encode("ascii")).hexdigest(),
            "size_bytes": len(str(exit_code).encode("ascii")),
        },
        "gate": "PASS" if exit_code == 0 else "FAIL",
    }
    ok, _violations = validate_command_receipt(receipt_payload)
    if not ok:
        raise ValueError(
            f"generated receipt for {command_id} failed schema validation: {_violations}"
        )

    receipt_path = out_dir / f"{command_id}.json"
    receipt_path.write_text(
        json.dumps(receipt_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    receipt_sha = _hash_file(receipt_path)
    exit_code_sha = hashlib.sha256(str(exit_code).encode("ascii")).hexdigest()
    return CommandSummary(
        command_id=command_id,
        receipt_path=receipt_path.name,
        receipt_sha256=receipt_sha,
        stdout_path=stdout_path.name,
        stdout_sha256=actual_stdout_sha,
        stderr_path=stderr_path.name,
        stderr_sha256=actual_stderr_sha,
        exit_code=exit_code,
        exit_code_sha256=exit_code_sha,
        gate=receipt_payload["gate"],
    )


def build_command_evidence_manifest(
    *,
    phase: str,
    command_receipts_dir: Path,
    artifact_root: Path | None = None,
    required_ids: Iterable[str] = REQUIRED_COMMAND_IDS,
) -> CommandEvidenceManifest:
    """Aggregate existing receipt files into a manifest.

    ``artifact_root`` is the review package root (the parent of ``command_receipts_dir``).
    All artifact paths stored in receipts are relative to ``artifact_root`` and are
    resolved safely without path traversal or absolute path assumptions.
    """
    if artifact_root is None:
        artifact_root = command_receipts_dir.parent
    required = tuple(required_ids)
    missing: list[str] = []
    invalid: list[str] = []
    summaries: list[CommandSummary] = []
    for cid in required:
        receipt_path = command_receipts_dir / f"{cid}.json"
        if not receipt_path.is_file():
            missing.append(cid)
            continue
        try:
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            invalid.append(cid)
            continue
        ok, _violations = validate_command_receipt(payload)
        if not ok:
            invalid.append(cid)
            continue
        stdout_rel = payload["stdout_artifact"]["path"]
        stderr_rel = payload["stderr_artifact"]["path"]
        if not isinstance(stdout_rel, str) or not isinstance(stderr_rel, str):
            invalid.append(cid)
            continue
        _has_traversal = (
            stdout_rel.startswith("/")
            or ".." in stdout_rel
            or stderr_rel.startswith("/")
            or ".." in stderr_rel
        )
        if _has_traversal:
            invalid.append(cid)
            continue
        stdout_path = (artifact_root / stdout_rel).resolve()
        stderr_path = (artifact_root / stderr_rel).resolve()
        artifact_root_resolved = artifact_root.resolve()
        if not stdout_path.is_file() or not stderr_path.is_file():
            invalid.append(cid)
            continue
        _stdout_ok = str(stdout_path).startswith(str(artifact_root_resolved))
        _stderr_ok = str(stderr_path).startswith(str(artifact_root_resolved))
        if not _stdout_ok or not _stderr_ok:
            invalid.append(cid)
            continue
        actual_stdout_sha = _hash_file(stdout_path)
        actual_stderr_sha = _hash_file(stderr_path)
        if (
            actual_stdout_sha != payload["stdout_artifact"]["sha256"]
            or actual_stderr_sha != payload["stderr_artifact"]["sha256"]
            or stdout_path.stat().st_size != payload["stdout_artifact"]["size_bytes"]
            or stderr_path.stat().st_size != payload["stderr_artifact"]["size_bytes"]
        ):
            invalid.append(cid)
            continue
        exit_art = payload.get("exit_code_artifact", {})
        exit_rel = exit_art.get("path") if isinstance(exit_art, dict) else None
        exit_code_sha256 = ""
        if isinstance(exit_rel, str) and not exit_rel.startswith("/") and ".." not in exit_rel:
            exit_path = (artifact_root / exit_rel).resolve()
            if exit_path.is_file():
                if not str(exit_path).startswith(str(artifact_root_resolved)):
                    invalid.append(cid)
                    continue
                exit_code_sha256 = _hash_file(exit_path)
                if exit_code_sha256 != exit_art.get("sha256"):
                    invalid.append(cid)
                    continue
                try:
                    actual_exit_code = int(exit_path.read_text(encoding="utf-8").strip())
                    if actual_exit_code != int(payload["exit_code"]):
                        invalid.append(cid)
                        continue
                except (ValueError, OSError):
                    invalid.append(cid)
                    continue
        summary = CommandSummary(
            command_id=cid,
            receipt_path=receipt_path.name,
            receipt_sha256=_hash_file(receipt_path),
            stdout_path=stdout_path.name,
            stdout_sha256=actual_stdout_sha,
            stderr_path=stderr_path.name,
            stderr_sha256=actual_stderr_sha,
            exit_code=int(payload["exit_code"]),
            exit_code_sha256=exit_code_sha256,
            gate=str(payload["gate"]),
        )
        summaries.append(summary)
    return CommandEvidenceManifest(
        phase=phase,
        required_receipts=len(required),
        valid_receipts=len(summaries),
        missing_receipts=tuple(missing),
        invalid_receipts=tuple(invalid),
        summaries=tuple(summaries),
    )


def write_command_evidence_manifest(manifest: CommandEvidenceManifest, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(manifest.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_path


__all__ = [
    "CommandEvidenceManifest",
    "CommandSummary",
    "REQUIRED_COMMAND_IDS",
    "build_command_evidence_manifest",
    "run_and_record_command",
    "write_command_evidence_manifest",
]
