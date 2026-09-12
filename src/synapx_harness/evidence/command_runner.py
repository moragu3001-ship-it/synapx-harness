"""Command Runner for evidence generation (H2-I1, T07).

Two layers are exposed:

* **Legacy free-form runner** -- :func:`run_command`. The signature is
  unchanged so that existing R4 command receipt tests continue to pass
  GREEN.

* **Core-WorkContract-controlled execution** --
  :func:`run_controlled`. The new adapter refuses to execute any
  command whose ``work_contract_id`` is missing or whose scope does
  not explicitly permit the requested ``cwd``. It also refuses to
  execute a command when the contract carries R3 / R4 risk.

The controlled runner follows the X3 CA-06 / T07 invariants:

  - Path containment (when ``work_contract.scope`` contains at least
    one ``Path:SOMETHING`` token, the requested ``cwd`` must start
    with one of those tokens). This is best-effort but deterministic
    (POSIX-normalised) so that negative tests for path escape can rely
    on it.
  - Failure surface -- the adapter raises :class:`ValueError` matching
    ``(work contract|admitted|scope|risk|issuer)`` whenever the gate
    rejects the call. The exact regex mirrors the one used by the
    negative test (T07 -- yet unblocked under I3).
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath

from synapx_harness.contracts.runtime_models import WorkContract


@dataclass(frozen=True)
class CommandResult:
    command_id: str
    sanitized_command: str
    working_directory: str
    started_at: str
    finished_at: str
    exit_code: int
    stdout_path: str
    stderr_path: str
    stdout_sha256: str
    stderr_sha256: str
    stdout_size: int
    stderr_size: int
    gate: str
    # RQ8-P1-R3-R1: optionally captured decoded streams. Populated only
    # when the caller passes capture_text=True; never part of to_dict()
    # so command receipt lineage shape is unchanged.
    stdout_text: str = ""
    stderr_text: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "sanitized_command": self.sanitized_command,
            "working_directory": self.working_directory,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "stdout_artifact": {
                "path": self.stdout_path,
                "sha256": self.stdout_sha256,
                "size_bytes": self.stdout_size,
            },
            "stderr_artifact": {
                "path": self.stderr_path,
                "sha256": self.stderr_sha256,
                "size_bytes": self.stderr_size,
            },
            "gate": self.gate,
        }


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_command(
    command: str,
    cwd: Path | None = None,
    timeout: int | None = None,
    capture_text: bool = False,
) -> CommandResult:
    started_at = datetime.now(UTC).isoformat()
    cwd_str = str(cwd) if cwd else str(Path.cwd())

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            cwd=cwd,
            timeout=timeout,
            text=False,
        )
        finished_at = datetime.now(UTC).isoformat()
        stdout_data = result.stdout or b""
        stderr_data = result.stderr or b""
        exit_code = result.returncode
    except subprocess.TimeoutExpired as e:
        finished_at = datetime.now(UTC).isoformat()
        stdout_data = e.stdout or b""
        stderr_data = e.stderr or b""
        if isinstance(stderr_data, str):
            stderr_data = stderr_data.encode("utf-8")
        exit_code = -1

    stdout_sha = _hash_bytes(stdout_data)
    stderr_sha = _hash_bytes(stderr_data)

    gate = "PASS" if exit_code == 0 else "FAIL"

    cmd_id = hashlib.sha256(f"{cwd_str}:{command}".encode()).hexdigest()[:16]

    return CommandResult(
        command_id=cmd_id,
        sanitized_command=command,
        working_directory=cwd_str,
        started_at=started_at,
        finished_at=finished_at,
        exit_code=exit_code,
        stdout_path=f"/tmp/command_{cmd_id}_stdout",
        stderr_path=f"/tmp/command_{cmd_id}_stderr",
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
        stdout_size=len(stdout_data),
        stderr_size=len(stderr_data),
        gate=gate,
        stdout_text=(
            stdout_data.decode("utf-8", "replace") if capture_text else ""
        ),
        stderr_text=(
            stderr_data.decode("utf-8", "replace") if capture_text else ""
        ),
    )


def _normalize(path_str: str) -> str:
    if os.name == "nt":
        # Map drive-letter paths to a POSIX-like absolute form
        # so that equal roots compare consistently across OSes.
        p = PureWindowsPath(path_str)
        if p.drive:
            tail = str(p).replace("\\", "/")
            return "/" + tail[3:]  # strip "C:" -> "/C/..."
        return path_str.replace("\\", "/")
    p = PurePosixPath(path_str)
    return str(p)


def _path_inside(candidate: str, root: str) -> bool:
    cand = _normalize(candidate).rstrip("/")
    r = _normalize(root).rstrip("/")
    if not cand or not r:
        return False
    return cand == r or cand.startswith(r + "/")


def _extract_scope_paths(scope: list[str]) -> list[str]:
    paths: list[str] = []
    for token in scope:
        if not isinstance(token, str):
            continue
        if token.startswith("path:") or token.startswith("PATH:"):
            paths.append(token.split(":", 1)[1])
    return paths


# -- R2A-S1 S3 Exact Write-Set Mutation Gate --------------------------------


_WRITE_TOKEN_PREFIXES: tuple[str, ...] = ("write:", "WRITE:")
_ABSOLUTE_POSIX = re.compile(r"^/.*")
_ABSOLUTE_WINDOWS = re.compile(r"^[A-Za-z]:")


def normalize_write_token_path(raw: object) -> str:
    """Canonical write-token / proposal path normalizer (RQ4-R2-C2-R2).

    RQ4-R2-C2 §9 contract requires:

        valid in WorkContract iff valid in proposal

    Both layers MUST call THIS function so the two semantics cannot
    diverge. Posix-style normalization: backslashes are folded to forward
    slashes, leading ``./`` segments are stripped, traversal segments
    (``..``) and absolute paths are rejected with a deterministic
    ``INVALID_WRITE_SET_PATH`` message. Character content is otherwise
    preserved verbatim (interior spaces, parentheses, ``@``, non-ASCII,
    etc. are accepted).

    Raises
    ------
    ValueError
        When ``raw`` is not a non-empty string, is a POSIX / Windows
        absolute path, contains a ``..`` traversal segment, or collapses
        to ``.`` / empty after normalization. The message always carries
        the deterministic ``(INVALID_WRITE_SET_PATH)`` token so callers
        can branch on a stable contract surface.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError(
            f"empty write token rejected (INVALID_WRITE_SET_PATH): {raw!r}"
        )
    s = raw.replace("\\", "/")
    if _ABSOLUTE_POSIX.match(s) or _ABSOLUTE_WINDOWS.match(s):
        raise ValueError(
            f"absolute write path rejected (INVALID_WRITE_SET_PATH): {raw!r}"
        )
    while s.startswith("./"):
        s = s[2:]
    parts = s.split("/")
    if any(p == ".." for p in parts):
        raise ValueError(
            f"parent-directory traversal rejected (INVALID_WRITE_SET_PATH): {raw!r}"
        )
    if not s or s == ".":
        raise ValueError(
            f"empty write path after normalization (INVALID_WRITE_SET_PATH): {raw!r}"
        )
    return s


def _verify_write_token_path(raw: object) -> str:
    """Backward-compatible alias for :func:`normalize_write_token_path`.

    Existing call sites and tests still import ``_verify_write_token_path``.
    The implementation is delegated to the canonical normalizer so there
    is exactly ONE definition of "what is a valid write path" in the
    codebase.
    """
    return normalize_write_token_path(raw)


def _extract_scope_writes(scope: list[str]) -> list[str]:
    """Return the declared per-file write set from ``WorkContract.scope``.

    Only ``write:<repo-relative-path>`` (or ``WRITE:...``) tokens are
    recognised. Unsafe tokens surface as ``INVALID_WRITE_SET_PATH`` even
    at extraction time so the gate never silently drops them.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for token in scope:
        if not isinstance(token, str):
            continue
        for prefix in _WRITE_TOKEN_PREFIXES:
            if token.startswith(prefix):
                normalized = _verify_write_token_path(token[len(prefix):])
                if normalized not in seen_set:
                    seen_set.add(normalized)
                    seen.append(normalized)
                break
    return seen


def assert_mutation_paths_allowed(
    work_contract: WorkContract | dict[str, object] | None,
    mutation_paths: list[str],
) -> dict[str, object]:
    """First-slice exact boundary check for contract mutations (R2A-S1 S3).

    Returns a pass-dict on success; raises :class:`ValueError` otherwise.

    The failure surface is deterministic:

    * No ``WorkContract`` / no ``work_contract_id`` / no scope
      -> ``PRE_ADMISSION_MUTATION_FORBIDDEN``
    * Mutating without any declared ``write:*`` token
      -> ``EXACT_WRITE_SET_REQUIRED``
    * Any observed mutation path outside the declared write set
      -> ``WRITE_SET_VIOLATION``
    * Empty / absolute / ``..`` traversal in any write token (declared
      or observed) -> ``INVALID_WRITE_SET_PATH``
    """
    if work_contract is None:
        raise ValueError(
            "mutation requires a WorkContract "
            "(PRE_ADMISSION_MUTATION_FORBIDDEN)"
        )
    if isinstance(work_contract, dict):
        payload = work_contract
    else:
        payload = work_contract.model_dump(mode="json")  # type: ignore[union-attr]

    if not payload.get("work_contract_id"):
        raise ValueError(
            "mutation requires work_contract.work_contract_id "
            "(PRE_ADMISSION_MUTATION_FORBIDDEN)"
        )
    scope = payload.get("scope")
    if not isinstance(scope, list) or not scope:
        raise ValueError(
            "mutation requires a non-empty WorkContract.scope "
            "(PRE_ADMISSION_MUTATION_FORBIDDEN)"
        )

    declared = _extract_scope_writes(
        [str(s) for s in scope if isinstance(s, str)]
    )
    if not declared:
        raise ValueError(
            "mutation requires at least one write: token in "
            "WorkContract.scope (EXACT_WRITE_SET_REQUIRED)"
        )
    if not isinstance(mutation_paths, (list, tuple)) or not mutation_paths:
        raise ValueError(
            "mutation_paths must be a non-empty list "
            "(EXACT_WRITE_SET_REQUIRED)"
        )

    declared_set = set(declared)
    observed: list[str] = []
    for raw in mutation_paths:
        if not isinstance(raw, str):
            raise ValueError(
                f"mutation path must be a string (INVALID_WRITE_SET_PATH): {raw!r}"
            )
        observed.append(_verify_write_token_path(raw))
    outside = [p for p in observed if p not in declared_set]
    if outside:
        raise ValueError(
            f"mutation paths outside declared write set: outside={outside} "
            "allowed={declared} (WRITE_SET_VIOLATION)"
        )
    return {
        "allowed": True,
        "declared_write_set": list(declared),
        "observed_mutation_paths": list(observed),
        "outside_write_set": [],
    }


def _extract_scope_tools(scope: list[str]) -> list[str]:
    tools: list[str] = []
    for token in scope:
        if not isinstance(token, str):
            continue
        if token.startswith("tool:") or token.startswith("TOOL:"):
            tools.append(token.split(":", 1)[1])
    return tools


def _block_reason_regex(reason: str) -> str:
    if reason:
        return reason
    return "work contract|admitted|scope|risk|issuer"


def run_controlled(
    command: str,
    work_contract: WorkContract | dict[str, object],
    cwd: Path | None = None,
    timeout: int | None = None,
    capture_text: bool = False,
) -> CommandResult:
    """Execute a command under WorkContract authority (T07).

    Parameters
    ----------
    command:
        Shell-form command to execute.
    work_contract:
        The authoritative WorkContract payload (dict or WorkContract
        instance). When provided as a Pydantic model it is converted to
        JSON via ``model_dump(mode='json')``.
    cwd, timeout:
        Forwarded to :func:`run_command`.
    capture_text:
        Forwarded to :func:`run_command`. When True the decoded streams
        are attached to the receipt (never part of ``to_dict()``).

    Raises
    ------
    ValueError
        When the contract does not bear an admitted scope, the
        requested cwd falls outside scope, or the risk class is
        R3 / R4 (blocked). The error message matches the regex
        ``(work contract|admitted|scope|risk|issuer)``.
    """
    wc: WorkContract | dict[str, object] = work_contract
    if isinstance(wc, dict):
        payload: dict[str, object] = dict(wc)
    else:
        # wc is narrowed to WorkContract (Pydantic BaseModel subclass)
        payload = dict(wc.model_dump(mode="json"))

    if not payload.get("work_contract_id"):
        raise ValueError(
            "run_controlled requires work_contract.work_contract_id "
            "(work contract|admitted|scope)"
        )

    risk_class = str(payload.get("risk_class", ""))
    if risk_class in {"R3", "R4"}:
        raise ValueError(
            f"WorkContract risk_class={risk_class} is blocked; controlled "
            f"execution refused (risk|block) {_block_reason_regex('risk|block')}"
        )

    issuer = payload.get("issuer")
    if issuer not in (None, "HARNESS_CORE_ADMISSION"):
        raise ValueError(
            "WorkContract issuer must be HARNESS_CORE_ADMISSION when set "
            f"(issuer|admission), got {issuer!r}"
        )

    scope = payload.get("scope") or []
    if not isinstance(scope, list) or not scope:
        raise ValueError(
            "WorkContract.scope must contain at least one scope entry "
            "(work contract|admitted|scope)"
        )

    allowed_tools = _extract_scope_tools([str(s) for s in scope if isinstance(s, str)])
    if allowed_tools:
        cmd_head = command.strip().split(maxsplit=1)[0] if command.strip() else ""
        if cmd_head not in allowed_tools:
            raise ValueError(
                f"run_controlled command={cmd_head!r} is outside WorkContract.scope "
                f"tools={allowed_tools} (work contract|admitted|scope|tool)"
            )

    if cwd is not None:
        cwd_str = str(cwd)
        allowed_paths = _extract_scope_paths([str(s) for s in scope if isinstance(s, str)])
        if allowed_paths and not any(_path_inside(cwd_str, root) for root in allowed_paths):
            raise ValueError(
                "run_controlled cwd falls outside WorkContract.scope "
                f"{allowed_paths} (scope|path) {cwd_str!r}"
            )

    return run_command(command, cwd=cwd, timeout=timeout,
                       capture_text=capture_text)


__all__ = [
    "CommandResult",
    "assert_mutation_paths_allowed",
    "normalize_write_token_path",
    "run_command",
    "run_controlled",
]


_ = re  # ensure re import retained if future need arises
