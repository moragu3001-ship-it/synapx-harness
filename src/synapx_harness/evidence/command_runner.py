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


def _persist_artifact_bytes(
    artifact_dir: Path,
    stdout_data: bytes,
    stderr_data: bytes,
) -> tuple[str, str, str, int, str, int]:
    """Persist raw subprocess stdout/stderr bytes to disk and return the
    authoritative artifact identity.

    RQ8-P1-R3-R3 §11-§12: when the caller passes ``artifact_dir``, the
    runner writes the raw subprocess bytes directly to disk (no
    decode/re-encode round trip) and re-reads the persisted file to
    compute SHA/size. The returned values are the authoritative artifact
    truth consumed by ``CommandResult`` and downstream observers.

    Returns
    -------
    ``(stdout_path, stderr_path, stdout_sha256, stdout_size,
       stderr_sha256, stderr_size)``
    """
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = artifact_dir / "stdout.log"
    stderr_path = artifact_dir / "stderr.log"
    stdout_path.write_bytes(stdout_data)
    stderr_path.write_bytes(stderr_data)
    # Re-read from disk so the receipt identity matches the persisted
    # artifact bytes exactly (defence-in-depth against any in-memory
    # mutation between write and hash).
    on_disk_stdout = stdout_path.read_bytes()
    on_disk_stderr = stderr_path.read_bytes()
    return (
        stdout_path.as_posix(),
        stderr_path.as_posix(),
        _hash_bytes(on_disk_stdout),
        len(on_disk_stdout),
        _hash_bytes(on_disk_stderr),
        len(on_disk_stderr),
    )


def run_command(
    command: str,
    cwd: Path | None = None,
    timeout: int | None = None,
    capture_text: bool = False,
    artifact_dir: Path | None = None,
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

    gate = "PASS" if exit_code == 0 else "FAIL"

    cmd_id = hashlib.sha256(f"{cwd_str}:{command}".encode()).hexdigest()[:16]

    if artifact_dir is not None:
        (
            stdout_path,
            stderr_path,
            stdout_sha,
            stdout_size,
            stderr_sha,
            stderr_size,
        ) = _persist_artifact_bytes(
            Path(artifact_dir), stdout_data, stderr_data
        )
    else:
        # Legacy placeholder path: no on-disk artifact, no persisted
        # bytes. Caller (or downstream observation stage) is responsible
        # for any artifact persistence if needed.
        stdout_sha = _hash_bytes(stdout_data)
        stderr_sha = _hash_bytes(stderr_data)
        stdout_size = len(stdout_data)
        stderr_size = len(stderr_data)
        stdout_path = f"/tmp/command_{cmd_id}_stdout"
        stderr_path = f"/tmp/command_{cmd_id}_stderr"

    return CommandResult(
        command_id=cmd_id,
        sanitized_command=command,
        working_directory=cwd_str,
        started_at=started_at,
        finished_at=finished_at,
        exit_code=exit_code,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        stdout_sha256=stdout_sha,
        stderr_sha256=stderr_sha,
        stdout_size=stdout_size,
        stderr_size=stderr_size,
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


def _require_artifact_dir_in_scope(
    artifact_dir: Path | str,
    scope: list[str],
    cwd: Path | None,
) -> Path:
    """Resolve ``artifact_dir`` and require WorkContract path containment.

    RQ8-P1-R3-R3-R1 §4-§6, §8: the artifact directory is a controlled
    filesystem side effect (``mkdir -p`` plus ``stdout.log`` /
    ``stderr.log`` writes), so it must sit inside at least one
    authoritative ``path:`` scope root. Containment is decided on
    ``resolve()``d paths via the canonical :func:`_path_inside` seam --
    no new path-comparison semantics. The resolved final artifact files
    are checked as well so a pre-existing symlink pointing outside
    scope fails closed instead of escaping on write.

    Returns the resolved artifact directory. Raises :class:`ValueError`
    (matching the ``(work contract|admitted|scope|risk|issuer)`` denial
    surface) when no ``path:`` scope exists or anything resolves
    outside scope.
    """
    allowed_paths = _extract_scope_paths(
        [str(s) for s in scope if isinstance(s, str)]
    )
    if not allowed_paths:
        raise ValueError(
            "run_controlled artifact_dir requires an authoritative "
            "path:* entry in WorkContract.scope "
            "(work contract|admitted|scope)"
        )
    base = Path(cwd) if cwd is not None else Path.cwd()
    candidate = Path(artifact_dir)
    resolved_dir = (
        (base / candidate).resolve()
        if not candidate.is_absolute()
        else candidate.resolve()
    )
    if not any(
        _path_inside(str(resolved_dir), root) for root in allowed_paths
    ):
        raise ValueError(
            "run_controlled artifact_dir falls outside WorkContract.scope "
            f"{allowed_paths} (scope|path) {str(resolved_dir)!r}"
        )
    for name in ("stdout.log", "stderr.log"):
        resolved_file = (resolved_dir / name).resolve()
        if not any(
            _path_inside(str(resolved_file), root)
            for root in allowed_paths
        ):
            raise ValueError(
                "run_controlled artifact file escapes WorkContract.scope "
                f"{allowed_paths} (scope|path) {str(resolved_file)!r}"
            )
    return resolved_dir


def run_controlled(
    command: str,
    work_contract: WorkContract | dict[str, object],
    cwd: Path | None = None,
    timeout: int | None = None,
    capture_text: bool = False,
    artifact_dir: Path | None = None,
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
    cwd, timeout, capture_text, artifact_dir:
        Forwarded to :func:`run_command`. ``artifact_dir`` (RQ8-P1-R3-R3
        §11) optionally persists the raw subprocess stdout/stderr bytes
        to ``<artifact_dir>/stdout.log`` and ``<artifact_dir>/stderr.log``
        and exposes their authoritative identity through the returned
        ``CommandResult``. When ``artifact_dir`` is ``None`` the legacy
        placeholder path shape is preserved (no on-disk artifact).
        A non-``None`` ``artifact_dir`` is resolved and gated against
        the authoritative ``path:`` scope roots (RQ8-P1-R3-R3-R1 §4-§6)
        BEFORE any subprocess starts; the resolved directory is what
        the runner persists to, so the receipt path is canonical.

    Raises
    ------
    ValueError
        When the contract does not bear an admitted scope, the
        requested cwd falls outside scope, the risk class is
        R3 / R4 (blocked), or a requested ``artifact_dir`` (or its
        resolved artifact files) falls outside the ``path:`` scope.
        The error message matches the regex
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

    # RQ8-P1-R3-R3-R1 §5, §9: artifact-dir scope is enforced BEFORE the
    # tool/cwd gates and before any subprocess starts, so a denial can
    # never leave a partially executed command behind.
    resolved_artifact_dir: Path | None = None
    if artifact_dir is not None:
        resolved_artifact_dir = _require_artifact_dir_in_scope(
            artifact_dir,
            [str(s) for s in scope if isinstance(s, str)],
            cwd,
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

    return run_command(
        command,
        cwd=cwd,
        timeout=timeout,
        capture_text=capture_text,
        artifact_dir=(
            resolved_artifact_dir if resolved_artifact_dir is not None
            else None
        ),
    )


__all__ = [
    "CommandResult",
    "assert_mutation_paths_allowed",
    "normalize_write_token_path",
    "run_command",
    "run_controlled",
]


_ = re  # ensure re import retained if future need arises
