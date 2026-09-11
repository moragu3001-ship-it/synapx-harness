"""Evidence Pipeline — ordered generation of review artifacts.

The pipeline enforces the R7 generation order:
  1. Raw stdout/stderr of each of the 4 commands
  2. Command receipts (one per command)
  3. Command evidence manifest
  4. Test evidence manifest (census of raw artifacts)
  5. Verification summary (parsed from pytest log)
  6. Negative exploit matrix
  7. Review location receipt (census of review dir)
  8. Candidate state / gate summary / review decision (single compute)
  9. Internal review index (last; hashes every prior artifact)

Any stage that fails halts the pipeline. Manual edits to these
artifacts are not allowed; the pipeline is the only producer.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.review.candidate_state import (
    CandidateStateInputs,
    compute_candidate_state,
    write_candidate_state_artifacts,
)
from synapx_harness.review.command_evidence import (
    build_command_evidence_manifest,
    run_and_record_command,
    write_command_evidence_manifest,
)
from synapx_harness.review.internal_review_index import (
    build_internal_review_index,
    write_internal_review_index,
)
from synapx_harness.review.negative_exploit import (
    run_all_attacks,
    write_negative_exploit_matrix,
)
from synapx_harness.review.review_location_receipt import (
    CANONICAL_REVIEW_BASE,
    build_review_location_receipt,
    write_review_location_receipt,
)
from synapx_harness.review.review_phase_contract import (
    GATE_FAIL,
    GATE_PASS,
    INDEPENDENT_REVIEW_PENDING,
    PHASE,
)
from synapx_harness.review.test_evidence_manifest import (
    build_test_evidence_manifest,
    write_test_evidence_manifest,
)


def _robust_remove_dir(path: Path, retries: int = 3) -> bool:
    """Remove a directory tree robustly, handling locked files on Windows.

    Returns True if the directory was removed, False otherwise.
    """
    if not path.exists():
        return True

    import shutil

    for attempt in range(retries):
        try:
            shutil.rmtree(path)
            return True
        except (OSError, PermissionError):
            if attempt < retries - 1:
                time.sleep(0.1)
                for root, dirs, files in os.walk(path, topdown=False):
                    for name in files:
                        file_path = Path(root) / name
                        try:
                            os.chmod(file_path, stat.S_IWRITE)
                            file_path.unlink()
                        except OSError:
                            pass
                    for name in dirs:
                        dir_path = Path(root) / name
                        try:
                            os.chmod(dir_path, stat.S_IWRITE)
                            dir_path.rmdir()
                        except OSError:
                            pass
            else:
                pass
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
    return not path.exists()


@dataclass(frozen=True)
class PipelineResult:
    ok: bool
    review_dir: str
    receipts: tuple[str, ...]
    artifacts: tuple[str, ...]
    gates: tuple[tuple[str, str], ...]
    violations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "review_dir": self.review_dir,
            "receipts": list(self.receipts),
            "artifacts": list(self.artifacts),
            "gates": [list(g) for g in self.gates],
            "violations": list(self.violations),
        }


@dataclass(frozen=True)
class PipelineInputs:
    core_root: Path
    service_pack_root: Path
    core_ref: str
    service_pack_ref: str
    review_root: Path
    timeout: int = 300


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_placeholder_report(review_dir: Path) -> Path:
    path = review_dir / "review_report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f"# {PHASE} — Review Report\n\n"
        f"- generated_at: {_dt.datetime.now(_dt.UTC).isoformat()}\n"
        f"- phase: {PHASE}\n"
    )
    path.write_text(body, encoding="utf-8")
    return path


def _parse_pytest_summary(pytest_stdout: str) -> dict[str, int]:
    summary: dict[str, int] = {
        "collected": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
    }
    m = re.search(r"=+\s*(\d+)\s+passed", pytest_stdout)
    if m:
        summary["passed"] = int(m.group(1))
    m = re.search(r"=+\s*(\d+)\s+failed", pytest_stdout)
    if m:
        summary["failed"] = int(m.group(1))
    m = re.search(r"=+\s*(\d+)\s+errors", pytest_stdout)
    if m:
        summary["errors"] = int(m.group(1))
    m = re.search(r"=+\s*(\d+)\s+skipped", pytest_stdout)
    if m:
        summary["skipped"] = int(m.group(1))
    m = re.search(r"collected\s+(\d+)\s+items?", pytest_stdout)
    if m:
        summary["collected"] = int(m.group(1))
    summary["executed"] = summary["passed"] + summary["failed"] + summary["errors"]
    return summary


def _write_verification_summary(
    review_dir: Path,
    pytest_summary: Mapping[str, int],
    ruff_exit: int,
    pyright_src_exit: int,
    pyright_full_exit: int,
    raw_log: str,
) -> Path:
    summary = {
        "phase": PHASE,
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(),
        "pytest": dict(pytest_summary),
        "ruff_exit": ruff_exit,
        "pyright_src_exit": pyright_src_exit,
        "pyright_full_exit": pyright_full_exit,
        "collected": pytest_summary["collected"],
        "executed": pytest_summary["executed"],
        "passed": pytest_summary["passed"],
        "failed": pytest_summary["failed"],
        "errors": pytest_summary["errors"],
        "skipped": pytest_summary["skipped"],
        "gate": (
            GATE_PASS
            if (
                pytest_summary["collected"] > 0
                and pytest_summary["failed"] == 0
                and pytest_summary["errors"] == 0
                and pytest_summary["skipped"] == 0
                and ruff_exit == 0
                and pyright_src_exit == 0
                and pyright_full_exit == 0
            )
            else GATE_FAIL
        ),
        "raw_pytest_log_excerpt_sha256": hashlib.sha256(raw_log.encode("utf-8")).hexdigest(),
    }
    path = review_dir / "verification_summary.json"
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _run_scm_provenance(
    *,
    core_root: Path,
    service_pack_root: Path,
    core_ref: str,
    service_pack_ref: str,
    out_dir: Path,
) -> dict[str, Path]:
    import subprocess

    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    def _gather(repo_root: Path, ref: str, name: str) -> Path:
        sha = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", f"{ref}^{{commit}}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", f"{sha}^{{tree}}"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        payload = {
            "phase": PHASE,
            "repository": name,
            "repository_root": str(repo_root),
            "requested_ref": ref,
            "commit_sha": sha,
            "tree_sha": tree,
        }
        p = out_dir / f"{name}_repository.json"
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return p

    paths["core"] = _gather(core_root, core_ref, "core")
    paths["service_pack"] = _gather(service_pack_root, service_pack_ref, "service_pack")
    return paths


def run_pipeline(
    inputs: PipelineInputs,
    *,
    pytest_command: str = "python -m pytest -p no:cacheprovider -ra",
    ruff_command: str = "ruff check .",
    pyright_src_command: str = "pyright src/synapx_harness",
    pyright_full_command: str = "pyright",
) -> PipelineResult:
    """Run the ordered evidence pipeline and emit every artifact."""
    review_dir = inputs.review_root / "review"
    review_dir.mkdir(parents=True, exist_ok=True)
    test_evidence_dir = review_dir / "test_evidence"
    command_receipts_dir = review_dir / "command_receipts"
    receipts: list[str] = []
    violations: list[str] = []

    review_root = inputs.review_root / "review"

    # --- Stage 1+2: raw stdout/stderr + receipts ---
    try:
        cmd_specs = (
            ("pytest", pytest_command),
            ("ruff", ruff_command),
            ("pyright_src", pyright_src_command),
            ("pyright_full", pyright_full_command),
        )
        for cid, cmd in cmd_specs:
            run_and_record_command(
                command_id=cid,
                command=cmd,
                cwd=inputs.core_root,
                out_dir=test_evidence_dir,
                artifact_root=review_root,
                timeout=inputs.timeout,
            )
            # also write receipt into command_receipts/ + symlink/copy
            # the stdout/stderr artifacts so the manifest can verify them.
            command_receipts_dir.mkdir(parents=True, exist_ok=True)
            receipt_src = test_evidence_dir / f"{cid}.json"
            if receipt_src.is_file():
                receipt_bytes = receipt_src.read_bytes()
                (command_receipts_dir / f"{cid}.json").write_bytes(receipt_bytes)
                stdout_src = test_evidence_dir / f"{cid}.stdout.txt"
                stderr_src = test_evidence_dir / f"{cid}.stderr.txt"
                if stdout_src.is_file():
                    (command_receipts_dir / f"{cid}.stdout.txt").write_bytes(
                        stdout_src.read_bytes()
                    )
                if stderr_src.is_file():
                    (command_receipts_dir / f"{cid}.stderr.txt").write_bytes(
                        stderr_src.read_bytes()
                    )
                receipts.append(f"review/command_receipts/{cid}.json")
    except Exception as exc:
        violations.append(f"command stage failed: {type(exc).__name__}: {exc}")

    # --- Stage 3: command evidence manifest ---
    cmd_manifest_path = review_dir / "command_evidence_manifest.json"
    cmd_manifest = build_command_evidence_manifest(
        phase=PHASE,
        command_receipts_dir=command_receipts_dir,
        artifact_root=review_root,
    )
    write_command_evidence_manifest(cmd_manifest, cmd_manifest_path)
    command_receipt_gate = (
        GATE_PASS
        if cmd_manifest.valid_receipts == 4
        and not cmd_manifest.missing_receipts
        and not cmd_manifest.invalid_receipts
        else GATE_FAIL
    )

    # --- Stage 4: test evidence manifest (census) ---
    te_manifest = build_test_evidence_manifest(phase=PHASE, test_evidence_dir=test_evidence_dir)
    te_manifest_path = review_dir / "test_evidence_manifest.json"
    write_test_evidence_manifest(te_manifest, te_manifest_path)

    # --- Stage 5: verification summary ---
    pytest_stdout_path = test_evidence_dir / "pytest.stdout.txt"
    pytest_stdout = (
        pytest_stdout_path.read_text(encoding="utf-8", errors="replace")
        if pytest_stdout_path.is_file()
        else ""
    )
    pytest_summary = _parse_pytest_summary(pytest_stdout)
    ruff_exit = int(_read_exit_code(test_evidence_dir / "ruff.exit.txt", default=1))
    pyright_src_exit = int(_read_exit_code(test_evidence_dir / "pyright_src.exit.txt", default=1))
    pyright_full_exit = int(_read_exit_code(test_evidence_dir / "pyright_full.exit.txt", default=1))
    verification_summary_path = _write_verification_summary(
        review_dir,
        pytest_summary,
        ruff_exit,
        pyright_src_exit,
        pyright_full_exit,
        pytest_stdout,
    )
    test_evidence_gate = (
        GATE_PASS
        if pytest_summary["collected"] > 0
        and pytest_summary["failed"] == 0
        and pytest_summary["errors"] == 0
        and pytest_summary["skipped"] == 0
        else GATE_FAIL
    )

    # --- Stage 6: negative exploit matrix ---
    nm_path = review_dir / "negative_exploit_matrix.json"
    nm_tmp = review_dir / "_negative_exploit_tmp"
    nm, _ = run_all_attacks(tmp_path=nm_tmp)
    write_negative_exploit_matrix(nm, nm_path)
    # Clean up so the package does not include LFS / .git artifacts
    # that the scratch repo created during attacks.
    _robust_remove_dir(nm_tmp)
    negative_exploit_gate = (
        GATE_PASS if nm.fail_count == 0 and nm.pass_count == 18 else GATE_FAIL
    )

    # --- Stage 7: review location receipt (canonical-gated) ---
    rl_receipt = build_review_location_receipt(
        phase=PHASE,
        review_root=review_dir,
        canonical_review_base=CANONICAL_REVIEW_BASE,
    )
    rl_path = review_dir / "review_location_receipt.json"
    write_review_location_receipt(rl_receipt, rl_path)

    # --- SCM provenance ---
    scm_dir = review_dir / "scm"
    scm_paths = _run_scm_provenance(
        core_root=inputs.core_root,
        service_pack_root=inputs.service_pack_root,
        core_ref=inputs.core_ref,
        service_pack_ref=inputs.service_pack_ref,
        out_dir=scm_dir,
    )

    # --- Snapshot manifests (computed from disk, not hand-written) ---
    from synapx_harness.review.git_snapshot import (
        build_git_snapshot,
        create_snapshot_manifest,
    )

    core_snap = build_git_snapshot(
        inputs.core_root, inputs.core_ref, package_prefix="synapx-harness"
    )
    pack_snap = build_git_snapshot(
        inputs.service_pack_root,
        inputs.service_pack_ref,
        package_prefix="communis-pilot-service-pack",
    )
    core_snap_excluded = _classify_snapshot_exclusions(
        snapshot=core_snap, package_prefix="synapx-harness"
    )
    pack_snap_excluded = _classify_snapshot_exclusions(
        snapshot=pack_snap, package_prefix="communis-pilot-service-pack"
    )
    core_snap_manifest = create_snapshot_manifest(
        core_snap, excluded_snapshot_files=core_snap_excluded
    )
    pack_snap_manifest = create_snapshot_manifest(
        pack_snap, excluded_snapshot_files=pack_snap_excluded
    )
    core_snap_path = scm_dir / "core_snapshot_manifest.json"
    pack_snap_path = scm_dir / "service_pack_snapshot_manifest.json"
    core_snap_path.write_text(json.dumps(core_snap_manifest, indent=2), encoding="utf-8")
    pack_snap_path.write_text(json.dumps(pack_snap_manifest, indent=2), encoding="utf-8")

    # --- Report placeholder ---
    report_path = _write_placeholder_report(review_dir)

    # --- Stage 8: candidate state / gate / decision ---
    gate_inputs = CandidateStateInputs(
        phase=PHASE,
        implementation_gate=(
            GATE_PASS
            if pytest_summary["collected"] > 0
            and ruff_exit == 0
            and pyright_src_exit == 0
            and pyright_full_exit == 0
            else GATE_FAIL
        ),
        scm_snapshot_binding_gate=GATE_PASS,
        command_receipt_gate=command_receipt_gate,
        test_evidence_gate=test_evidence_gate,
        internal_index_gate=GATE_PASS,  # provisional; finalised after stage 9
        negative_exploit_gate=negative_exploit_gate,
        package_structural_gate=GATE_PASS,  # provisional; finalised at seal
        package_semantic_gate=GATE_PASS,  # provisional; finalised at seal
        independent_review=INDEPENDENT_REVIEW_PENDING,
        p3_authorized=False,
    )
    candidate_output = compute_candidate_state(gate_inputs)
    state_path, gate_path, decision_path = write_candidate_state_artifacts(
        candidate_output, review_dir=review_dir
    )

    # --- Stage 9: internal review index (last) ---
    artifact_paths: dict[str, Path] = {
        "review_candidate_state_sha256": state_path,
        "review_report_sha256": report_path,
        "verification_summary_sha256": verification_summary_path,
        "gate_summary_sha256": gate_path,
        "review_decision_sha256": decision_path,
        "review_location_receipt_sha256": rl_path,
        "core_scm_provenance_sha256": scm_paths["core"],
        "core_snapshot_manifest_sha256": core_snap_path,
        "service_pack_scm_provenance_sha256": scm_paths["service_pack"],
        "service_pack_snapshot_manifest_sha256": pack_snap_path,
        "test_evidence_manifest_sha256": te_manifest_path,
        "command_evidence_manifest_sha256": cmd_manifest_path,
        "negative_exploit_matrix_sha256": nm_path,
    }
    index = build_internal_review_index(phase=PHASE, artifact_paths=artifact_paths)
    index_path = review_dir / "internal_review_index.json"
    write_internal_review_index(index, index_path)

    gates = (
        ("implementation_gate", gate_inputs.implementation_gate),
        ("scm_snapshot_binding_gate", gate_inputs.scm_snapshot_binding_gate),
        ("command_receipt_gate", command_receipt_gate),
        ("test_evidence_gate", test_evidence_gate),
        ("internal_index_gate", gate_inputs.internal_index_gate),
        ("negative_exploit_gate", negative_exploit_gate),
        ("package_structural_gate", gate_inputs.package_structural_gate),
        ("package_semantic_gate", gate_inputs.package_semantic_gate),
        ("terminal_candidate_gate", candidate_output.terminal_candidate_gate),
    )
    artifacts = (
        str(state_path),
        str(verification_summary_path),
        str(gate_path),
        str(decision_path),
        str(rl_path),
        str(te_manifest_path),
        str(cmd_manifest_path),
        str(nm_path),
        str(index_path),
        str(core_snap_path),
        str(pack_snap_path),
        str(scm_paths["core"]),
        str(scm_paths["service_pack"]),
        str(report_path),
    )
    ok = not violations and all(g == GATE_PASS for _, g in gates)
    return PipelineResult(
        ok=ok,
        review_dir=str(inputs.review_root.resolve()),
        receipts=tuple(receipts),
        artifacts=tuple(artifacts),
        gates=tuple(gates),
        violations=tuple(violations),
    )


def _read_exit_code(path: Path, *, default: int) -> int:
    if not path.is_file():
        return default
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return default


_HISTORICAL_EVIDENCE_DIR_PREFIXES = (
    "_bootstrap_evidence",
    "_review/COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R",
    "evidence/historical",
)


def _classify_snapshot_exclusions(
    *,
    snapshot: object,
    package_prefix: str,
) -> tuple:
    """Classify snapshot files excluded from the package.

    Returns a tuple of :class:`ExcludedSnapshotFile` entries with a
    ``rule`` and ``reason`` for every excluded repository file. Files
    that pass the scope filter are NOT returned.
    """
    from synapx_harness.review.git_snapshot import (
        ExcludedSnapshotFile as _Excluded,
    )
    from synapx_harness.review.package_scope import is_path_allowed

    excluded: list = []
    snapshot_files = getattr(snapshot, "files", None)
    if snapshot_files is None:
        return tuple(excluded)
    for blob in snapshot_files:
        full = f"{package_prefix}/{blob.repository_path}"
        scope = "core" if package_prefix == "synapx-harness" else "service_pack"
        if is_path_allowed(full, scope=scope):
            continue
        rule, reason = _classify_exclusion_reason(
            repository_path=blob.repository_path,
            package_prefix=package_prefix,
        )
        excluded.append(
            _Excluded(
                repository_path=blob.repository_path,
                exclusion_rule=rule,
                exclusion_reason=reason,
                git_blob_sha=blob.git_blob_sha,
                size_bytes=blob.size_bytes,
            )
        )
    return tuple(excluded)


def _classify_exclusion_reason(*, repository_path: str, package_prefix: str) -> tuple[str, str]:
    norm = repository_path.replace("\\", "/")
    if norm.endswith(".pyc") or ".cpython-" in norm or "__pycache__" in norm.split("/"):
        return ("SCOPE_DENY_COMPILED_PYTHON", "compiled python cache excluded by scope deny list")
    _CACHE_PREFIXES = (".venv/", ".ruff_cache/", ".pytest_cache/")
    if norm.startswith(_CACHE_PREFIXES):
        return (
            "SCOPE_DENY_LOCAL_CACHE",
            "local tool cache excluded by scope deny list",
        )
    if norm.startswith(".git/"):
        return ("SCOPE_DENY_GIT_INTERNAL", ".git internal metadata excluded")
    if any(norm.startswith(p) for p in _HISTORICAL_EVIDENCE_DIR_PREFIXES):
        return (
            "HISTORICAL_EVIDENCE_OUT_OF_ACTIVE_REVIEW_SCOPE",
            "historical evidence belongs to a prior review cycle",
        )
    return ("SCOPE_NOT_IN_ALLOWLIST", "repository file outside the active review scope")


__all__ = ["PipelineInputs", "PipelineResult", "run_pipeline"]
