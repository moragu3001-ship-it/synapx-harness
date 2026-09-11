"""CLI entry point for synapx_harness.

R7 review pipeline:
  synapx-harness review build       --workspace-root ... --phase ... --core ...
    --core-ref ... --service-pack ... --service-pack-ref ... --out ...
  synapx-harness review verify      <zip>
  synapx-harness review seal        <zip> --output-receipt <path>
  synapx-harness review verify-seal <zip> --receipt <path>

Validation failures always exit with a non-zero code.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import typer

from synapx_harness import __version__
from synapx_harness.review.evidence_pipeline import (
    PipelineInputs,
    run_pipeline,
)
from synapx_harness.review.package_builder import (
    PackagePayload,
    build_package,
)
from synapx_harness.review.package_verifier import verify_zip_path
from synapx_harness.review.review_phase_contract import PHASE
from synapx_harness.review.semantic_verifier import verify_review_package_bytes
from synapx_harness.review.terminal_seal import (
    build_external_seal_receipt,
    compute_terminal_seal,
    read_internal_terminal_state,
    write_zip_sha256_sidecar,
)
from synapx_harness.review.terminal_seal import (
    receipt_sha256 as compute_receipt_sha256,
)
from synapx_harness.review.verify_seal import verify_seal
from synapx_harness.validators.governance_validator import validate_governance
from synapx_harness.validators.scaffold_validator import validate_service_pack

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="SynapX-Harness CLI.",
)
"""Typer application surface."""

scaffold_app = typer.Typer(help="Scaffold commands", no_args_is_help=True)
contract_app = typer.Typer(help="Contract commands", no_args_is_help=True)
repository_app = typer.Typer(help="Repository commands", no_args_is_help=True)
policy_app = typer.Typer(help="Policy commands", no_args_is_help=True)
review_app = typer.Typer(help="Review commands", no_args_is_help=True)
storage_app = typer.Typer(help="Storage commands", no_args_is_help=True)

app.add_typer(scaffold_app, name="scaffold")
app.add_typer(contract_app, name="contract")
app.add_typer(repository_app, name="repository")
app.add_typer(policy_app, name="policy")
app.add_typer(review_app, name="review")
app.add_typer(storage_app, name="storage")


def _print_json(payload: dict[str, object]) -> None:
    typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))


def _exit_with_report(report: object, *, ok_attr: str = "ok") -> None:
    to_dict = getattr(report, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        if isinstance(result, dict):
            _print_json(result)
    ok = bool(getattr(report, ok_attr))
    if not ok:
        raise typer.Exit(code=1)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"synapx-harness {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print the SynapX-Harness version and exit.",
    ),
) -> None:
    """Root options for the synapx-harness CLI."""


@scaffold_app.command("validate")
def scaffold_validate(
    root: Path = typer.Option(..., "--root", help="Service-pack root path."),
) -> None:
    """Validate the service-pack directory layout."""
    report = validate_service_pack(root)
    _exit_with_report(report)


@contract_app.command("validate")
def contract_validate(
    root: Path = typer.Option(..., "--root", help="Service-pack root path."),
) -> None:
    """Validate governance contracts under a service-pack root."""
    policies = root / "policies"
    profiles = root / "profiles"
    registry = root / "repository-registry"
    report = validate_governance([policies, profiles, registry])
    _exit_with_report(report)


@repository_app.command("list")
def repository_list(
    root: Path = typer.Option(..., "--root", help="Service-pack root path."),
) -> None:
    """List repositories declared in the service pack."""
    from ruamel.yaml import YAML

    registry_path = root / "repository-registry" / "repositories.yaml"
    if not registry_path.is_file():
        _print_json({"ok": False, "repositories": [], "error": "missing repositories.yaml"})
        raise typer.Exit(code=1)
    yaml = YAML(typ="safe")
    data = yaml.load(registry_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        _print_json({"ok": False, "repositories": [], "error": "registry not a mapping"})
        raise typer.Exit(code=1)
    repos = data.get("repositories", [])
    if not isinstance(repos, list):
        _print_json({"ok": False, "repositories": [], "error": "repositories not a list"})
        raise typer.Exit(code=1)
    _print_json({"ok": True, "repositories": repos})
    if not repos:
        raise typer.Exit(code=1)


@policy_app.command("validate")
def policy_validate(
    root: Path = typer.Option(..., "--root", help="Service-pack root path."),
) -> None:
    """Validate Policy files under a service-pack root."""
    policies = root / "policies"
    report = validate_governance([policies])
    _exit_with_report(report)


def _git_status_clean(repo_path: Path) -> bool:
    res = subprocess.run(
        ["git", "-C", str(repo_path), "status", "--porcelain=v1"],
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout.strip() == ""


def _git_ref_resolve(repo_path: Path, ref: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--verify", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout.strip()


def _git_tree_sha(repo_path: Path, commit_sha: str) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", f"{commit_sha}^{{tree}}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout.strip()


@review_app.command("build")
def review_build(
    workspace_root: Path = typer.Option(
        ..., "--workspace-root", help="Workspace root (e.g., D:\\communis)."
    ),
    phase: str = typer.Option(..., "--phase", help="Phase identifier."),
    core: Path = typer.Option(..., "--core", help="synapx-harness root path."),
    core_ref: str = typer.Option(
        ..., "--core-ref", help="Git commit SHA for core repository."
    ),
    service_pack: Path = typer.Option(
        ..., "--service-pack", help="communis-pilot-service-pack root path."
    ),
    service_pack_ref: str = typer.Option(
        ..., "--service-pack-ref", help="Git commit SHA for service pack."
    ),
    out: Path = typer.Option(..., "--out", help="Output ZIP path."),
    review_artifacts: Path = typer.Option(
        None,
        "--review-artifacts",
        help="Pre-existing review/ directory. If absent, the pipeline generates it.",
    ),
) -> None:
    """Build the R7 review package using commit-bound snapshot inputs."""
    if phase != PHASE:
        _print_json(
            {"ok": False, "error": f"phase mismatch: got {phase!r}, expected {PHASE!r}"}
        )
        raise typer.Exit(code=1)

    if not _git_status_clean(core):
        _print_json({"ok": False, "error": "core working tree is not clean"})
        raise typer.Exit(code=1)
    if not _git_status_clean(service_pack):
        _print_json({"ok": False, "error": "service pack working tree is not clean"})
        raise typer.Exit(code=1)

    core_commit = _git_ref_resolve(core, core_ref)
    _git_tree_sha(core, core_commit)
    pack_commit = _git_ref_resolve(service_pack, service_pack_ref)
    _git_tree_sha(service_pack, pack_commit)

    review_root = workspace_root / "_review" / phase
    review_root.mkdir(parents=True, exist_ok=True)
    review_dir = review_root / "review"

    if review_artifacts is None:
        pipeline = run_pipeline(
            PipelineInputs(
                core_root=core,
                service_pack_root=service_pack,
                core_ref=core_commit,
                service_pack_ref=pack_commit,
                review_root=review_root,
                timeout=900,
            )
        )
        if not pipeline.ok:
            _print_json(pipeline.to_dict())
            raise typer.Exit(code=1)
        review_artifacts = review_dir

    from synapx_harness.review.git_snapshot import build_git_snapshot

    core_snap = build_git_snapshot(core, core_commit, package_prefix="synapx-harness")
    pack_snap = build_git_snapshot(
        service_pack, pack_commit, package_prefix="communis-pilot-service-pack"
    )

    review_payloads: list[PackagePayload] = []
    for entry in sorted(review_artifacts.rglob("*")):
        if entry.is_file():
            rel = f"review/{entry.relative_to(review_artifacts).as_posix()}"
            review_payloads.append(
                PackagePayload(package_path=rel, payload=entry.read_bytes())
            )

    result = build_package(
        core_snapshot=core_snap,
        service_pack_snapshot=pack_snap,
        review_payloads=review_payloads,
        out_path=out,
    )
    if not result.ok:
        _print_json(result.to_dict())
        raise typer.Exit(code=1)

    semantic = verify_review_package_bytes(out.read_bytes())
    if not semantic.canonical:
        _print_json(semantic.to_dict())
        raise typer.Exit(code=1)

    sidecar_path = write_zip_sha256_sidecar(out)

    _print_json(
        {
            "ok": True,
            "package": str(out),
            "package_sha256": result.zip_sha256,
            "sidecar": str(sidecar_path),
            "structural": semantic.package_structural_gate,
            "semantic": semantic.package_semantic_gate,
        }
    )


@review_app.command("verify")
def review_verify(
    zip: Path = typer.Argument(..., help="Review package ZIP path."),
) -> None:
    """Verify the R7 review package (structural + semantic)."""
    zip_bytes = zip.read_bytes()
    structural = verify_zip_path(str(zip))
    semantic = verify_review_package_bytes(zip_bytes)
    ok = structural.ok and semantic.canonical
    _print_json(
        {
            "ok": ok,
            "package_structural_gate": structural.gate,
            "package_semantic_gate": semantic.package_semantic_gate,
            "structural_violations": list(semantic.structural_violations),
            "semantic_violations": list(semantic.semantic_violations),
        }
    )
    if not ok:
        raise typer.Exit(code=1)


def zf_read_member(zip_bytes: bytes, name: str) -> bytes:
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        if name in zf.namelist():
            return zf.read(name)
    return b""


@review_app.command("seal")
def review_seal(
    zip: Path = typer.Argument(..., help="Review package ZIP path."),
    output_receipt: Path = typer.Option(
        ..., "--output-receipt", help="Output path for the external receipt."
    ),
) -> None:
    """Produce the R7 external seal receipt.

    The phase, gate, candidate_status, independent_review and
    p3_authorized are all read FROM the package. No CLI value is
    authoritative.
    """
    import hashlib

    zip_bytes = zip.read_bytes()
    structural = verify_zip_path(str(zip))
    semantic = verify_review_package_bytes(zip_bytes)
    if not structural.ok:
        _print_json({"ok": False, "error": "structural verify failed"})
        raise typer.Exit(code=1)
    if not semantic.canonical:
        _print_json(
            {"ok": False, "error": "semantic verify failed", "details": semantic.to_dict()}
        )
        raise typer.Exit(code=1)

    state_raw = zf_read_member(zip_bytes, "review/review_candidate_state.json")
    gate_raw = zf_read_member(zip_bytes, "review/gate_summary.json")
    decision_raw = zf_read_member(zip_bytes, "review/review_decision.json")
    index_raw = zf_read_member(zip_bytes, "review/internal_review_index.json")
    manifest_raw = zf_read_member(zip_bytes, "package_payload_manifest.json")
    core_scm_raw = zf_read_member(zip_bytes, "review/scm/core_repository.json")
    pack_scm_raw = zf_read_member(zip_bytes, "review/scm/service_pack_repository.json")
    state = json.loads(state_raw)
    gate = json.loads(gate_raw)
    decision = json.loads(decision_raw)
    pkg = {
        "review_candidate_state": state,
        "gate_summary": gate,
        "review_decision": decision,
        "structural": "PASS",
        "semantic": "PASS",
        "package_structural_gate": "PASS",
        "package_semantic_gate": "PASS",
        "structural_ok": True,
        "semantic_ok": True,
    }
    internal_state = read_internal_terminal_state(pkg)
    seal = compute_terminal_seal(internal_state)

    receipt = build_external_seal_receipt(
        internal_seal=seal,
        zip_filename=zip.name,
        zip_sha256=structural.zip_sha256,
        internal_review_index_sha256=hashlib.sha256(index_raw).hexdigest(),
        payload_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        review_candidate_state_sha256=hashlib.sha256(state_raw).hexdigest(),
        review_report_sha256=hashlib.sha256(
            zf_read_member(zip_bytes, "review/review_report.md")
        ).hexdigest(),
        verification_summary_sha256=hashlib.sha256(
            zf_read_member(zip_bytes, "review/verification_summary.json")
        ).hexdigest(),
        gate_summary_sha256=hashlib.sha256(gate_raw).hexdigest(),
        core_commit_sha=str(json.loads(core_scm_raw)["commit_sha"]),
        core_tree_sha=str(json.loads(core_scm_raw)["tree_sha"]),
        pack_commit_sha=str(json.loads(pack_scm_raw)["commit_sha"]),
        pack_tree_sha=str(json.loads(pack_scm_raw)["tree_sha"]),
    )
    output_receipt.parent.mkdir(parents=True, exist_ok=True)
    output_receipt.write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    receipt_sha = compute_receipt_sha256(receipt)
    sha_path = output_receipt.with_suffix(output_receipt.suffix + ".sha256")
    sha_path.write_text(
        f"{receipt_sha}  {output_receipt.name}\n",
        encoding="ascii",
    )
    zip_sidecar_path = write_zip_sha256_sidecar(zip)
    _print_json(receipt)
    _print_json(
        {
            "ok": True,
            "receipt": str(output_receipt),
            "receipt_sha256": receipt_sha,
            "receipt_sidecar": str(sha_path),
            "zip_sidecar": str(zip_sidecar_path),
        }
    )


@review_app.command("verify-seal")
def review_verify_seal(
    zip: Path = typer.Argument(..., help="Review package ZIP path."),
    receipt: Path = typer.Option(..., "--receipt", help="External receipt path."),
) -> None:
    """Re-verify a sealed R7 review package against its external receipt."""
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    res = verify_seal(zip_path=zip, receipt=payload)
    _print_json(res.to_dict())
    if not res.ok:
        raise typer.Exit(code=1)


@storage_app.command("census")
def storage_census(
    runs_root: Path = typer.Option(
        ..., "--runs-root", help="Path to _runs directory."
    ),
    project_root: Path = typer.Option(
        None, "--project-root", help="Project root for reference scanning."
    ),
    skip_ref_scan: bool = typer.Option(
        False, "--skip-ref-scan", help="Skip external reference scanning."
    ),
) -> None:
    """Read-only storage diagnostics for _runs directory. Never deletes."""
    from synapx_harness.storage.census import build_catalog

    effective_project_root = None if skip_ref_scan else project_root
    census_result = build_catalog(runs_root, project_root=effective_project_root)
    catalog = census_result.catalog

    _print_json({
        "ok": census_result.census_complete,
        "total_size_bytes": catalog.total_size_bytes,
        "run_count": catalog.run_count,
        "runs": [r.to_dict() for r in catalog.runs],
        "census_errors": [{"path": e.path, "error": e.error} for e in census_result.errors],
    })


@storage_app.command("gc")
def storage_gc(
    runs_root: Path = typer.Option(
        ..., "--runs-root", help="Path to _runs directory."
    ),
    project_root: Path = typer.Option(
        None, "--project-root", help="Project root for reference scanning."
    ),
    skip_ref_scan: bool = typer.Option(
        False, "--skip-ref-scan", help="Skip external reference scanning."
    ),
    ttl_days: int = typer.Option(
        90, "--ttl-days", help="Retention TTL in days."
    ),
    max_total_bytes: int = typer.Option(
        5 * 1024 * 1024 * 1024, "--max-total-bytes", help="Quota in bytes."
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Apply deletions. Without this flag, dry-run only."
    ),
) -> None:
    """Garbage collection for _runs directory. Dry-run by default."""
    from synapx_harness.storage.gc import execute_gc
    from synapx_harness.storage.policy import RetentionPolicy

    policy = RetentionPolicy(ttl_days=ttl_days, max_total_bytes=max_total_bytes)
    effective_project_root = None if skip_ref_scan else project_root
    gc_result = execute_gc(
        runs_root,
        policy,
        dry_run=not apply,
        project_root=effective_project_root,
    )

    _print_json({
        "ok": True,
        "mode": "actual" if apply else "dry-run",
        "plan": gc_result.plan.to_dict(),
        "receipts": [r.to_dict() for r in gc_result.receipts],
    })


def main() -> None:
    """Console entry point."""
    app()


if __name__ == "__main__":
    app()
