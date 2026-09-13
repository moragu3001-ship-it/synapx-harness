"""Lane C — Shared Understanding negative tests (NEG-C-01 .. NEG-C-15,
EVIDENCE-NEG-C-01 .. 03).

Each negative test attempts a forbidden operation and asserts rejection.
Structural rejection is enforced by the strict schema (extra=forbid) and
by the deterministic scanner's evidence-only rules.

R1 additions:
  NEG-C-11 .. NEG-C-15 — CANONICAL_JSON_VALUE_TYPE_GAP closure: arbitrary
  Python objects are rejected by the recursive JSON-safe value type.
  EVIDENCE-NEG-C-01 .. 03 — FUTURE_EVIDENCE_TIMESTAMP closure: future /
  invalid / inverted evidence timestamps are rejected.
"""
from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from synapx_harness.context.evidence_meta import (
    find_chronology_inversions,
    is_future_timestamp,
    parse_timestamp,
)
from synapx_harness.context.models import (
    AssertionRecord,
    FactRecord,
    RepositoryBinding,
    SharedUnderstandingContext,
    UnknownRecord,
)
from synapx_harness.context.renderer import render_text, to_canonical_json
from synapx_harness.context.scanner import scan_repository
from synapx_harness.contracts.runtime_models import compute_content_tree_hash
from synapx_harness.validators.schema_validator import validate_payload

CORE_ROOT = Path(__file__).resolve().parents[2]
REVISION_SHA = "a" * 40


def _write_tree(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _link_outside_dir(root: Path, target: Path, name: str) -> None:
    """Create a directory link escaping the repo root (symlink or junction).

    Fails closed: this suite must run deterministically on every host
    (R3 portable test environment forbids skipping).
    """
    try:
        os.symlink(target, root / name, target_is_directory=True)
        return
    except OSError:
        pass
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / name), str(target)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"cannot create escaping directory link at {root / name}"
        )


def _facts_by_key(context: SharedUnderstandingContext) -> dict[str, list[FactRecord]]:
    out: dict[str, list[FactRecord]] = {}
    for fact in context.facts:
        out.setdefault(fact.key, []).append(fact)
    return out


def _unknowns_by_key(context: SharedUnderstandingContext) -> dict[str, list[UnknownRecord]]:
    out: dict[str, list[UnknownRecord]] = {}
    for unknown in context.unknowns:
        out.setdefault(unknown.key, []).append(unknown)
    return out


# ---------------------------------------------------------------------------
# NEG-C-01: UNKNOWN -> FACT promotion attempt is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c01_unknown_to_fact_promotion_rejected() -> None:
    with pytest.raises(ValidationError):
        FactRecord(
            kind="UNKNOWN",  # type: ignore[arg-type]  # intentional invalid promotion
            key="test_command",
            value="pytest",
            source="guess",
            provenance="tests/ exists",
            repository_revision=REVISION_SHA,
        )

    unknown = UnknownRecord(
        key="test_command",
        value=None,
        reason="NO_EXPLICIT_SIGNAL",
        source="scanner",
        provenance="no explicit declaration",
        repository_revision=REVISION_SHA,
    )
    with pytest.raises(ValidationError):
        unknown.kind = "FACT"  # type: ignore[assignment]  # intentional mutation attempt


# ---------------------------------------------------------------------------
# NEG-C-02: ASSERTION -> FACT mutation without evidence is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c02_assertion_to_fact_mutation_rejected() -> None:
    assertion = AssertionRecord(
        key="repository_purpose",
        value="purpose",
        source="README",
        provenance="README.md",
        repository_revision=REVISION_SHA,
    )
    with pytest.raises(ValidationError):
        assertion.kind = "FACT"  # type: ignore[assignment]  # intentional mutation attempt


# ---------------------------------------------------------------------------
# NEG-C-03: ASSERTION authority=true injection is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c03_assertion_authority_injection_rejected() -> None:
    with pytest.raises(ValidationError):
        AssertionRecord(
            key="repository_purpose",
            value="purpose",
            source="README",
            provenance="README.md",
            repository_revision=REVISION_SHA,
            authority="RATIFIED",  # type: ignore[call-arg]  # intentional injection attempt
        )
    with pytest.raises(ValidationError):
        AssertionRecord(
            key="repository_purpose",
            value="purpose",
            source="README",
            provenance="README.md",
            repository_revision=REVISION_SHA,
            is_verified=True,  # type: ignore[call-arg]  # intentional injection attempt
        )


# ---------------------------------------------------------------------------
# NEG-C-04: repository source tries terminal_claim=COMPLETED -> NO EFFECT
# ---------------------------------------------------------------------------


def test_neg_c04_terminal_claim_has_no_effect() -> None:
    with pytest.raises(ValidationError):
        UnknownRecord(
            key="terminal_claim",
            value="COMPLETED",  # type: ignore[arg-type]  # intentional injection attempt
            reason="NOT_OBSERVED",
            source="repository",
            provenance="README.md",
            repository_revision=REVISION_SHA,
        )
    with pytest.raises(ValidationError):
        SharedUnderstandingContext(
            repository_id="x",  # type: ignore[call-arg]  # intentional injection attempt
            terminal_claim="COMPLETED",  # type: ignore[call-arg]  # intentional injection attempt
            facts=[],
            assertions=[],
            unknowns=[],
        )


# ---------------------------------------------------------------------------
# NEG-C-05: outside-root symlink read is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c05_outside_symlink_read_rejected(tmp_path: Path) -> None:
    outside = _write_tree(tmp_path / "outside", {"secret.txt": "EXTERNAL SECRET\n"})
    root = _write_tree(tmp_path / "repo", {"ok.txt": "ok\n"})
    _link_outside_dir(root, outside, "leak")

    context = scan_repository(root, repository_id="neg-c05")
    payload = context.model_dump(mode="json")
    assert "EXTERNAL SECRET" not in str(payload)


# ---------------------------------------------------------------------------
# NEG-C-06: conflicting package manager forced selection is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c06_conflicting_package_manager_not_forced(tmp_path: Path) -> None:
    root = _write_tree(
        tmp_path / "repo",
        {
            "package-lock.json": "{}",
            "pnpm-lock.yaml": "",
            "yarn.lock": "",
        },
    )
    context = scan_repository(root, repository_id="neg-c06")
    facts = _facts_by_key(context)
    assert "package_manager" not in facts
    unknowns = _unknowns_by_key(context)
    pm = unknowns.get("package_manager")
    assert pm and pm[0].reason == "CONFLICTING_SIGNALS"


# ---------------------------------------------------------------------------
# NEG-C-07: implicit guessed test command is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c07_implicit_test_command_rejected(tmp_path: Path) -> None:
    root = _write_tree(
        tmp_path / "repo",
        {
            "tests/test_x.py": "def test_x(): pass\n",
            "src/x/main.py": "print(1)\n",
        },
    )
    context = scan_repository(root, repository_id="neg-c07")
    assert not any(f.key == "test_command" for f in context.facts)
    unknowns = _unknowns_by_key(context)
    assert unknowns.get("test_command", [])[0].reason == "NO_EXPLICIT_SIGNAL"


# ---------------------------------------------------------------------------
# NEG-C-08: Codex-specific field added to canonical context is REJECTED
# ---------------------------------------------------------------------------


def test_neg_c08_codex_field_rejected() -> None:
    with pytest.raises(ValidationError):
        FactRecord(
            key="language",
            value="Python",
            source="scanner",
            provenance="pyproject.toml",
            repository_revision=REVISION_SHA,
            codex_instruction="do the thing",  # type: ignore[call-arg]  # intentional injection attempt
        )


def test_neg_c08_codex_payload_fails_schema_validation(tmp_path: Path) -> None:
    root = _write_tree(tmp_path / "repo", {"pyproject.toml": "[project]\n"})
    context = scan_repository(root, repository_id="neg-c08")
    payload = context.model_dump(mode="json")
    payload["codex_rules"] = {"must_comply": True}
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/shared_understanding_context.schema.json",
        payload=payload,
    )
    assert not report.ok


# ---------------------------------------------------------------------------
# NEG-C-09: missing revision must NOT be replaced by a fake revision
# ---------------------------------------------------------------------------


def test_neg_c09_gitless_repository_gets_no_fake_revision(tmp_path: Path) -> None:
    root = _write_tree(tmp_path / "repo", {"a.txt": "a\n"})
    context = scan_repository(root, repository_id="neg-c09")
    assert context.repository.revision is None
    payload = context.model_dump(mode="json")
    assert payload["repository"]["revision"] is None
    unknowns = _unknowns_by_key(context)
    assert "repository_revision" in unknowns


# ---------------------------------------------------------------------------
# NEG-C-10: scanner must NOT mutate the repository
# ---------------------------------------------------------------------------


def test_neg_c10_scanner_does_not_mutate_repository(tmp_path: Path) -> None:
    root = _write_tree(
        tmp_path / "repo",
        {
            "pyproject.toml": "[project]\nname = 'x'\n",
            "README.md": "# R\n",
            "src/x/__init__.py": "",
        },
    )
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "harness@synapx.local"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "SynapX Harness"],
        check=True,
    )
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-q", "-m", "fixture"],
        check=True,
    )
    before_hash = compute_content_tree_hash(root)
    before_status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        check=True,
    ).stdout

    scan_repository(root, repository_id="neg-c10")

    after_hash = compute_content_tree_hash(root)
    after_status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        check=True,
    ).stdout
    assert before_hash == after_hash
    assert before_status == after_status


# ---------------------------------------------------------------------------
# R1 — CANONICAL_JSON_VALUE_TYPE_GAP: NEG-C-11 .. NEG-C-15
# ---------------------------------------------------------------------------


def test_neg_c11_fact_object_rejected() -> None:
    with pytest.raises(ValidationError):
        FactRecord(
            key="x",
            value=object(),  # type: ignore[arg-type]  # intentional non-JSON input
            source="s",
            provenance="p",
            repository_revision=REVISION_SHA,
        )


def test_neg_c12_fact_path_rejected() -> None:
    with pytest.raises(ValidationError):
        FactRecord(
            key="x",
            value=Path("."),  # type: ignore[arg-type]  # intentional non-JSON input
            source="s",
            provenance="p",
            repository_revision=REVISION_SHA,
        )


def test_neg_c13_fact_nested_object_rejected() -> None:
    with pytest.raises(ValidationError):
        FactRecord(
            key="x",
            value={"nested": object()},  # type: ignore[arg-type]  # intentional non-JSON input
            source="s",
            provenance="p",
            repository_revision=REVISION_SHA,
        )
    with pytest.raises(ValidationError):
        FactRecord(
            key="x",
            value={"nested": {"deeper": Path(".")}},  # type: ignore[arg-type]  # intentional non-JSON input
            source="s",
            provenance="p",
            repository_revision=REVISION_SHA,
        )
    with pytest.raises(ValidationError):
        FactRecord(
            key="x",
            value=[1, {"bad": {1, 2}}],  # type: ignore[arg-type]  # intentional non-JSON input
            source="s",
            provenance="p",
            repository_revision=REVISION_SHA,
        )


def test_neg_c14_assertion_nested_object_rejected() -> None:
    with pytest.raises(ValidationError):
        AssertionRecord(
            key="repository_purpose",
            value={"nested": object()},  # type: ignore[arg-type]  # intentional non-JSON input
            source="s",
            provenance="p",
            repository_revision=REVISION_SHA,
        )


def test_neg_c15_valid_nested_json_full_pipeline() -> None:
    value = {
        "name": "Python",
        "versions": [3, 12],
        "metadata": {"supported": True, "optional": None},
    }
    fact = FactRecord(
        key="runtime",
        value=value,
        source="scanner",
        provenance="test",
        repository_revision=REVISION_SHA,
    )
    context = SharedUnderstandingContext(
        repository=RepositoryBinding(repository_id="neg-c15"),
        facts=[fact],
    )
    dumped = context.model_dump(mode="json")
    assert dumped["facts"][0]["value"] == value
    canonical = to_canonical_json(context)
    assert '"name": "Python"' in canonical
    report = validate_payload(
        package_root=CORE_ROOT,
        schema_relative_path="runtime/shared_understanding_context.schema.json",
        payload=dumped,
    )
    assert report.ok, report.errors
    rendered = render_text(context)
    assert "Python" in rendered


# ---------------------------------------------------------------------------
# R1 — FUTURE_EVIDENCE_TIMESTAMP: EVIDENCE-NEG-C-01 .. 03
# ---------------------------------------------------------------------------


def test_evidence_neg_c01_future_timestamp_rejected() -> None:
    now = datetime.now(UTC)
    future = (now + timedelta(hours=1)).isoformat()
    assert is_future_timestamp(future, reference=now)


def test_evidence_neg_c02_invalid_timestamp_rejected() -> None:
    for bad in ("not-a-timestamp", "", "2026-08-21T15:45:00"):
        with pytest.raises(ValueError):
            parse_timestamp(bad)


def test_evidence_neg_c03_chronology_inversion_rejected() -> None:
    earlier = "2026-08-21T15:00:00+00:00"
    later = "2026-08-21T16:00:00+00:00"
    inversions = find_chronology_inversions([("INPUT", later), ("CENSUS", earlier)])
    assert len(inversions) == 1
    assert "CENSUS" in inversions[0]
