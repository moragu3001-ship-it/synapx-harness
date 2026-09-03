"""H2-I4-A1-J1 — GIT_COMMIT revision binding acceptance (BUG_FIX RED/GREEN).

T00 contract (work_contract.schema.json:74-77, skill_activation_contract
.schema.json 4-kind enum — I2-R1 4fc31de 'GIT_COMMIT restored') admits
GIT_COMMIT as 1 of 4 revision kinds, but runtime_models.py rejects it
unconditionally (:118-123, :279-284). This test binds the provider-neutral
GIT_COMMIT admission path: with repository_id supplied, build() and
SourceRevisionRef must accept GIT_COMMIT; the git-only supported_kinds gate
(X3-N07) must remain.
"""
from __future__ import annotations

import pytest

from synapx_harness.contracts import runtime_models
from synapx_harness.kernel import work_contract_builder

RED_ID = "H2-I4-A1-J1"
INVARIANT_REFS = ["X3-N07", "I2-R1", "T00"]


def test_git_commit_source_revision_ref_accepted() -> None:
    """repository_id + GIT_COMMIT binding must be admitted (schema parity)."""
    ref = runtime_models.SourceRevisionRef(
        repository_id="repo-x",
        revision_kind="GIT_COMMIT",
        revision_value="a" * 40,
    )
    assert ref.repository_id == "repo-x"
    assert ref.revision_kind == "GIT_COMMIT"


def test_build_source_revision_ref_git_commit() -> None:
    """build_source_revision_ref must accept GIT_COMMIT (deterministic RED)."""
    ref = runtime_models.build_source_revision_ref(
        repository_id="repo-x",
        revision_kind="GIT_COMMIT",
        revision_value="a" * 40,
    )
    assert ref.revision_kind == "GIT_COMMIT"
    assert ref.repository_id == "repo-x"


def test_work_contract_admission_git_commit_revision() -> None:
    """build() must admit a provider-neutral GIT_COMMIT revision ref."""
    contract = work_contract_builder.build(
        work_contract_id="wc-a1-j1-git-commit",
        phase="H2-I4-A1",
        risk_class="R2",
        objective="GIT_COMMIT provider-neutral binding",
        scope=["src"],
        issuer="HARNESS_CORE_ADMISSION",
        admission_receipt={
            "receipt_id": "rec-a1-j1-admission",
            "admitted_at": "2026-08-17T00:00:00Z",
            "admitted_by": "HARNESS_CORE_ADMISSION",
            "red_receipt_ref": "evidence://h2-i4/a1/j1/red/git-commit-binding",
        },
        receipt_refs={
            "permission_receipt_ref": "perm-a1-j1",
            "eligibility_receipt_ref": "elig-a1-j1",
            "execution_receipt_ref": "exec-a1-j1",
        },
        task_type="BUG_FIX",
        source_revision_ref={
            "repository_id": "repo-x",
            "revision_kind": "GIT_COMMIT",
            "revision_value": "a" * 40,
        },
    )
    assert contract.source_revision_ref is not None
    assert contract.source_revision_ref.revision_kind == "GIT_COMMIT"
    assert contract.source_revision_ref.repository_id == "repo-x"


def test_coerce_supports_git_commit_with_four_kinds() -> None:
    """coerce_source_revision_ref must accept GIT_COMMIT when provider-neutral
    supported_kinds are bound (X3-N07 preserved for git-only)."""
    ref = runtime_models.build_source_revision_ref(
        repository_id="repo-x",
        revision_kind="GIT_COMMIT",
        revision_value="a" * 40,
    )
    payload = runtime_models.coerce_source_revision_ref(
        ref,
        supported_kinds=[
            "GIT_COMMIT",
            "CONTENT_TREE_HASH",
            "SNAPSHOT_ID",
            "EXTERNAL_REVISION",
        ],
    )
    assert payload is not None
    assert payload["revision_kind"] == "GIT_COMMIT"


def test_git_only_supported_kinds_still_rejected() -> None:
    """git-only supported_kinds must remain rejected (X3-N07 fail-closed)."""
    ref = runtime_models.build_source_revision_ref(
        repository_id="repo-x",
        revision_kind="GIT_COMMIT",
        revision_value="a" * 40,
    )
    with pytest.raises((ValueError, RuntimeError), match="revision|gitless"):
        runtime_models.coerce_source_revision_ref(
            ref,
            supported_kinds=["GIT_COMMIT"],
        )
