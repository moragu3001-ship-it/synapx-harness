"""R2 Governance Validator enforcement tests."""
from __future__ import annotations

from pathlib import Path

from synapx_harness.validators.governance_validator import validate_governance

CORE_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_ROOT = CORE_ROOT / "src" / "synapx_harness" / "_schemas"


def _write_yaml(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "contract_type: " + str(data.get("contract_type")) + "\n"
        "schema_version: " + str(data.get("schema_version")) + "\n",
        encoding="utf-8",
    )


def test_contract_validate_uses_registered_schema(tmp_path: Path) -> None:
    path = tmp_path / "repo.yaml"
    path.write_text(
        "contract_type: COMMUNIS_REPOSITORY_REGISTRY\n"
        "schema_version: '0.1.0'\n"
        "service_id: x\n"
        "registry_state: DRAFT\n"
        "authority: NON_AUTHORITATIVE\n"
        "repositories:\n"
        "  - repository_id: x\n"
        "    local_path: D:/x\n"
        "    role: AS_IS_LEGACY_CANDIDATE\n"
        "    analysis_mode: READ_ONLY\n"
        "    authority: NON_AUTHORITATIVE\n"
        "    ratification_state: NOT_RATIFIED\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert report.ok, report.errors


def test_unknown_contract_type_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_NOT_REAL\n"
        "schema_version: '0.1.0'\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_schema_version_mismatch_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_REPOSITORY_REGISTRY\n"
        "schema_version: '0.99.0'\n"
        "registry_state: DRAFT\n"
        "authority: NON_AUTHORITATIVE\n"
        "repositories: []\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_repository_registry_state_must_be_draft(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_REPOSITORY_REGISTRY\n"
        "schema_version: '0.1.0'\n"
        "registry_state: ACTIVE\n"
        "authority: NON_AUTHORITATIVE\n"
        "repositories: []\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_repository_registry_authority_must_be_non_authoritative(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_REPOSITORY_REGISTRY\n"
        "schema_version: '0.1.0'\n"
        "registry_state: DRAFT\n"
        "authority: ACTIVE_CANONICAL\n"
        "repositories: []\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_repository_analysis_mode_must_be_read_only(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_REPOSITORY_REGISTRY\n"
        "schema_version: '0.1.0'\n"
        "registry_state: DRAFT\n"
        "authority: NON_AUTHORITATIVE\n"
        "repositories:\n"
        "  - repository_id: x\n"
        "    local_path: D:/x\n"
        "    role: AS_IS_LEGACY_CANDIDATE\n"
        "    analysis_mode: WRITE\n"
        "    authority: NON_AUTHORITATIVE\n"
        "    ratification_state: NOT_RATIFIED\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_policy_values_are_checked_not_only_field_presence(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_RATIFICATION_POLICY\n"
        "schema_version: '0.1.0'\n"
        "policy_id: COMMUNIS_RATIFICATION_BOOTSTRAP_V0_1\n"
        "ratifiers_required: 3\n"
        "approval_rule: MAJORITY\n"
        "approval_count_required: 3\n"
        "hash_change_invalidates_approvals: true\n"
        "version_change_invalidates_approvals: true\n"
        "blocking_issue_count_required: 0\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_malformed_yaml_is_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "x.yaml").write_text(
        "contract_type: COMMUNIS_RATIFICATION_RECEIPT\n"
        "schema_version: '0.1.0'\n"
        "  bad indent\n",
        encoding="utf-8",
    )
    report = validate_governance([tmp_path], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_empty_governance_root_is_failure(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    report = validate_governance([empty], schemas_root=SCHEMAS_ROOT)
    assert not report.ok


def test_no_governance_roots_is_failure() -> None:
    report = validate_governance([], schemas_root=SCHEMAS_ROOT)
    assert not report.ok
