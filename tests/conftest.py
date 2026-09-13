"""Shared fixtures for synapx-harness tests.

Service pack root resolution:
  1. SYNAPX_HARNESS_SERVICE_PACK_ROOT environment variable
  2. The ``communis-pilot-service-pack`` sibling of the core repo
  3. Session-scoped git-backed temporary service pack (self-contained
     fallback — the suite must not depend on host-side pack presence)
  4. Otherwise fail (no skip)

H2-I0 executable RED freeze additions (append-only; legacy fixtures kept):
  - ``h2_i0_fixtures_root``: tests/fixtures directory
  - ``load_h2_i0_fixture``: JSON loader for RED fixtures
  - ``h2_i0_evidence_dir``: I0 evidence output directory

H2-I4-A1-J2 TEST_REPAIR (service-pack root self-containment):
  - ``service_pack_root`` falls back to a session-scoped git-backed
    temporary pack (``make_temporary_service_pack`` + git init/config/
    add/commit) when neither env nor sibling pack resolves, so the 16
    pre-existing errors (pytest.fail 'could not resolve service pack
    root') and the 2 ``test_r2_review_package_scope`` git-rev-parse
    failures are repaired without host-state dependency.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

SERVICE_PACK_FIXTURE_ENV = "SYNAPX_HARNESS_SERVICE_PACK_ROOT"


def _resolve_service_pack_root(core_root: Path) -> Path:
    env = os.environ.get(SERVICE_PACK_FIXTURE_ENV)
    if env:
        candidate = Path(env).resolve()
        if candidate.is_dir():
            return candidate
        pytest.fail(
            f"{SERVICE_PACK_FIXTURE_ENV}={env!r} is not an existing directory"
        )
    sibling = core_root.parent / "communis-pilot-service-pack"
    if sibling.is_dir():
        return sibling.resolve()
    pytest.fail(
        "could not resolve service pack root; set "
        f"{SERVICE_PACK_FIXTURE_ENV} or place a sibling "
        "'communis-pilot-service-pack' directory"
    )


def _make_git_backed_temporary_pack(base_dir: Path) -> Path:
    """Create a session-scoped, git-backed, fully self-contained pack.

    ``make_temporary_service_pack`` builds the directory layout; git
    init/config/add/commit make ``git rev-parse HEAD`` resolvable for
    the R2 review-package-scope and R3 read-only builder tests. Config
    is repository-local (never global).
    """
    pack = make_temporary_service_pack(base_dir)
    subprocess.run(["git", "init", "-q", str(pack)], check=True)
    subprocess.run(
        ["git", "-C", str(pack), "config", "user.email", "harness@synapx.local"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(pack), "config", "user.name", "SynapX Harness"],
        check=True,
    )
    subprocess.run(["git", "-C", str(pack), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(pack), "commit", "-q", "-m", "fixture service pack"],
        check=True,
    )
    return pack


def make_temporary_service_pack(tmp_path: Path) -> Path:
    """Create a minimal but valid service pack inside ``tmp_path``.

    The temporary service pack has every directory the scaffold
    validator needs, three repositories, all required policies and
    profiles. The fixture is fully self-contained — no host state is
    consulted.
    """

    pack = tmp_path / "pack"
    for name in (
        "repository-registry",
        "profiles",
        "policies",
        ".kiro",
        "llm-wiki",
        "governance",
        "integrations",
        "tests",
        "evidence",
    ):
        (pack / name).mkdir(parents=True, exist_ok=True)

    write = pack / "repository-registry" / "repositories.yaml"
    write.write_text(
        "contract_type: COMMUNIS_REPOSITORY_REGISTRY\n"
        "schema_version: 0.1.0\n"
        "service_id: communis-portal\n"
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

    write = pack / "profiles" / "x.yaml"
    write.write_text(
        "contract_type: COMMUNIS_AS_IS_PROFILE\n"
        "schema_version: 0.1.0\n"
        "profile_id: x\n"
        "profile_state: DRAFT\n"
        "authority: NON_AUTHORITATIVE\n"
        "target_repositories: [x]\n"
        "scope: {}\n",
        encoding="utf-8",
    )

    for policy, body in (
        (
            "source_read_only_policy.yaml",
            "contract_type: COMMUNIS_SOURCE_READ_ONLY_POLICY\n"
            "schema_version: 0.1.0\n"
            "policy_id: x\n"
            "application_source_mutation_allowed: false\n"
            "allowed_output_roots:\n"
            "  - D:/x\n"
            "immutable_roots:\n"
            "  - D:/y\n"
            "forbidden_output_roots: []\n",
        ),
        (
            "knowledge_authority_policy.yaml",
            "contract_type: COMMUNIS_KNOWLEDGE_AUTHORITY_POLICY\n"
            "schema_version: 0.1.0\n"
            "policy_id: x\n"
            "official_code_change_context: {}\n"
            "authoring_and_census_context: {}\n"
            "historical_analysis_context: {}\n",
        ),
        (
            "ratification_policy.yaml",
            "contract_type: COMMUNIS_RATIFICATION_POLICY\n"
            "schema_version: 0.1.0\n"
            "policy_id: x\n"
            "ratifiers_required: 4\n"
            "ratifiers_approved: 4\n"
            "approval_rule: UNANIMOUS\n"
            "approval_count_required: 4\n"
            "hash_change_invalidates_approvals: true\n"
            "version_change_invalidates_approvals: true\n"
            "blocking_issue_count_required: 0\n",
        ),
        (
            "activation_policy.yaml",
            "contract_type: COMMUNIS_ACTIVATION_POLICY\n"
            "schema_version: 0.1.0\n"
            "policy_id: x\n"
            "ratification_required: true\n"
            "ratifiers_approved_required: 4\n"
            "blocking_issue_count_required: 0\n"
            "content_hash_match_required: true\n"
            "document_version_match_required: true\n",
        ),
        (
            "pilot_risk_policy.yaml",
            "contract_type: COMMUNIS_PILOT_RISK_POLICY\n"
            "schema_version: 0.1.0\n"
            "policy_id: x\n"
            "risk_classes:\n"
            "  R0: { description: r0, admission: AUTO_ADMIT, hitl_required: false }\n",
        ),
    ):
        (pack / "policies" / policy).write_text(body, encoding="utf-8")
    return pack


@pytest.fixture(scope="session")
def core_root() -> Path:
    """Return the repository root containing `src/synapx_harness`."""
    here = Path(__file__).resolve()
    return here.parents[1]


@pytest.fixture(scope="session")
def service_pack_root(core_root: Path, tmp_path_factory) -> Path:
    """Return the service pack root, resolved portably.

    Falls back to a session-scoped git-backed temporary pack when
    neither ``SYNAPX_HARNESS_SERVICE_PACK_ROOT`` nor the sibling pack
    exists (H2-I4-A1-J2 self-containment repair).
    """
    env = os.environ.get(SERVICE_PACK_FIXTURE_ENV)
    if env:
        candidate = Path(env).resolve()
        if candidate.is_dir():
            return candidate
        pytest.fail(
            f"{SERVICE_PACK_FIXTURE_ENV}={env!r} is not an existing directory"
        )
    sibling = core_root.parent / "communis-pilot-service-pack"
    if sibling.is_dir():
        return sibling.resolve()
    return _make_git_backed_temporary_pack(
        tmp_path_factory.mktemp("service-pack-fallback")
    )


@pytest.fixture(scope="session")
def schemas_root(core_root: Path) -> Path:
    return core_root / "src" / "synapx_harness" / "_schemas"


@pytest.fixture
def temporary_service_pack_root(tmp_path: Path) -> Path:
    """Create a fully self-contained service pack under ``tmp_path``.

    The directory is built from scratch via :func:`make_temporary_service_pack`
    and exposes every directory the CLI/scaffold tests need. The fixture
    fails if it cannot construct the directory tree.
    """
    return make_temporary_service_pack(tmp_path)


@pytest.fixture
def evidence_dir() -> Path:
    return Path(os.environ.get("SYNAPX_HARNESS_EVIDENCE_DIR", "_test_evidence"))


@pytest.fixture
def backup_marker() -> str:
    return os.environ.get("SYNAPX_HARNESS_BACKUP_MARKER", "kilo-pre-communis-customos-20260723")


@pytest.fixture(scope="session")
def h2_i0_fixtures_root(core_root: Path) -> Path:
    """Return tests/fixtures (H2-I0 executable RED fixture root)."""
    return core_root / "tests" / "fixtures"


@pytest.fixture(scope="session")
def h2_i0_evidence_dir(core_root: Path) -> Path:
    """Return the I0 evidence directory (created lazily by tests)."""
    return core_root / "_test_evidence" / "h2_i0"


@pytest.fixture
def h2_i0_require_signature():
    """H2-I0 oracle: I1/I2/I3 가 반드시 노출해야 하는 미래 시그니처 검증.

    - 미래 모듈/함수가 없으면 AssertionError 로 즉시 실패 (EXPECTED_RED).
    - 구현 후 함수가 생기면 파라미터 명세까지 교차 검증해 GREEN 승격을
      결정론적으로 만든다.
    """

    def _require(module: object, func_name: str, params: tuple[str, ...] = ()) -> object:
        fn = getattr(module, func_name, None)
        assert fn is not None, (
            f"I1/I2/I3 must implement {getattr(module, '__name__', module)}.{func_name}"
        )
        if params:
            import inspect

            sig = inspect.signature(fn)
            missing = [p for p in params if p not in sig.parameters]
            assert not missing, (
                f"{func_name} must expose parameter(s) {missing} (H2-I0 oracle)"
            )
        return fn

    return _require


@pytest.fixture
def load_h2_i0_fixture(h2_i0_fixtures_root: Path):
    """Return a JSON fixture loader bound to the I0 fixture root."""

    def _load(name: str) -> dict[str, object]:
        path = h2_i0_fixtures_root / name
        if not path.is_file():
            raise FileNotFoundError(f"h2_i0 fixture missing: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    return _load
