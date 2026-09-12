"""RQ8-P1-R3 RED admission integration tests (bounded, test-first).

Contract under test (RQ8-REDQ-001, MODIFIED_OPTION_B):

* The public default path admits ONLY on comparator-derived match output
  from (QualifiedRedExpectation + actual RedObservation). Transport for
  the expectation is the default-path staged file
  ``workspace/.synapx_red_expectation.json``; the harness never invents it.
* Legacy ``.synapx_red_evidence.json`` booleans no longer authorize the
  public path (N14). Explicit caller seams (red_qualification_ref /
  red_qualified_override) stay as caller-asserted, non-authoritative test
  seams (Sec 18); the bridge always sends None on public entries.
* This file imports ONLY pre-existing modules so it collects both
  pre-repair (27c8d08, no comparator) and post-repair. Fingerprints and
  revisions are computed with stdlib mirrors of the specified canonical
  rules so no unimplemented helper is needed here.

Pre-repair (27c8d08) expected: F1/F2/F3 FAIL (no expectation transport,
legacy literal authorizes, no revision check); the rest of the matrix
already DENYs and keeps passing.
"""
from __future__ import annotations

import hashlib
import json
import sys
import textwrap
from pathlib import Path

import pytest

from synapx_harness.cli.agent_activity import source_from_result
from synapx_harness.cli.assurance_presentation import build_assurance_presentation
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    _fixture_root_sha,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_authority import (
    ExactPathMutationGate,
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
    parse_allowed_write_paths,
)

EXPECTATION_FILENAME = ".synapx_red_expectation.json"

CALC_BROKEN = "def add(a, b):\n    return a + b\n"

CALC_FIXED = (
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "\n"
    "def subtract(a, b):\n"
    "    return a - b\n"
)

CALC_TEST = textwrap.dedent(
    """\
    import calculator


    def test_add():
        assert calculator.add(2, 3) == 5


    def test_subtract():
        assert calculator.subtract(5, 3) == 2
    """
)

CALC_TASK = (
    "Fix the subtract regression.\n"
    "\n"
    "Allowed write paths:\n"
    "- calculator.py\n"
    "\n"
    "Do not modify unrelated files.\n"
    "Run the repository's authoritative tests and only complete "
    "if verification passes.\n"
)

CALC_FAILED_IDS = ["tests/test_calculator.py::test_subtract"]

RQ8_TASK = (
    "Fix the compressed URL-safe payload regression.\n"
    "\n"
    "Allowed write paths:\n"
    "- src/itsdangerous/url_safe.py\n"
    "\n"
    "Do not modify unrelated files.\n"
    "Run the repository's authoritative tests and only complete "
    "if verification passes.\n"
)

URL_SAFE_BROKEN = textwrap.dedent(
    '''\
    """Minimal mirror of the P1 seeded url_safe compressed-payload defect."""
    import zlib


    def dumps_payload(data: bytes) -> bytes:
        return b"." + zlib.compress(data)


    def loads_payload(payload: bytes) -> bytes:
        decompress = False
        if payload.startswith(b"."):
            payload = payload[1:]
            decompress = False
        if decompress:
            return zlib.decompress(payload)
        return payload
    '''
)

URL_SAFE_FIXED = URL_SAFE_BROKEN.replace(
    "        decompress = False\n", "        decompress = True\n", 1
)

URL_SAFE_TEST = textwrap.dedent(
    """\
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

    from itsdangerous.url_safe import dumps_payload, loads_payload


    def test_roundtrip_compressed():
        assert loads_payload(dumps_payload(b"hello")) == b"hello"


    def test_roundtrip_empty():
        assert loads_payload(dumps_payload(b"")) == b""
    """
)

URL_SAFE_FAILED_IDS = [
    "tests/test_url_safe.py::test_roundtrip_compressed",
    "tests/test_url_safe.py::test_roundtrip_empty",
]


def _fp(command: list[str]) -> str:
    """Stdlib mirror of the specified canonical fingerprint rule."""
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _write_calc_repo(root: Path, *, broken: bool) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "calculator.py").write_text(
        CALC_BROKEN if broken else CALC_FIXED, encoding="utf-8"
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_calculator.py").write_text(CALC_TEST, encoding="utf-8")
    return root


def _write_url_safe_repo(root: Path, *, broken: bool) -> Path:
    pkg = root / "src" / "itsdangerous"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "url_safe.py").write_text(
        URL_SAFE_BROKEN if broken else URL_SAFE_FIXED, encoding="utf-8"
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_url_safe.py").write_text(URL_SAFE_TEST, encoding="utf-8")
    return root


def _stage_expectation(
    repo: Path,
    *,
    revision: str | None = None,
    fingerprint: str | None = None,
    exit_code: int = 1,
    failed_ids: list[str] | None = None,
    status: str = "QUALIFIED",
    source_type: str = "BENCHMARK_FIXTURE",
    rule: str = "EXACT_FAILED_TEST_IDS",
    provenance: dict[str, str] | None = None,
    raw: object = None,
) -> Path:
    """Stage a QualifiedRedExpectation candidate at the default path."""
    path = repo / EXPECTATION_FILENAME
    if raw is not None:
        if isinstance(raw, bytes):
            path.write_bytes(raw)
        else:
            path.write_text(str(raw), encoding="utf-8")
        return path
    payload: dict[str, object] = {
        "expectation_id": "test/expectation/v1",
        "expectation_version": 1,
        "status": status,
        "source_type": source_type,
        "source_revision": (
            revision if revision is not None else _fixture_root_sha(repo)
        ),
        "verification_command_fingerprint": fingerprint or "",
        "expected_exit_code": exit_code,
        "match_rule": rule,
        "required_failed_test_ids": (
            list(CALC_FAILED_IDS) if failed_ids is None else list(failed_ids)
        ),
        "provenance": (
            {"source_ref": "test-stager", "source_sha256": "0" * 64}
            if provenance is None
            else dict(provenance)
        ),
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _stage_legacy_boolean(
    repo: Path, *, exit_code: int = 1, match: bool = True
) -> Path:
    path = repo / ".synapx_red_evidence.json"
    path.write_text(
        json.dumps(
            {
                "exit_code": exit_code,
                "failure_reason_matches_intended_defect": match,
            }
        ),
        encoding="utf-8",
    )
    return path


def _proposal_text(file_path: str, old: str, new: str) -> str:
    return (
        f"{PROPOSAL_BEGIN}\n"
        f"FILE: {file_path}\n"
        f"<<<< OLD\n"
        f"{old}\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"{new}\n"
        f">>>> NEW\n"
        f"{PROPOSAL_END}\n"
    )


def _calc_fix_proposal() -> str:
    return _proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)


VERIFICATION_COMMAND = [sys.executable, "-m", "pytest", "-q"]


def _run(
    repo: Path,
    *,
    proposal: str,
    task: str = CALC_TASK,
    red_qualification_ref: str | None = None,
    red_qualified_override: bool | None = None,
):  # -> GovernedExecutionResult
    request = GovernedExecutionRequest(
        workspace_root=repo,
        task=task,
        verification_command=list(VERIFICATION_COMMAND),
        codex_stdout_override=proposal,
        red_qualification_ref=red_qualification_ref,
        red_qualified_override=red_qualified_override,
    )
    return run_governed_execution(request)


# ---------------------------------------------------------------------------
# Sec 25 pre-repair failures + Sec 26 mandatory positive
# ---------------------------------------------------------------------------


class TestPositiveContract:
    def test_qualified_expectation_matching_failure_admits(
        self, tmp_path: Path
    ) -> None:
        """F1/Sec 26: RED_REQUIRED + qualified BENCHMARK_FIXTURE expectation
        + matching revision/command/exit/IDs + TEST_FAILURE -> RED QUALIFIED
        -> Admission ALLOW -> COMPLETED. FAILS pre-repair (no transport)."""
        repo = _write_calc_repo(tmp_path / "pos", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"
        assert result.path_gate_receipt is not None
        assert result.path_gate_receipt.gate_decision == "ALLOW"
        assert result.mutation_attempted is True
        assert result.verification_attempted is True
        assert result.errors == []
        assert result.terminal_decision.decision == "COMPLETED"
        assert (repo / "calculator.py").read_text(encoding="utf-8") == CALC_FIXED

    def test_exact_rq8_nested_path_positive(self, tmp_path: Path) -> None:
        """Exact RQ8 contract on the nested path via staged expectation."""
        assert parse_allowed_write_paths(RQ8_TASK) == [
            "src/itsdangerous/url_safe.py"
        ]
        repo = _write_url_safe_repo(tmp_path / "p1", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=list(URL_SAFE_FAILED_IDS),
        )
        result = _run(
            repo,
            proposal=_proposal_text(
                "src/itsdangerous/url_safe.py",
                "        decompress = False\n",
                "        decompress = True\n",
            ),
            task=RQ8_TASK,
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"
        assert result.path_gate_receipt is not None
        assert result.path_gate_receipt.gate_decision == "ALLOW"
        assert result.mutation_attempted is True
        assert result.terminal_decision.decision == "COMPLETED"
        assert (repo / "src" / "itsdangerous" / "url_safe.py").read_text(
            encoding="utf-8"
        ) == URL_SAFE_FIXED

    def test_legacy_literal_true_no_longer_authorizes(
        self, tmp_path: Path
    ) -> None:
        """F2/N14: legacy match=true boolean without comparator proof must
        DENY on the public path. FAILS pre-repair (it ALLOWS)."""
        repo = _write_calc_repo(tmp_path / "legacy", broken=True)
        _stage_legacy_boolean(repo, exit_code=1, match=True)
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert "None" not in str(result.errors[0])

    def test_revision_mismatch_denies(self, tmp_path: Path) -> None:
        """F3/N7: expectation bound to a different pre-mutation revision
        must DENY. FAILS pre-repair (no revision check exists)."""
        repo = _write_calc_repo(tmp_path / "revmis", broken=True)
        _stage_expectation(
            repo,
            revision="0" * 64,
            fingerprint=_fp(VERIFICATION_COMMAND),
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False


# ---------------------------------------------------------------------------
# Sec 27 negative matrix (admission level)
# ---------------------------------------------------------------------------


class TestNegativeMatrix:
    def test_n1_exit1_without_discriminator_denies(
        self, tmp_path: Path
    ) -> None:
        """N1: exit 1 with no usable defect discriminator (empty required
        IDs) can never qualify."""
        repo = _write_calc_repo(tmp_path / "n1", broken=True)
        _stage_expectation(
            repo, fingerprint=_fp(VERIFICATION_COMMAND), failed_ids=[]
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n2_wrong_failure_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n2", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=["tests/test_other.py::test_elsewhere"],
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n3_extra_unrelated_failure_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n3", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=[*CALC_FAILED_IDS, "tests/test_calculator.py::test_add"],
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n4_missing_expectation_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n4", broken=True)
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert not (repo / EXPECTATION_FILENAME).exists()

    def test_n5_proposed_expectation_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n5", broken=True)
        _stage_expectation(
            repo, fingerprint=_fp(VERIFICATION_COMMAND), status="PROPOSED"
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n6_llm_proposed_source_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n6", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            source_type="LLM_PROPOSED",
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n8_command_fingerprint_mismatch_denies(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "n8", broken=True)
        _stage_expectation(repo, fingerprint="f" * 64)
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n9_collection_failure_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n9", broken=True)
        (repo / "tests" / "test_broken.py").write_text(
            "def broken(:\n", encoding="utf-8"
        )
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n10_infrastructure_failure_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n10", broken=True)
        _stage_expectation(repo, fingerprint=_fp(["exit-3-stub"]))
        request = GovernedExecutionRequest(
            workspace_root=repo,
            task=CALC_TASK,
            verification_command=[
                sys.executable,
                "-c",
                "import sys; sys.exit(3)",
            ],
            codex_stdout_override=_calc_fix_proposal(),
        )
        result = run_governed_execution(request)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n11_unknown_parser_result_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n11", broken=True)
        _stage_expectation(repo, fingerprint=_fp(["exit-1-stub"]))
        request = GovernedExecutionRequest(
            workspace_root=repo,
            task=CALC_TASK,
            verification_command=[
                sys.executable,
                "-c",
                "import sys; sys.exit(1)",
            ],
            codex_stdout_override=_calc_fix_proposal(),
        )
        result = run_governed_execution(request)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n12_malformed_expectation_denies_and_preserved(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "n12", broken=True)
        garbage = b"{not json###"
        _stage_expectation(repo, raw=garbage)
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert (repo / EXPECTATION_FILENAME).read_bytes() == garbage

    def test_n13_missing_provenance_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n13", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            provenance={"source_ref": "", "source_sha256": ""},
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_n15_agent_done_with_deny_mutates_nothing(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "n15", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=["tests/test_other.py::test_elsewhere"],
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert result.verification_attempted is False
        assert (repo / "calculator.py").read_text(encoding="utf-8") == CALC_BROKEN

    def test_n16_green_cannot_retroactively_allow(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n16", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=["tests/test_other.py::test_elsewhere"],
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.terminal_decision.decision == "BLOCKED"
        assert result.mutation_attempted is False
        assert (repo / "calculator.py").read_text(encoding="utf-8") == CALC_BROKEN

    def test_n17_expectation_bytes_preserved(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "n17", broken=True)
        path = _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=["tests/test_other.py::test_elsewhere"],
        )
        before = path.read_bytes()
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert path.read_bytes() == before


# ---------------------------------------------------------------------------
# Path negatives, reason truth, chain, coexistence (retained R1 pins)
# ---------------------------------------------------------------------------


class TestPathNegatives:
    def _parsed(self, file_path: str) -> object:
        proposal = PatchProposalParser().parse_structured(
            _proposal_text(file_path, "old-text", "new-text")
        )
        assert proposal.valid
        return proposal

    @pytest.mark.parametrize(
        "proposed",
        [
            "../escape.py",
            "/abs/outside.py",
            "other.py",
            "calculator.py.bak",
            "sub/calculator.py",
        ],
    )
    def test_negative_paths_stay_denied(self, proposed: str) -> None:
        gate = ExactPathMutationGate()
        receipt = gate.check(
            proposal=self._parsed(proposed),  # type: ignore[arg-type]
            allowed_write_paths=["calculator.py"],
            source_revision="rev",
            admission_receipt_id="rct/x",
        )
        assert receipt.gate_decision == "DENY"
        assert receipt.apply_authority == "NOT_ISSUED"
        assert receipt.reason is not None

    def test_unauthorized_sibling_end_to_end_blocked(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "sib", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        (repo / "other.py").write_text("x = 1\n", encoding="utf-8")
        result = _run(
            repo, proposal=_proposal_text("other.py", "x = 1\n", "x = 2\n")
        )
        assert result.mutation_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert result.errors
        assert all("None" not in str(e) for e in result.errors)
        assert (repo / "other.py").read_text(encoding="utf-8") == "x = 1\n"

    def test_traversal_end_to_end_blocked(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "trav", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(
            repo,
            proposal=_proposal_text("../escape.py", "x = 1\n", "x = 2\n"),
        )
        assert result.mutation_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert not (tmp_path / "escape.py").exists()

    def test_absolute_end_to_end_blocked(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "abs", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(
            repo,
            proposal=_proposal_text("/abs/external.py", "x = 1\n", "x = 2\n"),
        )
        assert result.mutation_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"


class TestReasonAndChainTruth:
    def test_first_failure_chain(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "chain", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=["tests/test_other.py::test_elsewhere"],
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.path_gate_receipt is None
        assert result.mutation_attempted is False
        assert result.verification_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert result.errors
        assert result.errors[0] == result.primary_failure_message
        assert "None" not in str(result.errors[0])
        assert "RED" in str(result.errors[0]).upper()
        assurance = build_assurance_presentation(result)
        assert assurance.terminal_reason == result.errors[0]

    def test_completed_agent_beside_blocked_terminal(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "coexist", broken=True)
        _stage_expectation(
            repo,
            fingerprint=_fp(VERIFICATION_COMMAND),
            failed_ids=["tests/test_other.py::test_elsewhere"],
        )
        result = _run(repo, proposal=_calc_fix_proposal())
        agent = source_from_result(result)
        assert agent is not None
        assert agent.process_started is True
        assurance = build_assurance_presentation(result)
        assert assurance.terminal_state == "BLOCKED"
