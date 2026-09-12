"""RQ8-P1-R1 admission repair regression tests (bounded).

Covers Work Order RQ8-P1-R1 Sec 9-12 on top of the RQ8-P1 RC2 reason
repair (DENY always carries a non-None authoritative reason):

Authority rule under test (see RQ8_P1_R1_RED_AUTHORITY_CENSUS.json):
the harness only READS staged RED evidence. The intended-defect binding
is asserted by whoever stages the artifact (fixture author / operator
who knows the intended defect). A bare failing suite is NEVER equated
with a matched defect, staged artifacts are never created/overwritten,
and every other case fails closed with its cause.

* Sec 10: exact RQ8 contract (src/itsdangerous/url_safe.py, nested path)
  admitted via staged legitimate RED evidence. The calculator synthetic
  is kept as a secondary fixture only.
* Sec 11: mandatory negatives -- unrelated failures never auto-admit,
  exit-1/match-False DENYs, malformed/unreadable/green/non-1 staged
  evidence DENYs with the artifact preserved, path negatives DENY.
* Sec 12: first-failure chain truth.
* Sec 9: DENY reasons name the first authoritative cause, never None.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from synapx_harness.cli.agent_activity import source_from_result
from synapx_harness.cli.assurance_presentation import build_assurance_presentation
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_authority import (
    ExactPathMutationGate,
    MutationAdmissionGate,
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
    parse_allowed_write_paths,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

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

# Exact RQ8 P1 contract text shape (Work Order Sec 28).
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
    """Nested src-layout mirror of the RQ8 P1 target contract."""
    pkg = root / "src" / "itsdangerous"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "url_safe.py").write_text(
        URL_SAFE_BROKEN if broken else URL_SAFE_FIXED, encoding="utf-8"
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_url_safe.py").write_text(
        URL_SAFE_TEST, encoding="utf-8"
    )
    return root


def _stage_red(
    repo: Path,
    *,
    exit_code: int = 1,
    match: bool = True,
    ref: str | None = None,
) -> Path:
    """Operator-role staging of RED evidence (the legitimate producer).

    Mirrors the canonical run_red_evidence.py artifact shape: the match
    assertion travels WITH auditable observed evidence, asserted by the
    stager who knows the intended defect -- never derived by the harness.
    """
    path = Path(ref) if ref is not None else repo / ".synapx_red_evidence.json"
    path.write_text(
        json.dumps(
            {
                "exit_code": exit_code,
                "failure_reason_matches_intended_defect": match,
                "failure_reason": "observed RED failure for the intended defect",
                "intended_defect": "staged by test operator",
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
        verification_command=[sys.executable, "-m", "pytest", "-q"],
        codex_stdout_override=proposal,
        red_qualification_ref=red_qualification_ref,
        red_qualified_override=red_qualified_override,
    )
    return run_governed_execution(request)


# ---------------------------------------------------------------------------
# Sec 10 -- Exact RQ8 path regression (nested path, staged authority)
# ---------------------------------------------------------------------------


class TestExactRQ8PathContract:
    def test_canonical_rq8_write_set_parses_exactly(self) -> None:
        assert parse_allowed_write_paths(RQ8_TASK) == [
            "src/itsdangerous/url_safe.py"
        ]

    def test_exact_nested_path_admitted_with_staged_red(
        self, tmp_path: Path
    ) -> None:
        """Exact RQ8 contract: nested allowed path + exact proposed path +
        operator-staged qualified RED -> ALLOW / ALLOW / mutated / PASS /
        COMPLETED on the public default path (no ref, no override)."""
        repo = _write_url_safe_repo(tmp_path / "p1", broken=True)
        _stage_red(repo, exit_code=1, match=True)
        old = "        decompress = False\n"
        new = "        decompress = True\n"
        result = _run(
            repo,
            proposal=_proposal_text("src/itsdangerous/url_safe.py", old, new),
            task=RQ8_TASK,
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"
        assert result.path_gate_receipt is not None
        assert result.path_gate_receipt.gate_decision == "ALLOW"
        assert result.path_gate_receipt.proposal_paths == [
            "src/itsdangerous/url_safe.py"
        ]
        assert result.mutation_attempted is True
        assert result.verification_attempted is True
        assert result.errors == []
        assert result.terminal_decision.decision == "COMPLETED"
        assert (repo / "src" / "itsdangerous" / "url_safe.py").read_text(
            encoding="utf-8"
        ) == URL_SAFE_FIXED

    def test_calculator_synthetic_kept(self, tmp_path: Path) -> None:
        """Secondary synthetic positive (kept, does not replace Sec 10)."""
        repo = _write_calc_repo(tmp_path / "calc", broken=True)
        _stage_red(repo, exit_code=1, match=True)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"
        assert result.mutation_attempted is True
        assert result.terminal_decision.decision == "COMPLETED"


# ---------------------------------------------------------------------------
# Sec 7/8 -- Staged evidence authority and preservation
# ---------------------------------------------------------------------------


class TestStagedEvidenceAuthority:
    def test_explicit_ref_still_honored(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "staged", broken=True)
        ref = _stage_red(
            repo,
            exit_code=1,
            match=True,
            ref=str(repo / "custom_red.json"),
        )
        result = _run(
            repo,
            proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED),
            red_qualification_ref=str(ref),
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"

    def test_override_seams_unchanged(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "override", broken=True)
        result = _run(
            repo,
            proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED),
            red_qualified_override=True,
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "ALLOW"

    def test_malformed_artifact_denies_and_is_preserved(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "malformed", broken=True)
        red_path = repo / ".synapx_red_evidence.json"
        garbage = b"{not json###"
        red_path.write_bytes(garbage)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        # Existing evidence lineage is preserved byte-for-byte.
        assert red_path.read_bytes() == garbage

    def test_unreadable_artifact_denies_and_is_preserved(
        self, tmp_path: Path
    ) -> None:
        repo = _write_calc_repo(tmp_path / "unreadable", broken=True)
        red_path = repo / ".synapx_red_evidence.json"
        red_path.write_text("{}", encoding="utf-8")
        red_path.unlink()
        red_path.mkdir()
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert red_path.is_dir()

    def test_missing_artifact_denies_and_creates_nothing(
        self, tmp_path: Path
    ) -> None:
        """No staged evidence -> fail closed WITHOUT the harness writing
        any artifact of its own (Sec 8 preservation)."""
        repo = _write_calc_repo(tmp_path / "missing", broken=True)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert not (repo / ".synapx_red_evidence.json").exists()


# ---------------------------------------------------------------------------
# Sec 11 -- Mandatory negatives: failures never auto-admit
# ---------------------------------------------------------------------------


class TestNoAutoAdmission:
    def test_unrelated_failing_suite_without_staged_red_denies(
        self, tmp_path: Path
    ) -> None:
        """A genuinely failing suite (real exit 1) with NO staged
        intended-defect binding must NOT admit. This is the rejected
        da64adc equation, pinned as a negative."""
        repo = _write_calc_repo(tmp_path / "unrelated", broken=True)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False
        assert "None" not in str(result.errors[0])

    def test_exit1_without_defect_match_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "nomatch", broken=True)
        _stage_red(repo, exit_code=1, match=False)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_green_suite_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "green", broken=False)
        _stage_red(repo, exit_code=0, match=True)
        proposal = _proposal_text(
            "calculator.py", CALC_FIXED, CALC_FIXED + "\n# touch\n"
        )
        result = _run(repo, proposal=proposal)
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False

    def test_collection_error_exit_code_denies(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "colerr", broken=True)
        _stage_red(repo, exit_code=2, match=True)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.mutation_attempted is False


class TestPathNegatives:
    def _parsed(self, file_path: str) -> object:
        proposal = PatchProposalParser().parse_structured(
            _proposal_text(file_path, "old-text", "new-text")
        )
        assert proposal.valid
        return proposal

    def test_gate_denies_without_reason_loss(self) -> None:
        gate = MutationAdmissionGate()
        receipt = gate.admit(
            work_contract_id="wc-test",
            red_qualified=False,
            red_qualification_ref="/nonexistent/red.json",
            source_revision="rev",
            execution_identity={},
            allowed_write_paths=["calculator.py"],
        )
        assert receipt.admission_decision == "DENY"
        assert receipt.denied_reason is not None
        assert "None" not in str(receipt.denied_reason)

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
        repo = _write_calc_repo(tmp_path / "neg", broken=True)
        _stage_red(repo, exit_code=1, match=True)
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
        repo = _write_calc_repo(tmp_path / "traversal", broken=True)
        _stage_red(repo, exit_code=1, match=True)
        result = _run(
            repo,
            proposal=_proposal_text("../escape.py", "x = 1\n", "x = 2\n"),
        )
        assert result.mutation_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert not (tmp_path / "escape.py").exists()

    def test_absolute_end_to_end_blocked(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "absolute", broken=True)
        _stage_red(repo, exit_code=1, match=True)
        result = _run(
            repo,
            proposal=_proposal_text("/abs/external.py", "x = 1\n", "x = 2\n"),
        )
        assert result.mutation_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"


# ---------------------------------------------------------------------------
# Sec 9/12 -- Reason truth and first-failure chain
# ---------------------------------------------------------------------------


class TestReasonAndChainTruth:
    def test_first_failure_chain(self, tmp_path: Path) -> None:
        repo = _write_calc_repo(tmp_path / "chain", broken=True)
        _stage_red(repo, exit_code=0, match=True)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        assert result.admission_receipt is not None
        assert result.admission_receipt.admission_decision == "DENY"
        assert result.path_gate_receipt is None
        assert result.mutation_attempted is False
        assert result.verification_attempted is False
        assert result.terminal_decision.decision == "BLOCKED"
        assert result.errors
        assert result.errors[0] == result.primary_failure_message
        assert "None" not in str(result.errors[0])
        assurance = build_assurance_presentation(result)
        assert assurance.terminal_reason == result.errors[0]

    def test_completed_agent_beside_blocked_terminal(
        self, tmp_path: Path
    ) -> None:
        """Agent DONE + later admission DENY: activity Completed coexists
        with BLOCKED; activity is never derived from terminal state."""
        repo = _write_calc_repo(tmp_path / "coexist", broken=True)
        _stage_red(repo, exit_code=0, match=True)
        result = _run(
            repo, proposal=_proposal_text("calculator.py", CALC_BROKEN, CALC_FIXED)
        )
        agent = source_from_result(result)
        assert agent is not None
        assert agent.process_started is True
        assurance = build_assurance_presentation(result)
        assert assurance.terminal_state == "BLOCKED"
