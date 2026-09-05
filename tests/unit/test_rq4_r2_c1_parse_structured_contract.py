"""Contract tests for RQ4-R2 parse_structured canonical decoder.

These tests exercise ONLY the deterministic structured-proposal decoder
defined on ``PatchProposalParser.parse_structured``. They are bounded to
the partial implementation that the previous CodeBuddy HY4 Preview worker
deposited and that survived the recovery checkpoint.

Scope per continuation work order §16 (initial block C1..C4):

* C1 - strict structured proposal accepted
* C2 - free-form Codex prose rejected
* C3 - malformed markers rejected
* C4 - duplicate FILE section rejected

The remaining contract tests (C5..C14) are out of scope for this C1
continuation slice and will be added in a later worker session.

The tests do not depend on filesystem, network, or any external
subprocess: they are pure unit assertions on the dataclasses and the
parser state machine.
"""
from __future__ import annotations

import hashlib

import pytest

from synapx_harness.kernel.mutation_authority import (
    PatchProposalParser,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_structured_proposal(file_path: str, old: str, new: str) -> str:
    """Build a deterministic, well-formed structured proposal string."""
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


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def parser() -> PatchProposalParser:
    return PatchProposalParser()


# ---------------------------------------------------------------------------
# C1 - strict structured proposal accepted
# ---------------------------------------------------------------------------


class TestC1StrictStructuredProposalAccepted:
    """C1: a canonical structured proposal is decoded into a valid PatchProposal."""

    def test_canonical_proposal_yields_valid_patch_proposal(self, parser: PatchProposalParser) -> None:
        stdout = _build_structured_proposal(
            "calculator.py",
            old="def add(a, b):\n    return a + b\n",
            new="def add(a, b):\n    return a + b\n\n\ndef subtract(a, b):\n    return a - b\n",
        )

        proposal = parser.parse_structured(stdout)

        assert proposal.valid is True
        assert proposal.paths == ["calculator.py"]
        assert len(proposal.hunks) == 1
        assert proposal.hunks[0].file_path == "calculator.py"
        assert proposal.hunks[0].old_lines[0].startswith("def add(a, b):")
        assert proposal.hunks[0].new_lines[0].startswith("def add(a, b):")
        assert "def subtract(a, b):" in proposal.hunks[0].new_lines[0]
        assert "return a - b" in proposal.hunks[0].new_lines[0]
        assert proposal.parse_error is None

    def test_canonical_proposal_sha256_is_canonical_patch_sha(self, parser: PatchProposalParser) -> None:
        stdout = _build_structured_proposal(
            "x.py",
            old="a = 1\n",
            new="a = 2\n",
        )

        proposal = parser.parse_structured(stdout)

        assert proposal.sha256 != ""
        assert proposal.canonical_patch_sha256 == proposal.sha256
        assert proposal.raw_input_sha256 == _sha256(stdout)


# ---------------------------------------------------------------------------
# C2 - free-form Codex prose rejected
# ---------------------------------------------------------------------------


class TestC2FreeFormProseRejected:
    """C2: any text that lacks the canonical framing is invalid."""

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "   ",
            "I will modify calculator.py to add a subtract function.",
            "Here is the diff:\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new",
            "Please apply this change to your repo:\nold -> new",
        ],
        ids=["empty", "whitespace_only", "natural_language", "unified_diff", "change_to_format"],
    )
    def test_prose_without_markers_is_invalid(self, parser: PatchProposalParser, stdout: str) -> None:
        proposal = parser.parse_structured(stdout)

        assert proposal.valid is False
        assert proposal.hunks == []
        assert proposal.paths == []
        assert proposal.old_lines == []
        assert proposal.new_lines == []
        assert proposal.parse_error is not None
        assert proposal.parse_error != ""


# ---------------------------------------------------------------------------
# C3 - malformed markers rejected
# ---------------------------------------------------------------------------


class TestC3MalformedMarkersRejected:
    """C3: any structural deviation from the encoding is invalid."""

    def test_missing_begin_marker_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            "FILE: calculator.py\n"
            "<<<< OLD\nold\n>>>> OLD\n"
            "<<<< NEW\nnew\n>>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None

    def test_missing_end_marker_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\nold\n>>>> OLD\n"
            "<<<< NEW\nnew\n>>>> NEW\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None

    def test_unmatched_old_terminator_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "old\n"
            ">>>> NEW\n"
            "<<<< NEW\n"
            "new\n"
            ">>>> OLD\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None

    def test_unterminated_old_block_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "old\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None

    def test_conflict_marker_inside_proposal_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "old\n"
            "<<<<<<<<\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "new\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None
        assert "conflict marker" in proposal.parse_error

    def test_old_equals_new_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "same\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "same\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None
        assert "OLD equals NEW" in proposal.parse_error

    def test_empty_old_block_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "new\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None

    def test_empty_new_block_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "old\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None


# ---------------------------------------------------------------------------
# C4 - duplicate FILE section rejected
# ---------------------------------------------------------------------------


class TestCDuplicateFileSectionRejected:
    """C4: the same file path must not appear twice in one proposal."""

    def test_duplicate_file_path_is_rejected(self, parser: PatchProposalParser) -> None:
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "old1\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "new1\n"
            ">>>> NEW\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "old2\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "new2\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is False
        assert proposal.parse_error is not None
        assert "duplicate FILE section" in proposal.parse_error

    def test_two_distinct_files_are_accepted(self, parser: PatchProposalParser) -> None:
        """Two distinct FILE sections remain valid (multi-file support)."""
        stdout = (
            f"{PROPOSAL_BEGIN}\n"
            "FILE: calculator.py\n"
            "<<<< OLD\n"
            "def add(a, b):\n    return a + b\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "def add(a, b):\n    return a + b\n\n\ndef subtract(a, b):\n    return a - b\n"
            ">>>> NEW\n"
            "FILE: tests/test_calculator.py\n"
            "<<<< OLD\n"
            "def test_add():\n    assert add(2, 3) == 5\n"
            ">>>> OLD\n"
            "<<<< NEW\n"
            "def test_add():\n    assert add(2, 3) == 5\n\n\ndef test_subtract():\n    assert subtract(5, 3) == 2\n"
            ">>>> NEW\n"
            f"{PROPOSAL_END}\n"
        )
        proposal = parser.parse_structured(stdout)
        assert proposal.valid is True
        assert proposal.paths == ["calculator.py", "tests/test_calculator.py"]
        assert len(proposal.hunks) == 2
        assert proposal.canonical_patch_sha256 == proposal.sha256
