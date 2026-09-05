"""RQ4-R2-C2-R2: WorkContract write-token path normalization MUST equal
proposal-side path normalization.

C2-R2 contract: ``valid in WorkContract iff valid in proposal``.

The previous R1 test (``test_security_invariants_aligned``) was satisfied
only on a security-critical subset (empty, absolute, traversal, ``.``).
That allowed semantic divergence on the rest of the path space
(``foo bar.py``, ``(weird).py``, ``name@v1.py``, ``한글파일.py``,
``tests\\test_calculator.py``, ...). The Owner flagged this as a
remaining blocker for C2 close because two path semantics cannot coexist
on the same authority boundary.

This module proves ONE canonical normalizer
(:func:`synapx_harness.evidence.command_runner.normalize_write_token_path`)
is used by BOTH sides:

* WorkContract write-token side: ``normalize_write_token_path``
* Proposal / parse_allowed_write_paths side: ``_normalize_repo_relative``
  delegates to the same function.

For every case in :data:`SEMANTIC_IDENTITY_MATRIX`, both normalizers
either accept and produce the same canonical string, or both reject.
The total ``semantic_divergence_count`` MUST be zero.
"""
from __future__ import annotations

import pytest

from synapx_harness.evidence.command_runner import (
    normalize_write_token_path,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    MutationProposalContractError,
    _normalize_repo_relative,
    parse_allowed_write_paths,
)


# ---------------------------------------------------------------------------
# Differential matrix (RQ4-R2-C2-R2 §7)
# ---------------------------------------------------------------------------
#
# Each entry is ``(raw_input, expected_normalized_or_REJECT)``.
# The "expected" column is computed from the canonical semantics in
# :func:`normalize_write_token_path`; we then assert that BOTH the
# WorkContract side and the Proposal side produce the same result.

SEMANTIC_IDENTITY_MATRIX: list[tuple[str, str]] = [
    # Positive — basic shapes
    ("calculator.py", "calculator.py"),
    ("./calculator.py", "calculator.py"),
    ("tests/test_calculator.py", "tests/test_calculator.py"),
    ("tests\\test_calculator.py", "tests/test_calculator.py"),
    # Positive — interior / unusual characters
    ("foo bar.py", "foo bar.py"),
    ("dir/foo bar.py", "dir/foo bar.py"),
    ("(weird).py", "(weird).py"),
    ("name@v1.py", "name@v1.py"),
    ("한글파일.py", "한글파일.py"),
    # Negative — security-critical
    ("../secret.py", "REJECT"),
    ("/a.py", "REJECT"),
    ("C:\\a.py", "REJECT"),
    (".", "REJECT"),
    ("", "REJECT"),  # the empty path sentinel from §7 / §9
]


def _normalize_workcontract(raw: str) -> str:
    try:
        return normalize_write_token_path(raw)
    except ValueError:
        return "REJECT"


def _normalize_proposal(raw: str) -> str:
    try:
        return _normalize_repo_relative(raw)
    except MutationProposalContractError:
        return "REJECT"


@pytest.mark.parametrize("raw, expected", SEMANTIC_IDENTITY_MATRIX)
def test_full_semantic_identity_matrix(raw: str, expected: str) -> None:
    """Every matrix case MUST yield identical outcomes from both sides.

    ``semantic_divergence_count`` is the test failure indicator: this
    assertion fails on ANY divergence. The matrix covers both security
    rejections and non-security path shapes (spaces, parentheses,
    ``@``, non-ASCII) so that the proposal-side char whitelist cannot
    silently re-introduce a second policy.
    """
    workcontract_outcome = _normalize_workcontract(raw)
    proposal_outcome = _normalize_proposal(raw)

    assert workcontract_outcome == proposal_outcome, (
        f"semantic divergence on {raw!r}: "
        f"workcontract={workcontract_outcome!r} "
        f"proposal={proposal_outcome!r}"
    )
    assert workcontract_outcome == expected, (
        f"outcome drift on {raw!r}: "
        f"got={workcontract_outcome!r} expected={expected!r}"
    )


def test_semantic_divergence_count_is_zero() -> None:
    """Explicit divergence-count assertion (matches evidence schema).

    The differential matrix is iterated again here so a single integer
    counter is surfaced in the pytest output for evidence ingestion.
    """
    divergences = 0
    for raw, _expected in SEMANTIC_IDENTITY_MATRIX:
        if _normalize_workcontract(raw) != _normalize_proposal(raw):
            divergences += 1
    assert divergences == 0, (
        f"semantic_divergence_count={divergences} > 0; "
        "WorkContract and Proposal path semantics diverged."
    )


# ---------------------------------------------------------------------------
# Parser tests (RQ4-R2-C2-R2 §8)
# ---------------------------------------------------------------------------


class TestParseAllowedWritePathsInteriorSpace:
    def test_parser_accepts_interior_space_path(self) -> None:
        text = (
            "Allowed write paths:\n"
            "- foo bar.py\n"
        )
        assert parse_allowed_write_paths(text) == ["foo bar.py"]

    def test_parser_accepts_mixed_paths_with_spaces(self) -> None:
        text = (
            "Allowed write paths:\n"
            "- dir/foo bar.py\n"
            "- calculator.py\n"
        )
        assert parse_allowed_write_paths(text) == [
            "dir/foo bar.py",
            "calculator.py",
        ]

    def test_parser_dedup_after_normalization(self) -> None:
        text = (
            "Allowed write paths:\n"
            "- calculator.py\n"
            "- ./calculator.py\n"
            "- tests\\test_calculator.py\n"
            "- tests/test_calculator.py\n"
        )
        assert parse_allowed_write_paths(text) == [
            "calculator.py",
            "tests/test_calculator.py",
        ]


# ---------------------------------------------------------------------------
# Negative tests (RQ4-R2-C2-R2 §9)
# ---------------------------------------------------------------------------


NEGATIVE_RAWS = [
    "../secret.py",
    "/a.py",
    "C:\\a.py",
    ".",
    "",
]


@pytest.mark.parametrize("raw", NEGATIVE_RAWS)
def test_negative_paths_rejected_by_both_normalizers(raw: str) -> None:
    """Both sides MUST reject every security-critical negative.

    No path may become safer on one side and unsafe on the other.
    """
    workcontract_outcome = _normalize_workcontract(raw)
    proposal_outcome = _normalize_proposal(raw)

    assert workcontract_outcome == "REJECT", (
        f"WorkContract accepted security-negative {raw!r}; got "
        f"{workcontract_outcome!r}"
    )
    assert proposal_outcome == "REJECT", (
        f"Proposal accepted security-negative {raw!r}; got "
        f"{proposal_outcome!r}"
    )


def test_empty_string_rejected_by_both() -> None:
    """``""`` is the explicit "empty" sentinel from §7.

    Empty string rejection is part of the canonical semantics.
    """
    assert _normalize_workcontract("") == "REJECT"
    assert _normalize_proposal("") == "REJECT"


# ---------------------------------------------------------------------------
# Alias / delegation invariant (RQ4-R2-C2-R2 §4)
# ---------------------------------------------------------------------------


def test_proposal_normalizer_delegates_to_canonical() -> None:
    """The proposal-side wrapper MUST be a pure delegation.

    ``_normalize_repo_relative`` is the compatibility shim around the
    canonical normalizer. Stripping both sides of whitespace and stripping
    empty strings is part of the proposal-side contract, so for any input
    that survives both layers' strip+normalize pipeline the canonical
    function MUST produce the same answer.
    """
    for raw, expected in SEMANTIC_IDENTITY_MATRIX:
        if expected == "REJECT":
            continue
        # leading/trailing whitespace is tolerated by both layers
        assert _normalize_repo_relative("  " + raw + "  ") == expected


def test_canonical_function_is_public() -> None:
    """The canonical normalizer MUST be importable as a public symbol.

    ``_verify_write_token_path`` is preserved as a backward-compatible
    alias, but the source of truth is the public
    ``normalize_write_token_path``.
    """
    import synapx_harness.evidence.command_runner as cr

    assert hasattr(cr, "normalize_write_token_path")
    assert callable(cr.normalize_write_token_path)
    # Public symbol appears in __all__ so future readers / lint see it.
    assert "normalize_write_token_path" in cr.__all__


def test_verify_write_token_path_is_alias() -> None:
    """``_verify_write_token_path`` is a thin wrapper; no behavioral drift.

    Equivalent inputs produce identical outputs, including rejection
    messages carrying the deterministic ``(INVALID_WRITE_SET_PATH)`` token.
    """
    from synapx_harness.evidence.command_runner import (
        _verify_write_token_path,
    )

    for raw, expected in SEMANTIC_IDENTITY_MATRIX:
        if expected == "REJECT":
            with pytest.raises(ValueError) as excinfo:
                _verify_write_token_path(raw)
            assert "INVALID_WRITE_SET_PATH" in str(excinfo.value)
        else:
            assert _verify_write_token_path(raw) == expected
