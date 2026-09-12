"""RQ8-P1-R3 deterministic RED comparator unit tests (bounded).

Pure tests over ``synapx_harness.kernel.red_qualification``: no subprocess,
no filesystem, no agent. Covers the Sec 10 conjunction and the Sec 27
negative matrix at unit level (N1-N14), plus fingerprint determinism,
expectation validation, and failure-kind classification.

Pre-repair (27c8d08) this module errors at import: the comparator does
not exist. That collection error is recorded as absence proof in
PRE_R3_FAILURE_EVIDENCE.log; post-repair all tests pass.
"""
from __future__ import annotations

import pytest

from synapx_harness.evidence.pytest_result_parser import (
    classify_pytest_failure_kind,
    parse_pytest_error_test_ids,
    parse_pytest_failed_test_ids,
)
from synapx_harness.kernel.red_qualification import (
    COMPARATOR_VERSION,
    ExpectationError,
    QualifiedRedExpectation,
    RedObservation,
    compare_red_qualification,
    verification_command_fingerprint,
)

COMMAND = ["uv", "run", "pytest", "-q"]
_CREATED_AT = "2026-01-01T00:00:00+00:00"
REVISION = "r" * 64
FP = verification_command_fingerprint(COMMAND)
IDS = ("tests/test_url_safe.py::test_roundtrip_compressed",)


def _compare(
    expectation: QualifiedRedExpectation, observation: RedObservation
):  # -> RedQualificationEvidence
    return compare_red_qualification(
        expectation, observation, created_at=_CREATED_AT
    )


def _expectation(**overrides: object) -> QualifiedRedExpectation:
    base: dict[str, object] = {
        "expectation_id": "rq8/itsdangerous/compressed-payload/v1",
        "expectation_version": 1,
        "status": "QUALIFIED",
        "source_type": "BENCHMARK_FIXTURE",
        "source_revision": REVISION,
        "verification_command_fingerprint": FP,
        "expected_exit_code": 1,
        "match_rule": "EXACT_FAILED_TEST_IDS",
        "required_failed_test_ids": list(IDS),
        "provenance": {"source_ref": "bench", "source_sha256": "a" * 64},
    }
    base.update(overrides)
    return QualifiedRedExpectation.from_dict(base)


def _observation(**overrides: object) -> RedObservation:
    base: dict[str, object] = {
        "observation_id": "obs/1",
        "source_revision": REVISION,
        "verification_command": list(COMMAND),
        "verification_command_fingerprint": FP,
        "exit_code": 1,
        "failure_kind": "TEST_FAILURE",
        "failed_test_ids": list(IDS),
        "stdout_sha256": "b" * 64,
        "stderr_sha256": "c" * 64,
        "job_id": "job-1",
        "task_id": "task-1",
        "attempt_id": "att-1",
    }
    base.update(overrides)
    return RedObservation(**base)  # type: ignore[arg-type]


class TestPositiveConjunction:
    def test_full_conjunction_derives_match(self) -> None:
        evidence = _compare(_expectation(), _observation())
        assert evidence.match_result is True
        assert evidence.failure_reason_matches_intended_defect is True
        assert evidence.expected_failed_test_ids == IDS
        assert evidence.observed_failed_test_ids == IDS
        assert evidence.reason is None
        assert evidence.comparator_version == COMPARATOR_VERSION

    def test_fingerprint_deterministic_and_command_sensitive(self) -> None:
        assert verification_command_fingerprint(COMMAND) == FP
        assert verification_command_fingerprint([*COMMAND, "-x"]) != FP
        assert len(FP) == 64


class TestNegativeMatrix:
    def test_n1_empty_required_ids_denies(self) -> None:
        evidence = _compare(
            _expectation(required_failed_test_ids=[]), _observation()
        )
        assert evidence.match_result is False
        assert evidence.failure_reason_matches_intended_defect is False

    def test_n2_wrong_ids_deny(self) -> None:
        evidence = _compare(
            _expectation(),
            _observation(failed_test_ids=["tests/test_x.py::test_y"]),
        )
        assert evidence.match_result is False

    def test_n3_extra_ids_deny(self) -> None:
        evidence = _compare(
            _expectation(),
            _observation(
                failed_test_ids=[*IDS, "tests/test_url_safe.py::test_oops"]
            ),
        )
        assert evidence.match_result is False

    def test_n5_proposed_status_rejected_at_load(self) -> None:
        with pytest.raises(ExpectationError):
            _expectation(status="PROPOSED")

    def test_n6_llm_source_rejected_at_load(self) -> None:
        with pytest.raises(ExpectationError):
            _expectation(source_type="LLM_PROPOSED")

    def test_n7_revision_mismatch_denies(self) -> None:
        evidence = _compare(
            _expectation(), _observation(source_revision="0" * 64)
        )
        assert evidence.match_result is False
        assert "revision" in (evidence.reason or "").lower()

    def test_n8_fingerprint_mismatch_denies(self) -> None:
        evidence = _compare(
            _expectation(),
            _observation(verification_command_fingerprint="f" * 64),
        )
        assert evidence.match_result is False
        assert "fingerprint" in (evidence.reason or "").lower()

    def test_n9_collection_kind_denies(self) -> None:
        evidence = _compare(
            _expectation(), _observation(failure_kind="COLLECTION_ERROR")
        )
        assert evidence.match_result is False

    def test_n10_infra_kind_denies(self) -> None:
        evidence = _compare(
            _expectation(), _observation(failure_kind="INFRASTRUCTURE_ERROR")
        )
        assert evidence.match_result is False

    def test_n11_unknown_kind_denies(self) -> None:
        evidence = _compare(
            _expectation(), _observation(failure_kind="UNKNOWN")
        )
        assert evidence.match_result is False

    def test_n12_malformed_expectation_rejected(self) -> None:
        with pytest.raises(ExpectationError):
            QualifiedRedExpectation.from_dict({"status": "QUALIFIED"})

    def test_n13_missing_provenance_rejected(self) -> None:
        with pytest.raises(ExpectationError):
            _expectation(
                provenance={"source_ref": "", "source_sha256": ""},
            )

    def test_exit_mismatch_denies(self) -> None:
        evidence = _compare(
            _expectation(), _observation(exit_code=0)
        )
        assert evidence.match_result is False

    def test_seeded_revision_alias_accepted(self) -> None:
        base = {
            "expectation_id": "x",
            "expectation_version": 1,
            "status": "QUALIFIED",
            "source_type": "BENCHMARK_FIXTURE",
            "seeded_source_revision": REVISION,
            "verification_command_fingerprint": FP,
            "expected_exit_code": 1,
            "match_rule": "EXACT_FAILED_TEST_IDS",
            "required_failed_test_ids": list(IDS),
            "provenance": {"source_ref": "r", "source_sha256": "s"},
        }
        loaded = QualifiedRedExpectation.from_dict(base)
        assert loaded.source_revision == REVISION


class TestParserPrimitives:
    LOG = (
        "tests/test_a.py::test_1 PASSED\n"
        "tests/test_a.py::test_2 FAILED\n"
        "=========================== short test summary info ==========\n"
        "FAILED tests/test_a.py::test_2 - assert 1 == 2\n"
        "1 failed, 1 passed in 0.01s\n"
    )

    def test_failed_ids_extracted(self) -> None:
        assert parse_pytest_failed_test_ids(self.LOG) == [
            "tests/test_a.py::test_2"
        ]

    def test_error_ids_empty_without_errors(self) -> None:
        assert parse_pytest_error_test_ids(self.LOG) == []

    def test_kind_test_failure(self) -> None:
        assert (
            classify_pytest_failure_kind(
                1, ["tests/test_a.py::test_2"], []
            )
            == "TEST_FAILURE"
        )

    def test_kind_unknown_without_ids(self) -> None:
        assert classify_pytest_failure_kind(1, [], []) == "UNKNOWN"

    def test_kind_collection(self) -> None:
        assert classify_pytest_failure_kind(2, [], []) == "COLLECTION_ERROR"

    def test_kind_infrastructure(self) -> None:
        assert classify_pytest_failure_kind(3, [], []) == "INFRASTRUCTURE_ERROR"
        assert classify_pytest_failure_kind(-1, [], []) == "INFRASTRUCTURE_ERROR"

    def test_kind_unknown_on_green(self) -> None:
        assert classify_pytest_failure_kind(0, [], []) == "UNKNOWN"
