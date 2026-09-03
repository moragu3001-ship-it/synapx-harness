"""R4 Verification Evidence Truth Tests.

Tests that enforce verification summary truth semantics.
"""
from __future__ import annotations

from pathlib import Path


def test_zero_collected_tests_cannot_pass() -> None:
    summary = {
        "collected": 0,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary
    ok, _ = is_valid_verification_summary(summary)
    assert not ok, "Zero collected tests should not pass"


def test_zero_executed_tests_cannot_pass() -> None:
    summary = {
        "collected": 5,
        "executed": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary
    ok, _ = is_valid_verification_summary(summary)
    assert not ok, "Zero executed tests should not pass"


def test_pytest_summary_is_parsed_from_real_log(tmp_path: Path) -> None:
    log_content = """
============================= test session starts ==============================
collected 10 items

tests/contract/test_a.py .....                                           [ 50%]
tests/contract/test_b.py .....                                           [100%]

============================== 10 passed in 0.5s ==============================
"""
    log_file = tmp_path / "pytest.log"
    log_file.write_text(log_content)

    from synapx_harness.evidence.pytest_result_parser import parse_pytest_log_file
    summary = parse_pytest_log_file(log_file)

    assert summary is not None
    assert summary.collected == 10
    assert summary.passed == 10
    assert summary.failed == 0


def test_verification_summary_count_matches_pytest_log(tmp_path: Path) -> None:
    log_content = """
============================= test session starts ==============================
collected 224 items

============================== 224 passed in 1.0s ==============================
"""
    log_file = tmp_path / "pytest.log"
    log_file.write_text(log_content)

    from synapx_harness.evidence.pytest_result_parser import parse_pytest_log_file
    summary = parse_pytest_log_file(log_file)

    assert summary is not None
    assert summary.passed + summary.failed + summary.errors + summary.skipped == summary.collected


def test_reported_passed_count_matches_collected_count(tmp_path: Path) -> None:
    log_content = """
============================= test session starts ==============================
collected 3 items

tests/contract/test_a.py .
tests/contract/test_b.py .
tests/contract/test_c.py .

============================== 3 passed in 0.5s ==============================
"""
    log_file = tmp_path / "pytest.log"
    log_file.write_text(log_content, encoding="utf-8")
    log_sha = __import__("hashlib").sha256(log_file.read_bytes()).hexdigest()

    summary = {
        "pytest_log_path": str(log_file),
        "pytest_log_sha256": log_sha,
        "collected": 3,
        "executed": 3,
        "passed": 3,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary
    ok, violations = is_valid_verification_summary(summary)
    assert ok, f"Valid summary should pass: {violations}"


def test_failed_test_count_mismatch_is_detected() -> None:
    summary = {
        "collected": 5,
        "executed": 5,
        "passed": 4,
        "failed": 2,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary
    ok, violations = is_valid_verification_summary(summary)
    assert not ok, "Count mismatch should fail validation"
    assert any("collected" in v for v in violations)


def test_skipped_count_mismatch_is_detected() -> None:
    summary = {
        "collected": 5,
        "executed": 4,
        "passed": 3,
        "failed": 0,
        "errors": 0,
        "skipped": 1,
        "gate": "PASS",
    }
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary
    ok, violations = is_valid_verification_summary(summary)
    assert not ok, "Skipped count mismatch should fail validation"
    assert any("collected" in v for v in violations)


def test_hand_authored_verification_summary_is_rejected() -> None:
    summary = {
        "collected": 100,
        "executed": 50,
        "passed": 50,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "gate": "PASS",
    }
    from synapx_harness.evidence.pytest_result_parser import is_valid_verification_summary
    ok, violations = is_valid_verification_summary(summary)
    assert not ok, "Count mismatch should fail validation"
    assert any("collected" in v for v in violations)


def test_pytest_log_without_terminal_summary_is_rejected(tmp_path: Path) -> None:
    log_content = """
============================= test session starts ==============================
collected 5 items

tests/contract/test_a.py .F..                                              [100%]

============================== 1 passed, 1 failed in 0.5s ==============================
"""
    log_file = tmp_path / "pytest.log"
    log_file.write_text(log_content)

    from synapx_harness.evidence.pytest_result_parser import parse_pytest_log
    summary = parse_pytest_log(log_content)

    assert summary is not None
    assert summary.failed == 1
    assert summary.passed == 1
