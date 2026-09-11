"""Pytest Result Parser for verification evidence.

Parses actual pytest log output to generate verification_summary.json.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PytestSummary:
    collected: int
    executed: int
    passed: int
    failed: int
    errors: int
    skipped: int

    def to_dict(self) -> dict[str, object]:
        return {
            "collected": self.collected,
            "executed": self.executed,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
        }


@dataclass(frozen=True)
class VerificationSummary:
    pytest_log_path: str
    pytest_log_sha256: str
    collected: int
    executed: int
    passed: int
    failed: int
    errors: int
    skipped: int
    gate: str

    def to_dict(self) -> dict[str, object]:
        return {
            "pytest_log_path": self.pytest_log_path,
            "pytest_log_sha256": self.pytest_log_sha256,
            "collected": self.collected,
            "executed": self.executed,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "gate": self.gate,
        }


def parse_pytest_log(log_content: str) -> PytestSummary | None:
    passed = 0
    failed = 0
    errors = 0
    skipped = 0

    passed_match = re.search(r"(\d+)\s+passed", log_content)
    if passed_match:
        passed = int(passed_match.group(1))

    failed_match = re.search(r"(\d+)\s+failed", log_content)
    if failed_match:
        failed = int(failed_match.group(1))

    errors_match = re.search(r"(\d+)\s+error", log_content)
    if errors_match:
        errors = int(errors_match.group(1))

    skipped_match = re.search(r"(\d+)\s+skipped", log_content)
    if skipped_match:
        skipped = int(skipped_match.group(1))

    if passed == 0 and failed == 0 and errors == 0 and skipped == 0:
        return None

    collected_match = re.search(r"collected\s+(\d+)", log_content)
    collected = int(collected_match.group(1)) if collected_match else 0

    return PytestSummary(
        collected=collected,
        executed=passed + failed + errors + skipped,
        passed=passed,
        failed=failed,
        errors=errors,
        skipped=skipped,
    )


def parse_pytest_log_file(log_path: Path) -> VerificationSummary | None:
    if not log_path.is_file():
        return None

    content = log_path.read_text(encoding="utf-8")
    import hashlib
    log_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()

    summary = parse_pytest_log(content)
    if summary is None:
        return None

    gate = "PASS" if summary.failed == 0 and summary.errors == 0 else "FAIL"

    return VerificationSummary(
        pytest_log_path=str(log_path),
        pytest_log_sha256=log_sha,
        collected=summary.collected,
        executed=summary.executed,
        passed=summary.passed,
        failed=summary.failed,
        errors=summary.errors,
        skipped=summary.skipped,
        gate=gate,
    )


def is_valid_verification_summary(data: dict[str, object]) -> tuple[bool, list[str]]:
    violations: list[str] = []

    pytest_log_path = data.get("pytest_log_path")
    if not isinstance(pytest_log_path, str):
        violations.append("pytest_log_path must be a string")
    else:
        log_path = Path(pytest_log_path)
        if not log_path.is_file():
            violations.append("pytest_log_path does not exist")

        expected_sha = data.get("pytest_log_sha256")
        if isinstance(expected_sha, str) and log_path.is_file():
            import hashlib
            actual_content = log_path.read_bytes()
            actual_sha = hashlib.sha256(actual_content).hexdigest()
            if actual_sha != expected_sha:
                violations.append("pytest_log_sha256 mismatch (log hash changed)")

    collected = data.get("collected")
    if not isinstance(collected, int) or collected <= 0:
        violations.append("collected must be > 0")

    executed = data.get("executed")
    if not isinstance(executed, int) or executed < 0:
        violations.append("executed must be a non-negative integer")

    passed = data.get("passed")
    if not isinstance(passed, int):
        violations.append("passed must be an integer")

    failed = data.get("failed")
    if not isinstance(failed, int):
        violations.append("failed must be an integer")

    errors = data.get("errors")
    if not isinstance(errors, int):
        violations.append("errors must be an integer")

    skipped = data.get("skipped")
    if not isinstance(skipped, int):
        violations.append("skipped must be an integer")

    total = (
        (passed if isinstance(passed, int) else 0)
        + (failed if isinstance(failed, int) else 0)
        + (errors if isinstance(errors, int) else 0)
        + (skipped if isinstance(skipped, int) else 0)
    )
    if total != (collected if isinstance(collected, int) else 0):
        violations.append("passed + failed + errors + skipped must equal collected")

    if isinstance(executed, int) and isinstance(collected, int):
        if executed != collected:
            violations.append(f"executed ({executed}) must equal collected ({collected})")

    if isinstance(failed, int) and failed != 0:
        violations.append(f"failed must be 0 (got {failed})")

    if isinstance(errors, int) and errors != 0:
        violations.append(f"errors must be 0 (got {errors})")

    if isinstance(skipped, int) and skipped != 0:
        violations.append(f"skipped must be 0 (got {skipped})")

    if data.get("gate") not in ("PASS", "FAIL"):
        violations.append("gate must be PASS or FAIL")

    return len(violations) == 0, violations


def is_exit_code_consistent(exit_code: object) -> bool:
    """T08 check 13: process exit consistency (only 0 or 1 accepted)."""
    return isinstance(exit_code, int) and exit_code in (0, 1)


def is_semantic_result_consistent(
    verification_status: object,
    evidence_status: object,
) -> bool:
    """T08 check 14: semantic result consistency (PASS requires VALID evidence)."""
    if verification_status == "PASS":
        return evidence_status == "VALID"
    if verification_status == "FAIL":
        return evidence_status in ("VALID", "INVALID", "PENDING")
    return verification_status in ("PENDING",) and evidence_status in (
        "VALID",
        "INVALID",
        "PENDING",
    )


__all__ = [
    "PytestSummary",
    "VerificationSummary",
    "is_exit_code_consistent",
    "is_semantic_result_consistent",
    "is_valid_verification_summary",
    "parse_pytest_log",
    "parse_pytest_log_file",
]
