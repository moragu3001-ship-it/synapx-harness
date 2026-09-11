"""Evidence module for command execution and pytest result parsing."""
from __future__ import annotations

from synapx_harness.evidence.command_receipt import (
    PLACEHOLDER_HASH,
    validate_command_receipt,
)
from synapx_harness.evidence.command_runner import (
    CommandResult,
    run_command,
)
from synapx_harness.evidence.evidence_validator import (
    check_placeholder_hash,
    validate_artifact_hash_matches,
    validate_hash_format,
    validate_json_file,
    validate_required_artifact,
    validate_scoped_manifest_entry,
)
from synapx_harness.evidence.pytest_result_parser import (
    PytestSummary,
    VerificationSummary,
    is_valid_verification_summary,
    parse_pytest_log,
    parse_pytest_log_file,
)

__all__ = [
    "CommandResult",
    "PytestSummary",
    "VerificationSummary",
    "PLACEHOLDER_HASH",
    "check_placeholder_hash",
    "is_valid_verification_summary",
    "parse_pytest_log",
    "parse_pytest_log_file",
    "run_command",
    "validate_command_receipt",
    "validate_artifact_hash_matches",
    "validate_hash_format",
    "validate_json_file",
    "validate_required_artifact",
    "validate_scoped_manifest_entry",
]
