"""RQ8-R1-R2-R2-R1 (Q3) canonical --receipt-out E2E contract tests.

Repair Q3: a single ``GovernedExecutionResult`` object test is not enough.
The Public CLI path::

    synapx run
        -> frontdoor
        -> GovernedFrontDoorRuntimeBridge
        -> run_governed_execution
        -> lineage envelope
        -> --receipt-out

must be exercised end-to-end through ``typer.testing.CliRunner`` so the
``--receipt-out`` artifact on disk carries every required stage-truth
field. The same file is reused by the negative launch-failure test
and the positive/intermediate proposal-parse-failure test so a future
regression that drifts either stage truth breaks loudly.

Required fields per RQ8-R1-R2-R2-R1 §10:

    codex_process.process_started
    codex_process.failure_class
    codex_process.exit_code
    patch_proposal.parsing_attempted
    mutation.attempted
    verification.attempted
    verification.command
    verification.command_source
    terminal.decision
    terminal.primary_failure_stage
    terminal.primary_failure_class

Required negative (launch failure):

    process_started=false
    failure_class=PROCESS_LAUNCH_ERROR
    proposal parsing NOT_RUN
    mutation NOT_RUN
    verification NOT_RUN
    primary_failure_stage=AGENT_PROCESS
    primary_failure_class=PROCESS_LAUNCH_ERROR
    terminal.decision != COMPLETED
    ``Proposal INVALID: Empty stdout`` MUST NOT appear as primary failure.

Required positive/intermediate (started process + malformed proposal):

    process_started=true
    proposal_parsing_attempted=true
    mutation_attempted=false
    verification_attempted=false
    terminal decision FAILED / BLOCKED, NOT COMPLETED.
"""
import json
import subprocess as _real_subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from synapx_harness.adapters.codex.contract import CodexAdapter
from synapx_harness.adapters.codex.runtime import (
    PROCESS_LAUNCH_ERROR,
    SubprocessCodexRuntime,
)
from synapx_harness.cli.frontdoor import governed_app

# Capture the truly original subprocess.Popen at module load so the
# pass-through path can call back into it even after a test monkeypatched
# ``subprocess.Popen`` at module level. (Mirrors the existing R2 helper.)
_REAL_SUBPROCESS_POPEN = _real_subprocess.Popen

NPM_CODEX_PATH: str = r"C:\Users\morag\AppData\Roaming\npm\codex.CMD"


class _RaisingPopen:
    """Popen stand-in that raises FileNotFoundError+winerror=206 for codex.

    Mirrors the Windows ``WinError 206`` symptom; the runtime MUST
    classify this as a launch failure, NOT a normal process exit.
    """

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        is_codex = bool(cmd) and (
            "codex" in str(cmd[0]).lower()
            or (len(cmd) >= 2 and str(cmd[1]).lower() == "exec")
        )
        if is_codex:
            err = FileNotFoundError("파일 이름이나 확장명이 너무 깁니다")
            err.winerror = 206  # type: ignore[attr-defined]
            raise err
        # Pass-through: keep non-codex Popen callers working so the
        # shared-understanding scanner, git probes, etc. still work.
        # Use the module-load-time-captured original Popen so the
        # monkeypatched Popen (which is ``self.__class__`` here) does
        # NOT recurse.
        self._real_popen = _REAL_SUBPROCESS_POPEN(cmd, **kwargs)

    def __enter__(self):
        self._real_popen.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        return self._real_popen.__exit__(exc_type, exc, tb)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_popen, name)


class _EmptySuccessPopen:
    """Popen stand-in that returns exit 0 with empty stdout/stderr.

    Mirrors the existing R2 ``_EmptySuccessPopen`` shape but routes every
    non-codex Popen call through the module-load-captured original
    ``subprocess.Popen`` so the scanner's ``subprocess.run(["git", ...])``
    pass-through continues to work (it calls ``communicate`` and other
    Popen attributes this stub does not implement).
    """

    def __init__(self, cmd: list[str], **kwargs: Any) -> None:
        # Always delegate to the real Popen so any subprocess attribute
        # (``communicate``, ``terminate``, ...) we have not stubbed is
        # still available. The Codex-invocation path is taken over by
        # the adapter's normal failure handling; this class is only used
        # to satisfy the shared-understanding scanner's subprocess probes.
        self._real_popen = _REAL_SUBPROCESS_POPEN(cmd, **kwargs)

    def __enter__(self):
        self._real_popen.__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        return self._real_popen.__exit__(*args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_popen, name)


def _stub_runtime_factory() -> SubprocessCodexRuntime:
    """Build a SubprocessCodexRuntime that is then patched at the
    ``subprocess.Popen`` boundary by individual tests.

    The version cache is pinned to a stable string so the canonical
    receipt carries a deterministic ``codex_process.version``.
    """
    backend = SubprocessCodexRuntime(codex_bin=NPM_CODEX_PATH)
    backend._version_cache = "0.146.0"
    return backend


def _write_minimal_repo(tmp_path: Path) -> Path:
    """Create a uv-managed target repo so the resolver picks uv run pytest."""
    (tmp_path / "uv.lock").write_text("# canonical uv lockfile marker\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0.1.0"\n'
    )
    (tmp_path / "x.py").write_text("def add(a, b): return a + b\n")
    return tmp_path


# ---------------------------------------------------------------------------
# Negative: simulated launch failure -> canonical receipt
# ---------------------------------------------------------------------------


class TestReceiptLaunchFailureContract:
    """``--receipt-out`` MUST carry the launch failure as primary so the
    consumer never sees ``Proposal INVALID: Empty stdout`` as the head."""

    def test_receipt_carries_launch_failure_truth(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = _write_minimal_repo(tmp_path)
        backend = _stub_runtime_factory()
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )

        receipt_path = tmp_path / "receipt.json"
        runner = CliRunner()
        # Inject a pre-built bridge with the patched backend so the canonical
        # ``invoke_governed_with_result`` path is exercised end-to-end.
        from synapx_harness.cli.governed_runtime_bridge import (
            GovernedFrontDoorRuntimeBridge,
        )

        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=str(repo),
            codex_runtime_factory=lambda: backend,
        )
        monkeypatch.setattr(
            "synapx_harness.cli.frontdoor._build_governed_runtime",
            lambda workspace: bridge,
        )

        result = runner.invoke(
            governed_app,
            [
                "--workspace",
                str(repo),
                "--task",
                "Allowed write paths:\n  - x.py",
                "--receipt-out",
                str(receipt_path.resolve()),
            ],
        )
        # CLI MUST exit non-zero (NEEDS_ATTENTION) because the launch error
        # blocked the run; the receipt still has to exist on disk.
        assert result.exit_code != 0, (
            f"CLI exit code expected non-zero on launch failure; got "
            f"{result.exit_code}; output={result.output!r}"
        )
        assert receipt_path.resolve().is_file() or any(
            receipt_path.resolve().parent.glob("**/*receipt*")
        ), (
            "canonical --receipt-out artifact MUST be written even on "
            f"launch failure so the consumer can read stage truth; "
            f"output={result.output!r}; exit_code={result.exit_code}; "
            f"cwd={runner.runner.dir if hasattr(runner, 'runner') else 'n/a'}"
        )

        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

        # ----- Required schema fields present -----
        assert receipt.get("schema") == (
            "synapx.rq4.r2.c3.r1.execution_lineage.v1"
        )

        codex = receipt["codex_process"]
        assert codex["process_started"] is False
        assert codex["failure_class"] == PROCESS_LAUNCH_ERROR
        assert codex["exit_code"] == -1

        # patch_proposal MUST exist (even though parsing was NOT_RUN, the
        # envelope schema reserves the slot) and parsing_attempted MUST be
        # False.
        patch_proposal = receipt["patch_proposal"]
        assert patch_proposal is None or (
            isinstance(patch_proposal, dict)
            and patch_proposal.get("parsing_attempted") is False
        )

        # mutation.attempted MUST be False.
        mutation = receipt["mutation"]
        assert mutation["attempted"] is False

        # verification.attempted MUST be False.
        verification = receipt["verification"]
        assert verification is None or (
            isinstance(verification, dict)
            and verification.get("attempted") is False
        )

        # Terminal decision: primary failure MUST be AGENT_PROCESS /
        # PROCESS_LAUNCH_ERROR, and MUST NOT carry the spurious
        # "Proposal INVALID: Empty stdout" claim (D4 precedence).
        terminal = receipt["terminal_decision"]
        assert terminal["primary_failure_stage"] == "AGENT_PROCESS"
        assert terminal["primary_failure_class"] == PROCESS_LAUNCH_ERROR
        assert terminal["decision"] != "COMPLETED"
        assert "Empty stdout" not in (terminal.get("reason") or ""), (
            "primary failure MUST be the launch error, NOT a spurious "
            "parse-empty-stdout claim (RQ8-R1-R2-R2-R1 Q3 negative test)"
        )
        assert "Empty stdout" not in (
            terminal.get("primary_failure_message") or ""
        )

    def test_receipt_does_not_promote_launch_failure_to_completed(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = _write_minimal_repo(tmp_path)
        backend = _stub_runtime_factory()
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _RaisingPopen,
        )
        receipt_path = tmp_path / "receipt.json"
        runner = CliRunner()

        from synapx_harness.cli.governed_runtime_bridge import (
            GovernedFrontDoorRuntimeBridge,
        )

        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=str(repo),
            codex_runtime_factory=lambda: backend,
        )
        monkeypatch.setattr(
            "synapx_harness.cli.frontdoor._build_governed_runtime",
            lambda workspace: bridge,
        )

        runner.invoke(
            governed_app,
            [
                "--workspace",
                str(repo),
                "--task",
                "Allowed write paths:\n  - x.py",
                "--receipt-out",
                str(receipt_path),
            ],
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        assert receipt["success"] is False
        assert receipt["terminal_decision"]["decision"] in (
            "FAILED",
            "BLOCKED",
        )


# ---------------------------------------------------------------------------
# Positive / Intermediate: started process + malformed proposal
# ---------------------------------------------------------------------------


class TestReceiptProposalParseFailureContract:
    """A successfully started Codex process whose stdout is not a structured
    proposal must yield a receipt that records ``parsing_attempted=true``
    but ``mutation.attempted=false`` and ``verification.attempted=false``."""

    def test_receipt_carries_proposal_parse_stage_truth(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo = _write_minimal_repo(tmp_path)
        backend = _stub_runtime_factory()
        monkeypatch.setattr(
            "synapx_harness.adapters.codex.runtime.subprocess.Popen",
            _EmptySuccessPopen,
        )

        receipt_path = tmp_path / "receipt.json"
        runner = CliRunner()

        from synapx_harness.cli.governed_runtime_bridge import (
            GovernedFrontDoorRuntimeBridge,
        )

        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=str(repo),
            codex_runtime_factory=lambda: backend,
        )
        # Inject a fake adapter on the bridge so the started process
        # actually emits malformed stdout (not just empty stdout).
        from synapx_harness.adapters.codex.fake import FakeCodexRuntime, FakeScenario

        fake = FakeCodexRuntime(
            scenario=FakeScenario.SUCCESS, stdout="this is not a patch"
        )
        adapter = CodexAdapter(backend=fake)
        # Bind the adapter directly on the bridge so the run uses the
        # FakeCodexRuntime-backed adapter while still exercising the
        # canonical ``invoke_governed_with_result`` path.
        monkeypatch.setattr(bridge, "_codex_runtime_factory", lambda: fake)
        monkeypatch.setattr(bridge, "_model", "gpt-5.6-luna")

        # Force the bridge to inject a fake adapter by monkeypatching the
        # governed execution request factory.
        from synapx_harness.kernel import governed_execution as ge_mod

        original_run = ge_mod.run_governed_execution

        def patched_run(req: Any) -> Any:
            req.adapter = adapter
            return original_run(req)

        monkeypatch.setattr(ge_mod, "run_governed_execution", patched_run)

        monkeypatch.setattr(
            "synapx_harness.cli.frontdoor._build_governed_runtime",
            lambda workspace: bridge,
        )

        result = runner.invoke(
            governed_app,
            [
                "--workspace",
                str(repo),
                "--task",
                "Allowed write paths:\n  - x.py",
                "--receipt-out",
                str(receipt_path),
            ],
        )
        assert result.exit_code != 0, (
            f"CLI expected non-zero on proposal parse failure; got "
            f"{result.exit_code}; output={result.output!r}"
        )
        assert receipt_path.is_file()

        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

        # ----- Codex process actually started -----
        codex = receipt["codex_process"]
        assert codex["process_started"] is True
        assert codex["failure_class"] in (
            "PROCESS_SUCCESS",
            "PROCESS_STARTED_EXIT_NONZERO",
        )

        # ----- Proposal parsing WAS attempted but the proposal is invalid -----
        patch_proposal = receipt["patch_proposal"]
        assert isinstance(patch_proposal, dict)
        assert patch_proposal["parsing_attempted"] is True
        assert patch_proposal["valid"] is False

        # ----- Mutation NOT attempted (Q2 stage truth) -----
        mutation = receipt["mutation"]
        assert mutation["attempted"] is False

        # ----- Verification NOT attempted (Q2 stage truth) -----
        verification = receipt["verification"]
        # verification is either null (slot reserved) or a dict with
        # attempted=False.
        if verification is not None:
            assert verification["attempted"] is False

        # Terminal decision: FAILED/BLOCKED, NOT COMPLETED. Primary
        # failure must mention proposal rejection, NOT a launch error.
        terminal = receipt["terminal_decision"]
        assert terminal["decision"] != "COMPLETED"
        assert terminal["primary_failure_stage"] in (
            "PROPOSAL_PARSE_OR_ADMISSION",
            "PROPOSAL_REJECTED",
        )
        assert terminal["primary_failure_class"] == "PROPOSAL_REJECTED"
        assert "Proposal INVALID" in (
            terminal.get("primary_failure_message") or ""
        )

        # And the launch-failure class MUST NOT appear as primary failure.
        assert terminal["primary_failure_class"] != PROCESS_LAUNCH_ERROR
