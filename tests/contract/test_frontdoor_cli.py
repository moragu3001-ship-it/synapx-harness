"""Lane A Front Door CLI contract tests.

RED tests for Minimal Front Door (POST-H2 Lane A R1-A3).

These tests verify the synapx entry point and front door behavior
without requiring Lane D Codex adapter.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest
import typer

CORE_ROOT = Path(__file__).resolve().parents[2]


def _run_frontdoor(
    *args: str,
    cwd: Path | None = None,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    import os
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "synapx_harness.cli.frontdoor", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or CORE_ROOT),
        check=False,
        input=input_text,
        env=full_env,
    )


class TestA1SynapxEntry:
    def test_frontdoor_module_runs(self) -> None:
        result = _run_frontdoor("--version")
        assert result.returncode == 0
        assert "synapx" in result.stdout

    def test_frontdoor_module_help(self) -> None:
        result = _run_frontdoor("--help")
        assert result.returncode == 0


class TestA2WorkspaceDetection:
    def test_valid_workspace_detected(self, tmp_path: Path) -> None:
        result = _run_frontdoor(cwd=tmp_path)
        output = result.stdout + result.stderr
        assert result.returncode == 1
        assert "NEEDS_ATTENTION" in output

    def test_nonexistent_workspace_rejected(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "this_directory_does_not_exist_12345"
        result = _run_frontdoor("--workspace", str(nonexistent))
        assert result.returncode == 1
        output = result.stdout + result.stderr
        assert "NEEDS_ATTENTION" in output


class TestA3RuntimeUnavailable:
    def test_runtime_unavailable_reports_attention(self, tmp_path: Path) -> None:
        result = _run_frontdoor(cwd=tmp_path)
        output = result.stdout + result.stderr
        assert "Codex unavailable" in output
        assert "NEEDS_ATTENTION" in output


class TestA4EmptyTask:
    def test_empty_task_rejected(self, tmp_path: Path) -> None:
        result = _run_frontdoor(cwd=tmp_path, input_text="")
        assert result.returncode == 1
        output = result.stdout + result.stderr
        assert "NEEDS_ATTENTION" in output


class TestA5TaskCapture:
    def test_pass_string_not_mapped_to_verified(self, tmp_path: Path) -> None:
        result = _run_frontdoor("--task", "PASS", cwd=tmp_path)
        output = result.stdout + result.stderr
        assert "VERIFIED" not in output
        assert "NEEDS_ATTENTION" in output

    def test_arbitrary_string_not_mapped_to_verified(self, tmp_path: Path) -> None:
        result = _run_frontdoor("--task", "DONE", cwd=tmp_path)
        output = result.stdout + result.stderr
        assert "VERIFIED" not in output
        assert "NEEDS_ATTENTION" in output


class TestA6NoDirectCodexInvocation:
    def test_frontdoor_source_no_codex_subprocess(self) -> None:
        frontdoor_path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py"
        content = frontdoor_path.read_text(encoding="utf-8")
        has_subprocess = "subprocess" in content
        has_codex = "codex" in content.lower()
        assert not (has_subprocess and has_codex)
        assert "os.system" not in content
        assert "shutil.which" not in content


class TestA7NoTerminalAuthorityViolation:
    def test_frontdoor_no_terminal_finalizer_calls(self) -> None:
        frontdoor_path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py"
        content = frontdoor_path.read_text(encoding="utf-8")
        assert "build_terminal_decision" not in content
        assert "issue_terminal_decision" not in content
        assert "finalize" not in content
        assert "terminal_finalizer" not in content


class TestA8NoProductionEnvBypass:
    def test_env_test_seam_cannot_bypass_to_verified(self, tmp_path: Path) -> None:
        result = _run_frontdoor(
            "--task", "test",
            cwd=tmp_path,
            env={"SYNAPX_TEST_SEAM": "COMPLETED"},
        )
        output = result.stdout + result.stderr
        assert "VERIFIED" not in output
        if not ("Codex unavailable" in output or "NEEDS_ATTENTION" in output):
            raise AssertionError("Expected Codex unavailable or NEEDS_ATTENTION")

    def test_env_codex_available_cannot_enable_runtime(self, tmp_path: Path) -> None:
        result = _run_frontdoor(
            "--task", "test",
            cwd=tmp_path,
            env={"SYNAPX_CODEX_AVAILABLE": "1"},
        )
        output = result.stdout + result.stderr
        assert "VERIFIED" not in output
        if not ("Codex unavailable" in output or "NEEDS_ATTENTION" in output):
            raise AssertionError("Expected Codex unavailable or NEEDS_ATTENTION")

    def test_frontdoor_source_no_synapx_test_seam_env(self) -> None:
        frontdoor_path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py"
        content = frontdoor_path.read_text(encoding="utf-8")
        assert "SYNAPX_TEST_SEAM" not in content

    def test_frontdoor_source_no_synapx_codex_available_env(self) -> None:
        frontdoor_path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py"
        content = frontdoor_path.read_text(encoding="utf-8")
        assert "SYNAPX_CODEX_AVAILABLE" not in content


class TestA9NoRuntimeAuthorityImport:
    def test_no_runtime_models_import(self) -> None:
        frontdoor_path = CORE_ROOT / "src" / "synapx_harness" / "cli" / "frontdoor.py"
        content = frontdoor_path.read_text(encoding="utf-8")
        assert "from synapx_harness.contracts.runtime_models" not in content
        assert "from synapx_harness.kernel" not in content


class TestA10NoWorkspaceMutation:
    def test_no_workspace_mutation(self, tmp_path: Path) -> None:
        before = set(tmp_path.iterdir())
        _run_frontdoor("--task", "test", cwd=tmp_path)
        after = set(tmp_path.iterdir())
        assert before == after


class TestA11PresentationMapping:
    def test_completed_maps_to_verified(self, capsys: pytest.CaptureFixture[str]) -> None:
        from synapx_harness.cli.frontdoor import PresentationResult, run

        class FakeCompletedRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult("COMPLETED", "test completed")

        try:
            run(task="test", runtime=FakeCompletedRuntime())
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "VERIFIED" in output

    def test_failed_maps_to_failed(self, capsys: pytest.CaptureFixture[str]) -> None:
        from synapx_harness.cli.frontdoor import PresentationResult, run

        class FakeFailedRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult("FAILED", "test failed")

        try:
            run(task="test", runtime=FakeFailedRuntime())
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "FAILED" in output
        assert "VERIFIED" not in output

    def test_blocked_maps_to_attention(self, capsys: pytest.CaptureFixture[str]) -> None:
        from synapx_harness.cli.frontdoor import PresentationResult, run

        class FakeBlockedRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                return PresentationResult("BLOCKED", "test blocked")

        try:
            run(task="test", runtime=FakeBlockedRuntime())
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output

    def test_none_result_maps_to_attention(self, capsys: pytest.CaptureFixture[str]) -> None:
        from synapx_harness.cli.frontdoor import run

        class FakeNoneRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> None:
                return None

        try:
            run(task="test", runtime=FakeNoneRuntime())
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert "NEEDS_ATTENTION" in output
        assert "VERIFIED" not in output

    def test_dict_result_maps_to_attention(self) -> None:
        from synapx_harness.cli.frontdoor import _map_to_presentation

        result = _map_to_presentation({"decision": "COMPLETED"})
        assert result == "NEEDS_ATTENTION"

    def test_string_result_maps_to_attention(self) -> None:
        from synapx_harness.cli.frontdoor import _map_to_presentation

        result = _map_to_presentation("COMPLETED")
        assert result == "NEEDS_ATTENTION"

    def test_int_result_maps_to_attention(self) -> None:
        from synapx_harness.cli.frontdoor import _map_to_presentation

        result = _map_to_presentation(0)
        assert result == "NEEDS_ATTENTION"


class TestA12EmptyTaskWithAvailableRuntime:
    def test_empty_task_rejected_with_available_runtime(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from synapx_harness.cli.frontdoor import PresentationResult, run

        invoke_count = 0

        class CountingRuntime:
            def is_available(self) -> bool:
                return True

            def invoke(self, task: str) -> PresentationResult:
                nonlocal invoke_count
                invoke_count += 1
                return PresentationResult("COMPLETED", "done")

        try:
            run(task="", runtime=CountingRuntime())
        except typer.Exit:
            pass
        out = capsys.readouterr()
        output = out.out + out.err
        assert invoke_count == 0
        assert "NEEDS_ATTENTION" in output


class TestA13WeakAssertions:
    def test_no_weak_or_assertions_in_test_file(self) -> None:
        test_path = Path(__file__)
        content = test_path.read_text(encoding="utf-8")
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                if isinstance(node.test, ast.BoolOp):
                    raise AssertionError("No 'assert A or B' patterns allowed")

    def test_no_if_then_assert_in_test_file(self) -> None:
        test_path = Path(__file__)
        content = test_path.read_text(encoding="utf-8")
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                for stmt in node.body:
                    if isinstance(stmt, ast.Assert):
                        raise AssertionError("No 'if: assert' patterns allowed")

    def test_no_constant_truth_assertions_in_test_file(self) -> None:
        test_path = Path(__file__)
        content = test_path.read_text(encoding="utf-8")
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                if isinstance(node.test, ast.Constant) and bool(node.test.value):
                    raise AssertionError(f"No constant-truth assert allowed: {node.test.value!r}")

    def test_no_pytest_skip_in_test_file(self) -> None:
        test_path = Path(__file__)
        content = test_path.read_text(encoding="utf-8")
        import re
        skips = re.findall(r"@pytest\.mark\.skip", content)
        if skips:
            raise AssertionError(f"pytest.mark.skip found: {len(skips)}")
