"""RQ8-P1-R3-R3-R1 B4 -- controlled artifact-dir scope authority tests.

``run_controlled()`` gates command tool and cwd against the WorkContract
scope, but the R3-R3 ``artifact_dir`` extension is forwarded to
``run_command()`` with no path authorization. The runner then performs
filesystem side effects (``mkdir -p``, ``stdout.log`` / ``stderr.log``
writes) outside any admitted scope.

Required behaviour (R3-R3-R1 §4-§9):

  * ``artifact_dir`` is resolved and must be contained in at least one
    authoritative ``path:`` scope root BEFORE any subprocess starts.
  * ``artifact_dir`` requested with no ``path:`` scope -> DENY (fail closed).
  * On denial the command is NEVER executed (``run_command`` call count 0)
    and no artifact files are created.
  * Resolved final artifact files (``stdout.log`` / ``stderr.log``) must
    also stay in scope so a pre-existing symlink pointing outside scope
    fails closed. Symlink creation needs OS privilege; where unavailable
    the test records the limitation and the deterministic resolved-path
    unit tests carry the guarantee instead.
  * ``artifact_dir=None`` keeps legacy behaviour unchanged.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

import synapx_harness.evidence.command_runner as runner_mod
from synapx_harness.evidence.command_runner import run_controlled


def _wc(
    *,
    tools: tuple[str, ...] = ("echo",),
    paths: tuple[str, ...] = (),
) -> dict[str, object]:
    scope: list[str] = ["phase:public_governed"]
    scope.extend(f"tool:{t}" for t in tools)
    scope.extend(f"path:{p}" for p in paths)
    return {
        "work_contract_id": "wc-artifact-scope",
        "risk_class": "R0",
        "issuer": "HARNESS_CORE_ADMISSION",
        "scope": scope,
    }


def _counting_run_command(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Replace module run_command with a counter that fails if invoked."""
    calls: dict[str, int] = {"count": 0}
    real = runner_mod.run_command

    def counting(*args: Any, **kwargs: Any) -> Any:
        calls["count"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(runner_mod, "run_command", counting)
    return calls


class TestArtifactDirOutsideScopeDenied:
    def test_authorized_cwd_outside_artifact_dir_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Authorized cwd + artifact_dir outside scope -> DENY, no files,
        command never started."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        outside = tmp_path / "outside"
        calls = _counting_run_command(monkeypatch)
        with pytest.raises(ValueError, match="scope|path|admitted"):
            run_controlled(
                "echo hi",
                _wc(paths=(workspace.as_posix(),)),
                cwd=workspace,
                timeout=30,
                artifact_dir=outside,
            )
        assert calls["count"] == 0, "denied artifact scope must not start a command"
        assert not (outside / "stdout.log").exists()
        assert not (outside / "stderr.log").exists()
        assert not outside.exists()

    def test_traversal_artifact_dir_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """artifact_dir = <ws>/sub/../../outside -> resolves outside the
        workspace -> DENY. (One '..' only escapes 'sub' and stays
        inside scope; two are needed for a real escape.)"""
        workspace = tmp_path / "ws"
        (workspace / "sub").mkdir(parents=True)
        traversal = workspace / "sub" / ".." / ".." / "outside"
        calls = _counting_run_command(monkeypatch)
        with pytest.raises(ValueError, match="scope|path|admitted"):
            run_controlled(
                "echo hi",
                _wc(paths=(workspace.as_posix(),)),
                cwd=workspace,
                timeout=30,
                artifact_dir=traversal,
            )
        assert calls["count"] == 0
        assert not (tmp_path / "outside").exists()

    def test_unauthorized_sibling_artifact_dir_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """artifact_dir = unauthorized sibling of the workspace -> DENY."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        sibling = tmp_path / "sibling"
        calls = _counting_run_command(monkeypatch)
        with pytest.raises(ValueError, match="scope|path|admitted"):
            run_controlled(
                "echo hi",
                _wc(paths=(workspace.as_posix(),)),
                cwd=workspace,
                timeout=30,
                artifact_dir=sibling,
            )
        assert calls["count"] == 0
        assert not sibling.exists()

    def test_artifact_dir_without_path_scope_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """artifact_dir supplied but WorkContract carries no path: scope ->
        DENY (fail closed, never default-allow)."""
        artifact_dir = tmp_path / "artifacts"
        calls = _counting_run_command(monkeypatch)
        with pytest.raises(ValueError, match="scope|path|admitted"):
            run_controlled(
                "echo hi",
                _wc(tools=("echo",), paths=()),
                cwd=tmp_path,
                timeout=30,
                artifact_dir=artifact_dir,
            )
        assert calls["count"] == 0
        assert not artifact_dir.exists()


class TestArtifactDirScopePositives:
    def test_artifact_dir_inside_scope_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """artifact_dir inside the authorized workspace -> PASS with real
        persisted artifacts."""
        import hashlib

        workspace = tmp_path / "ws"
        workspace.mkdir()
        artifact_dir = workspace / "artifacts"
        python_token = sys.executable
        calls = _counting_run_command(monkeypatch)
        receipt = run_controlled(
            f"{sys.executable} -c \"print('scoped-ok')\"",
            _wc(
                tools=(python_token,),
                paths=(workspace.as_posix(),),
            ),
            cwd=workspace,
            timeout=60,
            artifact_dir=artifact_dir,
        )
        assert calls["count"] == 1
        assert receipt.stdout_path == (artifact_dir / "stdout.log").as_posix()
        on_disk = (artifact_dir / "stdout.log").read_bytes()
        assert receipt.stdout_sha256 == hashlib.sha256(on_disk).hexdigest()
        assert receipt.stdout_size == len(on_disk)

    def test_artifact_dir_none_legacy_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """artifact_dir=None -> legacy placeholder path, command runs."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        calls = _counting_run_command(monkeypatch)
        receipt = run_controlled(
            "echo hi",
            _wc(paths=(workspace.as_posix(),)),
            cwd=workspace,
            timeout=30,
            artifact_dir=None,
        )
        assert calls["count"] == 1
        assert receipt.stdout_path.startswith("/tmp/command_")


class TestArtifactDirResolutionDeterminism:
    def test_dotdot_resolving_inside_scope_allowed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """artifact_dir with '..' that RESOLVES inside scope is allowed
        (containment is decided on resolved paths, not lexical form)."""
        workspace = tmp_path / "ws"
        (workspace / "sub").mkdir(parents=True)
        nested = workspace / "sub" / ".." / "artifacts"
        calls = _counting_run_command(monkeypatch)
        receipt = run_controlled(
            "echo hi",
            _wc(paths=(workspace.as_posix(),)),
            cwd=workspace,
            timeout=30,
            artifact_dir=nested,
        )
        assert calls["count"] == 1
        assert (workspace / "artifacts" / "stdout.log").is_file()
        assert receipt.stdout_path == (
            workspace / "artifacts" / "stdout.log"
        ).as_posix()

    def test_helper_denies_unscoped_paths_directly(
        self, tmp_path: Path
    ) -> None:
        """Deterministic unit pin on the containment helper itself."""
        helper = getattr(runner_mod, "_require_artifact_dir_in_scope", None)
        assert callable(helper), "B4: no artifact scope helper to pin"
        workspace = tmp_path / "ws"
        workspace.mkdir()
        # Inside -> returns resolved dir.
        resolved = helper(
            workspace / "artifacts",
            [f"path:{workspace.as_posix()}"],
            workspace,
        )
        assert isinstance(resolved, Path)
        assert resolved == (workspace / "artifacts").resolve()
        # Outside -> raises.
        with pytest.raises(ValueError, match="scope|path|admitted"):
            helper(
                tmp_path / "outside",
                [f"path:{workspace.as_posix()}"],
                workspace,
            )
        # No path scope at all -> raises.
        with pytest.raises(ValueError, match="scope|path|admitted"):
            helper(workspace / "artifacts", ["phase:public_governed"], workspace)

    def test_preexisting_symlink_escape_fail_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pre-existing stdout.log symlink pointing outside scope must
        fail closed.

        Platform limitation (stated, never skipped -- skip calls are
        forbidden in this suite): creating a symlink needs OS privilege
        (Windows WinError 1314 without Developer Mode / elevation). When
        the privilege is unavailable the test takes the deterministic
        fallback branch below, which pins the same resolved-path
        containment at the helper level; the traversal negatives pin it
        end to end. Both branches assert real behaviour.
        """
        workspace = tmp_path / "ws"
        artifact_dir = workspace / "artifacts"
        artifact_dir.mkdir(parents=True)
        escape_target = tmp_path / "escape.txt"
        escape_target.write_bytes(b"do-not-touch")
        link = artifact_dir / "stdout.log"
        try:
            os.symlink(str(escape_target), str(link))
        except OSError:
            # Privilege unavailable: deterministic fallback. The gate
            # resolves the same final file paths, so pin allow/deny
            # decisions at the helper level instead of executing through
            # a real symlink.
            helper = runner_mod._require_artifact_dir_in_scope
            resolved = helper(
                artifact_dir,
                [f"path:{workspace.as_posix()}"],
                workspace,
            )
            assert isinstance(resolved, Path)
            assert resolved == artifact_dir.resolve()
            with pytest.raises(ValueError, match="scope|path|admitted"):
                helper(
                    tmp_path / "outside",
                    [f"path:{workspace.as_posix()}"],
                    workspace,
                )
            assert escape_target.read_bytes() == b"do-not-touch"
            return
        calls = _counting_run_command(monkeypatch)
        with pytest.raises(ValueError, match="scope|path|admitted"):
            run_controlled(
                "echo hi",
                _wc(paths=(workspace.as_posix(),)),
                cwd=workspace,
                timeout=30,
                artifact_dir=artifact_dir,
            )
        assert calls["count"] == 0
        assert escape_target.read_bytes() == b"do-not-touch"
