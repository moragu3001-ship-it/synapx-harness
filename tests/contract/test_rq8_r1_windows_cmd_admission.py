"""RQ8-R1 -- Windows npm ``codex.CMD`` admission deterministic tests.

Background
----------
On a clean-room Windows host the Codex CLI was installed via ``npm`` which
exposes ``codex`` as a ``.CMD`` wrapper, e.g.::

    C:\\Users\\<user>\\AppData\\Roaming\\npm\\codex.CMD

``shutil.which("codex")`` returns that absolute path. The previous
production ``discover_codex()`` then re-interpreted the bare ``"codex"``
string when invoking the version probe, which on Windows caused
``CreateProcess`` to fail with ``FileNotFoundError`` even though the
resolved absolute path executed successfully. As a result, ``synapx
doctor`` reported ``CODEX_VERSION_PROBE_FAILED`` and the harness
fail-closed.

These tests pin the RQ8-R1 invariant:

    discovery target == version-probe target == execution target

They use ``monkeypatch`` to simulate Windows ``CreateProcess`` semantics
without depending on the host's actual codex installation: the bare
``"codex"`` token cannot execute (mimicking ``WinError 2``), only the
resolved absolute ``.CMD`` path can. The tests therefore FAIL on the
pre-RQ8-R1 production code and PASS on the post-RQ8-R1 production code.
"""
from __future__ import annotations

import shutil
import subprocess
from unittest import mock

import pytest

from synapx_harness.cli.frontdoor import PresentationResult
from synapx_harness.cli.runtime_bridge import (
    CODEX_BIN_NAME,
    REASON_CODE_BIN_NOT_FOUND,
    REASON_CODE_OK,
    REASON_CODE_VERSION_PROBE_FAILED,
    CodexReadiness,
    FrontDoorRuntimeBridge,
    discover_codex,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


NPM_CODEX_PATH: str = r"C:\Users\morag\AppData\Roaming\npm\codex.CMD"
NATIVE_CODEX_PATH: str = r"C:\Users\morag\OpenAI\Codex\bin\codex.EXE"


def _windows_createprocess_fake_run(
    *,
    resolved_path: str,
    version_stdout: str,
    fail_code: int = 0,
):
    """Simulate Windows ``CreateProcess`` semantics for ``.CMD`` wrappers.

    * ``cmd[0] == "codex"`` (bare token)  -> ``FileNotFoundError`` (defect).
    * ``cmd[0] == resolved_path``         -> ``CompletedProcess`` success.

    The fake intentionally rejects the bare token so any production code
    that re-uses it after discovery cannot accidentally pass the test.
    """

    def fake_run(cmd, *args, **kwargs):
        exe = cmd[0]
        if exe == CODEX_BIN_NAME:
            raise FileNotFoundError(
                f"[WinError 2] The system cannot find the file specified: {exe!r}"
            )
        if exe == resolved_path:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=fail_code,
                stdout=version_stdout,
                stderr="",
            )
        raise AssertionError(f"unexpected cmd[0]: {exe!r}")

    return fake_run


def _failing_probe_run(resolved_path: str):
    """Resolved path exists but ``--version`` exits non-zero / returns garbage."""

    def fake_run(cmd, *args, **kwargs):
        if cmd[0] == resolved_path:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=2,
                stdout="",
                stderr="unexpected failure",
            )
        raise FileNotFoundError(cmd[0])

    return fake_run


# ---------------------------------------------------------------------------
# T1 -- Windows npm CMD positive path
# ---------------------------------------------------------------------------


class TestT1WindowsNpmCmdPositive:
    """A resolved ``codex.CMD`` from npm must produce READY."""

    def test_npm_cmd_yields_ready(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(
            subprocess,
            "run",
            _windows_createprocess_fake_run(
                resolved_path=NPM_CODEX_PATH,
                version_stdout="codex-cli 0.153.4\n",
            ),
        )

        readiness = discover_codex()
        assert readiness.executable_found is True
        assert readiness.executable_path == NPM_CODEX_PATH
        assert readiness.version == "0.153.4"
        assert readiness.supported is True
        assert readiness.ready is True
        assert readiness.reason_code == REASON_CODE_OK

    def test_npm_cmd_old_version_also_admits(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(
            subprocess,
            "run",
            _windows_createprocess_fake_run(
                resolved_path=NPM_CODEX_PATH,
                version_stdout="codex-cli 0.146.0\n",
            ),
        )

        readiness = discover_codex()
        assert readiness.version == "0.146.0"
        assert readiness.ready is True


# ---------------------------------------------------------------------------
# T2 -- Resolved path is actually used (anti-regression)
# ---------------------------------------------------------------------------


class TestT2ResolvedPathIsUsed:
    """``discover_codex`` MUST invoke the probe with the resolved path.

    The Windows ``CreateProcess`` fake rejects the bare ``"codex"`` token
    with ``FileNotFoundError``. Pre-RQ8-R1 production code passed the bare
    token, causing this test to fail-closed (``version=None``,
    ``CODEX_VERSION_PROBE_FAILED``). Post-RQ8-R1 the resolved absolute path
    is used, which the fake allows, producing READY.
    """

    def test_probe_target_is_resolved_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        captured: dict[str, object] = {}

        def capture_run(cmd, *args, **kwargs):
            captured["cmd"] = cmd
            if cmd[0] == CODEX_BIN_NAME:
                raise FileNotFoundError(
                    f"[WinError 2] Cannot find file: {cmd[0]!r}"
                )
            if cmd[0] == NPM_CODEX_PATH:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout="codex-cli 0.153.4\n",
                    stderr="",
                )
            raise AssertionError(f"unexpected cmd[0]: {cmd[0]!r}")

        monkeypatch.setattr(subprocess, "run", capture_run)

        readiness = discover_codex()

        # The probe MUST target the resolved path, never the bare token.
        assert captured["cmd"][0] == NPM_CODEX_PATH  # type: ignore[index]
        assert readiness.version == "0.153.4"
        assert readiness.ready is True

    def test_bridge_adapter_uses_same_resolved_path(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        """``FrontDoorRuntimeBridge._ensure_adapter`` MUST use the same
        resolved executable that discovery selected.

        The RQ8-R1 architectural invariant is: discovery target == probe
        target == execution target. If the adapter were constructed with
        the bare token instead of the resolved path, a Windows .CMD
        install would pass readiness but fail at actual execution.
        """
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(
            subprocess,
            "run",
            _windows_createprocess_fake_run(
                resolved_path=NPM_CODEX_PATH,
                version_stdout="codex-cli 0.153.4\n",
            ),
        )

        captured: dict[str, object] = {}

        # Stub out the real adapter so we only inspect the constructor
        # arguments: ``backend`` and ``codex_bin`` must carry the resolved
        # path, not the bare token.
        class _FakeAdapter:
            def __init__(self, backend=None, codex_bin=None):
                captured["backend_codex_bin"] = (
                    getattr(backend, "codex_bin", None) if backend is not None else None
                )
                captured["codex_bin"] = codex_bin

            def execute(self, request):  # pragma: no cover - never called
                raise AssertionError("execute() should not be reached")

        with mock.patch(
            "synapx_harness.cli.runtime_bridge.CodexAdapter", _FakeAdapter
        ):
            br = FrontDoorRuntimeBridge(workspace_root=str(tmp_path))
            assert br.readiness().ready is True
            adapter = br._ensure_adapter()
            assert isinstance(adapter, _FakeAdapter)
            assert captured["backend_codex_bin"] == NPM_CODEX_PATH
            assert captured["codex_bin"] == NPM_CODEX_PATH


# ---------------------------------------------------------------------------
# T3 -- Native codex.EXE compatibility
# ---------------------------------------------------------------------------


class TestT3NativeExeCompatibility:
    """Native codex.EXE discovery MUST keep working."""

    def test_native_exe_yields_ready(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NATIVE_CODEX_PATH)

        def fake_run(cmd, *args, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="codex-cli 0.146.0\n",
                stderr="",
            )

        monkeypatch.setattr(subprocess, "run", fake_run)

        readiness = discover_codex()
        assert readiness.executable_found is True
        assert readiness.executable_path == NATIVE_CODEX_PATH
        assert readiness.version == "0.146.0"
        assert readiness.supported is True
        assert readiness.ready is True
        assert readiness.reason_code == REASON_CODE_OK


# ---------------------------------------------------------------------------
# T4 -- Genuine version probe failure remains fail-closed
# ---------------------------------------------------------------------------


class TestT4GenuineProbeFailure:
    """If the resolved target fails ``--version`` the bridge MUST remain fail-closed."""

    def test_npm_cmd_probe_nonzero_exit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(
            subprocess, "run", _failing_probe_run(NPM_CODEX_PATH)
        )

        readiness = discover_codex()
        assert readiness.executable_found is True
        assert readiness.executable_path == NPM_CODEX_PATH
        assert readiness.version is None
        assert readiness.supported is False
        assert readiness.ready is False
        assert readiness.reason_code == REASON_CODE_VERSION_PROBE_FAILED

    def test_npm_cmd_probe_oserror(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate the probe raising an OS error on the resolved path."""

        def fake_run(cmd, *args, **kwargs):
            raise OSError("simulated Windows CreateProcess failure")

        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(subprocess, "run", fake_run)

        readiness = discover_codex()
        assert readiness.executable_found is True
        assert readiness.version is None
        assert readiness.ready is False
        assert readiness.reason_code == REASON_CODE_VERSION_PROBE_FAILED


# ---------------------------------------------------------------------------
# T5 -- Codex missing remains fail-closed
# ---------------------------------------------------------------------------


class TestT5CodexMissing:
    """``shutil.which("codex") == None`` MUST keep its existing reason code."""

    def test_missing_codex_unchanged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: None)

        readiness = discover_codex()
        assert readiness.executable_found is False
        assert readiness.executable_path is None
        assert readiness.version is None
        assert readiness.supported is False
        assert readiness.ready is False
        assert readiness.reason_code == REASON_CODE_BIN_NOT_FOUND


# ---------------------------------------------------------------------------
# T6 -- Existing version output formats
# ---------------------------------------------------------------------------


class TestT6VersionOutputFormats:
    """All previously-qualified version string formats MUST still parse."""

    @pytest.mark.parametrize(
        "stdout_text, expected_version",
        [
            ("codex-cli 0.146.0\n", "0.146.0"),
            ("codex-cli 0.153.4\n", "0.153.4"),
            # Token may be the first whitespace-separated word starting
            # with a digit and containing a dot.
            ("0.153.4\n", "0.153.4"),
            # Trailing garbage (e.g. a build suffix) is ignored -- the
            # token parser picks the first matching token.
            ("codex-cli 0.153.4-rc1 extra\n", "0.153.4-rc1"),
        ],
    )
    def test_version_parser_accepts_qualified_formats(
        self,
        monkeypatch: pytest.MonkeyPatch,
        stdout_text: str,
        expected_version: str,
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(
            subprocess,
            "run",
            _windows_createprocess_fake_run(
                resolved_path=NPM_CODEX_PATH,
                version_stdout=stdout_text,
            ),
        )

        readiness = discover_codex()
        assert readiness.version == expected_version
        assert readiness.ready is True


# ---------------------------------------------------------------------------
# Doctor wiring sanity (RQ8-R1)
# ---------------------------------------------------------------------------


class TestDoctorWiringSanity:
    """``synapx doctor --json`` MUST serialize the resolved executable path
    consistently with the same authority the version probe used."""

    def test_doctor_json_carries_resolved_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shutil, "which", lambda name: NPM_CODEX_PATH)
        monkeypatch.setattr(
            subprocess,
            "run",
            _windows_createprocess_fake_run(
                resolved_path=NPM_CODEX_PATH,
                version_stdout="codex-cli 0.153.4\n",
            ),
        )

        readiness = discover_codex()
        assert readiness.ready is True
        # The serialized surface MUST carry the same resolved path that
        # the probe used, so downstream tooling cannot diverge.
        payload = readiness.to_dict()
        assert payload["executable_found"] is True
        assert payload["executable_path"] == NPM_CODEX_PATH
        assert payload["version"] == "0.153.4"
        assert payload["ready"] is True
        assert payload["reason_code"] == REASON_CODE_OK