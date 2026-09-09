"""RQ8-R1-R1 -- Governed Codex runtime resolved-path bound determinism.

Background
----------
RQ8-R1 repaired the legacy ``FrontDoorRuntimeBridge`` so its version probe
target matches its discovery target. RQ8-R1-R1 closes the analogous gap in
the *governed* execution path: by default the
:class:`GovernedFrontDoorRuntimeBridge` constructed a
:class:`SubprocessCodexRuntime` with the bare ``"codex"`` token
(``CODEX_BIN_NAME``), so even when discovery and probe both admitted the
npm ``codex.CMD`` the canonical governed execution would drift back to
the bare token and Windows ``CreateProcess`` would fail.

This test module pins the RQ8-R1-R1 invariant:

    Discovery target
    == Version probe target
    == Admission target
    == Governed execution target

The bare ``"codex"`` token is intentionally unreachable via the production
default factory once a resolved readiness is present. The custom
``codex_runtime_factory`` injection seam is preserved verbatim.
"""
from __future__ import annotations

from typing import Any

import pytest

from synapx_harness.adapters.codex.runtime import SubprocessCodexRuntime
from synapx_harness.cli.governed_runtime_bridge import (
    GovernedFrontDoorRuntimeBridge,
)
from synapx_harness.cli.runtime_bridge import (
    CODEX_BIN_NAME,
    REASON_CODE_BIN_NOT_FOUND,
    REASON_CODE_OK,
    REASON_CODE_VERSION_PROBE_FAILED,
    CodexReadiness,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


NPM_CODEX_PATH: str = r"C:\Users\test\AppData\Roaming\npm\codex.CMD"
NATIVE_CODEX_PATH: str = r"C:\Users\test\OpenAI\Codex\bin\codex.EXE"


def _inject_readiness(
    bridge: GovernedFrontDoorRuntimeBridge,
    readiness: CodexReadiness,
) -> GovernedFrontDoorRuntimeBridge:
    """Inject a deterministic readiness directly into the bridge cache.

    Mirrors the same pattern used by ``tests/contract/test_runtime_bridge.py``
    so the test does not depend on the host's ``shutil.which``.
    """
    object.__setattr__(bridge, "_readiness", readiness)
    return bridge


def _make_ready_readiness(executable_path: str, version: str) -> CodexReadiness:
    return CodexReadiness(
        executable_found=True,
        executable_path=executable_path,
        version=version,
        supported=True,
        ready=True,
        reason_code=REASON_CODE_OK,
    )


# ---------------------------------------------------------------------------
# G1 -- Windows npm codex.CMD resolved path
# ---------------------------------------------------------------------------


class TestG1NpmCmdResolvedPath:
    """Default governed factory MUST honor the npm ``codex.CMD`` path."""

    def test_runtime_codex_bin_equals_readiness_path(self) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )

        factory = bridge.codex_runtime_factory()  # callable (closure)
        assert callable(factory)
        backend = factory()
        assert isinstance(backend, SubprocessCodexRuntime)
        # ``runtime.codex_bin`` MUST equal the resolved .CMD path the
        # readiness reported. Bare "codex" is forbidden here.
        assert backend.codex_bin == NPM_CODEX_PATH
        assert backend.codex_bin != CODEX_BIN_NAME
        assert backend.codex_bin == bridge.readiness().executable_path

    def test_factory_is_idempotent_under_cached_readiness(self) -> None:
        """Repeated factory invocations MUST yield the same target."""
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )

        factory = bridge.codex_runtime_factory()
        first = factory()
        second = factory()
        third = factory()
        # Each invocation produces a fresh runtime instance, but ALL
        # share the same resolved executable authority.
        assert first.codex_bin == second.codex_bin == third.codex_bin
        assert first.codex_bin == NPM_CODEX_PATH


# ---------------------------------------------------------------------------
# G2 -- bare "codex" and resolved .CMD distinguished
# ---------------------------------------------------------------------------


class TestG2BareVsResolvedDistinguished:
    """The default factory MUST select the resolved path, NOT the bare token.

    A bare ``"codex"``-only fallback is forbidden when a resolved readiness
    is present. The test verifies the factory result never equals the bare
    token.
    """

    def test_bare_token_forbidden_when_resolved_present(self) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )

        backend = bridge.codex_runtime_factory()()
        # Resolved .CMD path MUST be the execution target.
        assert backend.codex_bin == NPM_CODEX_PATH
        # Bare token MUST NOT be used when a resolved readiness exists.
        assert backend.codex_bin != CODEX_BIN_NAME
        # And the two MUST be observably distinct strings, not the same
        # object accidentally normalized.
        assert str(backend.codex_bin) != str(CODEX_BIN_NAME)
        assert "\\" in backend.codex_bin
        assert backend.codex_bin.lower().endswith(".cmd")


# ---------------------------------------------------------------------------
# G3 -- Native codex.EXE compatibility
# ---------------------------------------------------------------------------


class TestG3NativeExeCompatibility:
    """Same invariant MUST hold for the native codex.EXE case."""

    def test_native_exe_path_is_used(self) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NATIVE_CODEX_PATH, version="0.146.0"
            ),
        )

        factory = bridge.codex_runtime_factory()
        backend = factory()
        assert isinstance(backend, SubprocessCodexRuntime)
        assert backend.codex_bin == NATIVE_CODEX_PATH
        assert backend.codex_bin == bridge.readiness().executable_path
        assert backend.codex_bin.lower().endswith(".exe")


# ---------------------------------------------------------------------------
# G4 -- Custom test seam unchanged
# ---------------------------------------------------------------------------


class TestG4CustomSeamPreserved:
    """The ``codex_runtime_factory`` injection seam MUST keep working.

    Production default factory changes; explicit injected factories MUST
    be untouched. This is the existing test seam (see
    ``tests/contract/test_rq4_r2_c3_governed_execution.py:TestGovernedSubcommand``
    and the kernel seam ``codex_runtime_factory`` parameter in
    :func:`synapx_harness.kernel.governed_execution.run_governed_execution`).
    """

    def test_injected_factory_takes_precedence_over_default(self) -> None:
        captured: dict[str, Any] = {}
        sentinel_path = r"C:\sentinel\codex.exe"

        class _SentinelRuntime:
            codex_bin = sentinel_path

            def invoke(self, *args, **kwargs):  # pragma: no cover
                raise AssertionError

        def _custom_factory() -> Any:
            captured["called"] = True
            return _SentinelRuntime()

        bridge = GovernedFrontDoorRuntimeBridge(
            workspace_root=".",
            codex_runtime_factory=_custom_factory,
        )
        # Even if a resolved readiness is present, the injected factory
        # MUST win.
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )

        factory = bridge.codex_runtime_factory()
        backend = factory()
        assert captured.get("called") is True
        assert backend.codex_bin == sentinel_path
        # The injected factory's authority MUST be honored over the
        # readiness-reported path.
        assert backend.codex_bin != NPM_CODEX_PATH

    def test_default_factory_constructor_arg_is_optional(self) -> None:
        """No-arg construction MUST still bind the resolved-path default."""

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        # Without injection AND without an injected readiness, the
        # factory still builds a SubprocessCodexRuntime from somewhere
        # along the discovery path (or fallback). The seam MUST be
        # usable end-to-end.
        factory = bridge.codex_runtime_factory()
        assert callable(factory)
        backend = factory()
        assert isinstance(backend, SubprocessCodexRuntime)


# ---------------------------------------------------------------------------
# Fail-closed invariants
# ---------------------------------------------------------------------------


class TestFailClosedUnchanged:
    """When readiness is not READY the factory MUST remain fail-closed.

    The factory still produces a ``SubprocessCodexRuntime`` (the same
    shape as before repair), but the calling governance layer
    (``GovernedFrontDoorRuntimeBridge.invoke`` /
    ``kernel/governed_execution``) rejects any invocation whose
    ``readiness.ready`` is False. The CALLABLE ITSELF must remain
    callable; only the GOVERNED INVOCATION is fail-closed.
    """

    def test_probe_failure_still_yields_callable_factory(self) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            CodexReadiness(
                executable_found=True,
                executable_path=NPM_CODEX_PATH,
                version=None,
                supported=False,
                ready=False,
                reason_code=REASON_CODE_VERSION_PROBE_FAILED,
            ),
        )

        factory = bridge.codex_runtime_factory()
        assert callable(factory)
        backend = factory()
        # The factory falls back to the bare name so runtime
        # construction never crashes; the admission gate is the
        # upstream consumer's responsibility (and ``invoke()`` already
        # short-circuits on ready=False).
        assert isinstance(backend, SubprocessCodexRuntime)
        assert backend.codex_bin == CODEX_BIN_NAME

    def test_missing_codex_still_yields_callable_factory(self) -> None:
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            CodexReadiness(
                executable_found=False,
                executable_path=None,
                version=None,
                supported=False,
                ready=False,
                reason_code=REASON_CODE_BIN_NOT_FOUND,
            ),
        )

        factory = bridge.codex_runtime_factory()
        assert callable(factory)
        backend = factory()
        assert isinstance(backend, SubprocessCodexRuntime)
        assert backend.codex_bin == CODEX_BIN_NAME


# ---------------------------------------------------------------------------
# Authority flow integration (RQ8-R1-R1 §CLEAN-ROOM RE-ADMISSION CONTRACT)
# ---------------------------------------------------------------------------


class TestAuthorityContractIntegration:
    """Reproduce the exact contract the new-PC re-admission script runs."""

    def test_authority_contract_matches_clean_room_script(self) -> None:
        """The new-PC re-admission contract:

            bridge.readiness().executable_path
            == bridge.codex_runtime_factory()().codex_bin
        """
        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )

        readiness = bridge.readiness()
        runtime = bridge.codex_runtime_factory()()
        assert (
            runtime.codex_bin
            == readiness.executable_path
            == NPM_CODEX_PATH
        )

    def test_no_re_lookup_of_shutil_which(self, monkeypatch) -> None:
        """The factory MUST NOT trigger another ``shutil.which`` lookup.

        Per RQ8-R1-R1 §REQUIRED REPAIR: discovery authority is the cache,
        not a new filesystem lookup. Patch ``shutil.which`` so a forbidden
        re-call would surface as a sentinel exception.
        """

        def _forbidden_lookup(*args, **kwargs):
            raise AssertionError(
                "default codex_runtime_factory MUST NOT call shutil.which"
            )

        import shutil

        monkeypatch.setattr(shutil, "which", _forbidden_lookup)

        bridge = GovernedFrontDoorRuntimeBridge(workspace_root=".")
        _inject_readiness(
            bridge,
            _make_ready_readiness(
                executable_path=NPM_CODEX_PATH, version="0.153.4"
            ),
        )

        backend = bridge.codex_runtime_factory()()
        assert backend.codex_bin == NPM_CODEX_PATH
