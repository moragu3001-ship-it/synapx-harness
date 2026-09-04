"""SynapX Harness Front Door (RQ3-R2 bounded repair).

Lane A POST-H2 Public Alpha implementation. Public human entry layer.

The Front Door is intentionally minimal:

*  It does NOT probe the supported agent binary directly. Discovery is
   delegated to ``synapx_harness.cli.runtime_bridge``, the ONLY module
   allowed to invoke provider binaries on the user's behalf.
*  It does NOT construct canonical ``AgentRequest`` objects directly.
   Construction is delegated to the bridge.
*  It does NOT self-authorize verification, evidence sufficiency, or
   terminal completion. Agent ``DONE`` is presented as ``VERIFIED`` (a
   presentation label meaning "agent completed successfully") but never
   promoted to a Harness terminal authority.

Architectural invariants preserved:

*  :class:`RuntimePort` is a stable Protocol used by existing tests and
   downstream callers.
*  :func:`run` keeps the ``(workspace, task, runtime)`` signature so
   existing unit tests and the ``runtime=FakeXxxRuntime()`` injection
   seam still work.
*  Provider-binary invocation primitives (PATH lookup, system-call
   invocation, child-process invocation) are NOT imported in this module
   (per the existing ``TestA6`` contract).
*  Internal identity / kernel modules are NOT imported here (per the
   existing ``TestA9`` contract).
"""
from __future__ import annotations

import json
import os
import re
import sys
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Annotated, Protocol

import typer


DISTRIBUTION_NAME: str = "synapx-harness"


def _distribution_version() -> str:
    """Return the installed distribution version (SSoT: importlib.metadata)."""
    try:
        return importlib_metadata.version(DISTRIBUTION_NAME)
    except importlib_metadata.PackageNotFoundError:
        return "unknown"


class PresentationResult:
    """Lane-A local presentation result.

    This is NOT a TerminalDecisionRecord - it is a presentation-only
    value object used to map runtime results to public output.
    """

    def __init__(self, status: str, reason: str | None = None) -> None:
        self.status = status
        self.reason = reason


class RuntimePort(Protocol):
    """Lane A consumer-side seam for governed runtime execution.

    Front Door holds this port and calls it to request execution.
    Concrete implementations (real or test) must implement both methods.
    """

    def is_available(self) -> bool:
        """Check if the workspace-bound runtime is ready."""
        ...

    def invoke(self, task: str) -> PresentationResult | None:
        """Request task execution against the bound workspace.

        Returns ``None`` only if the implementation chooses to explicitly
        abstain; the canonical bridge always returns a ``PresentationResult``.
        """
        ...


# Front Door presentation map: agent outcome -> user-facing presentation string.
# IMPORTANT: ``VERIFIED`` here is a presentation label meaning "the supported
# agent completed successfully". It is NOT a Harness terminal authority
# (terminal authority is owned by evidence + verifier layers and is out
# of scope for the Front Door).
PRESENTATION_MAP: dict[str, str] = {
    "COMPLETED": "VERIFIED",
    "FAILED": "FAILED",
    "BLOCKED": "NEEDS_ATTENTION",
}


# Stable reason codes for Front Door user-facing output. Strings must remain
# stable so that downstream evidence / doctor / JSON surfaces can rely on them.
REASON_OK: str = "OK"
REASON_CODEX_NOT_FOUND: str = "CODEX_CLI_NOT_FOUND"
REASON_CODEX_PROBE_FAILED: str = "CODEX_VERSION_PROBE_FAILED"
REASON_INVALID_WORKSPACE: str = "INVALID_WORKSPACE"
REASON_EMPTY_TASK: str = "EMPTY_TASK"
REASON_RUNTIME_UNAVAILABLE: str = "RUNTIME_UNAVAILABLE"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"synapx {_distribution_version()}")
        raise typer.Exit()


def _detect_workspace(workspace_arg: Path | None) -> tuple[str, Path]:
    if workspace_arg is not None:
        path = workspace_arg
        if not path.exists():
            typer.echo("NEEDS_ATTENTION", err=True)
            typer.echo(
                f"Reason: Workspace path does not exist: {path}",
                err=True,
            )
            raise typer.Exit(code=1)
        if not path.is_dir():
            typer.echo("NEEDS_ATTENTION", err=True)
            typer.echo(
                f"Reason: Workspace path is not a directory: {path}",
                err=True,
            )
            raise typer.Exit(code=1)
        return path.name, path

    cwd = Path.cwd().resolve()
    return cwd.name, cwd


def _read_task_from_input() -> str:
    return input().strip()


def _render_progress(stage: str) -> None:
    typer.echo(f"{stage}...", err=True)


def _render_result(presentation: str, reason: str | None = None) -> None:
    typer.echo(presentation)
    if reason and presentation != "VERIFIED":
        typer.echo(f"Reason: {reason}", err=True)


def _map_to_presentation(result: object | None) -> str:
    if not isinstance(result, PresentationResult):
        return "NEEDS_ATTENTION"
    status = getattr(result, "status", None)
    if not isinstance(status, str):
        return "NEEDS_ATTENTION"
    return PRESENTATION_MAP.get(status, "NEEDS_ATTENTION")


def _build_runtime(workspace: Path) -> RuntimePort:
    """Construct the workspace-bound RuntimePort bridge.

    Imported lazily so that the bridge module is only loaded when the user
    actually runs a task. Importing ``runtime_bridge`` transitively imports
    ``synapx_harness.adapters.codex`` (canonical adapter). The Front Door
    itself never imports from ``adapters.codex`` directly.
    """
    from synapx_harness.cli.runtime_bridge import FrontDoorRuntimeBridge

    return FrontDoorRuntimeBridge(workspace_root=str(workspace))


def _missing_codex_user_message() -> tuple[str, str]:
    """User-facing actionable message when Codex CLI is not found.

    Returns ``(exit_message, actionable_guidance)``. Per RQ3-R2 §7 the
    message names the prerequisite, the PATH requirement, the verification
    command and the recheck command without hard-coding an install URL.
    """
    exit_message = "NEEDS_ATTENTION"
    guidance = (
        "Codex CLI prerequisite not satisfied.\n"
        "SynapX Public Alpha requires the Codex Official Headless CLI.\n"
        "- Requirement: `codex` must be on PATH.\n"
        "- Verify: `codex --version` (should print a version string).\n"
        "- Recheck SynapX readiness: `synapx doctor`."
    )
    return exit_message, guidance


def run(
    workspace: Path | None = None,
    task: str | None = None,
    runtime: RuntimePort | None = None,
) -> None:
    """Run synapx front door.

    Args:
        workspace: Explicit workspace path. Uses cwd if None.
        task: Task description. Prompts stdin if None.
        runtime: Runtime port for execution. If None, the workspace-bound
            canonical bridge is constructed on demand.
    """
    _render_progress("Detecting workspace")
    workspace_name, workspace_path = _detect_workspace(workspace)
    typer.echo(f"Workspace: {workspace_name}")

    _render_progress("Checking agent capability")
    if runtime is None:
        runtime = _build_runtime(workspace_path)
    agent_available = runtime.is_available()
    agent_name = "Codex" if agent_available else "Codex unavailable"
    typer.echo(f"Agent: {agent_name}")

    if not agent_available:
        typer.echo("NEEDS_ATTENTION", err=True)
        _exit_msg, guidance = _missing_codex_user_message()
        typer.echo(f"Reason: {guidance}", err=True)
        raise typer.Exit(code=1)

    effective_task = task
    if effective_task is None:
        typer.echo("> ", nl=False, err=True)
        effective_task = _read_task_from_input()

    if not effective_task:
        typer.echo("NEEDS_ATTENTION", err=True)
        typer.echo("Reason: Empty task is not allowed.", err=True)
        raise typer.Exit(code=1)

    _render_progress("Working")
    result = runtime.invoke(effective_task)

    _render_progress("Verifying")
    presentation = _map_to_presentation(result)
    _render_result(
        presentation,
        result.reason if isinstance(result, PresentationResult) else None,
    )


# ---------------------------------------------------------------------------
# Readiness diagnostic (`synapx doctor`)
# ---------------------------------------------------------------------------

doctor_app = typer.Typer(
    help="SynapX Harness readiness diagnostic.",
    no_args_is_help=False,
    add_completion=False,
)


def _doctor_workspace_check() -> dict[str, object]:
    """Workspace existence / directory check (read-only)."""
    cwd = Path.cwd().resolve()
    info: dict[str, object] = {
        "path": str(cwd),
        "basename": cwd.name,
        "exists": cwd.exists(),
        "is_directory": cwd.is_dir(),
    }
    return info


def _doctor_codex_check() -> dict[str, object]:
    """Codex readiness probe. Imported lazily to keep frontdoor free of provider invocation primitives."""
    from synapx_harness.cli.runtime_bridge import discover_codex

    return discover_codex().to_dict()


def _doctor_installed_distribution_check() -> dict[str, object]:
    return {
        "distribution": DISTRIBUTION_NAME,
        "version": _distribution_version(),
    }


def _doctor_supported_agent_check() -> dict[str, object]:
    from synapx_harness.cli.runtime_bridge import SUPPORTED_PUBLIC_AGENT

    return {"supported_agent": SUPPORTED_PUBLIC_AGENT}


def _render_doctor_human(payload: dict[str, object]) -> bool:
    """Render the doctor report in human-readable form.

    Returns ``True`` iff overall readiness is ``READY``.
    """
    ready = bool(payload.get("ready"))
    typer.echo("SynapX: " + ("READY" if ready else "NEEDS_ATTENTION"))
    dist = payload.get("distribution")
    if isinstance(dist, dict):
        typer.echo(
            f"Distribution: {dist.get('distribution')} {dist.get('version')}"
        )
    agent = payload.get("supported_agent")
    if isinstance(agent, dict):
        typer.echo(f"Agent: {agent.get('supported_agent')}")
    codex = payload.get("codex")
    if isinstance(codex, dict):
        if codex.get("executable_found"):
            typer.echo(
                f"Codex CLI: {codex.get('version') or 'found'} "
                f"({codex.get('executable_path')})"
            )
        else:
            typer.echo("Codex CLI: NOT_FOUND")
    ws = payload.get("workspace")
    if isinstance(ws, dict):
        typer.echo(f"Workspace: {ws.get('path')}")
    if not ready:
        typer.echo(
            "Next: install/enable Codex CLI and run `synapx doctor` again.",
            err=True,
        )
    return ready


@doctor_app.callback(invoke_without_command=True)
def doctor(
    ctx: typer.Context,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit the readiness report as JSON.",
    ),
) -> None:
    """Diagnose SynapX-Harness readiness for the supported Codex runtime."""
    if ctx.invoked_subcommand is not None:
        return

    dist = _doctor_installed_distribution_check()
    agent = _doctor_supported_agent_check()
    codex = _doctor_codex_check()
    workspace = _doctor_workspace_check()
    ready = bool(codex.get("ready"))

    payload: dict[str, object] = {
        "ready": ready,
        "distribution": dist,
        "supported_agent": agent,
        "codex": codex,
        "workspace": workspace,
    }

    if json_output:
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        _render_doctor_human(payload)

    if not ready:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Top-level CLI app
# ---------------------------------------------------------------------------

frontdoor_app = typer.Typer(
    help="SynapX Harness Front Door.",
    no_args_is_help=False,
    add_completion=False,
)
frontdoor_app.add_typer(doctor_app, name="doctor")


WorkspaceOption = Annotated[
    Path | None,
    typer.Option("--workspace", "-w", help="Workspace path."),
]
TaskOption = Annotated[
    str | None,
    typer.Option("--task", "-t", help="Task description."),
]


HELP_SHORT_DESCRIPTION: str = (
    "SynapX Harness runs governed coding-agent tasks through Codex."
)


HELP_LONG_DESCRIPTION: str = (
    "SynapX Harness runs governed coding-agent tasks through Codex.\n\n"
    "Public Alpha supported agent: Codex Official Headless CLI.\n\n"
    "First run:\n"
    "  synapx doctor\n"
    "  synapx --workspace <repo> --task \"<task>\"\n\n"
    "Options:\n"
    "  --workspace / -w  Repository path (defaults to current directory).\n"
    "  --task / -t       Task description. If omitted, SynapX reads from stdin.\n\n"
    "Use `synapx doctor` to diagnose Codex CLI readiness before running a task."
)


@frontdoor_app.callback(invoke_without_command=True)
def frontdoor(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True
    ),
    workspace: WorkspaceOption = None,
    task: TaskOption = None,
    help_flag: bool = typer.Option(
        False,
        "--help",
        callback=lambda v: _on_help(v),
        is_eager=True,
        help=HELP_LONG_DESCRIPTION,
    ),
) -> None:
    """SynapX Harness Front Door."""
    if ctx.invoked_subcommand is not None:
        return
    run(workspace=workspace, task=task)


_HELP_FLAG_RE = re.compile(r"--help\b")


def _on_help(value: bool) -> None:
    if not value:
        return
    typer.echo(HELP_SHORT_DESCRIPTION)
    typer.echo("")
    typer.echo(HELP_LONG_DESCRIPTION)
    raise typer.Exit()


def main() -> None:
    """Entry point for synapx CLI (no subcommand)."""
    # Custom --help rendering so we can include the first-run guidance.
    argv = sys.argv[1:]
    if any(arg == "--help" or arg == "-h" for arg in argv) and not any(
        a.startswith("doctor") for a in argv
    ):
        typer.echo(HELP_SHORT_DESCRIPTION)
        typer.echo("")
        typer.echo(HELP_LONG_DESCRIPTION)
        return
    frontdoor_app()


if __name__ == "__main__":
    main()