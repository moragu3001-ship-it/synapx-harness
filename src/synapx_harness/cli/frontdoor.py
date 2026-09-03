"""Minimal Front Door for synapx.

Lane A POST-H2 Public Alpha implementation.
This module provides the human entry layer only.
Execution is delegated to the governed runtime via Lane D adapter.
"""
from __future__ import annotations

from pathlib import Path
from typing import Annotated, Protocol

import typer


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

    This is a protocol/interface that Lane D adapter will implement.
    Front Door holds this port and calls it to request execution.
    """

    def is_available(self) -> bool:
        """Check if runtime is available."""
        ...

    def invoke(self, task: str) -> PresentationResult | None:
        """Request task execution. Returns None if unavailable."""
        ...


class DefaultRuntimePort:
    """Default runtime port - runtime not integrated."""

    def is_available(self) -> bool:
        return False

    def invoke(self, task: str) -> PresentationResult | None:
        return None


frontdoor_app = typer.Typer(help="SynapX Harness Front Door.", no_args_is_help=False)

PRESENTATION_MAP = {
    "COMPLETED": "VERIFIED",
    "FAILED": "FAILED",
    "BLOCKED": "NEEDS_ATTENTION",
}


def _detect_workspace(workspace_arg: Path | None) -> tuple[str, Path]:
    if workspace_arg is not None:
        path = workspace_arg
        if not path.exists():
            typer.echo("NEEDS_ATTENTION", err=True)
            typer.echo(f"Reason: Workspace path does not exist: {path}", err=True)
            raise typer.Exit(code=1)
        if not path.is_dir():
            typer.echo("NEEDS_ATTENTION", err=True)
            typer.echo(f"Reason: Workspace path is not a directory: {path}", err=True)
            raise typer.Exit(code=1)
        return path.name, path

    cwd = Path.cwd().resolve()
    return cwd.name, cwd


def _read_task_from_input() -> str:
    task = input().strip()
    return task


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


def run(
    workspace: Path | None = None,
    task: str | None = None,
    runtime: RuntimePort | None = None,
) -> None:
    """Run synapx front door.

    Args:
        workspace: Explicit workspace path. Uses cwd if None.
        task: Task description. Prompts stdin if None.
        runtime: Runtime port for execution. Uses DefaultRuntimePort if None.
    """
    runtime_port = runtime if runtime is not None else DefaultRuntimePort()

    _render_progress("Detecting workspace")
    workspace_name, workspace_path = _detect_workspace(workspace)
    typer.echo(f"Workspace: {workspace_name}")

    _render_progress("Checking agent capability")
    agent_available = runtime_port.is_available()
    agent_name = "Codex" if agent_available else "Codex unavailable"
    typer.echo(f"Agent: {agent_name}")

    if not agent_available:
        typer.echo("NEEDS_ATTENTION", err=True)
        typer.echo("Reason: Governed Codex runtime is not integrated.", err=True)
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
    result = runtime_port.invoke(effective_task)

    _render_progress("Verifying")
    presentation = _map_to_presentation(result)
    _render_result(presentation, result.reason if isinstance(result, PresentationResult) else None)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo("synapx 0.1.0")
        raise typer.Exit()


WorkspaceOption = Annotated[
    Path | None,
    typer.Option("--workspace", "-w", help="Workspace path."),
]

TaskOption = Annotated[
    str | None,
    typer.Option("--task", "-t", help="Task description."),
]


@frontdoor_app.callback(invoke_without_command=True)
def frontdoor(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", callback=_version_callback, is_eager=True),
    workspace: WorkspaceOption = None,
    task: TaskOption = None,
) -> None:
    """SynapX Harness Front Door."""
    if ctx.invoked_subcommand is not None:
        return
    run(workspace=workspace, task=task)


def main() -> None:
    """Entry point for synapx CLI (no subcommand)."""
    frontdoor_app()


if __name__ == "__main__":
    main()
