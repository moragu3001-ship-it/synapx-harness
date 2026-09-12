"""SynapX Harness Front Door (RQ8-P0 bounded repair).

Lane A POST-H2 Public Alpha implementation. Public human entry layer.

The Front Door is intentionally minimal and presentation-only:

*  It does NOT probe the supported agent binary directly. Discovery is
   delegated to the runtime bridge, the ONLY module allowed to invoke
   provider binaries on the user's behalf.
*  It does NOT construct canonical ``AgentRequest`` objects directly.
   Construction is delegated to the bridge.
*  It does NOT decide verification, evidence sufficiency, or terminal
   completion. The default ``synapx`` entry drives the same canonical
   governed execution as ``synapx run`` (via
   ``GovernedFrontDoorRuntimeBridge``); ``VERIFIED`` is rendered only
   when the governed terminal decision is ``COMPLETED``. Agent ``DONE``
   alone can never produce ``VERIFIED``.

Architectural invariants preserved:

*  :class:`RuntimePort` is a stable Protocol used by existing tests and
   downstream callers.
*  :func:`run` keeps the ``(workspace, task, runtime)`` signature so
   existing unit tests and the injection seam still work.
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
from collections.abc import Callable
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Annotated, Protocol

import typer

from synapx_harness.cli.agent_activity import (
    AgentActivitySource,
    activity_for_agent_source,
    render_activity_lines,
)
from synapx_harness.cli.assurance_presentation import render_assurance_lines
from synapx_harness.cli.console import (
    CONSOLE_PROMPT,
    ConsoleEvent,
    ConsoleEventKind,
    render_console_header,
    render_console_help,
)
from synapx_harness.cli.terminal_input import create_terminal_reader


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

    The optional ``assurance`` slot carries a read-only
    ``AssurancePresentation`` built by the governed runtime bridge from
    the canonical governed result. It is always optional so existing
    fake runtimes and tests without assurance keep working unchanged.

    The optional ``agent`` slot carries a read-only
    ``AgentActivitySource`` snapshot of the EXISTING agent-lifecycle
    signals from the canonical governed result (never the terminal
    status). It is always optional so runtimes without agent-truth
    plumbing render ``Unavailable`` instead of an inferred lifecycle.
    """

    def __init__(
        self,
        status: str,
        reason: str | None = None,
        assurance: object | None = None,
        agent: AgentActivitySource | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.assurance = assurance
        self.agent = agent


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


# Front Door presentation map: governed outcome -> user-facing presentation string.
# IMPORTANT: ``VERIFIED`` here is the public label for a governed terminal
# decision of ``COMPLETED``. The Front Door never decides completion itself;
# completion authority lives in the governed execution (terminal authority
# reached through verification and sealed evidence). Agent ``DONE`` alone
# can never produce ``VERIFIED`` (RQ8-P0).
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


def _render_activity_terminal(agent: object) -> None:
    """Render the agent-truth activity section ahead of assurance.

    The section is projected ONLY from existing agent-lifecycle signals
    (``AgentActivitySource``); the Harness terminal status is never an
    input. Anything unrenderable -- or any runtime without agent-truth
    plumbing -- produces ``Unavailable`` rather than invented output.
    """
    try:
        source = agent if isinstance(agent, AgentActivitySource) else None
        for line in render_activity_lines(activity_for_agent_source(source)):
            typer.echo(line)
    except Exception:
        return


def _display_reason(
    reason: str | None, assurance: object | None
) -> str | None:
    """Prefer the first-failure reason carried by the assurance projection.

    The bridge keeps the legacy ``errors[0]``-or-generic reason on
    ``PresentationResult`` for backward compatibility, but the
    user-facing reason must follow first-failure precedence
    (primary failure > errors[0] > terminal reason), which the
    read-only projection already resolves. When the projection knows
    the terminal state, its reason wins; otherwise the legacy reason
    is kept so fake runtimes without assurance render unchanged.
    """
    state = getattr(assurance, "terminal_state", None)
    if state in ("COMPLETED", "FAILED", "BLOCKED"):
        candidate = getattr(assurance, "terminal_reason", None)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return reason


def _render_assurance(assurance: object | None) -> None:
    """Render a read-only assurance projection, if one was attached.

    Fail-closed: anything unrenderable produces no claim lines rather
    than invented output. The existing terminal label below still
    renders from the presentation map.
    """
    if assurance is None:
        return
    try:
        for line in render_assurance_lines(assurance):  # type: ignore[arg-type]
            typer.echo(line)
    except Exception:
        return


def _render_result(
    presentation: str,
    reason: str | None = None,
    assurance: object | None = None,
    *,
    agent: object = None,
) -> None:
    _render_activity_terminal(agent)
    _render_assurance(assurance)
    typer.echo(presentation)
    reason = _display_reason(reason, assurance)
    if reason and presentation != "VERIFIED":
        typer.echo(f"Reason: {reason}", err=True)


def _enforce_public_exit_contract(presentation_label: str) -> None:
    """Map a Front Door presentation label to process exit semantics.

    RQ5-R2 §6/§7/§8: this is the ONLY place the Front Door translates a
    terminal presentation into an OS process exit code. It does NOT decide
    terminal state; it only enforces that any presentation other than
    ``VERIFIED`` (the public label for Terminal.COMPLETED) fails the process.

    Canonical public exit contract:

        VERIFIED        (Terminal_COMPLETED) -> process exit 0
        FAILED          (Terminal_FAILED)    -> process exit non-zero
        NEEDS_ATTENTION (Terminal_BLOCKED)   -> process exit non-zero
        unknown / invalid                    -> process exit non-zero

    The exact non-zero value is unified to ``1`` for the Public Alpha.
    """
    if presentation_label != "VERIFIED":
        raise typer.Exit(code=1)


def _map_to_presentation(result: object | None) -> str:
    if not isinstance(result, PresentationResult):
        return "NEEDS_ATTENTION"
    status = getattr(result, "status", None)
    if not isinstance(status, str):
        return "NEEDS_ATTENTION"
    return PRESENTATION_MAP.get(status, "NEEDS_ATTENTION")


def _build_runtime(workspace: Path) -> RuntimePort:
    """Construct the workspace-bound RuntimePort bridge.

    RQ8-P0 authority convergence: the default entry drives the canonical
    governed execution, so this resolves to
    ``GovernedFrontDoorRuntimeBridge`` -- the same bridge used by
    ``synapx run``. Imported lazily so that this module stays free of
    kernel imports per the existing ``TestA9`` contract.
    """
    from synapx_harness.cli.governed_runtime_bridge import (
        GovernedFrontDoorRuntimeBridge,
    )

    return GovernedFrontDoorRuntimeBridge(workspace_root=str(workspace))


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

    # RQ8-P0 truthfulness: no separate "Verifying" stage is rendered here.
    # Verification (when required) runs inside the governed execution owned
    # by the runtime bridge; rendering it as a pending stage after invoke
    # returns would manufacture stage state the Front Door did not observe.
    presentation = _map_to_presentation(result)
    _render_result(
        presentation,
        result.reason if isinstance(result, PresentationResult) else None,
        result.assurance if isinstance(result, PresentationResult) else None,
        agent=result.agent
        if isinstance(result, PresentationResult)
        else None,
    )
    _enforce_public_exit_contract(presentation)


def run_console(
    workspace: Path | None = None,
    runtime: RuntimePort | None = None,
    *,
    read_event: Callable[[], ConsoleEvent] | None = None,
    echo: Callable[..., None] | None = None,
) -> int:
    """Run the RQ8 Phase 2A minimal interactive console.

    Presentation / input shell only: the console renders the minimal header,
    then repeatedly reads normalized idle-prompt events and dispatches each
    ``TASK`` event to the workspace-bound canonical governed runtime — the
    same bridge used by ``synapx run``. The existing terminal presentation
    (``VERIFIED`` / ``FAILED`` / ``NEEDS_ATTENTION``) is rendered per task
    and the loop returns to the ``synapx>`` prompt.

    No session authority is created: every task is an independent governed
    execution and a task never reuses another task's terminal status.

    Returns the process exit code. Any graceful console exit (``:quit``,
    ``ESC``, idle ``Ctrl+C``, EOF) returns ``0``; leaving the console never
    re-computes terminal truth. An interrupt raised while governed
    execution is running is deliberately NOT caught here, so the existing
    canonical cancellation semantics are preserved verbatim (never mapped
    to ``VERIFIED``, never promoted from a partial result).
    """
    out: Callable[..., None] = echo if echo is not None else typer.echo
    _render_progress("Detecting workspace")
    workspace_name, workspace_path = _detect_workspace(workspace)
    out(f"Workspace: {workspace_name}")

    _render_progress("Checking agent capability")
    if runtime is None:
        runtime = _build_runtime(workspace_path)
    agent_available = runtime.is_available()
    agent_name = "Codex" if agent_available else "Codex unavailable"
    out(f"Agent: {agent_name}")

    if not agent_available:
        out("NEEDS_ATTENTION", err=True)
        _exit_msg, guidance = _missing_codex_user_message()
        out(f"Reason: {guidance}", err=True)
        raise typer.Exit(code=1)

    render_console_header(out, workspace_name=workspace_name)

    if read_event is not None:
        # Injected seam (contract tests): the loop echoes the prompt marker
        # so ``synapx>`` stays visible without terminal hardware.
        def _next_event() -> ConsoleEvent:
            out(CONSOLE_PROMPT, nl=False)
            return read_event()
    else:
        # Production path: the key-aware terminal reader renders its own
        # prompt and fires standalone ESC with no Enter required.
        _next_event = create_terminal_reader(CONSOLE_PROMPT, out)

    while True:
        event = _next_event()
        kind = event.kind
        if kind in (
            ConsoleEventKind.QUIT,
            ConsoleEventKind.EXIT_ESCAPE,
            ConsoleEventKind.EXIT_INTERRUPT,
            ConsoleEventKind.EOF,
        ):
            return 0
        if kind is ConsoleEventKind.EMPTY:
            continue
        if kind is ConsoleEventKind.HELP:
            render_console_help(out)
            continue
        if kind is ConsoleEventKind.UNKNOWN_COMMAND:
            out(f"Unknown command: {event.text} (type :help for commands)")
            continue
        _render_progress("Working")
        result = runtime.invoke(event.text)
        _render_result(
            _map_to_presentation(result),
            result.reason if isinstance(result, PresentationResult) else None,
            result.assurance if isinstance(result, PresentationResult) else None,
            agent=result.agent
            if isinstance(result, PresentationResult)
            else None,
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
    if task is not None:
        run(workspace=workspace, task=task)
        return
    if sys.stdin.isatty():
        raise typer.Exit(code=run_console(workspace=workspace))
    # Non-TTY without --task: legacy fail-safe. A single stdin read drives a
    # single governed execution and the process exits. The console loop is
    # never entered when stdin is not interactive (headless / CI / piped).
    run(workspace=workspace, task=None)


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


# ---------------------------------------------------------------------------
# RQ4-R2-C3 public governed run subcommand (RQ8-P0: also the default path).
#
# RQ8-P0 authority convergence: the default ``synapx`` entry resolves to
# ``GovernedFrontDoorRuntimeBridge`` (see :func:`_build_runtime`), so both
# public entries drive Shared Understanding -> WorkContract -> Admission ->
# ExecutionIdentity -> canonical AgentRequest -> real CodexAdapter
# (SubprocessCodexRuntime) -> read-only Codex -> structured proposal ->
# mutation chain -> independent verifier -> evidence seal -> terminal
# decision issuance -> Front Door presentation.
# The ``run`` subcommand remains as the explicit governed path carrying
# the ``--receipt-out`` same-run receipt seam.
# ---------------------------------------------------------------------------

governed_app = typer.Typer(
    help="RQ4-R2-C3 public governed execution (positive path).",
    no_args_is_help=False,
    add_completion=False,
)
frontdoor_app.add_typer(governed_app, name="run")


def _build_governed_runtime(workspace: Path) -> Any:
    """Construct the workspace-bound governed runtime bridge."""
    from synapx_harness.cli.governed_runtime_bridge import (
        GovernedFrontDoorRuntimeBridge,
    )

    return GovernedFrontDoorRuntimeBridge(workspace_root=str(workspace))


def _render_governed_result(presentation: PresentationResult) -> str:
    """Map the terminal decision into the public Front Door presentation label.

    RQ4-R2-C3-R1: the Front Door is presentation-only. The mapping from a
    canonical ``TerminalDecision`` value (COMPLETED / FAILED / BLOCKED) to
    the public label (VERIFIED / FAILED / NEEDS_ATTENTION) is owned by this
    function and nowhere else. The Front Door NEVER decides whether
    completion is allowed; that authority lives in the Terminal Finalizer.

    Returns the rendered presentation label so the caller can enforce the
    public exit contract in one place (RQ5-R2 §8).
    """
    presentation_label = PRESENTATION_MAP.get(presentation.status, "NEEDS_ATTENTION")
    _render_activity_terminal(getattr(presentation, "agent", None))
    _render_assurance(presentation.assurance)
    typer.echo(presentation_label)
    display_reason = _display_reason(presentation.reason, presentation.assurance)
    if display_reason and presentation_label != "VERIFIED":
        typer.echo(f"Reason: {display_reason}", err=True)
    return presentation_label


def _write_same_run_receipt(envelope: dict[str, object], out_path: Path) -> None:
    """Serialize a pre-built canonical lineage envelope to ``out_path``.

    RQ4-R2-C3-R2 §15 same-run receipt seam. The seam is **disabled by
    default** — the Front Door only invokes it when ``--receipt-out`` is
    supplied on the ``run`` subcommand. The ``envelope`` is built by
    the runtime bridge (so this module stays free of
    ``synapx_harness.kernel`` imports per TestA9); the serializer only
    writes it verbatim. It MUST NOT re-construct any prior stage,
    re-run Codex, or make any admission / terminal decision.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


@governed_app.callback(invoke_without_command=True)
def governed_callback(
    ctx: typer.Context,
    workspace: WorkspaceOption = None,
    task: TaskOption = None,
    receipt_out: Annotated[
        Path | None,
        typer.Option(
            "--receipt-out",
            help=(
                "Optional path for the same-run canonical lineage receipt. "
                "Disabled by default; when supplied, the canonical envelope "
                "from the current governed execution is serialized verbatim."
            ),
        ),
    ] = None,
) -> None:
    """Run the RQ4-R2-C3 public governed lifecycle."""
    if ctx.invoked_subcommand is not None:
        return
    if not task:
        typer.echo("NEEDS_ATTENTION", err=True)
        typer.echo("Reason: --task is required for the governed run.", err=True)
        raise typer.Exit(code=1)
    workspace_name, workspace_path = _detect_workspace(workspace)
    typer.echo(f"Workspace: {workspace_name}")
    runtime = _build_governed_runtime(workspace_path)

    if receipt_out is not None:
        # Duck-type the runtime: the canonical ``GovernedFrontDoorRuntimeBridge``
        # exposes ``invoke_governed_with_result``; the legacy
        # ``FrontDoorRuntimeBridge`` does not. When ``--receipt-out`` is
        # supplied we REQUIRE the canonical seam so the same-run contract
        # cannot be silently degraded by a non-governed runtime.
        if not hasattr(runtime, "invoke_governed_with_result"):
            typer.echo("NEEDS_ATTENTION", err=True)
            typer.echo(
                "Reason: --receipt-out requires the canonical governed "
                "runtime bridge (SubprocessCodexRuntime-backed).",
                err=True,
            )
            raise typer.Exit(code=1)
        _result, presentation, envelope = runtime.invoke_governed_with_result(
            task=task
        )
        _write_same_run_receipt(envelope, receipt_out)
    else:
        presentation = runtime.invoke(task)
    if presentation is None:
        typer.echo("NEEDS_ATTENTION", err=True)
        raise typer.Exit(code=1)
    label = _render_governed_result(presentation)
    _enforce_public_exit_contract(label)


if __name__ == "__main__":
    main()