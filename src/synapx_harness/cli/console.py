"""RQ8 Phase 2A minimal interactive console (line-oriented input shell).

Presentation / input shell ONLY — this module holds no execution authority:

*  It never constructs canonical agent requests and never invokes provider
   binaries (no executable lookup, no child-process primitives).
*  It never decides verification, evidence sufficiency, or terminal
   completion. Each ``TASK`` event is dispatched to the caller-supplied
   ``RuntimePort`` (the canonical governed runtime bridge built by
   ``frontdoor``); the returned ``PresentationResult`` is rendered with the
   existing Front Door presentation map. ``VERIFIED`` therefore still means
   only that the governed terminal decision was ``COMPLETED`` — agent
   ``DONE`` alone can never produce it.
*  It keeps no session authority: no persistent completion state, no shared
   terminal result, no orchestration state. Every task is an independent
   runtime invocation.

Stdlib only (``enum``, ``dataclasses``, builtin ``input``) plus the already
declared ``typer`` echo surface. No ``prompt_toolkit`` / ``textual`` /
``curses`` dependency — see ``RQ8_PHASE2A_CONSOLE_INPUT_CENSUS.json`` for
the terminal capability census and the ESC delivery limitation.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

CONSOLE_PROMPT: str = "synapx> "

ESC_TOKEN: str = "\x1b"

HELP_COMMAND: str = ":help"

QUIT_COMMAND: str = ":quit"


class ConsoleEventKind(Enum):
    """Normalized idle-prompt input events (RQ8 Phase 2A Section 19 seam)."""

    TASK = "TASK"
    EMPTY = "EMPTY"
    HELP = "HELP"
    QUIT = "QUIT"
    EXIT_ESCAPE = "EXIT_ESCAPE"
    EXIT_INTERRUPT = "EXIT_INTERRUPT"
    EOF = "EOF"
    UNKNOWN_COMMAND = "UNKNOWN_COMMAND"


@dataclass(frozen=True)
class ConsoleEvent:
    """One normalized console input event.

    ``text`` carries the stripped task instruction for ``TASK`` and the
    raw command token for ``UNKNOWN_COMMAND``; it is empty otherwise.
    """

    kind: ConsoleEventKind
    text: str = ""


def classify_console_line(line: str | None) -> ConsoleEvent:
    """Map one submitted input line onto a normalized console event.

    Mapping (line-oriented, cooked input only):

    *  ``None`` (closed stdin seam) -> ``EOF``.
    *  Empty / whitespace-only line -> ``EMPTY`` (reprompt, never executed).
    *  A line that is exactly the ESC byte (``0x1B``) -> ``EXIT_ESCAPE``.
       A standalone ESC keypress without Enter cannot be delivered through
       cooked ``input()`` on some terminals (see the input census); the
       guaranteed exits remain ``:quit``, ``Ctrl+C`` and EOF.
    *  ``:help`` -> ``HELP``; ``:quit`` -> ``QUIT``.
    *  Any other ``:``-prefixed line -> ``UNKNOWN_COMMAND`` (hint, never
       executed as a task, so control text is never sent to the agent).
    *  Anything else -> ``TASK`` with the stripped instruction.
    """
    if line is None:
        return ConsoleEvent(ConsoleEventKind.EOF)
    stripped = line.strip()
    if not stripped:
        return ConsoleEvent(ConsoleEventKind.EMPTY)
    if stripped == ESC_TOKEN:
        return ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE)
    if stripped == HELP_COMMAND:
        return ConsoleEvent(ConsoleEventKind.HELP)
    if stripped == QUIT_COMMAND:
        return ConsoleEvent(ConsoleEventKind.QUIT)
    if stripped.startswith(":"):
        return ConsoleEvent(ConsoleEventKind.UNKNOWN_COMMAND, text=stripped)
    return ConsoleEvent(ConsoleEventKind.TASK, text=stripped)


def read_line_event(
    reader: Callable[[], str | None] | None = None,
) -> ConsoleEvent:
    """Read one normalized console event from a bare line source.

    The default source is builtin ``input()`` (cooked, line-oriented); the
    ``synapx>`` prompt itself is rendered by the console loop so it stays
    visible even when ``reader`` is an injected test seam.

    ``KeyboardInterrupt`` (idle ``Ctrl+C``) maps to ``EXIT_INTERRUPT`` and
    ``EOFError`` (``Ctrl+Z`` / ``Ctrl+D`` / closed pipe) maps to ``EOF``.
    Only the idle read is guarded here: an interrupt raised while governed
    execution is running must propagate with the existing canonical
    cancellation semantics and is therefore never caught by this function.
    """
    read = reader if reader is not None else input
    try:
        line = read()
    except KeyboardInterrupt:
        return ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT)
    except EOFError:
        return ConsoleEvent(ConsoleEventKind.EOF)
    return classify_console_line(line)


def render_console_header(
    echo: Callable[..., None],
    *,
    workspace_name: str,
) -> None:
    """Render the minimal Phase 2A console header (Section 17 scope)."""
    echo("SynapX Harness")
    echo("")
    echo(f"Workspace  {workspace_name}")
    echo("Agent      Codex")
    echo("Status     Ready")
    echo("")


def render_console_help(echo: Callable[..., None]) -> None:
    """Render the Phase 2A ``:help`` text (Section 11 scope)."""
    echo("Commands")
    echo("  :help   Show available commands")
    echo("  :quit   Exit SynapX")
    echo("")
    echo("ESC / Ctrl+C")
    echo("  Return to the invoking shell")


__all__ = [
    "CONSOLE_PROMPT",
    "ESC_TOKEN",
    "HELP_COMMAND",
    "QUIT_COMMAND",
    "ConsoleEvent",
    "ConsoleEventKind",
    "classify_console_line",
    "read_line_event",
    "render_console_header",
    "render_console_help",
]
