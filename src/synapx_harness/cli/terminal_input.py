"""RQ8 Phase 2A-R1 key-aware terminal input (line-oriented only).

Production idle-prompt reader for the minimal interactive console. The
reader is backed by ``prompt_toolkit`` — used ONLY for a line-oriented
prompt with ``ESC`` / ``Ctrl+C`` bindings. No alternate screen, no panes,
no event bus, no streaming: Phase 2A stays ``THIN_LINE_ORIENTED_ONLY``.

A standalone ``ESC`` keypress (no Enter) exits immediately because the
binding fires on the key itself; normal line editing (arrows, backspace,
history navigation) keeps working since escape *sequences* are still
decoded as editing keys.

When ``prompt_toolkit`` is unavailable or stdin is not a TTY, the reader
falls back to cooked builtin ``input()`` with the ESC-token line mapping
(``RQ8_PHASE2A_CONSOLE_INPUT_CENSUS.json``). The fallback keeps the
console usable; it is not the contract path for real terminals.

This module holds no execution authority: it only normalizes idle-prompt
input into :class:`ConsoleEvent` values. It never constructs agent
requests, never invokes provider binaries, and never decides terminal
completion.
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

from synapx_harness.cli.console import (
    CONSOLE_PROMPT,
    ConsoleEvent,
    ConsoleEventKind,
    classify_console_line,
    read_line_event,
)


class _EscapePressed(Exception):
    """Raised by the ESC key binding to request immediate console exit."""


def _on_escape(_event: Any) -> None:
    """Key-binding handler: a standalone ESC key exits the console."""
    raise _EscapePressed()


def build_key_bindings() -> Any:
    """Build the minimal console key bindings (ESC only).

    ``Ctrl+C`` / EOF keep the ``prompt_toolkit`` defaults
    (``KeyboardInterrupt`` / ``EOFError``), which the reader maps to
    ``EXIT_INTERRUPT`` / ``EOF``. Only the standalone-ESC contract needs a
    custom binding.
    """
    from prompt_toolkit.key_binding import KeyBindings

    bindings = KeyBindings()

    @bindings.add("escape")
    def _escape_binding(event: Any) -> None:
        _on_escape(event)

    return bindings


def _build_session(
    prompt_text: str = CONSOLE_PROMPT,
    *,
    app_input: Any = None,
    app_output: Any = None,
) -> Any:
    """Build one key-aware prompt session.

    ``app_input`` / ``app_output`` are the deterministic test seam
    (``prompt_toolkit`` pipe input + dummy output); production passes
    nothing and the session binds the real terminal.
    """
    from prompt_toolkit import PromptSession

    return PromptSession(
        message=prompt_text,
        key_bindings=build_key_bindings(),
        input=app_input,
        output=app_output,
    )


def is_key_aware_available() -> bool:
    """Report whether the key-aware backend can drive the real terminal."""
    if not sys.stdin.isatty():
        return False
    try:
        import prompt_toolkit  # noqa: F401
    except ImportError:
        return False
    return True


def read_terminal_event(
    prompt_text: str = CONSOLE_PROMPT,
    *,
    app_input: Any = None,
    app_output: Any = None,
) -> ConsoleEvent:
    """Read one normalized idle-prompt event from the real terminal.

    Standalone ``ESC`` maps to ``EXIT_ESCAPE`` with no Enter required;
    idle ``Ctrl+C`` maps to ``EXIT_INTERRUPT``; ``Ctrl+Z`` / ``Ctrl+D``
    map to ``EOF``. Only the idle read is guarded: an interrupt raised
    while governed execution is running must propagate with the existing
    canonical cancellation semantics and is therefore never caught here.
    """
    session = _build_session(
        prompt_text, app_input=app_input, app_output=app_output
    )
    try:
        line = session.prompt()
    except _EscapePressed:
        return ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE)
    except KeyboardInterrupt:
        return ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT)
    except EOFError:
        return ConsoleEvent(ConsoleEventKind.EOF)
    return classify_console_line(line)


def create_terminal_reader(
    prompt_text: str = CONSOLE_PROMPT,
    echo: Callable[..., None] | None = None,
) -> Callable[[], ConsoleEvent]:
    """Create the production idle-prompt event source for ``run_console``.

    Key-aware ``prompt_toolkit`` path when the real terminal is attached;
    cooked ``input()`` fallback otherwise (the fallback echoes the prompt
    through ``echo`` first so the ``synapx>`` marker stays visible).
    """
    if is_key_aware_available():
        def _read_key_aware() -> ConsoleEvent:
            return read_terminal_event(prompt_text)

        return _read_key_aware

    def _read_cooked() -> ConsoleEvent:
        if echo is not None:
            echo(prompt_text, nl=False)
        return read_line_event()

    return _read_cooked


__all__ = [
    "build_key_bindings",
    "create_terminal_reader",
    "is_key_aware_available",
    "read_terminal_event",
]
