"""RQ8 Phase 2A-R1 key-aware terminal input (line-oriented only).

Production idle-prompt reader for the minimal interactive console. The
reader is backed by ``prompt_toolkit`` — used ONLY for a line-oriented
prompt with ``ESC`` / ``Ctrl+C`` bindings. No alternate screen, no panes,
no event bus, no streaming: Phase 2A stays ``THIN_LINE_ORIENTED_ONLY``.

Exit signalling uses the ``prompt_toolkit`` application-exit mechanism:
a key binding calls ``event.app.exit(result=<sentinel>)`` and
``session.prompt()`` returns that sentinel normally. Key bindings NEVER
raise control exceptions across the key processor / event loop — an
exception escaping a binding is treated by ``prompt_toolkit`` as an
event-loop crash (crash banner plus a blocking continue prompt) and the
console stays alive consuming later input as tasks (RQ8 Phase 2A-R2
incident). The console loop alone decides termination from the
normalized event.

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

EXIT_ESCAPE_SENTINEL: object = object()
"""Normal ``prompt()`` result requesting immediate console exit (ESC)."""

EXIT_INTERRUPT_SENTINEL: object = object()
"""Normal ``prompt()`` result requesting immediate console exit (Ctrl+C)."""


def build_key_bindings() -> Any:
    """Build the minimal console key bindings (ESC + Ctrl+C).

    Each binding terminates the ``prompt_toolkit`` application with a
    sentinel result via ``event.app.exit()``; ``session.prompt()`` then
    returns normally and the reader maps the sentinel onto a normalized
    console event. Bindings never raise: user-registered bindings take
    precedence over the ``prompt_toolkit`` defaults, so the explicit
    ``Ctrl+C`` binding below deterministically replaces the default
    abort path. The ``except KeyboardInterrupt`` / ``except EOFError``
    guards in :func:`read_terminal_event` remain purely as backstops
    (e.g. SIGINT from outside the key processor).
    """
    from prompt_toolkit.key_binding import KeyBindings

    bindings = KeyBindings()

    @bindings.add("escape")
    def _escape_binding(event: Any) -> None:
        event.app.exit(result=EXIT_ESCAPE_SENTINEL)

    @bindings.add("c-c")
    def _interrupt_binding(event: Any) -> None:
        event.app.exit(result=EXIT_INTERRUPT_SENTINEL)

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
    map to ``EOF``. The ``prompt()`` call always returns normally (exit
    signalling travels through sentinel results, never exceptions), so
    the ``prompt_toolkit`` event-loop crash handler can never engage and
    the console loop alone decides termination. Only the idle read is
    guarded: an interrupt raised while governed execution is running
    must propagate with the existing canonical cancellation semantics
    and is therefore never caught here.
    """
    session = _build_session(
        prompt_text, app_input=app_input, app_output=app_output
    )
    try:
        result = session.prompt()
    except KeyboardInterrupt:
        return ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT)
    except EOFError:
        return ConsoleEvent(ConsoleEventKind.EOF)
    if result is EXIT_ESCAPE_SENTINEL:
        return ConsoleEvent(ConsoleEventKind.EXIT_ESCAPE)
    if result is EXIT_INTERRUPT_SENTINEL:
        return ConsoleEvent(ConsoleEventKind.EXIT_INTERRUPT)
    return classify_console_line(result)


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
