"""Packaged JSON Schema resources.

Schemas live inside the Python package so that both source-checkout and
installed-wheel resolutions resolve to the same authoritative schema set
via :mod:`importlib.resources`. The previous layout placed schemas at
``<repo>/schemas/`` which is not packaged into the wheel.

This module exposes a single resolver function :func:`packaged_schemas_root`
used by the schema validator. No re-export of schema content; data files
remain opaque resources loaded on demand.
"""
from __future__ import annotations

from importlib.resources import files

_PACKAGE = __name__

__all__ = ["packaged_schemas_root", "PACKAGED_SCHEMAS_PACKAGE"]


def packaged_schemas_root():
    """Return the :class:`importlib.resources.abc.Traversable` root.

    Returns the package root as a Traversable so that callers can use
    ``/`` join semantics to reach any schema file regardless of whether
    the package is a regular directory (source checkout) or a zip
    member (installed wheel).
    """
    return files(_PACKAGE)


PACKAGED_SCHEMAS_PACKAGE = __name__
