"""Scaffold validator.

Checks that a service-pack directory has the required directory and
file layout. Used by `synapx-harness scaffold validate`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

REQUIRED_DIRECTORIES: tuple[str, ...] = (
    "repository-registry",
    "profiles",
    "policies",
    ".kiro",
    "llm-wiki",
    "governance",
    "integrations",
    "tests",
    "evidence",
)


@dataclass(frozen=True)
class ScaffoldValidationReport:
    ok: bool
    missing: tuple[str, ...]
    extra_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "missing": list(self.missing),
            "extra_notes": list(self.extra_notes),
        }


def validate_service_pack(root: Path) -> ScaffoldValidationReport:
    """Return a ScaffoldValidationReport for a service-pack root."""
    if not root.is_dir():
        return ScaffoldValidationReport(
            ok=False,
            missing=tuple(REQUIRED_DIRECTORIES),
            extra_notes=(f"root not found: {root}",),
        )
    missing: list[str] = []
    for name in REQUIRED_DIRECTORIES:
        if not (root / name).is_dir():
            missing.append(name)
    return ScaffoldValidationReport(
        ok=not missing,
        missing=tuple(missing),
    )


__all__ = [
    "REQUIRED_DIRECTORIES",
    "ScaffoldValidationReport",
    "validate_service_pack",
]
