"""Review package scope rules.

A *review package* is a ZIP file containing an evidence-backed snapshot
of two repositories plus the review's own artefacts. The scope rules
reject pyc / __pycache__ / cache / secrets / `.env` paths.
"""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from synapx_harness.validators.isolation_validator import PACKAGE_SCOPE_DENY_PATTERNS

CORE_FILE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "README.md",
        "AGENTS.md",
        "CHANGELOG.md",
        "VERSION",
        "pyproject.toml",
        "uv.lock",
        ".gitignore",
    }
)

SERVICE_PACK_FILE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "README.md",
        "AGENTS.md",
        "CHANGELOG.md",
        "VERSION",
        "SERVICE_PACK_MANIFEST.yaml",
        ".gitignore",
    }
)

SERVICE_PACK_DIR_ALLOWLIST: frozenset[str] = frozenset(
    {
        "repository-registry",
        "profiles",
        "policies",
        "integrations",
        ".kiro",
        "llm-wiki",
        "governance",
        "tests",
        "evidence",
    }
)

CORE_DIR_ALLOWLIST: frozenset[str] = frozenset({"src", "tests"})


def normalize_path(rel: str) -> str:
    """Normalize a relative path: forward slashes, no leading slash."""
    return rel.replace("\\", "/").lstrip("/")


def _is_gitkeep_placeholder(path: str) -> bool:
    return path.endswith("/.gitkeep") or path == ".gitkeep"


def is_path_allowed(rel: str, *, scope: str) -> bool:
    """Check if a normalized path is allowed in the review package."""
    path = normalize_path(rel)
    parts = path.split("/")
    if len(parts) < 2:
        return False
    repo = parts[0]
    inside = parts[1:]
    if scope == "core":
        if repo != "synapx-harness":
            return False
        if any(token == "__pycache__" for token in inside):
            return False
        if any(token.endswith(".pyc") or ".cpython-" in token for token in inside):
            return False
        if any(token.endswith(".pyo") for token in inside):
            return False
        if len(inside) == 1:
            return inside[0] in CORE_FILE_ALLOWLIST
        if inside[0] not in CORE_DIR_ALLOWLIST:
            return False
        if _is_gitkeep_placeholder(inside[-1]) and len(inside) == 2:
            return True
        if inside[0] == "tests":
            if _is_gitkeep_placeholder(inside[-1]):
                return True
            if len(inside) >= 2 and inside[1] == "fixtures":
                return inside[-1].endswith(".py") or inside[-1] == ""
            return inside[-1].endswith(".py")
        allowed_ext = (".py", ".json", ".yaml", ".yml", ".toml", ".md", ".lock", ".txt")
        return inside[-1].endswith(allowed_ext)
    if scope == "service_pack":
        if repo != "communis-pilot-service-pack":
            return False
        if any(token == "__pycache__" for token in inside):
            return False
        if any(token.endswith(".pyc") or ".cpython-" in token for token in inside):
            return False
        if any(token.endswith(".pyo") for token in inside):
            return False
        if len(inside) == 1:
            return inside[0] in SERVICE_PACK_FILE_ALLOWLIST
        if inside[0] not in SERVICE_PACK_DIR_ALLOWLIST:
            return False
        if _is_gitkeep_placeholder(inside[-1]):
            return True
        allowed_ext = (".py", ".json", ".yaml", ".yml", ".toml", ".md", ".mdx")
        return inside[-1].endswith(allowed_ext)
    return False


def iter_scope_files(
    *,
    core_root: Path | None = None,
    service_pack_root: Path | None = None,
) -> list[tuple[str, str, Path]]:
    """Yield (scope, normalized_path, source_path) tuples for the review package."""
    out: list[tuple[str, str, Path]] = []
    seen_exact: set[str] = set()
    if core_root is not None:
        for path in core_root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(core_root).as_posix()
            full = f"synapx-harness/{rel}"
            resolved = str(path.resolve())
            if resolved in seen_exact:
                continue
            seen_exact.add(resolved)
            if is_path_allowed(full, scope="core"):
                out.append(("core", full, path))
    seen_exact.clear()
    if service_pack_root is not None:
        for path in service_pack_root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(service_pack_root).as_posix()
            full = f"communis-pilot-service-pack/{rel}"
            resolved = str(path.resolve())
            if resolved in seen_exact:
                continue
            seen_exact.add(resolved)
            if is_path_allowed(full, scope="service_pack"):
                out.append(("service_pack", full, path))
    return out


def iter_scope_paths(
    *,
    core_root: Path | None = None,
    service_pack_root: Path | None = None,
) -> list[str]:
    """Yield only the relative paths inside the review package."""
    files = iter_scope_files(
        core_root=core_root,
        service_pack_root=service_pack_root,
    )
    return [name for _, name, _ in files]


def filter_allowed_paths(paths: Iterable[str], *, scope: str) -> list[str]:
    return [p for p in paths if is_path_allowed(p, scope=scope)]


def is_excluded(rel: str) -> bool:
    path = normalize_path(rel)
    for pattern in PACKAGE_SCOPE_DENY_PATTERNS:
        if pattern.search(path):
            return True
    return False


__all__ = [
    "CORE_DIR_ALLOWLIST",
    "CORE_FILE_ALLOWLIST",
    "SERVICE_PACK_DIR_ALLOWLIST",
    "SERVICE_PACK_FILE_ALLOWLIST",
    "filter_allowed_paths",
    "is_excluded",
    "is_path_allowed",
    "iter_scope_files",
    "normalize_path",
]
