"""Lane C — Deterministic repository scanner (A3).

Guarantees:
  - read-only: never writes, never runs project scripts, never installs
    packages, never executes repository code
  - repository-root bounded: every file access (including root-level
    targeted files such as manifests, lockfiles, runtime configs,
    README) goes through the bounded path layer (``_bounded`` /
    ``_safe_read_*``). A candidate path is resolved first; if the
    resolved target escapes the root, it is recorded as OUT_OF_SCOPE
    UNKNOWN and NEVER read. Symlink and junction escapes are covered.
  - network-free and LLM-free for FACT extraction
  - deterministic: same revision + same files -> same semantic result
    (sorted traversal, sorted outputs, no timestamps)

FACT promotion requires deterministic evidence (explicit manifest,
lockfile, declared command, observed extension pair). Absent or
conflicting evidence stays UNKNOWN. README-derived meaning is an
ASSERTION (non-authoritative), never a FACT.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.context.models import (
    AssertionRecord,
    FactRecord,
    JsonValue,
    RepositoryBinding,
    SharedUnderstandingContext,
    UnknownRecord,
)
from synapx_harness.contracts.runtime_models import (
    SourceRevisionRef,
    build_source_revision_ref,
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")

SOURCE_ROOT_DIRS = ("src", "lib")
TEST_ROOT_DIRS = ("tests", "test")
CONFIG_FILES = (
    ".ruff.toml",
    "ruff.toml",
    ".pre-commit-config.yaml",
    "pytest.ini",
    "setup.cfg",
    "mypy.ini",
    "tox.ini",
)
CI_CONFIG_SIGNALS = (".github/workflows", ".gitlab-ci.yml")

MANIFEST_NAMES = (
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
)

LOCKFILE_MANAGERS = {
    "uv.lock": "uv",
    "poetry.lock": "poetry",
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "Cargo.lock": "cargo",
    "go.sum": "go",
    "Gemfile.lock": "bundler",
    "Pipfile.lock": "pipenv",
}

LANGUAGE_MANIFESTS = {
    "pyproject.toml": "Python",
    "package.json": "JavaScript",
    "Cargo.toml": "Rust",
    "go.mod": "Go",
    "Gemfile": "Ruby",
    "composer.json": "PHP",
}

LANGUAGE_EXTENSIONS = {
    "Python": {".py"},
    "JavaScript": {".js", ".jsx"},
    "TypeScript": {".ts", ".tsx"},
    "Go": {".go"},
    "Rust": {".rs"},
    "Java": {".java"},
    "Ruby": {".rb"},
    "PHP": {".php"},
}

COMMAND_SOURCES: tuple[str, ...] = ("test", "lint", "build")


@dataclass(frozen=True)
class ScannerOptions:
    """Deterministic scanner options (all defaults are fail-closed)."""

    include_readme_assertions: bool = True
    readme_assertion_confidence: float = 0.5
    max_readme_chars: int = 200
    skip_dirs: tuple[str, ...] = (
        ".git",
        "__pycache__",
        ".venv",
        "node_modules",
        "dist",
        "build",
        ".ruff_cache",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
    )


@dataclass
class _ScanState:
    """Internal scan accumulation (sorted at the end)."""

    facts: list[FactRecord] = field(default_factory=list)
    assertions: list[AssertionRecord] = field(default_factory=list)
    unknowns: list[UnknownRecord] = field(default_factory=list)
    source_extensions: set[str] = field(default_factory=set)


class DeterministicRepositoryScanner:
    """Read-only, root-bounded, deterministic repository fact scanner."""

    def __init__(
        self,
        repository_root: str | Path,
        *,
        repository_id: str,
        options: ScannerOptions | None = None,
    ) -> None:
        self.root = Path(repository_root).resolve()
        self.repository_id = repository_id
        self.options = options or ScannerOptions()
        self._revision_string: str | None = None
        self._outside_symlinks: list[str] = []
        self._manifest_names: list[str] = []
        if not self.root.is_dir():
            raise ValueError(f"repository root is not a directory: {self.root!s}")

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def scan(self) -> SharedUnderstandingContext:
        state = _ScanState()
        revision = self._collect_revision(state)
        self._collect_manifests(state)
        self._collect_tree_evidence(state)
        self._collect_runtime(state)
        self._collect_commands(state)
        self._collect_important_paths(state)
        self._collect_readme_assertions(state)

        revision_value = self._revision_value()
        for name in sorted(self._outside_symlinks):
            self._unknown(
                state,
                key="outside_root_symlink",
                reason="OUT_OF_SCOPE",
                provenance=name,
                revision=revision_value,
            )

        state.facts.sort(key=lambda f: (f.key, f.provenance))
        state.assertions.sort(key=lambda a: (a.key, a.provenance))
        state.unknowns.sort(key=lambda u: (u.key, u.provenance))
        return SharedUnderstandingContext(
            repository=RepositoryBinding(
                repository_id=self.repository_id,
                revision=revision,
            ),
            facts=state.facts,
            assertions=state.assertions,
            unknowns=state.unknowns,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _revision_value(self) -> str:
        return self._revision_string if self._revision_string else "UNKNOWN"

    def _record(
        self,
        state: _ScanState,
        *,
        key: str,
        value: JsonValue,
        provenance: str,
        revision: str,
    ) -> None:
        state.facts.append(
            FactRecord(
                key=key,
                value=value,
                source="scanner",
                provenance=provenance,
                repository_revision=revision,
            )
        )

    def _unknown(
        self,
        state: _ScanState,
        *,
        key: str,
        reason: str,
        provenance: str,
        revision: str,
    ) -> None:
        state.unknowns.append(
            UnknownRecord(
                key=key,
                reason=reason,  # type: ignore[arg-type]
                source="scanner",
                provenance=provenance,
                repository_revision=revision,
            )
        )

    # ------------------------------------------------------------------
    # bounded path layer (R1, ROOT_FILE_SYMLINK_ESCAPE closure)
    #
    # Every repository file access goes through this layer. A candidate
    # path is resolved first; if the resolved target escapes the root,
    # it is recorded as OUT_OF_SCOPE and NEVER read. Direct
    # ``root / name`` reads are forbidden outside this layer.
    # ------------------------------------------------------------------

    def _bounded(self, rel: str) -> Path | None:
        """Resolve a repo-relative path; None if the target escapes root.

        Escaping targets are recorded as OUT_OF_SCOPE evidence
        (deduplicated), never read.
        """
        candidate = self.root / rel
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = None
        if resolved is None or not resolved.is_relative_to(self.root):
            if rel not in self._outside_symlinks:
                self._outside_symlinks.append(rel)
            return None
        return resolved

    def _safe_is_file(self, rel: str) -> bool:
        resolved = self._bounded(rel)
        return resolved is not None and resolved.is_file()

    def _safe_isdir(self, rel: str) -> bool:
        resolved = self._bounded(rel)
        return resolved is not None and resolved.is_dir()

    def _safe_exists(self, rel: str) -> bool:
        resolved = self._bounded(rel)
        return resolved is not None and resolved.exists()

    def _safe_read_text(
        self, rel: str, *, errors: str = "strict"
    ) -> str | None:
        resolved = self._bounded(rel)
        if resolved is None or not resolved.is_file():
            return None
        try:
            return resolved.read_text(encoding="utf-8", errors=errors)
        except (OSError, UnicodeError):
            return None

    def _safe_read_bytes(self, rel: str) -> bytes | None:
        resolved = self._bounded(rel)
        if resolved is None or not resolved.is_file():
            return None
        try:
            return resolved.read_bytes()
        except OSError:
            return None

    def _collect_revision(self, state: _ScanState) -> SourceRevisionRef | None:
        result = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            capture_output=True,
        )
        if result.returncode == 0:
            raw = result.stdout.decode("ascii", errors="replace").strip()
            if _HEX40.match(raw):
                self._revision_string = raw
                return build_source_revision_ref(
                    repository_id=self.repository_id,
                    revision_kind="GIT_COMMIT",
                    revision_value=raw,
                )
        self._unknown(
            state,
            key="repository_revision",
            reason="NOT_OBSERVED",
            provenance="git rev-parse HEAD (no resolvable commit)",
            revision="UNKNOWN",
        )
        return None

    def _walk(self) -> Iterable[tuple[str, list[str], list[str]]]:
        """Sorted os.walk bounded to the repository root.

        Symlinked directories are never traversed (os.walk
        followlinks=False). Windows junctions are NOT reported as
        symlinks by ``is_symlink()`` and os.walk would traverse them,
        so junction/reparse-point directories are checked explicitly
        against the root boundary and never walked when they escape.
        Escaping links are recorded, not read.
        """
        skip = set(self.options.skip_dirs)
        for dirpath, dirnames, filenames in os.walk(
            self.root, followlinks=False
        ):
            kept: list[str] = []
            for name in sorted(dirnames):
                if name in skip:
                    continue
                candidate = Path(dirpath) / name
                if candidate.is_symlink() or candidate.is_junction():
                    resolved = candidate.resolve()
                    if not resolved.is_relative_to(self.root):
                        rel = candidate.relative_to(self.root).as_posix()
                        if rel not in self._outside_symlinks:
                            self._outside_symlinks.append(rel)
                    continue
                kept.append(name)
            dirnames[:] = kept
            yield dirpath, dirnames, sorted(filenames)

    def _collect_manifests(self, state: _ScanState) -> None:
        revision = self._revision_value()
        manifests = [name for name in MANIFEST_NAMES if self._safe_is_file(name)]
        lockfiles = sorted(
            name for name in LOCKFILE_MANAGERS if self._safe_is_file(name)
        )
        self._manifest_names = manifests

        for name in manifests:
            self._record(
                state,
                key="manifest",
                value=name,
                provenance=name,
                revision=revision,
            )
        for name in lockfiles:
            self._record(
                state,
                key="lockfile",
                value=name,
                provenance=name,
                revision=revision,
            )

        if len(lockfiles) == 1:
            self._record(
                state,
                key="package_manager",
                value=LOCKFILE_MANAGERS[lockfiles[0]],
                provenance=lockfiles[0],
                revision=revision,
            )
        elif len(lockfiles) > 1:
            self._unknown(
                state,
                key="package_manager",
                reason="CONFLICTING_SIGNALS",
                provenance=", ".join(lockfiles),
                revision=revision,
            )

        if not lockfiles:
            self._unknown(
                state,
                key="package_manager",
                reason="NO_EXPLICIT_SIGNAL",
                provenance="no lockfile observed",
                revision=revision,
            )

    def _collect_tree_evidence(self, state: _ScanState) -> None:
        """Extension observation (bounded walk; links never followed)."""
        revision = self._revision_value()
        manifest_names = self._manifest_names

        for dirpath, _dirnames, filenames in self._walk():
            for name in filenames:
                path = Path(dirpath) / name
                if path.is_symlink():
                    resolved = path.resolve()
                    if not resolved.is_relative_to(self.root):
                        rel = path.relative_to(self.root).as_posix()
                        if rel not in self._outside_symlinks:
                            self._outside_symlinks.append(rel)
                    continue
                ext = path.suffix.lower()
                if ext:
                    state.source_extensions.add(ext)

        if not state.source_extensions:
            self._unknown(
                state,
                key="language",
                reason="NO_EXPLICIT_SIGNAL",
                provenance="no source file extension observed",
                revision=revision,
            )

        for manifest_name in manifest_names:
            language = LANGUAGE_MANIFESTS[manifest_name]
            observed = any(
                ext in LANGUAGE_EXTENSIONS[language]
                for ext in state.source_extensions
            )
            if observed:
                self._record(
                    state,
                    key="language",
                    value=language,
                    provenance=f"{manifest_name} + source extensions",
                    revision=revision,
                )
            else:
                self._unknown(
                    state,
                    key="language",
                    reason="NO_EXPLICIT_SIGNAL",
                    provenance=f"{manifest_name} present but no "
                    f"{language} source extension observed",
                    revision=revision,
                )

    def _collect_runtime(self, state: _ScanState) -> None:
        revision = self._revision_value()

        python_version = self._safe_read_text(".python-version")
        if python_version is not None:
            self._record(
                state,
                key="runtime",
                value={"name": "Python", "version": python_version.strip() or "UNKNOWN"},
                provenance=".python-version",
                revision=revision,
            )
            return

        node_version = self._safe_read_text(".node-version")
        nvmrc = self._safe_read_text(".nvmrc")
        if node_version is not None or nvmrc is not None:
            content = (node_version if node_version is not None else nvmrc) or ""
            self._record(
                state,
                key="runtime",
                value={"name": "Node", "version": content.strip() or "UNKNOWN"},
                provenance=".node-version" if node_version is not None else ".nvmrc",
                revision=revision,
            )
            return

        toolchain = self._safe_read_text("rust-toolchain.toml")
        if toolchain is None:
            toolchain = self._safe_read_text("rust-toolchain")
        if toolchain is not None:
            self._record(
                state,
                key="runtime",
                value={"name": "Rust", "version": toolchain.strip() or "UNKNOWN"},
                provenance="rust-toolchain",
                revision=revision,
            )
            return

        package_json_raw = self._safe_read_bytes("package.json")
        if package_json_raw is not None:
            try:
                payload = json.loads(package_json_raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = None
            engines = (
                payload.get("engines", {}) if isinstance(payload, dict) else {}
            )
            if isinstance(engines, dict) and "node" in engines:
                self._record(
                    state,
                    key="runtime",
                    value={
                        "name": "Node",
                        "version": str(engines["node"]) or "UNKNOWN",
                    },
                    provenance="package.json:engines.node",
                    revision=revision,
                )
                return

        go_mod = self._safe_read_text("go.mod")
        if go_mod is not None:
            go_version = _parse_go_version(go_mod)
            if go_version is not None:
                self._record(
                    state,
                    key="runtime",
                    value={"name": "Go", "version": go_version},
                    provenance="go.mod",
                    revision=revision,
                )
                return

        self._unknown(
            state,
            key="runtime",
            reason="NO_EXPLICIT_SIGNAL",
            provenance="no explicit runtime config observed "
            "(.python-version/.nvmrc/.node-version/rust-toolchain/engines/go.mod)",
            revision=revision,
        )

    def _collect_commands(self, state: _ScanState) -> None:
        revision = self._revision_value()
        candidates: dict[str, list[tuple[str, str]]] = {
            name: [] for name in COMMAND_SOURCES
        }

        package_json_raw = self._safe_read_bytes("package.json")
        if package_json_raw is not None:
            try:
                payload = json.loads(package_json_raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._unknown(
                    state,
                    key="package_json",
                    reason="UNSUPPORTED_FORMAT",
                    provenance="package.json",
                    revision=revision,
                )
                payload = None
            if isinstance(payload, dict) and isinstance(
                payload.get("scripts"), dict
            ):
                scripts = payload["scripts"]
                for key in COMMAND_SOURCES:
                    value = scripts.get(key)
                    if isinstance(value, str) and value.strip():
                        candidates[key].append(
                            (value.strip(), f"package.json:scripts.{key}")
                        )

        makefile = self._safe_read_text("Makefile")
        if makefile is not None:
            targets = _parse_makefile_targets(makefile)
            for key in COMMAND_SOURCES:
                if key in targets:
                    candidates[key].append(("make " + key, f"Makefile:{key}"))

        tox_ini = self._safe_read_text("tox.ini")
        if tox_ini is not None and _tox_has_envlist(tox_ini):
            candidates["test"].append(("tox", "tox.ini:[tox]envlist"))

        pyproject_raw = self._safe_read_bytes("pyproject.toml")
        if pyproject_raw is not None:
            try:
                pyproject_data = tomllib.loads(pyproject_raw.decode("utf-8"))
            except (tomllib.TOMLDecodeError, UnicodeDecodeError):
                pyproject_data = {}
            tool = pyproject_data.get("tool", {})
            if isinstance(tool, dict):
                if isinstance(tool.get("pytest"), dict) and tool["pytest"].get(
                    "ini_options"
                ):
                    candidates["test"].append(
                        ("pytest", "pyproject.toml:[tool.pytest.ini_options]")
                    )
                if isinstance(tool.get("ruff"), dict):
                    candidates["lint"].append(
                        ("ruff", "pyproject.toml:[tool.ruff]")
                    )

        for key in COMMAND_SOURCES:
            self._emit_command(state, key, candidates[key], revision)

    def _emit_command(
        self,
        state: _ScanState,
        key: str,
        candidates: list[tuple[str, str]],
        revision: str,
    ) -> None:
        command_key = f"{key}_command"
        if not candidates:
            self._unknown(
                state,
                key=command_key,
                reason="NO_EXPLICIT_SIGNAL",
                provenance=f"no explicit {key} command declared",
                revision=revision,
            )
            return
        unique: list[tuple[str, str]] = []
        seen: set[str] = set()
        for value, source in candidates:
            if value not in seen:
                seen.add(value)
                unique.append((value, source))
        if len(unique) == 1:
            value, source = unique[0]
            self._record(
                state,
                key=command_key,
                value=value,
                provenance=source,
                revision=revision,
            )
            return
        self._unknown(
            state,
            key=command_key,
            reason="CONFLICTING_SIGNALS",
            provenance="; ".join(source for _, source in unique),
            revision=revision,
        )

    def _collect_important_paths(self, state: _ScanState) -> None:
        revision = self._revision_value()

        for name in SOURCE_ROOT_DIRS:
            if self._safe_isdir(name):
                self._record(
                    state,
                    key="important_path",
                    value={"path": name, "category": "SOURCE_ROOT"},
                    provenance=name,
                    revision=revision,
                )
        for name in TEST_ROOT_DIRS:
            if self._safe_isdir(name):
                self._record(
                    state,
                    key="important_path",
                    value={"path": name, "category": "TEST_ROOT"},
                    provenance=name,
                    revision=revision,
                )
        for name in CONFIG_FILES:
            if self._safe_is_file(name):
                self._record(
                    state,
                    key="important_path",
                    value={"path": name, "category": "CONFIG"},
                    provenance=name,
                    revision=revision,
                )
        for signal in CI_CONFIG_SIGNALS:
            if self._safe_exists(signal):
                self._record(
                    state,
                    key="important_path",
                    value={"path": signal, "category": "CI_CONFIG"},
                    provenance=signal,
                    revision=revision,
                )

    def _collect_readme_assertions(self, state: _ScanState) -> None:
        if not self.options.include_readme_assertions:
            return
        revision = self._revision_value()
        for name in ("README.md", "README"):
            text = self._safe_read_text(name, errors="replace")
            if text is None:
                continue
            paragraph = _first_paragraph(
                text,
                max_chars=self.options.max_readme_chars,
            )
            if not paragraph:
                continue
            state.assertions.append(
                AssertionRecord(
                    key="repository_purpose",
                    value=paragraph,
                    source="README",
                    provenance=name,
                    repository_revision=revision,
                    confidence=self.options.readme_assertion_confidence,
                    qualification="UNQUALIFIED",
                )
            )
            break


def _parse_go_version(content: str) -> str | None:
    match = re.search(r"(?m)^go\s+(v?\d+(?:\.\d+)*)", content)
    if not match:
        return None
    return match.group(1)


def _parse_makefile_targets(content: str) -> set[str]:
    targets: set[str] = set()
    for line in content.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:", line)
        if match:
            targets.add(match.group(1))
    return targets


def _tox_has_envlist(content: str) -> bool:
    in_tox = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_tox = stripped.lower() == "[tox]"
            continue
        if in_tox and stripped.startswith("envlist") and "=" in stripped:
            value = stripped.split("=", 1)[1].strip()
            if value and not value.startswith(("#", ";")):
                return True
    return False


def _first_paragraph(text: str, *, max_chars: int) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    paragraph = re.split(r"\n\s*\n", stripped, maxsplit=1)[0].strip()
    if len(paragraph) <= max_chars:
        return paragraph
    cut = paragraph[:max_chars]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "..."


def scan_repository(
    repository_root: str | Path,
    *,
    repository_id: str,
    options: ScannerOptions | None = None,
) -> SharedUnderstandingContext:
    """Scan a repository and return the canonical Shared Understanding context."""
    return DeterministicRepositoryScanner(
        repository_root, repository_id=repository_id, options=options
    ).scan()


__all__ = [
    "DeterministicRepositoryScanner",
    "ScannerOptions",
    "scan_repository",
]
