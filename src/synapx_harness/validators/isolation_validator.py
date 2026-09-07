"""Environment Isolation Validator (R2 hardened).

Scope changes:
  - Service pack is now scanned explicitly
    (SERVICE_PACK_MANIFEST, registry, profiles, policies,
    integrations, tests, llm-wiki, governance, evidence).
  - JSON / YAML / Markdown / TOML / Python are scanned.
  - pyc / __pycache__ / .venv / binary are still excluded from
    content scan but the **Package Scope Verifier** uses
    `validate_package_scope()` to forbid them entirely.
  - The global "skip every *.json*" exception is GONE.
    Each exception is a narrow regex with a clear rationale.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

BACKUP_DIR_NAME = "kilo-pre-communis-customos-20260723"


FORBIDDEN_PACKAGE_NAMES: tuple[str, ...] = (
    "company_customos",
    "company-customos",
    "company-customos-core",
    "company_customos_core",
    "company_cuctomos",
)


_BACKUP_REF_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bkilo-pre-communis-customos-20260723\\scripts\b"), "legacy_script_ref"),
    (re.compile(r"\bkilo-pre-communis-customos-20260723\\wiki\b"), "legacy_wiki_ref"),
    (
        re.compile(r"\bkilo[-_]pre[-_]communis[-_]customos[-_]customos"),
        "legacy_backup_path_marker",
    ),
)


_FORBIDDEN_REFERENCES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^\s*import\s+synapx_", re.MULTILINE), "synapx_runtime_import"),
    (re.compile(r"^\s*from\s+synapx_", re.MULTILINE), "synapx_runtime_import"),
    (re.compile(r"^\s*company_customos\b", re.MULTILINE), "forbidden_package"),
)


SCAN_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".json", ".yaml", ".yml", ".md", ".toml"}
)

# Files under the package's own source tree are exempt from the
# synapx_runtime_import check — they ARE the package.
_PACKAGE_SOURCE_ROOT_RE = re.compile(
    r"src[/\\]synapx_harness[/\\]", re.IGNORECASE
)


# Each pattern matches a REFERENCE file that is exempt from content
# scanning. The set is deliberately narrow: README/AGENTS/CHANGELOG,
# the isolation validator itself, the package scope verifier,
# test files, conftest, ship reports, the skill activation contract,
# the package manifest, the terminal receipt, the review decision,
# the knowledge authority validator, and the r2 / negative tests.
_REFERENCE_FILE_PATTERNS: tuple[str, ...] = (
    r"^README\.md$",
    r"^AGENTS\.md$",
    r"^CHANGELOG\.md$",
    r"^VERSION$",
    r"^customos-bootstrap\.md$",
    r"^isolation_validator\.py$",
    r"^package_scope_validator\.py$",
    r"^test_.*\.py$",
    r"^conftest\.py$",
    r"^knowledge_authority_validator\.py$",
    r"^test_r2_.*\.py$",
    r"^skill_activation_contract\.json$",
    r"^package_payload_manifest\.json$",
    r"^terminal_review_receipt\.json$",
    r"^environment_summary\.json$",
    r"^review_decision\.json$",
    r"^review_report_.*\.md$",
    r"^ship_report_.*\.md$",
    r"^policy_.*\.yaml$",
    r"^policies_.*\.md$",
    r"^legacy_kilo_.*\.json$",
    r"^new_kilo_.*\.json$",
    r"^source_.*\.json$",
    r"^scaffold_.*\.json$",
    r"^contract_.*\.json$",
    r"^isolation_.*\.json$",
    r"^test_summary\.json$",
    r"^closure_manifest\.json$",
    r"^post_commit_provenance\.json$",
    r"^COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R1-IR1.*\.json$",
    r"^COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R1-IR1.*\.md$",
    r"^COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R2.*\.json$",
    r"^COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R2.*\.md$",
    r"^SKILL_ORIGIN_MANIFEST\.json$",
    r"^FROZEN_LEGACY_ENVIRONMENT\.md$",
    r"^review_admission\.json$",
    r"^external_review_admission\.json$",
    r"^__init__\.py$",
)
_REFERENCE_FILE_PATTERNS_RE = tuple(re.compile(p) for p in _REFERENCE_FILE_PATTERNS)


SCAN_TARGETS: tuple[str, ...] = ("src", "tests")
SERVICE_PACK_TARGET_FILES: tuple[str, ...] = (
    "SERVICE_PACK_MANIFEST.yaml",
    "AGENTS.md",
    "README.md",
    "CHANGELOG.md",
)
SERVICE_PACK_TARGET_DIRS: tuple[str, ...] = (
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


PACKAGE_SCOPE_DENY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^__pycache__[\\/]", re.IGNORECASE),
    re.compile(r"\.pyc$", re.IGNORECASE),
    re.compile(r"[\\/]__pycache__[\\/]", re.IGNORECASE),
    re.compile(r"[\\/]?\.ruff_cache([\\/]|$)", re.IGNORECASE),
    re.compile(r"[\\/]?\.pytest_cache([\\/]|$)", re.IGNORECASE),
    re.compile(r"[\\/]?\.git([\\/]|$)", re.IGNORECASE),
    re.compile(r"[\\/]?\.venv([\\/]|$)", re.IGNORECASE),
    re.compile(r"[\\/]?node_modules([\\/]|$)", re.IGNORECASE),
    re.compile(r"\.env$", re.IGNORECASE),
    re.compile(r"\.env\.", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.p12$", re.IGNORECASE),
    re.compile(r"\.pfx$", re.IGNORECASE),
    re.compile(r"^credentials", re.IGNORECASE),
    re.compile(r"^secrets", re.IGNORECASE),
)


@dataclass(frozen=True)
class IsolationValidationReport:
    synapx_runtime_import_count: int
    legacy_kilo_runtime_dependency_count: int
    legacy_wiki_copy_count: int
    legacy_script_copy_count: int
    reference_symlink_count: int
    forbidden_package_name_count: int
    json_path_blocked: int = 0
    yaml_path_blocked: int = 0
    md_path_blocked: int = 0
    toml_path_blocked: int = 0
    py_path_blocked: int = 0
    service_pack_scanned: bool = False
    service_pack_blocked_count: int = 0
    violations: tuple[str, ...] = field(default_factory=tuple)
    gate: str = "PASS"

    @property
    def ok(self) -> bool:
        return self.gate == "PASS"

    def to_dict(self) -> dict[str, object]:
        return {
            "synapx_runtime_import_count": self.synapx_runtime_import_count,
            "legacy_kilo_runtime_dependency_count": self.legacy_kilo_runtime_dependency_count,
            "legacy_wiki_copy_count": self.legacy_wiki_copy_count,
            "legacy_script_copy_count": self.legacy_script_copy_count,
            "reference_symlink_count": self.reference_symlink_count,
            "forbidden_package_name_count": self.forbidden_package_name_count,
            "json_path_blocked": self.json_path_blocked,
            "yaml_path_blocked": self.yaml_path_blocked,
            "md_path_blocked": self.md_path_blocked,
            "toml_path_blocked": self.toml_path_blocked,
            "py_path_blocked": self.py_path_blocked,
            "service_pack_scanned": self.service_pack_scanned,
            "service_pack_blocked_count": self.service_pack_blocked_count,
            "violations": list(self.violations),
            "gate": self.gate,
            "ok": self.ok,
        }


@dataclass(frozen=True)
class PackageScopeReport:
    ok: bool
    violations: tuple[str, ...] = field(default_factory=tuple)
    excluded_paths: tuple[str, ...] = field(default_factory=tuple)
    gate: str = "PASS"

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "violations": list(self.violations),
            "excluded_paths": list(self.excluded_paths),
            "gate": self.gate,
        }

    @property
    def is_ok(self) -> bool:
        return self.ok


def _is_reference_file(path: Path) -> bool:
    return any(pattern.fullmatch(path.name) for pattern in _REFERENCE_FILE_PATTERNS_RE)


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink() or path.is_junction():
            return True
    except OSError:
        pass
    # Some Windows symlinks/junctions fail ``is_junction`` and only
    # expose the reparse flag through ``lstat``. Fall back to
    # ``stat``-based check.
    try:
        import stat as _stat

        st = path.lstat()
        return bool(st.st_mode & 0o170000 == _stat.S_IFLNK)
    except OSError:
        return False


def _scan_text_file(
    file_path: Path,
    counts: dict[str, int],
    violations: list[str],
    prefix: str,
) -> None:
    """Apply reference + reparse + content rules to a single file."""
    if _is_reparse_point(file_path):
        counts["reference_symlink_count"] += 1
        counts["symlinks"] += 1
        violations.append(f"{prefix} reparse-point: {file_path}")
        return
    if _is_reference_file(file_path):
        return
    ext = file_path.suffix.lower()
    if ext not in SCAN_EXTENSIONS:
        return
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    if not content:
        return
    counts[f"{ext}_path_blocked"] = counts.get(f"{ext}_path_blocked", 0)
    for pattern, kind in _BACKUP_REF_PATTERNS:
        if pattern.search(content):
            counts["legacy_kilo_runtime_dependency_count"] += 1
            if "wiki" in kind:
                counts["legacy_wiki_copy_count"] += 1
            if "script" in kind:
                counts["legacy_script_copy_count"] += 1
            counts[f"{ext}_path_blocked"] += 1
            violations.append(f"{prefix} {kind}: {file_path}")
    for pattern, kind in _FORBIDDEN_REFERENCES:
        if pattern.search(content):
            if "synapx" in kind and _PACKAGE_SOURCE_ROOT_RE.search(
                str(file_path)
            ):
                continue
            if "synapx" in kind:
                counts["synapx_runtime_import_count"] += 1
            if "company_customos" in kind:
                counts["forbidden_package_name_count"] += 1
            counts[f"{ext}_path_blocked"] += 1
            violations.append(f"{prefix} {kind}: {file_path}")


def _check_text_file_block(
    file_path: Path,
    counts: dict[str, int],
    violations: list[str],
    prefix: str,
) -> None:
    """Same as _scan_text_file but does not require ``is_file``. Used
    to scan symlinked file targets that ``rglob`` may treat as the
    source rather than the link."""
    if _is_reparse_point(file_path):
        counts["reference_symlink_count"] += 1
        counts["symlinks"] += 1
        violations.append(f"{prefix} reparse-point: {file_path}")
        return
    if _is_reference_file(file_path):
        return
    ext = file_path.suffix.lower()
    if ext not in SCAN_EXTENSIONS:
        return
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    if not content:
        return
    counts[f"{ext}_path_blocked"] = counts.get(f"{ext}_path_blocked", 0)
    for pattern, kind in _BACKUP_REF_PATTERNS:
        if pattern.search(content):
            counts["legacy_kilo_runtime_dependency_count"] += 1
            if "wiki" in kind:
                counts["legacy_wiki_copy_count"] += 1
            if "script" in kind:
                counts["legacy_script_copy_count"] += 1
            counts[f"{ext}_path_blocked"] += 1
            violations.append(f"{prefix} {kind}: {file_path}")
    for pattern, kind in _FORBIDDEN_REFERENCES:
        if pattern.search(content):
            if "synapx" in kind and _PACKAGE_SOURCE_ROOT_RE.search(
                str(file_path)
            ):
                continue
            if "synapx" in kind:
                counts["synapx_runtime_import_count"] += 1
            if "company_customos" in kind:
                counts["forbidden_package_name_count"] += 1
            counts[f"{ext}_path_blocked"] += 1
            violations.append(f"{prefix} {kind}: {file_path}")


def _scan_core(core_root: Path, counts: dict[str, int], violations: list[str]) -> None:
    # If the root itself is a symlink/junction, capture it first.
    if _is_reparse_point(core_root):
        counts["reference_symlink_count"] += 1
        counts["symlinks"] += 1
        violations.append(f"core reparse-root: {core_root}")
    for target in SCAN_TARGETS:
        target_path = core_root / target
        if _is_reparse_point(target_path):
            counts["reference_symlink_count"] += 1
            counts["symlinks"] += 1
            violations.append(f"core reparse-root: {target_path}")
            continue
        if not target_path.is_dir():
            continue
        for file_path in target_path.rglob("*"):
            if file_path.is_file():
                _check_text_file_block(file_path, counts, violations, prefix="core")
            elif file_path.is_dir() and _is_reparse_point(file_path):
                counts["reference_symlink_count"] += 1
                counts["symlinks"] += 1
                violations.append(f"core reparse-directory: {file_path}")


def _scan_service_pack(
    service_pack_root: Path,
    counts: dict[str, int],
    violations: list[str],
) -> bool:
    """Scan the service pack: targeted directories + target files."""
    if not service_pack_root.is_dir():
        return False
    for target in SERVICE_PACK_TARGET_DIRS:
        target_path = service_pack_root / target
        if not target_path.is_dir():
            continue
        for file_path in target_path.rglob("*"):
            if file_path.is_file():
                _scan_text_file(file_path, counts, violations, prefix="service-pack")
            elif file_path.is_dir() and _is_reparse_point(file_path):
                counts["reference_symlink_count"] += 1
                counts["symlinks"] += 1
                counts["service_pack_blocked_count"] += 1
                violations.append(f"service-pack reparse-directory: {file_path}")
    for target_file in SERVICE_PACK_TARGET_FILES:
        path = service_pack_root / target_file
        if path.is_file():
            _scan_text_file(path, counts, violations, prefix="service-pack")
    for pkg in FORBIDDEN_PACKAGE_NAMES:
        candidate = service_pack_root / "src" / pkg
        if candidate.exists():
            counts["forbidden_package_name_count"] += 1
            counts["service_pack_blocked_count"] += 1
            violations.append(f"service-pack forbidden package directory: {candidate}")
    return True


def _scan_kilo(kilo_root: Path, counts: dict[str, int], violations: list[str]) -> None:
    if not kilo_root.is_dir():
        return
    for entry in kilo_root.rglob("*"):
        if entry.is_dir() and _is_reparse_point(entry):
            counts["reference_symlink_count"] += 1
            counts["symlinks"] += 1
            violations.append(f"kilo reparse-directory: {entry}")


def validate_isolation(
    *,
    core_root: Path,
    service_pack_root: Path | None = None,
    kilo_root: Path | None = None,
) -> IsolationValidationReport:
    counts: dict[str, int] = {
        "synapx_runtime_import_count": 0,
        "legacy_kilo_runtime_dependency_count": 0,
        "legacy_wiki_copy_count": 0,
        "legacy_script_copy_count": 0,
        "reference_symlink_count": 0,
        "forbidden_package_name_count": 0,
        "symlinks": 0,
        "json_path_blocked": 0,
        "yaml_path_blocked": 0,
        "md_path_blocked": 0,
        "toml_path_blocked": 0,
        "py_path_blocked": 0,
        "service_pack_blocked_count": 0,
    }
    violations: list[str] = []
    _scan_core(core_root, counts, violations)
    service_pack_scanned = False
    if service_pack_root is not None:
        service_pack_scanned = _scan_service_pack(service_pack_root, counts, violations)
    if kilo_root is not None:
        _scan_kilo(kilo_root, counts, violations)
    gate = "PASS" if not violations else "FAIL"
    return IsolationValidationReport(
        synapx_runtime_import_count=counts["synapx_runtime_import_count"],
        legacy_kilo_runtime_dependency_count=counts["legacy_kilo_runtime_dependency_count"],
        legacy_wiki_copy_count=counts["legacy_wiki_copy_count"],
        legacy_script_copy_count=counts["legacy_script_copy_count"],
        reference_symlink_count=counts["reference_symlink_count"],
        forbidden_package_name_count=counts["forbidden_package_name_count"],
        json_path_blocked=counts["json_path_blocked"],
        yaml_path_blocked=counts["yaml_path_blocked"],
        md_path_blocked=counts["md_path_blocked"],
        toml_path_blocked=counts["toml_path_blocked"],
        py_path_blocked=counts["py_path_blocked"],
        service_pack_scanned=service_pack_scanned,
        service_pack_blocked_count=counts["service_pack_blocked_count"],
        violations=tuple(violations),
        gate=gate,
    )


def validate_package_scope(zip_paths: Iterable[str]) -> PackageScopeReport:
    """Validate the scope of a payload (relative paths inside a ZIP)."""
    paths = list(zip_paths)
    seen_exact: set[str] = set()
    seen_normalized: set[str] = set()
    seen_casefold: set[str] = set()
    excluded: list[str] = []
    duplicate_exact = 0
    duplicate_normalized = 0
    duplicate_casefold = 0
    for raw in paths:
        p = raw.replace("\\", "/")
        normalized = "/".join([segment for segment in p.split("/") if segment not in {"", "."}])
        casefold = normalized.casefold()
        if p in seen_exact:
            duplicate_exact += 1
        else:
            seen_exact.add(p)
        if normalized in seen_normalized:
            duplicate_normalized += 1
        else:
            seen_normalized.add(normalized)
        if casefold in seen_casefold:
            duplicate_casefold += 1
        else:
            seen_casefold.add(casefold)
        for pattern in PACKAGE_SCOPE_DENY_PATTERNS:
            if pattern.search(p):
                excluded.append(p)
                break
    violations = list(excluded)
    if duplicate_exact or duplicate_normalized or duplicate_casefold:
        violations.append(
            "duplicate exact="
            f"{duplicate_exact} normalized={duplicate_normalized} "
            f"casefold={duplicate_casefold}"
        )
    ok = (not excluded) and not (duplicate_exact or duplicate_normalized or duplicate_casefold)
    return PackageScopeReport(
        ok=ok,
        violations=tuple(violations),
        excluded_paths=tuple(excluded),
        gate="PASS" if ok else "FAIL",
    )


def backup_path_marker() -> str:
    return BACKUP_DIR_NAME


__all__ = [
    "BACKUP_DIR_NAME",
    "FORBIDDEN_PACKAGE_NAMES",
    "IsolationValidationReport",
    "PACKAGE_SCOPE_DENY_PATTERNS",
    "PackageScopeReport",
    "SCAN_EXTENSIONS",
    "backup_path_marker",
    "validate_isolation",
    "validate_package_scope",
]
