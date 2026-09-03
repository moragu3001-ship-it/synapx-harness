"""_runs directory disk census."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from synapx_harness.storage.catalog import (
    ReferenceState,
    RunMetadata,
    RunStatus,
    StorageCatalog,
    compute_run_size,
)


@dataclass(frozen=True)
class CensusError:
    """Error encountered during census."""

    path: str
    error: str


@dataclass(frozen=True)
class CensusResult:
    """Census result with errors preserved."""

    catalog: StorageCatalog
    errors: tuple[CensusError, ...] = field(default_factory=tuple)

    @property
    def census_complete(self) -> bool:
        return len(self.errors) == 0


def _detect_status(run_path: Path) -> RunStatus:
    """Detect run status from filesystem signals.

    Terminal/finalization evidence is authoritative.
    worker_report alone does NOT imply COMPLETE.
    ACTIVE/RUNNING signals always take precedence.
    """
    if not run_path.is_dir():
        return RunStatus.UNKNOWN

    signals: list[str] = []
    for entry in run_path.rglob("*"):
        if not entry.is_file():
            continue
        name_lower = entry.name.lower()
        signals.append(name_lower)

    has_active = any("active" in s and "marker" in s for s in signals)
    has_running = any("running" in s for s in signals)

    if has_active or has_running:
        return RunStatus.ACTIVE if has_active else RunStatus.RUNNING

    has_terminal = any(
        ("final_seal" in s or "final_close" in s or "close_seal" in s)
        and s.endswith(".json")
        for s in signals
    )

    if has_terminal:
        return RunStatus.COMPLETE

    has_worker_report = any("worker_report" in s for s in signals)
    if has_worker_report:
        return RunStatus.INCOMPLETE

    has_any = len(signals) > 0
    if has_any:
        return RunStatus.INCOMPLETE

    return RunStatus.UNKNOWN


def _detect_sealed_evidence(run_path: Path) -> bool:
    """Check if run contains sealed evidence files."""
    for entry in run_path.rglob("*"):
        if not entry.is_file():
            continue
        name_lower = entry.name.lower()
        if "seal" in name_lower and name_lower.endswith(".json"):
            return True
        if name_lower.endswith("_seal_receipt.json"):
            return True
    return False


def _detect_review_package(run_path: Path) -> bool:
    """Check if run contains review package ZIP files."""
    for entry in run_path.rglob("*.zip"):
        name_lower = entry.name.lower()
        if "review" in name_lower or "package" in name_lower:
            return True
    return False


def _detect_authority_reference(run_path: Path) -> bool:
    """Check if run contains authority reference files."""
    for entry in run_path.rglob("*"):
        if not entry.is_file():
            continue
        name_lower = entry.name.lower()
        if "authority" in name_lower and name_lower.endswith(".json"):
            return True
        if "work_order" in name_lower and name_lower.endswith(".json"):
            return True
    return False


def _detect_pinned(run_path: Path) -> bool:
    """Check if run is pinned via marker file."""
    return (run_path / ".pinned").exists()


def _detect_protected(run_path: Path) -> bool:
    """Check if run is protected via marker file."""
    return (run_path / ".protected").exists()


def _last_known_activity_at(run_path: Path) -> str | None:
    """Read fresh last activity timestamp from filesystem mtime.

    Returns ISO string or None if unreadable.
    """
    try:
        stat = run_path.stat()
        return datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat()
    except OSError:
        return None


def _scan_all_external_references(
    project_root: Path,
    run_ids: set[str],
    *,
    required_dirs: frozenset[str] = frozenset({"_tracks", "review", "evidence"}),
) -> tuple[dict[str, ReferenceState], bool]:
    """Scan project root for external references to all run IDs.

    Returns (result_map, scan_complete).
    If scan is incomplete or errors occur, scan_complete=False
    and all results default to UNKNOWN.
    """
    result: dict[str, ReferenceState] = {rid: ReferenceState.UNREFERENCED for rid in run_ids}

    if not project_root.is_dir():
        return {rid: ReferenceState.UNKNOWN for rid in run_ids}, False

    search_dirs: list[Path] = []
    missing_dirs: list[str] = []
    for dirname in required_dirs:
        d = project_root / dirname
        if d.is_dir():
            search_dirs.append(d)
        else:
            missing_dirs.append(dirname)

    if missing_dirs:
        return {rid: ReferenceState.UNKNOWN for rid in run_ids}, False

    text_extensions = {".json", ".md", ".txt", ".yaml", ".yml", ".py", ".csv"}
    scan_errors = 0

    for search_dir in search_dirs:
        try:
            for f in search_dir.rglob("*"):
                if not f.is_file():
                    continue
                if f.suffix.lower() not in text_extensions:
                    continue
                try:
                    if f.stat().st_size > 5 * 1024 * 1024:
                        continue
                except OSError:
                    scan_errors += 1
                    continue
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    scan_errors += 1
                    continue
                for rid in run_ids:
                    if result[rid] == ReferenceState.UNREFERENCED and rid in content:
                        result[rid] = ReferenceState.REFERENCED
        except OSError:
            scan_errors += 1

    if scan_errors > 0:
        return {rid: ReferenceState.UNKNOWN for rid in run_ids}, False

    return result, True


def build_catalog(
    runs_root: Path,
    project_root: Path | None = None,
) -> CensusResult:
    """Build a complete catalog of all runs in _runs directory.

    Returns CensusResult with catalog and any errors encountered.
    If project_root is provided, scan for external references.
    Missing/error scan → reference_state = UNKNOWN.
    """
    if not runs_root.is_dir():
        return CensusResult(catalog=StorageCatalog())

    entries: list[Path] = []
    errors: list[CensusError] = []

    for entry in sorted(runs_root.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith("."):
            continue
        entries.append(entry)

    ref_states: dict[str, ReferenceState] = {}
    scan_complete = True
    if project_root is not None:
        run_ids = {e.name for e in entries}
        ref_states, scan_complete = _scan_all_external_references(project_root, run_ids)
        if not scan_complete:
            errors.append(CensusError(
                path=str(project_root),
                error="reference_scan_incomplete: missing required dirs or scan errors",
            ))

    runs: list[RunMetadata] = []
    for entry in entries:
        try:
            size_bytes = compute_run_size(entry)
        except OSError as e:
            errors.append(CensusError(path=str(entry), error=str(e)))
            size_bytes = 0

        status = _detect_status(entry)
        has_sealed = _detect_sealed_evidence(entry)
        has_review = _detect_review_package(entry)
        has_auth = _detect_authority_reference(entry)
        pinned = _detect_pinned(entry)
        protected = _detect_protected(entry)

        if project_root is not None and scan_complete:
            ref_state = ref_states.get(entry.name, ReferenceState.UNREFERENCED)
        elif project_root is not None and not scan_complete:
            ref_state = ReferenceState.UNKNOWN
        else:
            ref_state = ReferenceState.UNKNOWN

        try:
            stat = entry.stat()
            created_at = datetime.fromtimestamp(
                stat.st_ctime, tz=UTC
            ).isoformat()
            modified_at = datetime.fromtimestamp(
                stat.st_mtime, tz=UTC
            ).isoformat()
        except OSError as e:
            errors.append(CensusError(path=str(entry), error=str(e)))
            created_at = datetime.now(tz=UTC).isoformat()
            modified_at = created_at

        runs.append(
            RunMetadata(
                run_id=entry.name,
                path=str(entry),
                size_bytes=size_bytes,
                status=status,
                created_at=created_at,
                last_known_activity_at=modified_at,
                pinned=pinned,
                protected=protected,
                reference_state=ref_state,
                has_sealed_evidence=has_sealed,
                has_review_package=has_review,
                has_authority_reference=has_auth,
            )
        )

    return CensusResult(
        catalog=StorageCatalog(runs=tuple(runs)),
        errors=tuple(errors),
    )
