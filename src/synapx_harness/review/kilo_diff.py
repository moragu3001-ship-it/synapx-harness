"""Repair the .kilo current-vs-backup comparison report from IR1.

The previous report mis-classified the relationship between the
current `.kilo` and the legacy backup. This script reproduces the
comparison with explicit path arrays and categories so the R2 review
can rely on it as the single source of truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

BACKUP_DIR_NAME = "kilo-pre-communis-customos-20260723"


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _list_files(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    out: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            out[rel] = _hash_file(path)
    return out


def compare(kilo_root: Path, backup_root: Path) -> dict[str, object]:
    current = _list_files(kilo_root)
    backup = _list_files(backup_root)

    common = [k for k in current if k in backup]
    current_only = sorted(k for k in current if k not in backup)
    backup_only = sorted(k for k in backup if k not in current)
    same_hash = [k for k in common if current[k] == backup[k]]
    different_hash = [k for k in common if current[k] != backup[k]]

    legacy_agent = [k for k in current if re.match(r"^agents[\\/]customOS(-|\.|$)", k)]
    legacy_wiki = [k for k in current if re.match(r"^wiki[\\/]living[\\/]", k)]
    legacy_script = [k for k in current if re.match(r"^scripts[\\/]", k)]
    legacy_seed = [k for k in current if re.match(r"^seeds[\\/]", k)]
    using_git_worktrees = [
        k for k in current if re.match(r"^skills[\\/]using-git-worktrees[\\/]", k)
    ]

    classification = "MINIMAL_NEW_ENVIRONMENT"
    reasons: list[str] = []
    if current_only and not backup_only:
        classification = "MINIMAL_NEW_ENVIRONMENT"
        reasons.append("current has only newly-authored files outside the backup")
    elif backup_only and not current_only:
        classification = "EXACT_LEGACY_RESTORE"
        reasons.append("current is an exact restore of the backup")
    elif current_only and backup_only:
        classification = "LEGACY_ENVIRONMENT_PARTIAL_COPY"
        reasons.append("both sides have unique files")
    else:
        classification = "MIXED_OR_UNKNOWN"
        reasons.append("current and backup are identical")

    contains_legacy = bool(
        legacy_agent or legacy_wiki or legacy_script or legacy_seed or using_git_worktrees
    )
    minimal_supported = not contains_legacy

    return {
        "current_total_files": len(current),
        "backup_total_files": len(backup),
        "common_relative_path_count": len(common),
        "current_only_file_count": len(current_only),
        "backup_only_file_count": len(backup_only),
        "same_hash_count": len(same_hash),
        "different_hash_count": len(different_hash),
        "classification": classification,
        "classification_reasons": reasons,
        "current_only_files": current_only,
        "backup_only_files": backup_only,
        "same_hash_files": sorted(same_hash),
        "different_hash_files": sorted(different_hash),
        "current_matches_backup_exactly": (
            len(current_only) == 0
            and len(backup_only) == 0
            and not different_hash
        ),
        "current_contains_legacy_environment": contains_legacy,
        "minimal_environment_claim_supported": minimal_supported,
        "legacy_agent_files_in_current": sorted(legacy_agent),
        "legacy_wiki_files_in_current": sorted(legacy_wiki),
        "legacy_script_files_in_current": sorted(legacy_script),
        "legacy_seed_files_in_current": sorted(legacy_seed),
        "using_git_worktrees_in_current": sorted(using_git_worktrees),
        "gate": "PASS" if minimal_supported else "FAIL",
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kilo", default="D:\\communis\\.kilo")
    parser.add_argument(
        "--backup",
        default=f"D:\\communis\\_backup\\{BACKUP_DIR_NAME}",
    )
    parser.add_argument(
        "--out",
        default="D:\\communis\\_review\\COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R2\\kilo_current_vs_backup_comparison.json",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    kilo_root = Path(args.kilo)
    backup_root = Path(args.backup)
    if not backup_root.is_dir():
        raise SystemExit(f"backup path missing: {backup_root}")
    report = compare(kilo_root, backup_root)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
