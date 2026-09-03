"""Negative tests for forbidden activation artifacts."""
from __future__ import annotations

from pathlib import Path

CORE_ROOT = Path(__file__).resolve().parents[2]


def _candidate_files(service_pack_root: Path | None = None) -> list[Path]:
    roots = [CORE_ROOT]
    if service_pack_root is not None:
        roots.append(service_pack_root)
    found: list[Path] = []
    for root in roots:
        for sub in (
            "llm-wiki/active",
            "llm-wiki/release-candidates",
            "governance/ratification",
            "governance/activation",
            "llm-wiki/generated/graphify",
        ):
            candidate = root / sub
            if candidate.is_dir():
                for path in candidate.rglob("*"):
                    if path.is_file():
                        found.append(path)
    return found


def test_phase_cannot_create_active_documents(service_pack_root: Path) -> None:
    forbidden_names = {
        "ACTIVE_MANIFEST.json",
        "OKF_ACTIVATION_MANIFEST.json",
        "ratification_receipt.json",
        "release_candidate_bundle.json",
        "graph.json",
        "GRAPH_REPORT.md",
    }
    for path in _candidate_files(service_pack_root):
        assert path.name not in forbidden_names, f"forbidden artifact: {path}"


def test_phase_cannot_create_activation_manifest(service_pack_root: Path) -> None:
    forbidden = [
        CORE_ROOT / "ACTIVE_MANIFEST.json",
        CORE_ROOT / "OKF_ACTIVATION_MANIFEST.json",
        service_pack_root / "ACTIVE_MANIFEST.json",
        service_pack_root / "OKF_ACTIVATION_MANIFEST.json",
    ]
    for path in forbidden:
        assert not path.exists(), f"forbidden artifact: {path}"
