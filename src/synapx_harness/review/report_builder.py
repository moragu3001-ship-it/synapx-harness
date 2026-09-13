"""Review Report Builder.

Builds a structured Markdown review report. The report content is
hashed canonically and used as a binding artefact.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

REPORT_MARKER = "# COMMUNIS-CUSTOMOS-BOOTSTRAP-P1-P2-R3 — Review Report\n"


@dataclass(frozen=True)
class ReportBuildResult:
    report_path: str
    report_sha256: str


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_report(
    *,
    out_path: Path,
    phase: str,
    sections: Mapping[str, str],
    bullet_fields: Mapping[str, Mapping[str, object]],
    final_state: Mapping[str, str],
) -> ReportBuildResult:
    """Build the canonical review report.

    ``sections`` is an ordered mapping of H2 headings to prose. The
    final report is hashed canonically and the hash is returned.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# {phase} — Review Report")
    lines.append("")
    lines.append(f"- Generated: {_dt.datetime.now(_dt.UTC).isoformat()}")
    for title, items in bullet_fields.items():
        lines.append("")
        lines.append(f"- {title}:")
        for key, value in items.items():
            lines.append(f"  - {key}: {value}")
    lines.append("")
    lines.append("## Final State")
    for key, value in final_state.items():
        lines.append(f"- {key}: {value}")
    for title, body in sections.items():
        lines.append("")
        lines.append(f"## {title}")
        lines.append("")
        for line in body.splitlines():
            lines.append(line)
    text = "\n".join(lines) + "\n"
    out_path.write_text(text, encoding="utf-8")
    sha = hash_text(text)
    return ReportBuildResult(report_path=str(out_path), report_sha256=sha)


__all__ = ["ReportBuildResult", "build_report", "hash_bytes", "hash_text"]
