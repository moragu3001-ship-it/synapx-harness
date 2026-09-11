"""Knowledge Authority Validator.

Enforces the rule that SEMANTIC_ASSERTION knowledge items MUST NOT
carry ACTIVE_CANONICAL authority. ACTIVE_CANONICAL requires an
activation_manifest_ref binding.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class KnowledgeAuthorityReport:
    ok: bool
    violations: tuple[str, ...] = field(default_factory=tuple)
    payload_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "violations": list(self.violations),
            "payload_path": self.payload_path,
        }


def validate_knowledge_authority(payload: Mapping[str, object]) -> KnowledgeAuthorityReport:
    """Validate a knowledge item / document profile payload."""
    violations: list[str] = []
    knowledge_class = payload.get("knowledge_class")
    authority = payload.get("authority")
    state = payload.get("document_state")
    execution_authority = payload.get("execution_authority")

    if knowledge_class == "SEMANTIC_ASSERTION" and authority != "NON_AUTHORITATIVE":
        violations.append(
            f"SEMANTIC_ASSERTION requires authority=NON_AUTHORITATIVE "
            f"(got authority={authority!r})"
        )

    if authority == "ACTIVE_CANONICAL" and not payload.get("activation_manifest_ref"):
        violations.append(
            "ACTIVE_CANONICAL authority requires activation_manifest_ref"
        )

    if state in {"RAW", "DRAFT", "REVIEW_CANDIDATE", "RELEASE_CANDIDATE"}:
        if execution_authority is not False:
            violations.append(
                f"document_state={state!r} requires execution_authority=false "
                f"(got execution_authority={execution_authority!r})"
            )

    return KnowledgeAuthorityReport(
        ok=not violations,
        violations=tuple(violations),
    )


__all__ = ["KnowledgeAuthorityReport", "validate_knowledge_authority"]
