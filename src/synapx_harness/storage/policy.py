"""Retention and quota policy configuration."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetentionPolicy:
    """Minimal retention policy for B1."""

    ttl_days: int = 90
    max_total_bytes: int = 5 * 1024 * 1024 * 1024  # 5 GB default

    def __post_init__(self) -> None:
        if self.ttl_days < 0:
            raise ValueError("ttl_days must be non-negative")
        if self.max_total_bytes < 0:
            raise ValueError("max_total_bytes must be non-negative")
