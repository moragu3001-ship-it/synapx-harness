"""Kiro adapter package (placeholder).

This subpackage provides a protocol-only placeholder for future Kiro
integration. It MUST NOT implement concrete Kiro hooks, and MUST NOT
guess Kiro event names. The actual implementation is intentionally
deferred until the AWS Kiro Contract is published.
"""
from synapx_harness.adapters.kiro.protocol import KiroAdapterProtocol

__all__ = ["KiroAdapterProtocol"]
