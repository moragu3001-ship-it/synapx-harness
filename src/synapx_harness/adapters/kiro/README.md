# Kiro Adapter (Placeholder)

This subpackage is a protocol-only placeholder for future AWS Kiro
integration. It must NOT implement concrete Kiro hooks, events, or
runtime until the official Kiro contract is published.

## What MUST NOT be done in this subpackage

- No concrete Kiro hook names.
- No concrete Kiro event names.
- No Kiro SDK imports.
- No Kiro CLI shims.
- No Kiro runtime state.

## Why

SynapX-Harness defines a generic adapter boundary. The Kiro
implementation will be replaced when the official contract is
available. Adding speculative hooks now creates irreversible
contracts that block the real integration.
