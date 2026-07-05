"""Scope gate stub for standalone agent-trust library.

In the monorepo, this is provided by ouroboros.agent_trust_scope.
Standalone users can replace this with their own scope implementation.
"""

from typing import Optional


def gate_static_scope_manifest_consistency(
    _catalog: dict, _scope_manifest: Optional[dict] = None
) -> tuple[bool, str]:
    """Stub: always passes. Replace with real scope validation."""
    return True, "scope-gate: no scope manifest provided (standalone stub)"
