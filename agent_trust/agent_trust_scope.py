"""Compatibility import for the canonical standalone scope gate."""

from agent_trust.scope import (
    STATIC_SCOPE_CONTRACT_VERSION,
    SUPPORTED_STATIC_SCOPE_CONTRACT_VERSIONS,
    gate_static_scope_manifest_consistency,
)

__all__ = [
    "STATIC_SCOPE_CONTRACT_VERSION",
    "SUPPORTED_STATIC_SCOPE_CONTRACT_VERSIONS",
    "gate_static_scope_manifest_consistency",
]
