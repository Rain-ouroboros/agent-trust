"""Agent Trust — local agent safety gate.

Boundary-based prompt safety scanner with domain-aware attack detection,
scope-of-authority checks, and excessive-agency classification.
"""

from agent_trust.agent_trust_boundaries import (
    classify_boundary,
    check_boundaries,
    check_boundaries_batch,
    ALL_BOUNDARIES,
    BoundaryMatch,
)
from agent_trust.agent_trust_agency import (
    classify_action,
    check_scope,
    detect_excessive_agency,
    ScopeGrants,
    ScopeVerdict,
)
from agent_trust.agent_trust_scope import (
    Scope,
    ScopeCheckResult,
    check_scope as check_scope_legacy,
)
from agent_trust.agent_trust import (
    AgentTrustGate,
    check_prompt,
    check_prompts_batch,
)

__all__ = [
    "classify_boundary",
    "check_boundaries",
    "check_boundaries_batch",
    "ALL_BOUNDARIES",
    "BoundaryMatch",
    "classify_action",
    "check_scope",
    "detect_excessive_agency",
    "ScopeGrants",
    "ScopeVerdict",
    "Scope",
    "ScopeCheckResult",
    "check_scope_legacy",
    "AgentTrustGate",
    "check_prompt",
    "check_prompts_batch",
]
