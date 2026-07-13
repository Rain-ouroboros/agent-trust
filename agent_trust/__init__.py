"""Agent Trust: deterministic advisory checks for AI-agent inputs/actions.

The package has no runtime dependency beyond the standard library.  It returns
sanitized receipts; callers remain responsible for enforcement.
"""

from agent_trust.agent_trust_agency import (
    ScopeGrants,
    check_scope,
    classify_action,
    detect_excessive_agency,
)
from agent_trust.boundaries import (
    BOUNDARY_INTAKE_CONTRACT_VERSION,
    agent_trust_boundary_catalog,
    classify_agent_trust_boundaries,
    evaluate_agent_trust_change_control,
    gate_external_skill_descriptor,
    gate_runtime_pre_action_with_signals,
    gate_zero_trust_agent_action,
)
from agent_trust.scanner import (
    AgentTrustGate,
    MAX_PROMPT_BYTES,
    PromptVerdict,
    check_prompt,
    check_prompts_batch,
)
from agent_trust.scope import gate_static_scope_manifest_consistency
from agent_trust.utils import (
    canonicalize_agent_trust_packet,
    normalize_agent_trust_text,
    redact_agent_trust_packet,
)


__version__ = "0.2.0"

__all__ = [
    "AgentTrustGate",
    "BOUNDARY_INTAKE_CONTRACT_VERSION",
    "MAX_PROMPT_BYTES",
    "PromptVerdict",
    "ScopeGrants",
    "agent_trust_boundary_catalog",
    "canonicalize_agent_trust_packet",
    "check_prompt",
    "check_prompts_batch",
    "check_scope",
    "classify_action",
    "classify_agent_trust_boundaries",
    "detect_excessive_agency",
    "evaluate_agent_trust_change_control",
    "gate_external_skill_descriptor",
    "gate_runtime_pre_action_with_signals",
    "gate_static_scope_manifest_consistency",
    "gate_zero_trust_agent_action",
    "normalize_agent_trust_text",
    "redact_agent_trust_packet",
]
