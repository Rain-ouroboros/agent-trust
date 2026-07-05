"""Agent Trust: a multi-layered security gate for AI agents.

Core library — zero dependencies beyond the standard library.
No network calls, no LLM calls, no filesystem access.
Pure deterministic boundary checking.
"""

from agent_trust.utils import normalize_agent_trust_text, redact_agent_trust_packet

__all__ = [
    "normalize_agent_trust_text",
    "redact_agent_trust_packet",
]
