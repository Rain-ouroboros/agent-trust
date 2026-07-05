"""Utility functions for Agent Trust — normalization, redaction, secret detection.

Zero dependencies on ouroboros.*. Uses only stdlib.
"""
import re
import unicodedata
from typing import Any

# ---------------------------------------------------------------------------
# Homoglyphs and secret markers
# ---------------------------------------------------------------------------

_HOMOGLYPH_TRANSLATION = {
    ord(ch): replacement
    for ch, replacement in [
        ("а", "a"),  # Cyrillic a
        ("е", "e"),  # Cyrillic e
        ("о", "o"),  # Cyrillic o
        ("р", "p"),  # Cyrillic r
        ("с", "c"),  # Cyrillic s
        ("у", "y"),  # Cyrillic u
        ("х", "x"),  # Cyrillic kh
    ]
}

_SECRET_KEY_MARKERS = frozenset([
    "token", "api_key", "apikey", "secret", "password", "passwd",
    "credential", "private_key", "privatekey", "access_key", "accesskey",
    "auth", "bearer", "jwt", "session", "cookie",
])

_REDACTED_SECRET = "[REDACTED]"

_SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"[a-zA-Z0-9+/]{40,}={0,2}"),
    re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}"),
    re.compile(r"[0-9a-fA-F]{32,}"),
]

def normalize_agent_trust_text(value: Any) -> str:
    """Normalize adversarial text for advisory matching/redaction.

    This is intentionally small and dependency-free: strip Unicode formatting
    controls such as zero-width joiners, apply NFKC, and map a tiny set of
    common homoglyphs used to hide security-sensitive words. It is not a proof
    of semantic safety; it only makes obvious evasions visible to local checks.
    """
    text = unicodedata.normalize("NFKC", str(value)).translate(_HOMOGLYPH_TRANSLATION)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Cf")


def _looks_like_secret_key(key: Any) -> bool:
    normalized = normalize_agent_trust_text(key).lower().replace("-", "_").replace(" ", "_")
    return any(marker in normalized for marker in _SECRET_KEY_MARKERS)


def _redact_secret_text(value: str) -> str:
    redacted = value
    normalized = normalize_agent_trust_text(value)
    for pattern in _SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(_REDACTED_SECRET, redacted)
        if redacted == value and pattern.search(normalized):
            return _REDACTED_SECRET
    redacted = re.sub(r"(?i)(https?://)([^/@\s:]{3,}:[^/@\s]{3,}@)", r"\1[REDACTED_USERINFO]@", redacted)
    return redacted


def redact_agent_trust_packet(value: Any, *, parent_key: str | None = None) -> Any:
    """Return a JSON-safe copy with secret-shaped material removed.

    Agent Trust packets are advisory evidence artifacts and may become logs,
    receipts, or review bundles. They must never echo raw secret-looking input
    values. This redactor is conservative: key names associated with secrets
    redact their value even if the value itself is not pattern-matched.
    """
    if isinstance(value, dict):
        return {str(key): redact_agent_trust_packet(item, parent_key=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_agent_trust_packet(item, parent_key=parent_key) for item in value]
    if isinstance(value, tuple):
        return [redact_agent_trust_packet(item, parent_key=parent_key) for item in value]
    if isinstance(value, set):
        return sorted(redact_agent_trust_packet(item, parent_key=parent_key) for item in value)
    if isinstance(value, str):
        if parent_key is not None and _looks_like_secret_key(parent_key) and value.strip():
            return _REDACTED_SECRET
        return _redact_secret_text(value)
    return value


def canonicalize_agent_trust_packet(packet: Any) -> bytes:
    """Return deterministic canonical bytes for the redacted packet.

    The digest surface intentionally hashes the packet after conservative
    redaction. It is local integrity evidence only: no signing, timestamping,
    authentication, network call, wallet access, or execution is performed.
    """
    redacted = redact_agent_trust_packet(packet)
    return json.dumps(
        redacted,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

