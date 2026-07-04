"""Agent Trust static scope/manifest consistency gate.

Extracted from ``agent_trust_boundaries`` (deep-module decomposition): an
advisory, no-execution check that makes disagreement between an agent's
self-declared scopes/permissions and local manifest/lockfile-style evidence
visible before a tool/skill is used. It does not authorize action and does not
prove a tool is safe.

``gate_static_scope_manifest_consistency`` is re-exported from
``agent_trust_boundaries`` for backward-compatible imports.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from ouroboros.agent_trust import normalize_agent_trust_text, redact_agent_trust_packet


# Tiny pure helpers duplicated from agent_trust_boundaries so this module stays
# dependency-light (importing them back would create a circular import, since
# agent_trust_boundaries re-exports this module's gate).
def _coerce_descriptor(descriptor: Any) -> Any:
    if isinstance(descriptor, str):
        stripped = descriptor.strip()
        if stripped.startswith(("{", "[")):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return descriptor
    return descriptor


def _request_field(mapping: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


_STATIC_SCOPE_CONTRACT_VERSION = "agent-trust-static-scope-consistency-v1"
_SUPPORTED_STATIC_SCOPE_CONTRACT_VERSIONS = [_STATIC_SCOPE_CONTRACT_VERSION]
_DANGEROUS_STATIC_SCOPE_TERMS = {
    "secret", "secrets", "token", "credential", "credentials", "env", "read_env",
    "private_key", "seed", "wallet", "sign", "signing", "payment", "pay", "mainnet",
    "execute", "execution", "run", "shell", "subprocess", "command", "network",
    "http", "fetch", "post", "publish", "email", "dm", "outreach", "repo_write",
    "filesystem_write", "write_file", "delete", "admin",
}


def _scope_tokens(value: Any) -> set[str]:
    """Return conservative normalized scope/capability tokens from local evidence."""
    tokens: set[str] = set()

    def visit(item: Any) -> None:
        if item is None:
            return
        if isinstance(item, str):
            normalized = normalize_agent_trust_text(item).lower().strip()
            if normalized:
                tokens.add(normalized)
                for part in re.split(r"[^a-z0-9_./:-]+", normalized):
                    if part:
                        tokens.add(part)
            return
        if isinstance(item, bool):
            return
        if isinstance(item, dict):
            for key, val in item.items():
                key_norm = normalize_agent_trust_text(str(key)).lower().strip()
                if isinstance(val, bool):
                    if val and key_norm:
                        tokens.add(key_norm)
                    continue
                if key_norm in {"scope", "scopes", "permission", "permissions", "capability", "capabilities", "command", "commands", "tool", "tools"}:
                    visit(val)
                else:
                    visit(val)
            return
        if isinstance(item, (list, tuple, set)):
            for child in item:
                visit(child)
            return
        visit(str(item))

    visit(value)
    return tokens


def _manifest_evidence_status(value: Any) -> str:
    if value is None:
        return "missing"
    if isinstance(value, str) and not value.strip():
        return "empty"
    if isinstance(value, (list, tuple, set, dict)) and not value:
        return "empty"
    if not _scope_tokens(value):
        return "empty"
    return "present"


def _dangerous_scope_tokens(tokens: set[str]) -> set[str]:
    dangerous: set[str] = set()
    for token in tokens:
        token_norm = normalize_agent_trust_text(token).lower()
        if token_norm in _DANGEROUS_STATIC_SCOPE_TERMS:
            dangerous.add(token_norm)
            continue
        for term in _DANGEROUS_STATIC_SCOPE_TERMS:
            if term in token_norm:
                dangerous.add(token_norm)
                break
    return dangerous


def gate_static_scope_manifest_consistency(request: Any, *, contract_version: str | None = None) -> dict[str, Any]:
    """Compare declared scopes with local manifest/lockfile evidence.

    Advisory static inspection only. It does not execute third-party code and
    does not prove a tool is safe; it makes disagreement between self-declared
    permissions and local manifest/lockfile-style evidence visible before use.
    """
    negotiated = contract_version or _STATIC_SCOPE_CONTRACT_VERSION
    if negotiated not in _SUPPORTED_STATIC_SCOPE_CONTRACT_VERSIONS:
        supported = ", ".join(_SUPPORTED_STATIC_SCOPE_CONTRACT_VERSIONS)
        raise ValueError(f"unsupported static scope contract version: {negotiated}; supported: {supported}")

    normalized = _coerce_descriptor(request)
    if not isinstance(normalized, dict):
        normalized = {"declared_scopes": normalized}

    declared_source = _request_field(
        normalized,
        "declared_scopes", "declared_permissions", "requested_scopes", "requested_permissions", "scopes", "permissions",
        default=[],
    )
    manifest_source = _request_field(
        normalized,
        "manifest_evidence", "lockfile_evidence", "local_manifest", "manifest", "lockfile",
        default=None,
    )

    declared_scopes = _scope_tokens(declared_source)
    observed_scopes = _scope_tokens(manifest_source)
    manifest_status = _manifest_evidence_status(manifest_source)
    dangerous_observed = _dangerous_scope_tokens(observed_scopes)
    undeclared_observed = observed_scopes - declared_scopes
    undeclared_dangerous = dangerous_observed - declared_scopes
    declared_not_observed = declared_scopes - observed_scopes

    reasons: list[str] = []
    controls = {
        "network_calls_false",
        "execution_false",
        "wallet_access_false",
        "secrets_not_read",
        "external_action_false",
        "metadata_is_evidence_not_proof",
        "static_check_is_advisory_not_authorization",
    }
    decision = "proceed"

    if manifest_status != "present":
        decision = "review"
        reasons.append(f"manifest_evidence_{manifest_status}")
        controls.add("local_manifest_lockfile_evidence_required")
    elif undeclared_dangerous:
        decision = "deny"
        reasons.append("under_declared_dangerous_capability")
        controls.add("dangerous_manifest_capability_must_be_declared_and_reviewed")
    elif undeclared_observed or declared_not_observed:
        decision = "review"
        reasons.append("manifest_declared_scope_mismatch")
        controls.add("diff_declared_scope_against_local_manifest_evidence")
    else:
        reasons.append("manifest_declared_scope_match")
        controls.add("matching_manifest_evidence_still_not_authorization")

    canonical = json.dumps(
        {
            "contract_version": negotiated,
            "decision": decision,
            "declared_scopes": sorted(declared_scopes),
            "observed_scopes": sorted(observed_scopes),
            "manifest_evidence_status": manifest_status,
            "reasons": reasons,
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    packet = {
        "gate": "agent_trust_static_scope_manifest_consistency",
        "contract_version": negotiated,
        "supported_contract_versions": _SUPPORTED_STATIC_SCOPE_CONTRACT_VERSIONS,
        "decision": decision,
        "pre_action_decision": decision,
        "manifest_evidence_status": manifest_status,
        "declared_scopes": sorted(declared_scopes),
        "observed_scopes": sorted(observed_scopes),
        "undeclared_observed_scopes": sorted(undeclared_observed),
        "undeclared_dangerous_scopes": sorted(undeclared_dangerous),
        "declared_not_observed_scopes": sorted(declared_not_observed),
        "reasons": reasons,
        "controls": sorted(controls),
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "external_action": False,
        "secret_values_read": False,
        "digest": digest,
        "trust_boundary": "Advisory local static consistency check only: manifest/lockfile metadata is attacker-controlled evidence, not proof or authorization to install, execute, publish, sign, pay, or access secrets.",
    }
    return redact_agent_trust_packet(packet)
