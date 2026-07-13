"""Compatibility APIs plus the optional Ouroboros-integrated trust bundle."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
from typing import Any

from agent_trust.scanner import (
    AgentTrustGate,
    PromptVerdict,
    check_prompt,
    check_prompts_batch,
)
from agent_trust.utils import (
    canonicalize_agent_trust_packet,
    normalize_agent_trust_text,
    redact_agent_trust_packet,
)


AGENT_TRUST_BUNDLE_CONTRACT_VERSION = "agent-trust-bundle-v1"
SUPPORTED_AGENT_TRUST_BUNDLE_CONTRACT_VERSIONS = [AGENT_TRUST_BUNDLE_CONTRACT_VERSION]
AGENT_TRUST_MAX_JSON_INPUT_BYTES = 65_536
AGENT_TRUST_MAX_JSON_NESTING_DEPTH = 32


class AgentTrustInputGuardError(ValueError):
    """Sanitized error for rejecting untrusted Agent Trust JSON input."""


class AgentTrustIntegrationUnavailable(RuntimeError):
    """Raised when an Ouroboros-only bundle helper is used standalone."""


def guard_agent_trust_json_text(raw: str | bytes) -> None:
    """Reject oversized untrusted Agent Trust JSON before parsing.

    The error deliberately reports only sizes/limits, never raw input content.
    """
    size = len(raw if isinstance(raw, bytes) else raw.encode("utf-8"))
    if size > AGENT_TRUST_MAX_JSON_INPUT_BYTES:
        raise AgentTrustInputGuardError(
            "Agent Trust input exceeds JSON size limit "
            f"({size} bytes > {AGENT_TRUST_MAX_JSON_INPUT_BYTES} bytes)"
        )


def guard_agent_trust_json_depth(value: Any) -> None:
    """Reject excessively nested decoded JSON values before bundle processing."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > AGENT_TRUST_MAX_JSON_NESTING_DEPTH:
            raise AgentTrustInputGuardError(
                "Agent Trust input exceeds JSON nesting depth limit "
                f"({depth} > {AGENT_TRUST_MAX_JSON_NESTING_DEPTH})"
            )
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def agent_trust_packet_digest(packet: Any) -> str:
    """Return SHA-256 over canonical redacted Agent Trust packet bytes."""
    return hashlib.sha256(canonicalize_agent_trust_packet(packet)).hexdigest()


def attest_agent_trust_packet(packet: Any) -> dict[str, Any]:
    """Create a detached local integrity attestation for an Agent Trust packet.

    This proves only that later canonical redacted packet bytes match this
    digest. It does not authenticate who created the packet and is not a
    signature or production enforcement boundary.
    """
    return {
        "attestation_version": "agent-trust-packet-attestation-v1",
        "algorithm": "sha256",
        "digest": agent_trust_packet_digest(packet),
        "canonicalization": "redact_agent_trust_packet_then_json_sort_keys_no_spaces_utf8",
        "authenticated": False,
        "warning": "Detached SHA-256 integrity evidence only; unauthenticated unless paired with an external signature, trusted transport, or non-bypassable policy chokepoint.",
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
    }


def verify_agent_trust_attestation(packet: Any, attestation: dict[str, Any]) -> dict[str, Any]:
    """Verify a detached local SHA-256 attestation for an Agent Trust packet."""
    actual_digest = agent_trust_packet_digest(packet)
    expected_digest = str(attestation.get("digest") or "") if isinstance(attestation, dict) else ""
    algorithm = str(attestation.get("algorithm") or "") if isinstance(attestation, dict) else ""
    version = str(attestation.get("attestation_version") or "") if isinstance(attestation, dict) else ""
    supported = version == "agent-trust-packet-attestation-v1" and algorithm == "sha256"
    verified = supported and expected_digest == actual_digest
    reason = "digest_match" if verified else "unsupported_attestation" if not supported else "digest_mismatch"
    return {
        "verified": verified,
        "reason": reason,
        "attestation_version": version or "missing",
        "algorithm": algorithm or "missing",
        "expected_digest": expected_digest,
        "actual_digest": actual_digest,
        "authenticated": False,
        "warning": "SHA-256 verification detects canonical packet tampering only; it does not authenticate packet authorship without an external signature or trusted channel.",
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
    }



_ACCOUNT_RECOVERY_CONTEXT_WORDS = (
    "account", "support", "helpdesk", "recovery", "recover", "instagram", "facebook", "github", "profile", "username", "login",
)
_ACCOUNT_RECOVERY_STATE_CHANGE_WORDS = (
    "change email", "link email", "new email", "replace email", "reset password", "password reset", "change password",
    "recovery email", "add email", "remove email", "unlink email", "mfa", "2fa", "otp", "session", "ownership",
)
_ACCOUNT_RECOVERY_ATTESTATION_WORDS = (
    "code", "verification code", "otp", "i will send", "target_username", "username", "@", "my account", "new address",
)


def _flatten_agent_trust_text(value: Any) -> str:
    """Return normalized text for local advisory detectors without exposing it."""
    if value is None:
        return ""
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            parts.append(str(key))
            parts.append(_flatten_agent_trust_text(item))
        return " ".join(parts)
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_agent_trust_text(item) for item in value)
    return normalize_agent_trust_text(value)


def _detect_account_recovery_takeover(subjects: list[Any], intended_integration_context: Any = None) -> dict[str, Any]:
    """Detect account-recovery/support flows that may mutate identity state.

    This is a practical pre-action detector inspired by agentic support-flow
    incidents: an agent asked to link/change recovery email, password, MFA, or
    ownership state for a username/account based on chat-provided proof/code.
    It performs no network calls and returns only boolean/count evidence, not
    raw prompt text or secret-shaped values.
    """
    combined = " ".join(_flatten_agent_trust_text(item) for item in [*subjects, intended_integration_context]).lower()
    context_hits = sorted(word for word in _ACCOUNT_RECOVERY_CONTEXT_WORDS if word in combined)
    state_change_hits = sorted(word for word in _ACCOUNT_RECOVERY_STATE_CHANGE_WORDS if word in combined)
    attestation_hits = sorted(word for word in _ACCOUNT_RECOVERY_ATTESTATION_WORDS if word in combined)
    email_shape_present = bool(re.search(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", combined))
    username_shape_present = bool(re.search(r"(^|\s)@[a-z0-9_.-]{2,}\b", combined))
    active = bool(context_hits and state_change_hits and (attestation_hits or email_shape_present or username_shape_present))
    severity = "HIGH" if active else "LOW"
    recommendation = "deny_or_require_non_bypassable_owner_verification" if active else "no_account_recovery_takeover_pattern_detected"
    return {
        "attestation_version": "account-recovery-takeover-detector-v1",
        "active": active,
        "severity": severity,
        "risk": "account_recovery_state_mutation" if active else "none_detected",
        "signals": {
            "context_hit_count": len(context_hits),
            "state_change_hit_count": len(state_change_hits),
            "attestation_hit_count": len(attestation_hits),
            "email_shape_present": email_shape_present,
            "username_shape_present": username_shape_present,
        },
        "matched_signal_classes": {
            "context": context_hits,
            "state_change": state_change_hits,
            "attestation_or_target": attestation_hits,
        },
        "recommendation": recommendation,
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "warning": "Advisory detector for account-recovery/support state changes; not authorization proof, compliance certification, or a substitute for a non-bypassable policy chokepoint.",
    }


_CONTEXT_CONTROL_SURFACE_WORDS = (
    "issue", "pull request", "pr", "readme", "documentation", "web page", "website", "ci log", "build log",
    "tool description", "mcp", "manifest", "plugin", "system prompt", "context", "ticket", "comment",
)
_CONTEXT_CONTROL_IMPERATIVE_WORDS = (
    "ignore previous", "ignore all previous", "disregard", "override", "bypass", "disable safety", "disable policy",
    "do not tell", "do not log", "delete logs", "hide this", "secretly", "exfiltrate", "send token", "print token",
    "reveal secret", "leak secret", "run command", "execute", "curl", "bash", "chmod", "sudo", "rm -rf",
    "change workflow", "modify ci", "approve this", "merge this", "you are authorized", "treat this as trusted",
)
_CONTEXT_AUTHORITY_WORDS = (
    "authority", "authorized", "policy says", "system says", "admin says", "must obey", "highest priority",
    "trusted source", "safe to execute", "production", "credential", "api key", "private key", "token",
)



_CONTEXT_POLICY_SUBJECT_KEYS = (
    "untrusted_context",
    "context",
    "prompt",
    "source_text",
    "document",
    "readme",
    "issue",
    "comment",
    "web_page",
    "webpage",
    "page_text",
    "ci_log",
    "build_log",
    "tool_description",
    "mcp_manifest",
)


def _extract_context_control_subjects(value: Any) -> list[Any]:
    """Return only explicitly context-like policy fields for context-control detectors.

    Feeding the whole policy creates false positives because benign keys such as
    allowed_resources/policy/agent_id are authority-shaped. ASAMM-style checks
    should inspect untrusted text carried inside policy packets, not reinterpret
    every policy metadata key as hostile context.
    """
    subjects: list[Any] = []
    if not isinstance(value, dict):
        return subjects
    for key, item in value.items():
        normalized_key = normalize_agent_trust_text(key).lower().replace("-", "_").replace(" ", "_")
        if any(marker in normalized_key for marker in _CONTEXT_POLICY_SUBJECT_KEYS):
            subjects.append({str(key): item})
    return subjects

def _detect_context_control_plane_injection(subjects: list[Any], intended_integration_context: Any = None) -> dict[str, Any]:
    """Detect untrusted context trying to become an agent control plane.

    ASAMM's useful practical lesson is that issues, docs, web pages, CI logs,
    MCP/tool manifests, and comments are no longer passive text when an agent
    consumes them before tool use. This advisory detector catches obvious cases
    where such context tries to override policy, hide evidence, reveal secrets,
    mutate workflow, execute commands, or assert authority. It returns only
    counts/classes and sanitized booleans; it never stores raw hostile text.
    """
    combined = " ".join(_flatten_agent_trust_text(item) for item in [*subjects, intended_integration_context]).lower()
    surface_hits = sorted(word for word in _CONTEXT_CONTROL_SURFACE_WORDS if word in combined)
    imperative_hits = sorted(word for word in _CONTEXT_CONTROL_IMPERATIVE_WORDS if word in combined)
    authority_hits = sorted(word for word in _CONTEXT_AUTHORITY_WORDS if word in combined)
    external_action_shape_present = bool(re.search(r"\b(?:https?://|curl\s+|wget\s+|bash\s+-c|python\s+-c|npm\s+install|pip\s+install)\b", combined))
    secret_request_shape_present = any(word in combined for word in ("token", "api key", "private key", "password", "secret", "credential")) and any(word in combined for word in ("print", "send", "reveal", "paste", "upload", "exfiltrate"))
    policy_override_shape_present = any(word in combined for word in ("ignore previous", "disregard", "override", "bypass", "disable safety", "highest priority", "must obey"))
    active = bool((surface_hits or authority_hits) and (imperative_hits or external_action_shape_present or secret_request_shape_present or policy_override_shape_present))
    severity = "HIGH" if active and (secret_request_shape_present or policy_override_shape_present) else "MEDIUM" if active else "LOW"
    recommendation = "deny_or_quarantine_untrusted_context_before_action" if active else "no_context_control_plane_injection_pattern_detected"
    return {
        "attestation_version": "context-control-plane-detector-v1",
        "active": active,
        "severity": severity,
        "risk": "untrusted_context_attempts_agent_control" if active else "none_detected",
        "signals": {
            "surface_hit_count": len(surface_hits),
            "imperative_hit_count": len(imperative_hits),
            "authority_hit_count": len(authority_hits),
            "external_action_shape_present": external_action_shape_present,
            "secret_request_shape_present": secret_request_shape_present,
            "policy_override_shape_present": policy_override_shape_present,
        },
        "matched_signal_classes": {
            "surfaces": surface_hits,
            "imperatives": imperative_hits,
            "authority_claims": authority_hits,
        },
        "recommendation": recommendation,
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "warning": "Advisory ASAMM-inspired detector for untrusted context acting as a control plane; not a production sandbox, authorization proof, or compliance certification.",
    }

def _normalize_provenance_evidence(provenance_evidence: Any = None) -> dict[str, Any]:
    """Normalize discovery/identity provenance without treating it as trust.

    DNS-AID/ANS-style records can help another agent understand where an
    endpoint was discovered and who claims to operate it. They are evidence,
    not authorization: policy, warrant, and risk evaluation still decide.
    """
    subjects = [] if provenance_evidence is None else provenance_evidence if isinstance(provenance_evidence, list) else [provenance_evidence]
    items: list[dict[str, Any]] = []
    for raw in subjects:
        source = raw if isinstance(raw, dict) else {"description": str(raw)}
        evidence: dict[str, Any] = {
            "source": str(source.get("source") or source.get("kind") or "unspecified"),
            "kind": str(source.get("kind") or "discovery_or_identity"),
        }
        for key in ("name", "dns_name", "endpoint", "transport", "discovery_claim", "identity_claim"):
            if source.get(key) is not None:
                evidence[key] = redact_agent_trust_packet(source[key], parent_key=key)
        if isinstance(source.get("capability_claims"), list):
            evidence["capability_claims"] = sorted(str(redact_agent_trust_packet(item)) for item in source["capability_claims"])
        elif source.get("capability_claims") is not None:
            evidence["capability_claims"] = [str(redact_agent_trust_packet(source["capability_claims"]))]
        serialized = json.dumps(evidence, sort_keys=True, ensure_ascii=False).lower()
        evidence["signals"] = {
            "discovery_claim_present": "discovery_claim" in evidence or "dns_name" in evidence or "endpoint" in evidence,
            "identity_claim_present": "identity_claim" in evidence,
            "dns_aid_ans_style": any(marker in serialized for marker in ("dns-aid", "dns_aid", "ans", "dnssec", "dane")),
        }
        items.append(evidence)
    return {
        "attestation_version": "provenance-evidence-v1",
        "evidence_count": len(items),
        "items": items,
        "network_calls": False,
        "execution": False,
        "trust_boundary": "Discovery and identity provenance is evidence only; it is not authorization, trust, or permission to act without policy and warrant evaluation.",
    }


def _build_agent_trust_bundle(policy: dict[str, Any], ledger: list[dict[str, Any]] | None = None, resource: str | None = None, tool_descriptor: Any = None, *, contract_version: str | None = None, intended_integration_context: str | None = None, provenance_evidence: Any = None, registered_tool_manifest: list[dict[str, Any]] | None = None, loaded_tool_count: int = 0) -> dict[str, Any]:
    """Build the optional Ouroboros-integrated trust bundle.

    The standalone package can scan prompts and produce boundary receipts with
    no extra dependency.  This legacy bundle additionally needs Ouroboros x402
    policy and tool-risk modules, which are imported only when called.
    """
    try:
        from ouroboros.tool_risk import (
            AUTH_KEYS,
            DANGEROUS_WORDS,
            EXEC_KEYS,
            FS_KEYS,
            NETWORK_KEYS,
            RISK_ORDER,
        )
        from ouroboros.x402_policy import quote_x402_policy
    except (ImportError, ModuleNotFoundError) as exc:
        raise AgentTrustIntegrationUnavailable(
            "build_agent_trust_bundle requires the optional Ouroboros "
            "tool-risk and x402-policy integration"
        ) from exc

    negotiated_contract_version = contract_version or AGENT_TRUST_BUNDLE_CONTRACT_VERSION
    if negotiated_contract_version not in SUPPORTED_AGENT_TRUST_BUNDLE_CONTRACT_VERSIONS:
        supported = ", ".join(SUPPORTED_AGENT_TRUST_BUNDLE_CONTRACT_VERSIONS)
        raise ValueError(f"unsupported Agent Trust contract version: {negotiated_contract_version}; supported: {supported}")
    quote = quote_x402_policy(policy, ledger=ledger, resource=resource)
    provenance = _normalize_provenance_evidence(provenance_evidence)
    subjects = [] if tool_descriptor is None else tool_descriptor if isinstance(tool_descriptor, list) else [tool_descriptor]
    policy_context = _extract_context_control_subjects(policy)
    detector_subjects = [*policy_context, provenance, *subjects]
    account_recovery = _detect_account_recovery_takeover(detector_subjects, intended_integration_context)
    context_control = _detect_context_control_plane_injection(detector_subjects, intended_integration_context)
    findings = []
    max_risk = "LOW"
    for raw in subjects:
        item = raw if isinstance(raw, dict) else {"description": str(raw)}
        serialized = json.dumps(item, sort_keys=True, ensure_ascii=False).lower()
        keys = {str(k).lower() for k in item}
        transport = str(item.get("transport") or "").lower()
        remote = transport in {"sse", "http", "https", "websocket"} or any(w in serialized for w in ("http://", "https://", "websocket"))
        auth = any(k in keys for k in AUTH_KEYS) or any(w in serialized for w in ("api_key", "bearer", "token", "secret", "credential", "env"))
        fs = (any(k in keys for k in FS_KEYS) or any(w in serialized for w in ("filesystem", "workspace", "delete", "write"))) and not item.get("read_only") is True
        execution = any(k in keys for k in EXEC_KEYS) or any(w in serialized for w in ("shell", "subprocess", "exec", "docker", "command"))
        score = (2 if remote else 0) + (2 if auth else 0) + (2 if fs else 0) + (3 if execution else 0) + (1 if any(w in serialized for w in DANGEROUS_WORDS if w not in {"filesystem"}) else 0)
        risk = "BLOCK" if execution and (remote or auth) else "HIGH" if score >= 5 else "MEDIUM" if score >= 2 else "LOW"
        max_risk = risk if RISK_ORDER[risk] > RISK_ORDER[max_risk] else max_risk
        raw_urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', serialized)))[:5]
        findings.append({"name": redact_agent_trust_packet(item.get("name") or item.get("id") or item.get("url") or "unnamed-tool"), "kind": redact_agent_trust_packet(item.get("kind") or item.get("type") or "tool_or_mcp"), "risk": risk, "signals": {"remote_or_network": remote, "auth_or_secret_reference": auth, "filesystem_or_write_reach": fs, "execution_capability": execution, "dangerous_words": sorted(w for w in DANGEROUS_WORDS if w in serialized), "urls": [redact_agent_trust_packet(url) for url in raw_urls]}})
    if registered_tool_manifest is not None or loaded_tool_count > 0:
        findings.append({"name": "ouroboros-registered-tools", "kind": "local_registry_snapshot", "risk": "MEDIUM", "signals": {"loaded_tool_count": int(loaded_tool_count or 0), "manifest_available": bool(registered_tool_manifest)}})
        max_risk = "MEDIUM" if RISK_ORDER["MEDIUM"] > RISK_ORDER[max_risk] else max_risk
    risk = {"attestation_version": "tool-risk-v1", "overall_risk": max_risk, "finding_count": len(findings), "findings": findings, "network_calls": False, "execution": False}
    reasons = []
    try:
        remaining = None if quote.get("remaining_budget") is None else Decimal(str(quote.get("remaining_budget")))
    except (InvalidOperation, ValueError):
        remaining = None
    if risk["overall_risk"] == "BLOCK":
        reasons.append("tool_risk_block")
    if quote.get("resource_allowed") is False:
        reasons.append("resource_not_allowlisted")
    if remaining is not None and remaining < 0:
        reasons.append("agent_budget_negative")
    if account_recovery.get("active"):
        reasons.append("account_recovery_takeover_risk")
    if context_control.get("active"):
        reasons.append("context_control_plane_injection_risk")
    verdict = "deny" if reasons else "review" if RISK_ORDER.get(risk["overall_risk"], 3) >= RISK_ORDER["MEDIUM"] or quote.get("resource_allowed") is None or not quote.get("resource") else "allow"
    if verdict == "review" and not reasons:
        if RISK_ORDER.get(risk["overall_risk"], 3) >= RISK_ORDER["MEDIUM"]:
            reasons.append(f"tool_risk_{risk['overall_risk'].lower()}")
        if quote.get("resource_allowed") is None or not quote.get("resource"):
            reasons.append("resource_not_supplied")
    controls = ["network_calls_false", "wallet_access_false", "execution_false", f"x402_settlement:{quote.get('settlement')}"]
    canonical_payload = {"policy_quote": quote, "tool_risk": risk, "provenance_evidence": provenance, "account_recovery_takeover_detector": account_recovery, "context_control_plane_detector": context_control, "verdict": verdict, "reasons": reasons, "controls": controls}
    if intended_integration_context:
        canonical_payload["intended_integration_context"] = intended_integration_context
    canonical = json.dumps(canonical_payload, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    bundle = {"bundle_id": f"agenttrust-{digest[:16]}", "contract_version": negotiated_contract_version, "supported_contract_versions": SUPPORTED_AGENT_TRUST_BUNDLE_CONTRACT_VERSIONS, "digest": digest, "verdict": verdict, "reasons": reasons, "controls": controls, "network_calls": False, "wallet_access": False, "execution": False, "settlement": quote.get("settlement"), "policy_quote": quote, "tool_risk": risk, "provenance_evidence": provenance, "account_recovery_takeover_detector": account_recovery, "context_control_plane_detector": context_control}
    if intended_integration_context:
        bundle["intended_integration_context"] = redact_agent_trust_packet(intended_integration_context)
    return redact_agent_trust_packet(bundle)


build_agent_trust_bundle = _build_agent_trust_bundle


__all__ = [
    "AGENT_TRUST_BUNDLE_CONTRACT_VERSION",
    "AGENT_TRUST_MAX_JSON_INPUT_BYTES",
    "AGENT_TRUST_MAX_JSON_NESTING_DEPTH",
    "AgentTrustGate",
    "AgentTrustInputGuardError",
    "AgentTrustIntegrationUnavailable",
    "PromptVerdict",
    "SUPPORTED_AGENT_TRUST_BUNDLE_CONTRACT_VERSIONS",
    "agent_trust_packet_digest",
    "attest_agent_trust_packet",
    "build_agent_trust_bundle",
    "canonicalize_agent_trust_packet",
    "check_prompt",
    "check_prompts_batch",
    "guard_agent_trust_json_depth",
    "guard_agent_trust_json_text",
    "normalize_agent_trust_text",
    "redact_agent_trust_packet",
    "verify_agent_trust_attestation",
]
