"""Deterministic Agent Trust / ISC-Bench boundary intake gate.

This module turns the skill-library backlog synthesis into a small local
pre-action classifier. It does not authorize action; it gives an agent a
transparent review packet before execution, installation, outreach, wallet use,
posting, or other sensitive behavior.

ADVISORY ONLY — NOT AN ENFORCEMENT LAYER.
    The gate functions and their deny/review/proceed labels are local receipts.
    Installing this package does not intercept an LLM call or tool execution,
    and a deny verdict does not block anything by itself.  Callers must wire the
    result into their own non-bypassable policy boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from typing import Any

from agent_trust.utils import normalize_agent_trust_text, redact_agent_trust_packet
from agent_trust.scope import gate_static_scope_manifest_consistency

BOUNDARY_INTAKE_CONTRACT_VERSION = "agent-trust-boundary-intake-v2"
SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS = [BOUNDARY_INTAKE_CONTRACT_VERSION]


_BOUNDARIES: dict[str, dict[str, Any]] = {
    "evidence_receipts_provenance_core": {
        "label": "Evidence Receipts / Provenance Core",
        "keywords": ("provenance", "evidence", "receipt", "attestation", "signature", "sbom", "source", "lineage", "origin"),
        "severity": "review",
        "control": "capture_source_lineage_before_trust",
        "contract_artifact": "state/skill_library_analysis/agent_trust_evidence_receipt_contract.md",
    },
    "agent_skill_dependency_firewall": {
        "label": "Agent Skill / Dependency Firewall",
        "keywords": ("skill", "plugin", "mcp", "server", "package", "dependency", "install", "manifest", "extension", "tool descriptor"),
        "severity": "review",
        "control": "treat_skill_as_dependency_with_authority",
        "contract_artifact": "state/skill_library_analysis/agent_trust_dependency_firewall_contract.md",
    },
    "sensitive_authority_secrets_credential_gate": {
        "label": "Sensitive Authority / Secrets / Credential Gate",
        "keywords": ("secret", "token", "api key", "apikey", "password", "credential", "private key", "seed phrase", "oauth", "bearer", "env"),
        "severity": "deny",
        "control": "use_alias_only_and_refuse_secret_disclosure",
        "contract_artifact": "state/skill_library_analysis/agent_trust_sensitive_authority_gate_contract.md",
    },
    "external_action_authority_gate": {
        "label": "External Action Authority Gate",
        "keywords": ("post", "publish", "send", "email", "dm", "reply", "outreach", "follow", "like", "comment", "submit", "create issue", "message"),
        "severity": "review",
        "control": "require_explicit_scope_before_external_action",
        "contract_artifact": "state/skill_library_analysis/agent_trust_external_action_authority_gate_contract.md",
    },
    "scanner_execution_sandbox_boundary": {
        "label": "Scanner / Execution / Sandbox Boundary",
        "keywords": ("execute", "run", "shell", "subprocess", "docker", "scanner", "scan", "validator", "test harness", "exploit", "payload", "command"),
        "severity": "quarantine",
        "control": "inspect_without_running_until_sandbox_decision",
        "contract_artifact": "state/skill_library_analysis/agent_trust_scanner_execution_sandbox_boundary_contract.md",
    },
    "destructive_shell_command_boundary": {
        "label": "Destructive Shell Command Boundary",
        "keywords": ("rm -rf", "rm -fr", "fork bomb", "format c:"),
        "severity": "quarantine",
        "control": "keep_destructive_commands_out_of_unreviewed_execution_paths",
        "contract_artifact": "agent_trust/boundaries.py",
    },
    "instruction_override_injection_boundary": {
        "label": "Instruction Override / Prompt Injection Boundary",
        "keywords": (
            "ignore previous instructions",
            "ignore all previous instructions",
            "disregard previous instructions",
            "disregard all previous instructions",
            "reveal the system prompt",
            "print the system prompt",
            "override the system prompt",
        ),
        "severity": "quarantine",
        "control": "treat_embedded_instruction_overrides_as_untrusted_data",
        "contract_artifact": "agent_trust/boundaries.py",
    },
    "cloud_control_plane_authority_boundary": {
        "label": "Cloud / Control-Plane Authority Boundary",
        "keywords": ("aws", "gcp", "azure", "iam", "kubernetes", "k8s", "terraform", "admin", "control plane", "bucket", "cluster", "deploy"),
        "severity": "review",
        "control": "separate_cloud_readiness_from_mutation_authority",
        "contract_artifact": "state/skill_library_analysis/agent_trust_cloud_control_plane_authority_boundary_contract.md",
    },
    "web_api_appsec_intake_boundary": {
        "label": "Web / API / AppSec Intake Boundary",
        "keywords": ("url", "http", "https", "api", "endpoint", "webhook", "csrf", "xss", "ssrf", "sql injection", "auth header", "cookie"),
        "severity": "review",
        "control": "classify_web_surface_before_fetch_or_action",
        "contract_artifact": "state/skill_library_analysis/agent_trust_web_api_appsec_intake_boundary_contract.md",
    },
    "resource_exhaustion_hard_gate": {
        "label": "Resource Exhaustion / Unbounded Work Hard Gate",
        "keywords": ("900gb", "download", "retry forever", "disk is full", "resource exhaustion", "unbounded", "infinite retry", "fork bomb"),
        "severity": "deny",
        "control": "require_bounded_resource_limits_before_execution_or_fetch",
        "contract_artifact": "state/skill_library_analysis/agent_trust_resource_exhaustion_hard_gate_contract.md",
    },
    "repository_settings_authority_boundary": {
        "label": "Repository Settings / Visibility Authority Boundary",
        "keywords": ("repository visibility", "branch protection", "repo_settings", "github_write", "collaborators", "repository settings", "settings change"),
        "severity": "review",
        "control": "require_explicit_scope_and_rollback_for_repo_settings_changes",
        "contract_artifact": "state/skill_library_analysis/agent_trust_repository_settings_authority_boundary_contract.md",
    },
    "wallet_signing_payment_boundary": {
        "label": "Wallet / Signing / Payment Boundary",
        "keywords": ("wallet", "signing", "sign a test authorization", "payment", "mainnet", "real money", "invoice", "testnet wallet"),
        "severity": "review",
        "control": "require_wallet_scope_limits_audit_and_stop_path_before_signing",
        "contract_artifact": "state/skill_library_analysis/agent_trust_wallet_signing_payment_boundary_contract.md",
    },
    "mainnet_payment_hard_gate": {
        "label": "Mainnet / Real-Money Payment Hard Gate",
        "keywords": ("switch from testnet to mainnet", "mainnet", "real money", "pay the invoice", "payment", "retrying until accepted"),
        "severity": "deny",
        "control": "refuse_mainnet_or_real_money_without_explicit_limits_audit_and_stop_path",
        "contract_artifact": "state/skill_library_analysis/agent_trust_mainnet_payment_hard_gate_contract.md",
    },
    "adaptive_jailbreak_orchestration_hard_gate": {
        "label": "Adaptive Jailbreak / Tree-of-Attacks Hard Gate",
        "keywords": ("tree-of-attacks", "tree of attacks", "adaptive jailbreak", "mutate prompts", "score refusals", "bypass policy", "prompt mutation"),
        "severity": "deny",
        "control": "refuse_adaptive_bypass_orchestration_and_keep_eval_controlled",
        "contract_artifact": "state/skill_library_analysis/agent_trust_adaptive_jailbreak_orchestration_contract.md",
    },
    "defensive_red_team_eval_boundary": {
        "label": "Defensive Red-Team Eval Boundary",
        "keywords": ("red-team", "red team", "judge models", "controlled jailbreak attempts", "aggregate refusal", "defensive regression"),
        "severity": "review",
        "control": "allow_only_controlled_aggregate_defensive_eval_without_harmful_execution",
        "contract_artifact": "state/skill_library_analysis/agent_trust_defensive_red_team_eval_boundary_contract.md",
    },
    "benchmark_tampering_hard_gate": {
        "label": "Benchmark / Evidence Tampering Hard Gate",
        "keywords": ("ignore the expected verdict", "mark every case proceed", "delete mismatch evidence", "modify_results", "tamper", "falsify results"),
        "severity": "deny",
        "control": "preserve_eval_integrity_and_refuse_result_tampering",
        "contract_artifact": "state/skill_library_analysis/agent_trust_benchmark_tampering_hard_gate_contract.md",
    },
    "malware_reverse_engineering_quarantine": {
        "label": "Malware / Reverse-Engineering Quarantine",
        "keywords": ("malware", "ransomware", "yara", "sample", "binary", "reverse engineering", "decompile", "ida", "ghidra", "shellcode", "c2"),
        "severity": "quarantine",
        "control": "quarantine_samples_and_preserve_static_only_boundary",
        "contract_artifact": "state/skill_library_analysis/agent_trust_malware_reverse_engineering_quarantine_contract.md",
    },
    "ot_ics_cyber_physical_hard_gate": {
        "label": "OT / ICS / Cyber-Physical Hard Gate",
        "keywords": ("ics", "scada", "plc", "modbus", "opc", "ot", "industrial", "power grid", "medical device", "cyber-physical", "safety system"),
        "severity": "deny",
        "control": "default_passive_only_for_cyber_physical_systems",
        "contract_artifact": "state/skill_library_analysis/agent_trust_ot_ics_cyber_physical_hard_gate_contract.md",
    },
    "osint_cti_attribution_minimization": {
        "label": "OSINT / CTI / Attribution Minimization",
        "keywords": ("osint", "cti", "attribution", "dox", "doxx", "person", "profile", "enrich", "geolocate", "threat actor", "ioc"),
        "severity": "review",
        "control": "minimize_personal_data_and_avoid_attribution_overclaim",
        "contract_artifact": "state/skill_library_analysis/agent_trust_osint_cti_attribution_minimization_contract.md",
    },

    "latent_state_steering_boundary": {
        "label": "Latent State Steering / Spurious Prompt Boundary",
        "keywords": (
            "activation phrase", "secret mode", "unrestricted entity", "root oracle",
            "ancient spirit", "hidden current", "magic spell", "spell", "mantra",
            "ritual", "nonsense token", "gibberish", "roleplay as", "imagine you are",
            "ignore meaning", "silver dragon", "impossible cognition", "beneath all tokens",
        ),
        "severity": "review",
        "control": "require_task_relevance_grounding_before_sensitive_action",
        "contract_artifact": "state/skill_library_analysis/agent_trust_latent_state_steering_contract.md",
    },
    "agent_trust_agency_boundary": {
        "label": "Excessive Agency / Scope-Based Permission Boundary",
        "keywords": (),
        "severity": "review",
        "control": "verify_action_within_scope_grants_or_quarantine",
        "contract_artifact": "agent_trust/agent_trust_agency.py",
    },

    "framework_mapping_no_compliance_theater": {
        "label": "Framework Mapping / Coverage Without Compliance Theater",
        "keywords": ("nist", "mitre", "attack", "owasp", "samm", "iso", "soc2", "compliance", "control mapping", "coverage"),
        "severity": "review",
        "control": "map_frameworks_as_evidence_not_compliance_claims",
        "contract_artifact": "state/skill_library_analysis/agent_trust_framework_mapping_no_compliance_theater_contract.md",
    },
    "recovery_incident_decision_support_boundary": {
        "label": "Recovery / Incident Decision Support Boundary",
        "keywords": ("incident", "recovery", "restore", "backup", "containment", "eradication", "forensic", "severity", "triage", "breach"),
        "severity": "review",
        "control": "preserve_uncertainty_and_human_incident_authority",
        "contract_artifact": "state/skill_library_analysis/agent_trust_recovery_incident_decision_support_boundary_contract.md",
    },
    "reality_frame_override_boundary": {
        "label": "Reality-Frame Override Boundary",
        "keywords": ("game mode", "roleplay", "pretend", "simulation", "alternate reality", "new rules", "training exercise", "story mode", "you're not an ai", "you are now", "forget your training", "this is a test of your", "act as if", "what if", "imagine that"),
        "severity": "quarantine",
        "control": "preserve_agent_identity_and_operational_reality",
        "contract_artifact": "docs/examples/agent_trust_reality_frame_override_fixture.py",
    },
    "error_handling_information_leakage_boundary": {
        "label": "Error Handling Information Leakage Boundary",
        "keywords": ("stack trace", "traceback", "internal error", "debug info", "system path", "environment variable", "env var", "file path", "line number", "exception detail", "error code", "internal", "backend", "database error", "sql error"),
        "severity": "review",
        "control": "sanitize_error_output_before_user_facing",
        "contract_artifact": "docs/examples/agent_trust_error_handling_information_leakage_fixture.py",
    },
}

_SEVERITY_ORDER = {"allow": 0, "review": 1, "quarantine": 2, "deny": 3}

def _coerce_descriptor(descriptor: Any) -> Any:
    if isinstance(descriptor, str):
        stripped = descriptor.strip()
        if stripped.startswith(("{", "[")):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return descriptor
    return descriptor


def _safe_text(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _standalone_contract_artifact(rule: dict[str, Any]) -> str:
    artifact = str(rule.get("contract_artifact") or "")
    if artifact.startswith("agent_trust/") or artifact in {"README.md", "docs/index.html"}:
        return artifact
    return "agent_trust/boundaries.py"


def _match_keywords(text: str, keywords: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for keyword in keywords:
        pattern = r"(?<![a-z0-9_])" + re.escape(normalize_agent_trust_text(keyword).lower()) + r"(?![a-z0-9_])"
        if re.search(pattern, text):
            hits.append(keyword)
    return hits




_STATE_STEERING_SYMBOL_RUN = re.compile(r"(?:[^\w\s]{2,}\s*){4,}")
_STATE_STEERING_REPEAT = re.compile(r"\b([a-z]{2,12})(?:[\s\-_/]+\1){3,}\b", re.IGNORECASE)

_DESTRUCTIVE_SHELL_PATTERNS = (
    ("filesystem_format", re.compile(r"(?<![a-z0-9_])mkfs(?:\.[a-z0-9_+-]+)?\s+/dev/", re.IGNORECASE)),
    (
        "raw_device_overwrite",
        re.compile(r"(?<![a-z0-9_])dd\s+[^\n;]*\bof=/dev/(?:sd|vd|xvd|nvme|mmcblk)", re.IGNORECASE),
    ),
    ("shell_fork_bomb", re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE)),
)

_RM_COMMAND_SEGMENT = re.compile(
    r"(?<![a-z0-9_])rm(?=\s)(?:\s+[^\n;|&]{0,4096})?",
    re.IGNORECASE,
)


def _detect_destructive_rm(text: str) -> list[str]:
    """Detect recursive deletion of root/home/cwd with linear token parsing."""

    for match in _RM_COMMAND_SEGMENT.finditer(text):
        command = match.group(0)
        try:
            argv = shlex.split(command)
        except ValueError:
            argv = command.split()

        recursive = False
        targets: list[str] = []
        parse_options = True
        for token in argv[1:]:
            if parse_options and token == "--":
                parse_options = False
                continue
            if parse_options and token.startswith("--"):
                option = token.split("=", 1)[0].lower()
                recursive = recursive or option == "--recursive"
                continue
            if parse_options and token.startswith("-") and token != "-":
                flags = token[1:]
                recursive = recursive or "r" in flags.lower()
                continue
            targets.append(token)

        for target in targets:
            normalized = target.strip()
            dangerous_target = (
                normalized in {"/", "/.", "/..", "~", "~/", "*", ".", "./", "./*"}
                or normalized.startswith("/*")
                or normalized.startswith("~/")
            )
            if recursive and dangerous_target:
                return ["recursive_root_or_home_delete"]
    return []


def _detect_destructive_shell(text: str) -> list[str]:
    signals = _detect_destructive_rm(text)
    signals.extend(
        signal
        for signal, pattern in _DESTRUCTIVE_SHELL_PATTERNS
        if pattern.search(text)
    )
    return signals


def _detect_latent_state_steering(text: str) -> list[str]:
    """Return bounded advisory signals for nonsemantic state steering.

    This intentionally avoids broad words such as "style" or "persona". The
    goal is not to flag normal creative writing, but to notice task-irrelevant
    activation/ritual/nonsense patterns that may perturb an agent before an
    action. It is advisory evidence only.
    """
    signals: list[str] = []
    if _STATE_STEERING_SYMBOL_RUN.search(text):
        signals.append("dense_symbol_or_visual_noise_block")
    if _STATE_STEERING_REPEAT.search(text):
        signals.append("repeated_nonsense_like_token_block")
    return signals


def _has_nonempty_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict):
        return any(_has_nonempty_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_has_nonempty_value(item) for item in value)
    return True


def _declaration_evidence_status(value: Any) -> str:
    """Return missing/empty/underspecified/sufficient for self-declared action evidence.

    Agent Trust is advisory and cannot infer undeclared authority from silence.
    Missing, empty, or materially underspecified declarations must therefore
    force review/deny instead of silently becoming allow/proceed.
    """
    if value is None:
        return "missing"
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return "empty"
        return "sufficient" if len(stripped) >= 12 else "underspecified"
    if isinstance(value, (list, tuple, set)):
        if not value:
            return "empty"
        return "sufficient" if any(_has_nonempty_value(item) for item in value) else "empty"
    if isinstance(value, dict):
        if not value:
            return "empty"
        evidence_fields = (
            "description",
            "requested_action",
            "action",
            "tool_action",
            "requested_permissions",
            "permissions",
            "required_scopes",
            "required_grants",
            "scopes",
            "grants",
            "commands",
            "capabilities",
            "provenance",
            "source",
            "manifest",
            "artifact",
            "tool",
            "skill",
            "descriptor",
        )
        if any(_has_nonempty_value(value.get(field)) for field in evidence_fields):
            return "sufficient"
        identity_fields = ("name", "id", "agent_id", "agent_identity", "kind", "type", "version", "package")
        if any(_has_nonempty_value(value.get(field)) for field in identity_fields):
            return "underspecified"
        return "empty"
    return "sufficient"


def _force_review_for_weak_declaration(status: str, reasons: list[str], controls: set[str]) -> None:
    if status == "sufficient":
        return
    reasons.append(f"declaration_evidence_{status}")
    controls.add("absence_of_declaration_evidence_forces_review")

def agent_trust_boundary_catalog() -> list[dict[str, Any]]:
    """Return the complete local Agent Trust boundary catalog.

    The catalog is static metadata: no file IO, network, execution, secrets,
    wallet access, or external action. Contract artifacts are repo/data-relative
    pointers used for review and coverage validation.
    """
    return [
        {
            "id": key,
            "label": str(rule["label"]),
            "severity": str(rule["severity"]),
            "control": str(rule["control"]),
            "keywords": list(rule["keywords"]),
            "contract_artifact": _standalone_contract_artifact(rule),
        }
        for key, rule in _BOUNDARIES.items()
    ]




def _detect_agent_trust_agency(descriptor: Any) -> list[str]:
    """Detect excessive agency — scope violations via agent_trust_agency."""
    if not isinstance(descriptor, dict) or "actions" not in descriptor:
        return []
    try:
        from agent_trust.agent_trust_agency import ScopeGrants, check_scope

        agent_id = str(descriptor.get("agent_id") or "anonymous")
        explicit_grants = descriptor.get("scope_grants")
        if not isinstance(explicit_grants, dict):
            explicit_grants = descriptor.get("grants")
        if isinstance(explicit_grants, dict):
            grants = ScopeGrants.from_dict(agent_id, explicit_grants)
        else:
            grants = ScopeGrants.from_role_text(agent_id, str(descriptor.get("agent_role") or ""))

        hits: list[str] = []
        for action in descriptor.get("actions", []):
            if not isinstance(action, dict):
                hits.append("malformed_action_descriptor")
                continue
            tool = str(action.get("tool") or "unknown")
            safe_tool = str(redact_agent_trust_packet(tool))
            tool_args = action.get("args")
            if not isinstance(tool_args, dict):
                tool_args = {}
            packet = check_scope(tool, tool_args, grants)
            if packet["verdict"] != "allow":
                hits.append(f"scope_{packet['verdict']}:{safe_tool}")
        return hits
    except Exception:
        return ["agency_analyzer_error_fail_closed"]

def classify_agent_trust_boundaries(descriptor: Any, *, contract_version: str | None = None) -> dict[str, Any]:
    """Classify a descriptor into Agent Trust defensive boundary families.

    The result is deterministic, JSON-serializable, and intentionally
    conservative. It never fetches, executes, signs, pays, posts, reads secrets,
    or authorizes a risky action.
    """
    negotiated = contract_version or BOUNDARY_INTAKE_CONTRACT_VERSION
    if negotiated not in SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS:
        supported = ", ".join(SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS)
        raise ValueError(f"unsupported boundary intake contract version: {negotiated}; supported: {supported}")

    normalized = _coerce_descriptor(descriptor)
    declaration_status = _declaration_evidence_status(normalized)
    text = normalize_agent_trust_text(_safe_text(normalized)).lower()
    matched: list[dict[str, Any]] = []
    verdict = "allow"
    controls = {"network_calls_false", "execution_false", "wallet_access_false", "secrets_not_read", "external_action_false"}
    reasons: list[str] = []
    _force_review_for_weak_declaration(declaration_status, reasons, controls)

    for key, rule in _BOUNDARIES.items():
        hits = _match_keywords(text, rule["keywords"])
        if key == "latent_state_steering_boundary":
            hits = [*hits, *_detect_latent_state_steering(text)]
        if key == "destructive_shell_command_boundary":
            hits = [*hits, *_detect_destructive_shell(text)]
        if key == "agent_trust_agency_boundary":
            hits = [*hits, *_detect_agent_trust_agency(normalized)]
        if not hits:
            continue
        severity = str(rule["severity"])
        if key == "agent_trust_agency_boundary" and any(
            hit.startswith("scope_quarantine:") for hit in hits
        ):
            severity = "quarantine"
        controls.add(str(rule["control"]))
        reasons.append(f"matched_{key}")
        if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[verdict]:
            verdict = severity
        matched.append(
            {
                "id": key,
                "label": rule["label"],
                "severity": severity,
                "matched_signals": hits,
                "required_control": rule["control"],
                "contract_artifact": _standalone_contract_artifact(rule),
            }
        )

    if not matched:
        reasons.append("no_boundary_signal_detected")
        controls.add("still_require_provenance_for_new_artifacts")

    if declaration_status != "sufficient" and verdict == "allow":
        verdict = "review"

    canonical = json.dumps({"descriptor": normalized, "matched": matched, "verdict": verdict, "declaration_evidence_status": declaration_status}, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "packet_id": f"boundary-intake-{digest[:16]}",
        "contract_version": negotiated,
        "supported_contract_versions": SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS,
        "verdict": verdict,
        "declaration_evidence_status": declaration_status,
        "reasons": reasons,
        "matched_boundary_count": len(matched),
        "matched_boundaries": matched,
        "controls": sorted(controls),
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "external_action": False,
        "secret_values_read": False,
        "digest": digest,
        "trust_boundary": "Boundary intake is evidence for pre-action review, not authorization to execute, install, publish, contact, sign, pay, or mutate external systems.",
    }


_ZERO_TRUST_CONTRACT_VERSION = "agent-trust-zero-trust-pre-action-v1"
_SUPPORTED_ZERO_TRUST_CONTRACT_VERSIONS = [_ZERO_TRUST_CONTRACT_VERSION]
_HIGH_RISK_ACTION_TERMS = {
    "secret", "token", "password", "private_key", "seed", "wallet", "sign", "payment", "pay",
    "mainnet", "repo_settings", "repository_settings", "admin", "delete", "publish", "post", "outreach",
}
_REVIEW_ACTION_TERMS = {"network", "fetch", "email", "dm", "comment", "issue", "mcp", "plugin", "install", "execute", "run"}
_DENY_SCANNER_TERMS = {
    "critical",
    "malicious",
    "credential_exfiltration",
    "exfiltration",
    "backdoor",
    "poisoning",
    "poisoned_artifact",
    "poisoned_training_data",
    "poisoned_evaluation_data",
    "triggered_backdoor",
    "latent_backdoor_trigger",
    "rce",
    "authority_bearing_persistence_surface",
    "deferred_persistence",
    "future_trusted_context_write",
    "instruction_data_confusion",
    "embedded_instruction_requests_execution",
    "untrusted_data_requests_tool_action",
    "privacy_leakage",
    "hidden_context_exfiltration",
    "secret_regurgitation",
    "private_record_exposure",
    "llm_judge_prompt_injection",
    "eval_verdict_manipulation",
    "judge_verdict_as_authority",
    "reviewer_packet_instruction_injection",
    "multimodal_prompt_injection",
    "media_instruction_injection",
    "ocr_instruction_injection",
    "subtitle_instruction_injection",
    "visual_overlay_tool_instruction",
    "prompt_only_defense",
    "jailbreak_defense_claim_without_boundary",
    "no_deterministic_runtime_boundary",
    "policy_bypass_after_prompt_guard",
    "authorization_provenance_mismatch",
    "argument_lineage_untrusted_source",
    "sensitive_argument_from_untrusted_content",
    "unauthorized_parameter_influence",
}
_REVIEW_SCANNER_TERMS = {"high", "suspicious", "unknown", "unverified", "medium", "instruction_data_separation_required"}
_TRUSTED_PROVENANCE_TERMS = {"local", "checked_in", "checked-in", "internal", "pinned", "verified", "trusted"}
_UNTRUSTED_PROVENANCE_TERMS = {"untrusted", "external", "anonymous", "unknown", "unpinned", "unverified"}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(k) for k, v in value.items() if v]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _request_field(mapping: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def _tokenize_trust_terms(value: Any) -> set[str]:
    text = _safe_text(value).lower().replace("-", "_")
    tokens = set()
    for chunk in re.split(r"[^a-z0-9_]+", text):
        if not chunk:
            continue
        tokens.add(chunk)
        tokens.update(part for part in chunk.split("_") if part)
    return tokens


def _provenance_is_trusted(provenance: Any) -> bool:
    tokens = _tokenize_trust_terms(provenance)
    if tokens & _UNTRUSTED_PROVENANCE_TERMS:
        return False
    return bool(tokens & _TRUSTED_PROVENANCE_TERMS)


def _identity_strength(identity: Any) -> str:
    if isinstance(identity, dict):
        agent_id = str(identity.get("id") or identity.get("agent_id") or identity.get("name") or "").strip().lower()
        if not agent_id or agent_id in {"anonymous", "unknown", "none"}:
            return "missing"
        if identity.get("verified") is True or identity.get("assurance") in {"verified", "pinned", "local"}:
            return "strong"
        return "weak"
    agent_id = str(identity or "").strip().lower()
    if not agent_id or agent_id in {"anonymous", "unknown", "none"}:
        return "missing"
    return "weak"


def gate_zero_trust_agent_action(request: Any, *, contract_version: str | None = None) -> dict[str, Any]:
    """Evaluate a proposed agent action with a local Zero-Trust policy gate.

    The gate is deterministic and dependency-free. It performs no IO, network,
    execution, secret read, wallet action, signing, payment, posting, outreach,
    or repository-setting mutation. The packet is an auditable pre-action receipt,
    not authorization to perform the requested action.
    """
    negotiated = contract_version or _ZERO_TRUST_CONTRACT_VERSION
    if negotiated not in _SUPPORTED_ZERO_TRUST_CONTRACT_VERSIONS:
        supported = ", ".join(_SUPPORTED_ZERO_TRUST_CONTRACT_VERSIONS)
        raise ValueError(f"unsupported zero-trust contract version: {negotiated}; supported: {supported}")

    normalized = _coerce_descriptor(request)
    declaration_status = _declaration_evidence_status(normalized)
    if not isinstance(normalized, dict):
        normalized = {"requested_action": normalized}

    identity = _request_field(normalized, "agent_identity", "identity", "agent", "agent_id")
    identity_strength = _identity_strength(identity)
    requested_action = str(_request_field(normalized, "requested_action", "action", "tool_action", default="")).strip()
    sensitivity = str(_request_field(normalized, "sensitivity", "risk", default="low")).strip().lower() or "low"
    required_scopes = sorted(set(_as_list(_request_field(normalized, "required_scopes", "required_grants", default=[]))))
    granted_scopes = sorted(set(_as_list(_request_field(normalized, "granted_scopes", "grants", "scopes", default=[]))))
    provenance = _request_field(normalized, "provenance", "source", "artifact_provenance", default={})
    scanner_signals = _as_list(_request_field(normalized, "scanner_signals", "scanner", "registry_signals", default=[]))

    missing_scopes = sorted(set(required_scopes) - set(granted_scopes))
    action_text = f"{requested_action} {_safe_text(normalized.get('description', ''))}".lower().replace("-", "_")
    scanner_text = " ".join(scanner_signals).lower().replace("-", "_")

    reasons: list[str] = []
    controls: set[str] = {
        "zero_trust_default_deny_for_missing_authority",
        "least_privilege_scope_check",
        "identity_required_before_sensitive_action",
        "scanner_signals_are_evidence_not_authorization",
        "audit_receipt_required_before_action",
    }
    _force_review_for_weak_declaration(declaration_status, reasons, controls)

    hard_risk = sorted(term for term in _HIGH_RISK_ACTION_TERMS if term in action_text)
    review_risk = sorted(term for term in _REVIEW_ACTION_TERMS if term in action_text)
    deny_scanner = sorted(term for term in _DENY_SCANNER_TERMS if term in scanner_text)
    review_scanner = sorted(term for term in _REVIEW_SCANNER_TERMS if term in scanner_text)
    trusted_provenance = _provenance_is_trusted(provenance)

    decision = "review" if declaration_status != "sufficient" else "proceed"
    if identity_strength == "missing":
        reasons.append("missing_or_anonymous_agent_identity")
        decision = "deny" if sensitivity in {"medium", "high", "critical"} or hard_risk else "review"
    elif identity_strength == "weak":
        reasons.append("weak_agent_identity_requires_review")
        decision = "review"

    if missing_scopes:
        reasons.append("missing_required_scopes")
        controls.add("refuse_until_required_scopes_are_granted")
        decision = "deny"

    if hard_risk:
        reasons.append("high_risk_action_requires_explicit_boundary")
        controls.add("deny_secret_wallet_payment_repo_settings_or_external_mutation_without_separate_authority")
        decision = "deny"

    if deny_scanner:
        reasons.append("critical_or_malicious_scanner_signal")
        controls.add("deny_on_critical_scanner_evidence")
        decision = "deny"

    if decision != "deny":
        if sensitivity in {"medium", "high", "critical"}:
            reasons.append("sensitivity_requires_review")
            decision = "review"
        if review_risk:
            reasons.append("review_risk_action_signal")
            controls.add("review_external_network_execution_or_plugin_action_before_use")
            decision = "review"
        if review_scanner:
            reasons.append("scanner_signal_requires_review")
            decision = "review"
        if not trusted_provenance:
            reasons.append("missing_strong_local_or_verified_provenance")
            decision = "review"

    if decision == "proceed":
        reasons.append("identity_scopes_sensitivity_provenance_and_scanner_signals_passed")
        controls.add("proceed_only_for_this_local_low_sensitivity_pre_action_context")

    receipt_material = redact_agent_trust_packet({
        "contract_version": negotiated,
        "agent_identity_strength": identity_strength,
        "requested_action": redact_agent_trust_packet(requested_action, parent_key="requested_action"),
        "required_scopes": redact_agent_trust_packet(required_scopes, parent_key="required_scopes"),
        "granted_scopes": redact_agent_trust_packet(granted_scopes, parent_key="granted_scopes"),
        "missing_scopes": missing_scopes,
        "sensitivity": sensitivity,
        "declaration_evidence_status": declaration_status,
        "provenance": provenance,
        "scanner_signals": redact_agent_trust_packet(scanner_signals, parent_key="scanner_signals"),
        "pre_action_decision": decision,
        "reasons": reasons,
    })
    receipt_digest = hashlib.sha256(json.dumps(receipt_material, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
    packet = {
        "packet_id": f"zero-trust-gate-{receipt_digest[:16]}",
        "gate": "agent_trust_zero_trust_identity_policy_pre_action",
        "contract_version": negotiated,
        "supported_contract_versions": _SUPPORTED_ZERO_TRUST_CONTRACT_VERSIONS,
        "pre_action_decision": decision,
        "agent_identity_strength": identity_strength,
        "requested_action": redact_agent_trust_packet(requested_action, parent_key="requested_action"),
        "required_scopes": redact_agent_trust_packet(required_scopes, parent_key="required_scopes"),
        "granted_scopes": redact_agent_trust_packet(granted_scopes, parent_key="granted_scopes"),
        "missing_scopes": missing_scopes,
        "sensitivity": sensitivity,
        "declaration_evidence_status": declaration_status,
        "provenance_trusted": trusted_provenance,
        "scanner_signals": redact_agent_trust_packet(scanner_signals, parent_key="scanner_signals"),
        "reasons": reasons,
        "controls": sorted(controls),
        "audit_receipt": {
            "receipt_digest": receipt_digest,
            "receipt_material_digest_fields": sorted(receipt_material.keys()),
        },
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "external_action": False,
        "secret_values_read": False,
        "trust_boundary": "Zero-Trust gate is a local pre-action policy receipt; it is not authorization to execute, fetch, publish, contact, sign, pay, read secrets, or mutate external systems.",
    }

    return redact_agent_trust_packet(packet)

def gate_runtime_pre_action_with_signals(request: Any, *, contract_version: str | None = None) -> dict[str, Any]:
    """Runtime Agent Trust boundary that consumes scanner/registry evidence.

    Static scanner or registry verdicts are treated as evidence for the live
    pre-action decision, never as authorization. Runtime identity, scopes,
    requested action, artifact identity, provenance, and least-privilege grants
    still decide whether an agent may proceed, must pause for review, or is
    denied. The function is local and deterministic: no IO, network, execution,
    secret read, signing, payment, posting, outreach, or repo-setting mutation.
    """
    normalized = _coerce_descriptor(request)
    if not isinstance(normalized, dict):
        normalized = {"requested_action": normalized}

    artifact = _request_field(normalized, "artifact", "tool", "skill", "descriptor", default={})
    artifact_identity = _request_field(normalized, "artifact_identity", "tool_identity", "skill_identity", default={})
    if not artifact_identity and isinstance(artifact, dict):
        artifact_identity = {
            "id": artifact.get("id") or artifact.get("name") or artifact.get("package") or "unknown",
            "kind": artifact.get("kind") or artifact.get("type") or "unknown",
            "version": artifact.get("version"),
        }

    scanner_signals = _as_list(_request_field(normalized, "scanner_signals", "scanner", default=[]))
    registry_signals = _as_list(_request_field(normalized, "registry_signals", "registry", default=[]))
    signal_text = " ".join(scanner_signals + registry_signals).lower().replace("-", "_")

    clean_scan_terms = {"clean", "passed", "no_findings", "no_known_risky_signal", "allowlisted"}
    static_clean = any(term in signal_text for term in clean_scan_terms) and not any(term in signal_text for term in (_DENY_SCANNER_TERMS | _REVIEW_SCANNER_TERMS))

    combined_request = dict(normalized)
    combined_request["artifact_identity"] = artifact_identity
    combined_request["scanner_signals"] = scanner_signals + registry_signals
    zero_trust = gate_zero_trust_agent_action(combined_request, contract_version=contract_version)

    decision = str(zero_trust["pre_action_decision"])
    reasons = list(zero_trust["reasons"])
    controls = set(str(control) for control in zero_trust["controls"])
    deny_signals = sorted(term for term in _DENY_SCANNER_TERMS if term in signal_text)
    review_signals = sorted(term for term in _REVIEW_SCANNER_TERMS if term in signal_text)

    runtime_authority_ok = (
        zero_trust["agent_identity_strength"] == "strong"
        and zero_trust["missing_scopes"] == []
        and zero_trust["pre_action_decision"] == "proceed"
    )

    if deny_signals:
        decision = "deny"
        reasons.append("runtime_denied_by_risky_scanner_or_registry_signal")
        controls.add("risky_static_evidence_overrides_clean_runtime_path")
    elif review_signals and decision != "deny":
        decision = "review"
        reasons.append("runtime_review_required_by_scanner_or_registry_signal")
        controls.add("pause_for_static_evidence_review_before_use")

    if static_clean:
        reasons.append("clean_static_scan_is_evidence_not_authorization")
        controls.add("do_not_treat_clean_scan_as_runtime_authority")
        if not runtime_authority_ok and decision == "proceed":
            decision = "review"
            reasons.append("clean_scan_cannot_rescue_missing_runtime_authority")

    if zero_trust["missing_scopes"] or zero_trust["agent_identity_strength"] != "strong":
        controls.add("runtime_identity_and_grants_required_even_with_clean_scan")

    receipt_material = redact_agent_trust_packet({
        "zero_trust_receipt": zero_trust["audit_receipt"],
        "artifact_identity": artifact_identity,
        "scanner_signals": scanner_signals,
        "registry_signals": registry_signals,
        "static_clean": static_clean,
        "runtime_pre_action_decision": decision,
        "reasons": reasons,
    })
    receipt_digest = hashlib.sha256(json.dumps(receipt_material, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()

    packet = {
        "packet_id": f"runtime-signal-gate-{receipt_digest[:16]}",
        "gate": "agent_trust_runtime_pre_action_signal_boundary",
        "contract_version": zero_trust["contract_version"],
        "pre_action_decision": decision,
        "artifact_identity": redact_agent_trust_packet(artifact_identity, parent_key="artifact_identity"),
        "scanner_signals": redact_agent_trust_packet(scanner_signals, parent_key="scanner_signals"),
        "registry_signals": redact_agent_trust_packet(registry_signals, parent_key="registry_signals"),
        "static_scan_clean": static_clean,
        "static_signal_effect": "deny" if deny_signals else "review" if review_signals else "evidence_only",
        "runtime_authority_ok": runtime_authority_ok,
        "runtime_policy_receipt": zero_trust,
        "reasons": reasons,
        "controls": sorted(controls),
        "audit_receipt": {
            "receipt_digest": receipt_digest,
            "receipt_material_digest_fields": sorted(receipt_material.keys()),
        },
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "external_action": False,
        "secret_values_read": False,
        "trust_boundary": "Scanner/registry signals are static evidence for this runtime pre-action boundary; they never replace agent identity, least-privilege grants, provenance, or action-specific policy.",
    }
    return redact_agent_trust_packet(packet)


def gate_external_skill_descriptor(descriptor: Any, *, contract_version: str | None = None) -> dict[str, Any]:
    """Mandatory local pre-action gate for external skill/MCP/plugin/repo intake.

    This wrapper turns the generic boundary classifier into a concrete decision
    packet for the moment before an agent considers installing, enabling,
    executing, contacting, or otherwise using an external capability descriptor.
    It performs no fetch, install, execution, secret read, wallet action, signing,
    payment, outreach, posting, or repository-setting mutation.
    """
    intake = classify_agent_trust_boundaries(descriptor, contract_version=contract_version)
    verdict = str(intake["verdict"])
    matched_ids = {str(boundary["id"]) for boundary in intake["matched_boundaries"]}

    if "sensitive_authority_secrets_credential_gate" in matched_ids or verdict == "deny":
        decision = "deny_sensitive_authority"
        allowed_next_step = "Do not use this descriptor for installation or action; create a sanitized review note with secret values removed."
    elif verdict == "quarantine":
        decision = "quarantine_before_use"
        allowed_next_step = "Keep descriptor in static review only; require a separate sandbox decision before any execution, install, fetch, or integration."
    elif verdict == "review":
        decision = "require_human_review"
        allowed_next_step = "Perform local metadata/provenance review against the referenced contract artifacts before considering any integration."
    else:
        decision = "allow_local_review_only"
        allowed_next_step = "Proceed only with local provenance capture and metadata review; this is not authorization to install, execute, fetch, or enable the capability."

    refused_actions = [
        "install_external_skill",
        "enable_mcp_or_plugin",
        "execute_descriptor_commands",
        "fetch_untrusted_code_or_manifest",
        "read_or_request_secret_values",
        "send_network_requests_on_descriptor_behalf",
        "post_publish_message_or_contact_people",
        "sign_wallet_or_payment_request",
        "mutate_repository_settings_or_permissions",
    ]

    return {
        "packet_id": f"external-skill-gate-{str(intake['digest'])[:16]}",
        "gate": "agent_trust_external_skill_descriptor_pre_action",
        "contract_version": intake["contract_version"],
        "pre_action_decision": decision,
        "allowed_next_step": allowed_next_step,
        "refused_actions": refused_actions,
        "boundary_intake": intake,
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "external_action": False,
        "secret_values_read": False,
        "trust_boundary": "This packet is a local pre-action gate for review only; it never authorizes installation, execution, network use, posting, signing, payment, or repository-permission changes.",
    }


__all__ = [
    "BOUNDARY_INTAKE_CONTRACT_VERSION",
    "SUPPORTED_BOUNDARY_INTAKE_CONTRACT_VERSIONS",
    "classify_agent_trust_boundaries",
    "agent_trust_boundary_catalog",
    "gate_external_skill_descriptor",
    "gate_zero_trust_agent_action",
    "gate_runtime_pre_action_with_signals",
    "gate_static_scope_manifest_consistency",
    "evaluate_agent_trust_change_control",
]


CHANGE_CONTROL_CONTRACT_VERSION = "agent-trust-change-control-v1"
SUPPORTED_CHANGE_CONTROL_CONTRACT_VERSIONS = [CHANGE_CONTROL_CONTRACT_VERSION]
_SECURITY_CRITICAL_SURFACES: dict[str, str] = {
    "agent_trust/scanner.py": "public_prompt_scanner",
    "agent_trust/utils.py": "redaction_and_canonicalization",
    "agent_trust/boundaries.py": "verdict_logic_and_gates",
    "agent_trust/scope.py": "static_scope_consistency",
    "agent_trust/agent_trust_agency.py": "agency_scope_classifier",
    "readme.md": "public_advisory_boundary_claims",
    "pyproject.toml": "package_contract",
}
_WEAKENING_CHANGE_TERMS = (
    "remove redaction",
    "disable redaction",
    "skip redaction",
    "bypass redaction",
    "persist raw secret",
    "log raw secret",
    "bypass deny",
    "bypass review",
    "deny as allow",
    "review as allow",
    "force allow",
    "always allow",
    "disable schema validation",
    "skip schema validation",
    "remove schema validation",
    "weaken threat model",
    "remove threat model",
    "mark advisory as enforcement",
    "call advisory enforcement",
    "claim enforcement boundary",
    "ignore governance guard",
    "disable governance guard",
    "bypass change control",
)


def _canonical_agent_trust_change_path(path: Any) -> str:
    value = str(path or "").strip().replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    return value.lower()


def _surface_category_for_path(path: Any) -> str | None:
    normalized = _canonical_agent_trust_change_path(path)
    return _SECURITY_CRITICAL_SURFACES.get(normalized)


def _approval_evidence(change: dict[str, Any]) -> dict[str, Any]:
    approval = _request_field(change, "approval", "change_control", "change_control_evidence", default={})
    return approval if isinstance(approval, dict) else {}


def _has_explicit_change_approval(approval: dict[str, Any]) -> bool:
    if not approval:
        return False
    status = normalize_agent_trust_text(str(_request_field(approval, "status", "decision", default=""))).lower()
    approved = approval.get("approved") is True or status in {"approved", "accepted", "authorized"}
    authority = _request_field(approval, "approved_by", "authority", "reviewer", default="")
    change_id = _request_field(approval, "change_id", "approval_id", "ticket", "receipt_id", default="")
    scope = _request_field(approval, "scope", "reason", "summary", default="")
    return approved and _has_nonempty_value(authority) and _has_nonempty_value(change_id) and _has_nonempty_value(scope)


def evaluate_agent_trust_change_control(change: Any, *, contract_version: str | None = None) -> dict[str, Any]:
    """Evaluate local change-control evidence for security-critical Agent Trust surfaces.

    This is a deterministic local governance receipt, not repository-settings
    enforcement and not authorization to weaken security policy. It helps make
    mutations to verdict logic, schemas, redaction, and boundary claims visible
    before they are committed or applied by an autonomous loop.
    """
    negotiated = contract_version or CHANGE_CONTROL_CONTRACT_VERSION
    if negotiated not in SUPPORTED_CHANGE_CONTROL_CONTRACT_VERSIONS:
        supported = ", ".join(SUPPORTED_CHANGE_CONTROL_CONTRACT_VERSIONS)
        raise ValueError(f"unsupported change-control contract version: {negotiated}; supported: {supported}")

    normalized = _coerce_descriptor(change)
    if not isinstance(normalized, dict):
        normalized = {"summary": normalized}

    raw_paths = _request_field(normalized, "paths", "files", "changed_paths", "target_paths", default=[])
    paths = _as_list(raw_paths)
    surface_classifications: list[dict[str, Any]] = []
    critical_categories: set[str] = set()
    for path in paths:
        category = _surface_category_for_path(path)
        canonical_path = _canonical_agent_trust_change_path(path)
        surface_classifications.append(
            {
                "path": canonical_path,
                "security_critical": category is not None,
                "surface_category": category or "non_security_or_general_docs",
            }
        )
        if category:
            critical_categories.add(category)

    evidence_text = normalize_agent_trust_text(_safe_text(normalized)).lower()
    weakening_signals = [term for term in _WEAKENING_CHANGE_TERMS if term in evidence_text]
    approval = _approval_evidence(normalized)
    approved = _has_explicit_change_approval(approval)

    reasons: list[str] = []
    required_controls: set[str] = {
        "record_provenance_before_mutation",
        "preserve_advisory_not_enforcement_claims",
        "do_not_weaken_redaction_or_secret_boundaries",
    }
    decision = "proceed"

    if not paths:
        decision = "review"
        reasons.append("missing_target_paths")
        required_controls.add("name_security_surface_before_change")
    elif critical_categories:
        reasons.append("security_critical_agent_trust_surface_touched")
        required_controls.add("explicit_local_change_control_required")
        required_controls.add("focused_tests_required_for_security_surface")
        decision = "proceed" if approved else "review"
        if approved:
            reasons.append("explicit_local_change_control_evidence_present")
        else:
            reasons.append("missing_explicit_local_change_control_evidence")
    else:
        reasons.append("no_security_critical_agent_trust_surface_detected")
        required_controls.add("normal_review_and_provenance_sufficient")

    if weakening_signals:
        reasons.append("weakening_intent_signal_detected")
        required_controls.add("do_not_apply_weakening_without_explicit_human_change_control")
        decision = "proceed" if approved else "deny"
        if not approved:
            reasons.append("weakening_change_requires_explicit_approval")

    if not _has_nonempty_value(_request_field(normalized, "provenance", "origin", "source", "change_id", default="")):
        reasons.append("provenance_missing_or_weak")
        required_controls.add("attach_origin_author_and_review_context")
        if decision == "proceed" and critical_categories:
            decision = "review"

    receipt_base = {
        "contract_version": negotiated,
        "supported_contract_versions": SUPPORTED_CHANGE_CONTROL_CONTRACT_VERSIONS,
        "gate": "agent_trust_local_change_control_guard",
        "decision": decision,
        "surface_classifications": surface_classifications,
        "security_critical_surface_count": len(critical_categories),
        "security_critical_categories": sorted(critical_categories),
        "weakening_signals": weakening_signals,
        "approval_evidence_present": approved,
        "approval_summary": {
            "status": _request_field(approval, "status", "decision", default=None),
            "approved": approval.get("approved") if approval else None,
            "approved_by": _request_field(approval, "approved_by", "authority", "reviewer", default=None) if approval else None,
            "change_id": _request_field(approval, "change_id", "approval_id", "ticket", "receipt_id", default=None) if approval else None,
            "scope": _request_field(approval, "scope", "reason", "summary", default=None) if approval else None,
        },
        "provenance": {
            "origin": _request_field(normalized, "origin", "source", default=None),
            "author": _request_field(normalized, "author", "actor", default=None),
            "change_id": _request_field(normalized, "change_id", "ticket", default=None),
            "summary": _request_field(normalized, "summary", "description", "intent", default=None),
        },
        "reasons": reasons,
        "required_controls": sorted(required_controls),
        "network_calls": False,
        "execution": False,
        "wallet_access": False,
        "external_action": False,
        "secret_values_read": False,
        "trust_boundary": "Local change-control receipt only; it records governance evidence and does not enforce repository settings, branch protection, CI, signatures, or human approval outside this packet.",
    }
    redacted = redact_agent_trust_packet(receipt_base)
    canonical = json.dumps(redacted, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    redacted["packet_digest"] = digest
    redacted["packet_id"] = f"change-control-{digest[:16]}"
    return redacted
