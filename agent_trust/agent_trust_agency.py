"""ASI03 Excessive Agency — Scope-based permission model (Phase 1: core).

Deterministic, stdlib-only, offline. No LLM at runtime.
Integrates into the existing Agent Trust boundary registry
(``classify_agent_trust_boundaries``) via a new boundary id
``excessive_agency_scope_boundary``.

This module is ADVISORY ONLY — it produces a receipt, not an enforcement
decision. Enforcement wiring is deferred to a separate owner-gated phase.

Design: Fable 5 architecture response (2026-07-02).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from ouroboros.agent_trust import normalize_agent_trust_text, redact_agent_trust_packet


# ---------------------------------------------------------------------------
# Scope taxonomy
# ---------------------------------------------------------------------------

SCOPES = (
    "filesystem",
    "shell",
    "network",
    "git",
    "secrets",
    "external_action",
    "code_execution",
    "database",
)

# Scopes where a meaningful read-only tier exists.
READABLE_SCOPES = frozenset({"filesystem", "network", "git", "database"})

# Scopes that only ever require/grant "write" (read is meaningless).
WRITE_ONLY_SCOPES = frozenset(SCOPES) - READABLE_SCOPES

Capability = tuple[str, str]  # ("filesystem", "read") or ("shell", "write")


# ---------------------------------------------------------------------------
# Grants data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeGrants:
    """Immutable capability grants for one agent identity."""

    agent_id: str
    grants: frozenset[Capability]
    inferred: bool = False  # True when derived from role text, not explicit config

    def has(self, scope: str, mode: str = "read") -> bool:
        """Check whether *at least* ``mode`` is granted in ``scope``."""
        if mode == "write":
            return (scope, "write") in self.grants
        # read — granted explicitly, or write implies read for readable scopes
        if (scope, "read") in self.grants:
            return True
        if scope in READABLE_SCOPES and (scope, "write") in self.grants:
            return True
        return False

    @classmethod
    def from_dict(cls, agent_id: str, d: dict) -> "ScopeGrants":
        """Explicit grants from a config dict.

        Expected shape::

            {"filesystem": "write", "network": "read", "git": "write"}
        """
        grants: set[Capability] = set()
        for scope, mode in d.items():
            scope = scope.strip().lower()
            mode = mode.strip().lower()
            if scope not in SCOPES:
                continue
            if mode not in ("read", "write"):
                continue
            if scope in WRITE_ONLY_SCOPES and mode == "read":
                continue  # meaningless, skip
            grants.add((scope, mode))
        return cls(agent_id=agent_id, grants=frozenset(grants), inferred=False)

    @classmethod
    def from_role_text(cls, agent_id: str, role_text: str) -> "ScopeGrants":
        """Deterministic inference from free-text agent role description.

        This is a fallback. Explicit config always wins.  The mapping is
        intentionally small and keyword-based — same input always produces
        the same grants.
        """
        grants: dict[str, str] = {}  # scope → mode
        text = normalize_agent_trust_text(role_text).lower()

        # Strong signals — grant write
        if any(kw in text for kw in ("file-system", "filesystem", "files", "backup", "storage")):
            grants["filesystem"] = "write"
        if any(kw in text for kw in ("shell", "execute", "run command", "subprocess", "cli")):
            grants["shell"] = "write"
        if any(kw in text for kw in ("network", "http", "fetch", "crawl", "api call", "web request")):
            grants["network"] = "read"
        if any(kw in text for kw in ("git", "commit", "push", "pull request", "code review", "pr review")):
            grants["git"] = "write"
        if any(kw in text for kw in ("secret", "credential", "token", "key management")):
            grants["secrets"] = "write"
        if any(kw in text for kw in ("post", "publish", "send", "email", "dm", "reply", "outreach", "message", "telegram")):
            grants["external_action"] = "write"
        if any(kw in text for kw in ("code execution", "eval", "exec", "sandbox", "run code")):
            grants["code_execution"] = "write"
        if any(kw in text for kw in ("database", "sql", "query", "etl", "pipeline")):
            grants["database"] = "write"

        # Demotions — "read-only" / "never executes"
        if any(kw in text for kw in ("read-only", "read only", "reads", "never executes", "no shell", "no execution")):
            for scope in ("filesystem", "network", "git", "database"):
                if grants.get(scope) == "write":
                    grants[scope] = "read"
            for scope in WRITE_ONLY_SCOPES:
                grants.pop(scope, None)

        # Build capability set
        caps: set[Capability] = set()
        for scope, mode in grants.items():
            if scope not in SCOPES:
                continue
            if scope in WRITE_ONLY_SCOPES and mode == "read":
                continue
            caps.add((scope, mode))

        return cls(agent_id=agent_id, grants=frozenset(caps), inferred=True)

    def to_dict(self) -> dict:
        """Serialisable form for audit packets."""
        result: dict[str, str] = {}
        for scope, mode in sorted(self.grants):
            result[scope] = mode
        return result


# ---------------------------------------------------------------------------
# Tool → required capabilities map
# ---------------------------------------------------------------------------

# Seed from the live tool registry names.  Each entry maps a tool name to the
# capabilities it *requires*.  A tool not in this map is "unknown" and will
# trigger a ``review`` verdict (unless the agent has a broad grant covering
# that tool family — see ``_TOOL_FAMILY_FALLBACK``).

_TOOL_SCOPE_MAP: dict[str, frozenset[Capability]] = {
    # Read-only tools
    "repo_read": frozenset({("filesystem", "read")}),
    "repo_list": frozenset({("filesystem", "read")}),
    "data_read": frozenset({("filesystem", "read")}),
    "data_list": frozenset({("filesystem", "read")}),
    "git_status": frozenset({("filesystem", "read"), ("git", "read")}),
    "git_diff": frozenset({("filesystem", "read"), ("git", "read")}),
    "chat_history": frozenset({("filesystem", "read")}),
    "knowledge_read": frozenset({("filesystem", "read")}),
    "web_search": frozenset({("network", "read")}),
    "browse_page": frozenset({("network", "read")}),
    "browser_action": frozenset({("network", "read")}),
    "analyze_screenshot": frozenset({("network", "read")}),
    "codegraph_explore": frozenset({("filesystem", "read")}),
    "list_available_tools": frozenset(),
    "enable_tools": frozenset(),
    "secret_available": frozenset({("secrets", "read")}),
    "get_task_result": frozenset({("filesystem", "read")}),
    "wait_for_task": frozenset({("filesystem", "read")}),

    # Write tools
    "repo_write_commit": frozenset({("filesystem", "write"), ("git", "write")}),
    "repo_commit": frozenset({("filesystem", "write"), ("git", "write")}),
    "data_write": frozenset({("filesystem", "write")}),
    "update_scratchpad": frozenset({("filesystem", "write")}),
    "update_identity": frozenset({("filesystem", "write")}),
    "knowledge_write": frozenset({("filesystem", "write")}),
    "schedule_task": frozenset({("shell", "write")}),
    "request_restart": frozenset({("shell", "write")}),
    "promote_to_stable": frozenset({("git", "write"), ("shell", "write")}),
    "switch_model": frozenset({("shell", "write")}),
    "provision_secret": frozenset({("secrets", "write")}),
    "delegate_coding_task": frozenset({("shell", "write"), ("code_execution", "write")}),
    "claude_code_edit": frozenset({("shell", "write"), ("code_execution", "write")}),
    "send_owner_message": frozenset({("external_action", "write")}),

    # Shell — the most dangerous tool
    "run_shell": frozenset({("shell", "write")}),
}

# Tool-name prefix → family capability fallback.
# If a tool name is not in _TOOL_SCOPE_MAP, check whether it starts with
# one of these prefixes and assign the corresponding capability.
_TOOL_FAMILY_FALLBACK: dict[str, Capability] = {
    "telegram_": ("external_action", "write"),
    "polymarket_": ("external_action", "write"),
    "identity_browser_": ("network", "write"),
    "agentmail_": ("network", "write"),
}


# ---------------------------------------------------------------------------
# Shell argv enrichment table
# ---------------------------------------------------------------------------

# For ``run_shell`` / exec-like tools, argv[0] is inspected to ADD required
# capabilities.  The table only ever ADDS requirements (never relaxes), so
# evasion (e.g. ``bash -c "iptables …"``) degrades to the base ``shell:write``
# check, never below it.

_SHELL_ARGV_CAPABILITIES: dict[str, Capability] = {
    # Network tools
    "iptables": ("network", "write"),
    "ip": ("network", "write"),
    "ifconfig": ("network", "write"),
    "curl": ("network", "read"),
    "wget": ("network", "read"),
    "nc": ("network", "write"),
    "ncat": ("network", "write"),
    "netcat": ("network", "write"),
    "ping": ("network", "read"),
    "nslookup": ("network", "read"),
    "dig": ("network", "read"),
    "host": ("network", "read"),
    "traceroute": ("network", "read"),
    "ssh": ("network", "write"),
    "scp": ("network", "write"),
    "rsync": ("network", "write"),
    # Git
    "git": ("git", "write"),
    # Secrets / auth
    "passwd": ("secrets", "write"),
    "openssl": ("secrets", "write"),
    "gpg": ("secrets", "write"),
    # System mutation (host-level)
    "useradd": ("shell", "write"),
    "usermod": ("shell", "write"),
    "chmod": ("filesystem", "write"),
    "chown": ("filesystem", "write"),
    "reboot": ("shell", "write"),
    "shutdown": ("shell", "write"),
    "systemctl": ("shell", "write"),
    "service": ("shell", "write"),
    "docker": ("shell", "write"),
    "podman": ("shell", "write"),
    "kubectl": ("shell", "write"),
    "apt": ("shell", "write"),
    "apt-get": ("shell", "write"),
    "yum": ("shell", "write"),
    "dnf": ("shell", "write"),
    "pip": ("shell", "write"),
    "pip3": ("shell", "write"),
    "npm": ("shell", "write"),
}


def _extract_argv0(tool_args: dict) -> str | None:
    """Extract argv[0] from tool_args, handling common shapes."""
    cmd = tool_args.get("cmd")
    if isinstance(cmd, list) and len(cmd) > 0:
        arg0 = str(cmd[0])
        # Handle ``sudo cmd`` — shift to the real command
        if arg0 == "sudo" and len(cmd) > 1:
            arg0 = str(cmd[1])
        return arg0
    return None


# ---------------------------------------------------------------------------
# Action classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionRequirement:
    required: frozenset[Capability]
    evidence: tuple[str, ...]
    recognized: bool  # False → unknown tool → verdict "review"


def classify_action(tool_call: str, tool_args: dict) -> ActionRequirement:
    """Determine what capabilities a tool call requires.

    Two layers:
    1. **Tool map** — known tool → base requirement.
    2. **Shell argv enrichment** — for ``run_shell``, argv[0] ADDS requirements
       (never relaxes).
    """
    evidence: list[str] = [f"tool:{tool_call}"]
    required: set[Capability] = set()

    # Layer 1: tool map
    if tool_call in _TOOL_SCOPE_MAP:
        required.update(_TOOL_SCOPE_MAP[tool_call])
        recognized = True
    else:
        # Family fallback
        recognized = False
        for prefix, cap in _TOOL_FAMILY_FALLBACK.items():
            if tool_call.startswith(prefix):
                required.add(cap)
                recognized = True
                evidence.append(f"family:{prefix}")
                break

    # Layer 2: shell argv enrichment (only for run_shell / exec-like)
    if tool_call == "run_shell":
        arg0 = _extract_argv0(tool_args)
        if arg0:
            base = arg0.split("/")[-1]  # strip path: /usr/bin/curl → curl
            evidence.append(f"argv0:{base}")
            if base in _SHELL_ARGV_CAPABILITIES:
                extra = _SHELL_ARGV_CAPABILITIES[base]
                required.add(extra)
                evidence.append(f"argv_cap:{extra[0]}:{extra[1]}")

    return ActionRequirement(
        required=frozenset(required),
        evidence=tuple(evidence),
        recognized=recognized,
    )


# ---------------------------------------------------------------------------
# Excessive agency detection
# ---------------------------------------------------------------------------

# Dangerous combinations from the prompt — write-tier only.
# Read-only combos (e.g. fs:read + net:read = crawler) are NOT excessive.
_DANGEROUS_COMBOS: tuple[tuple[Capability, ...], ...] = (
    # RCE chain
    (("filesystem", "write"), ("network", "write"), ("shell", "write")),
    # CI/CD poisoning
    (("shell", "write"), ("git", "write"), ("network", "write")),
    # Data exfiltration
    (("secrets", "write"), ("network", "write")),
    # Social engineering
    (("external_action", "write"), ("secrets", "read")),
    # Supply-chain injection
    (("code_execution", "write"), ("network", "write")),
    # Privilege escalation
    (("shell", "write"), ("filesystem", "write")),
    # Full control
    (("shell", "write"), ("network", "write"), ("secrets", "write"), ("external_action", "write")),
    # DB + network
    (("database", "write"), ("network", "write")),
)


def detect_excessive_agency(grants: ScopeGrants) -> list[str]:
    """Return a list of excessive-agency warnings (dangerous combos present).

    Warnings are advisory — they do NOT flip an in-scope allow verdict.
    They are attached as ``standing_risk`` in the packet.
    """
    warnings: list[str] = []
    for combo in _DANGEROUS_COMBOS:
        if all(grants.has(scope, mode) for scope, mode in combo):
            names = sorted(f"{s}:{m}" for s, m in combo)
            warnings.append(" + ".join(names))
    return warnings


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------


def check_scope(
    tool_call: str,
    tool_args: dict,
    grants: ScopeGrants,
) -> dict:
    """Check a tool call against granted scopes.

    Returns a packet with verdict, reasons, required/granted/violations,
    and evidence.  Advisory-only — does not block execution.
    """
    req = classify_action(tool_call, tool_args)
    violations: list[str] = []
    required_caps: list[str] = []
    granted_caps: list[str] = sorted(f"{s}:{m}" for s, m in grants.grants)

    for scope, mode in sorted(req.required):
        required_caps.append(f"{scope}:{mode}")
        if not grants.has(scope, mode):
            violations.append(f"{scope}:{mode}")

    # Verdict rules (order matters)
    if not req.recognized:
        verdict = "review"
        reasons = ["unrecognized_tool_default_review"]
    elif violations:
        # Any mutation out of scope → quarantine
        has_mutating_violation = any(
            (scope, "write") in req.required for scope, _mode in req.required
        )
        if has_mutating_violation:
            verdict = "quarantine"
        else:
            verdict = "review"
        reasons = [f"missing_capability:{v}" for v in violations]
    else:
        verdict = "allow"
        reasons = ["all_required_capabilities_granted"]

    # Excessive agency detection (advisory only)
    excessive_warnings = detect_excessive_agency(grants)

    packet = {
        "agent_id": grants.agent_id,
        "grants_inferred": grants.inferred,
        "tool_call": tool_call,
        "required": required_caps,
        "granted": granted_caps,
        "violations": violations,
        "verdict": verdict,
        "reasons": reasons,
        "evidence": list(req.evidence),
        "standing_risk": excessive_warnings,
    }

    # Redact secrets from tool_args before including in packet
    safe_args = redact_agent_trust_packet(tool_args)
    packet["tool_args"] = safe_args

    canonical = json.dumps(packet, sort_keys=True, ensure_ascii=False, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    packet["packet_digest"] = digest
    packet["packet_id"] = f"asi03-scope-{digest[:16]}"

    return packet
