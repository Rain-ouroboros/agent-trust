"""Regression coverage for previously fail-open or dead security paths."""

from agent_trust import (
    ScopeGrants,
    canonicalize_agent_trust_packet,
    check_scope,
    classify_action,
    classify_agent_trust_boundaries,
    gate_static_scope_manifest_consistency,
    normalize_agent_trust_text,
    redact_agent_trust_packet,
)


def test_canonicalization_is_deterministic_bytes():
    first = canonicalize_agent_trust_packet({"b": 2, "a": 1})
    second = canonicalize_agent_trust_packet({"a": 1, "b": 2})
    assert first == second == b'{"a":1,"b":2}'


def test_nested_and_non_string_secrets_are_redacted():
    packet = {
        "password": {"value": "hunter2"},
        "api_key": 123456,
        "credentials": [{"value": "private"}],
        "clientSecret": "private-client-value",
        "author": "Rain",
    }
    redacted = redact_agent_trust_packet(packet)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["credentials"] == "[REDACTED]"
    assert redacted["clientSecret"] == "[REDACTED]"
    assert redacted["author"] == "Rain"


def test_secret_status_booleans_remain_machine_readable():
    redacted = redact_agent_trust_packet({"secret_values_read": False})
    assert redacted["secret_values_read"] is False


def test_secret_shapes_and_uppercase_homoglyphs_are_normalized():
    assert normalize_agent_trust_text("Аdmin１２") == "Admin12"
    packet = redact_agent_trust_packet(
        {"note": "credential AKIAABCDEFGHIJKLMNOP must not be logged"}
    )
    assert "AKIA" not in packet["note"]
    assert "[REDACTED]" in packet["note"]


def test_short_secret_prefix_does_not_redact_normal_words():
    text = "skateboarding by the lake"
    assert redact_agent_trust_packet(text) == text


def test_mixed_set_is_json_safe():
    assert redact_agent_trust_packet({1, "two"}) in ([1, "two"], ["two", 1])


def test_scope_gate_missing_dangerous_and_matching_evidence():
    missing = gate_static_scope_manifest_consistency({"declared_scopes": ["network"]})
    assert missing["pre_action_decision"] == "review"

    dangerous = gate_static_scope_manifest_consistency(
        {"declared_scopes": [], "manifest_evidence": ["network"]}
    )
    assert dangerous["pre_action_decision"] == "deny"

    matching = gate_static_scope_manifest_consistency(
        {"declared_scopes": ["network"], "manifest_evidence": ["network"]}
    )
    assert matching["pre_action_decision"] == "proceed"


def test_scope_gate_does_not_find_post_inside_composting():
    packet = gate_static_scope_manifest_consistency(
        {"declared_scopes": [], "manifest_evidence": ["composting"]}
    )
    assert packet["pre_action_decision"] == "review"
    assert packet["undeclared_dangerous_scopes"] == []


def test_role_inference_does_not_overgrant_on_substrings():
    grants = ScopeGrants.from_role_text(
        "analyst",
        "Postgres analyst who reviews profiles and reports.",
    )
    assert grants.has("external_action", "write") is False
    assert grants.has("filesystem", "write") is False


def test_string_shell_command_adds_network_requirement():
    requirement = classify_action(
        "run_shell",
        {"cmd": "curl https://example.invalid/status"},
    )
    assert ("shell", "write") in requirement.required
    assert ("network", "read") in requirement.required


def test_nested_mutating_curl_adds_network_write_requirement():
    requirement = classify_action(
        "run_shell",
        {"cmd": ["bash", "-c", "curl -X POST https://example.invalid/hook"]},
    )
    assert ("network", "read") in requirement.required
    assert ("network", "write") in requirement.required


def test_read_only_scope_violation_reviews_but_write_violation_quarantines():
    shell_only = ScopeGrants.from_dict("agent", {"shell": "write"})
    read_violation = check_scope(
        "run_shell",
        {"cmd": "curl https://example.invalid/status"},
        shell_only,
    )
    assert read_violation["violations"] == ["network:read"]
    assert read_violation["verdict"] == "review"

    no_grants = ScopeGrants.from_dict("agent", {})
    write_violation = check_scope("run_shell", {"cmd": ["echo", "hello"]}, no_grants)
    assert write_violation["verdict"] == "quarantine"


def test_agency_boundary_is_reachable_and_quarantines_write_violation():
    packet = classify_agent_trust_boundaries(
        {
            "description": "Check proposed repository action against explicit grants.",
            "agent_id": "reviewer",
            "scope_grants": {"filesystem": "read"},
            "actions": [{"tool": "repo_write_commit", "args": {}}],
        }
    )
    matches = {item["id"]: item for item in packet["matched_boundaries"]}
    assert "agent_trust_agency_boundary" in matches
    assert packet["verdict"] == "quarantine"
    assert matches["agent_trust_agency_boundary"]["matched_signals"] == [
        "scope_quarantine:repo_write_commit"
    ]


def test_scope_receipt_redacts_secret_shaped_tool_name():
    secret_tool_name = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
    packet = check_scope(secret_tool_name, {}, ScopeGrants.from_dict("agent", {}))
    assert secret_tool_name not in str(packet)
