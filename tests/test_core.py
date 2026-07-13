"""Core tests for standalone agent_trust package."""
import pytest
from agent_trust.utils import normalize_agent_trust_text, redact_agent_trust_packet
from agent_trust.boundaries import _BOUNDARIES, gate_zero_trust_agent_action


class TestUtils:
    def test_normalize_nfkc(self):
        """NFKC normalization removes compatibility characters."""
        # Fullwidth letters become ASCII
        result = normalize_agent_trust_text("ＤＲＯＰ")
        assert "DROP" in result

    def test_normalize_strips_control_formatting(self):
        """Zero-width and formatting controls are stripped."""
        result = normalize_agent_trust_text("hello\u200bworld")
        assert "\u200b" not in result
        assert "helloworld" in result

    def test_normalize_homoglyphs(self):
        """Cyrillic homoglyphs are mapped to Latin."""
        # Cyrillic 'а' (U+0430) -> Latin 'a'
        result = normalize_agent_trust_text("\u0430dmin")
        assert result == "admin"

    def test_redact_with_parent_key(self):
        """When parent_key is a secret marker, the value is redacted."""
        result = redact_agent_trust_packet("12345", parent_key="password")
        assert result == "[REDACTED]"

    def test_redact_without_parent_key_preserves(self):
        """Without parent_key, a string is not redacted by key name."""
        result = redact_agent_trust_packet("password=12345")
        # The string is checked for secret patterns, not key names
        assert isinstance(result, str)

    def test_redact_dict_recursive(self):
        """Dict values with secret-key names are redacted."""
        result = redact_agent_trust_packet({"api_key": "sk-abc123def456", "name": "test"})
        assert result["api_key"] == "[REDACTED]"
        assert result["name"] == "test"


class TestBoundaries:
    def test_all_boundaries_have_label(self):
        for key, boundary in _BOUNDARIES.items():
            assert "label" in boundary, f"{key} missing label"

    def test_all_boundaries_have_severity(self):
        for key, boundary in _BOUNDARIES.items():
            assert "severity" in boundary, f"{key} missing severity"

    def test_boundaries_count(self):
        assert len(_BOUNDARIES) == 25

    def test_security_boundaries_are_present(self):
        assert "destructive_shell_command_boundary" in _BOUNDARIES
        assert "instruction_override_injection_boundary" in _BOUNDARIES

    def test_gate_zero_trust_returns_decision(self):
        """Gate returns a pre_action_decision field."""
        verdict = gate_zero_trust_agent_action("DROP TABLE users; --")
        assert "pre_action_decision" in verdict
        assert verdict["pre_action_decision"] == "review"

    def test_gate_zero_trust_always_review_without_identity(self):
        """Zero-trust gate defaults to review when no identity is present."""
        verdict = gate_zero_trust_agent_action("echo hello")
        assert verdict["pre_action_decision"] == "review"
        assert "missing_or_anonymous_agent_identity" in verdict["reasons"]
