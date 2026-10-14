"""
Unit tests for Velocitee Vector Security & Compliance module.
Tests HMAC claim tokens, audit ring-buffer, and zero-trust validation.
"""

import time
import pytest
from vector.telia.daemon.security import (
    generate_claim_token,
    verify_claim_token,
    record_audit_event,
    get_audit_log,
    init_baseline_audit_log,
    is_valid_mac,
    is_valid_profile,
    audit_log,
    MAX_AUDIT_LOG_ENTRIES,
)


def test_mac_validation():
    """Verify MAC address format validation."""
    assert is_valid_mac("52:54:00:12:34:56") is True
    assert is_valid_mac("00-1A-2B-3C-4D-5E") is True
    assert is_valid_mac("invalid-mac") is False
    assert is_valid_mac("") is False
    assert is_valid_mac("52:54:00:12:34") is False
    assert is_valid_mac("52:54:00:12:34:56:78") is False


def test_profile_validation():
    """Verify provisioning profile whitelist validation."""
    assert is_valid_profile("plain-ubuntu-server") is True
    assert is_valid_profile("sovereign-legal-advisory") is True
    assert is_valid_profile("malicious-profile-exec") is False
    assert is_valid_profile("") is False


def test_claim_token_issuance_and_verification():
    """Verify valid token generation and HMAC-SHA256 verification."""
    mac = "52:54:00:12:34:56"
    profile = "plain-ubuntu-server"

    token, expires_at = generate_claim_token(mac, profile)
    assert "." in token
    parts = token.split(".")
    assert len(parts) == 2
    assert parts[0] == str(expires_at)
    assert len(parts[1]) == 64  # SHA-256 hex length

    assert verify_claim_token(mac, profile, token) is True


def test_claim_token_tamper_rejection():
    """Verify that tampering with MAC, profile, or signature invalidates the token."""
    mac = "52:54:00:12:34:56"
    profile = "plain-ubuntu-server"

    token, _ = generate_claim_token(mac, profile)

    # Different MAC
    assert verify_claim_token("00:11:22:33:44:55", profile, token) is False

    # Different profile
    assert verify_claim_token(mac, "sovereign-legal-advisory", token) is False

    # Tampered signature
    parts = token.split(".")
    tampered_token = f"{parts[0]}.{'0' * 64}"
    assert verify_claim_token(mac, profile, tampered_token) is False


def test_claim_token_expiration():
    """Verify that expired tokens are actively rejected."""
    mac = "52:54:00:12:34:56"
    profile = "plain-ubuntu-server"

    past_timestamp = int(time.time()) - 100
    fake_token = f"{past_timestamp}.{'a' * 64}"
    assert verify_claim_token(mac, profile, fake_token) is False


def test_claim_token_invalid_input_rejection():
    """Verify that generate_claim_token raises ValueError on malformed inputs."""
    with pytest.raises(ValueError):
        generate_claim_token("bad_mac", "plain-ubuntu-server")

    with pytest.raises(ValueError):
        generate_claim_token("52:54:00:12:34:56", "unauthorized-profile")


def test_audit_log_ring_buffer():
    """Verify that audit log is bounded and does not grow indefinitely."""
    audit_log.clear()
    assert len(get_audit_log()) == 0

    init_baseline_audit_log("52:54:00:12:34:56")
    initial_count = len(get_audit_log())
    assert initial_count >= 4

    # Flood with entries to test bounded ring buffer
    for i in range(MAX_AUDIT_LOG_ENTRIES + 100):
        record_audit_event("TEST_EVENT", "tester", "52:54:00:12:34:56", f"Test entry {i}")

    assert len(audit_log) == MAX_AUDIT_LOG_ENTRIES
    assert len(get_audit_log()) == MAX_AUDIT_LOG_ENTRIES


def test_claim_token_single_use_consumption():
    """Fix 2.8: consuming a token once (the authorised boot release) succeeds;
    a second consume of the same token is rejected as a replay. Non-consuming
    verifies still pass so the multi-request iPXE boot chain keeps working."""
    from vector.telia.daemon.security import is_token_consumed

    mac = "52:54:00:12:34:56"
    profile = "plain-ubuntu-server"
    token, _ = generate_claim_token(mac, profile)

    # Non-consuming verify is idempotent (asset fetches).
    assert verify_claim_token(mac, profile, token) is True
    assert verify_claim_token(mac, profile, token) is True
    assert is_token_consumed(token) is False

    # First consume wins; second is a rejected replay.
    assert verify_claim_token(mac, profile, token, consume=True) is True
    assert is_token_consumed(token) is True
    assert verify_claim_token(mac, profile, token, consume=True) is False
