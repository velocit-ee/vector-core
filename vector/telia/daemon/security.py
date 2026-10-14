"""
Velocitee Vector — Security & Compliance Module
Implements HMAC-SHA256 Claim Tokens, Audit Trails (NIS2/GDPR), and Zero-Trust Quarantine.
"""

from collections import deque
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List, Optional

# Edge secret key (generated per gateway instance)
_GATEWAY_SECRET = os.environ.get("TELIA_EDGE_SECRET", secrets.token_hex(32)).encode()
_TOKEN_TTL_SECONDS = 300  # 5 minute claim window
MAX_AUDIT_LOG_ENTRIES = 1000

# MAC address validation regex (standard EUI-48 format)
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
ALLOWED_PROFILES = {
    "prism",
    "prism-ai-appliance",
    "sovereign-legal-advisory",
    "plain-ubuntu-server",
}

# Memory-backed bounded audit log (structured RFC 5424 / CEF compatible)
audit_log: deque = deque(maxlen=MAX_AUDIT_LOG_ENTRIES)

# Single-use claim-token ledger (Fix 2.8). Maps token -> expiry epoch. Bounded
# so a flood of distinct tokens cannot grow it without limit; entries are also
# purged lazily once past expiry. Consumption is applied only at the point a
# token authorises a boot-script release, NOT on every verify: one iPXE boot
# fetches boot.ipxe, then the kernel, then the initrd as separate requests
# carrying the same token, so a blanket "reject if consumed" would break the
# legitimate flow. See consume() note in verify_claim_token.
_MAX_CONSUMED_TOKENS = 1000
_consumed_tokens: "dict[str, float]" = {}


def _purge_consumed(now: float) -> None:
    """Drop expired entries; if still over cap, drop the oldest by expiry."""
    for tok in [t for t, exp in _consumed_tokens.items() if exp < now]:
        _consumed_tokens.pop(tok, None)
    if len(_consumed_tokens) > _MAX_CONSUMED_TOKENS:
        for tok in sorted(_consumed_tokens, key=_consumed_tokens.get)[: len(_consumed_tokens) - _MAX_CONSUMED_TOKENS]:
            _consumed_tokens.pop(tok, None)


def is_token_consumed(token: str) -> bool:
    """True if this exact token has already authorised a boot-script release."""
    return token in _consumed_tokens

def is_valid_mac(mac: str) -> bool:
    """Validates that a string is a well-formed MAC address."""
    return bool(mac and MAC_REGEX.match(mac.strip()))

def is_valid_profile(profile: str) -> bool:
    """Validates that a profile is in the authorized whitelist."""
    return bool(profile and profile.strip() in ALLOWED_PROFILES)

def get_audit_log() -> List[Dict[str, Any]]:
    """Returns a snapshot list of current audit log entries."""
    return list(audit_log)

def record_audit_event(
    event_type: str,
    actor: str,
    target_mac: str,
    details: str,
    severity: str = "INFO",
    category: str = "SECURITY",
    facility: str = "daemon",
    event_id: Optional[str] = None
) -> Dict[str, Any]:
    """Records an immutable security audit event into the bounded ring buffer."""
    ts = datetime.now(timezone.utc).isoformat()
    eid = event_id or f"EVT-{secrets.randbelow(8999) + 1000}"
    event = {
        "timestamp": ts,
        "ts": ts,
        "event_id": eid,
        "eventId": eid,
        "severity": severity,
        "event_type": event_type,
        "category": category,
        "facility": facility or actor,
        "actor": actor,
        "target_mac": target_mac,
        "details": details,
        "message": details,
        "compliance": ["GDPR_Art32", "NIS2_SupplyChain", "Estonia_KTS"]
    }
    audit_log.append(event)
    print(f"  \033[1;35m[ROUTER-SYSLOG]\033[0m \033[36m[{ts[11:19]}]\033[0m [{severity:5s}] [{event_type:20s}] {details}", flush=True)
    return event

def init_baseline_audit_log(mac: str = "52:54:00:12:34:56"):
    """Populates initial audit ledger with baseline zero-trust entries."""
    audit_log.clear()
    record_audit_event("OPERATOR_SESSION", "authpriv", "router_cpe", "Operator session opened uid=admin@velocit.ee via mTLS · src=194.126.101.9", severity="INFO", category="SECURITY", facility="authpriv", event_id="EVT-1002")
    record_audit_event("UNCLAIMED_NODE", "daemon", mac, f"Unclaimed node detected on Port 4 · MAC={mac} · isolated VLAN 999", severity="WARN", category="PROVISIONING", facility="daemon", event_id="EVT-2041")
    record_audit_event("QUARANTINE_ENFORCED", "auth", mac, "Quarantine enforced · node denied LAN/WAN routing pending cryptographic claim", severity="ALERT", category="SECURITY", facility="auth", event_id="EVT-3300")
    record_audit_event("COMPLIANCE_SNAPSHOT", "audit", "router_cpe", "NIS2 Art.21 control snapshot persisted · hash-chain anchor tvHt7…d21a", severity="INFO", category="COMPLIANCE", facility="audit", event_id="EVT-4110")

def generate_claim_token(mac: str, profile: str) -> Tuple[str, int]:
    """Generates a cryptographically signed HMAC-SHA256 claim token for a specific hardware MAC."""
    if not is_valid_mac(mac):
        raise ValueError(f"Invalid MAC address format: '{mac}'")
    if not is_valid_profile(profile):
        raise ValueError(f"Invalid or unauthorized provisioning profile: '{profile}'")

    expires_at = int(time.time()) + _TOKEN_TTL_SECONDS
    payload = f"{mac.lower()}:{profile}:{expires_at}"
    signature = hmac.new(_GATEWAY_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    token = f"{expires_at}.{signature}"

    record_audit_event(
        event_type="CLAIM_TOKEN_ISSUED",
        actor="telia_admin_portal",
        target_mac=mac,
        details=f"Issued token for profile '{profile}', expires at {expires_at}"
    )
    return token, expires_at

def verify_claim_token(mac: str, profile: str, token: str, consume: bool = False) -> bool:
    """Verifies that a claim token is authentic, unexpired, and cryptographically valid.

    When ``consume`` is True (the authorised boot-script release path), the token is
    rejected if it was already consumed and, on success, is marked consumed so a
    sniffed token cannot trigger a second fresh authorised boot. Asset fetches call
    with ``consume`` False so the multi-request iPXE boot chain keeps working.
    """
    if not token or "." not in token:
        return False

    parts = token.split(".")
    if len(parts) != 2:
        return False

    try:
        expires_at = int(parts[0])
    except ValueError:
        return False

    now = time.time()
    # Reject tokens expired or suspiciously far in the future (> TTL + 60s)
    if now > expires_at or expires_at > now + _TOKEN_TTL_SECONDS + 60:
        record_audit_event(
            event_type="CLAIM_TOKEN_EXPIRED",
            actor="ipxe_client",
            target_mac=mac,
            details=f"Token expiration out of bounds: expires_at={expires_at}, now={int(now)}",
            severity="WARN"
        )
        return False

    expected_payload = f"{mac.lower()}:{profile}:{expires_at}"
    expected_sig = hmac.new(_GATEWAY_SECRET, expected_payload.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(parts[1], expected_sig):
        record_audit_event(
            event_type="CLAIM_TOKEN_INVALID_SIG",
            actor="ipxe_client",
            target_mac=mac,
            details="HMAC signature verification failed",
            severity="ALERT"
        )
        return False

    if consume:
        _purge_consumed(now)
        if is_token_consumed(token):
            record_audit_event(
                event_type="CLAIM_TOKEN_REPLAY",
                actor="ipxe_client",
                target_mac=mac,
                details="Rejected replay of an already-consumed claim token",
                severity="ALERT"
            )
            return False
        _consumed_tokens[token] = float(expires_at)

    return True

