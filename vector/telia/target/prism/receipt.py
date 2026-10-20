"""
Velocitee Prism — Cryptographic Compliance Receipt & Audit Ledger (PR-06)

Computes keyed HMAC-SHA256 compliance receipts over canonical JSON preimages using a
per-node secret key (mode 0600) and maintains a thread-safe, zero-PII audit ring buffer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional


GENESIS_AUDIT_HASH = "0" * 64


def load_or_create_node_key(key_path: Optional[Path] = None) -> bytes:
    """Loads or generates a 32-byte per-node HMAC key with 0600 permissions (PR-06)."""
    env_secret = os.environ.get("PRISM_NODE_HMAC_KEY", "").strip()
    if len(env_secret) >= 32:
        return env_secret.encode("utf-8")

    path = key_path or Path(
        os.environ.get("PRISM_NODE_KEY_PATH", "/tmp/velocitee-prism/node_hmac.key")
    )
    if path.exists():
        try:
            raw = path.read_text(encoding="utf-8").strip()
            if len(raw) >= 32:
                return raw.encode("utf-8")
        except OSError:
            pass

    generated_hex = secrets.token_hex(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(generated_hex + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass
    return generated_hex.encode("utf-8")


class ComplianceLedger:
    """
    Thread-safe HMAC-SHA256 compliance receipt generator and bounded audit ring buffer.
    Stores ONLY sanitized metadata — never raw prompts or raw PII values (PR-03, PR-06).
    """

    def __init__(self, node_key: Optional[bytes] = None, maxlen: int = 1000) -> None:
        self._lock = threading.Lock()
        self._node_key: bytes = node_key or load_or_create_node_key()
        self._entries: Deque[Dict[str, object]] = deque(maxlen=maxlen)
        self._seq: int = 0
        self._last_hash: str = GENESIS_AUDIT_HASH

    def compute_receipt(
        self,
        sanitized_text: str,
        timestamp: str,
        model_id: str,
        profile_id: str = "default",
        redaction_count: int = 0,
    ) -> str:
        """
        Computes keyed HMAC-SHA256 over canonical sorted-key JSON preimage (PR-06).
        """
        canonical_payload = json.dumps(
            {
                "model_id": model_id,
                "profile_id": profile_id,
                "redaction_count": redaction_count,
                "sanitized_text": sanitized_text,
                "timestamp": timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._node_key, canonical_payload, hashlib.sha256).hexdigest()

    def verify_receipt(
        self,
        receipt_hex: str,
        sanitized_text: str,
        timestamp: str,
        model_id: str,
        profile_id: str = "default",
        redaction_count: int = 0,
    ) -> bool:
        expected = self.compute_receipt(
            sanitized_text=sanitized_text,
            timestamp=timestamp,
            model_id=model_id,
            profile_id=profile_id,
            redaction_count=redaction_count,
        )
        return hmac.compare_digest(receipt_hex, expected)

    def record_operation(
        self,
        operation: str,
        profile_id: str,
        model_id: str,
        execution_mode: str,
        redaction_count: int,
        entity_types: List[str],
        sanitized_text: str,
    ) -> Dict[str, object]:
        """Records a zero-PII audit entry and returns its signed receipt object."""
        now_iso = datetime.now(timezone.utc).isoformat()
        receipt = self.compute_receipt(
            sanitized_text=sanitized_text,
            timestamp=now_iso,
            model_id=model_id,
            profile_id=profile_id,
            redaction_count=redaction_count,
        )
        sanitized_sha256 = hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest()

        with self._lock:
            self._seq += 1
            prev_hash = self._last_hash
            entry_core = {
                "seq": self._seq,
                "timestamp": now_iso,
                "operation": operation,
                "profile_id": profile_id,
                "model_id": model_id,
                "execution_mode": execution_mode,
                "redaction_count": redaction_count,
                "entity_types": sorted(set(entity_types)),
                "sanitized_sha256": sanitized_sha256,
                "compliance_receipt": receipt,
                "prev_hash": prev_hash,
            }
            canonical_entry = json.dumps(
                entry_core, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            entry_hash = hmac.new(self._node_key, canonical_entry, hashlib.sha256).hexdigest()
            entry_core["hash"] = entry_hash
            self._last_hash = entry_hash
            self._entries.append(entry_core)
            return dict(entry_core)

    def get_entries(self, limit: int = 100) -> List[Dict[str, object]]:
        with self._lock:
            items = list(self._entries)
        return items[-max(1, min(limit, 1000)) :]
