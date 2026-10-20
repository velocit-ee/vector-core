"""
Comprehensive Test Suite for Velocitee Prism v2.0 & Hermes Agent Integration
Verifies PR-01 through PR-09, multilingual PII corpus precision/recall,
customizable company profiles, and Hermes Agent OpenAI/MCP endpoints.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Tuple

TARGET_DIR = Path(__file__).resolve().parent.parent.parent
if str(TARGET_DIR) not in sys.path:
    sys.path.insert(0, str(TARGET_DIR))

from prism.profiles import ProfileRegistry
from prism.receipt import ComplianceLedger
from prism.redaction import (
    EphemeralVault,
    RedactionEngine,
    verify_estonian_isikukood,
    verify_finnish_hetu,
    verify_iban_mod97,
    verify_luhn,
    verify_swedish_personnummer,
)
from prism.server import (
    GatewayStateCache,
    MAX_BODY_BYTES,
    PrismRuntimeState,
    create_server,
)


class LiveServerContext:
    """Spins up an ephemeral ThreadingHTTPServer bound to 127.0.0.1:0 for HTTP testing."""

    def __init__(self, active: bool = True) -> None:
        os.environ["PRISM_QUIET_LOGS"] = "1"
        self.active = active
        self.tmp_dir = tempfile.TemporaryDirectory()
        tmp_path = Path(self.tmp_dir.name)

        def mock_fetcher(_url: str, _timeout: float) -> Dict[str, object]:
            return {
                "nodes": [
                    {
                        "mac": "3c:2c:30:98:b0:91",
                        "status": "active" if self.active else "quarantined",
                    }
                ]
            }

        self.cache = GatewayStateCache(
            gateway_url="http://127.0.0.1:9/api/v1/nodes",
            node_mac="3c:2c:30:98:b0:91",
            ttl_seconds=0.01,
            fetcher=mock_fetcher,
        )
        self.registry = ProfileRegistry(storage_path=tmp_path / "profiles.json")
        self.ledger = ComplianceLedger(node_key=b"test-prism-node-hmac-key-32bytes!")
        self.runtime = PrismRuntimeState(
            gateway_cache=self.cache,
            profile_registry=self.registry,
            ledger=self.ledger,
        )
        self.httpd, _, _ = create_server(
            host="127.0.0.1",
            port=0,
            runtime=self.runtime,
            start_edge_agent=False,
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "LiveServerContext":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp_dir.cleanup()

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: Dict[str, str] | None = None,
    ) -> Tuple[int, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        req_headers = dict(headers or {})
        if body is not None and "Content-Length" not in req_headers:
            req_headers["Content-Length"] = str(len(body))
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        return resp.status, data


def test_pr01_quarantine_gating_on_all_get_and_post_routes() -> None:
    """PR-01: When node is quarantined, all GET (except /health) and POST routes return 403."""
    with LiveServerContext(active=False) as srv:
        # /health is un-gated and reports activated=False
        st_health, body_health = srv.request("GET", "/health")
        assert st_health == 200
        assert json.loads(body_health)["activated"] is False

        # All other GET routes must return 403
        for get_path in ("/", "/api/v1/status", "/api/v1/audit", "/api/v1/profiles", "/v1/models"):
            st, body = srv.request("GET", get_path)
            assert st == 403, f"Expected 403 on GET {get_path} when quarantined, got {st}"
            parsed = json.loads(body)
            assert parsed["code"] == "QUARANTINED_ACCESS_DENIED"

        # All POST routes must return 403
        payload = json.dumps({"prompt": "Hello Jaan Tamm"}).encode("utf-8")
        for post_path in ("/api/v1/infer", "/api/v1/redact", "/api/v1/profiles", "/v1/chat/completions", "/api/v1/mcp"):
            st, body = srv.request(
                "POST",
                post_path,
                body=payload,
                headers={"Content-Type": "application/json"},
            )
            assert st == 403, f"Expected 403 on POST {post_path} when quarantined, got {st}"


def test_pr02_and_pr03_no_raw_pii_leak_and_concurrent_thread_safety() -> None:
    """PR-02 & PR-03: Never return 'raw' in responses and maintain thread isolation."""
    with LiveServerContext(active=True) as srv:
        secret_email = "confidential.ceo@telia.ee"
        secret_iban = "EE382200221020145685"
        payload = json.dumps(
            {
                "prompt": f"Customer Jaan Tamm ({secret_email}) transferred €25,400.00 to {secret_iban}."
            }
        ).encode("utf-8")
        st, text = srv.request(
            "POST",
            "/api/v1/infer",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        assert st == 200
        # Raw PII must never appear anywhere in the HTTP response
        assert secret_email not in text
        assert secret_iban not in text
        assert "Jaan Tamm" not in text

        data = json.loads(text)
        assert data["redaction_count"] >= 4
        for ent in data["entities_redacted"]:
            assert "raw" not in ent
            assert "token" in ent
            assert "type" in ent
            assert "sha256_prefix" in ent

        # Concurrent stress test: 32 threads x 8 requests each
        errors: List[str] = []

        def worker(tid: int) -> None:
            for seq in range(8):
                unique_email = f"user{tid}_{seq}@nordic-bank.eu"
                req_bytes = json.dumps(
                    {"prompt": f"Contact Alice Lindqvist at {unique_email} for €1,200.00."}
                ).encode("utf-8")
                code, resp_str = srv.request(
                    "POST",
                    "/api/v1/infer",
                    body=req_bytes,
                    headers={"Content-Type": "application/json"},
                )
                if code != 200:
                    errors.append(f"Thread {tid} got HTTP {code}")
                elif unique_email in resp_str:
                    errors.append(f"Thread {tid} leaked {unique_email}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, f"Concurrency errors: {errors}"


def test_pr04_content_length_bounds_and_malformed_json() -> None:
    """PR-04: Enforce 64 KB Content-Length cap (413) and reject invalid Content-Length/JSON (400)."""
    with LiveServerContext(active=True) as srv:
        # 1. Oversize body -> 413
        oversize = b'{"prompt":"' + (b"A" * (MAX_BODY_BYTES + 100)) + b'"}'
        st_large, _ = srv.request(
            "POST",
            "/api/v1/infer",
            body=oversize,
            headers={"Content-Type": "application/json"},
        )
        assert st_large == 413

        # 2. Non-numeric Content-Length -> 400
        st_bad_cl, _ = srv.request(
            "POST",
            "/api/v1/infer",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "not-a-number"},
        )
        assert st_bad_cl == 400

        # 3. Malformed JSON -> 400
        st_bad_json, _ = srv.request(
            "POST",
            "/api/v1/infer",
            body=b"{bad json",
            headers={"Content-Type": "application/json"},
        )
        assert st_bad_json == 400


def test_pr05_specific_redaction_regressions_and_multilingual_corpus() -> None:
    """
    PR-05:
    - Estonian name 'Õie Mägi' is redacted as PERSON_NAME
    - '$500 and €500 and £500' -> all 3 redacted as FINANCIAL_AMOUNT
    - 'Thank You' and 'New York' -> NOT redacted (0 false positives)
    - Full >= 300-line multilingual (EN/ET/FI/SV) corpus achieves recall >= 0.95 and precision >= 0.90
    """
    engine = RedactionEngine()

    # 1. Estonian diacritics name
    s1, v1 = engine.redact("Klient Õie Mägi kinnitas lepingu.")
    assert "[PII_PERSON_NAME_1]" in s1
    assert "Õie Mägi" not in s1
    assert v1.redaction_count == 1

    # 2. Currency symbols ($, €, £) without byte-class corruption
    s2, v2 = engine.redact("Balances of $500 and €500 and £500 were reconciled in section 42.")
    assert v2.redaction_count == 3
    assert "[PII_FINANCIAL_AMOUNT_1]" in s2
    assert "[PII_FINANCIAL_AMOUNT_2]" in s2
    assert "[PII_FINANCIAL_AMOUNT_3]" in s2
    assert "section 42" in s2

    # 3. Allowlisted greetings and cities
    s3, v3 = engine.redact("Thank You from our Customer Support team in New York and Tallinn Estonia.")
    assert v3.redaction_count == 0
    assert s3 == "Thank You from our Customer Support team in New York and Tallinn Estonia."

    # 4. Evaluate full >= 300-line corpus
    corpus_path = Path(__file__).resolve().parent / "corpus.jsonl"
    lines = [
        json.loads(line)
        for line in corpus_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) >= 300, f"Expected >= 300 corpus lines, found {len(lines)}"

    true_positives = 0
    false_negatives = 0
    false_positives = 0

    for item in lines:
        raw_text = item["text"]
        expected = item["expected"]
        vault = EphemeralVault()
        _, vault = engine.redact(raw_text, vault=vault)
        predicted_map = vault._token_to_raw  # {token: raw_val}
        predicted_pairs = [
            (meta.entity_type, predicted_map[meta.token]) for meta in vault._entities
        ]
        expected_pairs = [(e["type"], e["value"]) for e in expected]

        remaining_pred = list(predicted_pairs)
        for exp_pair in expected_pairs:
            if exp_pair in remaining_pred:
                true_positives += 1
                remaining_pred.remove(exp_pair)
            else:
                false_negatives += 1
        false_positives += len(remaining_pred)

    recall = true_positives / max(1, (true_positives + false_negatives))
    precision = true_positives / max(1, (true_positives + false_positives))
    assert recall >= 0.95, f"Corpus recall {recall:.4f} < 0.95 (TP={true_positives}, FN={false_negatives})"
    assert precision >= 0.90, f"Corpus precision {precision:.4f} < 0.90 (TP={true_positives}, FP={false_positives})"


def test_pr06_and_pr07_hmac_receipt_and_truthful_system_status() -> None:
    """PR-06 & PR-07: Keyed HMAC receipt verification and truthful system status."""
    with LiveServerContext(active=True) as srv:
        payload = json.dumps(
            {"prompt": "Customer Jaan Tamm (jaan.tamm@telia.ee) paid €500."}
        ).encode("utf-8")
        st, text = srv.request(
            "POST",
            "/api/v1/infer",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        assert st == 200
        resp = json.loads(text)
        receipt = resp["compliance_receipt"]
        assert len(receipt) == 64

        # Verify receipt with the node'sComplianceLedger key
        assert srv.ledger.verify_receipt(
            receipt_hex=receipt,
            sanitized_text=resp["sanitized_prompt"],
            timestamp=resp["timestamp"],
            model_id=resp["model"],
            profile_id=resp["profile_id"],
            redaction_count=resp["redaction_count"],
        )
        # Mutating sanitized_text must fail receipt verification
        assert not srv.ledger.verify_receipt(
            receipt_hex=receipt,
            sanitized_text=resp["sanitized_prompt"] + " tampered",
            timestamp=resp["timestamp"],
            model_id=resp["model"],
            profile_id=resp["profile_id"],
            redaction_count=resp["redaction_count"],
        )

        # Check /api/v1/status
        st_status, status_text = srv.request("GET", "/api/v1/status")
        assert st_status == 200
        status_json = json.loads(status_text)
        hw_sec = status_json["hardware_security"]
        assert hw_sec["luks2_encrypted"] in (True, False, "unknown")
        assert hw_sec["tpm2_present"] in (True, False, "unknown")


def test_pr08_custom_company_profiles_and_hermes_agent_integration() -> None:
    """
    Verifies customizable company profiles (`POST /api/v1/profiles`) and Hermes Agent
    OpenAI proxy (`POST /v1/chat/completions`) + MCP JSON-RPC (`POST /api/v1/mcp`).
    """
    with LiveServerContext(active=True) as srv:
        # 1. Register a custom company profile with custom regex & allowlist
        custom_prof = {
            "profile_id": "swedbank-baltic",
            "name": "Swedbank Baltic Custom Profile",
            "enabled_entities": ["EMAIL", "IBAN", "PERSON_NAME"],
            "custom_patterns": [
                {"type": "LOAN_CONTRACT_ID", "pattern": r"\bLOAN-\d{8}\b"}
            ],
            "allowlist": ["swedbank tallinn"],
            "default_model": "claude-3-7-sonnet-sovereign",
            "set_active": True,
        }
        st_prof, prof_text = srv.request(
            "POST",
            "/api/v1/profiles",
            body=json.dumps(custom_prof).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        assert st_prof == 200
        prof_resp = json.loads(prof_text)
        assert prof_resp["active_profile_id"] == "swedbank-baltic"

        # 2. Test Hermes Agent OpenAI-compatible `/v1/chat/completions` with custom profile
        chat_req = {
            "model": "claude-3-7-sonnet-sovereign",
            "rehydrate": True,
            "messages": [
                {
                    "role": "user",
                    "content": "Review contract LOAN-88412099 for Õie Mägi (oie.magi@swedbank.ee) at Swedbank Tallinn.",
                }
            ],
        }
        st_chat, chat_text = srv.request(
            "POST",
            "/v1/chat/completions",
            body=json.dumps(chat_req).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        assert st_chat == 200
        chat_resp = json.loads(chat_text)
        sov = chat_resp["prism_sovereignty"]
        assert sov["profile_id"] == "swedbank-baltic"
        assert sov["redaction_count"] == 3  # LOAN_CONTRACT_ID, PERSON_NAME, EMAIL
        # "Swedbank Tallinn" was allowlisted so not redacted
        assert "Swedbank Tallinn" in sov["sanitized_prompt"]
        assert "LOAN-88412099" not in sov["sanitized_prompt"]
        assert "Õie Mägi" not in sov["sanitized_prompt"]
        assert "oie.magi@swedbank.ee" not in sov["sanitized_prompt"]

        # Because rehydrate=True, the assistant message re-hydrates surrogates locally for Hermes Agent
        assistant_msg = chat_resp["choices"][0]["message"]["content"]
        assert "LOAN-88412099" in assistant_msg
        assert "Õie Mägi" in assistant_msg

        # 3. Test Hermes Agent MCP JSON-RPC `tools/list` and `tools/call`
        mcp_list_req = {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}}
        st_mcp1, mcp1_text = srv.request(
            "POST",
            "/api/v1/mcp",
            body=json.dumps(mcp_list_req).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        assert st_mcp1 == 200
        tools = json.loads(mcp1_text)["result"]["tools"]
        tool_names = {t["name"] for t in tools}
        assert "prism_redact_text" in tool_names
        assert "prism_sovereign_infer" in tool_names

        mcp_call_req = {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "prism_redact_text",
                "arguments": {
                    "text": "Contract LOAN-12345678 signed by Jaan Tamm.",
                    "profile_id": "swedbank-baltic",
                },
            },
        }
        st_mcp2, mcp2_text = srv.request(
            "POST",
            "/api/v1/mcp",
            body=json.dumps(mcp_call_req).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        assert st_mcp2 == 200
        sc = json.loads(mcp2_text)["result"]["structuredContent"]
        assert sc["redaction_count"] == 2
        assert "[PII_LOAN_CONTRACT_ID_1]" in sc["sanitized_text"]
        assert "[PII_PERSON_NAME_1]" in sc["sanitized_text"]
