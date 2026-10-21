"""
Velocitee Prism — Sovereign AI Hub & Hermes Agent Privacy Proxy Server
Implements PR-01 through PR-09.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .edge_agent import EdgeProvisioningAgent
from .hermes_bridge import (
    build_hermes_manifest,
    handle_mcp_jsonrpc,
    handle_openai_chat_completions,
)
from .model_client import execute_model_inference
from .profiles import ProfileRegistry
from .receipt import ComplianceLedger
from .redaction import EphemeralVault
from .system_status import collect_system_status


MAX_BODY_BYTES = 65536  # 64 KB cap (PR-04)

DEFAULT_GATEWAY_URL = os.environ.get(
    "GATEWAY_API_URL", "http://192.168.8.1:8088/api/v1/nodes"
)
DEFAULT_NODE_MAC = os.environ.get("PRISM_NODE_MAC", "3c:2c:30:98:b0:91").lower()
DEFAULT_PORT = int(os.environ.get("PRISM_PORT", "8090"))


class GatewayStateCache:
    """
    Thread-safe gateway node status checker with 1.0s TTL cache (PR-01).
    Fails closed (returns False) if the gateway is unreachable or the node is not `active`.
    """

    def __init__(
        self,
        gateway_url: str = DEFAULT_GATEWAY_URL,
        node_mac: str = DEFAULT_NODE_MAC,
        ttl_seconds: float = 1.0,
        fetcher: Optional[Callable[[str, float], Dict[str, object]]] = None,
    ) -> None:
        self._lock = threading.Lock()
        self.gateway_url = gateway_url
        self.node_mac = node_mac.lower()
        self.ttl_seconds = ttl_seconds
        self._fetcher = fetcher or self._default_fetch
        self._cached_active: bool = False
        self._cached_status: str = "quarantined"
        self._last_check: float = 0.0

    @staticmethod
    def _default_fetch(url: str, timeout: float) -> Dict[str, object]:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def invalidate(self) -> None:
        with self._lock:
            self._last_check = 0.0

    def check_node_active(self) -> Tuple[bool, str]:
        now = time.monotonic()
        with self._lock:
            if (now - self._last_check) < self.ttl_seconds and self._last_check > 0.0:
                return self._cached_active, self._cached_status

        active = False
        node_status = "unreachable"
        try:
            data = self._fetcher(self.gateway_url, 1.5)
            nodes = data if isinstance(data, list) else data.get("nodes", [])
            if isinstance(nodes, list):
                for n in nodes:
                    if isinstance(n, dict) and str(n.get("mac", "")).lower() == self.node_mac:
                        node_status = str(n.get("status", "quarantined"))
                        active = node_status == "active"
                        break
        except Exception:
            active = False
            node_status = "gateway_unreachable"

        with self._lock:
            self._cached_active = active
            self._cached_status = node_status
            self._last_check = time.monotonic()
        return active, node_status


def render_dashboard_html(active_profile_id: str) -> str:
    """Renders the Sovereign Hub interactive web console when node is active."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Velocitee Prism v2.0 — Sovereign AI & Hermes Agent Hub</title>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif; background: #090d16; color: #e2e8f0; margin: 0; padding: 24px; }}
  .container {{ max-width: 1080px; margin: 0 auto; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }}
  .badge {{ background: #065f46; color: #6ee7b7; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  textarea, select, input {{ width: 100%; background: #0b0f19; color: #f8fafc; border: 1px solid #334155; border-radius: 6px; padding: 10px; font-family: monospace; box-sizing: border-box; margin-top: 6px; margin-bottom: 12px; }}
  button {{ background: #6d28d9; color: white; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 600; cursor: pointer; }}
  button:hover {{ background: #7c3aed; }}
  pre {{ background: #060911; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: 1px solid #1e293b; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <h1 style="margin:0;font-size:22px;">Velocitee Prism v2.0 — Sovereign AI &amp; Hermes Agent Hub</h1>
      <p style="margin:4px 0 0;color:#94a3b8;font-size:13px;">Active Company Profile: <strong>{active_profile_id}</strong> | OpenAI Proxy: <code>/v1/chat/completions</code> | MCP: <code>/api/v1/mcp</code></p>
    </div>
    <span class="badge">VLAN 10 ACTIVE</span>
  </div>
  <div class="card">
    <h3 style="margin-top:0;">Interactive Sovereign Redaction &amp; Hybrid Model Router</h3>
    <label>Company Profile</label>
    <select id="profile">
      <option value="default">default — European Enterprise Sovereign Default</option>
      <option value="telia-nordic-core">telia-nordic-core — Telia Nordic &amp; Baltic Telecom Core</option>
      <option value="eu-finserv-strict">eu-finserv-strict — EU Financial Services DORA Strict</option>
      <option value="hermes-hybrid-agent">hermes-hybrid-agent — Nous Hermes Agent Multi-Tool Profile</option>
    </select>
    <label>Target Model Route</label>
    <select id="model">
      <option value="prism-sovereign-local">prism-sovereign-local (On-Premises Zero Marginal Cost)</option>
      <option value="claude-3-7-sonnet-sovereign">claude-3-7-sonnet-sovereign (Sanitized Cloud API)</option>
      <option value="gpt-4o-sovereign">gpt-4o-sovereign (Sanitized Cloud API)</option>
      <option value="hermes-3-llama-70b">hermes-3-llama-70b (Nous Hermes 3 via OpenRouter)</option>
    </select>
    <label>Enterprise Prompt (PII is redacted into ephemeral surrogates before model routing)</label>
    <textarea id="prompt" rows="4">Customer Jaan Tamm (Estonian ID 38504120256, email jaan.tamm@telia.ee, phone +372 5551234) authorized wire transfer of €25,400.00 to IBAN EE382200221020145685.</textarea>
    <button onclick="runInfer()">Sanitize &amp; Execute Sovereign Inference</button>
    <pre id="output">Ready.</pre>
  </div>
</div>
<script>
async function runInfer() {{
  const prompt = document.getElementById('prompt').value;
  const profile_id = document.getElementById('profile').value;
  const model = document.getElementById('model').value;
  const out = document.getElementById('output');
  out.textContent = 'Processing...';
  const res = await fetch('/api/v1/infer', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{prompt, profile_id, model}})
  }});
  const data = await res.json();
  out.textContent = JSON.stringify(data, null, 2);
}}
</script>
</body>
</html>"""


class PrismRuntimeState:
    """Encapsulates all runtime services for Velocitee Prism without global PII state."""

    def __init__(
        self,
        gateway_cache: Optional[GatewayStateCache] = None,
        profile_registry: Optional[ProfileRegistry] = None,
        ledger: Optional[ComplianceLedger] = None,
    ) -> None:
        self.gateway_cache = gateway_cache or GatewayStateCache()
        self.profile_registry = profile_registry or ProfileRegistry()
        self.ledger = ledger or ComplianceLedger()


def make_prism_handler(runtime: PrismRuntimeState):
    """Creates a request handler class bound to `runtime`."""

    class PrismRequestHandler(BaseHTTPRequestHandler):
        server_version = "VelociteePrism/2.0.0"

        def log_message(self, format_str: str, *args: object) -> None:
            if os.environ.get("PRISM_QUIET_LOGS") == "1":
                return
            super().log_message(format_str, *args)

        def _send_json(self, status_code: int, payload: Dict[str, object]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()
            self.wfile.write(raw)

        def _send_html(self, status_code: int, html: str) -> None:
            raw = html.encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _read_json_body(self) -> Tuple[Optional[Dict[str, object]], Optional[Tuple[int, Dict[str, object]]]]:
            """
            Validates Content-Length (<= 64 KB, PR-04) and parses JSON body.
            Returns `(parsed_dict, None)` on success or `(None, (http_code, err_dict))` on failure.
            """
            cl_header = self.headers.get("Content-Length")
            if cl_header is None:
                return None, (400, {"error": "Missing Content-Length header", "code": "MISSING_CONTENT_LENGTH"})
            try:
                content_length = int(cl_header)
            except ValueError:
                return None, (400, {"error": "Invalid Content-Length header", "code": "INVALID_CONTENT_LENGTH"})

            if content_length < 0:
                return None, (400, {"error": "Negative Content-Length header", "code": "INVALID_CONTENT_LENGTH"})
            if content_length > MAX_BODY_BYTES:
                return None, (
                    413,
                    {
                        "error": f"Payload exceeds maximum size of {MAX_BODY_BYTES} bytes",
                        "code": "PAYLOAD_TOO_LARGE",
                    },
                )
            if content_length == 0:
                return {}, None

            raw_bytes = self.rfile.read(content_length)
            try:
                decoded = raw_bytes.decode("utf-8")
                parsed = json.loads(decoded)
            except (UnicodeDecodeError, ValueError):
                return None, (400, {"error": "Malformed UTF-8 or JSON payload", "code": "MALFORMED_JSON"})

            if not isinstance(parsed, dict):
                return None, (400, {"error": "JSON body must be an object", "code": "INVALID_JSON_ROOT"})
            return parsed, None

        def _enforce_node_active(self) -> bool:
            """
            Enforces PR-01 quarantine gating across all GET and POST routes (except /health).
            Returns True if active, or writes a 403 Forbidden response and returns False.
            """
            is_active, gw_status = runtime.gateway_cache.check_node_active()
            if is_active:
                return True
            self._send_json(
                403,
                {
                    "error": "Node is quarantined in VLAN 999. Claim node via Vector Gateway to activate Sovereign Hub.",
                    "code": "QUARANTINED_ACCESS_DENIED",
                    "activated": False,
                    "gateway_node_status": gw_status,
                },
            )
            return False

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def do_GET(self) -> None:
            parsed_url = urlparse(self.path)
            path = parsed_url.path

            # /health is the ONLY un-gated endpoint so health monitors can inspect activation state
            if path == "/health":
                is_active, gw_status = runtime.gateway_cache.check_node_active()
                self._send_json(
                    200,
                    {
                        "status": "online",
                        "activated": is_active,
                        "gateway_node_status": gw_status,
                        "version": "2.0.0",
                    },
                )
                return

            # PR-01: Gate ALL other GET routes on node activation
            if not self._enforce_node_active():
                return

            if path in ("/", "/index.html"):
                self._send_html(
                    200,
                    render_dashboard_html(runtime.profile_registry.get_active_profile_id()),
                )
                return

            if path == "/api/v1/status":
                is_active, gw_status = runtime.gateway_cache.check_node_active()
                self._send_json(
                    200,
                    collect_system_status(
                        activated=is_active,
                        gateway_status=gw_status,
                        active_profile_id=runtime.profile_registry.get_active_profile_id(),
                    ),
                )
                return

            if path == "/api/v1/audit":
                qs = parse_qs(parsed_url.query)
                limit = 100
                if "limit" in qs:
                    try:
                        limit = int(qs["limit"][0])
                    except ValueError:
                        limit = 100
                entries = runtime.ledger.get_entries(limit=limit)
                self._send_json(
                    200,
                    {
                        "count": len(entries),
                        "entries": entries,
                    },
                )
                return

            if path == "/api/v1/profiles":
                self._send_json(
                    200,
                    {
                        "active_profile_id": runtime.profile_registry.get_active_profile_id(),
                        "profiles": runtime.profile_registry.list_profiles(),
                    },
                )
                return

            if path == "/api/v1/hermes/manifest":
                host_hdr = self.headers.get("Host", f"192.168.8.200:{DEFAULT_PORT}")
                manifest = build_hermes_manifest(f"http://{host_hdr}", runtime.profile_registry)
                self._send_json(200, manifest)
                return

            if path == "/v1/models":
                prof = runtime.profile_registry.get_profile()
                routing = prof.get("model_routing", {})
                models_list = []
                if isinstance(routing, dict):
                    for mid, mcfg in routing.items():
                        models_list.append(
                            {
                                "id": mid,
                                "object": "model",
                                "owned_by": "velocitee-prism",
                                "metadata": mcfg,
                            }
                        )
                self._send_json(200, {"object": "list", "data": models_list})
                return

            self._send_json(404, {"error": "Endpoint not found", "path": path})

        def do_POST(self) -> None:
            parsed_url = urlparse(self.path)
            path = parsed_url.path

            # PR-04: Validate Content-Length and JSON structure before processing
            body, err = self._read_json_body()
            if err is not None:
                self._send_json(err[0], err[1])
                return
            assert body is not None

            # PR-01: Enforce node activation across all POST routes
            if not self._enforce_node_active():
                return

            if path in ("/api/v1/infer", "/api/v1/redact"):
                prompt = body.get("prompt", body.get("text"))
                if not isinstance(prompt, str) or not prompt.strip():
                    self._send_json(
                        400,
                        {"error": "Missing or empty 'prompt' string", "code": "MISSING_PROMPT"},
                    )
                    return

                profile_id = str(
                    body.get("profile_id") or runtime.profile_registry.get_active_profile_id()
                )
                profile = runtime.profile_registry.get_profile(profile_id)
                engine = runtime.profile_registry.build_engine(profile_id)
                requested_model = (
                    str(body["model"]) if isinstance(body.get("model"), str) else None
                )

                # PR-02 & PR-03: Ephemeral per-request vault, cleared in finally block
                vault = EphemeralVault()
                try:
                    sanitized_prompt, _ = engine.redact(prompt, vault=vault)
                    entities = vault.public_entities
                    redaction_count = vault.redaction_count

                    if path == "/api/v1/redact":
                        now_iso = datetime.now(timezone.utc).isoformat()
                        audit_entry = runtime.ledger.record_operation(
                            operation="REDACT_ONLY",
                            profile_id=profile_id,
                            model_id="redaction-only",
                            execution_mode="deterministic_redactor",
                            redaction_count=redaction_count,
                            entity_types=[str(e["type"]) for e in entities],
                            sanitized_text=sanitized_prompt,
                        )
                        self._send_json(
                            200,
                            {
                                "sanitized_prompt": sanitized_prompt,
                                "redaction_count": redaction_count,
                                "entities_redacted": entities,
                                "profile_id": profile_id,
                                "compliance_receipt": audit_entry["compliance_receipt"],
                                "timestamp": now_iso,
                            },
                        )
                        return

                    infer_res = execute_model_inference(
                        sanitized_prompt=sanitized_prompt,
                        entities=entities,
                        profile=profile,
                        requested_model=requested_model,
                    )
                    audit_entry = runtime.ledger.record_operation(
                        operation="SOVEREIGN_INFER",
                        profile_id=profile_id,
                        model_id=str(infer_res["model_id"]),
                        execution_mode=str(infer_res["execution_mode"]),
                        redaction_count=redaction_count,
                        entity_types=[str(e["type"]) for e in entities],
                        sanitized_text=sanitized_prompt,
                    )

                    self._send_json(
                        200,
                        {
                            "sanitized_prompt": sanitized_prompt,
                            "redaction_count": redaction_count,
                            "entities_redacted": entities,
                            "output": infer_res["output_text"],
                            "model": infer_res["model_id"],
                            "upstream_model": infer_res["upstream_model"],
                            "provider": infer_res["provider"],
                            "billing_mode": infer_res["billing_mode"],
                            "execution_mode": infer_res["execution_mode"],
                            "profile_id": profile_id,
                            "compliance_receipt": audit_entry["compliance_receipt"],
                            "timestamp": audit_entry["timestamp"],
                            "latency_ms": infer_res["latency_ms"],
                        },
                    )
                finally:
                    vault.clear()
                return

            if path == "/api/v1/profiles":
                try:
                    set_active = bool(body.get("set_active", False))
                    updated = runtime.profile_registry.upsert_profile(body, set_active=set_active)
                    self._send_json(
                        200,
                        {
                            "status": "updated",
                            "active_profile_id": runtime.profile_registry.get_active_profile_id(),
                            "profile": updated,
                        },
                    )
                except ValueError as exc:
                    self._send_json(400, {"error": str(exc), "code": "INVALID_PROFILE"})
                return

            if path == "/v1/chat/completions":
                status_code, resp_obj = handle_openai_chat_completions(
                    body, runtime.profile_registry, runtime.ledger
                )
                self._send_json(status_code, resp_obj)
                return

            if path == "/api/v1/mcp":
                status_code, resp_obj = handle_mcp_jsonrpc(
                    body, runtime.profile_registry, runtime.ledger
                )
                self._send_json(status_code, resp_obj)
                return

            self._send_json(404, {"error": "Endpoint not found", "path": path})

    return PrismRequestHandler


def create_server(
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    runtime: Optional[PrismRuntimeState] = None,
    start_edge_agent: bool = True,
) -> Tuple[ThreadingHTTPServer, PrismRuntimeState, Optional[EdgeProvisioningAgent]]:
    state = runtime or PrismRuntimeState()
    handler_cls = make_prism_handler(state)
    httpd = ThreadingHTTPServer((host, port), handler_cls)
    agent: Optional[EdgeProvisioningAgent] = None
    if start_edge_agent and os.environ.get("PRISM_DISABLE_EDGE_AGENT") != "1":
        agent = EdgeProvisioningAgent(
            gateway_nodes_url=state.gateway_cache.gateway_url,
            node_mac=state.gateway_cache.node_mac,
            on_activated=state.gateway_cache.invalidate,
        )
        agent.start()
    return httpd, state, agent
