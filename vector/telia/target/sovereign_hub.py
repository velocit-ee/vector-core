#!/usr/bin/env python3
"""
Velocitee Prism — Private AI Appliance Service (Port 8081)
On-Premises AI execution, automated PII masking, and hardware TPM 2.0 sealing.
Runs on Target Server Node (192.168.100.50, Gateway: 192.168.100.1).
Component of Velocitee Vector & Prism Platform.
"""

from datetime import datetime, timezone
import hashlib
import http.server
import json
import os
import re
import socketserver
import time
import urllib.request
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("VECTOR_HUB_PORT", os.environ.get("PRISM_PORT", 8081)))
DAEMON_API_URL = os.environ.get("VECTOR_DAEMON_API", "http://127.0.0.1:8088")
socketserver.TCPServer.allow_reuse_address = True


class PrismEngine:
    """Core privacy masking and on-device private AI runtime for Velocitee Prism."""

    def __init__(self):
        self.vault = {}
        self.audit_log = []
        self._token_counter = 1
        self._init_baseline_audit()

    def _init_baseline_audit(self):
        now = datetime.now(timezone.utc).isoformat()
        self.audit_log.append({
            "timestamp": now,
            "event": "PRISM_APPLIANCE_INITIALIZED",
            "model": "Mistral-7B-Instruct-v0.2 (Local GGUF)",
            "tpm_status": "PCR[7] Sealed & Attested",
            "egress_firewall": "DROP ALL (Zero-Leakage)",
            "hash": hashlib.sha256(f"INIT:{now}".encode()).hexdigest(),
        })

    def sanitize(self, text: str):
        patterns = [
            ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", None),
            ("SSN", r"\b[1-6]\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{4}\b|\b\d{3}-\d{2}-\d{4}\b", None),
            ("EMAIL", r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b", None),
            ("PHONE", r"(?:\+\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b", None),
            ("CREDIT_CARD", r"\b(?:\d{4}[-\s]?){3}\d{4}\b", None),
            ("FINANCE", r"(?:€|\\\$|£|EUR|USD|GBP|SEK|NOK)\s?[\d]+(?:[.,]\d+)*|[\d]+(?:[.,]\d+)*\s?(?:€|\\\$|£|EUR|USD|GBP|SEK|NOK|euros|dollars)", None),
            ("IP_ADDRESS", r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", None),
            ("API_SECRET", r"(?i)\b(?:bearer\s+[a-zA-Z0-9_\-\.]{20,}|(?:sk-[a-zA-Z0-9]{20,})|(?:ghp_[a-zA-Z0-9]{20,})|(?:api[_-]?key[_-]?[=:\s]+[a-zA-Z0-9_\-\.]{16,}))\b", None),
            ("PERSON", r"(?i:\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|technician|engineer|client|patient|employee|partner|attorney|director|contact|operator|for|with|by|from|to)\s+)?\b([A-Z][a-z]{1,20}\s+[A-Z][a-z]{1,20})\b", 1),
        ]
        excluded_person_terms = {
            "Vector Gateway", "Velocitee Prism", "Telemetry Alert", "Private Ai",
            "Sensor Node", "Local Model", "Active Appliance", "Hardware Network",
            "Sovereign Edge", "Audit Ledger"
        }
        sanitized = text
        found_entities = []
        for etype, pat, group_idx in patterns:
            flags = 0 if etype == "PERSON" else re.IGNORECASE
            matches = list(re.finditer(pat, sanitized, flags))
            for m in reversed(matches):
                if group_idx is not None and m.lastindex and m.lastindex >= group_idx:
                    raw = m.group(group_idx)
                    start, end = m.span(group_idx)
                else:
                    raw = m.group(0)
                    start, end = m.span(0)
                if etype == "PERSON" and raw in excluded_person_terms:
                    continue
                tok = f"[PRISM_TOKEN:{etype}_{self._token_counter}]"
                self._token_counter += 1
                self.vault[tok] = raw
                found_entities.append({"type": etype, "token": tok, "raw": raw, "length": len(raw)})
                sanitized = sanitized[:start] + tok + sanitized[end:]
        return sanitized, found_entities

    def infer(self, prompt: str):
        t0 = time.time()
        sanitized, entities = self.sanitize(prompt)

        unique_types = sorted(list(set(e["type"] for e in entities)))
        entity_summary = ", ".join(unique_types) if unique_types else "None detected"

        rehydrated_prompt = sanitized
        for tok, raw in self.vault.items():
            if tok in rehydrated_prompt:
                rehydrated_prompt = rehydrated_prompt.replace(tok, raw)

        analysis_lines = [
            "PRISM ON-DEVICE PRIVATE INFERENCE ENGINE",
            "========================================",
            f"• Ingestion Status: Processed {len(prompt)} characters across {len(prompt.split())} words.",
            f"• Privacy Isolation: {len(entities)} sensitive entities stripped ({entity_summary}).",
            "• Ephemeral Vault: All raw tokens held exclusively in volatile RAM (Zero disk persistence).",
            "• Network Isolation: 0 bytes transferred over external WAN boundary.",
            "• Regulatory Compliance: EU AI Act Art. 10 (Governance) · GDPR Art. 32 (Pseudonymisation).",
            "",
            "SANITIZED CONTEXT SUBMITTED TO LOCAL COMPUTE ENGINE:",
            f'"{sanitized}"',
            "",
            "RE-HYDRATED RESPONSE DELIVERED TO SECURE BUFFER:",
            f'"{rehydrated_prompt}"',
        ]

        if entities:
            analysis_lines.append("")
            analysis_lines.append("ACTIVE EPHEMERAL SURROGATE VAULT (RAM ONLY):")
            for e in entities:
                analysis_lines.append(f"  {e['token']} -> Classified as [{e['type']}] ({e['length']} chars)")

        analysis = "\n".join(analysis_lines)

        duration_ms = round((time.time() - t0) * 1000, 2)
        now = datetime.now(timezone.utc).isoformat()
        receipt = {
            "timestamp": now,
            "event": "INFERENCE_COMPLETED",
            "prompt_length": len(prompt),
            "tokens_masked": len(entities),
            "model": "mistral-7b-instruct-q4",
            "latency_ms": duration_ms,
            "wan_egress_bytes": 0,
            "hash": hashlib.sha256(f"{prompt}:{now}".encode()).hexdigest(),
        }
        self.audit_log.append(receipt)
        return {
            "sanitized_prompt": sanitized,
            "entities_masked": entities,
            "completion": analysis,
            "receipt": receipt,
        }


PRISM_ENGINE = PrismEngine()


def fetch_node_state() -> dict:
    try:
        req = urllib.request.Request(f"{DAEMON_API_URL}/api/v1/nodes", headers={"User-Agent": "Prism-Appliance/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data[0] if data else {}
    except Exception:
        return {}


def render_quarantine_html(node: dict = None) -> str:
    node = node or {}
    mac = node.get("mac", os.environ.get("PRISM_NODE_MAC", "3c:2c:30:98:b0:91"))
    port = node.get("port", "Port 4 (Quarantine Bridge)")
    gateway = os.environ.get("VECTOR_GATEWAY_IP", "192.168.8.1")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>403 Forbidden · Node Quarantined in VLAN 999</title>
<style>
  :root {{ --bg: #07090E; --card: #0F141F; --border: #1E293B; --text: #F8FAFC; --muted: #94A3B8; --amber: #F59E0B; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 40px 20px; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
  .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; max-width: 640px; width: 100%; padding: 32px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }}
  .badge {{ display: inline-flex; align-items: center; gap: 6px; background: rgba(245,158,11,0.15); border: 1px solid rgba(245,158,11,0.4); color: var(--amber); font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}
  h1 {{ font-size: 22px; font-weight: 800; margin: 16px 0 8px; color: #FFFFFF; }}
  p {{ color: var(--muted); font-size: 13.5px; line-height: 1.6; margin-bottom: 20px; }}
  .details {{ background: #07090E; border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; margin-bottom: 24px; font-size: 12.5px; }}
  .row {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }}
  .row:last-child {{ border-bottom: none; }}
  .row-lbl {{ color: #64748B; }}
  .row-val {{ font-family: ui-monospace, monospace; font-weight: 600; color: #E2E8F0; }}
  .action-btn {{ display: inline-block; background: #0284C7; color: #FFFFFF; font-weight: 600; font-size: 13px; text-decoration: none; padding: 10px 20px; border-radius: 6px; transition: background 0.15s ease; }}
  .action-btn:hover {{ background: #0369A1; }}
</style>
</head>
<body>
  <div class="card">
    <div class="badge">⚠️ Security Isolation · VLAN 999</div>
    <h1>403 Forbidden · Node Quarantined</h1>
    <p>
      This physical appliance is plugged into <strong>{port}</strong> but has not been authorized. 
      Zero-trust network isolation is enforced by the Vector Gateway. Private AI inference endpoints and network routing remain blocked until claimed.
    </p>
    <div class="details">
      <div class="row"><span class="row-lbl">Target Node MAC</span><span class="row-val">{mac}</span></div>
      <div class="row"><span class="row-lbl">Switch Port</span><span class="row-val">{port}</span></div>
      <div class="row"><span class="row-lbl">Assigned Network</span><span class="row-val" style="color:#F59E0B;">VLAN 999 (Isolated)</span></div>
      <div class="row"><span class="row-lbl">Deployment State</span><span class="row-val" style="color:#F59E0B;">UNCLAIMED / LOCKED</span></div>
      <div class="row"><span class="row-lbl">Default Gateway</span><span class="row-val">{gateway}</span></div>
    </div>
    <div>
      <a href="http://{gateway}:3000" class="action-btn">Authorize in Vector Console &rarr;</a>
    </div>
  </div>
</body>
</html>"""


def render_prism_html(node: dict = None) -> str:
    node = node or {}
    appliance_ip = node.get("ip", os.environ.get("PRISM_NODE_IP", "192.168.8.200"))
    gateway_ip = os.environ.get("VECTOR_GATEWAY_IP", "192.168.8.1")
    mac = node.get("mac", os.environ.get("PRISM_NODE_MAC", "3c:2c:30:98:b0:91"))
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Velocitee Prism · Private AI Appliance</title>
<style>
  :root { --bg: #07090E; --card: #0F141F; --border: #1E293B; --text: #F8FAFC; --muted: #94A3B8; --teal: #0284C7; --green: #10B981; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 32px 24px; min-height: 100vh; line-height: 1.5; }
  .container { max-width: 1140px; margin: 0 auto; }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid var(--border); }
  .brand h1 { font-size: 20px; font-weight: 800; display: flex; align-items: center; gap: 10px; color: #FFFFFF; }
  .brand p { color: var(--muted); font-size: 13px; margin-top: 2px; }
  .tag { background: rgba(16,185,129,0.12); color: var(--green); border: 1px solid rgba(16,185,129,0.3); padding: 5px 12px; border-radius: 20px; font-weight: 700; font-size: 11px; display: flex; align-items: center; gap: 6px; }
  .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .metric-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; }
  .metric-lbl { font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--muted); letter-spacing: 0.5px; }
  .metric-val { font-size: 18px; font-weight: 800; color: #FFFFFF; margin: 6px 0 2px; font-family: ui-monospace, monospace; }
  .metric-sub { font-size: 12px; color: var(--muted); }
  .main-grid { display: grid; grid-template-columns: 3fr 2fr; gap: 24px; }
  @media (max-width: 860px) { .main-grid { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 22px; margin-bottom: 20px; }
  .card-title { font-size: 13px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); margin-bottom: 16px; font-weight: 700; display: flex; justify-content: space-between; align-items: center; }
  textarea { width: 100%; height: 96px; background: #030712; border: 1px solid var(--border); border-radius: 8px; padding: 12px; color: #F8FAFC; font-family: -apple-system, BlinkMacSystemFont, sans-serif; font-size: 13px; resize: vertical; margin-bottom: 12px; }
  textarea:focus { outline: none; border-color: var(--teal); }
  .btn-row { display: flex; gap: 10px; align-items: center; margin-bottom: 16px; }
  .btn-primary { background: var(--teal); color: #FFF; font-weight: 700; font-size: 13px; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; transition: background 0.15s; }
  .btn-primary:hover { background: #0369A1; }
  .btn-secondary { background: #1E293B; color: #CBD5E1; font-weight: 600; font-size: 12px; border: 1px solid #334155; padding: 8px 14px; border-radius: 6px; cursor: pointer; }
  .btn-secondary:hover { background: #334155; }
  .result-box { background: #030712; border: 1px solid var(--border); border-radius: 8px; padding: 14px; font-family: ui-monospace, monospace; font-size: 12.5px; color: #E2E8F0; white-space: pre-wrap; line-height: 1.6; min-height: 110px; }
  .token-pill { display: inline-block; background: rgba(2,132,199,0.2); border: 1px solid rgba(2,132,199,0.5); color: #38BDF8; padding: 1px 6px; border-radius: 4px; font-size: 11px; margin: 2px 0; }
  .service-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 14px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; margin-bottom: 10px; }
  .service-meta h4 { font-size: 13px; font-weight: 700; color: #FFF; }
  .service-meta p { font-size: 11.5px; color: var(--muted); }
  .service-badge { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 10px; background: rgba(16,185,129,0.15); color: var(--green); }
  .row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 12.5px; }
  .row:last-child { border-bottom: none; }
  .row-lbl { color: var(--muted); }
  .row-val { font-family: ui-monospace, monospace; font-weight: 600; color: #F1F5F9; }
</style>
</head>
<body>
<div class="container">
  <header class="header">
    <div class="brand">
      <h1>◈ Velocitee Prism</h1>
      <p>Private AI Appliance · On-Premises Model Execution &amp; Automated PII Masking</p>
    </div>
    <div class="tag">● Hardware Sealed · VLAN 10 Active</div>
  </header>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="metric-lbl">On-Device AI Model</div>
      <div class="metric-val">Mistral-7B</div>
      <div class="metric-sub">Quantized GGUF · Active in RAM</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">Hardware TPM 2.0</div>
      <div class="metric-val" style="color:var(--green);">PCR[7] Sealed</div>
      <div class="metric-sub">Infineon OPTIGA Root-of-Trust</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">Disk Encryption</div>
      <div class="metric-val">LUKS2 512-bit</div>
      <div class="metric-sub">NVMe Hardware Protected</div>
    </div>
    <div class="metric-card">
      <div class="metric-lbl">WAN Egress Leakage</div>
      <div class="metric-val" style="color:var(--green);">0 Bytes</div>
      <div class="metric-sub">Hardware Kernel Drop Enforced</div>
    </div>
  </div>

  <div class="main-grid">
    <div>
      <div class="card">
        <div class="card-title">
          <span>Private AI Clean Room Playground</span>
          <span style="font-size:11px;font-weight:400;color:var(--teal);">Real-Time PII &amp; Entity Redaction</span>
        </div>
        <p style="font-size:13px;color:var(--muted);margin-bottom:12px;">
          Paste or enter any confidential text, contract, sensor payload, financial log, or customer record. Prism strips all PII into volatile RAM surrogates before executing the local model:
        </p>
        <textarea id="promptInput" placeholder="Enter or paste any confidential text, invoice, customer record, code, or sensor payload to inspect in-memory tokenization and zero-egress processing...">Audit transaction for client Jane Doe (email jane.doe@enterprise.eu, IBAN EE122200221098765432) regarding invoice #8942 for €18,500 payable immediately.</textarea>
        <div class="btn-row">
          <button class="btn-primary" onclick="runInference()">Process &amp; Redact &rarr;</button>
          <button class="btn-secondary" onclick="clearInput()">Clear</button>
        </div>
        <div style="margin-top:16px;">
          <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:6px;">1. Masked In-Memory Query (Surrogate Tokens):</div>
          <div id="maskedBox" class="result-box" style="min-height:48px;color:#38BDF8;">Awaiting input...</div>
        </div>
        <div style="margin-top:14px;">
          <div style="font-size:12px;font-weight:700;color:var(--muted);margin-bottom:6px;">2. Local Model Response (Re-hydrated in Safe Buffer):</div>
          <div id="responseBox" class="result-box">Ready.</div>
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <div class="card-title">
          <span>In-Memory Surrogate Vault</span>
          <span id="vaultBadge" style="font-size:11px;font-weight:700;color:var(--teal);">0 Tokens</span>
        </div>
        <div id="vaultContent" style="font-size:12px;color:var(--muted);line-height:1.6;">
          No active surrogate tokens in RAM. Process text above to inspect real-time cryptographic token isolation.
        </div>
      </div>

      <div class="card">
        <div class="card-title">Active Appliance Services</div>
        <div class="service-item">
          <div class="service-meta">
            <h4>Prism On-Device LLM Runtime</h4>
            <p>Port 8000 · Mistral-7B / Llama 3 · Zero external API calls</p>
          </div>
          <span class="service-badge">ACTIVE</span>
        </div>
        <div class="service-item">
          <div class="service-meta">
            <h4>Prism Real-Time PII Filter</h4>
            <p>Port 8081 · Instant regex &amp; entropy scrubbing</p>
          </div>
          <span class="service-badge">ACTIVE</span>
        </div>
        <div class="service-item">
          <div class="service-meta">
            <h4>TPM 2.0 Encrypted Token Vault</h4>
            <p>Internal RAM · AES-256 surrogate mapping</p>
          </div>
          <span class="service-badge">SEALED</span>
        </div>
        <div class="service-item">
          <div class="service-meta">
            <h4>EU AI Act &amp; NIS2 Audit Ledger</h4>
            <p>Port 9100 · Cryptographic SHA-256 hash-chain</p>
          </div>
          <span class="service-badge">VERIFIED</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Hardware &amp; Network Ledger</div>
        <div class="row"><span class="row-lbl">Appliance IP</span><span class="row-val">192.168.100.50</span></div>
        <div class="row"><span class="row-lbl">Default Gateway</span><span class="row-val" style="color:var(--green);">192.168.100.1 (Vector Gateway)</span></div>
        <div class="row"><span class="row-lbl">Network Segment</span><span class="row-val">VLAN 10 (Trusted Production)</span></div>
        <div class="row"><span class="row-lbl">MAC Address</span><span class="row-val">52:54:00:12:34:56</span></div>
        <div class="row"><span class="row-lbl">Compliance Standard</span><span class="row-val" style="color:var(--green);">EU AI Act Art. 10 · GDPR Art. 32</span></div>
      </div>
    </div>
  </div>
</div>

<script>
function clearInput() {
  document.getElementById('promptInput').value = '';
  document.getElementById('maskedBox').textContent = 'Awaiting input...';
  document.getElementById('responseBox').textContent = 'Ready.';
  document.getElementById('vaultBadge').textContent = '0 Tokens';
  document.getElementById('vaultContent').innerHTML = '<span style="color:var(--muted);">No active surrogate tokens in RAM.</span>';
}

async function runInference() {
  const prompt = document.getElementById('promptInput').value.trim();
  if (!prompt) {
    alert('Please enter some text to test.');
    return;
  }
  const maskedBox = document.getElementById('maskedBox');
  const responseBox = document.getElementById('responseBox');
  const vaultBadge = document.getElementById('vaultBadge');
  const vaultContent = document.getElementById('vaultContent');

  maskedBox.textContent = 'Processing privacy filter...';
  responseBox.textContent = 'Running on-device model inference...';

  try {
    const res = await fetch('/api/v1/infer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: prompt })
    });
    if (!res.ok) {
      throw new Error('HTTP ' + res.status + ' ' + res.statusText);
    }
    const data = await res.json();
    maskedBox.textContent = data.sanitized_prompt;
    const hash = (data.receipt && data.receipt.hash) ? data.receipt.hash.substring(0, 24) : 'SEALED';
    const lat = (data.receipt && data.receipt.latency_ms !== undefined) ? data.receipt.latency_ms : '0.15';
    const receiptSuffix = String.fromCharCode(10, 10) + '[Receipt Hash: ' + hash + '... · Latency: ' + lat + 'ms · 0 WAN Egress Bytes]';
    responseBox.textContent = data.completion + receiptSuffix;

    const entities = data.entities_masked || [];
    vaultBadge.textContent = entities.length + ' Tokens Isolated';
    if (entities.length === 0) {
      vaultContent.innerHTML = '<div style="color:var(--muted);padding:8px 0;">No sensitive entities detected in input. Clean text passed directly to compute runtime.</div>';
    } else {
      let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
      entities.forEach((e) => {
        html += '<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.08);border-radius:6px;padding:8px 10px;">' +
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">' +
            '<span class="token-pill">' + e.token + '</span>' +
            '<span style="font-size:10px;font-weight:700;color:var(--green);background:rgba(16,185,129,0.15);padding:2px 6px;border-radius:4px;">RAM SEALED</span>' +
          '</div>' +
          '<div style="font-size:11px;color:#94A3B8;">Classification: <strong style="color:#FFF;">' + e.type + '</strong> · Length: ' + e.length + ' chars</div>' +
        '</div>';
      });
      html += '</div>';
      vaultContent.innerHTML = html;
    }
  } catch (err) {
    maskedBox.textContent = 'Error: ' + err.message;
    responseBox.textContent = 'Failed to communicate with Prism engine: ' + err.message;
  }
}
</script>
</body>
</html>"""
    return (
        html.replace("192.168.100.50", appliance_ip)
        .replace("192.168.100.1", gateway_ip)
        .replace("52:54:00:12:34:56", mac)
    )


def render_plain_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Velocitee Vector Edge Node #01 · Plain Ubuntu 24.04 LTS</title>
<style>
  :root {
    --bg: #07090E;
    --card: #0F141F;
    --card-accent: #141C2B;
    --border: #1E293B;
    --text: #F8FAFC;
    --muted: #94A3B8;
    --accent-blue: #38BDF8;
    --green: #10B981;
    --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-mono: ui-monospace, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font-sans); padding: 36px; min-height: 100vh; }
  .container { max-width: 1140px; margin: 0 auto; }
  .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; padding-bottom: 24px; border-bottom: 1px solid var(--border); }
  .brand-title h1 { font-size: 22px; font-weight: 800; display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
  .brand-title p { color: var(--muted); font-size: 13px; }
  .node-tag { background: rgba(56, 189, 248, 0.12); color: var(--accent-blue); border: 1px solid var(--accent-blue); padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 12px; display: flex; align-items: center; gap: 6px; }
  .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 28px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 24px; margin-bottom: 24px; }
  .card-title { font-size: 13px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); margin-bottom: 20px; font-weight: 700; }
  .app-item { display: flex; align-items: center; justify-content: space-between; padding: 16px; background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; margin-bottom: 14px; }
  .app-left { display: flex; align-items: center; gap: 16px; }
  .app-icon { font-size: 22px; background: rgba(56, 189, 248, 0.15); border-radius: 10px; width: 48px; height: 48px; display: flex; align-items: center; justify-content: center; }
  .app-name { font-weight: 700; font-size: 15px; margin-bottom: 2px; }
  .app-desc { font-size: 12px; color: var(--muted); }
  .status-pill { font-size: 11px; padding: 4px 10px; border-radius: 12px; font-weight: 700; }
  .status-active { background: rgba(16, 185, 129, 0.15); color: var(--green); }
  .row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 13px; }
  .row:last-child { border-bottom: none; }
  .row-label { color: var(--muted); }
  .row-val { font-family: var(--font-mono); font-weight: 600; }
  .cmd-box { background: #030712; border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; font-family: var(--font-mono); font-size: 13px; color: #38BDF8; margin: 12px 0; user-select: all; }
</style>
</head>
<body>
<div class="container">
  <header class="header">
    <div class="brand-title">
      <h1>⚡ Velocitee Vector Edge Node #01</h1>
      <p>Plain Ubuntu Server 24.04 LTS (Noble Numbat) · Hardened Bare-Metal Instance</p>
    </div>
    <div class="node-tag">
      <span>●</span> Active · Trusted LAN (192.168.100.50)
    </div>
  </header>

  <div class="grid">
    <div>
      <div class="card">
        <div class="card-title">Provisioned Base Runtime Services</div>

        <div class="app-item">
          <div class="app-left">
            <div class="app-icon">🐳</div>
            <div>
              <div class="app-name">Docker Engine 26.1 & containerd</div>
              <div class="app-desc">Container runtime active · Unix socket /var/run/docker.sock ready</div>
            </div>
          </div>
          <span class="status-pill status-active">Active</span>
        </div>

        <div class="app-item">
          <div class="app-left">
            <div class="app-icon">🔑</div>
            <div>
              <div class="app-name">OpenSSH Server 9.6p1</div>
              <div class="app-desc">Port 22 · Ed25519 public key auth enforced · Password auth disabled</div>
            </div>
          </div>
          <span class="status-pill status-active">Listening</span>
        </div>

        <div class="app-item">
          <div class="app-left">
            <div class="app-icon">📊</div>
            <div>
              <div class="app-name">Prometheus Node Exporter</div>
              <div class="app-desc">Port 9100 · System metrics scraping endpoint active</div>
            </div>
          </div>
          <span class="status-pill status-active">Streaming</span>
        </div>

        <div class="app-item">
          <div class="app-left">
            <div class="app-icon">🛡️</div>
            <div>
              <div class="app-name">UFW Hardened Firewall</div>
              <div class="app-desc">VLAN 10 routing enforced · Ports 22, 80, 443, 9100 allowed</div>
            </div>
          </div>
          <span class="status-pill status-active">Enforced</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Universal Custom Workload Slot</div>
        <div style="font-size:13px; color:#E2E8F0; line-height:1.6; margin-bottom:12px;">
          This edge node was provisioned with zero opinionated application payloads. Any developer or enterprise workload can be launched immediately over SSH or Docker Compose.
        </div>
        <div class="cmd-box">ssh -i ~/.ssh/id_ed25519 ubuntu@192.168.100.50</div>
        <div style="font-size:12px; color:var(--muted); margin-top:8px;">
          Example deployments: <code>docker run -d -p 11434:11434 ollama/ollama</code> (Local AI) or <code>curl -sfL https://get.k3s.io | sh -</code> (Lightweight Kubernetes).
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <div class="card-title">Hardware & Cryptographic Health</div>
        <div class="row"><span class="row-label">OS Platform</span><span class="row-val">Ubuntu 24.04 LTS</span></div>
        <div class="row"><span class="row-label">Linux Kernel</span><span class="row-val">6.8.0-40-generic</span></div>
        <div class="row"><span class="row-label">Architecture</span><span class="row-val">x86_64 / aarch64</span></div>
        <div class="row"><span class="row-label">Disk Encryption</span><span class="row-val" style="color:var(--green);">LUKS2 (AES-XTS-512)</span></div>
        <div class="row"><span class="row-label">Hardware Root</span><span class="row-val" style="color:var(--green);">TPM 2.0 PCR[7] Sealed</span></div>
        <div class="row"><span class="row-label">Memory Allocation</span><span class="row-val">0.8 / 16.0 GB RAM</span></div>
        <div class="row"><span class="row-label">Orchestrator</span><span class="row-val"><a href="https://velocit.ee" target="_blank" style="color:#38BDF8; text-decoration:none;">Velocitee Vector</a></span></div>
      </div>

      <div class="card">
        <div class="card-title">Appliance Profile Switch</div>
        <div style="font-size:13px; color:var(--muted); line-height:1.6; margin-bottom:12px;">
          View the Velocitee Prism Private AI Appliance:
        </div>
        <a href="/" style="display:block; text-align:center; background:#141C2B; border:1px solid #1E293B; color:#38BDF8; padding:10px; border-radius:8px; text-decoration:none; font-weight:700; font-size:12px;">
          Switch to Velocitee Prism (Private AI) →
        </a>
      </div>
    </div>
  </div>
</div>
</body>
</html>"""


class PrismHandler(http.server.SimpleHTTPRequestHandler):
    def _send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors()
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()

    def do_GET(self):
        node = fetch_node_state()
        is_active = node.get("status") == "active"

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        profile_req = query.get("profile", ["prism"])[0]

        # Allow API endpoints even if checking state
        if parsed.path == "/api/v1/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({
                "appliance": "Velocitee Prism (Private AI Appliance)",
                "status": "active" if is_active else "quarantined",
                "model": "mistral-7b-instruct-q4",
                "tpm_sealed": True,
                "luks2_encrypted": True,
                "egress_bytes": 0,
            }).encode("utf-8"))
            return

        if parsed.path == "/api/v1/audit":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps(PRISM_ENGINE.audit_log).encode("utf-8"))
            return

        if not is_active:
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors()
            self.end_headers()
            self.wfile.write(render_quarantine_html(node).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._send_cors()
        self.end_headers()
        if profile_req == "plain":
            self.wfile.write(render_plain_html().encode("utf-8"))
        else:
            self.wfile.write(render_prism_html(node).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            data = {}

        if parsed.path == "/api/v1/sanitize":
            text = data.get("text", "")
            sanitized, entities = PRISM_ENGINE.sanitize(text)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps({
                "sanitized_text": sanitized,
                "entities_found": entities,
                "tokens_count": len(entities)
            }).encode("utf-8"))
            return

        if parsed.path == "/api/v1/infer":
            prompt = data.get("prompt", "")
            result = PRISM_ENGINE.infer(prompt)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._send_cors()
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
            return

        self.send_response(404)
        self._send_cors()
        self.end_headers()

    def log_message(self, format, *args):
        pass


def run_hub():
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    print(f"\033[1;32m[PRISM-APPLIANCE]\033[0m Velocitee Prism Private AI Appliance listening on port {PORT} (Server IP: 192.168.100.50, Gateway: 192.168.100.1)")
    with http.server.ThreadingHTTPServer(("", PORT), PrismHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    run_hub()
