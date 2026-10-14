#!/usr/bin/env python3
"""
Velocitee Vector — Edge Gateway Orchestrator Daemon
Telia Carrier Edition (Technicolor DGA4330 / Telia X2).
Exposes REST API for management consoles, handles iPXE boot chains,
and implements zero-trust hardware claim workflows.
"""

import http.server
import json
import os
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from typing import Dict, Any, Optional, Tuple

try:
    from vector.telia.daemon.security import (
        generate_claim_token,
        verify_claim_token,
        record_audit_event,
        get_audit_log,
        init_baseline_audit_log,
        is_valid_mac,
        is_valid_profile,
    )
    from vector.telia.daemon.manifest_generator import build_velocitee_manifest
except ImportError:
    try:
        from core.vector.telia.daemon.security import (
            generate_claim_token,
            verify_claim_token,
            record_audit_event,
            get_audit_log,
            init_baseline_audit_log,
            is_valid_mac,
            is_valid_profile,
        )
        from core.vector.telia.daemon.manifest_generator import build_velocitee_manifest
    except ImportError:
        import sys
        _cur_dir = os.path.dirname(os.path.abspath(__file__))
        if _cur_dir not in sys.path:
            sys.path.insert(0, _cur_dir)
        from security import (
            generate_claim_token,
            verify_claim_token,
            record_audit_event,
            get_audit_log,
            init_baseline_audit_log,
            is_valid_mac,
            is_valid_profile,
        )
        from manifest_generator import build_velocitee_manifest

PORT = int(os.environ.get("VECTOR_ROUTER_PORT", 8088))
DAEMON_DIR = os.path.dirname(os.path.abspath(__file__))
TELIA_DIR = os.path.dirname(DAEMON_DIR)
ASSETS_DIR = os.environ.get("VECTOR_ASSETS_DIR") or (
    os.path.join(DAEMON_DIR, "assets")
    if os.path.exists(os.path.join(DAEMON_DIR, "assets"))
    else os.path.join(TELIA_DIR, "assets")
)
TARGET_DIR = os.environ.get("VECTOR_TARGET_DIR") or (
    os.path.join(DAEMON_DIR, "target")
    if os.path.exists(os.path.join(DAEMON_DIR, "target"))
    else os.path.join(TELIA_DIR, "target")
)


class EdgeOrchestrator:
    """Thread-safe state manager for the Telia Vector Edge Gateway."""

    def __init__(self):
        self._lock = threading.Lock()
        self.state: Dict[str, Any] = {}
        self.reset()

    def reset(self, mac: str = "52:54:00:12:34:56"):
        with self._lock:
            self.state = {
                "gateway": {
                    "brand": "Telia Eesti AS",
                    "product_name": "Telia Vector (Telia X2 Edition)",
                    "hardware_model": "Technicolor DGA4330 (Vantiva)",
                    "serial_number": "CP2138RA49B",
                    "subscription_id": "IN-884920-EE",
                    "cpu_arch": "Broadcom BCM63138 (Dual-core ARM Cortex-A9 @ 1.0 GHz)",
                    "ram_used_mb": 38,
                    "ram_total_mb": 512,
                    "flash_used_mb": 62,
                    "flash_total_mb": 256,
                    "firmware_version": "18.3.c.0454-Telia-Vector-v1.0",
                    "lan_ip": "192.168.100.1",
                    "lan_netmask": "255.255.255.0",
                    "uplink": {
                        "type": "Telia Ärikiud (Dedicated Business Fiber)",
                        "speed": "1000 / 1000 Mbps",
                        "wan_ip": "194.126.101.42",
                        "gateway": "194.126.101.1",
                        "sla": "99.95% Gold with 4G LTE Failover",
                    },
                    "ports": {
                        "LAN 1": {"status": "up", "speed": "1 Gbps", "role": "Office Network (VLAN 10)", "gateway": "192.168.10.1"},
                        "LAN 2": {"status": "up", "speed": "1 Gbps", "role": "VoIP SIP Trunk (VLAN 20)", "gateway": "192.168.20.1"},
                        "LAN 3": {"status": "down", "speed": "Auto", "role": "Guest Wi-Fi (VLAN 30)", "gateway": "192.168.30.1"},
                        "LAN 4": {"status": "up", "speed": "1 Gbps", "role": "Dedicated Server Port (VLAN 999 Quarantine)", "target_ip": "192.168.100.50", "gateway": "192.168.100.1"},
                    },
                    "compliance": {
                        "gdpr_compliant": True,
                        "nis2_certified": True,
                        "data_boundary": "Estonia (Tallinn Edge)",
                        "tpm_attestation": "TPM 2.0 Active",
                        "luks2_encryption": "Enforced",
                    },
                    "product": {
                        "name": "Vector",
                        "full_name": "Velocitee Vector (Telia Carrier Edition)",
                        "edition": "telia-vector-cpe",
                        "engine": "Velocitee Metal Provisioning Engine (VME)",
                        "version": "1.0.0-telia",
                        "domain": "https://velocit.ee",
                        "docs": "https://docs.velocit.ee/vme/",
                    },
                },
                "nodes": [
                    {
                        "mac": mac,
                        "current_ip": "192.168.100.50",
                        "gateway_ip": "192.168.100.1",
                        "port": "LAN 4",
                        "vlan": 999,
                        "vlan_name": "Quarantine / Zero-Trust Bootstrap",
                        "status": "quarantined",
                        "first_seen": datetime.now(timezone.utc).isoformat(),
                        "hardware_spec": {
                            "chassis": "Edge MicroServer 1U",
                            "cpu": "Intel Xeon E-2314 / ARM64 Ampere",
                            "memory_gb": 16,
                            "storage": "512 GB NVMe (Encrypted)",
                            "vendor": "Telia Certified Hardware",
                        },
                        "claim": {
                            "claimed": False,
                            "claimed_at": None,
                            "claimed_by": None,
                            "claim_token": None,
                            "profile": "plain-ubuntu-server",
                        },
                        "provisioning": {
                            "progress": 0,
                            "stage": "Waiting for hardware claim approval in management console",
                            "started_at": None,
                            "completed_at": None,
                            "active_apps": [],
                        },
                    }
                ],
            }
            init_baseline_audit_log(mac)

    def get_gateway(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self.state["gateway"])

    def get_nodes(self) -> list:
        with self._lock:
            return list(self.state["nodes"])

    def find_node(self, mac: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return next((n for n in self.state["nodes"] if n["mac"].lower() == mac.lower()), None)

    class ClaimConflict(Exception):
        """Raised when a node is already claimed or actively provisioning."""

    def start_claim(self, mac: str, profile: str, operator: str) -> Tuple[str, int]:
        node = self.find_node(mac)
        if not node:
            raise KeyError("Node not found")

        # Fix 2.9: refuse a second claim on a node that is already in flight.
        if node["claim"]["claimed"] or node["status"] in ("provisioning", "active"):
            raise EdgeOrchestrator.ClaimConflict(
                f"Node {mac} is already claimed or actively provisioning"
            )

        token, expires_at = generate_claim_token(mac, profile)
        with self._lock:
            node["claim"]["claimed"] = True
            node["claim"]["claimed_at"] = datetime.now(timezone.utc).isoformat()
            node["claim"]["claimed_by"] = operator
            node["claim"]["claim_token"] = token
            node["claim"]["profile"] = profile
            node["status"] = "provisioning"
            node["provisioning"]["started_at"] = datetime.now(timezone.utc).isoformat()
            node["provisioning"]["stage"] = "Claim verified. Unlocking bootloader..."

        record_audit_event(
            event_type="CLAIM_APPROVED",
            actor=operator,
            target_mac=mac,
            details=f"Hardware claim approved for profile '{profile}'. Token issued: {token[:12]}...",
            severity="INFO",
            category="SECURITY",
            facility="auth",
            event_id="EVT-2000",
        )

        threading.Thread(target=self._run_pipeline, args=(mac,), daemon=True).start()
        return token, expires_at

    def _run_pipeline(self, mac: str):
        node = self.find_node(mac)
        if not node:
            return

        profile = node["claim"].get("profile", "plain-ubuntu-server")
        if profile == "plain-ubuntu-server":
            stages = [
                (15, "HMAC-SHA256 claim token verified · single-use · ttl=60s", "INFO", "SECURITY", "auth", "EVT-3310"),
                (30, "DHCP lease granted 10.199.0.14/30 on quarantine bridge · chainloading iPXE", "INFO", "PROVISIONING", "daemon", "EVT-2050"),
                (50, "Kernel + rootfs streamed over TLS 1.3 · 1.9 GB · sig OK", "INFO", "PROVISIONING", "kern", "EVT-2061"),
                (70, "NVMe volume sealed with LUKS2 · key escrow to TPM 2.0 PCR[7]", "INFO", "COMPLIANCE", "audit", "EVT-4130"),
                (85, "Container runtime bootstrapped · containerd healthy", "INFO", "PROVISIONING", "daemon", "EVT-2072"),
                (100, "Quarantine lifted · node migrated to VLAN 10 · trusted routing enabled", "INFO", "SECURITY", "auth", "EVT-3390"),
            ]
        else:
            stages = [
                (15, "HMAC-SHA256 claim token verified · single-use · unlocking sovereign bootloader", "INFO", "SECURITY", "auth", "EVT-3310"),
                (30, "DHCP lease granted 10.199.0.14/30 on quarantine bridge · chainloading iPXE", "INFO", "PROVISIONING", "daemon", "EVT-2050"),
                (50, "Sovereign Linux kernel + encrypted initrd streamed over TLS 1.3 · sig OK", "INFO", "PROVISIONING", "kern", "EVT-2061"),
                (70, "NVMe partition sealed with LUKS2 · TPM 2.0 key escrow verified", "INFO", "COMPLIANCE", "audit", "EVT-4130"),
                (85, "Deploying Nextcloud legal vault, PostgreSQL & Telia DC sync agent", "INFO", "PROVISIONING", "daemon", "EVT-2072"),
                (100, "Quarantine lifted · node operational on VLAN 10 · data resident EE-Tallinn", "INFO", "SECURITY", "auth", "EVT-3390"),
            ]

        sleep_duration = 0.05 if os.environ.get("TELIA_VECTOR_FAST_SIMULATION") else 2.0
        for progress, stage_msg, severity, cat, fac, eid in stages:
            time.sleep(sleep_duration)
            with self._lock:
                node["provisioning"]["progress"] = progress
                node["provisioning"]["stage"] = stage_msg

            record_audit_event(
                event_type="PROVISIONING_PROGRESS",
                actor=fac,
                target_mac=mac,
                details=stage_msg,
                severity=severity,
                category=cat,
                facility=fac,
                event_id=eid,
            )

            if progress == 100:
                with self._lock:
                    node["status"] = "active"
                    node["vlan"] = 10
                    node["vlan_name"] = "Trusted Office Network"
                    node["current_ip"] = "192.168.100.50"
                    node["gateway_ip"] = "192.168.100.1"
                    node["provisioning"]["completed_at"] = datetime.now(timezone.utc).isoformat()
                    if profile == "plain-ubuntu-server":
                        node["provisioning"]["active_apps"] = [
                            {"name": "Universal Node Dashboard", "port": 8081, "status": "online"},
                            {"name": "OpenSSH Server (Port 22)", "port": 22, "status": "online"},
                            {"name": "Docker Engine (containerd)", "port": 2375, "status": "active"},
                            {"name": "Prometheus Node Exporter", "port": 9100, "status": "online"},
                        ]
                    else:
                        node["provisioning"]["active_apps"] = [
                            {"name": "Nextcloud Legal Vault", "port": 8081, "status": "online"},
                            {"name": "Encrypted Audit Database", "port": 5432, "status": "online"},
                            {"name": "Telia DC Backup Agent", "port": 9100, "status": "synced"},
                        ]


orchestrator = EdgeOrchestrator()


def safe_asset_path(base_dir: str, rel_path: str) -> Optional[str]:
    """Ensures a requested file path does not escape the canonical base directory."""
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(os.path.join(base_real, rel_path))
    if os.path.commonpath([base_real, target_real]) == base_real and os.path.isfile(target_real):
        return target_real
    return None


ROUTER_ADMIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Velocitee Vector - Edge Gateway Orchestrator</title>
<style>
  body { background:#111318; color:#F3F4F6; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; padding:32px; line-height:1.55; }
  .box { max-width:640px; margin:0 auto; background:#181B22; border:1px solid #262A35; border-radius:12px; padding:26px; }
  h1 { font-size:20px; font-weight:700; color:#fff; display:flex; align-items:center; gap:8px; margin-bottom:6px; }
  .pill { background:rgba(37,99,235,0.15); color:#3B82F6; border:1px solid #2563EB; font-size:11px; padding:3px 8px; border-radius:6px; font-weight:700; }
  .meta { color:#9CA3AF; font-size:13px; margin-bottom:18px; }
  .row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid #262A35; font-size:13px; }
  .lbl { color:#9CA3AF; }
  .val { font-family:monospace; font-weight:600; color:#F3F4F6; }
  .card { background:#13161F; border:1px solid #262A35; border-radius:10px; padding:16px; margin-top:18px; }
  .banner { border-radius:8px; padding:12px 14px; font-size:13px; margin-bottom:14px; }
  .b-warn { background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.35); color:#FDE68A; }
  .b-ok { background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.35); color:#6EE7B7; }
  .b-run { background:rgba(37,99,235,0.1); border:1px solid rgba(37,99,235,0.35); color:#93C5FD; }
  label { display:block; font-size:12px; color:#9CA3AF; margin:6px 0 4px; }
  select { width:100%; background:#0E1015; color:#F1F5F9; border:1px solid #262A35; border-radius:6px; padding:9px 10px; font-size:13px; }
  .btn { display:block; width:100%; text-align:center; background:#2563EB; color:#fff; border:none; text-decoration:none; font-weight:600; font-size:13px; padding:12px; border-radius:8px; margin-top:16px; cursor:pointer; }
  .btn:hover { background:#1D4ED8; }
  .btn:disabled { opacity:0.5; cursor:not-allowed; }
  .btn.secondary { background:transparent; border:1px solid #262A35; color:#9CA3AF; }
  .bar { height:8px; background:#1E232F; border-radius:6px; overflow:hidden; margin-top:12px; }
  .fill { height:100%; width:0%; background:linear-gradient(90deg,#1D4ED8,#60A5FA); transition:width .5s ease; }
  .stage { font-size:12px; color:#9CA3AF; margin-top:8px; font-family:monospace; }
  .hidden { display:none; }
</style>
</head>
<body>
<div class="box">
  <h1>&#9889; Velocitee Vector <span class="pill">CPE GATEWAY</span></h1>
  <div class="meta" id="meta">Telia Vector (Telia X2 Edition) &middot; Technicolor DGA4330 (Vantiva)</div>

  <div class="row"><span class="lbl">Gateway Router IP</span><span class="val" style="color:#10B981;" id="lan_ip">-</span></div>
  <div class="row"><span class="lbl">Port 4 Target Appliance</span><span class="val" id="target_ip">192.168.100.50</span></div>
  <div class="row"><span class="lbl">Uplink</span><span class="val" id="uplink">-</span></div>
  <div class="row"><span class="lbl">REST API</span><span class="val" style="color:#10B981;">&#9679; Online</span></div>

  <div class="card" id="control">
    <div class="banner b-warn" id="banner">Checking for an edge server on Port 4...</div>

    <div id="claim-form">
      <label for="profile">Operating system profile</label>
      <select id="profile">
        <option value="prism">Velocitee Prism (Private AI Appliance)</option>
        <option value="plain-ubuntu-server">Plain Ubuntu 24.04 LTS (universal base)</option>
      </select>
      <button class="btn" id="deploy" onclick="deploy()">&#128274; Authorize &amp; Deploy Appliance</button>
    </div>

    <div id="progress" class="hidden">
      <div class="bar"><div class="fill" id="fill"></div></div>
      <div class="stage" id="stage"></div>
    </div>

    <div id="done" class="hidden">
      <a class="btn" id="open-server" target="_blank" rel="noopener">Open Live Server Appliance &rarr;</a>
      <button class="btn secondary" onclick="resetNode()">Reset demo</button>
    </div>
  </div>

  <a href="#" id="console-link" class="btn secondary" style="margin-top:14px;">Open Full Management Console (:3000) &rarr;</a>
</div>

<script>
// Everything is same-origin: this page is served by the router daemon, so the
// API is wherever this page loaded from. No hardcoded hosts.
var apiBase = location.protocol + "//" + location.host;
// The rich Next.js console is a separate app on port 3000 of the same host.
document.getElementById("console-link").href = location.protocol + "//" + location.hostname + ":3000";
// The provisioned server's own web hub (localhost keeps working without the IP aliases).
var serverHost = (location.hostname === "localhost" || location.hostname === "127.0.0.1") ? "localhost" : "192.168.100.50";

async function getJSON(path) {
  var r = await fetch(apiBase + path);
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

function render(node, gw) {
  if (gw) {
    document.getElementById("meta").textContent = gw.product_name + " - " + gw.hardware_model;
    document.getElementById("lan_ip").textContent = (gw.lan_ip || "192.168.100.1") + " (Router Gateway)";
    if (gw.uplink) document.getElementById("uplink").textContent = gw.uplink.type + " (" + gw.uplink.speed + ")";
  }
  var banner = document.getElementById("banner");
  var form = document.getElementById("claim-form");
  var prog = document.getElementById("progress");
  var done = document.getElementById("done");
  var status = node ? node.status : "quarantined";
  var pct = node && node.provisioning ? (node.provisioning.progress || 0) : 0;
  var stage = node && node.provisioning ? (node.provisioning.stage || "") : "";

  if (status === "active") {
    banner.className = "banner b-ok";
    banner.textContent = "Server is deployed, encrypted, and on the trusted network (VLAN 10).";
    form.classList.add("hidden"); prog.classList.add("hidden"); done.classList.remove("hidden");
    var prof = node.claim ? node.claim.profile : "plain-ubuntu-server";
    var q = prof === "sovereign-legal-advisory" ? "legal" : "plain";
    document.getElementById("open-server").href = location.protocol + "//" + serverHost + ":8081/?profile=" + q;
  } else if (status === "provisioning") {
    banner.className = "banner b-run";
    banner.textContent = "Provisioning in progress. The router is installing the OS over the network.";
    form.classList.add("hidden"); done.classList.add("hidden"); prog.classList.remove("hidden");
    document.getElementById("fill").style.width = pct + "%";
    document.getElementById("stage").textContent = "[" + pct + "%] " + stage;
  } else {
    banner.className = "banner b-warn";
    banner.textContent = "Unclaimed edge server detected on Port 4, quarantined in VLAN 999. Approve to deploy.";
    form.classList.remove("hidden"); prog.classList.add("hidden"); done.classList.add("hidden");
  }
}

async function poll() {
  try {
    var nodes = await getJSON("/api/v1/nodes");
    var gw = await getJSON("/api/v1/telemetry");
    render(nodes[0], gw);
  } catch (e) { /* keep last view */ }
}

async function deploy() {
  var btn = document.getElementById("deploy");
  btn.disabled = true; btn.textContent = "Issuing cryptographic claim token...";
  var profile = document.getElementById("profile").value;
  try {
    var r = await fetch(apiBase + "/api/v1/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mac: "52:54:00:12:34:56", profile: profile, operator: "admin@velocit.ee" })
    });
    if (r.status === 409) { await poll(); }
  } catch (e) {
    btn.disabled = false; btn.textContent = "Authorize & Deploy Appliance";
    return;
  }
  await poll();
}

async function resetNode() {
  try { await fetch(apiBase + "/api/v1/reset", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }); } catch (e) {}
  await poll();
}

poll();
setInterval(poll, 1200);
</script>
</body>
</html>"""


class EnterpriseEdgeHandler(http.server.SimpleHTTPRequestHandler):
    """Clean HTTP request handler exposing REST API and iPXE zero-trust bootchains."""

    def send_cors_headers(self):
        # V-01: wildcard is fine for the local demo; production sets a strict origin.
        self.send_header("Access-Control-Allow-Origin", os.environ.get("VECTOR_CORS_ORIGIN", "*"))
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def send_json(self, status: int, data: Any):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_cors_headers()
        self.end_headers()

    def _authorized_for_boot(self, query: Dict[str, Any]) -> bool:
        """Fix 2.7: a boot artefact is released only for a claimed node whose
        query-string token verifies. Assets are fetched several times per boot,
        so this does NOT consume the token (single-use is enforced once, on the
        authorised boot.ipxe release)."""
        mac = query.get("mac", [""])[0]
        token = query.get("token", [""])[0]
        node = orchestrator.find_node(mac)
        if not node or not node["claim"]["claimed"]:
            return False
        return verify_claim_token(mac, node["claim"]["profile"], token, consume=False)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # ── REST API ──────────────────────────────────────────────────────────
        if path == "/api/v1/telemetry":
            self.send_json(200, orchestrator.get_gateway())
            return

        if path == "/api/v1/nodes":
            self.send_json(200, orchestrator.get_nodes())
            return

        if path in ("/api/v1/audit-log", "/api/v1/logs"):
            self.send_json(200, get_audit_log())
            return

        if path == "/api/v1/manifest":
            node = orchestrator.get_nodes()[0]
            status_map = {"active": "success", "provisioning": "in_progress",
                          "quarantined": "pending"}
            manifest = build_velocitee_manifest(
                ip=node.get("current_ip", "192.168.100.50"),
                gateway=node.get("gateway_ip", "192.168.100.1"),
                dns="192.168.100.1",
                mac=node.get("mac", "52:54:00:12:34:56"),
                profile=node.get("claim", {}).get("profile", "plain-ubuntu-server"),
                status=status_map.get(node.get("status"), "pending"),
            )
            self.send_json(200, manifest)
            return

        # ── iPXE Zero-Trust Chainloader ───────────────────────────────────────
        if path == "/boot.ipxe":
            mac = query.get("mac", ["52:54:00:12:34:56"])[0]
            token = query.get("token", [""])[0]
            node = orchestrator.find_node(mac)

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()

            authorized = bool(node and node["claim"]["claimed"]
                              and verify_claim_token(mac, node["claim"]["profile"], token, consume=True))
            if not authorized:
                script = f"""#!ipxe
echo ==============================================================================
echo   VELOCITEE VECTOR EDGE GATEWAY -- ROUTER {orchestrator.get_gateway()['lan_ip']}
echo   Port: LAN 4 (VLAN 999 Quarantine) · Target Node MAC: {mac}
echo ==============================================================================
echo
echo   [SECURITY ALERT] Node is quarantined in isolated provisioning network.
echo   Hardware is not yet authenticated in the Velocitee Vector Management Console.
echo
echo   To claim this node, visit: http://localhost:3000
echo   Retrying authentication in 5 seconds...
sleep 5
chain http://192.168.100.1:8088/boot.ipxe?mac={mac}&token={token}
"""
                self.wfile.write(script.encode("utf-8"))
                return

            script = f"""#!ipxe
echo ==============================================================================
echo   VELOCITEE VECTOR -- AUTHORIZED ZERO-TOUCH PROVISIONING
echo   Node MAC: {mac} · Profile: {node['claim']['profile']}
echo   Gateway: 192.168.100.1 · Assigned Node IP: 192.168.100.50
echo ==============================================================================
echo
echo   [1/3] Loading signed kernel over secure edge channel...
kernel http://192.168.100.1:8088/boot/vmlinuz?mac={mac}&token={token} ip=dhcp autoinstall ds=nocloud-net;s=http://192.168.100.1:8088/cloud-init/?mac={mac}&token={token} quiet ---
echo   [2/3] Loading secure initial ramdisk...
initrd http://192.168.100.1:8088/boot/initrd?mac={mac}&token={token}
echo   [3/3] Commencing zero-touch hardware provisioning...
boot
"""
            self.wfile.write(script.encode("utf-8"))
            return

        # ── Boot Assets & Cloud-Init with Safe Path Traversal Guard ────────────
        if path.startswith("/boot/"):
            if not self._authorized_for_boot(query):
                self.send_json(403, {"error": "Boot assets require a valid claim token", "code": "UNAUTHORIZED"})
                return
            rel_file = path[len("/boot/"):]
            safe_file = safe_asset_path(os.path.join(ASSETS_DIR, "boot"), rel_file)
            if safe_file:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(os.path.getsize(safe_file)))
                self.end_headers()
                with open(safe_file, "rb") as f:
                    while chunk := f.read(65536):
                        self.wfile.write(chunk)
                return
            self.send_json(404, {"error": "Boot asset not found", "code": "NOT_FOUND"})
            return

        if path.startswith("/cloud-init/"):
            if not self._authorized_for_boot(query):
                self.send_json(403, {"error": "Cloud-init templates require a valid claim token", "code": "UNAUTHORIZED"})
                return
            rel_file = path[len("/cloud-init/"):]
            safe_file = safe_asset_path(os.path.join(TARGET_DIR, "cloud-init"), rel_file)
            if safe_file:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                with open(safe_file, "rb") as f:
                    self.wfile.write(f.read())
                return
            self.send_json(404, {"error": "Cloud-init template not found", "code": "NOT_FOUND"})
            return

        # ── Clean Router Gateway Status & Console Redirect ────────────────────
        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_cors_headers()
            self.end_headers()
            # Lightweight, self-contained admin page served BY the router
            # daemon itself — the realistic thin-CPE model: a 512 MB / ~30 MB
            # router cannot host the heavy Next.js console, but it can serve
            # this vanilla-JS page and drive its own on-box REST API. Every
            # URL is derived from the browser's location, so this page works
            # identically at localhost:8088, 192.168.100.1:8088, and
            # 192.168.100.1:80 (via the port forwarder) with nothing hardcoded.
            self.wfile.write(ROUTER_ADMIN_PAGE.encode("utf-8"))
            return

        self.send_json(404, {"error": "Route not found", "code": "NOT_FOUND"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # ── Ingest External Audit Event ───────────────────────────────────────
        if path in ("/api/v1/events", "/api/v1/audit-log"):
            body = self._read_json_body()
            if body is None:
                return

            event = record_audit_event(
                event_type=body.get("event_type", "EXTERNAL_EVENT"),
                actor=body.get("actor", "system"),
                target_mac=body.get("target_mac", "52:54:00:12:34:56"),
                details=body.get("details", ""),
                severity=body.get("severity", "INFO"),
                category=body.get("category", "SECURITY"),
                facility=body.get("facility", "authpriv"),
                event_id=body.get("event_id") or body.get("eventId"),
            )
            self.send_json(200, {"success": True, "event": event})
            return

        # ── Reset Endpoint ────────────────────────────────────────────────────
        if path in ("/api/v1/reset", "/api/v1/nodes/reset") or (path.startswith("/api/v1/nodes/") and path.endswith("/reset")):
            mac = "52:54:00:12:34:56"
            if path.startswith("/api/v1/nodes/") and path != "/api/v1/nodes/reset":
                mac = path.split("/")[4]
            orchestrator.reset(mac)
            self.send_json(200, {"success": True, "status": "reset", "mac": mac})
            return

        # ── Claim Endpoint ────────────────────────────────────────────────────
        if (path.startswith("/api/v1/nodes/") and path.endswith("/claim")) or path in ("/api/v1/claim", "/api/v1/nodes/claim"):
            body = self._read_json_body()
            if body is None:
                return

            if path.startswith("/api/v1/nodes/") and path != "/api/v1/nodes/claim":
                mac = path.split("/")[4]
            else:
                mac = body.get("mac", "52:54:00:12:34:56")

            profile = body.get("profile", "plain-ubuntu-server")
            actor = body.get("operator", "admin@velocit.ee")

            # Strict input validation
            if not is_valid_mac(mac):
                self.send_json(400, {"error": "Invalid MAC address format", "code": "INVALID_MAC"})
                return

            node = orchestrator.find_node(mac)
            if not node:
                self.send_json(404, {"error": f"Node with MAC {mac} not found in inventory", "code": "NODE_NOT_FOUND"})
                return

            if not is_valid_profile(profile):
                self.send_json(400, {"error": f"Unauthorized profile: '{profile}'", "code": "INVALID_PROFILE"})
                return

            try:
                token, expires_at = orchestrator.start_claim(mac, profile, actor)
                self.send_json(200, {
                    "success": True,
                    "status": "claiming",
                    "product": "Telia Vector",
                    "mac": mac,
                    "claim_token": token,
                    "expires_at": expires_at,
                    "provisioning_status": "in_progress",
                })
            except EdgeOrchestrator.ClaimConflict as exc:
                self.send_json(409, {"error": str(exc), "code": "CLAIM_CONFLICT"})
            except KeyError:
                self.send_json(404, {"error": "Node not found", "code": "NODE_NOT_FOUND"})
            return

        self.send_json(404, {"error": "Endpoint not found", "code": "NOT_FOUND"})

    def _read_json_body(self) -> Optional[Dict[str, Any]]:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {"error": "Malformed JSON payload", "code": "MALFORMED_JSON"})
            return None


def run_daemon():
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    record_audit_event("VECTOR_DAEMON_START", "system", "router_cpe", f"Velocitee Vector edge gateway daemon initialized on port {PORT}", severity="INFO", category="SECURITY", facility="daemon", event_id="EVT-1000")
    print(f"\033[1;32m[ROUTER-GATEWAY]\033[0m Velocitee Vector Router Daemon listening on port {PORT} (Gateway IP: 192.168.100.1)")
    with http.server.ThreadingHTTPServer(("", PORT), EnterpriseEdgeHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    run_daemon()
