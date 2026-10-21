"""
Velocitee Prism — Zero-Touch Edge Provisioning Agent (HW-06, HW-07, HW-08, HW-09)

Runs on the bare-metal edge node (192.168.8.200) and monitors the Vector Gateway
(http://192.168.8.1:8088/api/v1/nodes). When an operator claims this node (`status == "in_progress"`
and `stage == "claiming"`), the agent executes the full event-driven provisioning handshake:
1. Fetches `GET /boot.ipxe?mac=<local_mac>` (consuming the one-shot boot slot and advancing to `pxe_chain_loaded`, 50%)
2. Extracts `vector.callback_key=<key>` and artifact URLs from the iPXE script
3. Fetches `GET /boot/vmlinuz?mac=<local_mac>` and `GET /boot/initrd?mac=<local_mac>` (verifying non-empty artifacts and advancing to `installing_os`, 75%)
4. Collects real kernel (`uname -r`), OS (`/etc/os-release`), LUKS2 (`lsblk`), and TPM 2.0 (`/dev/tpmrm0`) state
5. Signs and submits `POST /api/v1/callback` with `X-Vector-Signature: HMAC-SHA256(callback_key, body)` (advancing to `securing` -> `active`, 100%, VLAN 10).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from .system_status import probe_luks2_status, probe_tpm2_status, read_os_release


_CB_KEY_RE = re.compile(r"vector\.callback_key=([0-9a-fA-F]+)")


def execute_provisioning_handshake(
    gateway_base_url: str,
    node_mac: str,
    timeout: float = 3.0,
) -> bool:
    """
    Executes one complete provisioning handshake against `gateway_base_url` for `node_mac`.
    Returns True if the node transitioned to `active`.
    """
    base = gateway_base_url.rstrip("/")
    canon_mac = node_mac.strip().lower()

    # Step 1: Fetch one-shot iPXE script
    ipxe_url = f"{base}/boot.ipxe?mac={canon_mac}"
    try:
        with urllib.request.urlopen(ipxe_url, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            ipxe_script = resp.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return False

    m = _CB_KEY_RE.search(ipxe_script)
    if not m:
        return False
    callback_key = m.group(1)

    # Step 2: Fetch verified kernel & initrd artifacts
    for artifact in ("vmlinuz", "initrd"):
        art_url = f"{base}/boot/{artifact}?mac={canon_mac}"
        try:
            with urllib.request.urlopen(art_url, timeout=timeout) as resp:
                if resp.status != 200:
                    return False
                data = resp.read()
                if not data:
                    return False
        except (OSError, urllib.error.URLError):
            return False

    # Step 3: Collect real host attestation telemetry and POST signed callback
    luks_res = probe_luks2_status()
    tpm_res = probe_tpm2_status()
    callback_payload = {
        "mac": canon_mac,
        "os": read_os_release(),
        "kernel": platform.release(),
        "tpm_present": tpm_res if isinstance(tpm_res, bool) else False,
        "luks_active": luks_res if isinstance(luks_res, bool) else False,
        "prism_version": "2.0.0",
    }
    raw_body = json.dumps(callback_payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(callback_key.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()

    cb_req = urllib.request.Request(
        f"{base}/api/v1/callback",
        data=raw_body,
        headers={
            "Content-Type": "application/json",
            "X-Vector-Signature": sig,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(cb_req, timeout=timeout) as resp:
            return resp.status == 200
    except (OSError, urllib.error.URLError):
        return False


class EdgeProvisioningAgent:
    """Background daemon that watches the gateway and completes provisioning when claimed."""

    def __init__(
        self,
        gateway_nodes_url: str,
        node_mac: str,
        on_activated: Optional[Callable[[], None]] = None,
        poll_interval: float = 0.35,
    ) -> None:
        self._nodes_url = gateway_nodes_url
        self._gateway_base = gateway_nodes_url.split("/api/v1/")[0]
        self._node_mac = node_mac.strip().lower()
        self._on_activated = on_activated
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run_loop,
            name="prism-edge-provisioning-agent",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                with urllib.request.urlopen(self._nodes_url, timeout=1.5) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        nodes = data if isinstance(data, list) else data.get("nodes", [])
                        for node in nodes:
                            if not isinstance(node, dict):
                                continue
                            mac = str(node.get("mac", "")).lower()
                            if mac != self._node_mac:
                                continue
                            status = str(node.get("status", ""))
                            prov = node.get("provisioning", {})
                            stage = str(prov.get("stage", "")) if isinstance(prov, dict) else ""
                            if status == "in_progress" and stage in ("claiming", "token_issued"):
                                ok = execute_provisioning_handshake(
                                    self._gateway_base,
                                    self._node_mac,
                                )
                                if ok and self._on_activated is not None:
                                    self._on_activated()
            except Exception:
                pass
            self._stop_event.wait(self._poll_interval)
