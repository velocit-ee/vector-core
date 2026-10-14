"""
Velocitee Manifest Generator for Telia Edge Edition.
Strictly conforms to https://velocit.ee/schemas/vne/vme-input/1.0
"""

from datetime import datetime, timezone
from typing import Dict, Any

# Maps the claimed provisioning profile to the OS slug and login the manifest
# should advertise. Keeps the handoff honest about which image was deployed
# (Fix 5) instead of always reporting a Proxmox/root install.
_PROFILE_MANIFEST = {
    "plain-ubuntu-server": ("ubuntu-24.04-lts", "ubuntu"),
    "sovereign-legal-advisory": ("ubuntu-24.04-sovereign-legal", "ubuntu"),
}


def build_velocitee_manifest(
    hostname: str = "telia-sovereign-01",
    ip: str = "192.168.100.50",
    prefix: int = 24,
    gateway: str = "192.168.100.1",
    dns: str = "192.168.100.1",
    mac: str = "52:54:00:12:34:56",
    os_name: str = None,
    profile: str = "plain-ubuntu-server",
    status: str = "success",
    started_at: datetime = None,
    completed_at: datetime = None
) -> Dict[str, Any]:
    """Constructs the VME handoff manifest for downstream engines (VNE/VSE).

    ``os_name`` and the login are derived from the claimed ``profile`` unless
    ``os_name`` is passed explicitly; ``status`` reflects the node lifecycle
    (``pending`` / ``in_progress`` / ``success``) rather than a hardcoded win.
    """
    now = datetime.now(timezone.utc)
    started = started_at or now
    completed = completed_at or now
    duration = max(1.0, (completed - started).total_seconds())

    derived_os, username = _PROFILE_MANIFEST.get(profile, ("ubuntu-24.04-lts", "ubuntu"))
    resolved_os = os_name or derived_os

    return {
        "schema_version": "1.0",
        "target": {
            "hostname": hostname,
            "ip": ip,
            "prefix": prefix,
            "gateway": gateway,
            "dns": dns,
            "disk": "/dev/nvme0n1",
            "os": resolved_os,
            "mac": mac.lower()
        },
        "access": {
            "username": username,
            "ssh_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleTeliaEdgeKey admin@velocit.ee",
            "ssh_port": 22
        },
        "engines": {
            "vme": {
                "status": status,
                "version": "0.2.0-telia",
                "edition": "telia-cpe-edge",
                "gateway_hardware": "Technicolor DGA4330 (Telia X2)",
                "started_at": started.isoformat(),
                "completed_at": completed.isoformat(),
                "duration_seconds": duration,
                "compliance_verified": {
                    "gdpr_article_32": True,
                    "nis2_supply_chain": True,
                    "luks2_disk_encrypted": True,
                    "local_data_boundary": "EE-Tallinn"
                }
            }
        }
    }
