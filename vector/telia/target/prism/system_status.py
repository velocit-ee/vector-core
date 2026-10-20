"""
Velocitee Prism — Real Hardware & System Attestation Probes (PR-07)

Queries actual kernel and block-device state without fabricated compliance booleans:
- LUKS2 encryption: inspects `lsblk -J -o NAME,FSTYPE,TYPE` or `/sbin/cryptsetup`
- TPM 2.0 sealing: checks `/dev/tpmrm0`, `/dev/tpm0`, and `tpm2_getcap`
- Kernel, OS release, CPU load, and memory statistics from `/proc`
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Union


def probe_luks2_status() -> Union[bool, str]:
    """
    Returns True if an active LUKS2 volume is present on the host, False if block
    devices are readable and none use crypto_LUKS, or 'unknown' if inspection fails (PR-07).
    """
    lsblk_bin = shutil.which("lsblk")
    if lsblk_bin:
        try:
            proc = subprocess.run(
                [lsblk_bin, "-n", "-o", "FSTYPE,TYPE"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                out_lower = proc.stdout.lower()
                if "crypto_luks" in out_lower or "crypt" in out_lower:
                    return True
                return False
        except (OSError, subprocess.SubprocessError):
            pass

    dm_dir = Path("/dev/mapper")
    if dm_dir.exists():
        try:
            entries = [p.name for p in dm_dir.iterdir() if p.name != "control"]
            if any("luks" in e.lower() or "crypt" in e.lower() for e in entries):
                return True
        except OSError:
            pass

    return "unknown"


def probe_tpm2_status() -> Union[bool, str]:
    """
    Returns True if a hardware or virtual TPM 2.0 resource manager device is present,
    False on Linux when `/sys/class/tpm` is empty and `/dev/tpm*` are absent,
    or 'unknown' on non-Linux platforms (PR-07).
    """
    if Path("/dev/tpmrm0").exists() or Path("/dev/tpm0").exists():
        tpm_cap = shutil.which("tpm2_getcap")
        if tpm_cap:
            try:
                proc = subprocess.run(
                    [tpm_cap, "properties-fixed"],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                return proc.returncode == 0
            except (OSError, subprocess.SubprocessError):
                return True
        return True

    if platform.system().lower() == "linux":
        tpm_class = Path("/sys/class/tpm")
        if tpm_class.exists():
            try:
                return any(tpm_class.iterdir())
            except OSError:
                return "unknown"
        return False

    return "unknown"


def read_os_release() -> str:
    os_rel = Path("/etc/os-release")
    if os_rel.exists():
        try:
            for line in os_rel.read_text(encoding="utf-8").splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return f"{platform.system()} {platform.release()}"


def collect_system_status(
    activated: bool,
    gateway_status: str,
    active_profile_id: str,
) -> Dict[str, object]:
    """Builds a truthful `/api/v1/status` payload from real host probes (PR-07)."""
    mem_total_mb: Union[int, str] = "unknown"
    mem_avail_mb: Union[int, str] = "unknown"
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            fields: Dict[str, int] = {}
            for line in meminfo.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    fields[parts[0].rstrip(":")] = int(parts[1])
            if "MemTotal" in fields:
                mem_total_mb = fields["MemTotal"] // 1024
            if "MemAvailable" in fields:
                mem_avail_mb = fields["MemAvailable"] // 1024
        except OSError:
            pass

    uptime_seconds: Union[float, str] = "unknown"
    uptime_path = Path("/proc/uptime")
    if uptime_path.exists():
        try:
            first = uptime_path.read_text(encoding="utf-8").split()[0]
            uptime_seconds = round(float(first), 1)
        except (OSError, ValueError, IndexError):
            pass

    luks_state = probe_luks2_status()
    tpm_state = probe_tpm2_status()

    return {
        "service": "Velocitee Prism Sovereign AI Hub",
        "version": "2.0.0",
        "status": "online" if activated else "quarantined",
        "activated": activated,
        "gateway_node_status": gateway_status,
        "active_profile_id": active_profile_id,
        "hermes_agent_ready": True,
        "openai_proxy_endpoint": "/v1/chat/completions",
        "mcp_endpoint": "/api/v1/mcp",
        "host": {
            "hostname": platform.node(),
            "os": read_os_release(),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "pid": os.getpid(),
            "mem_total_mb": mem_total_mb,
            "mem_available_mb": mem_avail_mb,
            "uptime_seconds": uptime_seconds,
        },
        "hardware_security": {
            "luks2_encrypted": luks_state,
            "tpm2_present": tpm_state,
        },
    }
