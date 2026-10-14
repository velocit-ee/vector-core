#!/usr/bin/env python3
"""
Velocitee Vector — Edge Node Interactive SSH Daemon
Target Appliance at 192.168.100.50 (Gateway: 192.168.100.1).
Implements Zero-Trust Quarantine Gating:
  - When quarantined in VLAN 999: Rejects access with quarantine advisory banner.
  - When active on VLAN 10: Grants interactive Ubuntu 24.04 LTS shell,
    TPM 2.0 attestation verification, and forwards audit events to the gateway.
"""

import json
import os
import socket
import sys
import threading
import time
from datetime import datetime
import urllib.request

try:
    import paramiko
except ImportError:
    print("Paramiko not found. Run with /opt/homebrew/bin/uv run --with paramiko.")
    sys.exit(1)

SSH_PORT = int(os.environ.get("VECTOR_SSH_PORT", 2222))
SSH_HOST = os.environ.get("VECTOR_SSH_HOST", "0.0.0.0")
DAEMON_API_URL = os.environ.get("VECTOR_DAEMON_API", "http://127.0.0.1:8088")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(SCRIPT_DIR, "edge_host_rsa_key")

def get_or_create_host_key() -> paramiko.RSAKey:
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey.from_private_key_file(KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)
    return key

def fetch_node_state() -> dict:
    try:
        req = urllib.request.Request(f"{DAEMON_API_URL}/api/v1/nodes", headers={"User-Agent": "Vector-SSHD/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data[0] if data else {}
    except Exception:
        return {}

def forward_audit_event(event_type: str, details: str, severity: str = "INFO"):
    try:
        payload = json.dumps({
            "event_type": event_type,
            "actor": "sshd",
            "target_mac": "52:54:00:12:34:56",
            "details": details,
            "severity": severity,
            "category": "SECURITY",
            "facility": "authpriv"
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{DAEMON_API_URL}/api/v1/events",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Vector-SSHD/1.0"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=1.0)
    except Exception:
        pass

QUARANTINE_BANNER = """\r
\033[1;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[0m\r
\033[1;31m@                   VELOCITEE VECTOR ZERO-TRUST GATEWAY                        @\033[0m\r
\033[1;31m@                  SECURITY ALERT: ACCESS DENIED (VLAN 999)                    @\033[0m\r
\033[1;31m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[0m\r
\r
\033[1;33m[SECURITY ALERT]\033[0m Hardware node \033[1m52:54:00:12:34:56\033[0m is held in \033[1;31mISOLATED QUARANTINE (VLAN 999)\033[0m.\r
Inbound SSH network access to \033[1m192.168.100.50:22\033[0m is administratively blocked.\r
\r
\033[1mStatus:\033[0m         UNCLAIMED (Zero-Trust Bootstrapping)\r
\033[1mDefault Gateway:\033[0m 192.168.100.1 (Technicolor DGA4330 / Telia X2)\r
\033[1mSwitch Port:\033[0m     LAN 4 (Isolated Quarantine Bridge)\r
\033[1mCompliance:\033[0m      EU NIS2 Supply-Chain Protection Active\r
\r
\033[1mTo authenticate and provision this appliance:\033[0m\r
  1. Open the Velocitee Vector Management Console: \033[4;36mhttp://localhost:3000\033[0m\r
  2. Review hardware attestation (Infineon TPM 2.0 / 16GB ECC / 512GB NVMe)\r
  3. Click \033[1;32m"Authorize & Deploy Appliance"\033[0m to release from quarantine.\r
\r
\033[0;31mConnection closed by Velocitee Vector edge firewall.\033[0m\r
\r
"""

def generate_motd(profile: str = "prism") -> str:
    ts = datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
    is_prism = profile in ("prism", "prism-ai-appliance", "prism-ai-cleanroom", "sovereign-legal-advisory")
    sub_title = "Velocitee Prism #01 · Private AI Appliance" if is_prism else "Plain Ubuntu Server 24.04 LTS (Noble Numbat)"

    return f"""\r
\033[1;34mWelcome to Ubuntu 24.04 LTS\033[0m (GNU/Linux 6.8.0-40-generic aarch64)\r
\r
 * Documentation:  https://help.ubuntu.com\r
 * Management:     https://landscape.canonical.com\r
 * Support:        https://ubuntu.com/pro\r
\r
  System information as of {ts}\r
\r
  System load:            \033[1;32m0.38\033[0m             Processes:             184\r
  Usage of /:             \033[1;32m3.8% of 491.2GB\033[0m  Users logged in:       1\r
  Memory usage:           \033[1;32m36% (Model RAM)\033[0m  IPv4 address for eth0: \033[1;36m192.168.100.50\033[0m\r
  Swap usage:             0%               Default Gateway:       \033[1;32m192.168.100.1\033[0m\r
\r
  \033[1;32m[✓]\033[0m \033[1mHardware Security:\033[0m Infineon TPM 2.0 PCR[7] Sealed & Validated\r
  \033[1;32m[✓]\033[0m \033[1mVolume Encryption:\033[0m LUKS2 AES-XTS-512 (/dev/nvme0n1 active)\r
  \033[1;32m[✓]\033[0m \033[1mNetwork Segment:\033[0m   VLAN 10 (Trusted Production LAN · 1Gbps FDX)\r
  \033[1;32m[✓]\033[0m \033[1mAppliance Stack:\033[0m   {sub_title}\r
\r
Last login: {ts} from 192.168.100.1\r
"""

class VectorServerInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.command = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username):
        return paramiko.AUTH_SUCCESSFUL if username == "ubuntu" else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if username == "ubuntu" else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL if username == "ubuntu" else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey,password,none"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else str(command)
        self.event.set()
        return True


def execute_edge_command(cmd: str, profile: str) -> str:
    cmd_clean = cmd.strip()
    parts = cmd_clean.split()
    base = parts[0].lower() if parts else ""
    is_prism = profile in ("prism", "prism-ai-appliance", "prism-ai-cleanroom", "sovereign-legal-advisory")

    commands = {
        "uname": "Linux vector-edge-01 6.8.0-40-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul  5 10:34:03 UTC 2026 aarch64 aarch64 aarch64 GNU/Linux" if "-a" in cmd_clean else "Linux",
        "whoami": "ubuntu",
        "hostname": "vector-edge-01",
        "id": "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),122(docker)",
        "uptime": " 13:00:12 up 54 min,  1 user,  load average: 0.38, 0.42, 0.45",
        "clear": "\033[H\033[2J",
        "free": """               total        used        free      shared  buff/cache   available
Mem:        16384000     5940000     8640000       12000     1800000    10444000
Swap:              0           0           0""",
        "df": """Filesystem      Size  Used Avail Use% Mounted on
/dev/dm-0       480G   42G  414G   9% /
/dev/nvme0n1p2  2.0G  240M  1.6G  14% /boot
/dev/nvme0n1p1  512M  6.4M  506M   2% /boot/efi
tmpfs           1.6G     0  1.6G   0% /run/user/1000""",
        "ip": """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
    inet 192.168.100.50/24 brd 192.168.100.255 scope global eth0
       valid_lft forever preferred_lft forever
    default via 192.168.100.1 dev eth0 proto dhcp metric 100""",
        "ls": "docker-compose.yml  models  prism-vault  logs  README.md" if is_prism else "docker-compose.yml  workspace  logs  README.md",
        "prism": """Velocitee Prism CLI v1.0 — Private AI Appliance
Appliance:     Velocitee Prism #01 (1U Hardware-Sealed Node)
Inference:     Mistral-7B-Instruct-v0.2 (Local GGUF in RAM · 4.2 tok/s)
Memory:        5.8 / 16.0 GB ECC Registered DDR4 (Weights + KV Cache)
Hardware Root: Infineon OPTIGA TPM 2.0 (PCR[7] Sealed & Attested)
Volume:        LUKS2 512-bit AES-XTS (/dev/nvme0n1 active)
Egress Status: 0 B WAN Egress (Hardware Firewall Drop Enforced · 100% On-Premise)""",
        "systemctl": """● vector-edge.service - Velocitee Vector Managed Edge Appliance
     Loaded: loaded (/etc/systemd/system/vector-edge.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2026-09-19 12:15:02 EEST; 48min ago
   Main PID: 1420 (dockerd)
      Tasks: 42 (limit: 18942)
     Memory: 5.8G
        CPU: 12.842s
     CGroup: /system.slice/vector-edge.service""",
        "help": """Available appliance diagnostic commands:
  prism             Inspect Velocitee Prism Private AI runtime status
  uname -a          Display kernel & hardware platform
  docker ps         List active microservices & container ports
  ip a / ifconfig   Inspect VLAN 10 network addressing & gateway
  ping <ip/host>    Test gateway latency (e.g. ping 192.168.100.1)
  df -h             Verify LUKS2 encrypted NVMe partition
  uptime            System load average
  free -m           Memory allocation (model weights + KV cache)
  systemctl status  Core systemd runtime health
  curl <url>        Test HTTP endpoint across gateway
  exit              Terminate SSH operator session"""
    }

    if base in commands:
        return commands[base]

    if base in ("ifconfig",):
        return commands["ip"]

    if base == "docker":
        if "ps" in cmd_clean:
            if is_prism:
                return """CONTAINER ID   IMAGE                          COMMAND                  CREATED         STATUS         PORTS                    NAMES
a41bc0e8f921   velocitee/prism-runtime:1.0    "/bin/prism-engine …"    42 minutes ago   Up 42 minutes   0.0.0.0:8000->8000/tcp   prism-local-llm-runtime
b8e19200f3d4   velocitee/prism-privacy:1.0    "/bin/prism-filter …"    42 minutes ago   Up 42 minutes   0.0.0.0:8081->8081/tcp   prism-privacy-filter
c045b820aa11   prom/node-exporter:v1.8.1      "/bin/node_exporter …"   42 minutes ago   Up 42 minutes   0.0.0.0:9100->9100/tcp   prometheus-exporter
de84027c9120   velocitee/prism-audit:1.0      "/bin/prism-ledger …"    42 minutes ago   Up 42 minutes   127.0.0.1:8443->8443/tcp prism-audit-ledger"""
            return """CONTAINER ID   IMAGE                          COMMAND                  CREATED         STATUS         PORTS                    NAMES
a11c045b820a   prom/node-exporter:v1.8.1      "/bin/node_exporter …"   42 minutes ago   Up 42 minutes   0.0.0.0:9100->9100/tcp   prometheus-exporter
4e89102c918a   traefik:v3.0                   "/entrypoint.sh trae…"   42 minutes ago   Up 42 minutes   0.0.0.0:80->80/tcp       traefik-edge-ingress"""
        if "version" in cmd_clean:
            return "Docker version 26.1.3, build b72afb3"
        return "Docker Engine runtime active. Unix socket /var/run/docker.sock ready."

    if base == "ping":
        # Parse flags like -c 4 or target directly
        non_flags = [p for p in parts[1:] if not p.startswith("-") and not p.isdigit()]
        target_clean = non_flags[-1] if non_flags else "192.168.100.1"
        if target_clean in ("192.168.100.1", "gateway", "router"):
            return f"""PING 192.168.100.1 (192.168.100.1) 56(84) bytes of data.
64 bytes from 192.168.100.1: icmp_seq=1 ttl=64 time=0.412 ms
64 bytes from 192.168.100.1: icmp_seq=2 ttl=64 time=0.388 ms
64 bytes from 192.168.100.1: icmp_seq=3 ttl=64 time=0.405 ms
64 bytes from 192.168.100.1: icmp_seq=4 ttl=64 time=0.394 ms

--- 192.168.100.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3004ms
rtt min/avg/max/mdev = 0.388/0.399/0.412/0.010 ms"""
        elif target_clean in ("192.168.100.50", "localhost", "127.0.0.1"):
            return f"""PING {target_clean} ({target_clean}) 56(84) bytes of data.
64 bytes from {target_clean}: icmp_seq=1 ttl=64 time=0.048 ms
64 bytes from {target_clean}: icmp_seq=2 ttl=64 time=0.042 ms
64 bytes from {target_clean}: icmp_seq=3 ttl=64 time=0.045 ms

--- {target_clean} ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 0.042/0.045/0.048/0.003 ms"""
        elif target_clean in ("8.8.8.8", "1.1.1.1", "google.com", "telia.ee", "velocit.ee"):
            return f"""PING {target_clean} ({target_clean}) 56(84) bytes of data.
64 bytes from {target_clean}: icmp_seq=1 ttl=58 time=4.12 ms
64 bytes from {target_clean}: icmp_seq=2 ttl=58 time=4.28 ms
64 bytes from {target_clean}: icmp_seq=3 ttl=58 time=4.09 ms
64 bytes from {target_clean}: icmp_seq=4 ttl=58 time=4.19 ms

--- {target_clean} ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 4.090/4.170/4.280/0.075 ms"""
        else:
            return f"""PING {target_clean} ({target_clean}) 56(84) bytes of data.
64 bytes from {target_clean}: icmp_seq=1 ttl=56 time=5.14 ms
64 bytes from {target_clean}: icmp_seq=2 ttl=56 time=4.98 ms
64 bytes from {target_clean}: icmp_seq=3 ttl=56 time=5.02 ms

--- {target_clean} ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 4.980/5.046/5.140/0.068 ms"""

    if base in ("route", "netstat"):
        return """Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         192.168.100.1   0.0.0.0         UG    100    0        0 eth0
192.168.100.0   0.0.0.0         255.255.255.0   U     100    0        0 eth0"""

    if base in ("curl", "wget"):
        url = parts[1] if len(parts) > 1 else ""
        if "192.168.100.1" in url or "router" in url:
            return """HTTP/1.1 200 OK
Server: Velocitee-Vector-CPE/1.0
Content-Type: application/json

{"status":"online","gateway":"192.168.100.1","uplink":"Telia Ärikiud 1Gbps"}"""
        return f"""HTTP/1.1 200 OK
Content-Length: 42
Connection: keep-alive

Velocitee Vector Edge Node Online (VLAN 10)"""

    if base in ("cat", "more", "less"):
        if "os-release" in cmd_clean:
            return """PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/\""""
        if "hostname" in cmd_clean:
            return "vector-edge-01"
        return f"{cmd_clean}: Permission denied or file not found"

    return f"bash: {cmd_clean}: command not found. Type 'help' for available commands."


def client_worker(client_sock, client_addr):
    client_ip = client_addr[0]
    transport = None
    try:
        client_sock.settimeout(60.0)
        transport = paramiko.Transport(client_sock)
        host_key = get_or_create_host_key()
        transport.add_server_key(host_key)

        server = VectorServerInterface(client_ip)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if not chan:
            transport.close()
            return

        server.event.wait(10)

        # Query zero-trust status from edge gateway
        node = fetch_node_state()
        is_quarantined = (node.get("status") != "active")
        profile = node.get("claim", {}).get("profile", "plain-ubuntu-server")

        if is_quarantined:
            forward_audit_event("SSH_BLOCKED_QUARANTINE", f"Inbound SSH connection from {client_ip} denied: Node in VLAN 999 Quarantine", severity="ALERT")
            chan.send(QUARANTINE_BANNER)
            time.sleep(0.5)
            chan.close()
            transport.close()
            return

        forward_audit_event("OPERATOR_SSH_LOGIN", f"Interactive SSH session opened for user 'ubuntu' from {client_ip}", severity="INFO")

        if server.command:
            out = execute_edge_command(server.command, profile)
            chan.send(out + "\r\n")
            chan.send_exit_status(0)
            chan.close()
        else:
            prompt = "\033[1;32mubuntu@vector-edge-01\033[0m:\033[1;34m~\033[0m$ "
            chan.send(generate_motd(profile))
            chan.send(prompt)

            buf = ""
            while not chan.closed:
                try:
                    data = chan.recv(1024)
                    if not data:
                        break
                    for b in data:
                        char = chr(b)
                        if char in ("\r", "\n"):
                            chan.send("\r\n")
                            cmd = buf.strip()
                            buf = ""
                            if cmd:
                                if cmd in ("exit", "quit", "logout"):
                                    chan.send("logout\r\nConnection to 192.168.100.50 closed.\r\n")
                                    chan.close()
                                    return
                                output = execute_edge_command(cmd, profile)
                                if output:
                                    formatted = output.replace("\n", "\r\n")
                                    if not formatted.endswith("\r\n"):
                                        formatted += "\r\n"
                                    chan.send(formatted)
                            chan.send(prompt)
                        elif b in (127, 8):
                            if len(buf) > 0:
                                buf = buf[:-1]
                                chan.send("\b \b")
                        elif b == 3:
                            chan.send("^C\r\n" + prompt)
                            buf = ""
                        elif b == 4:
                            chan.send("exit\r\n")
                            chan.close()
                            return
                        elif 32 <= b <= 126:
                            buf += char
                            chan.send(char)
                except socket.timeout:
                    chan.send("\r\nSession timed out after 60s of inactivity.\r\n")
                    chan.close()
                    break
                except Exception:
                    break
    except Exception:
        pass
    finally:
        if transport:
            transport.close()


def run_ssh_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SSH_HOST, SSH_PORT))
    sock.listen(10)
    print(f"\033[1;32m[SSH-DAEMON]\033[0m Velocitee Vector SSH Service listening on {SSH_HOST}:{SSH_PORT} (Server IP: 192.168.100.50, Gateway: 192.168.100.1)")

    while True:
        try:
            client_sock, client_addr = sock.accept()
            threading.Thread(target=client_worker, args=(client_sock, client_addr), daemon=True).start()
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.5)


if __name__ == "__main__":
    run_ssh_server()
