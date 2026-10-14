#!/usr/bin/env python3
"""
Velocitee Vector — Telia Carrier CPE Router SSH Daemon (Port 2221)
Represents the Gateway Router at 192.168.100.1 (Technicolor DGA4330 / Telia X2).
Provides an authentic OpenWrt / carrier shell with live telemetry,
UCI network configuration, firewall rules, and syslog stream.
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

ROUTER_SSH_PORT = int(os.environ.get("VECTOR_ROUTER_SSH_PORT", 2221))
ROUTER_SSH_HOST = os.environ.get("VECTOR_ROUTER_SSH_HOST", "0.0.0.0")
DAEMON_API_URL = os.environ.get("VECTOR_DAEMON_API", "http://127.0.0.1:8088")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(SCRIPT_DIR, "router_host_rsa_key")


def get_or_create_host_key() -> paramiko.RSAKey:
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey.from_private_key_file(KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_FILE)
    return key


def fetch_gateway_telemetry() -> dict:
    try:
        req = urllib.request.Request(f"{DAEMON_API_URL}/api/v1/telemetry", headers={"User-Agent": "Router-SSHD/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {
            "hardware_model": "Technicolor DGA4330 (Vantiva)",
            "lan_ip": "192.168.100.1",
            "cpu_arch": "Broadcom BCM63138 (Dual-core ARM Cortex-A9 @ 1.0 GHz)",
            "ram_used_mb": 38,
            "ram_total_mb": 512,
            "uplink": {"wan_ip": "194.126.101.42", "speed": "1000 / 1000 Mbps", "type": "Telia Ärikiud"}
        }


def fetch_audit_logs() -> list:
    try:
        req = urllib.request.Request(f"{DAEMON_API_URL}/api/v1/audit-log", headers={"User-Agent": "Router-SSHD/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []


def fetch_node_state() -> dict:
    try:
        req = urllib.request.Request(f"{DAEMON_API_URL}/api/v1/nodes", headers={"User-Agent": "Router-SSHD/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            nodes = json.loads(resp.read().decode("utf-8"))
            return nodes[0] if nodes else {}
    except Exception:
        return {}


ROUTER_MOTD = """\r
\033[1;36m  _______     _ _         __      __        _             \033[0m\r
\033[1;36m |__   __|   | (_)        \\ \\    / /       | |            \033[0m\r
\033[1;36m    | | ___  | |_  __ _    \\ \\  / /__  ___ | |_ ___  _ __ \033[0m\r
\033[1;36m    | |/ _ \\ | | |/ _` |    \\ \\/ / _ \\/ __/| __/ _ \\| '__|\033[0m\r
\033[1;36m    | |  __/ | | | (_| |     \\  /  __/ (__ | || (_) | |   \033[0m\r
\033[1;36m    |_|\\___| |_|_|\\__,_|      \\/ \\___|\\___| \\__\\___/|_|   \033[0m\r
\033[1;30m----------------------------------------------------------------------\033[0m\r
 \033[1;37mTelia Carrier Edge Gateway\033[0m · Technicolor DGA4330 (Telia X2 CPE)\r
 Firmware:     18.3.c.0454-Telia-Vector-v1.0 (Broadcom BCM63138 @ 1.0 GHz)\r
 Router IP:    \033[1;32m192.168.100.1/24\033[0m (br-lan default gateway)\r
 WAN Uplink:   194.126.101.42 (Telia Ärikiud 1000/1000 Mbps SFP+)\r
 Target Node:  \033[1;34m192.168.100.50\033[0m on Port 4 (Quarantine / Zero-Trust Bridge)\r
 System Specs: 512 MB RAM · Broadcom Cortex-A9 Dual-Core · TPM 2.0\r
\033[1;30m----------------------------------------------------------------------\033[0m\r
 Type 'help' for available carrier management commands.\r
\r
"""


class RouterSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.command = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username in ("root", "admin"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        if username in ("root", "admin"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username in ("root", "admin"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "none,password,publickey"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.command = command.decode("utf-8", errors="replace") if isinstance(command, bytes) else str(command)
        self.event.set()
        return True


def execute_router_cmd(raw_cmd: str) -> str:
    cmd = raw_cmd.strip()
    gw = fetch_gateway_telemetry()
    node = fetch_node_state()
    node_status = node.get("status", "unknown")
    node_vlan = "VLAN 10 (Trusted Office)" if node_status == "active" else "VLAN 999 (Isolated Quarantine)"

    if cmd in ("help", "?"):
        return """Available Carrier Router Commands:
  uci show network       - View OpenWrt network interface configuration
  uci show firewall      - View zero-trust traffic isolation policy
  iptables -L -n -v      - Inspect hardware port filtering rules
  ip a / ifconfig        - Display gateway network interfaces and IPs
  logread                - Stream gateway syslog and Vector orchestration events
  free -m                - Inspect CPE memory footprint (512MB hardware budget)
  uname -a               - Display carrier kernel architecture
  vector-status          - Summarize Port 4 bare-metal target state
  cat /etc/os-release    - Display Telia Vector carrier firmware release
  exit / quit            - Close terminal session
"""

    if "uci show network" in cmd or cmd == "uci show":
        return f"""network.loopback=interface
network.loopback.device='lo'
network.loopback.proto='static'
network.loopback.ipaddr='127.0.0.1'
network.loopback.netmask='255.0.0.0'

network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.100.1'
network.lan.netmask='255.255.255.0'

network.wan=interface
network.wan.device='eth0'
network.wan.proto='static'
network.wan.ipaddr='{gw.get("uplink", {}).get("wan_ip", "194.126.101.42")}'
network.wan.netmask='255.255.255.0'
network.wan.gateway='194.126.101.1'

network.port4_edge=interface
network.port4_edge.device='lan4'
network.port4_edge.proto='static'
network.port4_edge.ipaddr='192.168.100.1'
network.port4_edge.target_ip='192.168.100.50'
network.port4_edge.vlan='{999 if node_status != "active" else 10}'
network.port4_edge.segment='{node_vlan}'
"""

    if "uci show firewall" in cmd or "iptables" in cmd:
        return f"""# Hardware Port 4 Zero-Trust Isolation Filter (Telia X2)
Chain FORWARD (policy DROP 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
 1420 85200 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0           ctstate RELATED,ESTABLISHED
    0     0 ACCEPT     all  --  br-lan br-lan  192.168.100.0/24     192.168.100.0/24
    0     0 {"ACCEPT" if node_status == "active" else "DROP"}     all  --  lan4   *       192.168.100.50       0.0.0.0/0           /* Port 4 Node: {node_vlan} */
 2104  126K ACCEPT     all  --  *      eth0    192.168.100.0/24     0.0.0.0/0           /* WAN NAT masquerade */
"""

    if cmd in ("ip a", "ip addr", "ifconfig"):
        return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP
    link/ether 00:10:18:7a:9b:01 brd ff:ff:ff:ff:ff:ff
    inet {gw.get("uplink", {}).get("wan_ip", "194.126.101.42")}/24 brd 194.126.101.255 scope global eth0
3: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 00:10:18:7a:9b:02 brd ff:ff:ff:ff:ff:ff
    inet 192.168.100.1/24 brd 192.168.100.255 scope global br-lan
4: lan4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP
    link/ether 00:10:18:7a:9b:06 brd ff:ff:ff:ff:ff:ff
    inet 192.168.100.1/24 scope global lan4 (Attached: 192.168.100.50 · {node_vlan})
"""

    if cmd in ("free", "free -m", "free -h"):
        return """              total        used        free      shared  buff/cache   available
Mem:            512          38         432           4          42         464
Swap:             0           0           0
"""

    if cmd in ("uname", "uname -a"):
        return "Linux telia-gateway 5.4.188-broadcom #1 SMP PREEMPT Thu Mar 19 14:22:01 UTC 2026 armv7l GNU/Linux\n"

    if cmd.startswith("cat /proc/cpuinfo") or cmd == "lscpu":
        return """processor	: 0
model name	: ARMv7 Processor rev 5 (v7l)
BogoMIPS	: 2000.00
Features	: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt
CPU implementer	: 0x41
CPU architecture: 7
CPU variant	: 0x0
CPU part	: 0xc09
CPU revision	: 5

processor	: 1
model name	: ARMv7 Processor rev 5 (v7l)
Hardware	: Broadcom BCM63138 (Technicolor DGA4330 Telia X2)
Revision	: 0000
"""

    if cmd.startswith("cat /etc/os-release"):
        return """NAME="Telia Vector Carrier OS"
VERSION="18.3.c.0454"
ID="telia-vector"
ID_LIKE="openwrt lede"
PRETTY_NAME="Telia Vector Carrier Edition 18.3 (Technicolor DGA4330)"
HOME_URL="https://velocit.ee"
BUG_REPORT_URL="https://support.telia.ee"
"""

    if "logread" in cmd or "syslog" in cmd:
        logs = fetch_audit_logs()
        if not logs:
            return "Sep 19 13:00:00 telia-gateway syslogd: Vector audit log streaming active\n"
        out = []
        for l in logs[-12:]:
            ts = l.get("timestamp", "")[:19].replace("T", " ")
            sev = l.get("severity", "INFO")
            ev = l.get("event_type", "AUDIT")
            det = l.get("details", "")
            out.append(f"{ts} telia-gateway [{sev}] [{ev}] {det}")
        return "\n".join(out) + "\n"

    if cmd in ("vector-status", "status"):
        return f"""======================================================================
  VELOCITEE VECTOR CPE ORCHESTRATOR STATUS
======================================================================
  Router IP:         192.168.100.1 (Broadcom BCM63138 · RAM: 38MB / 512MB)
  WAN Uplink:        {gw.get("uplink", {}).get("wan_ip")} ({gw.get("uplink", {}).get("speed")})
  Target Appliance:  192.168.100.50 (Port 4)
  Target MAC:        {node.get("mac", "52:54:00:12:34:56")}
  Target Status:     {node_status.upper()}
  Active Segment:    {node_vlan}
  API Gateway:       Online (:8088) · Next.js Management Console (:3000)
======================================================================
"""

    return f"sh: command not found: {cmd}. Type 'help' for available commands.\n"


def handle_router_client(client_sock, addr):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(get_or_create_host_key())
    server = RouterSSHServer()

    try:
        transport.start_server(server=server)
    except Exception as e:
        transport.close()
        return

    channel = transport.accept(20)
    if channel is None:
        transport.close()
        return

    server.event.wait(10)
    client_sock.settimeout(60.0)

    try:
        if server.command:
            output = execute_router_cmd(server.command)
            channel.send(output + "\r\n")
            channel.send_exit_status(0)
            channel.close()
            transport.close()
            return

        channel.send(ROUTER_MOTD.replace("\n", "\r\n"))
        channel.send("\033[1;32mroot@telia-gateway\033[0m:\033[1;34m~\033[0m# ")

        buf = ""
        while True:
            char = channel.recv(1)
            if not char:
                break

            if char in (b"\r", b"\n"):
                channel.send("\r\n")
                cmd = buf.strip()
                buf = ""
                if cmd in ("exit", "quit"):
                    channel.send("Connection to 192.168.100.1 closed.\r\n")
                    break
                elif cmd:
                    output = execute_router_cmd(cmd)
                    channel.send(output.replace("\n", "\r\n"))
                channel.send("\033[1;32mroot@telia-gateway\033[0m:\033[1;34m~\033[0m# ")
            elif char in (b"\x7f", b"\x08"):
                if buf:
                    buf = buf[:-1]
                    channel.send("\b \b")
            elif char == b"\x03":  # Ctrl+C
                channel.send("^C\r\n\033[1;32mroot@telia-gateway\033[0m:\033[1;34m~\033[0m# ")
                buf = ""
            elif char == b"\x04":  # Ctrl+D
                break
            else:
                try:
                    s = char.decode("utf-8")
                    buf += s
                    channel.send(s)
                except UnicodeDecodeError:
                    pass
    except (socket.timeout, OSError):
        pass
    finally:
        channel.close()
        transport.close()


def run_router_ssh():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((ROUTER_SSH_HOST, ROUTER_SSH_PORT))
    server_sock.listen(10)
    print(f"\033[1;36m[ROUTER-SSHD]\033[0m Carrier Router SSH Daemon listening on port {ROUTER_SSH_PORT} (Router Gateway IP: 192.168.100.1)")

    while True:
        try:
            client_sock, addr = server_sock.accept()
            t = threading.Thread(target=handle_router_client, args=(client_sock, addr), daemon=True)
            t.start()
        except Exception as e:
            time.sleep(0.5)


if __name__ == "__main__":
    run_router_ssh()
