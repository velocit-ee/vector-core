#!/usr/bin/env python3
"""
Velocitee Vector — True Carrier IP Port Forwarder (macOS)
Binds standard ports (Port 80 for HTTP, Port 22 for SSH) directly to dedicated IPs:
  - http://192.168.100.1     -> Router Gateway Web & API (:8088)
  - ssh root@192.168.100.1   -> Router Gateway SSH Shell (:2221)
  - http://192.168.100.50    -> Server Node Sovereign Hub (:8081)
  - ssh ubuntu@192.168.100.50-> Server Node Appliance SSH Shell (:2222)

Enables bookmarking and accessing both machines directly by IP with NO port numbers!
Requires sudo privileges to bind standard ports 80 and 22.
"""

import asyncio
import os
import subprocess
import sys

RELAYS = [
    ("192.168.100.1", 80, "127.0.0.1", 8088, "Router Gateway Web & REST API"),
    ("192.168.100.1", 22, "127.0.0.1", 2221, "Router Gateway SSH (root@192.168.100.1)"),
    ("192.168.100.50", 80, "127.0.0.1", 8081, "Server Node Sovereign Web Hub"),
    ("192.168.100.50", 22, "127.0.0.1", 2222, "Server Node Appliance SSH (ubuntu@192.168.100.50)"),
]


def ensure_lo0_aliases():
    """Ensure 192.168.100.1 and 192.168.100.50 are bound to lo0."""
    try:
        out = subprocess.check_output(["ifconfig", "lo0"]).decode()
        for ip in ("192.168.100.1", "192.168.100.50"):
            if ip not in out:
                print(f"[!] Aliasing {ip} to lo0...")
                subprocess.check_call(["ifconfig", "lo0", "alias", ip, "255.255.255.255"])
                print(f"[✓] {ip} successfully aliased on lo0.")
    except Exception as e:
        print(f"[✗] Failed to configure lo0 aliases: {e}")
        print("    Please run: sudo ifconfig lo0 alias 192.168.100.1 255.255.255.255")
        print("                sudo ifconfig lo0 alias 192.168.100.50 255.255.255.255")
        sys.exit(1)


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_connection(client_reader, client_writer, target_host, target_port, name):
    client_ip = client_writer.get_extra_info('peername')
    try:
        remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
    except Exception as e:
        client_writer.close()
        return

    try:
        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer),
            return_exceptions=True
        )
    except Exception:
        pass


async def start_relays():
    servers = []
    print("\n╔══════════════════════════════════════════════════════════════════════╗")
    print("║        VELOCITEE VECTOR — CARRIER IP PORT FORWARDER (ACTIVE)        ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print("  Standard ports 80 (HTTP) & 22 (SSH) are now mapped directly to IPs:\n")

    for listen_ip, listen_port, target_ip, target_port, name in RELAYS:
        try:
            # We pass reuse_port=True where supported for clean cycling
            server = await asyncio.start_server(
                lambda r, w, tip=target_ip, tp=target_port, nm=name: handle_connection(r, w, tip, tp, nm),
                host=listen_ip,
                port=listen_port,
                reuse_address=True
            )
            servers.append(server)
            proto = "HTTP" if listen_port == 80 else "SSH "
            print(f"  [✓] \033[1;32m{proto}\033[0m \033[1;37m{listen_ip}:{listen_port}\033[0m ──➔ {target_ip}:{target_port} ({name})")
        except PermissionError:
            print(f"  [✗] Permission denied binding to {listen_ip}:{listen_port}.")
            print(f"      Standard ports (<1024) require root. Please re-run with: sudo python3 {__file__}")
            sys.exit(1)
        except OSError as e:
            print(f"  [✗] Failed to bind {listen_ip}:{listen_port}: {e}")

    print("\n══════════════════════════════════════════════════════════════════════")
    print("  YOU CAN NOW BOOKMARK AND OPEN DIRECTLY WITH NO PORT NUMBERS:")
    print("  • Router Gateway:   \033[1;36mhttp://192.168.100.1\033[0m")
    print("  • Server Node Hub:  \033[1;36mhttp://192.168.100.50\033[0m")
    print("  • Router SSH:       \033[1;33mssh root@192.168.100.1\033[0m")
    print("  • Server Node SSH:  \033[1;33mssh ubuntu@192.168.100.50\033[0m")
    print("══════════════════════════════════════════════════════════════════════\n")

    # Run forever
    await asyncio.gather(*(s.serve_forever() for s in servers))


def main():
    if os.geteuid() != 0:
        print("\n\033[1;31m[ERROR] Root privileges required to bind standard Port 80 and Port 22.\033[0m")
        print(f"Please run with sudo:\n  sudo python3 {os.path.abspath(__file__)}\n")
        sys.exit(1)

    ensure_lo0_aliases()

    try:
        asyncio.run(start_relays())
    except KeyboardInterrupt:
        print("\n[!] Port forwarder stopped. Restoring unprivileged state.")


if __name__ == "__main__":
    main()
