#!/bin/bash
set -e

# Velocitee Vector — Edge Network & SSH Configuration Helper
# Configures dedicated IP space on macOS loopback (lo0):
#   - 192.168.100.1  -> Router Gateway (Technicolor DGA4330 CPE)
#   - 192.168.100.50 -> Server Node (Bare-Metal MicroServer Appliance)
# Maps ~/.ssh/config for authentic 'ssh ubuntu@192.168.100.50' access.

ROUTER_IP="192.168.100.1"
SERVER_IP="192.168.100.50"
SERVER_PORT="2222"
SSH_CONFIG="$HOME/.ssh/config"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║       VELOCITEE VECTOR — DEDICATED EDGE NETWORK SETUP (macOS)       ║"
echo "║       Router Gateway: 192.168.100.1 · Server Node: 192.168.100.50   ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

if [ "$1" == "--remove" ] || [ "$1" == "teardown" ]; then
    echo "[+] Removing dedicated IP aliases from lo0..."
    sudo ifconfig lo0 -alias "$ROUTER_IP" 2>/dev/null || true
    sudo ifconfig lo0 -alias "$SERVER_IP" 2>/dev/null || true
    echo "[✓] Dedicated IPs removed from lo0."
    exit 0
fi

echo "[1/3] Configuring loopback aliases on lo0..."
for IP in "$ROUTER_IP" "$SERVER_IP"; do
    if ifconfig lo0 | grep -q "$IP"; then
        echo "  [✓] $IP is already bound to lo0."
    else
        echo "  [!] Binding $IP to lo0 (requires sudo)..."
        sudo ifconfig lo0 alias "$IP" 255.255.255.255
        echo "  [✓] $IP successfully aliased on lo0."
    fi
done

echo "[2/3] Verifying ICMP reachability..."
for IP in "$ROUTER_IP" "$SERVER_IP"; do
    if ping -c 1 -W 1 "$IP" >/dev/null 2>&1; then
        echo "  [✓] Ping to $IP succeeded."
    else
        echo "  [i] Note: Ping to $IP did not respond immediately, continuing..."
    fi
done

echo "[3/3] Configuring SSH client configuration in $SSH_CONFIG..."
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$SSH_CONFIG"

if grep -q "Host 192.168.100.1" "$SSH_CONFIG" 2>/dev/null; then
    echo "  [✓] Host 192.168.100.1 is already configured in $SSH_CONFIG."
else
    cat << 'SSHCFG' >> "$SSH_CONFIG"

# Velocitee Vector Router Gateway (Technicolor DGA4330 CPE)
Host 192.168.100.1
    HostName 192.168.100.1
    Port 2221
    User root
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
SSHCFG
    echo "  [✓] Added Host 192.168.100.1 block to $SSH_CONFIG (Port 2221, User root)."
fi

if grep -q "Host 192.168.100.50" "$SSH_CONFIG" 2>/dev/null; then
    echo "  [✓] Host 192.168.100.50 is already configured in $SSH_CONFIG."
else
    cat << 'SSHCFG' >> "$SSH_CONFIG"

# Velocitee Vector Edge Appliance (Target Bare-Metal Node)
Host 192.168.100.50
    HostName 192.168.100.50
    Port 2222
    User ubuntu
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
SSHCFG
    echo "  [✓] Added Host 192.168.100.50 block to $SSH_CONFIG (Port 2222, User ubuntu)."
fi

echo
echo "══════════════════════════════════════════════════════════════════════"
echo "  CONFIGURATION COMPLETE!"
echo "  • Router Gateway IP:   http://192.168.100.1:8088"
echo "  • Router Gateway SSH:  ssh root@192.168.100.1"
echo "  • Server Node Hub IP:  http://192.168.100.50:8081"
echo "  • Server Node SSH:     ssh ubuntu@192.168.100.50"
echo "  • Management Console:  http://localhost:3000"
echo "══════════════════════════════════════════════════════════════════════"
