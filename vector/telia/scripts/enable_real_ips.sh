#!/bin/bash
# ==============================================================================
# Velocitee Vector — Enable Real Carrier IP Port Forwarding
# Binds standard Port 80 (HTTP) and Port 22 (SSH) directly to:
#   • 192.168.100.1  (Router Gateway)
#   • 192.168.100.50 (Server Node)
# ==============================================================================

set -e

# Resolve real script directory through any symlinks
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"

# Find edge_port_forwarder.py
FORWARDER_PY="$SCRIPT_DIR/edge_port_forwarder.py"
if [ ! -f "$FORWARDER_PY" ]; then
    if [ -f "$SCRIPT_DIR/core/vector/telia/scripts/edge_port_forwarder.py" ]; then
        FORWARDER_PY="$SCRIPT_DIR/core/vector/telia/scripts/edge_port_forwarder.py"
    else
        echo "[✗] Error: Cannot locate edge_port_forwarder.py"
        exit 1
    fi
fi

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║          VELOCITEE VECTOR — ENABLING TRUE CARRIER IP ACCESS         ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Root privileges required to bind standard ports (80 & 22)."
    echo "[*] Requesting sudo permission..."
    exec sudo "$0" "$@"
fi

python3 "$FORWARDER_PY"
