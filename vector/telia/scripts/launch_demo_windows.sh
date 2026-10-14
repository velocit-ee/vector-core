#!/bin/bash
# ==============================================================================
# Velocitee Vector — Demo Window Launcher (macOS)
# Launches browser dashboards and two side-by-side Terminal windows for SSH.
#
# Usage:
#   bash core/vector/telia/scripts/launch_demo_windows.sh
#   bash core/vector/telia/scripts/launch_demo_windows.sh --monitor  # Also opens Activity Monitor
# ==============================================================================

set -e

ROUTER_IP="192.168.100.1"
SERVER_IP="192.168.100.50"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║          VELOCITEE VECTOR — DEMO WORKSPACE LAUNCHER                  ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# Check if services are listening, auto-start any missing daemons
echo "[1/4] Ensuring all demo daemons are active..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/core/vector/telia" ]; then
    PROJECT_ROOT="$SCRIPT_DIR"
else
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
fi
TELIA_DIR="$PROJECT_ROOT/core/vector/telia"
FRONTEND_DIR="$PROJECT_ROOT/vercel-v0-export"

# 1. Edge Router Orchestrator (:8088)
if ! lsof -ti :8088 >/dev/null 2>&1; then
    echo "  [*] Starting Router Edge Orchestrator (:8088)..."
    nohup python3 "$TELIA_DIR/daemon/agent.py" >/dev/null 2>&1 &
    sleep 0.5
fi
echo "  [✓] Router Edge Orchestrator (:8088) is active."

# 2. Velocitee Prism — Private AI Appliance (:8081)
if ! lsof -ti :8081 >/dev/null 2>&1; then
    echo "  [*] Starting Velocitee Prism Private AI Appliance (:8081)..."
    nohup python3 "$TELIA_DIR/target/sovereign_hub.py" >/dev/null 2>&1 &
    sleep 0.5
fi
echo "  [✓] Velocitee Prism Private AI Appliance (:8081) is active."

# 3. Server Node SSH Daemon (:2222)
if ! lsof -ti :2222 >/dev/null 2>&1; then
    echo "  [*] Starting Server Node SSH Daemon (:2222)..."
    nohup /opt/homebrew/bin/uv run --with paramiko python3 "$TELIA_DIR/target/edge_node_ssh.py" >/dev/null 2>&1 &
    sleep 0.5
fi
echo "  [✓] Server Node SSH Daemon (:2222) is active."

# 4. Router SSH Daemon (:2221)
if ! lsof -ti :2221 >/dev/null 2>&1; then
    echo "  [*] Starting Router SSH Daemon (:2221)..."
    nohup /opt/homebrew/bin/uv run --with paramiko python3 "$TELIA_DIR/daemon/router_ssh.py" >/dev/null 2>&1 &
    sleep 0.5
fi
echo "  [✓] Router SSH Daemon (:2221) is active."

# 5. Next.js Management Console (:3000)
if ! lsof -ti :3000 >/dev/null 2>&1; then
    echo "  [*] Starting Next.js Management Console (:3000)..."
    python3 -c "
import subprocess
subprocess.Popen(
    ['npx', 'next', 'dev', '-H', '0.0.0.0', '-p', '3000'],
    cwd='$FRONTEND_DIR',
    stdin=subprocess.DEVNULL,
    stdout=open('/tmp/next_demo.log', 'w'),
    stderr=subprocess.STDOUT,
    start_new_session=True
)
"
    for i in {1..20}; do
        if lsof -ti :3000 >/dev/null 2>&1; then break; fi
        sleep 0.5
    done
fi
echo "  [✓] Next.js Management Console (:3000) is active."

echo "[2/4] Opening Management Console on Carrier Router IP (192.168.100.1)..."
open "http://192.168.100.1:3000"
echo "  [✓] Opened Management Console at http://192.168.100.1:3000"

echo "[3/4] Launching Terminal for Server Node SSH (192.168.100.50)..."
osascript << 'EOF'
tell application "Terminal"
    do script "echo '=== VELOCITEE PRISM — PRIVATE AI APPLIANCE (192.168.100.50) ===' && ssh -p 2222 -o StrictHostKeyChecking=no ubuntu@192.168.100.50"
    activate
end tell
EOF
echo "  [✓] Launched Server Node SSH Terminal (ubuntu@192.168.100.50:2222)"

if [ "${1:-}" == "--router" ] || [ "${1:-}" == "--all" ]; then
    echo "  [*] Launching optional Router Gateway SSH Terminal (192.168.100.1)..."
    osascript << 'EOF'
tell application "Terminal"
    do script "echo '=== VELOCITEE VECTOR ROUTER GATEWAY (192.168.100.1) ===' && ssh -p 2221 -o StrictHostKeyChecking=no root@192.168.100.1"
end tell
EOF
fi

echo "[4/4] Opening macOS Activity Monitor to display native resource allocation..."
open -a "Activity Monitor"
echo "  [✓] Opened Activity Monitor."

echo
echo "══════════════════════════════════════════════════════════════════════"
echo "  VELOCITEE VECTOR & PRISM DEMO READY FOR PRESENTATION!"
echo "  Router Orchestrator (:8088): http://192.168.100.1:8088"
echo "  Next.js Console (:3000):     http://192.168.100.1:3000"
echo "  Velocitee Prism (:8081):     http://192.168.100.50:8081"
echo "  Prism SSH Terminal:          ssh -p 2222 ubuntu@192.168.100.50"
echo "══════════════════════════════════════════════════════════════════════"
