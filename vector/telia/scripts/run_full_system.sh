#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TELIA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$TELIA_DIR/../../.." && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/vercel-v0-export"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║          VELOCITEE VECTOR — FULL STACK EDGE ENVIRONMENT             ║"
echo "║          Telia Carrier Edition · Zero-Trust Metal Orchestrator      ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# Clean up any lingering processes on ports 8088, 8081, 2222
cleanup() {
    echo ""
    echo "[!] Shutting down Velocitee Vector daemons..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[✓] All processes stopped."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Start Python Edge Gateway Daemon (Port 8088)
echo "[1/4] Starting Telia Vector Edge Gateway Daemon (:8088)..."
python3 "$TELIA_DIR/daemon/agent.py" &
PID_AGENT=$!

# Wait for daemon to bind
sleep 1.0

# 2. Start Sovereign Target Node Console Service (Port 8081)
echo "[2/4] Starting Sovereign Target Node Service (:8081)..."
python3 "$TELIA_DIR/target/sovereign_hub.py" &
PID_HUB=$!

# 3. Start Interactive Edge Node SSH Daemon (:2222)
echo "[3/4] Starting Edge Node SSH Daemon (:2222)..."
/opt/homebrew/bin/uv run --with paramiko python3 "$TELIA_DIR/target/edge_node_ssh.py" &
PID_SSH=$!

# 4. Check Next.js Frontend (:3000)
echo "[4/4] Verifying Next.js Orchestration Console (:3000)..."
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 | grep -q "200"; then
    echo "  [✓] Next.js dev server is already running on http://localhost:3000"
else
    if [ -d "$FRONTEND_DIR" ]; then
        echo "  [*] Launching Next.js development server..."
        (cd "$FRONTEND_DIR" && npx next dev -p 3000) &
    fi
fi

echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "  VELOCITEE VECTOR FULL SYSTEM ONLINE"
echo "══════════════════════════════════════════════════════════════════════"
echo "  • Web Management Console:   http://localhost:3000"
echo "  • Edge Router REST API:     http://localhost:8088/api/v1/telemetry"
echo "  • Target Node Web Service:  http://192.168.100.50:8081 (or http://localhost:8081)"
echo "  • Appliance SSH Endpoint:   ssh ubuntu@192.168.100.50 (or ssh -p 2222 ubuntu@localhost)"
echo "  • Zero-Trust State:         Quarantine Enforced (VLAN 999) -> Unlock via Web UI"
echo "══════════════════════════════════════════════════════════════════════"
echo "  Press Ctrl+C to stop all daemons."
echo ""

wait
