#!/bin/bash
# ==============================================================================
# Velocitee Vector — Edge Demo Teardown Script
# Safely stops all background daemons, cleans up sockets, and recycles ports.
#
# Usage:
#   bash core/vector/telia/scripts/teardown_demo.sh
#   bash core/vector/telia/scripts/teardown_demo.sh --network   # Also removes lo0 aliases
# ==============================================================================

set -e

PORTS=(3000 8088 8081 2221 2222)
PORT_NAMES=(
    "Next.js Management Console"
    "Router Edge Orchestrator"
    "Target Node Sovereign Hub"
    "Router Gateway SSH Server"
    "Edge Appliance SSH Server"
)

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║          VELOCITEE VECTOR — DEMO ENVIRONMENT TEARDOWN               ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

echo "[1/3] Terminating demo background processes..."
for i in "${!PORTS[@]}"; do
    PORT="${PORTS[$i]}"
    NAME="${PORT_NAMES[$i]}"
    
    # Find PIDs on this port
    PIDS=$(lsof -ti :"$PORT" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        echo "  [!] Stopping $NAME on :$PORT (PIDs: $PIDS)..."
        for PID in $PIDS; do
            kill -15 "$PID" 2>/dev/null || true
        done
    else
        echo "  [✓] :$PORT ($NAME) is already clean."
    fi
done

# Short grace period
sleep 1

# Force kill any stubborn remnants
echo "[2/3] Verifying clean port recycling..."
ALL_CLEAN=true
for i in "${!PORTS[@]}"; do
    PORT="${PORTS[$i]}"
    NAME="${PORT_NAMES[$i]}"
    REMAINING=$(lsof -ti :"$PORT" 2>/dev/null || true)
    if [ -n "$REMAINING" ]; then
        echo "  [!] Force-killing remaining PID(s) $REMAINING on :$PORT..."
        for PID in $REMAINING; do
            kill -9 "$PID" 2>/dev/null || true
        done
        sleep 0.5
    fi
    
    # Final check
    if lsof -ti :"$PORT" >/dev/null 2>&1; then
        echo "  [✗] Warning: Port :$PORT could not be freed."
        ALL_CLEAN=false
    else
        echo "  [✓] Port :$PORT is completely free."
    fi
done

# Optional: Network loopback removal
if [ "$1" == "--network" ] || [ "$1" == "--all" ]; then
    echo "[3/3] Removing macOS loopback aliases (192.168.100.1 & 192.168.100.50)..."
    sudo ifconfig lo0 -alias 192.168.100.1 2>/dev/null || true
    sudo ifconfig lo0 -alias 192.168.100.50 2>/dev/null || true
    echo "  [✓] Loopback IP aliases removed."
else
    echo "[3/3] Preserving loopback IP aliases (use --network to remove them)."
fi

echo
echo "══════════════════════════════════════════════════════════════════════"
if [ "$ALL_CLEAN" = true ]; then
    echo "  [✓] TEARDOWN COMPLETE — All demo ports and processes recycled."
else
    echo "  [!] TEARDOWN COMPLETE WITH WARNINGS — Check lsof above."
fi
echo "══════════════════════════════════════════════════════════════════════"
