#!/usr/bin/env bash
# Velocitee Vector — 1-Click Router Deployer
# Automatically packages VME Lite and deploys it to your OpenWrt / GL.iNet router over SSH.

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0 [ROUTER_IP] [ROUTER_USER] [SSH_PORT]"
    echo ""
    echo "Deploys Velocitee Vector VME Lite to an OpenWrt / GL.iNet router."
    echo "Defaults:"
    echo "  ROUTER_IP:   192.168.8.1 (standard GL.iNet default)"
    echo "  ROUTER_USER: root"
    echo "  SSH_PORT:    22"
    echo ""
    echo "Example:"
    echo "  $0 192.168.8.1 root"
    exit 0
fi

ROUTER_IP="${1:-192.168.8.1}"
ROUTER_USER="${2:-root}"
SSH_PORT="${3:-22}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TELIA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DAEMON_DIR="$TELIA_DIR/daemon"
ROUTER_DIR="$TELIA_DIR/router"
ASSETS_DIR="$TELIA_DIR/assets"

echo "=========================================================="
echo "  VELOCITEE VECTOR — VME LITE ROUTER DEPLOYER"
echo "  Target Gateway: ${ROUTER_USER}@${ROUTER_IP}:${SSH_PORT}"
echo "=========================================================="

# 1. Test SSH connectivity
echo "[1/5] Testing SSH connection to router..."
if ! ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=3 "${ROUTER_USER}@${ROUTER_IP}" "echo '[SSH OK] Connected to \$(uname -n)'" 2>/dev/null; then
    echo "[!] Could not connect via passwordless SSH."
    echo "[!] Attempting interactive SSH connection..."
    ssh -p "$SSH_PORT" -o ConnectTimeout=5 "${ROUTER_USER}@${ROUTER_IP}" "echo '[SSH OK] Connected to \$(uname -n)'"
fi

# 2. Package the VME Lite bundle
BUNDLE_DIR=$(mktemp -d /tmp/vme-lite-build.XXXXXX)
ARCHIVE="/tmp/vme-lite-bundle.tar.gz"

echo "[2/5] Assembling VME Lite runtime bundle..."
mkdir -p "$BUNDLE_DIR/assets"

cp "$DAEMON_DIR/agent.py" "$BUNDLE_DIR/"
cp "$DAEMON_DIR/security.py" "$BUNDLE_DIR/"
cp "$DAEMON_DIR/manifest_generator.py" "$BUNDLE_DIR/"
cp "$ROUTER_DIR/vme-lite.init" "$BUNDLE_DIR/"
cp "$ROUTER_DIR/install.sh" "$BUNDLE_DIR/"
cp "$ROUTER_DIR/uninstall.sh" "$BUNDLE_DIR/"

if [ -d "$ASSETS_DIR/tftp" ]; then
    cp -r "$ASSETS_DIR/tftp" "$BUNDLE_DIR/assets/"
fi

chmod +x "$BUNDLE_DIR/install.sh" "$BUNDLE_DIR/uninstall.sh" "$BUNDLE_DIR/vme-lite.init"

tar -czf "$ARCHIVE" -C "$BUNDLE_DIR" .
rm -rf "$BUNDLE_DIR"

ARCHIVE_SIZE=$(ls -lh "$ARCHIVE" | awk '{print $5}')
echo "[2/5] Package assembled: $ARCHIVE ($ARCHIVE_SIZE)"

# 3. Transfer bundle to router
echo "[3/5] Uploading package to router (/tmp)..."
scp -P "$SSH_PORT" "$ARCHIVE" "${ROUTER_USER}@${ROUTER_IP}:/tmp/vme-lite-bundle.tar.gz"
rm -f "$ARCHIVE"

# 4. Trigger remote installation
echo "[4/5] Executing remote installation on OpenWrt..."
ssh -p "$SSH_PORT" "${ROUTER_USER}@${ROUTER_IP}" "
    mkdir -p /tmp/vme-lite
    tar -xzf /tmp/vme-lite-bundle.tar.gz -C /tmp/vme-lite
    sh /tmp/vme-lite/install.sh --with-tftp
    rm -rf /tmp/vme-lite /tmp/vme-lite-bundle.tar.gz
"

# 5. Remote verification from laptop
echo "[5/5] Testing router telemetry endpoint..."
sleep 2

if curl -s --max-time 4 "http://${ROUTER_IP}:8088/api/v1/health" | grep -q '"status":"ok"'; then
    echo "=========================================================="
    echo "  [DEPLOYMENT COMPLETE] VME Lite is live on your router!"
    echo "  API Endpoint:  http://${ROUTER_IP}:8088/api/v1/telemetry"
    echo "  Live Console:  http://${ROUTER_IP}:8088/api/v1/status"
    echo "  Service CMD:   ssh ${ROUTER_USER}@${ROUTER_IP} '/etc/init.d/vme-lite status'"
    echo "=========================================================="
else
    echo "[!] Warning: Deployed successfully, but HTTP check did not return immediately."
    echo "[!] Check service status manually: ssh ${ROUTER_USER}@${ROUTER_IP} '/etc/init.d/vme-lite status'"
fi
