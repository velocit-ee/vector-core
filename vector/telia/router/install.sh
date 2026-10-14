#!/bin/sh
# Velocitee Vector — VME Lite Router Installer
# Installs and configures VME Lite on OpenWrt / GL.iNet routers.

set -e

INSTALL_DIR="/opt/vme-lite"
INIT_SCRIPT="/etc/init.d/vme-lite"
TFTP_DIR="$INSTALL_DIR/assets/tftp"
PORT="${VECTOR_ROUTER_PORT:-8088}"

echo "=========================================================="
echo "  VELOCITEE VECTOR — VME LITE ROUTER INSTALLER"
echo "  Target: OpenWrt / GL.iNet Gateway"
echo "=========================================================="

# Check root permissions
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This installer must be run as root."
    exit 1
fi

# Check available flash space (at least 8MB free)
FREE_KB=$(df -k / | awk 'NR==2 {print $4}')
if [ "$FREE_KB" -lt 8192 ]; then
    echo "[!] Warning: Low disk space on rootfs (${FREE_KB}KB free). Proceeding with caution."
fi

# 1. Install Python 3 if missing
if ! command -v python3 >/dev/null 2>&1; then
    echo "[1/5] Python 3 not detected. Updating opkg repositories..."
    opkg update
    echo "[1/5] Installing lightweight Python 3 runtime..."
    opkg install python3 python3-urllib python3-json
else
    echo "[1/5] Python 3 already present: $(python3 --version 2>&1)"
fi

# 2. Setup directory structure
echo "[2/5] Creating VME Lite installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/assets/tftp"
mkdir -p /tmp/telia-vector
chmod 0750 /tmp/telia-vector

# 3. Copy files from current directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[3/5] Installing VME Lite core modules..."

if [ -f "$SCRIPT_DIR/agent.py" ]; then
    cp "$SCRIPT_DIR/agent.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/security.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/manifest_generator.py" "$INSTALL_DIR/"
else
    echo "[!] Error: Core files (agent.py) not found in $SCRIPT_DIR."
    exit 1
fi

if [ -d "$SCRIPT_DIR/assets/tftp" ]; then
    cp -r "$SCRIPT_DIR/assets/tftp/"* "$INSTALL_DIR/assets/tftp/" 2>/dev/null || true
fi

# 4. Install and enable OpenWrt init service
echo "[4/5] Installing OpenWrt procd service..."
if [ -f "$SCRIPT_DIR/vme-lite.init" ]; then
    cp "$SCRIPT_DIR/vme-lite.init" "$INIT_SCRIPT"
    chmod +x "$INIT_SCRIPT"
    "$INIT_SCRIPT" enable
    "$INIT_SCRIPT" restart
else
    echo "[!] Error: vme-lite.init script not found."
    exit 1
fi

# 5. Optional: Configure dnsmasq for iPXE / TFTP netbooting
if [ "$CONFIG_TFTP" = "1" ] || [ "$1" = "--with-tftp" ]; then
    echo "[+] Configuring dnsmasq for bare-metal netbooting..."
    mkdir -p /etc/dnsmasq.d
    if ! grep -q "conf-dir=/etc/dnsmasq.d" /etc/dnsmasq.conf 2>/dev/null; then
        echo "conf-dir=/etc/dnsmasq.d" >> /etc/dnsmasq.conf
    fi

    cat <<EOF > /etc/dnsmasq.d/vme-lite.conf
# Velocitee VME Lite TFTP & iPXE Configuration
enable-tftp
tftp-root=$TFTP_DIR

# iPXE chainloading
dhcp-match=set:efi-x86_64,option:client-arch,7
dhcp-match=set:efi-x86_64,option:client-arch,9
dhcp-boot=tag:efi-x86_64,ipxe-x86_64.efi

dhcp-match=set:efi-arm64,option:client-arch,11
dhcp-boot=tag:efi-arm64,ipxe-arm64.efi

dhcp-match=set:bios,option:client-arch,0
dhcp-boot=tag:bios,undionly.kpxe

dhcp-userclass=set:ipxe,iPXE
dhcp-boot=tag:ipxe,http://192.168.8.1:$PORT/boot.ipxe
EOF
    /etc/init.d/dnsmasq reload 2>/dev/null || /etc/init.d/dnsmasq restart
    echo "[+] dnsmasq netboot configuration active."
fi

# 6. Verify service health
echo "[5/5] Verifying VME Lite daemon status..."
sleep 2

HEALTH_CHECK=0
for i in 1 2 3 4 5; do
    if command -v wget >/dev/null 2>&1; then
        if wget -qO- "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
            HEALTH_CHECK=1
            break
        fi
    elif command -v curl >/dev/null 2>&1; then
        if curl -s "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1; then
            HEALTH_CHECK=1
            break
        fi
    fi
    sleep 1
done

if [ "$HEALTH_CHECK" -eq 1 ]; then
    echo "----------------------------------------------------------"
    echo "  [SUCCESS] VME Lite is active and healthy!"
    echo "  Endpoint: http://$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.8.1'):$PORT/api/v1/telemetry"
    echo "  Service:  /etc/init.d/vme-lite {start|stop|status|restart}"
    echo "----------------------------------------------------------"
else
    echo "[!] Warning: Daemon started but health check timed out. Check logs with 'logread | grep vme'."
fi
