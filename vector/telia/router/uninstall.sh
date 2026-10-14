#!/bin/sh
# Velocitee Vector — VME Lite Router Uninstaller

set -e

echo "Uninstalling VME Lite from router..."

if [ -f /etc/init.d/vme-lite ]; then
    /etc/init.d/vme-lite stop 2>/dev/null || true
    /etc/init.d/vme-lite disable 2>/dev/null || true
    rm -f /etc/init.d/vme-lite
fi

if [ -f /etc/dnsmasq.d/vme-lite.conf ]; then
    rm -f /etc/dnsmasq.d/vme-lite.conf
    /etc/init.d/dnsmasq reload 2>/dev/null || true
fi

rm -rf /opt/vme-lite
rm -rf /tmp/telia-vector

echo "[SUCCESS] VME Lite completely uninstalled."
