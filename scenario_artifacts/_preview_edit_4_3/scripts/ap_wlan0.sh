#!/usr/bin/env bash
set -euo pipefail
AP_IF="wlan0"
AP_IP_CIDR="10.0.10.1/24"
AP_IP="${AP_IP_CIDR%/*}"
DHCP_RANGE="10.0.10.50,10.0.10.150,12h"
HOSTAPD_CONF="configs/hostapd_wlan0.conf"
log() { echo "[AP:wlan0] $1"; }
wait_for_iface() {
  for i in $(seq 1 80); do ip link show "wlan0" >/dev/null 2>&1 && return 0; sleep 0.25; done
  echo "iface wlan0 not present in ns"; exit 1
}
wait_for_iface

rfkill unblock all >/dev/null 2>&1 || true
pkill -x hostapd >/dev/null 2>&1 || true
pkill -x dnsmasq >/dev/null 2>&1 || true
dhclient -r "$AP_IF" >/dev/null 2>&1 || true

ip link set "$AP_IF" down || true
iw dev "$AP_IF" set type __ap || true
ip link set "$AP_IF" up || true

ip addr flush dev "$AP_IF" || true
ip addr add "$AP_IP_CIDR" dev "$AP_IF" || true

tries=0
until hostapd "$HOSTAPD_CONF" -B; do
  tries=$((tries+1)); [ $tries -ge 3 ] && { log "hostapd failed"; exit 1; }
  sleep 1
done
log "hostapd started"

dnsmasq --interface="$AP_IF" --bind-interfaces --except-interface=lo \
  --dhcp-range="10.0.10.50,10.0.10.150,12h" --dhcp-option=3,"$AP_IP" --dhcp-option=6,1.1.1.1,8.8.8.8 --no-hosts || true

iw dev "$AP_IF" info || true
