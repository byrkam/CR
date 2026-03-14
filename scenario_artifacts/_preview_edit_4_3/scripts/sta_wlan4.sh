#!/usr/bin/env bash
set -euo pipefail
STA_IF="wlan4"
SSID="lab-wpa2"
PSK="labpassword"
WPA_CONF="configs/wpa_supplicant_wlan4.conf"
log() { echo "[STA:wlan4] $1"; }
wait_for_iface() {
  for i in $(seq 1 80); do ip link show "wlan4" >/dev/null 2>&1 && return 0; sleep 0.25; done
  echo "iface wlan4 not present in ns"; exit 1
}
wait_for_iface

rfkill unblock all >/dev/null 2>&1 || true
pkill -x wpa_supplicant >/dev/null 2>&1 || true
dhclient -r "$STA_IF" >/dev/null 2>&1 || true
rm -rf /var/run/wpa_supplicant_testbed 2>/dev/null || true
mkdir -p /var/run/wpa_supplicant_testbed

ip link set "$STA_IF" down || true
iw dev "$STA_IF" set type managed 2>/dev/null || iw dev "$STA_IF" set type station || true
ip link set "$STA_IF" up || true

tries=0
until wpa_supplicant -i "$STA_IF" -c "$WPA_CONF" -B; do
  tries=$((tries+1)); [ $tries -ge 3 ] && { log "wpa_supplicant failed"; exit 1; }
  sleep 1
done
log "wpa_supplicant started"

for i in $(seq 1 30); do
  iw dev "$STA_IF" link | grep -q '^Connected' && break
  [ $i -eq 30 ] && { log "no association"; exit 1; }
  sleep 0.5
done

dhclient -v "$STA_IF" || true

iw dev "$STA_IF" link || true
ip -4 addr show "$STA_IF" | sed 's/^/  /' || true
