#!/usr/bin/env bash
set -euo pipefail

MANIFEST="scripts/manifest.json"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
for bin in ip iw jq; do need "$bin"; done
[ -f "$MANIFEST" ] || { echo "Missing $MANIFEST (run the generator first)"; exit 1; }

AP_NS=$(jq -r '.namespaces.ap'  "$MANIFEST")
STA_NS=$(jq -r '.namespaces.sta' "$MANIFEST")
mapfile -t AP_IFS  < <(jq -r '.aps[].iface'  "$MANIFEST")
mapfile -t STA_IFS < <(jq -r '.stas[].iface' "$MANIFEST")

ns_exec() {
  local role="$1"; shift
  local ns="$AP_NS"; [ "$role" = "sta" ] && ns="$STA_NS"
  sudo ip netns exec "$ns" "$@"
}

status() {
  echo "== Namespaces =="; ip netns list || true; echo
  echo "== APs ($AP_NS) =="; for i in "${AP_IFS[@]}"; do
    ns_exec ap ip -brief link show "$i" || true
    ns_exec ap ip -brief addr show "$i" || true
    ns_exec ap iw dev "$i" info || true
    echo
  done
  echo "== STAs ($STA_NS) =="; for i in "${STA_IFS[@]}"; do
    ns_exec sta ip -brief link show "$i" || true
    ns_exec sta ip -brief addr show "$i" || true
    ns_exec sta iw dev "$i" link || true
    echo
  done
  echo "== Neighbors =="
  for i in "${AP_IFS[@]}";  do ns_exec ap  ip neigh show dev "$i" || true; done
  for i in "${STA_IFS[@]}"; do ns_exec sta ip neigh show dev "$i" || true; done
}

logs() {
  echo "(If you want live logs, run hostapd/wpa_supplicant with -f FILE and tail here.)"
}

cleanup() {
  echo "Stopping wpa_supplicant / hostapd / dnsmasq ..."
  ns_exec sta pkill -x wpa_supplicant || true
  ns_exec ap  pkill -x hostapd       || true
  ns_exec ap  pkill -x dnsmasq       || true
  for i in "${STA_IFS[@]}"; do ns_exec sta dhclient -r "$i" 2>/dev/null || true; done
  for i in "${AP_IFS[@]}";  do ns_exec ap  ip addr flush dev "$i" || true; done
  for i in "${STA_IFS[@]}"; do ns_exec sta ip addr flush dev "$i" || true; done
}

hard-reset() {
  cleanup
  echo "Reloading mac80211_hwsim ..."
  sudo modprobe -r mac80211_hwsim || true
  sudo modprobe mac80211_hwsim || true
}

ping-ap() {
  # Ping AP IP from each STA
  for ai in "${AP_IFS[@]}"; do
    AP_IP=$(ns_exec ap ip -4 addr show "$ai" | awk "/inet /{print \$2}" | cut -d/ -f1 | head -n1)
    [ -z "$AP_IP" ] && continue
    for si in "${STA_IFS[@]}"; do
      echo "STA($si) -> AP($ai) $AP_IP"
      ns_exec sta ping -I "$si" -c 3 "$AP_IP" || true
    done
  done
}

ping-sta() {
  # Ping each STA IP from AP namespace
  for si in "${STA_IFS[@]}"; do
    STA_IP=$(ns_exec sta ip -4 addr show "$si" | awk "/inet /{print \$2}" | cut -d/ -f1 | head -n1)
    [ -z "$STA_IP" ] && continue
    echo "AP(ns-ap) -> STA($si) $STA_IP"
    ns_exec ap ping -c 3 "$STA_IP" || true
  done
}

capture() {
  # capture <ap|sta> <iface> <outfile.pcap>
  role="${1:-}"; iface="${2:-}"; out="${3:-capture.pcap}"
  [ -z "$role" ] || [ -z "$iface" ] && { echo "Usage: $0 capture <ap|sta> <iface> <outfile.pcap>"; exit 1; }
  ns="$AP_NS"; [ "$role" = "sta" ] && ns="$STA_NS"
  echo "Enabling monitor on $role/$iface in $ns → $out"
  ns_exec "$role" bash -c "
    set -e
    mon=mon_${iface}; ip link del \$mon 2>/dev/null || true
    iw dev $iface interface add \$mon type monitor
    ip link set \$mon up
    tcpdump -i \$mon -s 0 -w $out &
    echo \$! > /tmp/tcpdump_\$mon.pid
  "
  echo "tcpdump running. Stop with: sudo ip netns exec $ns pkill -F /tmp/tcpdump_mon_${iface}.pid"
}

fix-arp() {
  echo "Tweaking ARP sysctls in both namespaces"
  for role in ap sta; do
    ns_exec "$role" sysctl -w net.ipv4.conf.all.arp_ignore=1 || true
    ns_exec "$role" sysctl -w net.ipv4.conf.all.arp_announce=2 || true
  done
}

arpshow() {
  echo "AP ns:"
  ns_exec ap  ip neigh || true
  echo "STA ns:"
  ns_exec sta ip neigh || true
}

usage() {
  cat <<EOF
Usage: $0 {status|logs|cleanup|hard-reset|ping-ap|ping-sta|capture|fix-arp|arpshow}
Examples:
  $0 status
  $0 ping-ap
  $0 capture ap  wlan0 ap-handshake.pcap
  $0 capture sta wlan1 sta-handshake.pcap
EOF
}

cmd="${1:-}"; shift || true
case "$cmd" in
  status|logs|cleanup|hard-reset|ping-ap|ping-sta|capture|fix-arp|arpshow) "$cmd" "$@";;
  *) usage; exit 1;;
esac
