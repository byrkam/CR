#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- (re)load hwsim with proper radio count ---
sudo modprobe -r mac80211_hwsim 2>/dev/null || true
sudo modprobe mac80211_hwsim radios=5
sudo rfkill unblock all || true
sleep 1

# --- wait for wlan* to appear in root ns ---
want=5
timeout=40
while :; do
  have=$(ls /sys/class/net 2>/dev/null | grep -E '^wlan[0-9]+' | wc -l || true)
  [ "$have" -ge "$want" ] && break || true
  timeout=$((timeout-1)); [ $timeout -le 0 ] && { echo 'Timeout waiting for wlan*'; exit 1; }
  sleep 0.25
done

# --- namespaces (idempotent) ---
sudo ip netns add ns-ap  2>/dev/null || true
sudo ip netns add ns-sta 2>/dev/null || true

# --- helpers: PHY move + in-ns recreation ---
phy_of() { basename "$(readlink -f "/sys/class/net/$1/phy80211")"; }

move_phy_to_ns() {
  dev="$1"; ns="$2";
  if [ -e "/sys/class/net/${dev}" ]; then
    phy="$(phy_of "$dev")" || true
    [ -n "${phy:-}" ] && sudo iw phy "$phy" set netns name "$ns" || true
  fi
}

recreate_in_ns() {
  ns="$1"; name="$2"; type="$3";
  sudo ip netns exec "$ns" bash -lc '
    set -e
    rfkill unblock all >/dev/null 2>&1 || true
    ip link set '"$name"' down 2>/dev/null || true
    iw dev '"$name"' del 2>/dev/null || true
    P="$(iw phy | sed -n "s/^Wiphy //p" | head -n1)"
    iw phy "$P" interface add '"$name"' type '"$type"'
    ip link set '"$name"' up || true
  '
}

# --- move PHYs to namespaces and recreate wlan* with correct types ---
move_phy_to_ns wlan0 ns-ap
recreate_in_ns ns-ap wlan0 __ap
move_phy_to_ns wlan1 ns-sta
recreate_in_ns ns-sta wlan1 managed
move_phy_to_ns wlan2 ns-sta
recreate_in_ns ns-sta wlan2 managed
move_phy_to_ns wlan3 ns-sta
recreate_in_ns ns-sta wlan3 managed
move_phy_to_ns wlan4 ns-sta
recreate_in_ns ns-sta wlan4 managed

# --- wait until the interfaces are visible inside each ns ---
want_ap=1; want_sta=4
for i in $(seq 1 80); do
  have_ap=$(sudo ip netns exec ns-ap  bash -lc "ls /sys/class/net | grep -E '^wlan[0-9]+' | wc -l || true")
  have_sta=$(sudo ip netns exec ns-sta bash -lc "ls /sys/class/net | grep -E '^wlan[0-9]+' | wc -l || true")
  if [ "$have_ap" -ge "$want_ap" ] && [ "$have_sta" -ge "$want_sta" ]; then break; fi
  sleep 0.25
  [ $i -eq 80 ] && { echo 'Timeout waiting for ifaces in namespaces'; exit 1; }
done

# --- bring interfaces up inside ns (skip lo) ---
for n in ns-ap ns-sta; do
  sudo ip netns exec "$n" rfkill unblock all >/dev/null 2>&1 || true
  for i in $(sudo ip netns exec "$n" bash -lc "ls /sys/class/net | grep -v '^lo$'") ; do
    sudo ip netns exec "$n" ip link set "$i" up 2>/dev/null || true
  done
done

# --- assign IPs to APs (flush then add) ---
sudo ip netns exec ns-ap ip addr flush dev wlan0 2>/dev/null || true
sudo ip netns exec ns-ap ip addr add 10.0.10.1/24 dev wlan0 2>/dev/null || true

# --- launch per-interface scripts inside namespaces ---
sudo ip netns exec ns-ap ./scripts/ap_wlan0.sh &
sudo ip netns exec ns-sta ./scripts/sta_wlan1.sh &
sudo ip netns exec ns-sta ./scripts/sta_wlan2.sh &
sudo ip netns exec ns-sta ./scripts/sta_wlan3.sh &
sudo ip netns exec ns-sta ./scripts/sta_wlan4.sh &
wait
echo "All role scripts started."
echo "Helper: ./scripts/wlan-tools.sh status"
