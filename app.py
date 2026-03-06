from flask import Flask, request, render_template, send_from_directory
import os
import json
import re
import subprocess
from pathlib import Path

app = Flask(__name__)

# =========================
# Defaults & knobs
# =========================

DEFAULTS = {
    # Basic RF / PSK defaults
    "COUNTRY": "US",
    "BAND": "2g",          # "2g" or "5g"
    "CHANNEL": 6,
    "CHANNEL_2G": 6,
    "CHANNEL_5G": 36,
    "CHANNEL_WIDTH": 20,
    "PASSPHRASE": "strongpassword",

    # Enterprise / RADIUS defaults
    "RADIUS_ADDR": "127.0.0.1",
    "RADIUS_PORT": 1812,
    "RADIUS_SECRET": "mysecret",
    "RADIUS_CA": "/etc/hostapd/certs/ca.pem",
    "RADIUS_SERVER_CERT": "/etc/hostapd/certs/server.pem",
    "RADIUS_SERVER_KEY": "/etc/hostapd/certs/server.key",

    # STA EAP-TLS defaults
    "EAP_CA": "/etc/freeradius/3.0/certs/ca.pem",
    "EAP_CLIENT_CERT": "/etc/freeradius/3.0/certs/client.pem",
    "EAP_CLIENT_KEY": "/etc/freeradius/3.0/certs/client.key",
    "EAP_IDENTITY_PREFIX": "user",
}

SECURITY_MODES = {
    "open",
    "wpa2-psk",
    "wpa3-sae",
    "wpa2-enterprise",
    "wpa3-enterprise",
}

# =========================
# Security helpers
# =========================

def normalize_security_mode(raw: str | None) -> str:
    """
    Normalize UI / description security text to one of:
      open, wpa2-psk, wpa3-sae, wpa2-enterprise, wpa3-enterprise
    """
    if not raw:
        return "wpa2-psk"
    s = raw.strip().lower()

    if s in SECURITY_MODES:
        return s

    if "open" in s:
        return "open"

    if "enterprise" in s:
        if "wpa3" in s or "3" in s:
            return "wpa3-enterprise"
        return "wpa2-enterprise"

    if "wpa3" in s or "sae" in s:
        return "wpa3-sae"

    if "wpa2" in s or "psk" in s:
        return "wpa2-psk"

    return "wpa2-psk"


def norm_security(sec: str) -> str:
    """
    Older generator's normalization (for hostapd/wpa_supp configs).
    Accepts our 'security_mode' and maps to the older set.
    """
    s = (sec or "").strip().lower()
    mapping = {
        "": "open",
        "open": "open",
        "none": "open",

        "wpa": "wpa-psk",
        "wpa-psk": "wpa-psk",
        "wpa1": "wpa-psk",

        "wpa2": "wpa2-psk",
        "wpa2-psk": "wpa2-psk",
        "rsn": "wpa2-psk",

        "wpa3": "wpa3-sae",
        "wpa3-sae": "wpa3-sae",
        "sae": "wpa3-sae",

        "wpa2/wpa3": "mixed-psk",
        "wpa3/wpa2": "mixed-psk",
        "sae-mixed": "mixed-psk",
        "wpa2-wpa3": "mixed-psk",

        # Enterprise families
        "enterprise": "wpa2-enterprise",
        "wpa-enterprise": "wpa2-enterprise",
        "wpa2-enterprise": "wpa2-enterprise",
        "wpa3-enterprise": "wpa3-enterprise",
        "wpa-eap": "wpa2-enterprise",
        "eap-tls": "wpa2-enterprise",
        "peap": "wpa2-enterprise",
    }
    return mapping.get(s, s)


def is_enterprise(sec: str) -> bool:
    ns = norm_security(sec)
    return ns in ("wpa2-enterprise", "wpa3-enterprise")


def hw_mode_and_channel(band: str, channel: int):
    b = (band or "").lower()
    if b in ("5g", "5ghz", "a"):
        return "a", channel if channel else DEFAULTS["CHANNEL_5G"]
    return "g", channel if channel else DEFAULTS["CHANNEL_2G"]

# =========================
# NEW: Description validation
# =========================

def validate_description(desc: str) -> list[str]:
    """
    Server-side validation of the structured description (step 2).
    Checks:
    - At least one AP block
    - Each AP has Band / Channel / Stations / Security
    - Stations >= 1
    - WPA2/WPA3-Personal: Passphrase length 8–63
    - WPA2/WPA3-Enterprise: requires RADIUS block
    - 2.4 vs 5 GHz channel sanity
    """
    errors: list[str] = []
    text = desc.replace("\r", "")

    ap_block_pattern = re.compile(
        r"^AP\s+(\d+):([\s\S]*?)(?=^AP\s+\d+:|^RADIUS\s*:|\Z)",
        re.M | re.I,
    )
    ap_matches = list(ap_block_pattern.finditer(text))
    if not ap_matches:
        errors.append("No AP blocks found. Add blocks like:\nAP 1:\n  SSID: ...\n  Band: 2.4 GHz\n  Channel: 6\n  Security: ...\n  Passphrase: ...\n  Stations: 2")
        return errors

    has_radius = bool(re.search(r"^\s*RADIUS\s*:", text, re.M | re.I))

    for m in ap_matches:
        ap_num = m.group(1)
        block = m.group(2)

        band_match = re.search(r"Band\s*:\s*(.+)", block, re.I)
        band_text = band_match.group(1).strip().lower() if band_match else None

        chan_match = re.search(r"Channel\s*:\s*(\d+)", block, re.I)
        channel = int(chan_match.group(1)) if chan_match else None

        sta_match = re.search(r"Stations\s*:\s*(\d+)", block, re.I)
        stations = int(sta_match.group(1)) if sta_match else None

        sec_match = re.search(r"Security\s*:\s*(.+)", block, re.I)
        security_raw = sec_match.group(1).strip() if sec_match else None
        security = security_raw.lower() if security_raw else None

        pass_match = re.search(r"Passphrase\s*:\s*\"?(.+?)\"?\s*$", block, re.I | re.M)
        passphrase = pass_match.group(1).strip() if pass_match else None
        has_passphrase = passphrase is not None

        # Required fields
        if band_text is None:
            errors.append(f"AP {ap_num}: Missing 'Band:' line.")
        if channel is None:
            errors.append(f"AP {ap_num}: Missing 'Channel:' line.")
        if stations is None:
            errors.append(f"AP {ap_num}: Missing 'Stations:' line.")
        elif stations < 1:
            errors.append(f"AP {ap_num}: Stations is {stations}. It should be at least 1.")

        if security is None:
            errors.append(
                f"AP {ap_num}: Missing 'Security:' line. "
                "Use one of: open, wpa2-psk, wpa3-sae, wpa2-enterprise, wpa3-enterprise."
            )
            canon = None
        else:
            canon = normalize_security_mode(security)
            if canon not in SECURITY_MODES:
                errors.append(
                    f"AP {ap_num}: Unsupported Security '{security_raw}'. "
                    "Allowed: open, wpa2-psk, wpa3-sae, wpa2-enterprise, wpa3-enterprise."
                )

        # Personal modes: must have passphrase 8–63
        if canon in ("wpa2-psk", "wpa3-sae"):
            if not has_passphrase:
                errors.append(
                    f"AP {ap_num}: Security is {canon} but no 'Passphrase:' is set."
                )
            else:
                length = len(passphrase)
                if length < 8 or length > 63:
                    errors.append(
                        f"AP {ap_num}: Passphrase length is {length} characters. "
                        "For WPA2/WPA3-Personal it must be between 8 and 63 characters."
                    )

        # Enterprise: require RADIUS
        if canon in ("wpa2-enterprise", "wpa3-enterprise") and not has_radius:
            errors.append(
                f"AP {ap_num}: Security is {canon} but no 'RADIUS:' block is defined."
            )

        # Band/channel sanity
        if band_text and channel is not None:
            is_24 = "2.4" in band_text or "2g" in band_text
            is_5 = "5" in band_text
            if is_24 and channel >= 20:
                errors.append(
                    f"AP {ap_num}: Band is 2.4 GHz but channel {channel} looks like a 5 GHz channel."
                )
            if is_5 and 1 <= channel <= 14:
                errors.append(
                    f"AP {ap_num}: Band is 5 GHz but channel {channel} is typically used on 2.4 GHz."
                )

    return errors

# =========================
# NEW: Parse structured description → topology
# =========================

def parse_description(desc: str):
    """
    Parse your step-2 structured text into a 'topology' dict:

    {
      "country": "GR",
      "aps": [
        {
          "id": "ap1",
          "ssid": "...",
          "band": "2g" | "5g",
          "channel": 6,
          "security_mode": "wpa2-psk",
          "passphrase": "...",
          "stas": ["sta1_0", "sta1_1"],
          "radius": { "addr": ..., "port": ..., "shared_secret": ... }   # optional
        },
        ...
      ]
    }
    """
    text = desc.replace("\r", "")
    lines = text.splitlines()

    # Country
    country = DEFAULTS["COUNTRY"]
    for line in lines:
        m = re.match(r"\s*Country\s*:\s*(\S+)", line, re.I)
        if m:
            country = m.group(1).upper()
            break

    # RADIUS block (optional, shared)
    radius = None
    radius_match = re.search(r"RADIUS\s*:\s*(.*)", text, flags=re.I | re.S)
    if radius_match:
        radius_block = text[radius_match.start():]
        radius_lines = radius_block.splitlines()
        r_addr = r_port = r_secret = None
        for line in radius_lines[1:]:
            if re.match(r"^\s*AP\s+\d+:", line):
                break
            m_addr = re.match(r"\s*Address\s*:\s*(.+)", line, re.I)
            m_port = re.match(r"\s*Port\s*:\s*(\d+)", line, re.I)
            m_sec = re.match(r"\s*Shared\s+secret\s*:\s*\"?(.+?)\"?\s*$", line, re.I)
            if m_addr:
                r_addr = m_addr.group(1).strip()
            if m_port:
                r_port = int(m_port.group(1))
            if m_sec:
                r_secret = m_sec.group(1).strip()

        if r_addr or r_port or r_secret:
            radius = {
                "addr": r_addr or DEFAULTS["RADIUS_ADDR"],
                "port": r_port or DEFAULTS["RADIUS_PORT"],
                "shared_secret": r_secret or DEFAULTS["RADIUS_SECRET"],
            }

    # AP blocks
    aps = []
    ap_iter = list(re.finditer(r"^AP\s+(\d+):", text, flags=re.I | re.M))
    for idx, m in enumerate(ap_iter):
        num = int(m.group(1))
        start = m.start()
        if idx + 1 < len(ap_iter):
            end = ap_iter[idx + 1].start()
        else:
            next_radius = text.find("RADIUS:", start)
            end = next_radius if next_radius != -1 else len(text)
        block = text[start:end]
        aps.append(parse_ap_block(num, block, radius))

    return {
        "country": country,
        "aps": aps,
    }


def parse_ap_block(num: int, block: str, radius: dict | None):
    ssid = f"ap{num}"
    band = DEFAULTS["BAND"]
    channel = DEFAULTS["CHANNEL_2G"]
    security_mode = "wpa2-psk"
    passphrase = DEFAULTS["PASSPHRASE"]
    stations = 1

    for line in block.splitlines()[1:]:
        m_ssid = re.match(r"\s*SSID\s*:\s*\"?(.+?)\"?\s*$", line, re.I)
        m_band = re.match(r"\s*Band\s*:\s*(.+)", line, re.I)
        m_chan = re.match(r"\s*Channel\s*:\s*(\d+)", line, re.I)
        m_sec = re.match(r"\s*Security\s*:\s*(.+)", line, re.I)
        m_pass = re.match(r"\s*Passphrase\s*:\s*\"?(.+?)\"?\s*$", line, re.I)
        m_sta = re.match(r"\s*Stations\s*:\s*(\d+)", line, re.I)

        if m_ssid:
            ssid = m_ssid.group(1).strip()
        if m_band:
            band_text = m_band.group(1).lower()
            if "5" in band_text:
                band = "5g"
                channel = DEFAULTS["CHANNEL_5G"]
            else:
                band = "2g"
                channel = DEFAULTS["CHANNEL_2G"]
        if m_chan:
            channel = int(m_chan.group(1))
        if m_sec:
            security_mode = normalize_security_mode(m_sec.group(1))
        if m_pass:
            passphrase = m_pass.group(1).strip()
        if m_sta:
            stations = int(m_sta.group(1))

    stas = [f"sta{num}_{i}" for i in range(stations)]

    ap = {
        "id": f"ap{num}",
        "ssid": ssid,
        "band": band,
        "channel": channel,
        "security_mode": security_mode,
        "passphrase": passphrase,
        "stas": stas,
    }

    if security_mode in ("wpa2-enterprise", "wpa3-enterprise") and radius:
        ap["radius"] = radius

    return ap

# =========================
# ADAPTER: topology -> old 'parsed' structure
# =========================

def topology_to_parsed(topology: dict) -> dict:
    """
    Convert our 'topology' to the structure used by the old generator:

    parsed = {
      "aps": [
        {
          "id": "ap1",
          "ssid": "...",
          "security": "wpa2-psk",
          "passphrase": "...",
          "country": "US",
          "band": "2g",
          "channel": 6,
          "channel_width": 20,
          "radius": {...},
          "stas": ["sta1_0", "sta1_1"],
        },
        ...
      ]
    }
    """
    country = topology.get("country", DEFAULTS["COUNTRY"])
    parsed_aps = []
    for ap in topology["aps"]:
        sec = ap.get("security_mode", "wpa2-psk")
        ap_obj = {
            "id": ap["id"],
            "ssid": ap["ssid"],
            "security": sec,
            "passphrase": ap.get("passphrase", DEFAULTS["PASSPHRASE"]),
            "country": country,
            "band": ap.get("band", DEFAULTS["BAND"]),
            "channel": ap.get("channel", DEFAULTS["CHANNEL"]),
            "channel_width": DEFAULTS["CHANNEL_WIDTH"],
            "stas": list(ap.get("stas", [])),
        }
        if "radius" in ap:
            ap_obj["radius"] = ap["radius"]
        parsed_aps.append(ap_obj)

    return {"aps": parsed_aps}

# =========================
# Interface allocation (old model)
# =========================

def allocate_interfaces(parsed: dict):
    """
    APs first, then each AP's STAs → stable wlan numbering and AP binding.
    Returns list of (iface_name, role, ap_obj).
    role ∈ {"ap", "sta"}
    """
    interfaces = []
    idx = 0
    for ap in parsed["aps"]:
        iface_ap = f"wlan{idx}"; idx += 1
        interfaces.append((iface_ap, "ap", ap))
        stas = ap.get("stas", [])
        for _ in stas:
            iface_sta = f"wlan{idx}"; idx += 1
            interfaces.append((iface_sta, "sta", ap))
    return interfaces

# =========================
# Enterprise bootstrap (FreeRADIUS + certs) – unchanged from previous.py
# =========================

def ensure_enterprise_radius(secret: str = DEFAULTS["RADIUS_SECRET"]):
    """
    Ensure FreeRADIUS is installed, certs generated, symlinks to /etc/hostapd/certs exist,
    localhost client exists with the given secret, and service is running.
    Uses sudo; requires appropriate privileges.
    """
    try:
        # 1) Install freeradius if missing
        subprocess.run(
            [
                "bash",
                "-lc",
                "dpkg -s freeradius >/dev/null 2>&1 || "
                "(sudo apt-get update -y && sudo apt-get install -y freeradius freeradius-utils)",
            ],
            check=False,
        )

        # 2) Generate certs with Makefile
        cmds = [
            "set -e",
            "cd /etc/freeradius/3.0/certs",
            "sudo make clean >/dev/null 2>&1 || true",
            "sudo make",
        ]
        subprocess.run(["bash", "-lc", " ; ".join(cmds)], check=True)

        # 3) Symlink certs for hostapd
        subprocess.run(
            [
                "bash",
                "-lc",
                "sudo mkdir -p /etc/hostapd/certs && "
                "for f in ca.pem server.pem server.key; do "
                "[ -e \"/etc/hostapd/certs/$f\" ] || sudo ln -s \"/etc/freeradius/3.0/certs/$f\" \"/etc/hostapd/certs/$f\"; "
                "done",
            ],
            check=True,
        )

        # 4) Ensure localhost client with secret
        clients_file = "/etc/freeradius/3.0/clients.conf"
        awk_cmd = (
            r"""sudo awk -v secret='""" + secret + r"""' '
BEGIN { found=0 }
^\s*client\s+localhost\s*\{ { found=1 }
{ print }
END {
  if (!found) {
    print ""
    print "client localhost {"
    print "  ipaddr = 127.0.0.1"
    print "  secret = " secret
    print "  require_message_authenticator = no"
    print "}"
  }
}' """ + clients_file + r""" > /tmp/clients.conf.tmp && sudo mv /tmp/clients.conf.tmp """ + clients_file
        )
        subprocess.run(["bash", "-lc", awk_cmd], check=True)
        
                # 4b) Ensure a lab user 'user1' with password 'password1'
        users_file = "/etc/freeradius/3.0/mods-config/files/authorize"
        awk_users = (
            r"""sudo awk '
BEGIN { found=0 }
^\s*user1\s/ {{ found=1 }}
{ print }
END {
  if (!found) {
    print ""
    print "user1 Cleartext-Password := \"password1\""
  }
}' """ + users_file + r""" > /tmp/authorize.tmp && sudo mv /tmp/authorize.tmp """ + users_file
        )
        subprocess.run(["bash", "-lc", awk_users], check=True)

        # 5) Enable & restart radius
        subprocess.run(
            ["bash", "-lc", "sudo systemctl enable --now freeradius && sudo systemctl restart freeradius"],
            check=True,
        )

        print("[radius] bootstrap complete.")
    except Exception as e:
        print(f"[radius] bootstrap error: {e}")

# =========================
# Config generation (old, slightly adapted)
# =========================

def hostapd_conf_for(iface: str, ap: dict) -> str:
    ssid = ap.get("ssid", iface)
    sec = norm_security(ap.get("security", "open"))
    passphrase = ap.get("passphrase", DEFAULTS["PASSPHRASE"])
    country = ap.get("country", DEFAULTS["COUNTRY"])
    band = ap.get("band", DEFAULTS["BAND"])
    channel = int(ap.get("channel", DEFAULTS["CHANNEL"]))
    channel_width = int(ap.get("channel_width", DEFAULTS["CHANNEL_WIDTH"]))
    hw_mode, ch = hw_mode_and_channel(band, channel)

    lines = [
        f"interface={iface}",
        f"ssid={ssid}",
        f"country_code={country}",
        f"hw_mode={hw_mode}",
        f"channel={ch}",
        "ieee80211n=1",
    ]
    if hw_mode == "a" and channel_width >= 40:
        lines += ["ieee80211ac=1"]

    if sec == "open":
        lines += ["auth_algs=1", "wpa=0"]

    elif sec == "wpa-psk":
        lines += ["wpa=1", "wpa_key_mgmt=WPA-PSK", f"wpa_passphrase={passphrase}", "wpa_pairwise=TKIP CCMP"]

    elif sec == "wpa2-psk":
        lines += ["wpa=2", "wpa_key_mgmt=WPA-PSK", f"wpa_passphrase={passphrase}", "rsn_pairwise=CCMP"]

    elif sec == "wpa3-sae":
        lines += ["wpa=2", "wpa_key_mgmt=SAE", "ieee80211w=2", f"sae_password={passphrase}", "rsn_pairwise=CCMP"]

    elif sec == "mixed-psk":
        lines += [
            "wpa=2",
            "wpa_key_mgmt=SAE WPA-PSK",
            "ieee80211w=1",
            f"sae_password={passphrase}",
            f"wpa_passphrase={passphrase}",
            "rsn_pairwise=CCMP",
        ]

    elif sec in ("wpa2-enterprise", "wpa3-enterprise"):
        # External RADIUS server on localhost, hostapd is just the authenticator.
        radius = ap.get("radius", {}) or {}
        r_addr = radius.get("addr", DEFAULTS["RADIUS_ADDR"])
        r_port = int(radius.get("port", DEFAULTS["RADIUS_PORT"]))
        r_secret = radius.get("shared_secret", DEFAULTS["RADIUS_SECRET"])

        lines += [
            "wpa=2",
            "ieee8021x=1",
            "wpa_key_mgmt=WPA-EAP",
            "rsn_pairwise=CCMP",
            f"auth_server_addr={r_addr}",
            f"auth_server_port={r_port}",
            f"auth_server_shared_secret={r_secret}",
            "eapol_key_index_workaround=0",
        ]
        # WPA3-Enterprise requires PMF; WPA2-Enterprise can use optional PMF.
        if sec == "wpa3-enterprise":
            lines.append("ieee80211w=2")
        else:
            lines.append("ieee80211w=1")

    else:
        # Fallback to WPA2-PSK
        lines += ["wpa=2", "wpa_key_mgmt=WPA-PSK", f"wpa_passphrase={passphrase}", "rsn_pairwise=CCMP"]

    return "\n".join(lines) + "\n"


def wpa_supplicant_conf_psk(country: str, ssid: str, sec: str, passphrase: str) -> str:
    head = [
        "ctrl_interface=/var/run/wpa_supplicant_testbed",
        "update_config=1",
        f"country={country}",
        "",
        "network={",
        f'    ssid="{ssid}"',
    ]
    s = norm_security(sec)
    if s == "open":
        body = ["    key_mgmt=NONE"]
    elif s == "wpa-psk":
        body = [f'    psk="{passphrase}"', "    key_mgmt=WPA-PSK", "    proto=WPA", "    pairwise=TKIP CCMP"]
    elif s == "wpa2-psk":
        body = [f'    psk="{passphrase}"', "    key_mgmt=WPA-PSK", "    proto=RSN", "    pairwise=CCMP", "    group=CCMP"]
    elif s == "wpa3-sae":
        body = [f'    psk="{passphrase}"', "    key_mgmt=SAE", "    ieee80211w=2", "    pairwise=CCMP", "    group=CCMP"]
    elif s == "mixed-psk":
        body = [f'    psk="{passphrase}"', "    key_mgmt=SAE WPA-PSK", "    ieee80211w=1", "    pairwise=CCMP", "    group=CCMP"]
    else:
        body = [f'    psk="{passphrase}"', "    key_mgmt=WPA-PSK", "    proto=RSN", "    pairwise=CCMP", "    group=CCMP"]
    tail = ["}"]
    return "\n".join(head + body + tail) + "\n"


def wpa_supplicant_conf_enterprise(country: str, ssid: str, identity: str = "user1") -> str:
    """
    EAP-PEAP/MSCHAPv2 profile for lab use.
    Works with a simple FreeRADIUS user:
        user1 Cleartext-Password := "password1"
    created by ensure_enterprise_radius().
    """
    lines = [
        "ctrl_interface=/var/run/wpa_supplicant_testbed",
        "update_config=1",
        f"country={country}",
        "",
        "network={",
        f'    ssid="{ssid}"',
        "    key_mgmt=WPA-EAP",
        "    eap=PEAP",
        f'    identity="user1"',
        f'    password="password1"',
        f'    ca_cert="{DEFAULTS["EAP_CA"]}"',
        '    phase1="peapver=0"',
        '    phase2="auth=MSCHAPV2"',
        "}",
    ]
    return "\n".join(lines) + "\n"


def hostapd_conf_path(iface: str) -> Path:
    return Path(f"configs/hostapd_{iface}.conf")


def wpa_conf_path(iface: str) -> Path:
    return Path(f"configs/wpa_supplicant_{iface}.conf")


def save_configs(interfaces, parsed):
    os.makedirs("configs", exist_ok=True)

    any_ent = any(is_enterprise(ap.get("security", "")) for _, role, ap in interfaces if role == "ap")
    if any_ent:
        ensure_enterprise_radius(secret=DEFAULTS["RADIUS_SECRET"])

    ent_sta_counter = 0
    for iface, role, ap in interfaces:
        if role == "ap":
            hostapd_conf_path(iface).write_text(hostapd_conf_for(iface, ap))
        else:
            sec = ap.get("security", "open")
            country = ap.get("country", DEFAULTS["COUNTRY"])
            ssid = ap.get("ssid", f"{iface}_ssid")

            if is_enterprise(sec):
                ident = f'{DEFAULTS["EAP_IDENTITY_PREFIX"]}{ent_sta_counter}'
                ent_sta_counter += 1
                wpa_conf_path(iface).write_text(
                    wpa_supplicant_conf_enterprise(country, ssid, ident)
                )
            else:
                passphrase = ap.get("passphrase", DEFAULTS["PASSPHRASE"])
                wpa_conf_path(iface).write_text(
                    wpa_supplicant_conf_psk(country, ssid, sec, passphrase)
                )

# =========================
# Per-role scripts (AP / STA) – from previous.py, slightly tweaked
# =========================

def ap_script_text(iface: str, ap_ip_cidr: str, dhcp_range: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
AP_IF="{iface}"
AP_IP_CIDR="{ap_ip_cidr}"
AP_IP="${{AP_IP_CIDR%/*}}"
DHCP_RANGE="{dhcp_range}"
HOSTAPD_CONF="configs/hostapd_{iface}.conf"
log() {{ echo "[AP:{iface}] $1"; }}
wait_for_iface() {{
  for i in $(seq 1 80); do ip link show "{iface}" >/dev/null 2>&1 && return 0; sleep 0.25; done
  echo "iface {iface} not present in ns"; exit 1
}}
wait_for_iface

# cleanup
pkill -x hostapd   >/dev/null 2>&1 || true
pkill -x dnsmasq   >/dev/null 2>&1 || true
dhclient -r "$AP_IF" >/dev/null 2>&1 || true

# prepare
ip link set "$AP_IF" down || true
iw dev "$AP_IF" set type __ap || true
ip link set "$AP_IF" up || true

# address
ip addr flush dev "$AP_IF" || true
ip addr add "$AP_IP_CIDR" dev "$AP_IF" || true

# hostapd (retry)
tries=0
until hostapd "$HOSTAPD_CONF" -B; do
  tries=$((tries+1)); [ $tries -ge 3 ] && {{ log "hostapd failed"; exit 1; }}
  sleep 1
done
log "hostapd started"

# dnsmasq (per-AP)
dnsmasq --interface="$AP_IF" --bind-interfaces --except-interface=lo \\
  --dhcp-range="{dhcp_range}" --dhcp-option=3,"$AP_IP" --dhcp-option=6,1.1.1.1,8.8.8.8 --no-hosts || true

# status
iw dev "$AP_IF" info || true
"""


def sta_script_text(iface: str, ssid: str, psk: str, wpa_conf_path: str) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail
STA_IF="{iface}"
SSID="{ssid}"
PSK="{psk}"
WPA_CONF="{wpa_conf_path}"
log() {{ echo "[STA:{iface}] $1"; }}
wait_for_iface() {{
  for i in $(seq 1 80); do ip link show "{iface}" >/dev/null 2>&1 && return 0; sleep 0.25; done
  echo "iface {iface} not present in ns"; exit 1
}}
wait_for_iface

# cleanup
pkill -x wpa_supplicant >/dev/null 2>&1 || true
dhclient -r "$STA_IF"   >/dev/null 2>&1 || true
rm -rf /var/run/wpa_supplicant_testbed 2>/dev/null || true
mkdir -p /var/run/wpa_supplicant_testbed

# prepare
ip link set "$STA_IF" down || true
iw dev "$STA_IF" set type managed 2>/dev/null || iw dev "$STA_IF" set type station || true
ip link set "$STA_IF" up || true

# wpa_supplicant (retry)
tries=0
until wpa_supplicant -i "$STA_IF" -c "$WPA_CONF" -B; do
  tries=$((tries+1)); [ $tries -ge 3 ] && {{ log "wpa_supplicant failed"; exit 1; }}
  sleep 1
done
log "wpa_supplicant started"

# wait for association
for i in $(seq 1 30); do
  iw dev "$STA_IF" link | grep -q '^Connected' && break
  [ $i -eq 30 ] && {{ log "no association"; exit 1; }}
  sleep 0.5
done

# DHCP
dhclient -v "$STA_IF" || true

# status
iw dev "$STA_IF" link || true
ip -4 addr show "$STA_IF" | sed 's/^/  /' || true
"""

def generate_role_scripts(interfaces):
    """
    For each iface, generate AP / STA scripts that will be executed inside namespaces.
    """
    os.makedirs("scripts", exist_ok=True)

    subnet_base = 10
    ap_index = 0

    for iface, role, ap in interfaces:
        if role == "ap":
            # 10.0.10.1/24, 10.0.11.1/24, ...
            cidr = f"10.0.{subnet_base + ap_index}.1/24"
            dhcp_range = f"10.0.{subnet_base + ap_index}.50,10.0.{subnet_base + ap_index}.150,12h"
            ap_index += 1
            content = ap_script_text(iface, cidr, dhcp_range)
            out = Path(f"scripts/ap_{iface}.sh")
        else:
            ssid = ap.get("ssid", f"{iface}_ssid")
            sec = ap.get("security", "open")
            psk = "" if is_enterprise(sec) or norm_security(sec) == "open" else ap.get("passphrase", DEFAULTS["PASSPHRASE"])
            content = sta_script_text(iface, ssid, psk, f"configs/wpa_supplicant_{iface}.conf")
            out = Path(f"scripts/sta_{iface}.sh")

        out.write_text(content)
        os.chmod(out, 0o755)

# =========================
# Manifest + tools + dnsmasq (from previous.py)
# =========================

def write_manifest(interfaces):
    os.makedirs("scripts", exist_ok=True)
    data = {
        "namespaces": {"ap": "ns-ap", "sta": "ns-sta"},
        "aps": [{"iface": iface, "ns": "ns-ap"} for iface, role, _ in interfaces if role == "ap"],
        "stas": [{"iface": iface, "ns": "ns-sta"} for iface, role, _ in interfaces if role == "sta"],
    }
    Path("scripts/manifest.json").write_text(json.dumps(data, indent=2))


def write_wlan_tools():
    tools = r'''#!/usr/bin/env bash
set -euo pipefail

MANIFEST="scripts/manifest.json"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
for bin in ip iw jq; do need "$bin"; end;'''  # We'll correct tools below
    # To keep it simple and avoid syntax mistakes, we'll write the original content:

    tools = r'''#!/usr/bin/env bash
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
'''
    os.makedirs("scripts", exist_ok=True)
    p = Path("scripts/wlan-tools.sh")
    p.write_text(tools)
    os.chmod(p, 0o755)


def generate_central_dnsmasq_config(interfaces):
    os.makedirs("configs", exist_ok=True)
    subnet_base = 10
    ap_count = 0
    lines = [
        "domain-needed",
        "bogus-priv",
        "no-resolv",
        "server=8.8.8.8",
        "bind-interfaces",
    ]
    for iface, role, ap in interfaces:
        if role != "ap":
            continue
        subnet_id = subnet_base + ap_count
        ap_ip = f"10.0.{subnet_id}.1"
        lines += [
            f"interface={iface}",
            f"listen-address={ap_ip}",
            f"dhcp-range=10.0.{subnet_id}.50,10.0.{subnet_id}.150,12h",
        ]
        ap_count += 1
    Path("configs/dnsmasq.conf").write_text("\n".join(lines) + "\n")

# =========================
# Master script: namespaces + PHY moving (old working logic)
# =========================

def generate_shell_script(parsed, interfaces):
    """
    Namespace + PHY-aware orchestrator:
      - (re)load mac80211_hwsim with needed radios
      - create ns-ap / ns-sta
      - move PHY to ns, recreate wlanX in ns
      - assign AP IPs, launch per-role scripts
    """
    radios = len(parsed["aps"]) + sum(len(ap.get("stas", [])) for ap in parsed["aps"])
    ap_ifaces = [iface for iface, role, _ in interfaces if role == "ap"]
    sta_ifaces = [iface for iface, role, _ in interfaces if role == "sta"]

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# --- (re)load hwsim with proper radio count ---",
        "sudo modprobe -r mac80211_hwsim 2>/dev/null || true",
        f"sudo modprobe mac80211_hwsim radios={radios}",
        "",
        "# --- wait for wlan* to appear in root ns ---",
        f"want={radios}",
        "timeout=40",
        "while :; do",
        "  have=$(ls /sys/class/net 2>/dev/null | grep -E '^wlan[0-9]+' | wc -l || true)",
        "  [ \"$have\" -ge \"$want\" ] && break || true",
        "  timeout=$((timeout-1)); [ $timeout -le 0 ] && { echo 'Timeout waiting for wlan*'; exit 1; }",
        "  sleep 0.25",
        "done",
        "",
        "# --- namespaces (idempotent) ---",
        "sudo ip netns add ns-ap  2>/dev/null || true",
        "sudo ip netns add ns-sta 2>/dev/null || true",
        "",
        "# --- helpers: PHY move + in-ns recreation ---",
        'phy_of() { basename "$(readlink -f "/sys/class/net/$1/phy80211")"; }',
        "",
        "move_phy_to_ns() {",
        "  dev=\"$1\"; ns=\"$2\";",
        "  if [ -e \"/sys/class/net/${dev}\" ]; then",
        "    phy=\"$(phy_of \"$dev\")\" || true",
        "    [ -n \"${phy:-}\" ] && sudo iw phy \"$phy\" set netns name \"$ns\" || true",
        "  fi",
        "}",
        "",
        "recreate_in_ns() {",
        "  ns=\"$1\"; name=\"$2\"; type=\"$3\";",
        "  sudo ip netns exec \"$ns\" bash -lc '",
        "    set -e",
        "    ip link set '\"$name\"' down 2>/dev/null || true",
        "    iw dev '\"$name\"' del 2>/dev/null || true",
        "    P=\"$(iw phy | sed -n \"s/^Wiphy //p\" | head -n1)\"",
        "    iw phy \"$P\" interface add '\"$name\"' type '\"$type\"'",
        "    ip link set '\"$name\"' up || true",
        "  '",
        "}",
        "",
        "# --- move PHYs to namespaces and recreate wlan* with correct types ---",
    ]

    for iface, role, _ in interfaces:
        ns = "ns-ap" if role == "ap" else "ns-sta"
        iftype = "__ap" if role == "ap" else "managed"
        lines.append(f"move_phy_to_ns {iface} {ns}")
        lines.append(f"recreate_in_ns {ns} {iface} {iftype}")

    lines += [
        "",
        "# --- wait until the interfaces are visible inside each ns ---",
        f"want_ap={len(ap_ifaces)}; want_sta={len(sta_ifaces)}",
        "for i in $(seq 1 80); do",
        "  have_ap=$(sudo ip netns exec ns-ap  bash -lc \"ls /sys/class/net | grep -E '^wlan[0-9]+' | wc -l || true\")",
        "  have_sta=$(sudo ip netns exec ns-sta bash -lc \"ls /sys/class/net | grep -E '^wlan[0-9]+' | wc -l || true\")",
        "  if [ \"$have_ap\" -ge \"$want_ap\" ] && [ \"$have_sta\" -ge \"$want_sta\" ]; then break; fi",
        "  sleep 0.25",
        "  [ $i -eq 80 ] && { echo 'Timeout waiting for ifaces in namespaces'; exit 1; }",
        "done",
        "",
        "# --- bring interfaces up inside ns (skip lo) ---",
        "for n in ns-ap ns-sta; do",
        "  for i in $(sudo ip netns exec \"$n\" bash -lc \"ls /sys/class/net | grep -v '^lo$\") ; do",
        "    sudo ip netns exec \"$n\" ip link set \"$i\" up 2>/dev/null || true",
        "  done",
        "done",
        "",
        "# --- assign IPs to APs (flush then add) ---",
    ]

    subnet_base = 10
    ap_count = 0
    for iface, role, _ in interfaces:
        if role == "ap":
            ip = f"10.0.{subnet_base + ap_count}.1/24"
            lines.append(f"sudo ip netns exec ns-ap ip addr flush dev {iface} 2>/dev/null || true")
            lines.append(f"sudo ip netns exec ns-ap ip addr add {ip} dev {iface} 2>/dev/null || true")
            ap_count += 1

    lines += [
        "",
        "# --- launch per-interface scripts inside namespaces ---",
    ]
    for iface, role, ap in interfaces:
        ns = "ns-ap" if role == "ap" else "ns-sta"
        sh = f"./scripts/ap_{iface}.sh" if role == "ap" else f"./scripts/sta_{iface}.sh"
        lines.append(f"sudo ip netns exec {ns} {sh} &")

    lines += [
        "wait",
        'echo "All role scripts started."',
        'echo "Helper: ./scripts/wlan-tools.sh status"',
    ]

    script = "\n".join(lines) + "\n"
    Path("generated_script.sh").write_text(script)
    os.chmod("generated_script.sh", 0o755)
    return script

# =========================
# Flask routes
# =========================

@app.route("/", methods=["GET", "POST"])
def index():
    script = ""
    topology = None
    description = ""
    show_step2 = False
    scenario = ""
    errors: list[str] = []

    if request.method == "POST":
        description = request.form.get("description", "") or ""
        scenario = request.form.get("scenario", "") or ""
        if description.strip():
            show_step2 = True
            errors = validate_description(description)
            if not errors:
                topology = parse_description(description)
                parsed = topology_to_parsed(topology)

                # Allocate interfaces & generate everything (old working pipeline)
                interfaces = allocate_interfaces(parsed)
                save_configs(interfaces, parsed)
                generate_role_scripts(interfaces)
                generate_central_dnsmasq_config(interfaces)
                write_manifest(interfaces)
                write_wlan_tools()
                script = generate_shell_script(parsed, interfaces)

    return render_template(
        "testbed.html",
        script=script,
        topology=topology,
        description=description,
        show_step2=show_step2,
        scenario=scenario,
        errors=errors,
    )


@app.route("/favicon.ico")
def favicon():
    return send_from_directory("static", "favicon.ico", mimetype="image/vnd.microsoft.icon")


if __name__ == "__main__":
    Path("configs").mkdir(exist_ok=True)
    Path("scripts").mkdir(exist_ok=True)
    app.run(host="127.0.0.1", port=5000, debug=True)

