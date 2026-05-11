<p align="center">
  <img src="static/icons/wifi-logo.png" alt="Wi-Fi BlackBeacon Logo" width="160"/>
</p>

<h1 align="center">Wi-Fi BlackBeacon</h1>

<p align="center">
  A web-based cybersecurity training platform for designing, generating, and deploying virtual Wi-Fi testbed scenarios — built for instructors and learners in wireless security education.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/flask-3.x-lightgrey?style=flat-square" alt="Flask"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/platform-Linux-orange?style=flat-square" alt="Linux"/>
</p>

---

## Overview

**Wi-Fi BlackBeacon** is a multi-role Flask web application that lets instructors create realistic Wi-Fi network testbed scenarios — complete with auto-generated `hostapd` configs, `wpa_supplicant` configs, network namespace setup scripts, and a `dnsmasq` DHCP server config — all from a simple natural-language description.

Learners gain access to those scenarios along with a live Wi-Fi security news feed and a real-time CVE dashboard sourced from the NVD API.

---

## Features

### 🎓 Role-Based Access
- **Admin** — Manage users, reset passwords, view platform statistics and threat intelligence
- **Instructor** — Create, preview, edit, and delete Wi-Fi testbed scenarios
- **Learner** — Access published scenarios, view Wi-Fi security news and recent CVEs

### 🛜 Scenario Engine
- Parses natural-language AP descriptions into full testbed configurations
- Supports all major Wi-Fi security modes:
  - `open` — No encryption
  - `wpa2-psk` — WPA2-Personal (PSK)
  - `wpa3-sae` — WPA3-Personal (SAE)
  - `wpa2-enterprise` — WPA2-Enterprise (EAP/RADIUS)
  - `wpa3-enterprise` — WPA3-Enterprise (EAP/RADIUS)
- Auto-generates:
  - `hostapd_wlanX.conf` — Access Point configuration
  - `wpa_supplicant_wlanX.conf` — Station configuration
  - `ap_wlanX.sh` / `sta_wlanX.sh` — Per-interface setup scripts
  - `generated_script.sh` — Master orchestration script using Linux network namespaces and `mac80211_hwsim`
  - `dnsmasq.conf` — DHCP server config per AP
  - `manifest.json` — Interface-to-namespace mapping
  - `wlan-tools.sh` — Diagnostic and management utility (status, ping, capture, cleanup)
- Bootstraps FreeRADIUS automatically for enterprise scenarios
- Interactive topology visualizer (vis.js network graph)

### 📡 Live Threat Intelligence
- Wi-Fi security news from RSS feeds (SecurityWeek, BleepingComputer, The Hacker News, Dark Reading, Wi-Fi Alliance) — cached 15 min
- Recent Wi-Fi CVEs from NVD API 2.0 (keywords: `wifi`, `wlan`, `802.11`, `wpa2`, `wpa3`, `eapol`, `pmkid`, etc.) — cached 30 min

### 🔐 Security
- CSRF protection (Flask-WTF) on all forms
- Session-based authentication with 30-minute auto-logout
- HTTP-only, SameSite=Lax cookies
- Strong password enforcement (8+ chars, upper, lower, digit, special character)
- No-cache headers on all authenticated responses

---

## Architecture

```
Wi-Fi BlackBeacon
├── app1.py                  # Flask application: routes, auth, session management
├── models.py                # SQLAlchemy models: User, Scenario
├── scenario_engine.py       # Core engine: parse → generate → persist testbed artifacts
├── templates/               # Jinja2 HTML templates (per-role dashboards, forms)
├── static/
│   ├── css/                 # Per-role stylesheets (base, admin, instructor, learner, etc.)
│   ├── icons/               # Topology node icons (ap.png, sta.png, radius.png)
│   └── js/
│       ├── topology.js      # vis.js network topology renderer
│       ├── password_validation.js  # Client-side password strength checker
│       └── news_widget.html # Wi-Fi news/CVE widget partial
├── scenario_artifacts/      # Generated testbed artifacts (per scenario slug)
│   └── <slug>/
│       ├── configs/         # hostapd & wpa_supplicant configs, dnsmasq.conf
│       ├── scripts/         # Per-interface shell scripts, manifest.json, wlan-tools.sh
│       └── generated_script.sh
└── database.db              # SQLite database (auto-created on first run)
```

---

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 22.04+ recommended)
- **Kernel modules**: `mac80211_hwsim` (for virtual Wi-Fi radios)
- **System packages**:

```bash
sudo apt-get update
sudo apt-get install -y \
    hostapd \
    wpasupplicant \
    dnsmasq \
    iw \
    rfkill \
    iproute2 \
    dhclient \
    jq \
    tcpdump
```

- **For WPA2/WPA3-Enterprise scenarios** (auto-bootstrapped if needed):
```bash
sudo apt-get install -y freeradius freeradius-utils
```

### Python Requirements
- Python 3.10 or higher
- pip

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/wifi-blackbeacon.git
cd wifi-blackbeacon

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install flask flask-sqlalchemy flask-wtf werkzeug feedparser requests

# 4. (Optional) Set your NVD API key for higher CVE rate limits
export NVD_API_KEY=your_api_key_here
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
```

> ⚠️ **Security Notice**: Before deploying in any non-local environment, change the `app.secret_key` in `app1.py` to a strong random value and set `SESSION_COOKIE_SECURE = True` if running over HTTPS.

---

## Running the Application

```bash
python app1.py
```

The app will start on `http://127.0.0.1:5000`. On the first run it will:
1. Create the SQLite database (`database.db`)
2. Seed a default admin account: `admin@test.com` / `admin`

> **Change the default admin credentials immediately after first login.**

---

## Scenario Description Format

Instructors write scenarios using a structured natural-language format. The scenario engine parses each `AP N` block:

```
Country: US

AP 1
  SSID: CorpNet
  Band: 2.4 GHz
  Channel: 6
  Security: WPA2-PSK
  Passphrase: SecurePass1!
  Stations: 3

AP 2
  SSID: CorpNet-5G
  Band: 5 GHz
  Channel: 36
  Security: WPA3-SAE
  Passphrase: AnotherPass99
  Stations: 2
```

### Enterprise (EAP/RADIUS) Example

```
Country: US

RADIUS
  Address: 127.0.0.1
  Port: 1812
  Shared-Secret: mysecret

AP 1
  SSID: EnterpriseNet
  Band: 5 GHz
  Channel: 36
  Security: WPA2-Enterprise
  Stations: 2
```

### Supported Security Modes

| Value | Protocol |
|---|---|
| `open` | No encryption |
| `wpa2-psk` | WPA2-Personal (PSK/CCMP) |
| `wpa3-sae` | WPA3-Personal (SAE/CCMP) |
| `wpa2-enterprise` | WPA2-Enterprise (EAP-PEAP/MSCHAPv2) |
| `wpa3-enterprise` | WPA3-Enterprise (EAP-PEAP + PMF required) |

---

## Running a Generated Testbed

After saving a scenario, the generated artifacts are stored under `scenario_artifacts/<slug>/`. To launch the testbed on a Linux machine with `mac80211_hwsim`:

```bash
cd scenario_artifacts/<scenario-slug>/
sudo bash generated_script.sh
```

To inspect the running testbed:

```bash
sudo bash scripts/wlan-tools.sh status        # Show interface state
sudo bash scripts/wlan-tools.sh ping-ap       # Ping APs from STAs
sudo bash scripts/wlan-tools.sh ping-sta      # Ping STAs from AP namespace
sudo bash scripts/wlan-tools.sh capture ap wlan0 out.pcap  # Packet capture
sudo bash scripts/wlan-tools.sh cleanup       # Stop hostapd/wpa_supplicant/dnsmasq
sudo bash scripts/wlan-tools.sh hard-reset    # Full teardown + module reload
```

---

## User Roles & Routes

| Role | Login URL | Key Routes |
|---|---|---|
| Admin | `/login` | `/admin`, `/admin/users`, `/admin/scenarios`, `/admin/assets` |
| Instructor | `/login/instructor` | `/instructor`, `/instructor/scenarios`, `/instructor/scenarios/create` |
| Learner | `/login/learner` | `/learner`, `/learner/scenarios`, `/learner/resources`, `/learner/help` |

All roles share `/profile` for username, bio, and password management.

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `NVD_API_KEY` | NVD API key for higher CVE request rate limits | None (unauthenticated) |

---

## Known Limitations & Notes

- **Development mode only**: `app.run(debug=True)` is set by default. Use a production WSGI server (Gunicorn, uWSGI) for any deployment beyond local testing.
- **SQLite**: Suitable for single-instance development. Swap `SQLALCHEMY_DATABASE_URI` for PostgreSQL/MySQL in production.
- **Enterprise RADIUS auto-bootstrap** runs system commands via `subprocess` — requires `sudo` privileges and FreeRADIUS installed.
- **mac80211_hwsim** only supports software-simulated radios. For real hardware, replace `modprobe mac80211_hwsim` with your physical interface setup.
- **secret_key**: The current value (`supersecretkey`) is a placeholder — replace it before any real deployment.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [hostapd](https://w1.fi/hostapd/) — IEEE 802.11 AP management
- [wpa_supplicant](https://w1.fi/wpa_supplicant/) — Wi-Fi client authentication
- [FreeRADIUS](https://freeradius.org/) — Enterprise RADIUS authentication
- [vis.js Network](https://visjs.github.io/vis-network/) — Topology graph visualization
- [NVD API](https://nvd.nist.gov/developers) — CVE data
- [feedparser](https://pythonhosted.org/feedparser/) — RSS/Atom feed parsing
