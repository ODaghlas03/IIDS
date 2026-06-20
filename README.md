# IIDS — Intelligent Intrusion Detection System

A network-based Intrusion Detection System that uses a deep learning autoencoder to classify network flows as benign or malicious in real time, with a full-featured PHP web dashboard for monitoring, alerting, and incident response.

---

## Features

- **Autoencoder-based detection** — unsupervised anomaly detection using reconstruction error on CICFlowMeter network flow features
- **Multi-stage detection pipeline** — Stage 1 (model), Stage 2 (aggregate flood/scan detection), and Bot detection running every cycle
- **Attack classification** — automatically labels flows as DDoS, PortScan, BruteForce, Bot, or Benign
- **Live dashboard** — real-time metrics, flow table, top attackers, and cycle pipeline visualization
- **Alerts & IP blocking** — alert acknowledgement, one-click IP block via iptables
- **Role-based access control** — Admin, Analyst, and User roles with approval workflow for sensitive actions
- **AI-powered tools** — natural language database queries and AI chat assistant for incident analysis, AI-generated incident reports
- **Security hardening** — bcrypt password hashing, CSRF protection, rate limiting, brute-force lockout, 2FA (TOTP), audit logging, session management

---

## Project Structure

```
IIDS_Project/
├── ids_backend/
│   ├── infer.py              # Main inference engine (autoencoder + classifiers)
│   ├── init_db.py            # Database initializer
│   ├── run_ids.sh            # Detection loop script
│   ├── models/
│   │   ├── autoencoder_best.keras
│   │   ├── scaler.pkl
│   │   ├── selected_features.json
│   │   └── threshold.json
│   └── static/
│       └── iids_logo.png
├── php_dashboard/
│   ├── index.php             # Main dashboard entry point
│   ├── api/                  # REST API endpoints
│   │   ├── alerts.php
│   │   ├── analytics.php
│   │   ├── block.php
│   │   ├── chat.php
│   │   ├── cycles.php
│   │   ├── login.php
│   │   ├── metrics.php
│   │   ├── nl_search.php
│   │   ├── report.php
│   │   └── ...
│   ├── includes/
│   │   ├── auth.php          # Session management
│   │   ├── config.php        # App configuration
│   │   ├── db.php            # SQLite helpers
│   │   ├── rbac.php          # Role-based access control
│   │   └── security.php      # Security utilities
│   └── assets/
│       ├── css/style.css
│       └── js/app.js
├── system_config/
│   ├── iids.conf             # Apache HTTP config
│   ├── iids-ssl.conf         # Apache HTTPS config
│   └── ids-detector.service  # Systemd service unit
└── docs/
    ├── IDS_Run_Instructions.md
    └── IDS_Setup_Documentation.md
```

---

## Requirements

### Detection Backend (Ubuntu VM)
- Python 3.10+
- `numpy`, `pandas`, `joblib`, `h5py`, `scikit-learn`
- CICFlowMeter
- `tcpdump`

### Dashboard (Apache + PHP)
- Apache 2.4+
- PHP 8.1+
- SQLite3 PHP extension
- OpenSSL PHP extension

---

## Setup

### 1. Initialize the database

```bash
python3 ids_backend/init_db.py
```

Creates `ids.db` and a default admin account (`admin` / `changeme123`). Change the password after first login.

### 2. Configure environment

Create `ids_backend/.env`:

```
ANTHROPIC_API_KEY=your_key_here
ENCRYPTION_KEY=your_base64_32byte_key_here
```

The Anthropic API key is required for the NL Search, AI Chat, and Report Generation features.

### 3. Install the PHP dashboard

Copy `php_dashboard/` to your Apache web root (e.g. `/var/www/html/iids/`) and enable the Apache config:

```bash
sudo cp system_config/iids.conf /etc/apache2/sites-available/iids.conf
sudo cp system_config/iids-ssl.conf /etc/apache2/sites-available/iids-ssl.conf
sudo a2ensite iids iids-ssl
sudo systemctl restart apache2
```

Update `php_dashboard/includes/config.php` with the correct `DB_PATH` and other paths for your environment.

### 4. Run the detection loop

```bash
~/ids/run_ids.sh
```

The script captures traffic, converts it to flows via CICFlowMeter, runs inference, and writes results to the database. Repeat every ~35 seconds.

To run as a systemd service:

```bash
sudo cp system_config/ids-detector.service /etc/systemd/system/
sudo systemctl enable ids-detector
sudo systemctl start ids-detector
```

---

## Dashboard Access

Open your browser at `https://<server-ip>:8443`

Default credentials: `admin` / `changeme123` — **change immediately after first login.**

---

## Detection Architecture

```
tcpdump (30s capture)
       ↓
CICFlowMeter (PCAP → flow features CSV)
       ↓
infer.py
  ├── Stage 1: Autoencoder reconstruction error > threshold → flag
  ├── Stage 2: Aggregate flood/scan detection (flow rate, port diversity)
  └── Stage 3: Bot detection (periodic C2 traffic pattern)
       ↓
SQLite DB (flows, alerts, cycles)
       ↓
PHP Dashboard (live feed, analytics, alerts)
```

---

## Security Notes

- The `.env` file (API keys) and SSL private key are excluded from this repository
- Never commit `.env` to version control
- Change all default passwords before deploying in any non-local environment
- The dashboard uses HTTPS with a self-signed certificate by default — replace with a trusted certificate for production use
