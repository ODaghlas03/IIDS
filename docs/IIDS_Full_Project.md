# IIDS — Intelligent Intrusion Detection System
## Complete Project Documentation

---

## Table of Contents
1. [What This Project Does](#what-this-project-does)
2. [Network Topology](#network-topology)
3. [System Architecture](#system-architecture)
4. [File Structure](#file-structure)
5. [How to Run the Project](#how-to-run-the-project)
6. [How to Access the Dashboard](#how-to-access-the-dashboard)
7. [How to Run an Attack Test](#how-to-run-an-attack-test)
8. [Dashboard Guide](#dashboard-guide)
9. [How the Detection Works](#how-the-detection-works)
10. [The AI Model](#the-ai-model)
11. [The Database](#the-database)
12. [Troubleshooting](#troubleshooting)
13. [Useful Commands](#useful-commands)
14. [Recommendations](#recommendations)

---

## What This Project Does

IIDS is a **Network Intrusion Detection System** that:
- Watches all network traffic passing through a gateway VM
- Detects attacks in real-time: port scans, DDoS floods, brute-force attempts, bot traffic
- Shows live results on a web dashboard
- Can automatically block attacker IPs using firewall rules
- Lets an analyst ask questions about the data in plain English using Claude AI

The system runs on a **VirtualBox Ubuntu VM** that sits between a Kali Linux attacker and an Ubuntu victim. All traffic must pass through the IDS — it is an **inline gateway**, not a passive tap.

---

## Network Topology

```
┌─────────────────┐         ┌──────────────────────────┐         ┌──────────────────┐
│   Kali Linux    │         │     IDS Ubuntu VM         │         │  Victim Ubuntu   │
│   (Attacker)    │         │   (192.168.56.101)        │         │                  │
│                 │──────── │  enp0s3: 10.0.1.1         │ ──────  │  IP: 10.0.2.10   │
│  IP: 10.0.1.10  │         │  enp0s8: 10.0.2.1         │         │                  │
└─────────────────┘         │  enp0s9: 192.168.56.101   │         └──────────────────┘
                            │                            │
                            │  Dashboard: port 8443      │◄── Your laptop browser
                            └──────────────────────────┘
```

- **enp0s3** (10.0.1.1) — faces the Kali attacker, traffic is captured here
- **enp0s8** (10.0.2.1) — faces the victim Ubuntu machine
- **enp0s9** (192.168.56.101) — host-only adapter for accessing the dashboard from your laptop

All traffic from Kali to the victim must pass through the IDS VM. The IDS captures it, analyses it, and can block it using iptables on the FORWARD chain.

### Routing (Permanent — already configured)

| VM | Route added | Via | Config |
|---|---|---|---|
| Kali (10.0.1.10) | `10.0.2.0/24` | `10.0.1.1` | NM connection `attacker-static` |
| Ubuntu victim (10.0.2.10) | `10.0.1.0/24` | `10.0.2.1` | NM connection `victim-static` |
| IDS VM | IP forwarding ON | — | `/etc/sysctl.d/99-ipforward.conf` |

These routes are permanent and survive reboot on all three VMs.

---

## System Architecture

```
                        ┌─────────────────────────────────────────────┐
  Network traffic       │               IDS Ubuntu VM                  │
  on enp0s3             │                                              │
        │               │  run_ids.sh (loops every 30 seconds)        │
        ▼               │  ┌──────────────────────────────────────┐   │
   tcpdump              │  │  1. tcpdump  → cap_XXXXXX.pcap       │   │
   (capture 30s)        │  │  2. cicflowmeter → flows_XXXXXX.csv  │   │
        │               │  │  3. infer.py → ids.db                │   │
        ▼               │  └──────────────────────────────────────┘   │
   CICFlowMeter         │                    │                         │
   (pcap → CSV)         │                    ▼                         │
        │               │             SQLite database                  │
        ▼               │             (ids.db)                         │
   infer.py             │                    │                         │
   (3-stage detection)  │                    ▼                         │
        │               │         Apache + PHP dashboard               │
        │               │         http://192.168.56.101:8080           │
        └───────────────┘                                              │
                                                                       │
                        └─────────────────────────────────────────────┘
```

### Components

| Component | What it does | Language |
|---|---|---|
| `run_ids.sh` | Main loop — orchestrates capture, conversion, inference | Bash |
| `tcpdump` | Captures raw network packets to a .pcap file | System tool |
| CICFlowMeter | Converts .pcap packets into flow-level statistics (CSV) | Java |
| `infer.py` | Runs the ML model and rule-based detectors, writes to DB | Python |
| `ids.db` | Stores all results, users, sessions, alerts | SQLite |
| Apache + PHP | Serves the web dashboard at port 8080 | PHP |
| `app.js` + `style.css` | Dashboard frontend — charts, tables, interactivity | JS + CSS |

---

## File Structure

```
/home/ids/ids/                         ← Main project directory
├── run_ids.sh                         ← Detection loop (run this to start)
├── infer.py                           ← ML inference engine
├── init_db.py                         ← Run once to create the database
├── ids.db                             ← SQLite database (all data)
├── .env                               ← API key: ANTHROPIC_API_KEY=sk-ant-...
├── models/
│   ├── autoencoder_best.keras         ← Trained neural network weights
│   ├── scaler.pkl                     ← StandardScaler (fitted on benign data)
│   ├── selected_features.json         ← 30 feature names the model uses
│   └── threshold.json                 ← Anomaly threshold = 0.1572
├── pcaps/                             ← Last 5 capture files (.pcap)
├── flows/                             ← Last 5 CICFlowMeter output files (.csv)
├── logs/
│   └── ids.log                        ← Log of every detection cycle
├── static/
│   └── iids_logo.png                  ← Logo
└── venv/                              ← Symlink → /home/ids/miniconda3/envs/ids (conda env)

/var/www/html/iids/                    ← PHP Dashboard (new, primary)
├── index.php                          ← Main page (login + dashboard)
├── includes/
│   ├── config.php                     ← Constants and paths
│   ├── db.php                         ← Database helper functions
│   └── auth.php                       ← Session validation
├── api/                               ← JSON API endpoints (called by JavaScript)
│   ├── login.php                      ← Login / logout / register
│   ├── metrics.php                    ← Live feed data
│   ├── analytics.php                  ← Chart data
│   ├── alerts.php                     ← Alerts list + acknowledge
│   ├── block.php                      ← Block / unblock IP
│   ├── verdict.php                    ← Analyst verdict on flows
│   ├── nl_search.php                  ← Natural language → SQL
│   ├── chat.php                       ← AI analyst chat
│   ├── report.php                     ← Incident report generation
│   ├── pcap.php                       ← PCAP file download
│   └── cycles.php                     ← Cycle list for reports
└── assets/
    ├── css/style.css                  ← All styling
    └── js/app.js                      ← All JavaScript logic

/home/ids/Desktop/
├── IIDS_Full_Project.md               ← This file
└── Dashboard_New_PHP.md               ← PHP dashboard documentation

/etc/systemd/system/
├── ids-detector.service               ← Auto-starts run_ids.sh on boot
└── apache2.service.d/override.conf   ← Allows Apache to access /home/ directory
```

---

## How to Run the Project

### Option A — Everything auto-starts on boot (recommended)

Both the detection loop and the PHP dashboard are configured to start automatically when the VM boots. You don't need to do anything.

After booting the VM:
1. Wait about 30 seconds
2. Open your browser and go to: **https://192.168.56.101:8443**
3. Accept the self-signed certificate warning (Advanced → Proceed)
4. Login with: `admin` / `Admin@IIDS2024!`

To check that services are running:
```bash
sudo systemctl status ids-detector apache2
```

Both should say **active (running)**.

---

### Option B — Start manually in terminals

If you want to see the live output in a terminal window:

**Terminal 1 — Stop the auto-started detector, then run manually:**
```bash
sudo systemctl stop ids-detector
~/ids/run_ids.sh
```
> You will see log output for every 30-second cycle.

**Terminal 2 — Watch the log live (optional):**
```bash
tail -f ~/ids/logs/ids.log
```

**Dashboard is always on** — Apache starts automatically on boot:
```bash
sudo systemctl status apache2   # check it's running
```

---

### Starting / Stopping services

```bash
# Check status
sudo systemctl status ids-detector apache2

# Stop everything
sudo systemctl stop ids-detector apache2

# Start everything
sudo systemctl start ids-detector apache2

# Restart just the dashboard (after editing PHP files)
sudo systemctl restart apache2

# View live detector logs
sudo journalctl -fu ids-detector

# View Apache error logs
sudo tail -f /var/log/apache2/iids_error.log
```

---

### Resetting the database (start fresh)

```bash
python3 - <<'EOF'
import sqlite3
con = sqlite3.connect('/home/ids/ids/ids.db')
for t in ['flows','alerts','cycles','blocked_ips','chat_sessions','nl_queries','sessions']:
    con.execute(f'DELETE FROM {t}')
    con.execute(f'DELETE FROM sqlite_sequence WHERE name="{t}"')
con.commit()
con.close()
print("Database cleared (users kept).")
EOF
```

> This keeps the `users` table so your admin password is preserved.

---

## How to Access the Dashboard

| Dashboard | URL | Port | Technology |
|---|---|---|---|
| **PHP Dashboard** (primary) | https://192.168.56.101:8443 | 8443 | PHP + HTML + CSS + JS (HTTPS) |
| HTTP redirect | http://192.168.56.101:8080 | 8080 | Redirects → 8443 |

**Login:** username `admin`, password `Admin@IIDS2024!`

> Accept the self-signed certificate warning in your browser (click Advanced → Proceed). Sessions expire after 30 minutes of inactivity.

---

## How to Run an Attack Test

Run these commands **from the Kali VM** (IP: 10.0.1.10).

### Port Scan
```bash
nmap -sS -p 1-1000 10.0.2.10
```
- Detected by: **Stage 2** (many unique destination ports)
- Shows as: **PortScan** (severity: low)
- Appears in dashboard within 30 seconds

### SYN Flood (DDoS)
```bash
sudo hping3 -S --flood -V -p 80 10.0.2.10
# Stop after 10-15 seconds with Ctrl+C
```
- Detected by: **Stage 1** (high reconstruction error) + **Stage 2** (high rate, single port)
- Shows as: **DDoS** (severity: high)
- tcpdump will stop at 150,000 packets to prevent disk fill

### Brute Force (SSH)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.2.10
```
- Detected by: **Stage 1** rule (brute-force ports + bidirectional traffic)
- Shows as: **BruteForce** (severity: medium)

### Bot Simulation (slow periodic HTTP)
```bash
for i in $(seq 1 20); do curl -s http://10.0.2.10 > /dev/null; sleep 4; done
```
- Detected by: **Stage 3** bot detector (periodic connections at C2-like rate)
- Shows as: **Bot** (severity: medium)

### After running an attack:
1. Wait up to 30 seconds for the cycle to complete
2. Open the dashboard → **Live Feed** tab: attack flows appear in the table
3. Open **Alerts** tab: new unacknowledged alert appears
4. To block the attacker: enter `10.0.1.10` in the "Block IP" panel and click **Block**

---

## Dashboard Guide

### Live Feed Tab
- **Metric cards** (top row): total flows seen, attacks detected, benign flows, Stage 2 detections, average reconstruction error
- **Recent Flows table**: last 100 flows with source/destination IP, port, protocol, ML error score, attack type badge, and analyst verdict
- **Detection Cycle panel** (right): shows which stage the current 30-second cycle is in (Capture → Convert → Analyse → Done) with a progress bar
- **Top Attackers** (right): bar chart of IPs with the most attack flows
- **Block IP** (right): enter an IP address and reason to add an iptables firewall rule; active blocks are listed below

### Analytics Tab
Six charts:
1. **Reconstruction error distribution** — histogram showing benign vs attack flows, with the detection threshold line
2. **Attack type breakdown** — pie chart of attack types (DDoS, PortScan, BruteForce, Bot, Unknown)
3. **Attacks per cycle** — stacked bar chart showing attack vs benign flows over the last 20 cycles
4. **Protocol distribution** — pie chart of network protocols seen
5. **Traffic composition** — pie chart of overall benign vs attack ratio
6. **Top targeted ports** — horizontal bar chart of most-attacked ports

Plus a table showing top attacker IPs with counts broken down by attack type.

### Alerts Tab
Each alert represents a unique attacking IP in a detection cycle. For each alert you can:
- **Acknowledge** — mark it as reviewed
- **Block** — immediately add an iptables rule to block that IP
- **Download PCAP** — download the packet capture file for that cycle

### NL Search Tab
Ask questions about your data in plain English. Examples:
- *"Show me all DDoS attacks in the last hour"*
- *"Which IP has the most port scans?"*
- *"How many attacks were there today?"*

Claude AI converts your question to a SQL query, runs it (read-only), and shows the results. Limited to 20 queries per login session.

### Analyst Chat Tab
A multi-turn conversation with Claude AI. You can ask follow-up questions about security incidents, request analysis of attack patterns, or ask what SQL queries to run. The AI knows the database schema so it can give specific answers.

### Reports Tab
- Select a detection cycle from the dropdown
- View that cycle's summary (total flows, attacks, start/end time)
- Click **Generate AI Report** to have Claude write a structured incident report
- Download the report as a text file
- Use the **Flow Verdict** panel to mark specific flows as "Confirmed attack" or "False positive"

---

## How the Detection Works

Every 30 seconds, the following pipeline runs:

### Step 1 — Capture
`tcpdump` records raw packets from `enp0s3` for 30 seconds into a `.pcap` file.
- Maximum 150,000 packets per cycle (prevents disk fill during flood attacks)
- Only the first 128 bytes of each packet are saved (headers only — CICFlowMeter doesn't need payload)

### Step 2 — Flow Conversion
`CICFlowMeter` reads the `.pcap` and produces a `.csv` where each row is a **network flow** (a conversation between two IPs) with ~80 statistical features like packet rates, byte counts, inter-arrival times, etc.

### Step 3 — Detection (3 stages in infer.py)

**Stage 1 — Autoencoder (ML model)**
- Takes 30 selected features from each flow
- Feeds them through a trained neural network (autoencoder)
- The autoencoder was trained only on benign traffic, so it reconstructs benign flows well but "doesn't understand" attacks
- If the reconstruction error is above the threshold (0.1572), the flow is flagged
- Catches: unusual traffic patterns the model hasn't seen before

**Stage 2 — Aggregate Detector**
- Groups flows by source IP over a 10-second sliding window
- Flags as **DDoS**: ≥50 flows/second AND ≤3 unique destination ports (flood to one target)
- Flags as **PortScan**: ≥50 flows/second AND many unique ports, OR ≥20 unique ports at any rate
- This stage exists because floods and port scans produce identical per-flow statistics — you can only tell them apart by looking at the whole group

**Stage 3 — Bot Detector**
- Runs on ALL flows regardless of ML score
- Bot traffic (slow HTTP to a C2 server) looks identical to normal HTTP — the autoencoder won't flag it
- Detects: same source IP making ≥3 connections to a common C2 port (80, 443, 8080, 8443, 53) at a rate of 0.05–2.0 flows/second, with the server responding

### Attack Classification

| Attack type | How detected | Severity |
|---|---|---|
| DDoS | Stage 2 (flood) or Stage 1 high-rate rule | High |
| PortScan | Stage 2 (scan) | Low |
| BruteForce | Stage 1 rule (brute-force ports + two-way traffic) | Medium |
| Bot | Stage 3 | Medium |
| Unknown | Stage 1 anomaly, no matching rule | Low |

### Packet Blocking
When you block an IP from the dashboard, PHP runs:
```bash
sudo iptables -A FORWARD -s <ip> -j DROP
sudo iptables -A INPUT   -s <ip> -j DROP
```
This drops all packets from that IP at the Linux kernel level — before they can reach the victim. The block is stored in the database and restored on reboot by the dashboard.

---

## The AI Model

### Architecture
A **6-layer autoencoder** (encoder compresses, decoder reconstructs):
```
Input (30 features)
    → Dense 30→24 + BatchNorm + ReLU
    → Dense 24→12 + BatchNorm + ReLU
    → Dense 12→6  (bottleneck — compressed representation)
    → Dense 6→12  + BatchNorm + ReLU
    → Dense 12→24 + BatchNorm + ReLU
    → Dense 24→30 (reconstruction output)
```

### Training
- Trained on **benign traffic only** from the CICIDS2017 dataset
- Loss function: mean squared error between input and reconstruction
- The threshold (0.1572) is the 95th percentile of reconstruction errors on benign training data
- This means the model will flag about 5% of benign traffic as suspicious (false positives) and catch most attacks

### Why numpy instead of TensorFlow?
TensorFlow requires AVX CPU instructions. The VirtualBox VM only exposes SSE4, causing TensorFlow to crash with exit code 132 (SIGILL). The model weights are loaded directly from the `.keras` file using `h5py` and the forward pass is computed manually in numpy — no TensorFlow needed at runtime.

### The 30 Input Features
```
Flow Duration, Flow Bytes/s, Flow IAT Max, Idle Mean, Bwd IAT Max,
Fwd IAT Mean, Bwd IAT Mean, Flow IAT Std, Flow IAT Mean, Fwd IAT Std,
Flow IAT Min, Fwd Header Length, Bwd IAT Std, Idle Std, Active Max,
Bwd Header Length, Active Mean, min_seg_size_forward, Active Min,
Active Std, Flow Packets/s, Packet Length Variance, Bwd Packets/s,
Destination Port, Init_Win_bytes_forward, Init_Win_bytes_backward,
Total Length of Fwd Packets, Total Fwd Packets, Max Packet Length,
Bwd Packet Length Max
```

---

## The Database

SQLite file at `/home/ids/ids/ids.db`. All tables:

| Table | Purpose | Key columns |
|---|---|---|
| `flows` | One row per network flow | source_ip, dest_ip, dest_port, attack, attack_type, reconstruction_error, analyst_verdict |
| `cycles` | One row per 30s detection cycle | started_at, ended_at, total_flows, attacks, benign |
| `alerts` | One row per attacking IP per cycle | source_ip, attack_type, severity, acknowledged |
| `blocked_ips` | Active firewall blocks | ip, reason, blocked_by, active |
| `users` | Dashboard user accounts | username, password_hash, role |
| `sessions` | Active login sessions | token, username, last_active |
| `nl_queries` | Audit log of AI SQL queries | natural_query, generated_sql |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Dashboard not loading at :8443 | Apache stopped | `sudo systemctl start apache2` |
| Dashboard shows "Session expired" | 10-min timeout reached | Log in again |
| No flows appearing after attack | Cycle hasn't finished yet | Wait up to 30 seconds |
| All flows classified as BENIGN | Threshold too high, or attack too short | Lower threshold in `models/threshold.json`, or run attack for longer |
| Block IP says "iptables failed" | Sudo permission missing | Check `/etc/sudoers.d/www-data-iptables` exists |
| AI features say "API key not configured" | Missing `.env` file | `echo 'ANTHROPIC_API_KEY=sk-ant-...' > ~/ids/.env && chmod 600 ~/ids/.env`, then `sudo systemctl restart apache2` |
| CICFlowMeter stuck / timed out | Large pcap from flood | Already handled automatically — the script skips that cycle |
| DB not updating | infer.py crashing | Check `~/ids/logs/ids.log` for Python errors |
| `ids-detector` service keeps restarting | run_ids.sh error | `sudo journalctl -fu ids-detector` to see the error |

---

## Useful Commands

```bash
# ── Service management ──────────────────────────────────────────────────────
sudo systemctl status ids-detector apache2       # check both at once
sudo systemctl restart ids-detector              # restart detection loop
sudo systemctl restart apache2                   # restart dashboard

# ── Live monitoring ─────────────────────────────────────────────────────────
tail -f ~/ids/logs/ids.log                       # watch detection cycles live
sudo journalctl -fu ids-detector                 # systemd logs for detector
sudo journalctl -fu apache2                      # systemd logs for Apache

# ── Database inspection ─────────────────────────────────────────────────────
python3 -c "
import sqlite3
con = sqlite3.connect('/home/ids/ids/ids.db')
print('cycles:', con.execute('SELECT COUNT(*) FROM cycles').fetchone()[0])
print('flows: ', con.execute('SELECT COUNT(*) FROM flows').fetchone()[0])
print('attacks:', con.execute('SELECT COUNT(*) FROM flows WHERE attack=1').fetchone()[0])
print('alerts:', con.execute('SELECT COUNT(*) FROM alerts').fetchone()[0])
"

# ── Firewall ────────────────────────────────────────────────────────────────
sudo iptables -L FORWARD -n                      # show all forward rules
sudo iptables -L INPUT -n                        # show all input rules
sudo iptables -F FORWARD                         # flush ALL forward rules (careful!)

# ── Attack tests (run from Kali) ────────────────────────────────────────────
nmap -sS -p 1-1000 10.0.2.10                    # port scan
sudo hping3 -S --flood -V -p 80 10.0.2.10       # SYN flood (stop with Ctrl+C)

# ── Tune detection sensitivity ──────────────────────────────────────────────
# Lower = more sensitive (more false positives)
# Higher = less sensitive (may miss attacks)
python3 -c "
import json
with open('/home/ids/ids/models/threshold.json') as f:
    d = json.load(f)
print('Current threshold:', d['threshold'])
"
# To change it:
# nano ~/ids/models/threshold.json
```

---

## Recommendations

These are improvements that would make the project stronger. They are not bugs — everything works — but they would raise the quality significantly.

### Security

**1. Change the default admin password**
The database has `admin`/`admin`. Before demonstrating the project to your professor, change it:
```bash
source ~/ids/venv/bin/activate
python3 -c "
import sqlite3, bcrypt
pw = input('New password: ').encode()
h = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
con = sqlite3.connect('/home/ids/ids/ids.db')
con.execute('UPDATE users SET password_hash=? WHERE username=?', (h, 'admin'))
con.commit()
print('Done.')
"
```

**2. HTTPS for the dashboard**
Right now the dashboard uses plain HTTP — passwords are sent unencrypted. For a real deployment, you would configure Apache with a TLS certificate (even a self-signed one). For a school demo on a local network, HTTP is acceptable.

**3. Tighten iptables for the IDS VM itself**
The VM currently forwards all traffic and only drops flagged IPs. You could add default DROP rules for the INPUT chain to protect the IDS VM itself from being attacked.

---

### Detection Quality

**4. Reduce false positives on DNS traffic**
The current model flags a lot of DNS flows as BENIGN but occasionally marks normal DNS as Unknown. You could add a whitelist rule in `classify_attack_type()` to always mark port 53 UDP flows as BENIGN unless the rate is extremely high.

**5. Add a whitelist for known-good IPs**
Add a `whitelist_ips` table to the database. Flows from whitelisted IPs would skip the ML model entirely. Useful if the gateway itself generates traffic that triggers false positives.

**6. Persist iptables rules across reboots**
Currently, if the VM reboots, all firewall blocks are lost (even though they are still in the database). Install `iptables-persistent` to restore rules on boot:
```bash
sudo apt install iptables-persistent
```
Or add a script that re-applies rules from the database on startup.

**7. Lower the detection threshold carefully**
The current threshold (0.1572) was set at the 95th percentile of benign errors, meaning 5% of benign traffic gets a false positive. If you have enough data now, you could retrain or at least recalculate the threshold from your own captured benign traffic for a better fit.

---

### Dashboard and Usability

**8. Email or SMS alerts**
When a high-severity alert is created, send an email or SMS notification. PHP can send email with the built-in `mail()` function, or you could use a service like Twilio for SMS.

**9. Add pagination to the flows table**
The Live Feed currently shows only the last 100 flows. A "Load more" button or pagination would make it easy to browse older data without using the NL Search.

**10. Export flows to CSV**
Add a button on the Analytics or Flows tab that lets the analyst download all attack flows as a CSV file. This is useful for offline analysis or submitting evidence.

**11. Auto-unblock after a time period**
Right now, blocked IPs stay blocked forever until manually unblocked. Add an `unblock_at` column to `blocked_ips` and a background check in the PHP dashboard to auto-unblock after (e.g.) 24 hours.

**12. Dashboard password change UI**
Currently there is no way to change your password from the dashboard — you have to run a Python script in the terminal. Adding a "Change password" page to the dashboard would be user-friendly.

---

### Infrastructure

**13. Automated backups of the database**
The database accumulates all traffic data and would be very bad to lose. Add a daily cron job to back it up:
```bash
# Add to crontab (crontab -e):
0 2 * * * cp /home/ids/ids/ids.db /home/ids/ids/backup/ids_$(date +\%Y\%m\%d).db
```

**14. Log rotation**
The file `~/ids/logs/ids.log` grows forever. Configure `logrotate` to rotate it weekly:
```bash
sudo nano /etc/logrotate.d/ids
# Content:
# /home/ids/ids/logs/ids.log {
#     weekly
#     rotate 4
#     compress
#     missingok
# }
```

**15. Rate-limit the NL Search API**
Currently the 20-queries-per-session limit is tracked in the database but there is no rate-limiting at the HTTP level. A motivated user could create many sessions to bypass it. For a production system, you would add rate limiting at the Apache level.

---

---

## Security Hardening (Added June 2026)

The following security tests are now addressed by the codebase:

| Test ID | Feature | Files |
|---------|---------|-------|
| ST-01 Unit | Password policy, lockout, RBAC functions independently testable | `includes/security.php`, `includes/rbac.php` |
| ST-02 Integration | Parameterized queries throughout; password policy + history enforced | All `api/*.php` |
| ST-03 System | Full workflow: login → detect → alert → pending action → approval | End-to-end |
| ST-04 Auth | bcrypt-12, lockout after 5 fails, 15-min lock, no user enumeration | `api/login.php` |
| ST-05 RBAC | admin / analyst / user; pending_actions approval workflow | `includes/rbac.php`, `api/pending_actions.php` |
| ST-06 Injection | Injection detection, CSP headers, parameterized SQL, escapeshellarg | `includes/security.php`, `.htaccess` |
| ST-07 Session | 30-min timeout, session regen on login, CSRF tokens, HttpOnly/SameSite | `includes/auth.php`, `api/login.php` |
| ST-08 API | Rate limiting (10/min login, 100/min API), 401 on missing auth | `includes/security.php`, all API files |
| ST-09 Encryption | HTTPS (port 8443), HSTS, AES-256 field encryption, bcrypt-12 | `iids-ssl.conf`, `includes/security.php` |
| ST-10 Performance | DB indexes, pagination (LIMIT/OFFSET), query busy timeout | `migrate_security.php`, all list endpoints |
| ST-11 Pen Test | No injection; CSRF; input validation; no path traversal in pcap.php | Multiple files |
| ST-12 Error | Custom 400/401/403/404/429/500 pages; no stack traces in output | `errors/*.php`, `.htaccess` |

### New DB Tables
- `login_attempts` — records every login attempt (used by lockout + audit)
- `password_history` — last 5 hashed passwords per user
- `audit_logs` — immutable record of all security-relevant events
- `rate_limits` — sliding-window request counters
- `pending_actions` — analyst action requests awaiting admin approval
- `ip_allowlist` — optional admin IP restriction

### Run Migration
```bash
php /var/www/html/iids/migrate_security.php
```

*Documentation updated: June 2026*
*Project: IIDS — Intelligent Intrusion Detection System*
