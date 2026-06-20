# IDS — Run Instructions & Dashboard Guide

## Starting the IDS (Every Boot)

Open **3 terminals** and run one command in each.

---

### Terminal 1 — Main Detection Loop
```bash
~/ids/run_ids.sh
```
This captures 30 seconds of traffic → converts to flows → runs inference → appends to `results.csv`. Loops forever. Each cycle takes ~35–40 seconds total.

> **Do NOT run with `sudo`.** The script calls `sudo tcpdump` internally.

---

### Terminal 2 — Live Dashboard (PHP)
The PHP dashboard starts automatically with Apache. No command needed.

Open on your laptop browser: **https://192.168.56.101:8443**
(HTTP port 8080 redirects automatically to HTTPS 8443)

---

### Terminal 3 — Live Log (optional)
```bash
tail -f ~/ids/logs/ids.log
```

---

## Auto-Start on Boot (Systemd)

Both the detector and the PHP dashboard (via Apache) start automatically on boot. No terminals needed — the dashboard is available at **https://192.168.56.101:8443** as soon as the VM boots.

### Service management commands

```bash
# Check status
sudo systemctl status ids-detector apache2

# Stop both
sudo systemctl stop ids-detector apache2

# Start both
sudo systemctl start ids-detector apache2

# View live logs
sudo journalctl -fu ids-detector
sudo journalctl -fu apache2
```

### Editing the PHP dashboard

After editing any file under `/var/www/html/iids/`, changes take effect immediately (PHP is interpreted on each request). For config changes, restart Apache:

```bash
sudo systemctl restart apache2
```

The detector (`ids-detector`) keeps running untouched the whole time.

---

## Stopping Everything (manual / terminal mode)

- **Terminal 1 (detector):** `Ctrl+C`
- **Dashboard:** `sudo systemctl stop apache2`

---

## Running an Attack Test (from Kali)

> **Prerequisites:** Routing must be configured. Kali (10.0.1.10) needs a route to the victim subnet — this is now permanently configured via NetworkManager (`attacker-static` connection).

```bash
# Port scan — triggers Stage 2 (PortScan detection)
nmap -sS -p 1-1000 10.0.2.10

# SYN Flood — triggers Stage 1 + Stage 2 (DDoS detection)
# Stop after 10–15 seconds with Ctrl+C
sudo hping3 -S --flood -V -p 80 10.0.2.10

# SSH Brute Force — triggers Stage 1 (BruteForce detection)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.2.10

# Bot simulation — triggers Stage 3 (Bot detection)
for i in $(seq 1 20); do curl -s http://10.0.2.10 > /dev/null; sleep 4; done
```

Wait up to 30 seconds for the next IDS cycle. Attacks appear in the PHP dashboard under **Live Feed** and **Alerts** tabs.

---

## Changing the Detection Threshold

The threshold is stored in `~/ids/models/threshold.json`:
```json
{"threshold": 0.1572}
```
Lower the value → more sensitive (more false positives).
Raise the value → less sensitive (fewer false positives, may miss attacks).

Edit it:
```bash
nano ~/ids/models/threshold.json
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Permission denied` on `ids.log` | `sudo chown ids:ids ~/ids/logs/ids.log` |
| CICFlowMeter stuck for minutes | Large pcap from a flood attack. Kill it: `pkill -f cicflowmeter`, then re-run `run_ids.sh` |
| Dashboard not loading at :8443 | `sudo systemctl start apache2` |
| All flows BENIGN after attack | Make sure hping3 was stopped before the cycle ended, or lower the threshold |
| `cicflowmeter: command not found` | Run `export PATH="/home/ids/ids/venv/bin:$PATH"` first |
| High memory use | A flood attack during capture inflates the pcap. The `-s 128` flag limits this. |
| DB not updating | Check `~/ids/logs/ids.log` for Python errors in `infer.py` |

---

## File Reference

| File | Purpose |
|---|---|
| `~/ids/run_ids.sh` | Main loop — edit `INTERVAL` (seconds) and `IFACE` here |
| `~/ids/infer.py` | Inference engine — numpy autoencoder |
| `~/ids/ids.db` | SQLite database — all flows, alerts, cycles, users |
| `~/ids/models/threshold.json` | Detection sensitivity — edit to tune |
| `~/ids/logs/ids.log` | Timestamped log of every cycle |
| `/var/www/html/iids/` | PHP dashboard root — all UI edits go here |
