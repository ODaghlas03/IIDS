# IDS Project — Setup Documentation

## Overview

A Network Intrusion Detection System (IDS) built on a VirtualBox Ubuntu VM. It captures live network traffic, converts it to flow features using CICFlowMeter, and classifies flows using a trained autoencoder neural network. Detected attacks are displayed on a live PHP web dashboard (Apache + PHP 8.5) at https://192.168.56.101:8443.

---

## System Architecture

```
[Kali Attacker VM] ──────────────────────────────────────────────────────────────┐
      (nmap, hping3)                                                              │
                                                                                  ▼
                                                             [IDS Ubuntu VM — 192.168.56.101]
                                                             ┌──────────────────────────────┐
                                                             │  tcpdump (30s capture)       │
                                                             │       ↓                      │
                                                             │  CICFlowMeter (pcap→CSV)     │
                                                             │       ↓                      │
                                                             │  infer.py (numpy autoencoder)│
                                                             │       ↓                      │
                                                             │  ids.db (SQLite)             │
                                                             │       ↓                      │
                                                             │  Apache + PHP Dashboard :8443│
                                                             └──────────────────────────────┘
```

---

## File Structure

```
~/ids/   (= /home/ids/ids/)
├── models/
│   ├── autoencoder_best.keras   — trained autoencoder (Keras 3 ZIP format)
│   ├── scaler.pkl               — StandardScaler fitted on training data
│   ├── selected_features.json   — 30 CIC feature names used by the model
│   └── threshold.json           — reconstruction error threshold (0.1572)
├── infer.py                     — inference engine (pure numpy, no TensorFlow)
├── run_ids.sh                   — main detection loop script
├── ids.db                       — SQLite database (all detection results)
├── pcaps/                       — rolling 5 pcap files (30s each)
├── flows/                       — CICFlowMeter CSV outputs
└── logs/
    └── ids.log                  — timestamped run log
```

---

## Problems Encountered and How They Were Fixed

### 1. TensorFlow Crashes (SIGILL — Illegal Instruction)
**Problem:** TensorFlow 2.21 requires AVX CPU instructions. The VirtualBox VM only exposes SSE4 to the guest (no AVX), causing TF to crash immediately with exit code 132.

**Fix:** Replaced TensorFlow entirely with a pure numpy inference engine. The `.keras` model file (a ZIP archive containing `config.json` + `model.weights.h5`) is loaded using `zipfile` + `h5py`. The forward pass (Dense layers, BatchNormalization) is implemented in numpy. No TensorFlow needed at runtime.

### 2. Keras Config Layer Name Mismatch
**Problem:** The model's `config.json` names layers `bottleneck` and `output`, but the weight file uses sequential names `dense_2`, `dense_3`, `dense_4`, `dense_5`. Name-based weight lookup failed.

**Fix:** Changed weight assignment to be index-based — the nth Dense layer in the config gets the nth Dense weight block from the HDF5 file, regardless of the layer's name.

### 3. CICFlowMeter `AttributeError: 'bool' object has no attribute 'split'`
**Problem:** Bug in the installed `cicflowmeter` Python package (`sniffer.py` line 300). The function `create_sniffer()` has `input_directory` as its 5th positional argument, but `main()` was passing `args.fields` there. As a result, `args.verbose` (a bool) was landing in the `fields` parameter.

**Fix:** Changed the `main()` call to use keyword arguments: `fields=args.fields, verbose=args.verbose`.
File patched: `/home/ids/ids/venv/lib/python3.12/site-packages/cicflowmeter/sniffer.py`

### 4. Column Name Mismatch (CICFlowMeter vs Model Features)
**Problem:** The Python `cicflowmeter` package outputs lowercase snake_case column names (`flow_duration`, `src_ip`, `dst_port`). The trained model expects CIC dataset-style names (`Flow Duration`, `Source IP`, `Destination Port`).

**Fix:** Added a `COLUMN_MAP` dictionary in `infer.py` that remaps all ~80 column names at load time using `df.rename(columns=COLUMN_MAP)`.

### 5. tcpdump Permission Denied Writing to pcaps Directory
**Problem:** Running `run_ids.sh` with `sudo` caused the whole script to run as root. tcpdump, when started as root, drops privileges to the system `tcpdump` user (UID 983) after opening the network interface. The `tcpdump` user cannot write to `/home/ids/ids/pcaps/` (owned by `ids`). chmod 777 and AppArmor changes did not help because the issue was privilege dropping, not filesystem permissions.

**Fix:** Added `-Z ids` flag to tcpdump: `sudo tcpdump -Z ids ...`. This tells tcpdump to drop to the `ids` user instead of the `tcpdump` system user, so it retains write access to the project directories. The script is now run **without** `sudo` — `~/ids/run_ids.sh` — while only `tcpdump` inside the script uses sudo.

### 6. AppArmor Blocking tcpdump
**Problem:** The tcpdump AppArmor profile was enforcing path restrictions. The `/**.[pP][cC][aA][pP] rw` rule should have allowed writing `.pcap` files anywhere, but it was still blocking writes to `/home/ids/ids/pcaps/`. Writing to `/tmp/` worked but project directories did not.

**Fix:** Disabled the tcpdump AppArmor profile:
```bash
sudo ln -sf /etc/apparmor.d/usr.bin.tcpdump /etc/apparmor.d/disable/usr.bin.tcpdump
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.tcpdump
```

### 7. venv Missing `activate` Script (Conda Environment)
**Problem:** The project expects a standard Python venv at `~/ids/venv/` with a `bin/activate` script. The environment was built using Miniconda (`/home/ids/miniconda3/envs/ids/`) which does not ship a bash `activate` script at the expected path, causing `run_ids.sh` to fail immediately with: `/home/ids/ids/venv/bin/activate: No such file or directory`.

**Fix (step 1):** Created a symlink so all `~/ids/venv/bin/*` paths resolve correctly:
```bash
ln -s /home/ids/miniconda3/envs/ids /home/ids/ids/venv
```

**Fix (step 2):** Replaced `source ~/ids/venv/bin/activate` in `run_ids.sh` with a direct PATH export (conda envs do not use activate scripts the same way):
```bash
export PATH="/home/ids/ids/venv/bin:$PATH"
```

---

### 8. Kali → Ubuntu Routing (Cross-Subnet Attack Traffic)
**Problem:** Kali (10.0.1.10) and the Ubuntu victim (10.0.2.10) are on different subnets. Without explicit routes, attack traffic from Kali never reaches the victim and the IDS captures nothing.

**Fix:** Added permanent static routes via NetworkManager on each VM:

*On Kali:*
```bash
sudo nmcli connection modify 'attacker-static' +ipv4.routes '10.0.2.0/24 10.0.1.1'
sudo nmcli connection up 'attacker-static'
```

*On Ubuntu victim:*
```bash
sudo nmcli connection modify 'victim-static' +ipv4.routes '10.0.1.0/24 10.0.2.1'
sudo nmcli connection up 'victim-static'
```

The IDS VM itself acts as the gateway (`10.0.1.1` / `10.0.2.1`) with IP forwarding permanently enabled via `/etc/sysctl.d/99-ipforward.conf`.

---

### 9. Huge pcap Files During DoS Flood
**Problem:** hping3 `--flood` generates millions of SYN packets per second. A 60-second capture produced a 132MB pcap file. CICFlowMeter consumed 2.3GB of RAM trying to process it and never finished.

**Fix:** Two changes to `run_ids.sh`:
- Added `-s 128` to tcpdump: captures only the first 128 bytes of each packet (headers only). CICFlowMeter only needs packet headers for flow statistics — no payload. This reduces flood pcap size from ~132MB to ~2–3MB.
- Reduced `INTERVAL` from 60 to 30 seconds for faster, smaller cycles.

---

## Model Details

| Property | Value |
|---|---|
| Architecture | Functional autoencoder — 6 Dense layers + 4 BatchNorm layers |
| Input features | 30 CIC network flow features |
| Layer sizes | 30 → 24 → 12 → 6 (bottleneck) → 12 → 24 → 30 |
| Activation | ReLU (hidden), Linear (output) |
| Anomaly threshold | 0.1572 (reconstruction MSE) |
| Scaler | StandardScaler (sklearn 1.6.1) |

### Three-Stage Detection

| Stage | Method | Trigger |
|---|---|---|
| Stage 1 | Autoencoder reconstruction error | MSE > 0.1572 |
| Stage 2 | Aggregate heuristic | ≥50 flows/sec from one IP, or ≥20 unique destination ports in 10s window |
| Stage 3 | Bot detector | Same IP making ≥3 connections to C2 ports at 0.05–2.0 flows/sec with server responding |

---

## Network Configuration

| VM | Interface | IP |
|---|---|---|
| IDS (Ubuntu) | enp0s3 (NAT — monitored) | 10.0.1.1 |
| IDS (Ubuntu) | enp0s9 (Host-only — dashboard) | 192.168.56.101 |
| Kali (Attacker) | Target IP | 10.0.2.10 |

---

## Key Decisions

- **No TensorFlow at runtime** — numpy-only inference is faster to start, uses less memory, and works on any CPU regardless of AVX support.
- **Header-only capture (`-s 128`)** — reduces pcap size by 10–100x for high-traffic environments, especially important during flood attacks.
- **Three-stage detection** — Stage 1 catches anomalous individual flows; Stage 2 catches volumetric/scanning attacks; Stage 3 catches periodic bot traffic that looks like normal HTTP.
- **SQLite database** — all results stored in `ids.db`, served by the PHP dashboard over HTTPS.
