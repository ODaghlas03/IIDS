#!/usr/bin/env python3
"""
infer.py — Numpy-based autoencoder inference with SQLite output.
Reads a CICFlowMeter CSV, classifies flows, writes results to ids.db.

Usage:
    python3 infer.py --flows /path/to/flows.csv --models ~/ids/models \
                     --db ~/ids/ids.db --cycle-id 1 --pcap /path/to/cap.pcap
"""
from __future__ import annotations

import argparse, json, os, sqlite3, zipfile, warnings
from datetime import datetime
from pathlib import Path

import h5py
import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── Column name map: CICFlowMeter actual snake_case → model's CamelCase ────────
# Keys must match the exact column names that cicflowmeter writes to CSV.
COLUMN_MAP = {
    # Identity/meta
    "src_ip":               "Source IP",
    "dst_ip":               "Destination IP",
    "src_port":             "Source Port",
    "dst_port":             "Destination Port",
    "protocol":             "Protocol",
    "timestamp":            "Timestamp",
    # Flow-level
    "flow_duration":        "Flow Duration",
    "flow_byts_s":          "Flow Bytes/s",
    "flow_pkts_s":          "Flow Packets/s",
    "fwd_pkts_s":           "Fwd Packets/s",
    "bwd_pkts_s":           "Bwd Packets/s",
    # Packet counts
    "tot_fwd_pkts":         "Total Fwd Packets",
    "tot_bwd_pkts":         "Total Backward Packets",
    "totlen_fwd_pkts":      "Total Length of Fwd Packets",
    "totlen_bwd_pkts":      "Total Length of Bwd Packets",
    # Fwd packet lengths
    "fwd_pkt_len_max":      "Fwd Packet Length Max",
    "fwd_pkt_len_min":      "Fwd Packet Length Min",
    "fwd_pkt_len_mean":     "Fwd Packet Length Mean",
    "fwd_pkt_len_std":      "Fwd Packet Length Std",
    # Bwd packet lengths
    "bwd_pkt_len_max":      "Bwd Packet Length Max",
    "bwd_pkt_len_min":      "Bwd Packet Length Min",
    "bwd_pkt_len_mean":     "Bwd Packet Length Mean",
    "bwd_pkt_len_std":      "Bwd Packet Length Std",
    # Packet length aggregates — model uses "Max Packet Length" (not "Packet Length Max")
    "pkt_len_max":          "Max Packet Length",
    "pkt_len_min":          "Packet Length Min",
    "pkt_len_mean":         "Packet Length Mean",
    "pkt_len_std":          "Packet Length Std",
    "pkt_len_var":          "Packet Length Variance",
    "pkt_size_avg":         "Average Packet Size",
    # Flow IAT
    "flow_iat_mean":        "Flow IAT Mean",
    "flow_iat_std":         "Flow IAT Std",
    "flow_iat_max":         "Flow IAT Max",
    "flow_iat_min":         "Flow IAT Min",
    # Fwd IAT
    "fwd_iat_tot":          "Fwd IAT Total",
    "fwd_iat_mean":         "Fwd IAT Mean",
    "fwd_iat_std":          "Fwd IAT Std",
    "fwd_iat_max":          "Fwd IAT Max",
    "fwd_iat_min":          "Fwd IAT Min",
    # Bwd IAT
    "bwd_iat_tot":          "Bwd IAT Total",
    "bwd_iat_mean":         "Bwd IAT Mean",
    "bwd_iat_std":          "Bwd IAT Std",
    "bwd_iat_max":          "Bwd IAT Max",
    "bwd_iat_min":          "Bwd IAT Min",
    # Flags
    "fwd_psh_flags":        "Fwd PSH Flags",
    "bwd_psh_flags":        "Bwd PSH Flags",
    "fwd_urg_flags":        "Fwd URG Flags",
    "bwd_urg_flags":        "Bwd URG Flags",
    "fin_flag_cnt":         "FIN Flag Count",
    "syn_flag_cnt":         "SYN Flag Count",
    "rst_flag_cnt":         "RST Flag Count",
    "psh_flag_cnt":         "PSH Flag Count",
    "ack_flag_cnt":         "ACK Flag Count",
    "urg_flag_cnt":         "URG Flag Count",
    "cwr_flag_count":       "CWE Flag Count",
    "ece_flag_cnt":         "ECE Flag Count",
    # Headers
    "fwd_header_len":       "Fwd Header Length",
    "bwd_header_len":       "Bwd Header Length",
    # Misc
    "down_up_ratio":        "Down/Up Ratio",
    "fwd_seg_size_avg":     "Avg Fwd Segment Size",
    "bwd_seg_size_avg":     "Avg Bwd Segment Size",
    # Bulk
    "fwd_byts_b_avg":       "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg":       "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg":     "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg":       "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg":       "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg":     "Bwd Avg Bulk Rate",
    # Subflows
    "subflow_fwd_pkts":     "Subflow Fwd Packets",
    "subflow_fwd_byts":     "Subflow Fwd Bytes",
    "subflow_bwd_pkts":     "Subflow Bwd Packets",
    "subflow_bwd_byts":     "Subflow Bwd Bytes",
    # Init window
    "init_fwd_win_byts":    "Init_Win_bytes_forward",
    "init_bwd_win_byts":    "Init_Win_bytes_backward",
    # Segment size / act data
    "fwd_act_data_pkts":    "act_data_pkt_fwd",
    "fwd_seg_size_min":     "min_seg_size_forward",
    # Active / Idle
    "active_mean":          "Active Mean",
    "active_std":           "Active Std",
    "active_max":           "Active Max",
    "active_min":           "Active Min",
    "idle_mean":            "Idle Mean",
    "idle_std":             "Idle Std",
    "idle_max":             "Idle Max",
    "idle_min":             "Idle Min",
}


# ── Numpy autoencoder loader ──────────────────────────────────────────────────

class NumpyAutoencoder:
    """Loads a Keras autoencoder from its .keras ZIP file and runs inference
    in pure numpy. Supports Dense + BatchNormalization layers."""

    BN_EPS = 1e-3  # Keras default epsilon for BatchNorm

    # Explicit layer sequence: (h5_layer_name, type, activation_or_None)
    # Derived from inspecting the .keras model architecture.
    # Encoder: Dense(30→24)→BN→Dense(24→12)→BN→Dense(12→6)
    # Decoder: Dense(6→12)→BN→Dense(12→24)→BN→Dense(24→30)
    _LAYER_SEQUENCE = [
        ("dense",                 "dense", "relu"),
        ("batch_normalization",   "bn",    None),
        ("dense_1",               "dense", "relu"),
        ("batch_normalization_1", "bn",    None),
        ("dense_2",               "dense", "relu"),   # bottleneck
        ("dense_3",               "dense", "relu"),
        ("batch_normalization_2", "bn",    None),
        ("dense_4",               "dense", "relu"),
        ("batch_normalization_3", "bn",    None),
        ("dense_5",               "dense", "linear"), # reconstruction output
    ]

    def __init__(self, keras_path: str):
        self.layers: list[dict] = []
        self._load(keras_path)

    def _load(self, path: str):
        import io
        with zipfile.ZipFile(path) as zf:
            with zf.open("model.weights.h5") as f:
                buf = io.BytesIO(f.read())
        wf = h5py.File(buf, "r")
        layer_grp = wf["layers"]

        for h5_name, ltype, act in self._LAYER_SEQUENCE:
            v = layer_grp[h5_name]["vars"]
            if ltype == "dense":
                self.layers.append({
                    "type": "dense",
                    "w":    np.array(v["0"]),   # kernel (in, out)
                    "b":    np.array(v["1"]),   # bias   (out,)
                    "act":  act,
                })
            else:  # bn: vars order is gamma, beta, moving_mean, moving_var
                self.layers.append({
                    "type":  "bn",
                    "gamma": np.array(v["0"]),
                    "beta":  np.array(v["1"]),
                    "mean":  np.array(v["2"]),
                    "var":   np.array(v["3"]),
                })
        wf.close()

    @staticmethod
    def _activate(x: np.ndarray, name: str) -> np.ndarray:
        if name == "relu":
            return np.maximum(0, x)
        if name == "sigmoid":
            return 1 / (1 + np.exp(-x))
        return x  # linear

    def predict(self, X: np.ndarray) -> np.ndarray:
        out = X.astype(np.float32)
        for lyr in self.layers:
            if lyr["type"] == "dense":
                out = out @ lyr["w"] + lyr["b"]
                out = self._activate(out, lyr["act"])
            else:  # BatchNorm inference: y = gamma*(x-mean)/sqrt(var+eps) + beta
                out = lyr["gamma"] * (out - lyr["mean"]) / np.sqrt(lyr["var"] + self.BN_EPS) + lyr["beta"]
        return out


# ── Attack type classifier (rule-based) ──────────────────────────────────────

BRUTE_PORTS  = {21, 22, 23, 25, 110, 143, 389, 445, 3389, 5900}
C2_PORTS     = {80, 443, 8080, 8443, 53}

# Destination ports where short/low-packet flows are completely normal.
# Excluded from PortScan classification and aggregate scan port counting.
BENIGN_PORTS = {
    53,           # DNS
    67, 68,       # DHCP
    123,          # NTP
    137, 138, 139,# NetBIOS
    1900,         # SSDP / UPnP
    5353,         # mDNS
    5355,         # LLMNR
}

def classify_attack_type(row, context: str | None = None) -> str:
    """
    context is set by the aggregate/bot detectors and takes priority:
      "flood" → high rate, few destination ports        → DDoS/DoS
      "scan"  → many destination ports                  → PortScan
      "bot"   → slow periodic C2 traffic               → Bot
      None    → stage-1 (model) only; use flow features
    """
    # Aggregate/bot context overrides per-flow rules — this is the fix for
    # SYN flood being misclassified as PortScan (both look like 1-packet probes
    # per flow; only the aggregate pattern reveals which one it is).
    if context == "flood":
        return "DDoS"
    if context == "scan":
        return "PortScan"
    if context == "bot":
        return "Bot"

    # Stage-1 only: rule-based on per-flow features.
    try:
        dst_port      = int(float(row.get("Destination Port", 0) or 0))
        pkts_s        = float(row.get("Flow Packets/s",       0) or 0)
        bytes_s       = float(row.get("Flow Bytes/s",         0) or 0)
        fwd_pkts      = float(row.get("Total Fwd Packets",    0) or 0)
        bwd_pkts      = float(row.get("Total Backward Packets", 0) or 0)
        total_pkts    = fwd_pkts + bwd_pkts
        pkt_len_mean  = float(row.get("Packet Length Mean",   0) or 0)
        flow_iat_mean = float(row.get("Flow IAT Mean",        0) or 0)
    except (TypeError, ValueError):
        return "Unknown"

    # High-rate flows the model flagged but aggregate didn't catch
    if (pkts_s > 100 or bytes_s > 100_000) and total_pkts > 4:
        return "DDoS"

    # PortScan: few small one-directional packets to a non-whitelisted port.
    # DNS (53), NTP (123), DHCP (67/68) etc. are always short — never PortScan.
    if (pkt_len_mean < 100 and total_pkts <= 4 and bwd_pkts <= 1
            and dst_port not in BENIGN_PORTS and dst_port != 0):
        return "PortScan"

    if dst_port in BRUTE_PORTS and pkt_len_mean < 200 and fwd_pkts > 3 and bwd_pkts > 1:
        return "BruteForce"

    return "Unknown"


# ── Stage-2 aggregate detector ────────────────────────────────────────────────

def aggregate_detect(df: pd.DataFrame,
                     window_seconds: int = 10,
                     flows_per_sec_thresh: int = 50,
                     unique_ports_thresh: int = 20) -> tuple[set, set]:
    """
    Returns (flood_flags, scan_flags).

    flood_flags: high flow-rate to few destination ports  → DDoS/DoS
    scan_flags:  many distinct destination ports probed   → PortScan

    Separating the two cases is critical: a SYN flood and a port scan both
    produce 1-packet flows with identical per-flow statistics. Only the
    aggregate pattern distinguishes them.
    """
    required = ["Source IP", "Timestamp", "Destination Port"]
    if not all(c in df.columns for c in required):
        return set(), set()
    df = df.copy()
    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    df = df.dropna(subset=["Timestamp"]).sort_values("Timestamp").reset_index(drop=False)
    flood_flags: set = set()
    scan_flags:  set = set()
    for _, grp in df.groupby("Source IP"):
        if len(grp) < 5:
            continue
        times = grp["Timestamp"]
        cur   = times.min()
        t_end = times.max()

        # Flood bursts often all land at the same timestamp after second-level
        # parsing — the while loop below would never run.  Treat the whole
        # group as one window when the time span is shorter than window_seconds.
        if (t_end - cur).total_seconds() < window_seconds:
            fps         = len(grp) / window_seconds
            unique_ports = grp["Destination Port"].nunique()
            # For slow-scan detection only: exclude benign service ports (DNS/NTP/DHCP…)
            # so normal background traffic never inflates the scan count.
            scan_unique  = grp["Destination Port"][
                ~grp["Destination Port"].isin(BENIGN_PORTS)].nunique()
            if fps >= flows_per_sec_thresh:
                if unique_ports <= 3:
                    flood_flags.update(grp["index"].tolist())
                else:
                    scan_flags.update(grp["index"].tolist())
            elif scan_unique >= unique_ports_thresh:
                scan_flags.update(grp["index"].tolist())
            continue

        while cur < t_end:
            w_end  = cur + pd.Timedelta(seconds=window_seconds)
            window = grp[(times >= cur) & (times < w_end)]
            if len(window) >= 3:
                fps          = len(window) / window_seconds
                unique_ports = window["Destination Port"].nunique()
                scan_unique  = window["Destination Port"][
                    ~window["Destination Port"].isin(BENIGN_PORTS)].nunique()
                if fps >= flows_per_sec_thresh:
                    # High rate: flood if concentrated on few ports, scan otherwise
                    if unique_ports <= 3:
                        flood_flags.update(window["index"].tolist())
                    else:
                        scan_flags.update(window["index"].tolist())
                elif scan_unique >= unique_ports_thresh:
                    # Slower scan but hitting many distinct non-benign ports
                    scan_flags.update(window["index"].tolist())
            cur = w_end
    return flood_flags, scan_flags


def detect_bots(df: pd.DataFrame, window_seconds: int = 30,
                min_flows: int = 3, max_fps: float = 2.0) -> set:
    """
    Detect periodic C2 communication on ALL flows (regardless of model score).

    Bot traffic mimics benign HTTP so the autoencoder gives it a low
    reconstruction error and never flags it. We detect it by pattern:
    same source IP making repeated low-rate connections to a C2 port
    where the server actually responds (bwd_pkts > 0).

    For ports 80/443 only: also require traffic targets ≤3 distinct
    servers — a browser fans out to many hosts, a bot beacon targets one.
    Port 53 keeps the original (src, port) grouping so periodic DNS
    queries to different resolvers are still caught as one group.
    """
    needed = {"Source IP", "Destination Port", "Total Backward Packets"}
    if not needed.issubset(df.columns):
        return set()
    bot_flags: set = set()
    c2_mask   = df["Destination Port"].isin(C2_PORTS)
    has_dst_ip = "Destination IP" in df.columns
    for (_, dst_port), grp in df[c2_mask].groupby(["Source IP", "Destination Port"]):
        # Standard web ports: skip if traffic fans to many different servers
        # (browser behaviour — not a focused C2 beacon)
        if dst_port in {80, 443} and has_dst_ip:
            if grp["Destination IP"].nunique() > 3:
                continue
        flow_min = 8 if dst_port in {80, 443} else min_flows
        if len(grp) < flow_min:
            continue
        # Use actual observed time span for fps so periodicity reflects
        # reality, not an arbitrary constant divisor.
        if "Timestamp" in df.columns:
            times = pd.to_datetime(grp["Timestamp"], errors="coerce").dropna()
            span  = max((times.max() - times.min()).total_seconds(), 1.0) if len(times) >= 2 else float(window_seconds)
        else:
            span = float(window_seconds)
        fps     = len(grp) / span
        avg_bwd = float(grp["Total Backward Packets"].mean())
        if 0.05 <= fps <= max_fps and avg_bwd > 0:
            bot_flags.update(grp.index.tolist())
    return bot_flags


# ── DB helpers ────────────────────────────────────────────────────────────────

def open_db(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def create_cycle(con: sqlite3.Connection, pcap: str, flows_file: str) -> int:
    cur = con.execute(
        "INSERT INTO cycles (started_at, pcap_file, flows_file) VALUES (?,?,?)",
        (datetime.now().isoformat(), pcap, flows_file),
    )
    con.commit()
    return cur.lastrowid


def close_cycle(con: sqlite3.Connection, cycle_id: int,
                total: int, attacks: int, benign: int):
    con.execute(
        "UPDATE cycles SET ended_at=?,total_flows=?,attacks=?,benign=? WHERE id=?",
        (datetime.now().isoformat(), total, attacks, benign, cycle_id),
    )
    con.commit()


def insert_flows(con: sqlite3.Connection, rows: list[tuple]):
    con.executemany(
        """INSERT INTO flows
           (cycle_id,flow_timestamp,source_ip,dest_ip,dest_port,protocol,
            flow_duration,flow_packets_s,flow_bytes_s,total_fwd_packets,
            total_bwd_packets,packet_length_mean,flow_iat_mean,
            reconstruction_error,attack,stage1,stage2,attack_type)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    con.commit()


def upsert_alerts(con: sqlite3.Connection, cycle_id: int, df: pd.DataFrame):
    """Create one alert row per unique attacking source IP per cycle."""
    if "Source IP" not in df.columns or "ATTACK" not in df.columns:
        return
    attack_df = df[df["ATTACK"] == True]
    if attack_df.empty:
        return
    for ip, grp in attack_df.groupby("Source IP"):
        atype    = grp["attack_type"].mode()[0] if "attack_type" in grp.columns else "Unknown"
        max_err  = float(grp["Reconstruction_Error"].max()) if "Reconstruction_Error" in grp.columns else None
        severity = "high" if atype == "DDoS" else "medium" if atype in ("BruteForce","Bot") else "low"
        con.execute(
            """INSERT INTO alerts (cycle_id,source_ip,attack_type,severity,flow_count,max_error)
               VALUES (?,?,?,?,?,?)""",
            (cycle_id, ip, atype, severity, len(grp), max_err),
        )
    con.commit()


# ── Main inference pipeline ───────────────────────────────────────────────────

def run(flows_csv: str, models_dir: str, db_path: str, pcap_file: str):

    # Load artifacts
    models = Path(models_dir)
    with open(models / "threshold.json") as f:
        THRESHOLD = json.load(f)["threshold"]
    with open(models / "selected_features.json") as f:
        FEATURES = json.load(f)
    scaler = joblib.load(models / "scaler.pkl")
    model  = NumpyAutoencoder(str(models / "autoencoder_best.keras"))

    # Load flows CSV
    df = pd.read_csv(flows_csv, low_memory=False)
    df.columns = df.columns.str.strip()
    df.rename(columns=COLUMN_MAP, inplace=True)

    # Ensure all required features exist
    for feat in FEATURES:
        if feat not in df.columns:
            df[feat] = 0.0

    # Preprocess
    X = df[FEATURES].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(X.median(numeric_only=True), inplace=True)

    X_scaled = scaler.transform(X.values.astype(np.float32))
    X_recon  = model.predict(X_scaled)
    errors   = np.mean((X_scaled - X_recon) ** 2, axis=1)

    df["Reconstruction_Error"] = errors
    stage1_flags          = set(np.where(errors > THRESHOLD)[0].tolist())
    flood_flags, scan_flags = aggregate_detect(df)
    bot_flags             = detect_bots(df)
    stage2_flags          = flood_flags | scan_flags
    combined              = stage1_flags | stage2_flags | bot_flags

    # Build per-index context so classify_attack_type knows WHY a flow was flagged.
    # Priority: flood > bot > scan.
    # Flood wins over bot because a high-rate aggregate burst is stronger evidence
    # than the periodic-pattern heuristic; a slow DDoS below the flood threshold
    # can legitimately be re-tagged as Bot if the bot detector fires.
    context_map: dict[int, str] = {}
    for idx in scan_flags:  context_map[idx] = "scan"
    for idx in bot_flags:   context_map[idx] = "bot"     # bot wins over scan
    for idx in flood_flags: context_map[idx] = "flood"   # flood wins over everything

    df["Stage1"] = df.index.isin(stage1_flags)
    df["Stage2"] = df.index.isin(stage2_flags | bot_flags)
    df["ATTACK"] = df.index.isin(combined)
    df["Label"]  = df["ATTACK"].map({True: "ATTACK", False: "BENIGN"})
    df["attack_type"] = df.apply(
        lambda r: classify_attack_type(r, context=context_map.get(r.name))
                  if r["ATTACK"] else "BENIGN",
        axis=1,
    )

    # Stage-1-only Unknown flows are background-protocol false positives.
    # ARP, NTP, mDNS etc. can trigger the autoencoder (unusual vs training data)
    # but none of the per-flow rules match them.  Without a Stage-2 or bot
    # confirmation there is no reliable evidence of an actual attack.
    stage1_only_unknown = (
        (df["attack_type"] == "Unknown") &
        df["Stage1"] &
        ~df["Stage2"]
    )
    df.loc[stage1_only_unknown, "attack_type"] = "BENIGN"
    df.loc[stage1_only_unknown, "ATTACK"]      = False

    # Write to DB
    con = open_db(db_path)
    cycle_id = create_cycle(con, pcap_file, flows_csv)

    def _safe(val, cast=None):
        # pd.isna handles None, float NaN, numpy NaN, and pd.NaT uniformly.
        try:
            if pd.isna(val):
                return None
        except (TypeError, ValueError):
            pass
        if cast is None:
            return val
        try:
            return cast(val)
        except (ValueError, TypeError):
            return None

    rows = []
    for _, r in df.iterrows():
        rows.append((
            cycle_id,
            _safe(r.get("Timestamp")),
            _safe(r.get("Source IP")),
            _safe(r.get("Destination IP")),
            _safe(r.get("Destination Port"), int),
            _safe(r.get("Protocol")),
            _safe(r.get("Flow Duration"),        float),
            _safe(r.get("Flow Packets/s"),        float),
            _safe(r.get("Flow Bytes/s"),          float),
            _safe(r.get("Total Fwd Packets"),     float),
            _safe(r.get("Total Backward Packets"),float),
            _safe(r.get("Packet Length Mean"),    float),
            _safe(r.get("Flow IAT Mean"),         float),
            float(r["Reconstruction_Error"]),
            int(r["ATTACK"]),
            int(r["Stage1"]),
            int(r["Stage2"]),
            r["attack_type"],
        ))

    insert_flows(con, rows)
    upsert_alerts(con, cycle_id, df)

    total   = len(df)
    attacks = int(df["ATTACK"].sum())
    benign  = total - attacks
    close_cycle(con, cycle_id, total, attacks, benign)
    con.close()

    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"cycle={cycle_id}  flows={total}  attacks={attacks}  "
        f"benign={benign}  thr={THRESHOLD:.4f}",
        flush=True,
    )
    return cycle_id


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--flows",    required=True)
    p.add_argument("--models",   default=os.path.expanduser("~/ids/models"))
    p.add_argument("--db",       default=os.path.expanduser("~/ids/ids.db"))
    p.add_argument("--pcap",     default="")
    args = p.parse_args()
    run(args.flows, args.models, args.db, args.pcap)
