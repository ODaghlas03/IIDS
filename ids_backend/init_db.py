#!/usr/bin/env python3
"""
init_db.py — Initialize the IDS SQLite database.
Run once: python3 ~/ids/init_db.py
Creates all tables and a default admin user (admin / changeme123).
"""
import sqlite3, bcrypt, os, sys
from pathlib import Path

DB = Path(os.getenv("IDS_DB", "~/ids/ids.db")).expanduser()
DB.parent.mkdir(parents=True, exist_ok=True)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    DEFAULT 'analyst',
    created_at    TEXT    DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS cycles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    total_flows INTEGER DEFAULT 0,
    attacks     INTEGER DEFAULT 0,
    benign      INTEGER DEFAULT 0,
    pcap_file   TEXT,
    flows_file  TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id             INTEGER REFERENCES cycles(id),
    flow_timestamp       TEXT,
    source_ip            TEXT,
    dest_ip              TEXT,
    dest_port            INTEGER,
    protocol             TEXT,
    flow_duration        REAL,
    flow_packets_s       REAL,
    flow_bytes_s         REAL,
    total_fwd_packets    REAL,
    total_bwd_packets    REAL,
    packet_length_mean   REAL,
    flow_iat_mean        REAL,
    reconstruction_error REAL,
    attack               INTEGER DEFAULT 0,
    stage1               INTEGER DEFAULT 0,
    stage2               INTEGER DEFAULT 0,
    attack_type          TEXT    DEFAULT 'BENIGN',
    analyst_verdict      TEXT    DEFAULT 'Unreviewed',
    analyst_note         TEXT,
    triage_score         INTEGER,
    created_at           TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id         INTEGER REFERENCES cycles(id),
    source_ip        TEXT NOT NULL,
    attack_type      TEXT,
    severity         TEXT DEFAULT 'medium',
    flow_count       INTEGER DEFAULT 1,
    max_error        REAL,
    acknowledged     INTEGER DEFAULT 0,
    acknowledged_by  TEXT,
    acknowledged_at  TEXT,
    created_at       TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT UNIQUE NOT NULL,
    reason     TEXT,
    blocked_by TEXT,
    blocked_at TEXT DEFAULT (datetime('now')),
    active     INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS chat_sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    role       TEXT NOT NULL,
    content    TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS nl_queries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT,
    natural_query TEXT NOT NULL,
    generated_sql TEXT,
    result_count  INTEGER,
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_flows_attack     ON flows(attack);
CREATE INDEX IF NOT EXISTS idx_flows_source_ip  ON flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_flows_cycle      ON flows(cycle_id);
CREATE INDEX IF NOT EXISTS idx_flows_created    ON flows(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_ack       ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_blocked_active   ON blocked_ips(active);
"""

def init(default_password: str = "changeme123"):
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)

    # Insert default admin only if no users exist
    cur = con.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        pw_hash = bcrypt.hashpw(default_password.encode(), bcrypt.gensalt()).decode()
        con.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", pw_hash, "admin"),
        )
        print(f"[init_db] Created default user: admin / {default_password}")
        print("[init_db] IMPORTANT: change this password after first login.")
    else:
        print("[init_db] Users table already populated — skipping default user.")

    con.commit()
    con.close()
    print(f"[init_db] Database ready at {DB}")

if __name__ == "__main__":
    pw = sys.argv[1] if len(sys.argv) > 1 else "changeme123"
    init(pw)
