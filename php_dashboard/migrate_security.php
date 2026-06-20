<?php
/**
 * Security DB Migration — run ONCE to add all new security tables/columns.
 * Run from CLI: php migrate_security.php
 * Or web (one-time): http://192.168.56.101:8080/migrate_security.php
 * This file DELETES ITSELF after successful migration.
 */

define('DB_PATH', '/home/ids/ids/ids.db');

function col_exists(SQLite3 $db, string $table, string $col): bool {
    $res = $db->query("PRAGMA table_info(" . $db->escapeString($table) . ")");
    while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
        if ($row['name'] === $col) return true;
    }
    return false;
}

function table_exists(SQLite3 $db, string $table): bool {
    $res = $db->querySingle(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='" .
        $db->escapeString($table) . "'"
    );
    return (int)$res > 0;
}

try {
    $db = new SQLite3(DB_PATH, SQLITE3_OPEN_READWRITE);
    $db->busyTimeout(5000);
} catch (Exception $e) {
    die("Cannot open DB: " . $e->getMessage() . "\n");
}

$steps = [];

// ── 1. Extend users table ──────────────────────────────────────────────────
$user_cols = [
    'email'           => "TEXT DEFAULT ''",
    'failed_attempts' => 'INTEGER DEFAULT 0',
    'locked_until'    => 'TEXT',
    'totp_secret'     => 'TEXT',
    'totp_enabled'    => 'INTEGER DEFAULT 0',
    'ip_allowlist'    => 'TEXT',
    'must_change_pw'  => 'INTEGER DEFAULT 0',
];
foreach ($user_cols as $col => $def) {
    if (!col_exists($db, 'users', $col)) {
        $db->exec("ALTER TABLE users ADD COLUMN $col $def");
        $steps[] = "users.$col added";
    }
}

// ── 2. Extend sessions table ───────────────────────────────────────────────
$sess_cols = [
    'csrf_token'  => "TEXT DEFAULT ''",
    'ip_address'  => "TEXT DEFAULT ''",
    'user_agent'  => "TEXT DEFAULT ''",
];
foreach ($sess_cols as $col => $def) {
    if (!col_exists($db, 'sessions', $col)) {
        $db->exec("ALTER TABLE sessions ADD COLUMN $col $def");
        $steps[] = "sessions.$col added";
    }
}

// ── 3. login_attempts table ────────────────────────────────────────────────
if (!table_exists($db, 'login_attempts')) {
    $db->exec("CREATE TABLE login_attempts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT NOT NULL DEFAULT '',
        ip_address  TEXT NOT NULL DEFAULT '',
        user_agent  TEXT DEFAULT '',
        attempted_at TEXT NOT NULL,
        success     INTEGER DEFAULT 0
    )");
    $db->exec("CREATE INDEX idx_la_username ON login_attempts(username)");
    $db->exec("CREATE INDEX idx_la_ip ON login_attempts(ip_address)");
    $steps[] = "login_attempts table created";
}

// ── 4. password_history table ──────────────────────────────────────────────
if (!table_exists($db, 'password_history')) {
    $db->exec("CREATE TABLE password_history (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id       INTEGER NOT NULL,
        password_hash TEXT NOT NULL,
        created_at    TEXT NOT NULL
    )");
    $db->exec("CREATE INDEX idx_ph_user ON password_history(user_id)");
    $steps[] = "password_history table created";
}

// ── 5. audit_logs table ────────────────────────────────────────────────────
if (!table_exists($db, 'audit_logs')) {
    $db->exec("CREATE TABLE audit_logs (
        log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id      INTEGER,
        username     TEXT NOT NULL DEFAULT '',
        role         TEXT NOT NULL DEFAULT '',
        action       TEXT NOT NULL,
        target_table TEXT DEFAULT '',
        target_id    INTEGER,
        old_value    TEXT DEFAULT '',
        new_value    TEXT DEFAULT '',
        ip_address   TEXT DEFAULT '',
        user_agent   TEXT DEFAULT '',
        timestamp    TEXT NOT NULL
    )");
    $db->exec("CREATE INDEX idx_al_user ON audit_logs(username)");
    $db->exec("CREATE INDEX idx_al_time ON audit_logs(timestamp)");
    $steps[] = "audit_logs table created";
}

// ── 6. rate_limits table ───────────────────────────────────────────────────
if (!table_exists($db, 'rate_limits')) {
    $db->exec("CREATE TABLE rate_limits (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        key_value    TEXT NOT NULL,
        hit_count    INTEGER DEFAULT 1,
        window_start TEXT NOT NULL
    )");
    $db->exec("CREATE UNIQUE INDEX idx_rl_key ON rate_limits(key_value)");
    $steps[] = "rate_limits table created";
}

// ── 7. pending_actions table ───────────────────────────────────────────────
if (!table_exists($db, 'pending_actions')) {
    $db->exec("CREATE TABLE pending_actions (
        action_id        INTEGER PRIMARY KEY AUTOINCREMENT,
        requested_by     INTEGER NOT NULL,
        analyst_username TEXT NOT NULL,
        action_type      TEXT NOT NULL,
        action_data      TEXT NOT NULL DEFAULT '{}',
        description      TEXT NOT NULL DEFAULT '',
        status           TEXT NOT NULL DEFAULT 'pending',
        requested_at     TEXT NOT NULL,
        reviewed_by      TEXT DEFAULT '',
        reviewed_at      TEXT DEFAULT '',
        rejection_reason TEXT DEFAULT '',
        notification_sent INTEGER DEFAULT 0
    )");
    $db->exec("CREATE INDEX idx_pa_status ON pending_actions(status)");
    $db->exec("CREATE INDEX idx_pa_user ON pending_actions(analyst_username)");
    $steps[] = "pending_actions table created";
}

// ── 8. ip_allowlist table ──────────────────────────────────────────────────
if (!table_exists($db, 'ip_allowlist')) {
    $db->exec("CREATE TABLE ip_allowlist (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_cidr     TEXT NOT NULL,
        description TEXT DEFAULT '',
        created_by  TEXT DEFAULT '',
        created_at  TEXT NOT NULL,
        active      INTEGER DEFAULT 1
    )");
    $steps[] = "ip_allowlist table created";
}

// ── 9. Performance indexes ─────────────────────────────────────────────────
$indexes = [
    'CREATE INDEX IF NOT EXISTS idx_flows_attack     ON flows(attack)',
    'CREATE INDEX IF NOT EXISTS idx_flows_cycle      ON flows(cycle_id)',
    'CREATE INDEX IF NOT EXISTS idx_flows_source_ip  ON flows(source_ip)',
    'CREATE INDEX IF NOT EXISTS idx_flows_created_at ON flows(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_acked     ON alerts(acknowledged)',
    'CREATE INDEX IF NOT EXISTS idx_alerts_cycle     ON alerts(cycle_id)',
    'CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(username)',
    'CREATE INDEX IF NOT EXISTS idx_sessions_active  ON sessions(last_active)',
];
foreach ($indexes as $sql) {
    $db->exec($sql);
}
$steps[] = "Performance indexes created/verified";

// ── 10. Seed ENCRYPTION_KEY in .env if missing ────────────────────────────
$env_path = '/home/ids/ids/.env';
if (file_exists($env_path)) {
    $env_content = file_get_contents($env_path);
    if (!preg_match('/ENCRYPTION_KEY\s*=/', $env_content)) {
        $key = base64_encode(random_bytes(32));
        file_put_contents($env_path, "\nENCRYPTION_KEY=$key\n", FILE_APPEND);
        $steps[] = "ENCRYPTION_KEY added to .env";
    } else {
        $steps[] = "ENCRYPTION_KEY already in .env";
    }
} else {
    $steps[] = "WARNING: /home/ids/ids/.env not found — create it with ENCRYPTION_KEY=<base64-32-bytes>";
}

$db->close();

echo "=== IIDS Security Migration ===\n";
foreach ($steps as $i => $s) {
    echo sprintf("  [%2d] %s\n", $i + 1, $s);
}
echo "\nMigration complete. Deleting this script.\n";
@unlink(__FILE__);
