<?php
/**
 * Login / Logout endpoint
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$data   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $data['action'] ?? 'login';
$ip     = get_client_ip();
$ua     = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 512);

// ── LOGOUT ────────────────────────────────────────────────────────────────
if ($action === 'logout') {
    $token = $_COOKIE['ids_token'] ?? $data['token'] ?? '';
    if ($token) {
        $rows = qdb("SELECT username FROM sessions WHERE token=?", [$token]);
        $who  = $rows[0]['username'] ?? 'unknown';
        wdb("DELETE FROM sessions WHERE token=?", [$token]);
        // Get role for audit
        $ur = qdb("SELECT role FROM users WHERE username=?", [$who]);
        audit_log($who, $ur[0]['role'] ?? '', 'LOGOUT', 'sessions', 0, '', '', 0);
    }
    setcookie('ids_token', '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => HTTPS_ENABLED,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    echo json_encode(['ok' => true]);
    exit;
}

// ── REGISTER (public self-registration is permanently disabled) ───────────
if ($action === 'register') {
    http_response_code(403);
    echo json_encode(['error' => 'Account registration is not available. Contact an administrator.']);
    exit;
}

// ── LOGIN ─────────────────────────────────────────────────────────────────
// Rate limit login endpoint
if (!check_rate_limit("login_ip:$ip", RATE_LIMIT_LOGIN)) {
    audit_log('', '', 'LOGIN_RATE_LIMIT', 'login_attempts', 0, $ip, '429');
    rate_limit_response();
}

$username = sanitize_string(trim($data['username'] ?? ''), 80);
$password = $data['password'] ?? '';

if (!$username || !$password) {
    echo json_encode(['error' => 'Username and password required']);
    exit;
}

// Detect injection in username field
if (detect_injection($username)) {
    audit_log($username, '', 'LOGIN_INJECTION_ATTEMPT', 'login_attempts', 0, $ip, '');
    echo json_encode(['error' => 'Invalid credentials']);
    exit;
}

// Fetch user
$rows = qdb(
    "SELECT id, password_hash, role, failed_attempts, locked_until, totp_enabled
     FROM users WHERE username=?",
    [$username]
);

// Log attempt regardless of whether user exists (timing-safe behaviour)
$log_success = 0;
$now         = date('Y-m-d H:i:s');

if (!$rows) {
    wdb("INSERT INTO login_attempts (username, ip_address, user_agent, attempted_at, success) VALUES (?,?,?,?,0)",
        [$username, $ip, $ua, $now]);
    // Same response as wrong password to prevent user enumeration
    echo json_encode(['error' => 'Invalid credentials']);
    exit;
}

$user = $rows[0];

// Check if account is locked
if ($user['locked_until']) {
    $lock_time = strtotime($user['locked_until']);
    if (time() < $lock_time) {
        $mins_left = (int)ceil(($lock_time - time()) / 60);
        wdb("INSERT INTO login_attempts (username, ip_address, user_agent, attempted_at, success) VALUES (?,?,?,?,0)",
            [$username, $ip, $ua, $now]);
        echo json_encode(['error' => "Account locked. Try again in $mins_left minute(s)."]);
        exit;
    } else {
        // Lockout expired — reset
        wdb("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", [$username]);
    }
}

// Verify password
$hash = str_replace('$2b$', '$2y$', $user['password_hash']);
if (!password_verify($password, $hash)) {
    $attempts = (int)$user['failed_attempts'] + 1;
    if ($attempts >= MAX_LOGIN_ATTEMPTS) {
        $locked_until = date('Y-m-d H:i:s', time() + LOCKOUT_MINUTES * 60);
        wdb("UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
            [$attempts, $locked_until, $username]);
        send_lockout_email($username, $ip);
        audit_log($username, $user['role'], 'ACCOUNT_LOCKED', 'users', (int)$user['id'],
            '', "locked_until=$locked_until");
        wdb("INSERT INTO login_attempts (username, ip_address, user_agent, attempted_at, success) VALUES (?,?,?,?,0)",
            [$username, $ip, $ua, $now]);
        echo json_encode(['error' => "Account locked after too many failed attempts. Try again in " . LOCKOUT_MINUTES . " minutes."]);
    } else {
        wdb("UPDATE users SET failed_attempts=? WHERE username=?", [$attempts, $username]);
        $remaining = MAX_LOGIN_ATTEMPTS - $attempts;
        wdb("INSERT INTO login_attempts (username, ip_address, user_agent, attempted_at, success) VALUES (?,?,?,?,0)",
            [$username, $ip, $ua, $now]);
        echo json_encode(['error' => "Invalid credentials. $remaining attempt(s) remaining before lockout."]);
    }
    exit;
}

// Successful login — reset lockout counters
wdb("UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? WHERE username=?",
    [$now, $username]);

wdb("INSERT INTO login_attempts (username, ip_address, user_agent, attempted_at, success) VALUES (?,?,?,?,1)",
    [$username, $ip, $ua, $now]);

// Create new session (regenerates token on each login)
[$token, $csrf_token] = create_session($username);

set_session_cookie($token);

audit_log($username, $user['role'], 'LOGIN_SUCCESS', 'sessions', 0, '', '', (int)$user['id']);

echo json_encode([
    'ok'         => true,
    'token'      => $token,
    'csrf_token' => $csrf_token,
    'username'   => $username,
    'role'       => $user['role'],
]);
