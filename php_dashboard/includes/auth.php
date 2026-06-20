<?php
/**
 * Authentication helpers
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

function validate_session(string $token): ?string {
    if (!$token) return null;
    $rows = qdb(
        "SELECT username, last_active FROM sessions WHERE token=?",
        [$token]
    );
    if (!$rows) return null;
    $elapsed = time() - strtotime($rows[0]['last_active']);
    if ($elapsed > SESSION_TIMEOUT) {
        wdb("DELETE FROM sessions WHERE token=?", [$token]);
        return null;
    }
    wdb("UPDATE sessions SET last_active=? WHERE token=?",
        [date('Y-m-d H:i:s'), $token]);
    return $rows[0]['username'];
}

/**
 * Lightweight auth check for endpoints that don't need RBAC.
 * For role-sensitive endpoints use require_role() from rbac.php instead.
 */
function require_auth(): string {
    $token = $_COOKIE['ids_token'] ?? $_SERVER['HTTP_X_IDS_TOKEN'] ?? '';
    if (!$token) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Not authenticated']);
        exit;
    }
    $user = validate_session($token);
    if (!$user) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Session expired']);
        exit;
    }
    return $user;
}

/**
 * Create a new session. Returns [token, csrf_token].
 * Regenerates session ID on every login to prevent session fixation.
 */
function create_session(string $username): array {
    // Invalidate all previous sessions for this user (single-session policy)
    wdb("DELETE FROM sessions WHERE username=?", [$username]);

    $token      = bin2hex(random_bytes(32));
    $csrf_token = bin2hex(random_bytes(32));
    $now        = date('Y-m-d H:i:s');
    $ip         = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua         = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 512);

    wdb(
        "INSERT INTO sessions (token, username, created_at, last_active, csrf_token, ip_address, user_agent)
         VALUES (?,?,?,?,?,?,?)",
        [$token, $username, $now, $now, $csrf_token, $ip, $ua]
    );
    return [$token, $csrf_token];
}

/**
 * Set the session cookie with all security flags.
 * HttpOnly, SameSite=Strict; Secure when HTTPS is enabled.
 */
function set_session_cookie(string $token): void {
    $expires = time() + SESSION_TIMEOUT;
    setcookie('ids_token', $token, [
        'expires'  => $expires,
        'path'     => '/',
        'secure'   => HTTPS_ENABLED,
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function json_response(mixed $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json');
    header('Cache-Control: no-cache');
    echo json_encode($data);
    exit;
}
