<?php
/**
 * RBAC middleware
 * Always re-fetches role from DB on each request to prevent stale session escalation.
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/security.php';

const ROLE_ADMIN   = 'admin';
const ROLE_ANALYST = 'analyst';
const ROLE_USER    = 'user';

/**
 * Require authentication AND one of the specified roles.
 * Returns ['username', 'role', 'user_id', 'csrf'].
 * Exits with 401 or 403 JSON if checks fail.
 */
function require_role(string ...$roles): array {
    // Authenticate first
    $token = $_COOKIE['ids_token'] ?? $_SERVER['HTTP_X_IDS_TOKEN'] ?? '';
    if (!$token) {
        json_error(401, 'Not authenticated');
    }

    $rows = qdb(
        "SELECT s.username, s.csrf_token, s.ip_address, s.user_agent,
                u.id AS user_id, u.role, u.locked_until, u.totp_enabled
         FROM sessions s
         JOIN users u ON u.username = s.username
         WHERE s.token = ?",
        [$token]
    );

    if (!$rows) {
        json_error(401, 'Session expired or invalid');
    }

    $sess = $rows[0];

    // Check session timeout
    $last_rows = qdb("SELECT last_active FROM sessions WHERE token=?", [$token]);
    if ($last_rows) {
        $elapsed = time() - strtotime($last_rows[0]['last_active']);
        if ($elapsed > SESSION_TIMEOUT) {
            wdb("DELETE FROM sessions WHERE token=?", [$token]);
            json_error(401, 'Session expired');
        }
        wdb("UPDATE sessions SET last_active=? WHERE token=?",
            [date('Y-m-d H:i:s'), $token]);
    }

    // Optional IP binding — warn but don't block (strict binding breaks NAT)
    // Uncomment to enforce strict IP binding:
    // $current_ip = get_client_ip();
    // if ($sess['ip_address'] && $sess['ip_address'] !== $current_ip) {
    //     wdb("DELETE FROM sessions WHERE token=?", [$token]);
    //     json_error(401, 'Session IP mismatch — please log in again');
    // }

    // Always re-fetch role from DB (prevents stale-session privilege escalation)
    $user_row = qdb("SELECT id, role, locked_until FROM users WHERE username=?", [$sess['username']]);
    if (!$user_row) {
        json_error(401, 'User not found');
    }
    $role = $user_row[0]['role'];

    // Check role authorisation
    if (!empty($roles) && !in_array($role, $roles, true)) {
        audit_log($sess['username'], $role, 'ACCESS_DENIED', '', 0,
            implode(',', $roles), '403');
        json_error(403, 'Forbidden — insufficient role');
    }

    return [
        'username' => $sess['username'],
        'role'     => $role,
        'user_id'  => (int)$user_row[0]['id'],
        'csrf'     => $sess['csrf_token'],
        'token'    => $token,
    ];
}

/**
 * Verify CSRF token for state-changing requests.
 * Call after require_role() on POST/PUT/DELETE endpoints.
 * Uses constant-time comparison to prevent timing attacks.
 */
function verify_csrf(array $auth_ctx): void {
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN']
         ?? (json_decode(file_get_contents('php://input'), true)['_csrf'] ?? '');
    if (!$sent || !hash_equals($auth_ctx['csrf'], $sent)) {
        audit_log($auth_ctx['username'], $auth_ctx['role'], 'CSRF_FAIL');
        json_error(403, 'Invalid CSRF token');
    }
}

function json_error(int $code, string $message): never {
    http_response_code($code);
    header('Content-Type: application/json');
    header('Cache-Control: no-cache');
    echo json_encode(['error' => $message]);
    exit;
}
