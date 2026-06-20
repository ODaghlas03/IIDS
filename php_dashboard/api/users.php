<?php
/**
 * User management — admin-only
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

// admin-only
$auth = require_role(ROLE_ADMIN);
verify_csrf($auth);

$data   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $data['action'] ?? 'list';

// ── LIST ──────────────────────────────────────────────────────────────────
if ($action === 'list') {
    $users = qdb(
        "SELECT id, username, email, role, created_at, last_login,
                totp_enabled, locked_until, failed_attempts
         FROM users ORDER BY id"
    );
    // Never expose password_hash in list
    echo json_encode(['ok' => true, 'users' => $users]);
    exit;
}

// ── CREATE ────────────────────────────────────────────────────────────────
if ($action === 'create') {
    $u     = sanitize_string(trim($data['username'] ?? ''), 80);
    $email = sanitize_string(trim($data['email']    ?? ''), 200);
    $p     = $data['password']  ?? '';
    $p2    = $data['password2'] ?? '';
    $role  = $data['role'] ?? 'user';

    // Validate username
    if (strlen($u) < 3) {
        echo json_encode(['error' => 'Username must be at least 3 characters']); exit;
    }
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $u)) {
        echo json_encode(['error' => 'Username may only contain letters, numbers, and underscores']); exit;
    }
    if (detect_injection($u) || detect_injection($email)) {
        echo json_encode(['error' => 'Invalid input detected']); exit;
    }

    // Validate role
    $allowed_roles = [ROLE_ADMIN, ROLE_ANALYST, ROLE_USER];
    if (!in_array($role, $allowed_roles, true)) {
        echo json_encode(['error' => 'Invalid role. Must be: admin, analyst, or user']); exit;
    }

    // Validate passwords match
    if ($p !== $p2) {
        echo json_encode(['error' => 'Passwords do not match']); exit;
    }

    // Enforce password policy
    $pw_errors = validate_password($p, $u);
    if ($pw_errors) {
        echo json_encode(['error' => implode(' ', $pw_errors)]); exit;
    }

    if (qdb("SELECT id FROM users WHERE username=?", [$u])) {
        echo json_encode(['error' => "Username '$u' is already taken"]); exit;
    }

    // Hash with bcrypt
    $hash = password_hash($p, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
    wdb(
        "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
        [$u, $email, $hash, $role, date('Y-m-d H:i:s')]
    );
    $new_id = wdb_id();

    // Seed password history
    save_password_history($new_id, $hash);

    // Audit log
    audit_log($auth['username'], $auth['role'], 'USER_CREATED', 'users', $new_id,
        '', "username=$u,role=$role", $auth['user_id']);

    echo json_encode(['ok' => true, 'message' => "User '$u' created with role '$role'"]);
    exit;
}

// ── CHANGE ROLE ───────────────────────────────────────────────────────────
if ($action === 'change_role') {
    $uid  = (int)($data['id'] ?? 0);
    $role = $data['role'] ?? '';

    $allowed_roles = [ROLE_ADMIN, ROLE_ANALYST, ROLE_USER];
    if (!$uid || !in_array($role, $allowed_roles, true)) {
        echo json_encode(['error' => 'Invalid user ID or role']); exit;
    }

    $target = qdb("SELECT username, role FROM users WHERE id=?", [$uid]);
    if (!$target) { echo json_encode(['error' => 'User not found']); exit; }
    if ($target[0]['username'] === $auth['username']) {
        echo json_encode(['error' => 'Cannot change your own role']); exit;
    }

    $old_role = $target[0]['role'];
    wdb("UPDATE users SET role=? WHERE id=?", [$role, $uid]);

    audit_log($auth['username'], $auth['role'], 'ROLE_CHANGED', 'users', $uid,
        "role=$old_role", "role=$role", $auth['user_id']);

    echo json_encode(['ok' => true, 'message' => "Role changed to '$role'"]);
    exit;
}

// ── TOGGLE 2FA ─────────────────────────────────────────────────────────────
if ($action === 'disable_totp') {
    $uid = (int)($data['id'] ?? 0);
    if (!$uid) { echo json_encode(['error' => 'Invalid user ID']); exit; }
    wdb("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", [$uid]);
    $target = qdb("SELECT username FROM users WHERE id=?", [$uid]);
    audit_log($auth['username'], $auth['role'], '2FA_DISABLED', 'users', $uid,
        '', '', $auth['user_id']);
    echo json_encode(['ok' => true]);
    exit;
}

// ── UNLOCK ─────────────────────────────────────────────────────────────────
if ($action === 'unlock') {
    $uid = (int)($data['id'] ?? 0);
    if (!$uid) { echo json_encode(['error' => 'Invalid user ID']); exit; }
    wdb("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", [$uid]);
    $target = qdb("SELECT username FROM users WHERE id=?", [$uid]);
    audit_log($auth['username'], $auth['role'], 'ACCOUNT_UNLOCKED', 'users', $uid,
        '', '', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => 'Account unlocked']);
    exit;
}

// ── DELETE ────────────────────────────────────────────────────────────────
if ($action === 'delete') {
    $uid = (int)($data['id'] ?? 0);
    if (!$uid) {
        echo json_encode(['error' => 'Invalid user ID']); exit;
    }
    $target = qdb("SELECT username, role FROM users WHERE id=?", [$uid]);
    if (!$target) {
        echo json_encode(['error' => 'User not found']); exit;
    }
    if ($target[0]['username'] === $auth['username']) {
        echo json_encode(['error' => 'Cannot delete your own account']); exit;
    }

    wdb("DELETE FROM sessions       WHERE username=?", [$target[0]['username']]);
    wdb("DELETE FROM password_history WHERE user_id=?", [$uid]);
    wdb("DELETE FROM users           WHERE id=?",       [$uid]);

    audit_log($auth['username'], $auth['role'], 'USER_DELETED', 'users', $uid,
        "username={$target[0]['username']},role={$target[0]['role']}", '', $auth['user_id']);

    echo json_encode(['ok' => true]);
    exit;
}

// ── SET IP ALLOWLIST ──────────────────────────────────────────────────────
if ($action === 'set_ip_allowlist') {
    $uid        = (int)($data['id'] ?? 0);
    $ip_list    = sanitize_string($data['ip_allowlist'] ?? '', 500);
    if (!$uid) { echo json_encode(['error' => 'Invalid user ID']); exit; }
    wdb("UPDATE users SET ip_allowlist=? WHERE id=?", [$ip_list, $uid]);
    audit_log($auth['username'], $auth['role'], 'IP_ALLOWLIST_SET', 'users', $uid,
        '', $ip_list, $auth['user_id']);
    echo json_encode(['ok' => true]);
    exit;
}

echo json_encode(['error' => 'Unknown action']);
