<?php
/**
 * Password change
 * All authenticated users can change their own password.
 * Admin can force-reset another user's password.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$auth = require_role(ROLE_ADMIN, ROLE_ANALYST, ROLE_USER);
verify_csrf($auth);

$data        = json_decode(file_get_contents('php://input'), true) ?? [];
$action      = $data['action'] ?? 'change';
$new_pw      = $data['new_password']     ?? '';
$confirm_pw  = $data['confirm_password'] ?? '';

// ── Self password change ──────────────────────────────────────────────────
if ($action === 'change') {
    $current_pw = $data['current_password'] ?? '';

    if (!$current_pw || !$new_pw || !$confirm_pw) {
        echo json_encode(['error' => 'All password fields are required']); exit;
    }

    // Verify current password
    $row = qdb("SELECT id, username, password_hash FROM users WHERE id=?", [$auth['user_id']]);
    if (!$row) { echo json_encode(['error' => 'User not found']); exit; }

    $hash = str_replace('$2b$', '$2y$', $row[0]['password_hash']);
    if (!password_verify($current_pw, $hash)) {
        audit_log($auth['username'], $auth['role'], 'PW_CHANGE_FAIL', 'users',
            $auth['user_id'], '', 'wrong current password');
        echo json_encode(['error' => 'Current password is incorrect']); exit;
    }

    if ($new_pw !== $confirm_pw) {
        echo json_encode(['error' => 'New passwords do not match']); exit;
    }

    $pw_errors = validate_password($new_pw, $auth['username'], $auth['user_id']);
    if ($pw_errors) {
        echo json_encode(['error' => implode(' ', $pw_errors)]); exit;
    }

    $new_hash = password_hash($new_pw, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
    wdb("UPDATE users SET password_hash=?, must_change_pw=0 WHERE id=?",
        [$new_hash, $auth['user_id']]);
    save_password_history($auth['user_id'], $new_hash);

    // Invalidate all other sessions so stolen session tokens don't persist
    wdb("DELETE FROM sessions WHERE username=? AND token != ?",
        [$auth['username'], $auth['token']]);

    audit_log($auth['username'], $auth['role'], 'PASSWORD_CHANGED', 'users',
        $auth['user_id'], '', '', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => 'Password changed successfully.']);
    exit;
}

// ── Admin force-reset another user's password ─────────────────────────────
if ($action === 'admin_reset') {
    if ($auth['role'] !== ROLE_ADMIN) {
        json_error(403, 'Admin access required');
    }

    $target_id = (int)($data['user_id'] ?? 0);
    if (!$target_id) { echo json_encode(['error' => 'User ID required']); exit; }

    if ($new_pw !== $confirm_pw) {
        echo json_encode(['error' => 'Passwords do not match']); exit;
    }

    $target = qdb("SELECT id, username FROM users WHERE id=?", [$target_id]);
    if (!$target) { echo json_encode(['error' => 'User not found']); exit; }

    $pw_errors = validate_password($new_pw, $target[0]['username'], $target_id);
    if ($pw_errors) {
        echo json_encode(['error' => implode(' ', $pw_errors)]); exit;
    }

    $new_hash = password_hash($new_pw, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
    wdb("UPDATE users SET password_hash=?, must_change_pw=1, failed_attempts=0, locked_until=NULL WHERE id=?",
        [$new_hash, $target_id]);
    save_password_history($target_id, $new_hash);

    // Invalidate target's sessions
    wdb("DELETE FROM sessions WHERE username=?", [$target[0]['username']]);

    audit_log($auth['username'], $auth['role'], 'PASSWORD_RESET', 'users',
        $target_id, '', "reset_by={$auth['username']}", $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => "Password reset for {$target[0]['username']}. They must log in again."]);
    exit;
}

echo json_encode(['error' => 'Unknown action']);
