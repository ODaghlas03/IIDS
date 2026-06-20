<?php
/**
 * Security Events — admin dashboard widget
 * Shows recent failed logins, locked accounts, pending approvals, and role changes.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$auth = require_role(ROLE_ADMIN);

$since = date('Y-m-d H:i:s', strtotime('-24 hours'));

// Recent failed logins
$failed_logins = qdb(
    "SELECT username, ip_address, user_agent, attempted_at
     FROM login_attempts
     WHERE success=0 AND attempted_at >= ?
     ORDER BY attempted_at DESC LIMIT 20",
    [$since]
);

// Currently locked accounts
$locked_accounts = qdb(
    "SELECT username, locked_until, failed_attempts
     FROM users
     WHERE locked_until IS NOT NULL AND locked_until > ?",
    [date('Y-m-d H:i:s')]
);

// Pending analyst actions
$pending_count = qdb("SELECT COUNT(*) n FROM pending_actions WHERE status='pending'");

// Recent role changes from audit log
$role_changes = qdb(
    "SELECT username, action, old_value, new_value, ip_address, timestamp
     FROM audit_logs
     WHERE action IN ('ROLE_CHANGED','USER_CREATED','USER_DELETED','ACCOUNT_LOCKED','2FA_ENABLED','2FA_DISABLED')
     AND timestamp >= ?
     ORDER BY timestamp DESC LIMIT 20",
    [$since]
);

// Active sessions count
$active_sessions = qdb(
    "SELECT COUNT(*) n FROM sessions WHERE last_active >= ?",
    [date('Y-m-d H:i:s', time() - SESSION_TIMEOUT)]
);

echo json_encode([
    'ok'             => true,
    'failed_logins'  => $failed_logins,
    'locked_accounts'=> $locked_accounts,
    'pending_actions'=> (int)($pending_count[0]['n'] ?? 0),
    'role_changes'   => $role_changes,
    'active_sessions'=> (int)($active_sessions[0]['n'] ?? 0),
]);
