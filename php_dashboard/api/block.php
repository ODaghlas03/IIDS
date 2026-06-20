<?php
/**
 * Block / Unblock IP
 * Admin: executes directly. Analyst: submits pending_action for approval. User: 403.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

// Admins and analysts may access this endpoint; users may not
$auth = require_role(ROLE_ADMIN, ROLE_ANALYST);
verify_csrf($auth);

$data   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $data['action'] ?? '';
$ip     = sanitize_string(trim($data['ip'] ?? ''), 45);

if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['error' => 'Invalid IP address']);
    exit;
}

if (detect_injection($ip)) {
    audit_log($auth['username'], $auth['role'], 'INJECTION_ATTEMPT', 'block', 0, $ip, '');
    echo json_encode(['error' => 'Invalid input']);
    exit;
}

// ── ANALYST: submit pending action ────────────────────────────────────────
if ($auth['role'] === ROLE_ANALYST) {
    $reason = sanitize_string($data['reason'] ?? 'Analyst request', 500);
    if (detect_injection($reason)) {
        echo json_encode(['error' => 'Invalid input in reason field']); exit;
    }

    wdb(
        "INSERT INTO pending_actions
            (requested_by, analyst_username, action_type, action_data, description, status, requested_at)
         VALUES (?,?,?,?,?,?,?)",
        [
            $auth['user_id'],
            $auth['username'],
            $action,
            json_encode(['ip' => $ip, 'reason' => $reason]),
            ucfirst($action) . " IP $ip — $reason",
            'pending',
            date('Y-m-d H:i:s'),
        ]
    );
    $pa_id = wdb_id();
    audit_log($auth['username'], $auth['role'], 'PENDING_ACTION_CREATED', 'pending_actions',
        $pa_id, '', "$action:$ip", $auth['user_id']);
    echo json_encode([
        'ok'      => true,
        'pending' => true,
        'message' => "Action submitted for admin approval (Request #$pa_id).",
    ]);
    exit;
}

// ── ADMIN: execute directly ───────────────────────────────────────────────
if ($action === 'block') {
    $reason = sanitize_string($data['reason'] ?? 'Manually blocked', 500);

    $existing = qdb("SELECT id FROM blocked_ips WHERE ip=? AND active=1", [$ip]);
    if ($existing) {
        echo json_encode(['error' => "IP $ip is already blocked"]); exit;
    }

    exec("sudo /sbin/iptables -A FORWARD -s " . escapeshellarg($ip) . " -j DROP 2>&1");
    exec("sudo /sbin/iptables -A INPUT -s "   . escapeshellarg($ip) . " -j DROP 2>&1");

    $now = date('Y-m-d H:i:s');
    $exists_any = qdb("SELECT id FROM blocked_ips WHERE ip=?", [$ip]);
    if ($exists_any) {
        wdb("UPDATE blocked_ips SET active=1, reason=?, blocked_by=?, blocked_at=? WHERE ip=?",
            [$reason, $auth['username'], $now, $ip]);
    } else {
        wdb("INSERT INTO blocked_ips (ip, reason, blocked_by, blocked_at, active) VALUES (?,?,?,?,1)",
            [$ip, $reason, $auth['username'], $now]);
    }

    audit_log($auth['username'], $auth['role'], 'IP_BLOCKED', 'blocked_ips', 0,
        '', $ip, $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => "IP $ip has been blocked"]);
    exit;
}

if ($action === 'unblock') {
    exec("sudo /sbin/iptables -D FORWARD -s " . escapeshellarg($ip) . " -j DROP 2>&1");
    exec("sudo /sbin/iptables -D INPUT -s "   . escapeshellarg($ip) . " -j DROP 2>&1");

    wdb("UPDATE blocked_ips SET active=0 WHERE ip=?", [$ip]);

    audit_log($auth['username'], $auth['role'], 'IP_UNBLOCKED', 'blocked_ips', 0,
        $ip, '', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => "IP $ip has been unblocked"]);
    exit;
}

echo json_encode(['error' => 'Unknown action. Use block or unblock.']);
