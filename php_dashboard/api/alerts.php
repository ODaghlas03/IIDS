<?php
/**
 * Alerts — all authenticated roles can view; only admin/analyst can ack/block
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$auth   = require_role(ROLE_ADMIN, ROLE_ANALYST, ROLE_USER);
$method = $_SERVER['REQUEST_METHOD'];

// ── GET: read-only for all roles ──────────────────────────────────────────
if ($method === 'GET') {
    // Paginated — limit 100, supports ?offset=
    $offset = max(0, (int)($_GET['offset'] ?? 0));
    $alerts = qdb(
        "SELECT a.id, a.cycle_id, a.source_ip, a.attack_type, a.severity,
                a.flow_count, a.max_error, a.acknowledged, a.acknowledged_by,
                a.acknowledged_at, a.created_at, c.pcap_file
         FROM alerts a
         LEFT JOIN cycles c ON c.id = a.cycle_id
         ORDER BY a.id DESC
         LIMIT 100 OFFSET ?",
        [$offset]
    );
    echo json_encode(['alerts' => $alerts]);
    exit;
}

// ── POST: state-changing — require non-user role + CSRF ───────────────────
verify_csrf($auth);
if ($auth['role'] === ROLE_USER) {
    json_error(403, 'Insufficient permissions');
}

$data   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $data['action'] ?? '';

if ($action === 'ack') {
    $id = (int)($data['id'] ?? 0);
    if (!$id) { echo json_encode(['error' => 'Alert ID required']); exit; }

    $now = date('Y-m-d H:i:s');
    wdb("UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=? WHERE id=?",
        [$auth['username'], $now, $id]);

    audit_log($auth['username'], $auth['role'], 'ALERT_ACK', 'alerts', $id,
        '', "ack_by={$auth['username']}", $auth['user_id']);
    echo json_encode(['ok' => true]);
    exit;
}

if ($action === 'block') {
    $ip       = sanitize_string(trim($data['ip'] ?? ''), 45);
    $alert_id = (int)($data['alert_id'] ?? 0);

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo json_encode(['error' => 'Invalid IP address']); exit;
    }

    // Delegate to block.php logic based on role
    if ($auth['role'] === ROLE_ANALYST) {
        wdb(
            "INSERT INTO pending_actions
                (requested_by, analyst_username, action_type, action_data, description, status, requested_at)
             VALUES (?,?,?,?,?,?,?)",
            [
                $auth['user_id'], $auth['username'], 'block',
                json_encode(['ip' => $ip, 'reason' => "Alert #$alert_id"]),
                "Block IP $ip (from Alert #$alert_id)",
                'pending', date('Y-m-d H:i:s'),
            ]
        );
        $pa_id = wdb_id();
        audit_log($auth['username'], $auth['role'], 'PENDING_ACTION_CREATED', 'pending_actions',
            $pa_id, '', "block:$ip", $auth['user_id']);
        echo json_encode(['ok' => true, 'pending' => true,
            'message' => "Block request submitted for admin approval."]);
        exit;
    }

    // Admin: execute directly
    $existing = qdb("SELECT id FROM blocked_ips WHERE ip=? AND active=1", [$ip]);
    if ($existing) {
        echo json_encode(['error' => "IP $ip is already blocked"]); exit;
    }
    exec("sudo /sbin/iptables -A FORWARD -s " . escapeshellarg($ip) . " -j DROP 2>&1");
    exec("sudo /sbin/iptables -A INPUT -s "   . escapeshellarg($ip) . " -j DROP 2>&1");

    $reason  = "Alert #$alert_id – blocked by {$auth['username']}";
    $now     = date('Y-m-d H:i:s');
    $exists_any = qdb("SELECT id FROM blocked_ips WHERE ip=?", [$ip]);
    if ($exists_any) {
        wdb("UPDATE blocked_ips SET active=1, reason=?, blocked_by=?, blocked_at=? WHERE ip=?",
            [$reason, $auth['username'], $now, $ip]);
    } else {
        wdb("INSERT INTO blocked_ips (ip, reason, blocked_by, blocked_at, active) VALUES (?,?,?,?,1)",
            [$ip, $reason, $auth['username'], $now]);
    }

    if ($alert_id) {
        wdb("UPDATE alerts SET acknowledged=1, acknowledged_by=?, acknowledged_at=? WHERE id=?",
            [$auth['username'], $now, $alert_id]);
    }

    audit_log($auth['username'], $auth['role'], 'IP_BLOCKED', 'blocked_ips', 0,
        '', $ip, $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => "IP $ip blocked via iptables"]);
    exit;
}

if ($action === 'unblock') {
    $ip = sanitize_string(trim($data['ip'] ?? ''), 45);
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo json_encode(['error' => 'Invalid IP address']); exit;
    }
    if ($auth['role'] === ROLE_ANALYST) {
        wdb(
            "INSERT INTO pending_actions
                (requested_by, analyst_username, action_type, action_data, description, status, requested_at)
             VALUES (?,?,?,?,?,?,?)",
            [
                $auth['user_id'], $auth['username'], 'unblock',
                json_encode(['ip' => $ip]),
                "Unblock IP $ip",
                'pending', date('Y-m-d H:i:s'),
            ]
        );
        echo json_encode(['ok' => true, 'pending' => true,
            'message' => "Unblock request submitted for admin approval."]);
        exit;
    }
    exec("sudo /sbin/iptables -D FORWARD -s " . escapeshellarg($ip) . " -j DROP 2>&1");
    exec("sudo /sbin/iptables -D INPUT -s "   . escapeshellarg($ip) . " -j DROP 2>&1");
    wdb("UPDATE blocked_ips SET active=0 WHERE ip=?", [$ip]);
    audit_log($auth['username'], $auth['role'], 'IP_UNBLOCKED', 'blocked_ips', 0,
        $ip, '', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => "IP $ip unblocked"]);
    exit;
}

echo json_encode(['error' => 'Unknown action']);
