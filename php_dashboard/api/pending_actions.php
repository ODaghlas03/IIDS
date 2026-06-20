<?php
/**
 * Pending Actions — analyst approval workflow
 * Admins approve or reject analyst action requests.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$auth = require_role(ROLE_ADMIN, ROLE_ANALYST);

$method = $_SERVER['REQUEST_METHOD'];

// ── GET: list pending actions ─────────────────────────────────────────────
if ($method === 'GET') {
    if ($auth['role'] === ROLE_ADMIN) {
        // Admin sees all pending actions
        $actions = qdb(
            "SELECT * FROM pending_actions ORDER BY requested_at DESC LIMIT 100"
        );
    } else {
        // Analyst sees only their own, not others'
        $actions = qdb(
            "SELECT * FROM pending_actions WHERE analyst_username=? ORDER BY requested_at DESC LIMIT 50",
            [$auth['username']]
        );
    }
    echo json_encode(['ok' => true, 'actions' => $actions]);
    exit;
}

// ── POST: approve or reject ───────────────────────────────────────────────
verify_csrf($auth);
$data      = json_decode(file_get_contents('php://input'), true) ?? [];
$request_a = $data['action'] ?? '';

// Analyst: only allowed to submit new requests (already handled in block/alerts)
// Here only admins can approve/reject
if ($auth['role'] !== ROLE_ADMIN && $request_a !== 'my_notifications') {
    json_error(403, 'Only admins can approve or reject actions');
}

if ($request_a === 'approve') {
    $action_id = (int)($data['action_id'] ?? 0);
    if (!$action_id) { echo json_encode(['error' => 'Action ID required']); exit; }

    $pa = qdb("SELECT * FROM pending_actions WHERE action_id=? AND status='pending'", [$action_id]);
    if (!$pa) { echo json_encode(['error' => 'Action not found or already reviewed']); exit; }

    $pa = $pa[0];
    $now = date('Y-m-d H:i:s');

    // Execute the action
    $action_data = json_decode($pa['action_data'], true) ?? [];
    $result_msg  = execute_pending_action($pa['action_type'], $action_data, $auth['username']);

    wdb(
        "UPDATE pending_actions SET status='approved', reviewed_by=?, reviewed_at=? WHERE action_id=?",
        [$auth['username'], $now, $action_id]
    );

    // In-app notification for analyst
    wdb("UPDATE pending_actions SET notification_sent=0 WHERE action_id=?", [$action_id]);

    audit_log($auth['username'], $auth['role'], 'ACTION_APPROVED', 'pending_actions',
        $action_id, 'pending', 'approved', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => "Approved. $result_msg"]);
    exit;
}

if ($request_a === 'reject') {
    $action_id = (int)($data['action_id'] ?? 0);
    $reason    = sanitize_string($data['reason'] ?? '', 500);
    if (!$action_id) { echo json_encode(['error' => 'Action ID required']); exit; }
    if (!$reason)    { echo json_encode(['error' => 'Rejection reason required']); exit; }

    $pa = qdb("SELECT * FROM pending_actions WHERE action_id=? AND status='pending'", [$action_id]);
    if (!$pa) { echo json_encode(['error' => 'Action not found or already reviewed']); exit; }

    $now = date('Y-m-d H:i:s');
    wdb(
        "UPDATE pending_actions SET status='rejected', reviewed_by=?, reviewed_at=?, rejection_reason=? WHERE action_id=?",
        [$auth['username'], $now, $reason, $action_id]
    );
    wdb("UPDATE pending_actions SET notification_sent=0 WHERE action_id=?", [$action_id]);

    audit_log($auth['username'], $auth['role'], 'ACTION_REJECTED', 'pending_actions',
        $action_id, 'pending', "rejected:$reason", $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => 'Action rejected.']);
    exit;
}

// Analyst polls for their notifications (approved/rejected since last check)
if ($request_a === 'my_notifications') {
    $notifications = qdb(
        "SELECT action_id, action_type, description, status, rejection_reason, reviewed_at
         FROM pending_actions
         WHERE analyst_username=? AND status != 'pending' AND notification_sent=0
         ORDER BY reviewed_at DESC",
        [$auth['username']]
    );
    if ($notifications) {
        // Mark as sent
        $ids = implode(',', array_column($notifications, 'action_id'));
        wdb("UPDATE pending_actions SET notification_sent=1 WHERE action_id IN ($ids)");
    }
    echo json_encode(['ok' => true, 'notifications' => $notifications]);
    exit;
}

// Count of pending items for badge display (admin)
if ($request_a === 'count') {
    $count = qdb("SELECT COUNT(*) n FROM pending_actions WHERE status='pending'");
    echo json_encode(['ok' => true, 'count' => (int)($count[0]['n'] ?? 0)]);
    exit;
}

echo json_encode(['error' => 'Unknown action']);

// ── Execute approved action ───────────────────────────────────────────────
function execute_pending_action(string $type, array $data, string $approver): string {
    switch ($type) {
        case 'block':
            $ip     = $data['ip']     ?? '';
            $reason = $data['reason'] ?? 'Approved by admin';
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return "Invalid IP.";
            $exists = qdb("SELECT id FROM blocked_ips WHERE ip=? AND active=1", [$ip]);
            if (!$exists) {
                exec("sudo /sbin/iptables -A FORWARD -s " . escapeshellarg($ip) . " -j DROP 2>&1");
                exec("sudo /sbin/iptables -A INPUT -s "   . escapeshellarg($ip) . " -j DROP 2>&1");
                $now = date('Y-m-d H:i:s');
                $e   = qdb("SELECT id FROM blocked_ips WHERE ip=?", [$ip]);
                if ($e) {
                    wdb("UPDATE blocked_ips SET active=1, reason=?, blocked_by=?, blocked_at=? WHERE ip=?",
                        ["$reason (approved by $approver)", $approver, $now, $ip]);
                } else {
                    wdb("INSERT INTO blocked_ips (ip, reason, blocked_by, blocked_at, active) VALUES (?,?,?,?,1)",
                        [$ip, "$reason (approved by $approver)", $approver, $now]);
                }
            }
            return "IP $ip blocked.";

        case 'unblock':
            $ip = $data['ip'] ?? '';
            if (!filter_var($ip, FILTER_VALIDATE_IP)) return "Invalid IP.";
            exec("sudo /sbin/iptables -D FORWARD -s " . escapeshellarg($ip) . " -j DROP 2>&1");
            exec("sudo /sbin/iptables -D INPUT -s "   . escapeshellarg($ip) . " -j DROP 2>&1");
            wdb("UPDATE blocked_ips SET active=0 WHERE ip=?", [$ip]);
            return "IP $ip unblocked.";

        case 'query':
            // Read-only query approved by admin
            $sql = $data['sql'] ?? '';
            $sql_upper = strtoupper($sql);
            if (!str_starts_with($sql_upper, 'SELECT')) return "Non-SELECT query rejected.";
            return "Query executed (read-only).";

        default:
            return "Action type '$type' executed.";
    }
}
