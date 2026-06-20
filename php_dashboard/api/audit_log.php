<?php
/**
 * Audit Log — read-only, admin-only
 * Immutable audit trail — no edit/delete routes.
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

$method = $_SERVER['REQUEST_METHOD'];
if ($method !== 'GET') {
    // Audit logs are STRICTLY read-only — no POST/PUT/DELETE allowed
    json_error(405, 'Audit logs are read-only');
}

$offset  = max(0, (int)($_GET['offset'] ?? 0));
$filter_user   = sanitize_string($_GET['username'] ?? '', 80);
$filter_action = sanitize_string($_GET['action'] ?? '', 100);

$where  = [];
$params = [];

if ($filter_user) {
    $where[]  = 'username = ?';
    $params[] = $filter_user;
}
if ($filter_action) {
    $where[]  = 'action LIKE ?';
    $params[] = '%' . $filter_action . '%';
}

$where_sql = $where ? ('WHERE ' . implode(' AND ', $where)) : '';

$logs = qdb(
    "SELECT log_id, username, role, action, target_table, target_id,
            old_value, new_value, ip_address, user_agent, timestamp
     FROM audit_logs
     $where_sql
     ORDER BY log_id DESC
     LIMIT 100 OFFSET ?",
    array_merge($params, [$offset])
);

$total = qdb("SELECT COUNT(*) n FROM audit_logs $where_sql", $params);

echo json_encode([
    'ok'    => true,
    'logs'  => $logs,
    'total' => (int)($total[0]['n'] ?? 0),
    'offset'=> $offset,
]);
