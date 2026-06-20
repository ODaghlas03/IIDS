<?php
/**
 * Flow analyst verdict
 * Users: read-only. Analysts and Admins can set verdicts.
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
verify_csrf($auth);

$data    = json_decode(file_get_contents('php://input'), true) ?? [];
$flow_id = (int)($data['flow_id'] ?? 0);
$verdict = sanitize_string(trim($data['verdict'] ?? ''), 50);
$note    = sanitize_string(trim($data['note'] ?? ''), 2000);

if (!$flow_id) {
    echo json_encode(['error' => 'Flow ID required']); exit;
}

if (detect_injection($note)) {
    echo json_encode(['error' => 'Invalid content in note field']); exit;
}

$allowed_verdicts = ['benign', 'attack', 'suspicious', 'false_positive', ''];
if (!in_array($verdict, $allowed_verdicts, true)) {
    echo json_encode(['error' => 'Invalid verdict value']); exit;
}

$flow = qdb("SELECT id, analyst_verdict FROM flows WHERE id=?", [$flow_id]);
if (!$flow) {
    echo json_encode(['error' => 'Flow not found']); exit;
}

$old_verdict = $flow[0]['analyst_verdict'] ?? '';
$ok = wdb(
    "UPDATE flows SET analyst_verdict=?, analyst_note=? WHERE id=?",
    [$verdict ?: null, $note ?: null, $flow_id]
);

if ($ok) {
    audit_log($auth['username'], $auth['role'], 'VERDICT_SET', 'flows', $flow_id,
        $old_verdict, $verdict, $auth['user_id']);
    echo json_encode(['ok' => true, 'flow_id' => $flow_id, 'verdict' => $verdict]);
} else {
    echo json_encode(['error' => 'Database error']);
}
