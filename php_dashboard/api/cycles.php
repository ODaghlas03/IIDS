<?php
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';
$auth = require_role(ROLE_ADMIN, ROLE_ANALYST, ROLE_USER);
$user = $auth['username'];
security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$cycles = qdb(
    "SELECT id, started_at, ended_at, total_flows, attacks, benign, pcap_file
     FROM cycles
     ORDER BY id DESC
     LIMIT 50"
);

echo json_encode(['cycles' => $cycles]);
