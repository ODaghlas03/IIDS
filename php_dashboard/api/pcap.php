<?php
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';
security_headers();
$auth = require_role(ROLE_ADMIN, ROLE_ANALYST);
$user = $auth['username'];

$filename = $_GET['file'] ?? '';

// Security: basename only, must end in .pcap
$safe_name = basename($filename);
if (!$safe_name || !preg_match('/\.pcap$/i', $safe_name)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Invalid filename. Must be a .pcap file.']);
    exit;
}

// Construct full path and verify it stays within PCAP_DIR
$full_path = realpath(PCAP_DIR . '/' . $safe_name);

// realpath returns false if file doesn't exist
if ($full_path === false) {
    // Try without realpath to give a better error
    $candidate = PCAP_DIR . '/' . $safe_name;
    if (!file_exists($candidate)) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'PCAP file not found']);
        exit;
    }
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Access denied']);
    exit;
}

// Ensure the resolved path starts with the PCAP_DIR (prevent path traversal)
$pcap_real = realpath(PCAP_DIR);
if ($pcap_real === false || strpos($full_path, $pcap_real . '/') !== 0) {
    // Allow exact match of the directory itself (shouldn't happen with a .pcap file)
    if ($full_path !== $pcap_real) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Access denied: path traversal detected']);
        exit;
    }
}

$file_size = filesize($full_path);
$mime      = 'application/vnd.tcpdump.pcap';

header('Content-Type: ' . $mime);
header('Content-Disposition: attachment; filename="' . $safe_name . '"');
header('Content-Length: ' . $file_size);
header('Cache-Control: no-cache');
header('X-Content-Type-Options: nosniff');

readfile($full_path);
exit;
