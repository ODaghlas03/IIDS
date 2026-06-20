<?php
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';

require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';
$auth = require_role(ROLE_ADMIN, ROLE_ANALYST);
$user = $auth['username'];
security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');
if (!check_rate_limit("api:{$auth['username']}", RATE_LIMIT_API)) rate_limit_response();

$data    = json_decode(file_get_contents('php://input'), true) ?? [];
$message = trim($data['message'] ?? '');
$history = $data['history'] ?? [];

if (!$message) {
    echo json_encode(['error' => 'Message required']);
    exit;
}

$api_key = get_api_key();
if (!$api_key) {
    echo json_encode(['error' => 'Anthropic API key not configured']);
    exit;
}

// Build messages array from history + new message
$messages = [];
foreach ($history as $h) {
    $role    = $h['role'] ?? '';
    $content = $h['content'] ?? '';
    if (in_array($role, ['user', 'assistant']) && $content) {
        $messages[] = ['role' => $role, 'content' => $content];
    }
}
$messages[] = ['role' => 'user', 'content' => $message];

// Get some DB context
$stats = qdb("SELECT COUNT(*) t, SUM(CASE WHEN attack=1 THEN 1 ELSE 0 END) a FROM flows")[0] ?? ['t' => 0, 'a' => 0];
$top_types = qdb("SELECT attack_type, COUNT(*) n FROM flows WHERE attack=1 AND attack_type!='' GROUP BY attack_type ORDER BY n DESC LIMIT 5");
$top_ips   = qdb("SELECT source_ip, COUNT(*) n FROM flows WHERE attack=1 GROUP BY source_ip ORDER BY n DESC LIMIT 3");

$context_lines = [
    "Current IDS stats: {$stats['t']} total flows, {$stats['a']} attacks detected.",
];
if ($top_types) {
    $types = implode(', ', array_map(fn($r) => "{$r['attack_type']}({$r['n']})", $top_types));
    $context_lines[] = "Top attack types: $types";
}
if ($top_ips) {
    $ips = implode(', ', array_map(fn($r) => "{$r['source_ip']}({$r['n']})", $top_ips));
    $context_lines[] = "Top attacking IPs: $ips";
}

$system = "You are an expert cybersecurity analyst assistant for a Network Intrusion Detection System (IDS). " .
    "You help analysts understand network threats, investigate alerts, and respond to incidents. " .
    "You are knowledgeable about DDoS attacks, port scans, brute force attacks, botnets, and network forensics. " .
    "Be concise, technical, and actionable. " .
    implode(' ', $context_lines);

$payload = json_encode([
    'model'      => 'claude-haiku-4-5-20251001',
    'max_tokens' => 1024,
    'system'     => $system,
    'messages'   => $messages,
]);

$ch = curl_init('https://api.anthropic.com/v1/messages');
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $payload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'x-api-key: ' . $api_key,
        'anthropic-version: 2023-06-01',
    ],
    CURLOPT_TIMEOUT => 60,
]);
$resp = curl_exec($ch);
$curl_err = curl_error($ch);
curl_close($ch);

if ($curl_err) {
    echo json_encode(['error' => 'API request failed: ' . $curl_err]);
    exit;
}

$json = json_decode($resp, true);
if (!$json || isset($json['error'])) {
    $err_msg = $json['error']['message'] ?? 'Unknown API error';
    echo json_encode(['error' => $err_msg]);
    exit;
}

$reply = $json['content'][0]['text'] ?? '';
echo json_encode(['reply' => $reply]);
