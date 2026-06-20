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

$data     = json_decode(file_get_contents('php://input'), true) ?? [];
$cycle_id = (int)($data['cycle_id'] ?? 0);

if (!$cycle_id) {
    echo json_encode(['error' => 'Cycle ID required']);
    exit;
}

// Fetch cycle info
$cycle = qdb("SELECT * FROM cycles WHERE id=?", [$cycle_id]);
if (!$cycle) {
    echo json_encode(['error' => 'Cycle not found']);
    exit;
}
$cycle = $cycle[0];

// Fetch alerts for this cycle
$alerts = qdb(
    "SELECT source_ip, attack_type, severity, flow_count, max_error, acknowledged
     FROM alerts
     WHERE cycle_id=?
     ORDER BY flow_count DESC",
    [$cycle_id]
);

// Fetch top attack types
$attack_types = qdb(
    "SELECT attack_type, COUNT(*) n
     FROM flows
     WHERE cycle_id=? AND attack=1 AND attack_type != ''
     GROUP BY attack_type
     ORDER BY n DESC
     LIMIT 10",
    [$cycle_id]
);

// Fetch top attacking IPs
$top_ips = qdb(
    "SELECT source_ip, COUNT(*) n, MAX(reconstruction_error) max_err
     FROM flows
     WHERE cycle_id=? AND attack=1
     GROUP BY source_ip
     ORDER BY n DESC
     LIMIT 5",
    [$cycle_id]
);

// Fetch flow stats
$flow_stats = qdb(
    "SELECT AVG(reconstruction_error) avg_err, MAX(reconstruction_error) max_err,
            COUNT(*) total, SUM(CASE WHEN attack=1 THEN 1 ELSE 0 END) attacks
     FROM flows
     WHERE cycle_id=?",
    [$cycle_id]
)[0] ?? [];

// Build report context
$started = $cycle['started_at'] ?? 'Unknown';
$ended   = $cycle['ended_at'] ?? 'In progress';
$total   = (int)($cycle['total_flows'] ?? 0);
$attacks = (int)($cycle['attacks'] ?? 0);
$benign  = (int)($cycle['benign'] ?? 0);
$pcap    = $cycle['pcap_file'] ?? 'N/A';

$context = "Incident Report Request for Cycle #$cycle_id\n";
$context .= "Time: $started to $ended\n";
$context .= "Flows: $total total, $attacks attacks, $benign benign\n";
$context .= "PCAP: $pcap\n\n";

if ($flow_stats) {
    $context .= sprintf(
        "Error stats: avg=%.4f, max=%.4f\n\n",
        (float)($flow_stats['avg_err'] ?? 0),
        (float)($flow_stats['max_err'] ?? 0)
    );
}

if ($attack_types) {
    $context .= "Attack type breakdown:\n";
    foreach ($attack_types as $at) {
        $context .= "  - {$at['attack_type']}: {$at['n']} flows\n";
    }
    $context .= "\n";
}

if ($top_ips) {
    $context .= "Top attacking IPs:\n";
    foreach ($top_ips as $ip) {
        $context .= sprintf("  - %s: %d flows, max error %.4f\n",
            $ip['source_ip'], (int)$ip['n'], (float)$ip['max_err']);
    }
    $context .= "\n";
}

if ($alerts) {
    $context .= "Active alerts (" . count($alerts) . " total):\n";
    foreach (array_slice($alerts, 0, 10) as $a) {
        $acked = $a['acknowledged'] ? 'acknowledged' : 'OPEN';
        $context .= "  - [{$a['severity']}] {$a['attack_type']} from {$a['source_ip']} – {$a['flow_count']} flows ($acked)\n";
    }
    $context .= "\n";
}

$api_key = get_api_key();
if (!$api_key) {
    echo json_encode(['error' => 'Anthropic API key not configured']);
    exit;
}

$system = "You are a cybersecurity incident report writer for a Network Intrusion Detection System. " .
    "Generate professional, structured incident reports in plain text format. " .
    "Include: Executive Summary, Timeline, Attack Analysis, Affected Systems, Severity Assessment, " .
    "Recommended Actions, and Conclusion. Use clear headings with === or --- separators. " .
    "Be specific, technical but readable, and actionable.";

$user_msg = "Generate a comprehensive incident report for the following IDS detection cycle:\n\n$context";

$payload = json_encode([
    'model'      => 'claude-haiku-4-5-20251001',
    'max_tokens' => 2048,
    'system'     => $system,
    'messages'   => [['role' => 'user', 'content' => $user_msg]],
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
$resp     = curl_exec($ch);
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

$report = $json['content'][0]['text'] ?? '';
echo json_encode([
    'ok'       => true,
    'report'   => $report,
    'cycle_id' => $cycle_id,
    'cycle'    => $cycle,
]);
