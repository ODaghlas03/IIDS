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
if (!check_rate_limit("api:{$auth['username']}", RATE_LIMIT_API)) rate_limit_response();

// --- Error distribution (sampled, max 2000 each) ---
$benign_raw = qdb(
    "SELECT reconstruction_error FROM flows WHERE attack=0 AND reconstruction_error IS NOT NULL ORDER BY id"
);
$attack_raw = qdb(
    "SELECT reconstruction_error FROM flows WHERE attack=1 AND reconstruction_error IS NOT NULL ORDER BY id"
);

function sample_errors(array $rows, int $max = 2000): array {
    $count = count($rows);
    if ($count <= $max) {
        return array_column($rows, 'reconstruction_error');
    }
    $step   = (int)ceil($count / $max);
    $result = [];
    for ($i = 0; $i < $count; $i += $step) {
        $result[] = (float)$rows[$i]['reconstruction_error'];
    }
    return $result;
}

$benign_errors = sample_errors($benign_raw);
$attack_errors = sample_errors($attack_raw);

// Threshold
$threshold = null;
if (file_exists(THRESHOLD_FILE)) {
    $tj = json_decode(file_get_contents(THRESHOLD_FILE), true);
    $threshold = (float)($tj['threshold'] ?? $tj['value'] ?? 0);
}

// --- Attack types ---
$attack_types = qdb(
    "SELECT attack_type AS label, COUNT(*) AS count
     FROM flows
     WHERE attack=1 AND attack_type IS NOT NULL AND attack_type != ''
     GROUP BY attack_type
     ORDER BY count DESC"
);

// --- Cycles (last 20) ---
$cycles = qdb(
    "SELECT id, attacks, benign, total_flows, started_at
     FROM cycles
     ORDER BY id DESC
     LIMIT 20"
);

// --- Protocol distribution ---
$protocols = qdb(
    "SELECT protocol, COUNT(*) AS count
     FROM flows
     WHERE protocol IS NOT NULL AND protocol != ''
     GROUP BY protocol
     ORDER BY count DESC"
);

// --- Top 10 targeted ports ---
$ports = qdb(
    "SELECT dest_port AS port, COUNT(*) AS count
     FROM flows
     WHERE attack=1 AND dest_port IS NOT NULL
     GROUP BY dest_port
     ORDER BY count DESC
     LIMIT 10"
);

// --- Traffic composition ---
$tc_row       = qdb("SELECT SUM(CASE WHEN attack=0 THEN 1 ELSE 0 END) b, SUM(CASE WHEN attack=1 THEN 1 ELSE 0 END) a FROM flows")[0] ?? ['b' => 0, 'a' => 0];
$traffic_comp = ['benign' => (int)$tc_row['b'], 'attack' => (int)$tc_row['a']];

// --- Top attacker IPs with breakdown ---
$top_attackers_raw = qdb(
    "SELECT source_ip,
            COUNT(*) AS flows,
            SUM(CASE WHEN LOWER(attack_type) LIKE '%ddos%' OR LOWER(attack_type) LIKE '%dos%' THEN 1 ELSE 0 END) AS ddos,
            SUM(CASE WHEN LOWER(attack_type) LIKE '%scan%' OR LOWER(attack_type) LIKE '%port%' THEN 1 ELSE 0 END) AS scan,
            SUM(CASE WHEN LOWER(attack_type) LIKE '%brute%' OR LOWER(attack_type) LIKE '%ssh%' OR LOWER(attack_type) LIKE '%ftp%' THEN 1 ELSE 0 END) AS brute,
            SUM(CASE WHEN LOWER(attack_type) LIKE '%bot%' THEN 1 ELSE 0 END) AS bot,
            MAX(reconstruction_error) AS max_err
     FROM flows
     WHERE attack=1
     GROUP BY source_ip
     ORDER BY flows DESC
     LIMIT 10"
);

$top_attackers = array_map(function ($r) {
    return [
        'source_ip' => $r['source_ip'],
        'flows'     => (int)$r['flows'],
        'ddos'      => (int)$r['ddos'],
        'scan'      => (int)$r['scan'],
        'brute'     => (int)$r['brute'],
        'bot'       => (int)$r['bot'],
        'max_err'   => round((float)$r['max_err'], 4),
    ];
}, $top_attackers_raw);

echo json_encode([
    'err_dist' => [
        'benign_errors' => $benign_errors,
        'attack_errors' => $attack_errors,
        'threshold'     => $threshold,
    ],
    'attack_types'  => $attack_types,
    'cycles'        => array_reverse($cycles),
    'protocols'     => $protocols,
    'ports'         => $ports,
    'traffic_comp'  => $traffic_comp,
    'top_attackers' => $top_attackers,
]);
