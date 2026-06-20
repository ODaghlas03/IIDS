<?php
/**
 * Natural Language Search
 * Analysts: read-only SELECT only; Users: no access; Admins: full read.
 * Action queries (non-SELECT) are saved as pending_actions, never executed.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

// Users have no access to the query interface
$auth = require_role(ROLE_ADMIN, ROLE_ANALYST);
verify_csrf($auth);

// Rate limiting per user
if (!check_rate_limit("nlsearch:{$auth['username']}", RATE_LIMIT_API)) {
    rate_limit_response();
}

$data  = json_decode(file_get_contents('php://input'), true) ?? [];
$query = sanitize_string(trim($data['query'] ?? ''), 500);

if (!$query) {
    echo json_encode(['error' => 'Query required']); exit;
}

if (detect_injection($query)) {
    audit_log($auth['username'], $auth['role'], 'INJECTION_ATTEMPT', 'nl_search', 0, $query, '');
    echo json_encode(['error' => 'Query contains invalid content']); exit;
}

// Daily query limit
$today      = date('Y-m-d');
$count_rows = qdb(
    "SELECT COUNT(*) n FROM nl_queries WHERE username=? AND created_at >= ?",
    [$auth['username'], $today . ' 00:00:00']
);
$call_count = (int)(($count_rows[0] ?? ['n' => 0])['n']);
if ($call_count >= MAX_NL_CALLS) {
    echo json_encode(['error' => "Daily limit of " . MAX_NL_CALLS . " NL queries reached"]); exit;
}

// Generate SQL from natural language
$system = <<<SYSTEM
You are a read-only SQL assistant for a Network Intrusion Detection System.
Generate a single SQLite SELECT query based on the user's natural language request.

Database schema (attacks database only — you MUST NOT reference users, sessions, audit_logs, password_history, rate_limits, or ip_allowlist tables):
- flows(id, cycle_id, flow_timestamp, source_ip, dest_ip, dest_port, protocol, flow_duration,
        flow_packets_s, flow_bytes_s, total_fwd_packets, total_bwd_packets, packet_length_mean,
        flow_iat_mean, reconstruction_error, attack, stage1, stage2, attack_type,
        analyst_verdict, analyst_note, triage_score, created_at)
- cycles(id, started_at, ended_at, total_flows, attacks, benign, pcap_file, flows_file)
- alerts(id, cycle_id, source_ip, attack_type, severity, flow_count, max_error,
         acknowledged, acknowledged_by, acknowledged_at, created_at)
- blocked_ips(id, ip, reason, blocked_by, blocked_at, active)

Rules:
1. Return ONLY the SQL query — no explanation, no markdown, no backticks.
2. Only generate SELECT statements.
3. NEVER reference: users, sessions, audit_logs, password_history, rate_limits, pending_actions, ip_allowlist, login_attempts, totp_secrets
4. Always add LIMIT 200 unless the request is for aggregates.
5. Use proper SQLite syntax.
SYSTEM;

$sql_text = call_claude_query($system, $query);

$sql_text = preg_replace('/```(?:sql)?\s*/i', '', $sql_text);
$sql_text = str_replace('```', '', $sql_text);
$sql_text = trim($sql_text);

// Strict SQL validation — SELECT only, no forbidden keywords, no forbidden tables
$sql_upper = strtoupper(preg_replace('/\s+/', ' ', $sql_text));

if (!str_starts_with($sql_upper, 'SELECT')) {
    // Non-SELECT action query from analyst → pending action, not executed
    if ($auth['role'] === ROLE_ANALYST) {
        wdb(
            "INSERT INTO pending_actions
                (requested_by, analyst_username, action_type, action_data, description, status, requested_at)
             VALUES (?,?,?,?,?,?,?)",
            [
                $auth['user_id'], $auth['username'], 'query',
                json_encode(['sql' => $sql_text, 'natural' => $query]),
                "NL Query: $query",
                'pending', date('Y-m-d H:i:s'),
            ]
        );
        echo json_encode(['error' => 'Action queries require admin approval. Request submitted.']);
    } else {
        echo json_encode(['error' => 'Generated query is not a SELECT statement', 'sql' => $sql_text]);
    }
    exit;
}

// Block queries against protected tables
$protected_tables = ['users', 'sessions', 'audit_logs', 'password_history',
                     'rate_limits', 'pending_actions', 'ip_allowlist',
                     'login_attempts'];
foreach ($protected_tables as $table) {
    if (preg_match('/\b' . strtoupper($table) . '\b/', $sql_upper)) {
        audit_log($auth['username'], $auth['role'], 'BLOCKED_TABLE_ACCESS', 'nl_search', 0,
            $table, $query);
        echo json_encode(['error' => "Query references a restricted table ($table)"]); exit;
    }
}

// Block dangerous keywords
$dangerous = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'CREATE', 'ALTER',
              'ATTACH', 'DETACH', 'PRAGMA', 'TRUNCATE', 'REPLACE'];
foreach ($dangerous as $kw) {
    if (preg_match('/\b' . $kw . '\b/', $sql_upper)) {
        echo json_encode(['error' => "Query contains forbidden keyword: $kw"]); exit;
    }
}

// Execute read-only query
$rows = qdb($sql_text);

// Log query
wdb(
    "INSERT INTO nl_queries (username, natural_query, generated_sql, created_at) VALUES (?,?,?,?)",
    [$auth['username'], $query, $sql_text, date('Y-m-d H:i:s')]
);
audit_log($auth['username'], $auth['role'], 'NL_QUERY', 'nl_queries', 0,
    '', mask_sensitive($query, 20), $auth['user_id']);

$columns = $rows ? array_keys($rows[0]) : [];

echo json_encode([
    'ok'              => true,
    'sql'             => $sql_text,
    'columns'         => $columns,
    'rows'            => $rows,
    'count'           => count($rows),
    'calls_used'      => $call_count + 1,
    'calls_remaining' => MAX_NL_CALLS - $call_count - 1,
]);

function call_claude_query(string $system, string $user_msg): string {
    $api_key = get_api_key();
    if (!$api_key) return '';

    $payload = json_encode([
        'model'      => 'claude-haiku-4-5-20251001',
        'max_tokens' => 400,
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
        CURLOPT_TIMEOUT => 30,
    ]);
    $resp = curl_exec($ch);
    curl_close($ch);

    if (!$resp) return '';
    $json = json_decode($resp, true);
    return $json['content'][0]['text'] ?? '';
}
