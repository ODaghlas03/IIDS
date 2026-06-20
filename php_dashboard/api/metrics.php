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

// Totals
$totals  = qdb("SELECT COUNT(*) t, SUM(CASE WHEN attack=1 THEN 1 ELSE 0 END) a, SUM(CASE WHEN stage2=1 THEN 1 ELSE 0 END) s2 FROM flows")[0] ?? ['t' => 0, 'a' => 0, 's2' => 0];
$total   = (int)($totals['t'] ?? 0);
$attacks = (int)($totals['a'] ?? 0);
$benign  = $total - $attacks;
$s2      = (int)($totals['s2'] ?? 0);
$rate    = $total > 0 ? round($attacks / $total * 100, 1) : 0;

$avg_err_row = qdb("SELECT AVG(reconstruction_error) avg FROM flows WHERE attack=1")[0] ?? ['avg' => 0];
$avg_err     = round((float)($avg_err_row['avg'] ?? 0), 4);

// Recent flows
$flows = qdb(
    "SELECT f.id, f.source_ip, f.dest_ip, f.dest_port, f.protocol,
            f.reconstruction_error, f.attack, f.attack_type, f.stage2,
            f.analyst_verdict, f.flow_timestamp
     FROM flows f
     ORDER BY f.id DESC
     LIMIT 100"
);

// Top attacking IPs
$top_ips = qdb(
    "SELECT source_ip, COUNT(*) n
     FROM flows
     WHERE attack=1
     GROUP BY source_ip
     ORDER BY n DESC
     LIMIT 5"
);

// Active blocked IPs
$blocked = qdb(
    "SELECT ip, reason, blocked_at, blocked_by
     FROM blocked_ips
     WHERE active=1
     ORDER BY blocked_at DESC"
);

// Cycle count from DB
$cycle_num = (int)((qdb("SELECT COUNT(*) n FROM cycles")[0] ?? ['n' => 0])['n']);

// Determine latest cycle progress from log file
$cycle_pct      = 0;
$cycle_statuses = ['waiting', 'waiting', 'waiting', 'waiting'];
$stopped        = false;

if (file_exists(LOG_PATH) && filesize(LOG_PATH) > 0) {
    $fp = fopen(LOG_PATH, 'rb');
    fseek($fp, max(0, filesize(LOG_PATH) - 262144));
    $log = fread($fp, 262144);
    fclose($fp);

    $lines    = array_values(array_filter(array_map('trim', explode("\n", $log))));
    $last_cap = -1;
    foreach ($lines as $i => $line) {
        if (strpos($line, 'Capturing') !== false) {
            $last_cap = $i;
        }
    }

    if ($last_cap >= 0) {
        $recent   = array_slice($lines, $last_cap);
        $done_cap = (bool)array_filter($recent, fn($l) => strpos($l, 'Converting') !== false);
        $done_cic = (bool)array_filter($recent, fn($l) => strpos($l, 'Running') !== false);
        $done_inf = (bool)array_filter($recent, fn($l) => strpos($l, 'Cycle done') !== false);
        $age      = time() - filemtime(LOG_PATH);
        $stopped  = $age > IDS_INTERVAL * 3;

        if ($done_inf) {
            $cycle_statuses = ['done', 'done', 'done', 'done'];
            $cycle_pct      = 100;
        } elseif ($done_cic) {
            $cycle_statuses = ['done', 'done', 'active', 'waiting'];
            $cycle_pct      = 65;
        } elseif ($done_cap) {
            $cycle_statuses = ['done', 'active', 'waiting', 'waiting'];
            $cycle_pct      = 35;
        } else {
            // Capture phase in progress — estimate elapsed time from log timestamp
            $cap_line = $lines[$last_cap];
            if (preg_match('/\[(\d{2}:\d{2}:\d{2})\]/', $cap_line, $m)) {
                $cap_time = strtotime(date('Y-m-d') . ' ' . $m[1]);
                if ($cap_time > time()) $cap_time -= 86400; // midnight rollover
                $elapsed   = max(0, time() - $cap_time);
                $cycle_pct = (int)min(90, round(($elapsed / IDS_INTERVAL) * 90));
            } else {
                $cycle_pct = 5;
            }
            $cycle_statuses = ['active', 'waiting', 'waiting', 'waiting'];
        }

        if ($stopped) {
            $cycle_statuses = array_map(
                fn($s) => $s === 'active' ? 'stopped' : $s,
                $cycle_statuses
            );
        }
    }
}

// Latest cycle from DB
$latest_cycle = qdb("SELECT * FROM cycles ORDER BY id DESC LIMIT 1")[0] ?? null;

echo json_encode([
    'total'          => $total,
    'attacks'        => $attacks,
    'benign'         => $benign,
    's2'             => $s2,
    'rate'           => $rate,
    'avg_err'        => $avg_err,
    'flows'          => $flows,
    'top_ips'        => $top_ips,
    'blocked'        => $blocked,
    'cycle_num'      => $cycle_num,
    'cycle_pct'      => $cycle_pct,
    'cycle_statuses' => $cycle_statuses,
    'stopped'        => $stopped,
    'latest_cycle'   => $latest_cycle,
]);
