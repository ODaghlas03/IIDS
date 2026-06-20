<?php
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/security.php';

// Apply security headers on every page load
security_headers();

$token    = $_COOKIE['ids_token'] ?? '';
$username = $token ? validate_session($token) : null;
$role     = '';
$csrf_token = '';
$user_id  = 0;
if ($username) {
    $u    = qdb("SELECT id, role FROM users WHERE username=?", [$username]);
    $role = $u[0]['role'] ?? 'user';
    $user_id = (int)($u[0]['id'] ?? 0);
    // Fetch CSRF token for this session
    $sc = qdb("SELECT csrf_token FROM sessions WHERE token=?", [$token]);
    $csrf_token = $sc[0]['csrf_token'] ?? '';
}
$initial = $username ? strtoupper(substr($username, 0, 1)) : 'A';
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IIDS — Intrusion Detection Dashboard</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
</head>
<body>

<?php if (!$username): ?>
<!-- ═══════════════════ LOGIN PAGE ═══════════════════ -->
<div id="login-page" class="login-page">

    <!-- Left branding panel -->
    <div class="login-brand-left">
        <img src="assets/IIDS_Logo.png" class="login-brand-logo-img" alt="IIDS Logo">
        <div class="login-brand-name">IIDS</div>
        <div class="login-brand-sub">Intelligent Intrusion Detection System</div>
    </div>

    <!-- Right login card -->
    <div class="login-card">
        <div class="login-logo">
            <img src="assets/IIDS_Logo.png" class="login-card-logo-img" alt="IIDS">
            <div class="login-logo-text">
                <h1>Sign In</h1>
                <span>IIDS Security Dashboard</span>
            </div>
        </div>

        <!-- Login Form -->
        <div class="login-form-section active" id="login-section">
            <div class="login-error" id="login-error"></div>
            <form id="login-form" autocomplete="on">
                <div class="form-group">
                    <label class="form-label" for="login-username">Username</label>
                    <input class="form-input" type="text" id="login-username"
                           name="username" autocomplete="username"
                           placeholder="analyst" required>
                </div>
                <div class="form-group">
                    <label class="form-label" for="login-password">Password</label>
                    <input class="form-input" type="password" id="login-password"
                           name="password" autocomplete="current-password"
                           placeholder="••••••••" required>
                </div>
                <button type="submit" class="btn btn-primary login-btn">Sign In</button>
            </form>
        </div>

        <div style="margin-top:20px;text-align:center">
            <button id="theme-toggle" class="theme-toggle">☀ Light</button>
        </div>
    </div>
</div>

<?php else: ?>
<!-- ═══════════════════ DASHBOARD ═══════════════════ -->
<script>
    window.IDS_USER  = <?= json_encode($username) ?>;
    window.IDS_ROLE  = <?= json_encode($role) ?>;
    window.IDS_TOKEN = <?= json_encode($token) ?>;
    window.IDS_CSRF  = <?= json_encode($csrf_token) ?>;
</script>

<div id="app">

<!-- ══════════ SIDEBAR ══════════ -->
<aside class="sidebar">

    <!-- Brand -->
    <div class="sidebar-brand">
        <img src="assets/IIDS_Logo.png" class="brand-logo-img" alt="IIDS">
        <div>
            <div class="brand-name">IIDS</div>
            <div class="brand-tagline">Security</div>
        </div>
    </div>

    <!-- IDS Status -->
    <div class="sidebar-status">
        <span id="status-dot" class="status-dot" title="IDS status"></span>
        <span class="status-label">IDS Active</span>
    </div>

    <!-- Navigation -->
    <nav class="sidebar-nav">
        <div class="nav-section">Monitoring</div>

        <button class="tab-btn active" data-tab="live-feed">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
            </svg>
            <span>Live Feed</span>
        </button>

        <button class="tab-btn" data-tab="analytics">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <rect x="2" y="12" width="4" height="10" rx="1"/>
                <rect x="9" y="7" width="4" height="15" rx="1"/>
                <rect x="16" y="3" width="4" height="19" rx="1"/>
            </svg>
            <span>Analytics</span>
        </button>

        <button class="tab-btn" data-tab="alerts">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            <span>Alerts</span>
        </button>

        <div class="nav-section">AI Tools</div>

        <button class="tab-btn" data-tab="nl-search">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <span>NL Search</span>
        </button>

        <button class="tab-btn" data-tab="chat">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
            </svg>
            <span>AI Chat</span>
        </button>

        <button class="tab-btn" data-tab="reports">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
                <line x1="16" y1="13" x2="8" y2="13"/>
                <line x1="16" y1="17" x2="8" y2="17"/>
                <polyline points="10 9 9 9 8 9"/>
            </svg>
            <span>Reports</span>
        </button>

        <?php if ($role === 'admin'): ?>
        <div class="nav-section">Admin</div>
        <button class="tab-btn" data-tab="users">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
                <circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
                <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
            </svg>
            <span>User Mgmt</span>
        </button>
        <button class="tab-btn" data-tab="pending-approvals" id="pending-tab-btn">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
            </svg>
            <span>Approvals <span id="pending-badge" class="badge badge-attack" style="display:none;font-size:10px;padding:1px 5px;margin-left:4px">0</span></span>
        </button>
        <button class="tab-btn" data-tab="audit-log">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M9 11l3 3L22 4"/>
                <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
            </svg>
            <span>Audit Log</span>
        </button>
        <button class="tab-btn" data-tab="security-events">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span>Security</span>
        </button>
        <?php endif; ?>
        <?php if ($role === 'analyst'): ?>
        <div class="nav-section">My Requests</div>
        <button class="tab-btn" data-tab="my-requests">
            <svg class="nav-icon" viewBox="0 0 24 24">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
            </svg>
            <span>My Requests</span>
        </button>
        <?php endif; ?>
    </nav>

    <!-- User + Logout -->
    <div class="sidebar-bottom">
        <div class="sidebar-user-card">
            <div class="user-avatar-sb"><?= htmlspecialchars($initial) ?></div>
            <div>
                <div class="user-name-sb"><?= htmlspecialchars($username) ?></div>
                <div class="user-role-sb"><?= htmlspecialchars($role) ?></div>
            </div>
        </div>
        <div style="display:flex;gap:6px;margin-bottom:6px">
            <button id="change-pw-btn" class="btn btn-ghost btn-sm" style="flex:1;font-size:11px" title="Change Password">🔑 Password</button>
            <button id="totp-btn"      class="btn btn-ghost btn-sm" style="flex:1;font-size:11px" title="2FA Settings">🔐 2FA</button>
        </div>
        <button id="logout-btn" class="btn-sb-logout">Sign Out</button>
    </div>

</aside><!-- /sidebar -->

<!-- ══════════ MAIN AREA ══════════ -->
<div class="main-area">

    <!-- Topbar -->
    <header class="topbar">
        <div class="topbar-left">
            <span class="topbar-title">IIDS Dashboard</span>
            <span class="topbar-breadcrumb" id="topbar-section">Live Feed</span>
            <span id="cycle-stopped" class="badge badge-attack" style="display:none">STOPPED</span>
        </div>
        <div class="topbar-right">
            <div class="refresh-badge">↻ <span id="refresh-countdown">20</span>s</div>
            <button id="theme-toggle" class="theme-toggle">☀ Light</button>
        </div>
    </header>

    <!-- Tab Content -->
    <main id="tab-content">

    <!-- ════════════ LIVE FEED TAB ════════════ -->
    <div id="tab-live-feed" class="tab-panel active">

        <!-- Metric Cards -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Total Flows</div>
                <div class="metric-value accent" id="metric-total">—</div>
                <div class="metric-sub">All time</div>
            </div>
            <div class="metric-card attack">
                <div class="metric-label">Attacks Detected</div>
                <div class="metric-value attack" id="metric-attacks">—</div>
                <div class="metric-sub" id="metric-rate">—% attack rate</div>
            </div>
            <div class="metric-card benign">
                <div class="metric-label">Benign Flows</div>
                <div class="metric-value benign" id="metric-benign">—</div>
                <div class="metric-sub">Normal traffic</div>
            </div>
            <div class="metric-card warn">
                <div class="metric-label">Stage-2 Confirmed</div>
                <div class="metric-value warn" id="metric-s2">—</div>
                <div class="metric-sub">High confidence</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Avg Recon Error</div>
                <div class="metric-value" id="metric-avgerr">—</div>
                <div class="metric-sub">Attacks only</div>
            </div>
        </div>

        <!-- Cycle Pipeline -->
        <div class="panel" style="margin-bottom:14px">
            <div class="panel-header">
                <span class="panel-title"><span class="icon">⟳</span> Detection Cycle</span>
                <span id="cycle-num" class="text-muted fs-sm">Cycle #0</span>
            </div>
            <div id="cycle-stages" class="cycle-pipeline"></div>
        </div>

        <div class="two-col">
            <!-- Recent Flows Table -->
            <div class="panel col-span-2">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">≡</span> Recent Flows</span>
                    <span class="text-muted fs-sm">Last 100 flows</span>
                </div>
                <div class="table-wrap" style="max-height:360px;overflow-y:auto">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Source IP</th>
                                <th>Dest IP</th>
                                <th>Port</th>
                                <th>Proto</th>
                                <th>Recon Error</th>
                                <th>Classification</th>
                                <th>Verdict</th>
                            </tr>
                        </thead>
                        <tbody id="flows-tbody">
                            <tr><td colspan="8" class="loading"><div class="spinner"></div> Loading flows...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="two-col">
            <!-- Top Attacking IPs -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">⚡</span> Top Attackers</span>
                </div>
                <ul id="top-ips-list" class="ip-bar-list">
                    <li class="loading"><div class="spinner"></div></li>
                </ul>
            </div>

            <!-- Blocked IPs + Block Form -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">⊘</span> Blocked IPs</span>
                </div>
                <form id="block-form" class="block-form" style="margin-bottom:12px">
                    <div class="form-group" style="flex:1">
                        <label class="form-label">IP Address</label>
                        <input class="form-input" type="text" id="block-ip-input"
                               placeholder="192.168.1.100" pattern="^[\d\.\:a-fA-F]+$">
                    </div>
                    <div class="form-group" style="flex:2">
                        <label class="form-label">Reason</label>
                        <input class="form-input" type="text" id="block-reason-input"
                               placeholder="DDoS attack" value="Manual block">
                    </div>
                    <div class="form-group" style="align-self:flex-end">
                        <button type="submit" class="btn btn-danger">Block IP</button>
                    </div>
                </form>
                <hr class="divider">
                <ul id="blocked-list" class="blocked-list">
                    <li class="loading"><div class="spinner"></div></li>
                </ul>
            </div>
        </div>

    </div><!-- /live-feed -->

    <!-- ════════════ ANALYTICS TAB ════════════ -->
    <div id="tab-analytics" class="tab-panel">

        <div class="two-col">
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Reconstruction Error Distribution</span>
                    <span class="text-muted fs-sm">Threshold: <strong id="threshold-val">—</strong></span>
                </div>
                <div class="chart-wrap" style="height:240px">
                    <canvas id="chart-err-dist"></canvas>
                </div>
            </div>
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Attack Type Breakdown</span>
                </div>
                <div class="chart-wrap" style="height:240px">
                    <canvas id="chart-attack-types"></canvas>
                </div>
            </div>
        </div>

        <div class="two-col">
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Attacks per Cycle (Last 20)</span>
                </div>
                <div class="chart-wrap" style="height:220px">
                    <canvas id="chart-cycles"></canvas>
                </div>
            </div>
            <div class="two-col" style="margin:0">
                <div class="panel">
                    <div class="panel-header"><span class="panel-title">Protocols</span></div>
                    <div class="chart-wrap" style="height:220px">
                        <canvas id="chart-protocols"></canvas>
                    </div>
                </div>
                <div class="panel">
                    <div class="panel-header"><span class="panel-title">Traffic Mix</span></div>
                    <div class="chart-wrap" style="height:220px">
                        <canvas id="chart-traffic"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="two-col">
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Top Targeted Ports</span>
                </div>
                <div class="chart-wrap" style="height:260px">
                    <canvas id="chart-ports"></canvas>
                </div>
            </div>
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Top Attacker IPs</span>
                </div>
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Flows</th>
                                <th>DDoS/DoS</th>
                                <th>Scan</th>
                                <th>Brute</th>
                                <th>Bot</th>
                                <th>Max Err</th>
                            </tr>
                        </thead>
                        <tbody id="top-attackers-tbody">
                            <tr><td colspan="7" class="loading"><div class="spinner"></div></td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div><!-- /analytics -->

    <!-- ════════════ ALERTS TAB ════════════ -->
    <div id="tab-alerts" class="tab-panel">
        <div class="section-header">
            <h2>Active Alerts</h2>
            <button class="btn btn-ghost btn-sm" onclick="loadAlerts()">↻ Refresh</button>
        </div>
        <div id="alerts-list">
            <div class="loading"><div class="spinner"></div> Loading alerts...</div>
        </div>
    </div>

    <!-- ════════════ NL SEARCH TAB ════════════ -->
    <div id="tab-nl-search" class="tab-panel">
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">Natural Language Database Query</span>
                <span class="text-muted fs-sm">AI-powered · Limit: <?= MAX_NL_CALLS ?>/day</span>
            </div>

            <form id="nl-search-form" class="nl-search-form">
                <input class="form-input" type="text" id="nl-query-input"
                       placeholder="e.g. Show top 10 attacking IPs from the last cycle"
                       autocomplete="off">
                <button type="submit" id="nl-submit-btn" class="btn btn-primary">Ask</button>
            </form>

            <div class="nl-examples">
                <button class="nl-example-btn" data-query="Show the top 10 attacking IP addresses">Top attackers</button>
                <button class="nl-example-btn" data-query="How many DDoS attacks were detected today?">DDoS count today</button>
                <button class="nl-example-btn" data-query="List flows with reconstruction error above 0.8">High error flows</button>
                <button class="nl-example-btn" data-query="Show all stage-2 confirmed attacks">Stage-2 attacks</button>
                <button class="nl-example-btn" data-query="What are the most targeted destination ports?">Top ports</button>
                <button class="nl-example-btn" data-query="Show unacknowledged alerts ordered by severity">Open alerts</button>
                <button class="nl-example-btn" data-query="Count attacks per protocol">Attacks by protocol</button>
                <button class="nl-example-btn" data-query="Show the last 20 flows marked as false positive">False positives</button>
            </div>

            <div id="nl-sql" class="nl-sql-block" style="display:none"></div>
            <div id="nl-results"></div>
        </div>
    </div>

    <!-- ════════════ AI CHAT TAB ════════════ -->
    <div id="tab-chat" class="tab-panel">
        <div class="panel" style="max-width:900px;margin:0 auto">
            <div class="panel-header">
                <span class="panel-title">AI Security Analyst Chat</span>
                <button id="chat-clear-btn" class="btn btn-ghost btn-sm">Clear</button>
            </div>

            <div class="chat-container">
                <div class="chat-messages" id="chat-messages">
                    <div class="chat-bubble bot">
                        Hello! I'm your IDS security analyst assistant.
                        Ask me anything about network threats, attack patterns, incident response,
                        or the data in your dashboard.
                    </div>
                </div>
                <form id="chat-form" class="chat-input-area">
                    <textarea class="chat-input" id="chat-input"
                              placeholder="Ask about threats, attack types, response actions... (Enter to send)"
                              rows="1"></textarea>
                    <button type="submit" id="chat-send-btn" class="btn btn-primary">Send</button>
                </form>
            </div>
        </div>
    </div>

    <!-- ════════════ REPORTS TAB ════════════ -->
    <div id="tab-reports" class="tab-panel">
        <div class="two-col">
            <!-- Cycle Selection + Report Generation -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Incident Report Generator</span>
                </div>

                <div class="form-group">
                    <label class="form-label">Select Detection Cycle</label>
                    <select class="form-select" id="cycle-select">
                        <option value="">— Loading cycles... —</option>
                    </select>
                </div>

                <div id="cycle-summary" class="cycle-summary-card" style="display:none"></div>
                <div id="cycle-pcap" style="margin:10px 0"></div>

                <div class="flex-center" style="margin-top:12px;gap:8px">
                    <button id="gen-report-btn" class="btn btn-primary">Generate AI Report</button>
                    <button id="dl-report-btn" class="btn btn-ghost btn-sm" style="display:none">⬇ Download .txt</button>
                </div>

                <hr class="divider">

                <div id="report-output" class="report-output" style="display:block;min-height:60px">
                    <span class="text-muted">Select a cycle and click Generate to create an incident report.</span>
                </div>
            </div>

            <!-- Flow Verdict Form -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">Flow Analyst Verdict</span>
                </div>
                <form id="verdict-form" class="verdict-form">
                    <div class="form-group">
                        <label class="form-label">Flow ID</label>
                        <input class="form-input" type="number" id="verdict-flow-id"
                               placeholder="e.g. 12345" min="1" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Verdict</label>
                        <div class="radio-group">
                            <label class="radio-label">
                                <input type="radio" name="verdict" value="attack">
                                <span class="text-attack">Attack</span>
                            </label>
                            <label class="radio-label">
                                <input type="radio" name="verdict" value="benign">
                                <span class="text-benign">Benign</span>
                            </label>
                            <label class="radio-label">
                                <input type="radio" name="verdict" value="suspicious">
                                <span class="text-warn">Suspicious</span>
                            </label>
                            <label class="radio-label">
                                <input type="radio" name="verdict" value="false_positive">
                                <span class="text-muted">False Positive</span>
                            </label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Analyst Note</label>
                        <textarea class="form-textarea" id="verdict-note"
                                  placeholder="Optional notes about this flow..."></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Verdict</button>
                </form>
            </div>
        </div>
    </div><!-- /reports -->

    <?php if ($role === 'analyst'): ?>
    <!-- ════════════ MY REQUESTS TAB (analyst) ════════════ -->
    <div id="tab-my-requests" class="tab-panel">
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title"><span class="icon">⟳</span> My Pending Requests</span>
                <button class="btn btn-ghost btn-sm" onclick="loadMyRequests()">↻ Refresh</button>
            </div>
            <div id="my-requests-list">
                <div class="loading"><div class="spinner"></div> Loading...</div>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($role === 'admin'): ?>
    <!-- ════════════ PENDING APPROVALS TAB (admin) ════════════ -->
    <div id="tab-pending-approvals" class="tab-panel">
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title"><span class="icon">⟳</span> Pending Analyst Requests</span>
                <button class="btn btn-ghost btn-sm" onclick="loadPendingApprovals()">↻ Refresh</button>
            </div>
            <div id="pending-approvals-list">
                <div class="loading"><div class="spinner"></div> Loading...</div>
            </div>
        </div>
    </div>

    <!-- ════════════ AUDIT LOG TAB (admin) ════════════ -->
    <div id="tab-audit-log" class="tab-panel">
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title"><span class="icon">≡</span> Audit Log</span>
                <button class="btn btn-ghost btn-sm" onclick="loadAuditLog()">↻ Refresh</button>
            </div>
            <div class="form-group" style="display:flex;gap:8px;margin-bottom:10px">
                <input class="form-input" type="text" id="audit-filter-user" placeholder="Filter by username" style="flex:1">
                <input class="form-input" type="text" id="audit-filter-action" placeholder="Filter by action" style="flex:1">
                <button class="btn btn-primary btn-sm" onclick="loadAuditLog()">Search</button>
            </div>
            <div id="audit-log-wrap" class="table-wrap" style="max-height:500px;overflow-y:auto">
                <div class="loading"><div class="spinner"></div> Loading...</div>
            </div>
        </div>
    </div>

    <!-- ════════════ SECURITY EVENTS TAB (admin) ════════════ -->
    <div id="tab-security-events" class="tab-panel">
        <div class="two-col">
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">⚠</span> Recent Failed Logins</span>
                    <button class="btn btn-ghost btn-sm" onclick="loadSecurityEvents()">↻ Refresh</button>
                </div>
                <div id="sec-failed-logins" class="table-wrap">
                    <div class="loading"><div class="spinner"></div></div>
                </div>
            </div>
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">⊘</span> Locked Accounts</span>
                </div>
                <div id="sec-locked-accounts">
                    <div class="loading"><div class="spinner"></div></div>
                </div>
            </div>
        </div>
        <div class="two-col">
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">≡</span> Recent Security Events</span>
                </div>
                <div id="sec-role-changes" class="table-wrap" style="max-height:320px;overflow-y:auto">
                    <div class="loading"><div class="spinner"></div></div>
                </div>
            </div>
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">⟳</span> Session Stats</span>
                </div>
                <div id="sec-stats">
                    <div class="loading"><div class="spinner"></div></div>
                </div>
            </div>
        </div>
    </div>

    <?php endif; ?>

    <?php if ($role === 'admin'): ?>
    <!-- ════════════ USER MANAGEMENT TAB ════════════ -->
    <div id="tab-users" class="tab-panel">
        <div class="two-col">

            <!-- Create user -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">＋</span> Create User</span>
                </div>
                <div class="login-error"   id="adduser-error"  ></div>
                <div class="login-success" id="adduser-success"></div>
                <form id="adduser-form" autocomplete="off">
                    <div class="form-group">
                        <label class="form-label">Username</label>
                        <input class="form-input" type="text" id="adduser-username"
                               placeholder="new_analyst" minlength="3" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Email (optional)</label>
                        <input class="form-input" type="email" id="adduser-email"
                               placeholder="analyst@example.com">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Password <span class="text-muted fs-sm">(min 12 chars, upper+lower+number+special)</span></label>
                        <input class="form-input" type="password" id="adduser-password"
                               placeholder="••••••••••••" minlength="12" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Confirm Password</label>
                        <input class="form-input" type="password" id="adduser-password2"
                               placeholder="••••••••••••" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">Role</label>
                        <select class="form-select" id="adduser-role">
                            <option value="user">User (read-only)</option>
                            <option value="analyst">Analyst</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-primary">Create Account</button>
                </form>
            </div>

            <!-- User list -->
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title"><span class="icon">≡</span> All Users</span>
                    <button class="btn btn-ghost btn-sm" id="users-refresh-btn">↻ Refresh</button>
                </div>
                <div id="users-table-wrap" class="table-wrap">
                    <div class="loading"><div class="spinner"></div> Loading...</div>
                </div>
            </div>

        </div>
    </div><!-- /users -->
    <?php endif; ?>

    </main>
</div><!-- /.main-area -->
</div><!-- /#app -->

<?php endif; ?>

<!-- Toast container -->
<div id="toast-container"></div>

<!-- Change Password Modal -->
<div id="change-pw-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;align-items:center;justify-content:center">
    <div class="panel" style="min-width:360px;max-width:440px;width:100%;margin:0 20px">
        <div class="panel-header">
            <span class="panel-title">Change Password</span>
            <button onclick="document.getElementById('change-pw-modal').style.display='none'" class="btn btn-ghost btn-sm">✕</button>
        </div>
        <div class="login-error" id="cpw-error"></div>
        <div class="login-success" id="cpw-success"></div>
        <form id="change-pw-form" autocomplete="off">
            <div class="form-group">
                <label class="form-label">Current Password</label>
                <input class="form-input" type="password" id="cpw-current" required>
            </div>
            <div class="form-group">
                <label class="form-label">New Password <span class="text-muted fs-sm">(12+ chars, upper+lower+digit+special)</span></label>
                <input class="form-input" type="password" id="cpw-new" required minlength="12">
            </div>
            <div class="form-group">
                <label class="form-label">Confirm New Password</label>
                <input class="form-input" type="password" id="cpw-confirm" required>
            </div>
            <button type="submit" class="btn btn-primary" id="cpw-submit">Change Password</button>
        </form>
    </div>
</div>

<!-- 2FA Modal -->
<div id="totp-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;align-items:center;justify-content:center">
    <div class="panel" style="min-width:360px;max-width:480px;width:100%;margin:0 20px">
        <div class="panel-header">
            <span class="panel-title">Two-Factor Authentication (2FA)</span>
            <button onclick="document.getElementById('totp-modal').style.display='none'" class="btn btn-ghost btn-sm">✕</button>
        </div>
        <div class="login-error" id="totp-error"></div>
        <div class="login-success" id="totp-success"></div>
        <div id="totp-status-area"></div>
        <div id="totp-setup-area" style="display:none">
            <p class="text-muted fs-sm">Scan the secret key with Google Authenticator, Authy, or FreeOTP:</p>
            <div class="panel" style="background:var(--bg-card);padding:12px;text-align:center;margin:8px 0">
                <div style="font-family:monospace;font-size:14px;letter-spacing:2px;word-break:break-all" id="totp-secret-display"></div>
                <div class="text-muted fs-sm" style="margin-top:6px">or copy the URI: <code id="totp-uri-display" style="font-size:10px;word-break:break-all"></code></div>
            </div>
            <div class="form-group">
                <label class="form-label">Enter the 6-digit code from your app to confirm:</label>
                <input class="form-input" type="text" id="totp-confirm-code" placeholder="000000" maxlength="6" pattern="\d{6}">
            </div>
            <button class="btn btn-primary" onclick="confirmTOTP()">Enable 2FA</button>
        </div>
        <div id="totp-disable-area" style="display:none">
            <p class="text-muted fs-sm">Enter your current 2FA code to disable it:</p>
            <div class="form-group">
                <input class="form-input" type="text" id="totp-disable-code" placeholder="000000" maxlength="6" pattern="\d{6}">
            </div>
            <button class="btn btn-danger" onclick="disableTOTP()">Disable 2FA</button>
        </div>
    </div>
</div>

<script src="assets/js/app.js"></script>

<!-- Update topbar breadcrumb on tab switch -->
<script>
(function() {
    const labels = {
        'live-feed':         'Live Feed',
        'analytics':         'Analytics',
        'alerts':            'Alerts',
        'nl-search':         'NL Search',
        'chat':              'AI Chat',
        'reports':           'Reports',
        'users':             'User Management',
        'pending-approvals': 'Pending Approvals',
        'audit-log':         'Audit Log',
        'security-events':   'Security Events',
        'my-requests':       'My Requests',
    };
    document.addEventListener('tabSwitched', function(e) {
        const el = document.getElementById('topbar-section');
        if (el) el.textContent = labels[e.detail] || '';
    });

    // NL SQL display fix
    const nlSql = document.getElementById('nl-sql');
    if (nlSql) {
        new MutationObserver(() => {
            if (nlSql.textContent.trim()) nlSql.style.display = 'block';
        }).observe(nlSql, { childList: true, subtree: true, characterData: true });
    }
})();
</script>

<?php if ($role === 'admin'): ?>
<script>
(function() {
    async function loadUserList() {
        const wrap = document.getElementById('users-table-wrap');
        if (!wrap) return;
        wrap.innerHTML = '<div class="loading"><div class="spinner"></div> Loading...</div>';
        try {
            const res  = await fetch('api/users.php', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' }, body: JSON.stringify({ action: 'list' }) });
            const data = await res.json();
            if (!data.ok) { wrap.innerHTML = `<p class="text-muted">${data.error}</p>`; return; }
            if (!data.users.length) { wrap.innerHTML = '<p class="text-muted">No users found.</p>'; return; }
            wrap.innerHTML = `<table><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th><th>Last Login</th><th></th></tr></thead><tbody>
${data.users.map(u => `<tr>
    <td>${u.id}</td>
    <td><strong>${u.username}</strong></td>
    <td><span class="badge ${u.role === 'admin' ? 'badge-attack' : 'badge-benign'}">${u.role}</span></td>
    <td class="text-muted fs-sm">${u.created_at ? u.created_at.split(' ')[0] : '—'}</td>
    <td class="text-muted fs-sm">${u.last_login ? u.last_login.split(' ')[0] : 'Never'}</td>
    <td>${u.username !== <?= json_encode($username) ?> ? `<button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id},'${u.username}')">Delete</button>` : '<span class="text-muted fs-sm">you</span>'}</td>
</tr>`).join('')}
</tbody></table>`;
        } catch(e) { wrap.innerHTML = '<p class="text-muted">Failed to load users.</p>'; }
    }

    window.deleteUser = async function(id, uname) {
        if (!confirm(`Delete user "${uname}"? This cannot be undone.`)) return;
        try {
            const res  = await fetch('api/users.php', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' }, body: JSON.stringify({ action: 'delete', id }) });
            const data = await res.json();
            if (data.ok) { loadUserList(); }
            else { alert(data.error || 'Delete failed'); }
        } catch(e) { alert('Network error'); }
    };

    document.addEventListener('DOMContentLoaded', function() {
        const form    = document.getElementById('adduser-form');
        const errEl   = document.getElementById('adduser-error');
        const succEl  = document.getElementById('adduser-success');
        const refBtn  = document.getElementById('users-refresh-btn');

        if (refBtn) refBtn.addEventListener('click', loadUserList);

        document.addEventListener('tabSwitched', function(e) {
            if (e.detail === 'users') loadUserList();
        });

        if (form) form.addEventListener('submit', async function(e) {
            e.preventDefault();
            errEl.textContent = ''; errEl.classList.remove('visible');
            succEl.textContent = ''; succEl.classList.remove('visible');

            const username  = document.getElementById('adduser-username').value.trim();
            const email     = document.getElementById('adduser-email')?.value.trim() || '';
            const password  = document.getElementById('adduser-password').value;
            const password2 = document.getElementById('adduser-password2').value;
            const role      = document.getElementById('adduser-role').value;
            const submitBtn = form.querySelector('[type="submit"]');

            if (password !== password2) {
                errEl.textContent = 'Passwords do not match'; errEl.classList.add('visible'); return;
            }

            submitBtn.disabled = true; submitBtn.textContent = 'Creating...';
            try {
                const res  = await fetch('api/users.php', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' }, body: JSON.stringify({ action: 'create', username, email, password, password2, role }) });
                const data = await res.json();
                if (data.ok) {
                    succEl.textContent = data.message || 'User created!'; succEl.classList.add('visible');
                    form.reset();
                    loadUserList();
                } else {
                    errEl.textContent = data.error || 'Failed to create user'; errEl.classList.add('visible');
                }
            } catch(err) {
                errEl.textContent = 'Network error'; errEl.classList.add('visible');
            }
            submitBtn.disabled = false; submitBtn.textContent = 'Create Account';
        });
    });
})();
</script>
<?php endif; ?>
<script>
/* ── Security-related JS ── */

// Change Password modal
document.getElementById('change-pw-btn')?.addEventListener('click', () => {
    document.getElementById('change-pw-modal').style.display = 'flex';
    document.getElementById('cpw-error').textContent = '';
    document.getElementById('cpw-success').textContent = '';
    document.getElementById('change-pw-form').reset();
});
document.getElementById('change-pw-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    const errEl  = document.getElementById('cpw-error');
    const succEl = document.getElementById('cpw-success');
    const btn    = document.getElementById('cpw-submit');
    errEl.textContent = ''; succEl.textContent = '';
    errEl.classList.remove('visible'); succEl.classList.remove('visible');
    btn.disabled = true; btn.textContent = 'Updating...';
    try {
        const res  = await fetch('api/change_password.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
            body: JSON.stringify({
                action: 'change',
                current_password: document.getElementById('cpw-current').value,
                new_password:     document.getElementById('cpw-new').value,
                confirm_password: document.getElementById('cpw-confirm').value,
            })
        });
        const data = await res.json();
        if (data.ok) {
            succEl.textContent = data.message; succEl.classList.add('visible');
            this.reset();
        } else {
            errEl.textContent = data.error; errEl.classList.add('visible');
        }
    } catch { errEl.textContent = 'Network error'; errEl.classList.add('visible'); }
    btn.disabled = false; btn.textContent = 'Change Password';
});

// 2FA modal
document.getElementById('totp-btn')?.addEventListener('click', async () => {
    const modal = document.getElementById('totp-modal');
    modal.style.display = 'flex';
    document.getElementById('totp-error').textContent = '';
    document.getElementById('totp-success').textContent = '';
    document.getElementById('totp-setup-area').style.display = 'none';
    document.getElementById('totp-disable-area').style.display = 'none';
    const statusArea = document.getElementById('totp-status-area');
    statusArea.innerHTML = '<div class="loading"><div class="spinner"></div> Loading 2FA status...</div>';
    try {
        const res  = await fetch('api/totp.php', { headers: { 'X-IDS-Token': window.IDS_TOKEN || '' } });
        const data = await res.json();
        if (data.totp_enabled) {
            statusArea.innerHTML = '<p class="text-muted" style="margin:8px 0">2FA is <strong style="color:var(--benign)">ENABLED</strong> on your account.</p>';
            document.getElementById('totp-disable-area').style.display = 'block';
        } else {
            statusArea.innerHTML = '<p class="text-muted" style="margin:8px 0">2FA is <strong style="color:var(--attack)">DISABLED</strong>. Set it up below.</p>' +
                '<button class="btn btn-primary" onclick="setupTOTP()">Set Up 2FA</button>';
        }
    } catch { statusArea.innerHTML = '<p class="text-muted">Could not load 2FA status.</p>'; }
});

window.setupTOTP = async function() {
    const errEl = document.getElementById('totp-error');
    errEl.textContent = '';
    try {
        const res  = await fetch('api/totp.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
            body: JSON.stringify({ action: 'generate' })
        });
        const data = await res.json();
        if (data.ok) {
            document.getElementById('totp-secret-display').textContent = data.secret;
            document.getElementById('totp-uri-display').textContent    = data.uri;
            document.getElementById('totp-setup-area').style.display   = 'block';
            document.getElementById('totp-status-area').innerHTML = '';
        } else { errEl.textContent = data.error; errEl.classList.add('visible'); }
    } catch { errEl.textContent = 'Network error'; errEl.classList.add('visible'); }
};

window.confirmTOTP = async function() {
    const code  = document.getElementById('totp-confirm-code').value.trim();
    const errEl = document.getElementById('totp-error');
    const sucEl = document.getElementById('totp-success');
    try {
        const res  = await fetch('api/totp.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
            body: JSON.stringify({ action: 'enable', code })
        });
        const data = await res.json();
        if (data.ok) {
            sucEl.textContent = data.message; sucEl.classList.add('visible');
            document.getElementById('totp-setup-area').style.display = 'none';
        } else { errEl.textContent = data.error; errEl.classList.add('visible'); }
    } catch { errEl.textContent = 'Network error'; errEl.classList.add('visible'); }
};

window.disableTOTP = async function() {
    const code  = document.getElementById('totp-disable-code').value.trim();
    const errEl = document.getElementById('totp-error');
    const sucEl = document.getElementById('totp-success');
    try {
        const res  = await fetch('api/totp.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
            body: JSON.stringify({ action: 'disable', code })
        });
        const data = await res.json();
        if (data.ok) {
            sucEl.textContent = data.message; sucEl.classList.add('visible');
            document.getElementById('totp-disable-area').style.display = 'none';
        } else { errEl.textContent = data.error; errEl.classList.add('visible'); }
    } catch { errEl.textContent = 'Network error'; errEl.classList.add('visible'); }
};

// Pending Approvals tab (admin)
window.loadPendingApprovals = async function() {
    const el = document.getElementById('pending-approvals-list');
    if (!el) return;
    el.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    try {
        const res  = await fetch('api/pending_actions.php', { headers: { 'X-IDS-Token': window.IDS_TOKEN || '' } });
        const data = await res.json();
        if (!data.ok || !data.actions.length) { el.innerHTML = '<p class="text-muted">No pending requests.</p>'; return; }
        el.innerHTML = '<table><thead><tr><th>#</th><th>Analyst</th><th>Type</th><th>Description</th><th>Requested</th><th>Status</th><th>Actions</th></tr></thead><tbody>' +
            data.actions.map(a => `<tr>
                <td>${a.action_id}</td>
                <td><strong>${esc(a.analyst_username)}</strong></td>
                <td><span class="badge badge-warn">${esc(a.action_type)}</span></td>
                <td>${esc(a.description)}</td>
                <td class="text-muted fs-sm">${esc(a.requested_at)}</td>
                <td><span class="badge ${a.status === 'pending' ? 'badge-warn' : a.status === 'approved' ? 'badge-benign' : 'badge-attack'}">${esc(a.status)}</span></td>
                <td>${a.status === 'pending' ? `
                    <button class="btn btn-primary btn-sm" onclick="approveAction(${a.action_id})">✓ Approve</button>
                    <button class="btn btn-danger btn-sm" style="margin-left:4px" onclick="rejectAction(${a.action_id})">✗ Reject</button>
                ` : `<span class="text-muted fs-sm">${esc(a.reviewed_by || '—')}</span>`}</td>
            </tr>`).join('') + '</tbody></table>';
    } catch { el.innerHTML = '<p class="text-muted">Error loading requests.</p>'; }
};

function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

window.approveAction = async function(id) {
    if (!confirm('Approve this action? It will be executed immediately.')) return;
    const res  = await fetch('api/pending_actions.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
        body: JSON.stringify({ action: 'approve', action_id: id })
    });
    const data = await res.json();
    alert(data.message || data.error);
    loadPendingApprovals();
};

window.rejectAction = async function(id) {
    const reason = prompt('Rejection reason (required):');
    if (!reason) return;
    const res  = await fetch('api/pending_actions.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
        body: JSON.stringify({ action: 'reject', action_id: id, reason })
    });
    const data = await res.json();
    alert(data.message || data.error);
    loadPendingApprovals();
};

// Audit Log tab
window.loadAuditLog = async function() {
    const wrap   = document.getElementById('audit-log-wrap');
    if (!wrap) return;
    wrap.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    const fu = document.getElementById('audit-filter-user')?.value || '';
    const fa = document.getElementById('audit-filter-action')?.value || '';
    try {
        const res  = await fetch(`api/audit_log.php?username=${encodeURIComponent(fu)}&action=${encodeURIComponent(fa)}`,
            { headers: { 'X-IDS-Token': window.IDS_TOKEN || '' } });
        const data = await res.json();
        if (!data.ok || !data.logs.length) { wrap.innerHTML = '<p class="text-muted">No audit logs found.</p>'; return; }
        wrap.innerHTML = '<table><thead><tr><th>#</th><th>User</th><th>Role</th><th>Action</th><th>Target</th><th>Old</th><th>New</th><th>IP</th><th>Time</th></tr></thead><tbody>' +
            data.logs.map(l => `<tr>
                <td>${l.log_id}</td>
                <td><strong>${esc(l.username)}</strong></td>
                <td><span class="badge ${l.role==='admin'?'badge-attack':'badge-benign'}">${esc(l.role)}</span></td>
                <td>${esc(l.action)}</td>
                <td class="text-muted fs-sm">${esc(l.target_table)}${l.target_id?'#'+l.target_id:''}</td>
                <td class="text-muted fs-sm">${esc(l.old_value)}</td>
                <td class="text-muted fs-sm">${esc(l.new_value)}</td>
                <td class="text-muted fs-sm">${esc(l.ip_address)}</td>
                <td class="text-muted fs-sm">${esc(l.timestamp)}</td>
            </tr>`).join('') + `</tbody></table><p class="text-muted fs-sm" style="margin:8px 0">Total: ${data.total} entries</p>`;
    } catch { wrap.innerHTML = '<p class="text-muted">Error loading audit log.</p>'; }
};

// Security Events tab
window.loadSecurityEvents = async function() {
    try {
        const res  = await fetch('api/security_events.php', { headers: { 'X-IDS-Token': window.IDS_TOKEN || '' } });
        const data = await res.json();
        if (!data.ok) return;

        const fl = document.getElementById('sec-failed-logins');
        if (fl) {
            if (!data.failed_logins.length) { fl.innerHTML = '<p class="text-muted">No failed logins in last 24h.</p>'; }
            else fl.innerHTML = '<table><thead><tr><th>User</th><th>IP</th><th>Time</th></tr></thead><tbody>' +
                data.failed_logins.map(l => `<tr>
                    <td>${esc(l.username)}</td>
                    <td class="text-muted fs-sm">${esc(l.ip_address)}</td>
                    <td class="text-muted fs-sm">${esc(l.attempted_at)}</td>
                </tr>`).join('') + '</tbody></table>';
        }

        const la = document.getElementById('sec-locked-accounts');
        if (la) {
            if (!data.locked_accounts.length) { la.innerHTML = '<p class="text-muted" style="padding:8px">No locked accounts.</p>'; }
            else la.innerHTML = data.locked_accounts.map(a => `<div style="padding:8px 0;border-bottom:1px solid var(--border)">
                <strong>${esc(a.username)}</strong> — locked until <span class="text-attack">${esc(a.locked_until)}</span>
                <span class="text-muted fs-sm">(${a.failed_attempts} failed attempts)</span>
            </div>`).join('');
        }

        const rc = document.getElementById('sec-role-changes');
        if (rc) {
            if (!data.role_changes.length) { rc.innerHTML = '<p class="text-muted">No security events in last 24h.</p>'; }
            else rc.innerHTML = '<table><thead><tr><th>User</th><th>Action</th><th>Detail</th><th>IP</th><th>Time</th></tr></thead><tbody>' +
                data.role_changes.map(r => `<tr>
                    <td>${esc(r.username)}</td>
                    <td><span class="badge badge-warn">${esc(r.action)}</span></td>
                    <td class="text-muted fs-sm">${esc(r.new_value)}</td>
                    <td class="text-muted fs-sm">${esc(r.ip_address)}</td>
                    <td class="text-muted fs-sm">${esc(r.timestamp)}</td>
                </tr>`).join('') + '</tbody></table>';
        }

        const ss = document.getElementById('sec-stats');
        if (ss) ss.innerHTML = `
            <div style="padding:12px">
                <div class="metric-label">Active Sessions</div>
                <div class="metric-value accent">${data.active_sessions}</div>
            </div>
            <div style="padding:12px;border-top:1px solid var(--border)">
                <div class="metric-label">Pending Approvals</div>
                <div class="metric-value warn">${data.pending_actions}</div>
            </div>`;
    } catch(e) { console.error(e); }
};

// My Requests tab (analyst)
window.loadMyRequests = async function() {
    const el = document.getElementById('my-requests-list');
    if (!el) return;
    el.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    try {
        const res  = await fetch('api/pending_actions.php', { headers: { 'X-IDS-Token': window.IDS_TOKEN || '' } });
        const data = await res.json();
        if (!data.ok || !data.actions.length) { el.innerHTML = '<p class="text-muted">You have no submitted requests.</p>'; return; }
        el.innerHTML = '<table><thead><tr><th>#</th><th>Type</th><th>Description</th><th>Status</th><th>Reviewed by</th><th>Requested</th></tr></thead><tbody>' +
            data.actions.map(a => `<tr>
                <td>${a.action_id}</td>
                <td><span class="badge badge-warn">${esc(a.action_type)}</span></td>
                <td>${esc(a.description)}</td>
                <td><span class="badge ${a.status === 'pending' ? 'badge-warn' : a.status === 'approved' ? 'badge-benign' : 'badge-attack'}">${esc(a.status)}</span>
                ${a.status === 'rejected' && a.rejection_reason ? `<span class="text-muted fs-sm"> — ${esc(a.rejection_reason)}</span>` : ''}</td>
                <td class="text-muted fs-sm">${esc(a.reviewed_by || '—')}</td>
                <td class="text-muted fs-sm">${esc(a.requested_at)}</td>
            </tr>`).join('') + '</tbody></table>';
    } catch { el.innerHTML = '<p class="text-muted">Error loading requests.</p>'; }
};

// Poll pending count for admin badge
async function pollPendingBadge() {
    if (window.IDS_ROLE !== 'admin') return;
    try {
        const res  = await fetch('api/pending_actions.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
            body: JSON.stringify({ action: 'count' })
        });
        const data = await res.json();
        const badge = document.getElementById('pending-badge');
        if (badge) {
            if (data.count > 0) { badge.textContent = data.count; badge.style.display = 'inline'; }
            else { badge.style.display = 'none'; }
        }
    } catch {}
}

// Poll analyst notifications
async function pollMyNotifications() {
    if (window.IDS_ROLE !== 'analyst') return;
    try {
        const res  = await fetch('api/pending_actions.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': window.IDS_CSRF || '' },
            body: JSON.stringify({ action: 'my_notifications' })
        });
        const data = await res.json();
        if (data.notifications?.length) {
            data.notifications.forEach(n => {
                const msg = `Request #${n.action_id} (${n.action_type}) was ${n.status.toUpperCase()}` +
                    (n.status === 'rejected' && n.rejection_reason ? `: ${n.rejection_reason}` : '');
                // Use existing toast system from app.js
                if (typeof toast === 'function') toast(msg, n.status === 'approved' ? 'success' : 'error', 6000);
            });
        }
    } catch {}
}

// Tab switch handlers for new tabs
document.addEventListener('tabSwitched', function(e) {
    if (e.detail === 'pending-approvals') loadPendingApprovals();
    if (e.detail === 'audit-log')         loadAuditLog();
    if (e.detail === 'security-events')   loadSecurityEvents();
    if (e.detail === 'my-requests')       loadMyRequests();
});

// Start polling
document.addEventListener('DOMContentLoaded', function() {
    if (window.IDS_ROLE === 'admin') {
        pollPendingBadge();
        setInterval(pollPendingBadge, 60000);
    }
    if (window.IDS_ROLE === 'analyst') {
        pollMyNotifications();
        setInterval(pollMyNotifications, 30000);
    }
});
</script>
</body>
</html>
