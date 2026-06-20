/* ========================================================
   IIDS Dashboard — app.js
   Vanilla JavaScript, no dependencies except Chart.js
   ======================================================== */

'use strict';

// ── State ────────────────────────────────────────────────
const state = {
    activeTab: 'live-feed',
    theme: localStorage.getItem('ids_theme') || 'dark',
    chatHistory: [],
    charts: {},
    refreshTimer: null,
    refreshCountdown: 20,
    countdownTimer: null,
    nlCallCount: 0,
    cycleList: [],
    selectedCycle: null,
    lastCycleNum: null,
    cycleAnimTimer: null,
};

// ── API Helper ───────────────────────────────────────────
async function api(endpoint, options = {}) {
    try {
        const headers = {
            'Content-Type': 'application/json',
            'X-IDS-Token':    window.IDS_TOKEN || '',
            'X-CSRF-Token':   window.IDS_CSRF  || '',
            ...(options.headers || {}),
        };
        const resp = await fetch('api/' + endpoint, { ...options, headers });
        if (resp.status === 401) {
            window.location.reload();
            return null;
        }
        if (resp.status === 429) {
            return { error: 'Too many requests. Please wait before retrying.' };
        }
        return await resp.json();
    } catch (err) {
        console.error('API error', endpoint, err);
        return { error: err.message };
    }
}

// ── Toast Notifications ──────────────────────────────────
function toast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), duration);
}

// ── Theme ────────────────────────────────────────────────
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ids_theme', theme);
    state.theme = theme;
    const btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = theme === 'dark' ? '☀ Light' : '☾ Dark';
    updateChartThemes();
}

function toggleTheme() {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
}

function updateChartThemes() {
    const gridColor = getComputedStyle(document.documentElement)
        .getPropertyValue('--chart-grid').trim();
    const textColor = getComputedStyle(document.documentElement)
        .getPropertyValue('--text-muted').trim();
    Object.values(state.charts).forEach(chart => {
        if (!chart) return;
        if (chart.options.scales) {
            Object.values(chart.options.scales).forEach(scale => {
                if (scale.grid) scale.grid.color = gridColor;
                if (scale.ticks) scale.ticks.color = textColor;
            });
        }
        if (chart.options.plugins?.legend?.labels) {
            chart.options.plugins.legend.labels.color = textColor;
        }
        chart.update('none');
    });
}

function cssVar(name) {
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// ── Tab Routing ──────────────────────────────────────────
function switchTab(tabId) {
    state.activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === 'tab-' + tabId);
    });
    document.dispatchEvent(new CustomEvent('tabSwitched', { detail: tabId }));
    // Load data for the new tab
    if (tabId === 'live-feed') loadLiveFeed();
    if (tabId === 'analytics') loadAnalytics();
    if (tabId === 'alerts') loadAlerts();
    if (tabId === 'reports') loadReports();
    if (tabId === 'nl-search') { /* static form, nothing to load */ }
    if (tabId === 'chat') { /* static form */ }
}

// ── Auto Refresh ─────────────────────────────────────────
function startRefresh() {
    stopRefresh();
    state.refreshCountdown = 20;
    updateCountdownUI();

    state.countdownTimer = setInterval(() => {
        state.refreshCountdown--;
        updateCountdownUI();
        if (state.refreshCountdown <= 0) {
            state.refreshCountdown = 20;
            refreshActiveTab();
        }
    }, 1000);
}

function stopRefresh() {
    clearInterval(state.refreshTimer);
    clearInterval(state.countdownTimer);
    state.refreshTimer = null;
    state.countdownTimer = null;
}

function refreshActiveTab() {
    if (state.activeTab === 'live-feed') loadLiveFeed();
    if (state.activeTab === 'analytics') loadAnalytics();
    if (state.activeTab === 'alerts') loadAlerts();
}

function updateCountdownUI() {
    const el = document.getElementById('refresh-countdown');
    if (el) el.textContent = state.refreshCountdown + 's';
}

// ── Format Helpers ───────────────────────────────────────
function fmtNum(n) {
    if (n == null) return '—';
    return Number(n).toLocaleString();
}

function fmtErr(v) {
    if (v == null) return '—';
    const f = parseFloat(v);
    const cls = f > 0.5 ? 'err-high' : f > 0.2 ? 'err-med' : 'err-low';
    return `<span class="${cls}">${f.toFixed(4)}</span>`;
}

function fmtTime(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-GB', { hour12: false });
    } catch { return ts; }
}

function fmtDateTime(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(ts);
        return d.toLocaleString('en-GB', { hour12: false });
    } catch { return ts; }
}

function attackTypeBadge(type) {
    if (!type) return '';
    const t = (type || '').toLowerCase();
    let cls = 'badge-attack';
    if (t.includes('ddos') || t.includes('dos')) cls = 'badge-ddos';
    else if (t.includes('scan') || t.includes('port')) cls = 'badge-scan';
    else if (t.includes('brute') || t.includes('ssh') || t.includes('ftp')) cls = 'badge-brute';
    else if (t.includes('bot')) cls = 'badge-bot';
    return `<span class="badge ${cls}">${esc(type)}</span>`;
}

function severityBadge(sev) {
    const s = (sev || '').toLowerCase();
    return `<span class="badge badge-${s}">${esc(sev || '—')}</span>`;
}

function verdictBadge(v) {
    if (!v) return '<span class="text-muted">—</span>';
    return `<span class="badge badge-verdict-${v}">${esc(v)}</span>`;
}

function esc(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ── Chart Helpers ────────────────────────────────────────
function getChartDefaults() {
    return {
        gridColor: cssVar('--chart-grid'),
        textColor: cssVar('--text-muted'),
        accent:    cssVar('--accent'),
        attack:    cssVar('--attack'),
        benign:    cssVar('--benign'),
        warn:      cssVar('--warn'),
    };
}

function destroyChart(key) {
    if (state.charts[key]) {
        state.charts[key].destroy();
        state.charts[key] = null;
    }
}

function upsertChart(key, canvasId, config) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    if (state.charts[key]) {
        // Update existing chart data
        const chart = state.charts[key];
        const newData = config.data;
        chart.data.labels = newData.labels;
        newData.datasets.forEach((ds, i) => {
            if (chart.data.datasets[i]) {
                chart.data.datasets[i].data = ds.data;
            }
        });
        chart.update();
        return;
    }
    state.charts[key] = new Chart(canvas, config);
}

// ── Live Feed Tab ─────────────────────────────────────────
async function loadLiveFeed() {
    const data = await api('metrics.php');
    if (!data || data.error) return;
    renderMetricCards(data);
    renderFlowsTable(data.flows || []);
    renderTopIps(data.top_ips || []);
    renderCyclePipeline(data);
    renderBlockedIps(data.blocked || []);
}

function renderMetricCards(data) {
    setEl('metric-total',   fmtNum(data.total));
    setEl('metric-attacks', fmtNum(data.attacks));
    setEl('metric-benign',  fmtNum(data.benign));
    setEl('metric-s2',      fmtNum(data.s2));
    setEl('metric-avgerr',  (data.avg_err || 0).toFixed(4));
    setEl('metric-rate',    (data.rate || 0) + '%');

    const dot = document.getElementById('status-dot');
    if (dot) {
        dot.classList.toggle('stopped', !!data.stopped);
        dot.title = data.stopped ? 'IDS stopped' : 'IDS running';
    }
}

function setEl(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function renderFlowsTable(flows) {
    const tbody = document.getElementById('flows-tbody');
    if (!tbody) return;
    if (!flows.length) {
        tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No flows yet</td></tr>';
        return;
    }
    tbody.innerHTML = flows.map(f => {
        const rowCls = f.attack ? 'row-attack' : '';
        const s2 = f.stage2 ? '<span class="badge badge-s2">S2</span>' : '';
        return `<tr class="${rowCls}">
            <td class="text-mono">${esc(f.id)}</td>
            <td class="text-mono">${esc(f.source_ip)}</td>
            <td class="text-mono">${esc(f.dest_ip)}</td>
            <td class="text-mono">${esc(f.dest_port)}</td>
            <td>${esc(f.protocol)}</td>
            <td>${fmtErr(f.reconstruction_error)}</td>
            <td>${f.attack ? attackTypeBadge(f.attack_type) : '<span class="badge badge-benign">Benign</span>'} ${s2}</td>
            <td>${verdictBadge(f.analyst_verdict)}</td>
        </tr>`;
    }).join('');
}

function renderTopIps(top_ips) {
    const list = document.getElementById('top-ips-list');
    if (!list) return;
    if (!top_ips.length) {
        list.innerHTML = '<li class="empty-state">No attack data yet</li>';
        return;
    }
    const max = top_ips[0]?.n || 1;
    list.innerHTML = top_ips.map(ip => {
        const pct = Math.round((ip.n / max) * 100);
        return `<li class="ip-bar-item">
            <span class="ip-addr">${esc(ip.source_ip)}</span>
            <div class="ip-bar-track"><div class="ip-bar-fill" style="width:${pct}%"></div></div>
            <span class="ip-count">${fmtNum(ip.n)}</span>
            <button class="btn btn-danger btn-sm" onclick="quickBlock('${esc(ip.source_ip)}')">Block</button>
        </li>`;
    }).join('');
}

function _drawCyclePipeline(stages, pct, cycleNum) {
    const labels = ['Capture', 'Convert', 'Analyze', 'Done'];
    const container = document.getElementById('cycle-stages');
    if (container) {
        container.innerHTML = (stages || ['waiting','waiting','waiting','waiting']).map((s, i) => {
            if (i === 0) {
                return `<div class="cycle-stage stage-${s} with-progress">
                    <div class="stage-top">
                        <span class="stage-dot ${s}"></span>
                        <span class="stage-label">${labels[i]}</span>
                    </div>
                    <div class="stage-cap-bar">
                        <div class="stage-cap-fill" id="cycle-progress-fill" style="width:0%"></div>
                    </div>
                </div>`;
            }
            return `<div class="cycle-stage stage-${s}">
                <span class="stage-dot ${s}"></span>
                <span class="stage-label">${labels[i]}</span>
            </div>`;
        }).join('');
    }
    // Animate width in next frame so CSS transition fires
    requestAnimationFrame(() => {
        const bar = document.getElementById('cycle-progress-fill');
        if (bar) bar.style.width = (pct || 0) + '%';
    });
    setEl('cycle-num', 'Cycle #' + (cycleNum || 0));
}

function renderCyclePipeline(data) {
    const newNum = data.cycle_num || 0;

    // When cycle_num increases a cycle just completed — animate through stages
    if (state.lastCycleNum !== null && newNum > state.lastCycleNum) {
        if (state.cycleAnimTimer) clearTimeout(state.cycleAnimTimer);
        const n = newNum;
        const anim = [
            { s: ['done','active','waiting','waiting'], p: 35,  d: 0    },
            { s: ['done','done','active','waiting'],    p: 65,  d: 700  },
            { s: ['done','done','done','active'],       p: 88,  d: 1400 },
            { s: ['done','done','done','done'],         p: 100, d: 2100 },
        ];
        anim.forEach(({ s, p, d }) => {
            state.cycleAnimTimer = setTimeout(() => _drawCyclePipeline(s, p, n), d);
        });
        // After animation settle back to real server state
        setTimeout(() => {
            _drawCyclePipeline(data.cycle_statuses, data.cycle_pct, n);
        }, 3200);
    } else if (state.cycleAnimTimer === null) {
        // No animation in flight — render server state directly
        _drawCyclePipeline(data.cycle_statuses, data.cycle_pct, newNum);
    }
    // else: animation is running, don't overwrite it

    state.lastCycleNum = newNum;

    const stopped = document.getElementById('cycle-stopped');
    if (stopped) stopped.style.display = data.stopped ? 'inline' : 'none';

    // Clear anim lock after it finishes
    if (state.cycleAnimTimer !== null) {
        setTimeout(() => { state.cycleAnimTimer = null; }, 3300);
    }
}

function renderBlockedIps(blocked) {
    const list = document.getElementById('blocked-list');
    if (!list) return;
    if (!blocked.length) {
        list.innerHTML = '<li style="color:var(--text-muted);font-size:0.82rem;padding:8px 0">No blocked IPs</li>';
        return;
    }
    list.innerHTML = blocked.map(b => `
        <li class="blocked-item">
            <span class="blocked-ip">${esc(b.ip)}</span>
            <span class="blocked-reason">${esc(b.reason)}</span>
            <span class="blocked-time">${fmtDateTime(b.blocked_at)}</span>
            <button class="btn btn-ghost btn-sm" onclick="unblockIp('${esc(b.ip)}')">Unblock</button>
        </li>`).join('');
}

async function quickBlock(ip) {
    const reason = prompt(`Block IP ${ip}?\nReason:`, 'Manual block from dashboard');
    if (reason === null) return;
    const data = await api('block.php', {
        method: 'POST',
        body: JSON.stringify({ action: 'block', ip, reason: reason || 'Manual block' }),
    });
    if (data?.ok) {
        toast(`IP ${ip} blocked`, 'success');
        loadLiveFeed();
    } else {
        toast(data?.error || 'Block failed', 'error');
    }
}

async function unblockIp(ip) {
    if (!confirm(`Unblock IP ${ip}?`)) return;
    const data = await api('block.php', {
        method: 'POST',
        body: JSON.stringify({ action: 'unblock', ip }),
    });
    if (data?.ok) {
        toast(`IP ${ip} unblocked`, 'success');
        loadLiveFeed();
    } else {
        toast(data?.error || 'Unblock failed', 'error');
    }
}

// ── Analytics Tab ─────────────────────────────────────────
async function loadAnalytics() {
    const panel = document.getElementById('tab-analytics');
    if (!panel) return;

    const data = await api('analytics.php');
    if (!data || data.error) {
        panel.innerHTML = `<div class="empty-state"><span class="icon">⚠</span>${data?.error || 'Failed to load analytics'}</div>`;
        return;
    }

    renderErrDistChart(data.err_dist);
    renderAttackTypeChart(data.attack_types);
    renderCyclesChart(data.cycles);
    renderProtocolChart(data.protocols);
    renderTrafficChart(data.traffic_comp);
    renderPortsChart(data.ports);
    renderTopAttackersTable(data.top_attackers);
}

function renderErrDistChart(dist) {
    if (!dist) return;
    const c = getChartDefaults();
    const benignErrs = dist.benign_errors || [];
    const attackErrs = dist.attack_errors || [];

    // Build histogram bins
    const allVals = [...benignErrs, ...attackErrs];
    if (!allVals.length) return;
    const maxVal = Math.max(...allVals);
    const bins = 40;
    const binSize = maxVal / bins;
    const labels = [];
    const benignCounts = new Array(bins).fill(0);
    const attackCounts = new Array(bins).fill(0);

    for (let i = 0; i < bins; i++) {
        labels.push((i * binSize).toFixed(3));
    }

    benignErrs.forEach(v => {
        const idx = Math.min(Math.floor(v / binSize), bins - 1);
        benignCounts[idx]++;
    });
    attackErrs.forEach(v => {
        const idx = Math.min(Math.floor(v / binSize), bins - 1);
        attackCounts[idx]++;
    });

    const threshold = dist.threshold;

    const canvas = document.getElementById('chart-err-dist');
    if (!canvas) return;

    destroyChart('errDist');
    state.charts['errDist'] = new Chart(canvas, {
        type: 'bar',
        data: {
            labels,
            datasets: [
                {
                    label: 'Benign',
                    data: benignCounts,
                    backgroundColor: c.benign + '88',
                    borderColor: c.benign,
                    borderWidth: 1,
                },
                {
                    label: 'Attack',
                    data: attackCounts,
                    backgroundColor: c.attack + '88',
                    borderColor: c.attack,
                    borderWidth: 1,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: c.textColor } },
                tooltip: { mode: 'index' },
                annotation: threshold ? {
                    annotations: {
                        threshold: {
                            type: 'line',
                            xMin: threshold,
                            xMax: threshold,
                            borderColor: c.warn,
                            borderWidth: 2,
                            label: { content: 'Threshold', enabled: true },
                        }
                    }
                } : {},
            },
            scales: {
                x: {
                    stacked: false,
                    grid: { color: c.gridColor },
                    ticks: { color: c.textColor, maxTicksLimit: 10 },
                    title: { display: true, text: 'Reconstruction Error', color: c.textColor },
                },
                y: {
                    grid: { color: c.gridColor },
                    ticks: { color: c.textColor },
                    title: { display: true, text: 'Flow Count', color: c.textColor },
                },
            },
        },
    });

    // Show threshold value
    setEl('threshold-val', threshold ? threshold.toFixed(4) : '—');
}

function renderAttackTypeChart(attack_types) {
    if (!attack_types?.length) return;
    const c = getChartDefaults();
    const colors = ['#ff4d6d','#ffb547','#00e5a0','#00d4ff','#b87fff','#ff9933','#7ec8e3','#ff6b8a','#a0d4ff','#ffd700'];

    upsertChart('attackType', 'chart-attack-types', {
        type: 'doughnut',
        data: {
            labels: attack_types.map(a => a.label),
            datasets: [{
                data: attack_types.map(a => a.count),
                backgroundColor: colors.slice(0, attack_types.length),
                borderWidth: 2,
                borderColor: cssVar('--surface'),
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: c.textColor, padding: 12, font: { size: 11 } },
                },
            },
            cutout: '60%',
        },
    });
}

function renderCyclesChart(cycles) {
    if (!cycles?.length) return;
    const c = getChartDefaults();
    upsertChart('cycles', 'chart-cycles', {
        type: 'bar',
        data: {
            labels: cycles.map(cy => '#' + cy.id),
            datasets: [
                { label: 'Attacks', data: cycles.map(cy => cy.attacks || 0), backgroundColor: c.attack + 'cc' },
                { label: 'Benign',  data: cycles.map(cy => cy.benign  || 0), backgroundColor: c.benign + 'cc' },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: c.textColor } } },
            scales: {
                x: { stacked: true, grid: { color: c.gridColor }, ticks: { color: c.textColor } },
                y: { stacked: true, grid: { color: c.gridColor }, ticks: { color: c.textColor } },
            },
        },
    });
}

function renderProtocolChart(protocols) {
    if (!protocols?.length) return;
    const c = getChartDefaults();
    const colors = [c.accent, c.benign, c.warn, c.attack, '#b87fff', '#7ec8e3'];
    upsertChart('protocol', 'chart-protocols', {
        type: 'doughnut',
        data: {
            labels: protocols.map(p => p.protocol || 'Unknown'),
            datasets: [{
                data: protocols.map(p => p.count),
                backgroundColor: colors.slice(0, protocols.length),
                borderWidth: 2,
                borderColor: cssVar('--surface'),
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { color: c.textColor, font: { size: 11 } } } },
            cutout: '55%',
        },
    });
}

function renderTrafficChart(traffic_comp) {
    if (!traffic_comp) return;
    const c = getChartDefaults();
    upsertChart('traffic', 'chart-traffic', {
        type: 'doughnut',
        data: {
            labels: ['Benign', 'Attack'],
            datasets: [{
                data: [traffic_comp.benign || 0, traffic_comp.attack || 0],
                backgroundColor: [c.benign + 'cc', c.attack + 'cc'],
                borderColor: [c.benign, c.attack],
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: c.textColor } },
                tooltip: {
                    callbacks: {
                        label: function(ctx) {
                            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const pct = total > 0 ? ((ctx.raw / total) * 100).toFixed(1) : 0;
                            return `${ctx.label}: ${ctx.raw.toLocaleString()} (${pct}%)`;
                        }
                    }
                },
            },
            cutout: '60%',
        },
    });
}

function renderPortsChart(ports) {
    if (!ports?.length) return;
    const c = getChartDefaults();
    upsertChart('ports', 'chart-ports', {
        type: 'bar',
        data: {
            labels: ports.map(p => 'Port ' + p.port),
            datasets: [{
                label: 'Attack Flows',
                data: ports.map(p => p.count),
                backgroundColor: c.attack + 'bb',
                borderColor: c.attack,
                borderWidth: 1,
            }],
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: c.gridColor }, ticks: { color: c.textColor } },
                y: { grid: { color: c.gridColor }, ticks: { color: c.textColor } },
            },
        },
    });
}

function renderTopAttackersTable(attackers) {
    const tbody = document.getElementById('top-attackers-tbody');
    if (!tbody) return;
    if (!attackers?.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No data</td></tr>';
        return;
    }
    tbody.innerHTML = attackers.map(a => `
        <tr>
            <td class="text-mono text-attack fw-600">${esc(a.source_ip)}</td>
            <td class="text-mono">${fmtNum(a.flows)}</td>
            <td class="text-mono">${fmtNum(a.ddos)}</td>
            <td class="text-mono">${fmtNum(a.scan)}</td>
            <td class="text-mono">${fmtNum(a.brute)}</td>
            <td class="text-mono">${fmtNum(a.bot)}</td>
            <td>${fmtErr(a.max_err)}</td>
        </tr>`).join('');
}

// ── Alerts Tab ────────────────────────────────────────────
async function loadAlerts() {
    const data = await api('alerts.php');
    if (!data || data.error) return;
    renderAlertsList(data.alerts || []);
}

function renderAlertsList(alerts) {
    const list = document.getElementById('alerts-list');
    if (!list) return;
    if (!alerts.length) {
        list.innerHTML = '<div class="empty-state"><span class="icon">✓</span>No alerts</div>';
        return;
    }
    list.innerHTML = alerts.map(a => {
        const sev = (a.severity || 'low').toLowerCase();
        const acked = a.acknowledged ? 'acknowledged' : '';
        const pcapBtn = a.pcap_file
            ? `<a href="api/pcap.php?file=${encodeURIComponent(a.pcap_file)}" class="btn btn-ghost btn-sm pcap-link" download>⬇ PCAP</a>`
            : '';
        const ackBtn = a.acknowledged
            ? `<span class="badge badge-benign" style="font-size:0.72rem">ACK</span>`
            : `<button class="btn btn-ghost btn-sm" onclick="ackAlert(${a.id})">Ack</button>`;
        const blockBtn = `<button class="btn btn-danger btn-sm" onclick="blockFromAlert('${esc(a.source_ip)}', ${a.id})">Block IP</button>`;

        return `<div class="alert-item ${acked}" id="alert-${a.id}">
            <div class="alert-severity ${sev}"></div>
            <div class="alert-body">
                <div class="alert-title">
                    ${severityBadge(a.severity)}
                    ${attackTypeBadge(a.attack_type)}
                    <span class="text-mono" style="margin-left:4px">${esc(a.source_ip)}</span>
                </div>
                <div class="alert-meta">
                    <span>Cycle #${esc(a.cycle_id)}</span>
                    <span>${fmtNum(a.flow_count)} flows</span>
                    <span>Max error: ${parseFloat(a.max_error || 0).toFixed(4)}</span>
                    <span>${fmtDateTime(a.created_at)}</span>
                    ${a.acknowledged ? `<span class="text-muted">Acked by ${esc(a.acknowledged_by)}</span>` : ''}
                </div>
            </div>
            <div class="alert-actions">
                ${pcapBtn}
                ${ackBtn}
                ${blockBtn}
            </div>
        </div>`;
    }).join('');
}

async function ackAlert(id) {
    const data = await api('alerts.php', {
        method: 'POST',
        body: JSON.stringify({ action: 'ack', id }),
    });
    if (data?.ok) {
        toast('Alert acknowledged', 'success');
        loadAlerts();
    } else {
        toast(data?.error || 'Failed', 'error');
    }
}

async function blockFromAlert(ip, alertId) {
    if (!confirm(`Block IP ${ip}?`)) return;
    const data = await api('alerts.php', {
        method: 'POST',
        body: JSON.stringify({ action: 'block', ip, alert_id: alertId }),
    });
    if (data?.ok) {
        toast(`IP ${ip} blocked`, 'success');
        loadAlerts();
    } else {
        toast(data?.error || 'Block failed', 'error');
    }
}

// ── NL Search Tab ─────────────────────────────────────────
function setupNLSearch() {
    const form = document.getElementById('nl-search-form');
    const input = document.getElementById('nl-query-input');
    const examples = document.querySelectorAll('.nl-example-btn');

    examples.forEach(btn => {
        btn.addEventListener('click', () => {
            if (input) input.value = btn.dataset.query;
        });
    });

    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();
            const query = input?.value?.trim();
            if (!query) return;
            await runNLQuery(query);
        });
    }
}

async function runNLQuery(query) {
    const sqlBlock = document.getElementById('nl-sql');
    const resultDiv = document.getElementById('nl-results');
    const submitBtn = document.getElementById('nl-submit-btn');

    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Thinking...'; }
    if (sqlBlock) sqlBlock.textContent = 'Generating SQL...';
    if (resultDiv) resultDiv.innerHTML = '<div class="loading"><div class="spinner"></div> Running query...</div>';

    const data = await api('nl_search.php', {
        method: 'POST',
        body: JSON.stringify({ query }),
    });

    if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Ask'; }

    if (!data || data.error) {
        if (sqlBlock) sqlBlock.textContent = data?.sql || '';
        if (resultDiv) resultDiv.innerHTML = `<div class="login-error visible">${esc(data?.error || 'Failed')}</div>`;
        return;
    }

    if (sqlBlock) sqlBlock.textContent = data.sql || '';
    if (resultDiv) {
        const callsInfo = `<div class="nl-result-info">${data.count} rows · ${data.calls_used}/${data.calls_used + data.calls_remaining} calls used today</div>`;
        if (!data.rows?.length) {
            resultDiv.innerHTML = callsInfo + '<div class="empty-state">No results</div>';
        } else {
            const cols = data.columns || [];
            const th = cols.map(c => `<th>${esc(c)}</th>`).join('');
            const tbody = data.rows.map(row =>
                '<tr>' + cols.map(c => `<td class="text-mono">${esc(row[c] ?? '')}</td>`).join('') + '</tr>'
            ).join('');
            resultDiv.innerHTML = callsInfo + `
                <div class="table-wrap">
                    <table><thead><tr>${th}</tr></thead><tbody>${tbody}</tbody></table>
                </div>`;
        }
    }
}

// ── Analyst Chat Tab ──────────────────────────────────────
function setupChat() {
    const form = document.getElementById('chat-form');
    const clearBtn = document.getElementById('chat-clear-btn');
    const input = document.getElementById('chat-input');

    if (form) {
        form.addEventListener('submit', async e => {
            e.preventDefault();
            const msg = input?.value?.trim();
            if (!msg) return;
            if (input) input.value = '';
            await sendChatMessage(msg);
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            state.chatHistory = [];
            const messages = document.getElementById('chat-messages');
            if (messages) messages.innerHTML = '<div class="chat-bubble bot">Hello! I\'m your IDS security analyst assistant. Ask me anything about network threats, attack patterns, or how to respond to incidents.</div>';
        });
    }

    // Ctrl+Enter to send
    if (input) {
        input.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                form?.dispatchEvent(new Event('submit'));
            }
        });
    }
}

async function sendChatMessage(message) {
    const messages = document.getElementById('chat-messages');
    const sendBtn = document.getElementById('chat-send-btn');
    if (!messages) return;

    // Add user bubble
    const userBubble = document.createElement('div');
    userBubble.className = 'chat-bubble user';
    userBubble.textContent = message;
    messages.appendChild(userBubble);

    // Typing indicator
    const typingEl = document.createElement('div');
    typingEl.className = 'chat-typing';
    typingEl.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
    messages.appendChild(typingEl);
    messages.scrollTop = messages.scrollHeight;

    if (sendBtn) sendBtn.disabled = true;

    const data = await api('chat.php', {
        method: 'POST',
        body: JSON.stringify({ message, history: state.chatHistory }),
    });

    typingEl.remove();
    if (sendBtn) sendBtn.disabled = false;

    const botBubble = document.createElement('div');
    if (data?.reply) {
        botBubble.className = 'chat-bubble bot';
        botBubble.textContent = data.reply;
        state.chatHistory.push({ role: 'user', content: message });
        state.chatHistory.push({ role: 'assistant', content: data.reply });
        // Keep history to last 20 turns
        if (state.chatHistory.length > 40) {
            state.chatHistory = state.chatHistory.slice(-40);
        }
    } else {
        botBubble.className = 'chat-bubble error';
        botBubble.textContent = data?.error || 'Error: could not get response';
    }
    messages.appendChild(botBubble);
    messages.scrollTop = messages.scrollHeight;
}

// ── Reports Tab ───────────────────────────────────────────
async function loadReports() {
    const data = await api('cycles.php');
    if (!data || data.error) return;
    state.cycleList = data.cycles || [];
    renderCycleDropdown(state.cycleList);
}

function renderCycleDropdown(cycles) {
    const select = document.getElementById('cycle-select');
    if (!select) return;
    select.innerHTML = '<option value="">— Select a cycle —</option>' +
        cycles.map(c => `<option value="${c.id}">Cycle #${c.id} — ${c.started_at || ''} (${c.attacks||0} attacks)</option>`).join('');
}

function setupReports() {
    const select = document.getElementById('cycle-select');
    const genBtn = document.getElementById('gen-report-btn');
    const dlBtn = document.getElementById('dl-report-btn');
    const verdictForm = document.getElementById('verdict-form');

    if (select) {
        select.addEventListener('change', async () => {
            const id = parseInt(select.value);
            if (!id) return;
            state.selectedCycle = id;
            showCycleSummary(id);
        });
    }

    if (genBtn) {
        genBtn.addEventListener('click', async () => {
            const id = state.selectedCycle;
            if (!id) { toast('Select a cycle first', 'info'); return; }
            genBtn.disabled = true;
            genBtn.textContent = 'Generating...';
            const data = await api('report.php', {
                method: 'POST',
                body: JSON.stringify({ cycle_id: id }),
            });
            genBtn.disabled = false;
            genBtn.textContent = 'Generate AI Report';
            if (data?.report) {
                const el = document.getElementById('report-output');
                if (el) el.textContent = data.report;
                if (dlBtn) dlBtn.style.display = 'inline-flex';
            } else {
                toast(data?.error || 'Report generation failed', 'error');
            }
        });
    }

    if (dlBtn) {
        dlBtn.addEventListener('click', () => {
            const el = document.getElementById('report-output');
            const text = el?.textContent || '';
            if (!text) return;
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `iids-report-cycle-${state.selectedCycle || 'unknown'}.txt`;
            a.click();
            URL.revokeObjectURL(url);
        });
    }

    if (verdictForm) {
        verdictForm.addEventListener('submit', async e => {
            e.preventDefault();
            const flowId = parseInt(document.getElementById('verdict-flow-id')?.value || 0);
            const verdict = document.querySelector('input[name="verdict"]:checked')?.value || '';
            const note = document.getElementById('verdict-note')?.value?.trim() || '';
            if (!flowId) { toast('Enter a Flow ID', 'info'); return; }
            const data = await api('verdict.php', {
                method: 'POST',
                body: JSON.stringify({ flow_id: flowId, verdict, note }),
            });
            if (data?.ok) {
                toast(`Verdict saved for flow #${flowId}`, 'success');
                verdictForm.reset();
            } else {
                toast(data?.error || 'Failed to save verdict', 'error');
            }
        });
    }
}

function showCycleSummary(cycleId) {
    const cycle = state.cycleList.find(c => c.id == cycleId);
    if (!cycle) return;

    const summaryEl = document.getElementById('cycle-summary');
    if (summaryEl) {
        summaryEl.innerHTML = `
            <div class="cycle-summary-item"><div class="label">Cycle</div><div class="value">#${esc(cycle.id)}</div></div>
            <div class="cycle-summary-item"><div class="label">Total Flows</div><div class="value">${fmtNum(cycle.total_flows)}</div></div>
            <div class="cycle-summary-item"><div class="label">Attacks</div><div class="value attack">${fmtNum(cycle.attacks)}</div></div>
            <div class="cycle-summary-item"><div class="label">Benign</div><div class="value benign">${fmtNum(cycle.benign)}</div></div>`;
        summaryEl.style.display = 'grid';
    }

    const pcapEl = document.getElementById('cycle-pcap');
    if (pcapEl) {
        if (cycle.pcap_file) {
            pcapEl.innerHTML = `<a href="api/pcap.php?file=${encodeURIComponent(cycle.pcap_file)}" class="btn btn-ghost btn-sm" download>⬇ Download PCAP: ${esc(cycle.pcap_file)}</a>`;
        } else {
            pcapEl.innerHTML = '<span class="text-muted fs-sm">No PCAP available</span>';
        }
    }

    const reportEl = document.getElementById('report-output');
    if (reportEl) reportEl.textContent = '';
    const dlBtn = document.getElementById('dl-report-btn');
    if (dlBtn) dlBtn.style.display = 'none';
}

// ── Logout ────────────────────────────────────────────────
async function logout() {
    await api('login.php', {
        method: 'POST',
        body: JSON.stringify({ action: 'logout' }),
    });
    window.location.reload();
}

// ── Block Form (Live Feed) ─────────────────────────────────
function setupBlockForm() {
    const form = document.getElementById('block-form');
    if (!form) return;
    form.addEventListener('submit', async e => {
        e.preventDefault();
        const ip = document.getElementById('block-ip-input')?.value?.trim();
        const reason = document.getElementById('block-reason-input')?.value?.trim() || 'Manual block';
        if (!ip) return;
        const data = await api('block.php', {
            method: 'POST',
            body: JSON.stringify({ action: 'block', ip, reason }),
        });
        if (data?.ok) {
            toast(`IP ${ip} blocked`, 'success');
            form.reset();
            loadLiveFeed();
        } else {
            toast(data?.error || 'Failed', 'error');
        }
    });
}

// ── Login Page ────────────────────────────────────────────
function setupLoginPage() {
    const loginForm   = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const loginTab    = document.getElementById('login-tab');
    const registerTab = document.getElementById('register-tab');
    const loginSection = document.getElementById('login-section');
    const registerSection = document.getElementById('register-section');

    if (loginTab) {
        loginTab.addEventListener('click', () => {
            loginTab.classList.add('active');
            registerTab?.classList.remove('active');
            loginSection?.classList.add('active');
            registerSection?.classList.remove('active');
        });
    }

    if (registerTab) {
        registerTab.addEventListener('click', () => {
            registerTab.classList.add('active');
            loginTab?.classList.remove('active');
            registerSection?.classList.add('active');
            loginSection?.classList.remove('active');
        });
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async e => {
            e.preventDefault();
            const username = document.getElementById('login-username')?.value?.trim();
            const password = document.getElementById('login-password')?.value;
            const errEl    = document.getElementById('login-error');
            const submitBtn = loginForm.querySelector('[type="submit"]');

            if (errEl) errEl.classList.remove('visible');
            if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Signing in...'; }

            const data = await api('login.php', {
                method: 'POST',
                body: JSON.stringify({ username, password }),
            });

            if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Sign In'; }

            if (data?.ok) {
                if (data.csrf_token) window.IDS_CSRF = data.csrf_token;
                window.location.reload();
            } else {
                if (errEl) {
                    errEl.textContent = data?.error || 'Login failed';
                    errEl.classList.add('visible');
                }
            }
        });
    }

    if (registerForm) {
        registerForm.addEventListener('submit', async e => {
            e.preventDefault();
            const username  = document.getElementById('reg-username')?.value?.trim();
            const password  = document.getElementById('reg-password')?.value;
            const password2 = document.getElementById('reg-password2')?.value;
            const errEl     = document.getElementById('register-error');
            const succEl    = document.getElementById('register-success');
            const submitBtn = registerForm.querySelector('[type="submit"]');

            if (errEl) errEl.classList.remove('visible');
            if (succEl) succEl.classList.remove('visible');
            if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = 'Creating...'; }

            const data = await api('login.php', {
                method: 'POST',
                body: JSON.stringify({ action: 'register', username, password, password2 }),
            });

            if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = 'Create Account'; }

            if (data?.ok) {
                if (succEl) { succEl.textContent = data.message || 'Account created!'; succEl.classList.add('visible'); }
                registerForm.reset();
                // Auto-switch to login tab
                setTimeout(() => loginTab?.click(), 1500);
            } else {
                if (errEl) { errEl.textContent = data?.error || 'Registration failed'; errEl.classList.add('visible'); }
            }
        });
    }
}

// ── Init ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    // Apply saved theme
    applyTheme(state.theme);

    // Theme toggle button
    const themeBtn = document.getElementById('theme-toggle');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    if (window.IDS_USER) {
        // Dashboard mode
        // Tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => switchTab(btn.dataset.tab));
        });

        // Logout button
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) logoutBtn.addEventListener('click', logout);

        // Setup static forms
        setupBlockForm();
        setupNLSearch();
        setupChat();
        setupReports();

        // Load initial tab
        loadLiveFeed();
        startRefresh();
    } else {
        // Login page mode
        setupLoginPage();
    }
});
