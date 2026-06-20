# New Dashboard — PHP / HTML / CSS / JavaScript

## Overview
The IIDS dashboard is a hardened web application built with PHP, HTML, CSS, and JavaScript. It now runs on HTTPS port **8443** (HTTP port 8080 redirects to 8443).

**Primary URL:** `https://192.168.56.101:8443`
**Fallback (redirects):** `http://192.168.56.101:8080`

---

## Technology Stack
| Component | Technology |
|---|---|
| Web server | Apache 2.4 + mod_ssl |
| Backend language | PHP 8.5 |
| Database access | PHP SQLite3 (parameterized queries only) |
| Frontend structure | HTML5 |
| Frontend styling | CSS3 (custom, dark/light themes via CSS variables) |
| Frontend logic | Vanilla JavaScript (ES6+) |
| Charts | Chart.js 4 (CDN) |
| AI integration | Anthropic API via PHP cURL |
| Authentication | bcrypt cost-12, account lockout, 2FA TOTP |
| Sessions | SQLite `sessions` table + CSRF tokens |
| Roles | admin / analyst / user (RBAC enforced server-side) |

---

## File Structure
```
/var/www/html/iids/
├── index.php                       ← Main page (login + dashboard)
├── .htaccess                       ← Security hardening: error pages, header rules
├── migrate_security.php            ← Run ONCE to set up security DB tables
├── includes/
│   ├── config.php                  ← Constants (timeouts, bcrypt cost, rate limits)
│   ├── db.php                      ← SQLite helpers: qdb(), wdb(), wdb_id()
│   ├── auth.php                    ← Session management, cookie helpers
│   ├── security.php                ← Rate limiting, CSRF, password policy, audit, TOTP
│   └── rbac.php                    ← require_role() RBAC middleware
├── api/
│   ├── login.php                   ← Login (lockout, rate limit, audit)
│   ├── metrics.php                 ← Live Feed data
│   ├── analytics.php               ← Chart data
│   ├── alerts.php                  ← Alerts (RBAC: view all roles; mutate admin/analyst)
│   ├── block.php                   ← Block/Unblock IP (admin=direct; analyst=pending)
│   ├── verdict.php                 ← Flow verdict (admin + analyst)
│   ├── nl_search.php               ← NL→SQL query (admin + analyst; protected tables blocked)
│   ├── chat.php                    ← AI chat (admin + analyst)
│   ├── report.php                  ← Incident report (admin + analyst)
│   ├── pcap.php                    ← PCAP download (admin + analyst)
│   ├── cycles.php                  ← Cycle list
│   ├── users.php                   ← User management (admin only)
│   ├── change_password.php         ← Password change (all roles; policy enforced)
│   ├── pending_actions.php         ← Analyst approval workflow
│   ├── audit_log.php               ← Audit log viewer (admin only, read-only)
│   ├── totp.php                    ← 2FA setup/verify
│   └── security_events.php         ← Security events dashboard (admin only)
├── errors/
│   ├── 400.php / 401.php / 403.php ← Custom error pages (no stack traces)
│   ├── 404.php / 429.php / 500.php
│   └── error_template.php
└── assets/
    ├── css/style.css               ← All styles (unchanged)
    └── js/app.js                   ← SPA logic + CSRF header injection
```

---

## Security Features (Added June 2026)

### Authentication (ST-04)
- bcrypt cost factor 12 for all passwords
- Account lockout after 5 failed attempts (15-minute lock)
- Failed attempts logged with timestamp, IP, user-agent
- Admin email alert on account lockout (configure `ADMIN_EMAIL` in `.env`)
- Session token is 64-character random hex; regenerated on every login

### Password Policy (ST-02)
- Minimum 12 characters
- Must contain: uppercase, lowercase, digit, special character
- Must not contain the username
- Must not match any of the last 5 passwords (stored hashed in `password_history`)

### RBAC — Three Roles (ST-05)
| Role | Permissions |
|------|-------------|
| **admin** | Full access; user creation/deletion; role assignment; approve/reject analyst actions; audit log; security events |
| **analyst** | View all attack data; run NL queries (attacks DB only); submit block/unblock requests (pending approval); AI chat/reports |
| **user** | Read-only access to Live Feed, Analytics, Alerts |

Role is **always re-fetched from the DB** on each request — stale session privilege escalation is impossible.

### Analyst Approval Workflow (ST-05 / Task 5)
- Analysts cannot directly execute block/unblock operations
- All destructive requests go to `pending_actions` table as **status=pending**
- Admin reviews in **Pending Approvals** tab — approve (executes) or reject (with reason)
- Analyst sees status in **My Requests** tab; notifications appear as toasts

### Session Management (ST-07)
- 30-minute inactivity timeout
- Session ID regenerated on every login (prevents fixation)
- CSRF token per session — sent as `X-CSRF-Token` header on all state-changing requests
- Cookies: `HttpOnly=true`, `SameSite=Strict`, `Secure=true` (when HTTPS enabled)
- Logout invalidates session server-side immediately

### Rate Limiting (ST-08)
- Login endpoint: max **10 requests/minute per IP** → HTTP 429
- All other API endpoints: max **100 requests/minute per user** → HTTP 429

### Input Validation (ST-06)
- All inputs sanitized and length-limited server-side
- Injection pattern detection (`<script`, `UNION SELECT`, `DROP TABLE`, etc.)
- SQL: parameterized queries only — zero raw string interpolation
- IP blocks use `escapeshellarg()` before passing to iptables
- Content-Security-Policy, X-Frame-Options, X-Content-Type-Options headers on every response

### Data Encryption (ST-09)
- HTTPS via self-signed cert (`/etc/apache2/ssl/iids/iids.crt`)
- HTTP → HTTPS 301 redirect
- HSTS header: `max-age=31536000; includeSubDomains`
- AES-256-CBC for sensitive field encryption (key in `.env`)
- Passwords: bcrypt only — never stored or logged in plaintext

### Audit Logging (ST-12 / Task 12)
Every login, logout, failed login, user creation, deletion, role change, password change, NL query, verdict, block action, and approval/rejection is written to `audit_logs`. Logs are **read-only** — no API route allows editing or deleting them. Admin views them in the **Audit Log** tab.

### 2FA (ST-13)
- TOTP (RFC 6238 / Google Authenticator compatible)
- Setup: click 🔐 **2FA** button in sidebar → get secret key → enter in authenticator app → confirm with 6-digit code
- Standard 30-second TOTP window with ±1 window tolerance

### Error Handling (ST-12 / Task 11)
- Custom error pages for 400, 401, 403, 404, 429, 500 — no stack traces, no file paths
- All PHP errors suppressed from browser output (`display_errors=off`)
- Full error details logged to Apache error log only

---

## Setup After Fresh Install

```bash
# 1. Run DB migration (adds all security tables/columns)
php /var/www/html/iids/migrate_security.php

# 2. Enable HTTPS
sudo a2enmod ssl rewrite headers
sudo a2ensite iids-ssl
sudo systemctl restart apache2

# 3. Update config.php — set HTTPS_ENABLED to true after SSL is working
# define('HTTPS_ENABLED', true);

# 4. Add ENCRYPTION_KEY to /home/ids/ids/.env (auto-added by migration if .env exists)
# ENCRYPTION_KEY=<base64-encoded-32-bytes>

# 5. Change the default admin password from the dashboard (🔑 Password button)
```

---

## Default Login
`admin` / `Admin@IIDS2024!`

> Password policy enforced: minimum 12 characters, must contain uppercase, lowercase, digit, and special character.

---

## Key Bug Fixes
- bcrypt `$2b$` → `$2y$` normalisation: still applied in login.php
- WAL: `$db->busyTimeout(5000)` — do NOT set PRAGMA WAL from PHP
- Apache `ProtectHome=no` override: still required for DB access from `/home/ids/`
