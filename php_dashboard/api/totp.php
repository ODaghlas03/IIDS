<?php
/**
 * TOTP 2FA management
 * Users can set up TOTP; verification happens inside the login flow.
 */
require_once __DIR__ . '/../includes/config.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/security.php';
require_once __DIR__ . '/../includes/rbac.php';

security_headers();
header('Content-Type: application/json');
header('Cache-Control: no-cache');

$auth = require_role(ROLE_ADMIN, ROLE_ANALYST, ROLE_USER);

$data   = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $data['action'] ?? '';

// ── GET status ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $row = qdb("SELECT totp_enabled FROM users WHERE id=?", [$auth['user_id']]);
    echo json_encode([
        'ok'          => true,
        'totp_enabled'=> (bool)($row[0]['totp_enabled'] ?? false),
    ]);
    exit;
}

verify_csrf($auth);

// ── Generate a new TOTP secret (first step of setup) ─────────────────────
if ($action === 'generate') {
    $secret = totp_generate_secret();
    // Store secret temporarily (not yet enabled until confirmed)
    wdb("UPDATE users SET totp_secret=? WHERE id=?", [$secret, $auth['user_id']]);
    $uri = totp_qr_uri($secret, $auth['username']);
    echo json_encode([
        'ok'     => true,
        'secret' => $secret,
        'uri'    => $uri,
    ]);
    exit;
}

// ── Confirm TOTP code to enable 2FA ──────────────────────────────────────
if ($action === 'enable') {
    $code = sanitize_string($data['code'] ?? '', 10);
    $row  = qdb("SELECT totp_secret FROM users WHERE id=?", [$auth['user_id']]);
    if (!$row || !$row[0]['totp_secret']) {
        echo json_encode(['error' => 'No TOTP secret found. Generate one first.']); exit;
    }
    if (!totp_verify($row[0]['totp_secret'], $code)) {
        echo json_encode(['error' => 'Invalid TOTP code. Try again.']); exit;
    }
    wdb("UPDATE users SET totp_enabled=1 WHERE id=?", [$auth['user_id']]);
    audit_log($auth['username'], $auth['role'], '2FA_ENABLED', 'users',
        $auth['user_id'], '', '', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => '2FA enabled successfully.']);
    exit;
}

// ── Disable 2FA ────────────────────────────────────────────────────────────
if ($action === 'disable') {
    $code = sanitize_string($data['code'] ?? '', 10);
    $row  = qdb("SELECT totp_secret, totp_enabled FROM users WHERE id=?", [$auth['user_id']]);
    if (!$row || !$row[0]['totp_enabled']) {
        echo json_encode(['error' => '2FA is not enabled']); exit;
    }
    if (!totp_verify($row[0]['totp_secret'], $code)) {
        echo json_encode(['error' => 'Invalid TOTP code']); exit;
    }
    wdb("UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?", [$auth['user_id']]);
    audit_log($auth['username'], $auth['role'], '2FA_DISABLED', 'users',
        $auth['user_id'], '', '', $auth['user_id']);
    echo json_encode(['ok' => true, 'message' => '2FA disabled.']);
    exit;
}

echo json_encode(['error' => 'Unknown action']);
