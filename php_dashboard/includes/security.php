<?php
/**
 * Central security utilities
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

// ── Security Headers ──────────────────────────────────────────────────────
function security_headers(): void {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
    header("Content-Security-Policy: " .
        "default-src 'self'; " .
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; " .
        "style-src 'self' 'unsafe-inline'; " .
        "img-src 'self' data:; " .
        "font-src 'self'; " .
        "connect-src 'self'; " .
        "frame-ancestors 'none';"
    );
    if (HTTPS_ENABLED) {
        header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    }
}

// ── Rate Limiting ─────────────────────────────────────────────────────────
function check_rate_limit(string $key, int $max_per_minute): bool {
    $now    = time();
    $window = date('Y-m-d H:i', $now); // 1-minute window
    $row    = qdb("SELECT id, hit_count, window_start FROM rate_limits WHERE key_value=?", [$key]);

    if (!$row) {
        wdb("INSERT INTO rate_limits (key_value, hit_count, window_start) VALUES (?,1,?)",
            [$key, $window]);
        return true;
    }

    if ($row[0]['window_start'] !== $window) {
        // New window — reset counter
        wdb("UPDATE rate_limits SET hit_count=1, window_start=? WHERE key_value=?",
            [$window, $key]);
        return true;
    }

    $count = (int)$row[0]['hit_count'];
    if ($count >= $max_per_minute) {
        return false; // Rate limit exceeded
    }

    wdb("UPDATE rate_limits SET hit_count=hit_count+1 WHERE key_value=?", [$key]);
    return true;
}

function rate_limit_response(): never {
    http_response_code(429);
    header('Content-Type: application/json');
    header('Retry-After: 60');
    echo json_encode(['error' => 'Too many requests. Please wait before retrying.']);
    exit;
}

// ── Password Policy ───────────────────────────────────────────────────────
function validate_password(string $password, string $username = '', int $user_id = 0): array {
    $errors = [];

    if (strlen($password) < 12) {
        $errors[] = "Password must be at least 12 characters.";
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Password must contain at least one uppercase letter.";
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Password must contain at least one lowercase letter.";
    }
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Password must contain at least one number.";
    }
    if (!preg_match('/[!@#$%^&*()\-_=+\[\]{};:\'",.<>?\/\\|`~]/', $password)) {
        $errors[] = "Password must contain at least one special character.";
    }
    if ($username && stripos($password, $username) !== false) {
        $errors[] = "Password must not contain your username.";
    }

    // Check password history
    if ($user_id > 0 && empty($errors)) {
        $history = qdb(
            "SELECT password_hash FROM password_history WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            [$user_id, PASSWORD_HISTORY]
        );
        foreach ($history as $h) {
            $hash = str_replace('$2b$', '$2y$', $h['password_hash']);
            if (password_verify($password, $hash)) {
                $errors[] = "Password must not be one of your last " . PASSWORD_HISTORY . " passwords.";
                break;
            }
        }
    }

    return $errors;
}

// ── CSRF Protection ───────────────────────────────────────────────────────
function generate_csrf_token(): string {
    return bin2hex(random_bytes(32));
}

function verify_csrf_token(string $token, string $session_token): bool {
    if (!$token || !$session_token) return false;
    $rows = qdb("SELECT csrf_token FROM sessions WHERE token=?", [$session_token]);
    if (!$rows || !$rows[0]['csrf_token']) return false;
    return hash_equals($rows[0]['csrf_token'], $token);
}

// ── Input Validation / Injection Detection ────────────────────────────────
function detect_injection(string $input): bool {
    $patterns = [
        '/<script/i',
        '/javascript:/i',
        '/on\w+\s*=/i',
        '/--/',
        '/;\s*--/',
        '/union\s+select/i',
        '/drop\s+table/i',
        '/insert\s+into/i',
        '/delete\s+from/i',
        '/update\s+\w+\s+set/i',
        '/exec\s*\(/i',
        '/xp_cmdshell/i',
        '/\bor\b\s+1\s*=\s*1/i',
        '/\band\b\s+1\s*=\s*1/i',
        '/<\?php/i',
        '/base64_decode/i',
        '/eval\s*\(/i',
    ];
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) return true;
    }
    return false;
}

function sanitize_string(string $input, int $max_len = 1000): string {
    $input = trim($input);
    $input = substr($input, 0, $max_len);
    return $input;
}

function validate_ip(string $ip): bool {
    return (bool)filter_var($ip, FILTER_VALIDATE_IP);
}

// ── Data Encryption ───────────────────────────────────────────────────────
function encrypt_field(string $plaintext): string {
    if ($plaintext === '') return '';
    $key    = get_encryption_key();
    $iv     = random_bytes(16);
    $cipher = openssl_encrypt($plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if ($cipher === false) return '';
    return base64_encode($iv . $cipher);
}

function decrypt_field(string $ciphertext): string {
    if ($ciphertext === '') return '';
    $raw = base64_decode($ciphertext);
    if (strlen($raw) < 17) return '';
    $key    = get_encryption_key();
    $iv     = substr($raw, 0, 16);
    $cipher = substr($raw, 16);
    $plain  = openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $plain === false ? '' : $plain;
}

function mask_sensitive(string $value, int $show = 4): string {
    $len = strlen($value);
    if ($len <= $show) return str_repeat('*', $len);
    return str_repeat('*', $len - $show) . substr($value, -$show);
}

// ── Audit Logging ─────────────────────────────────────────────────────────
function audit_log(
    string $username,
    string $role,
    string $action,
    string $target_table = '',
    int    $target_id    = 0,
    string $old_value    = '',
    string $new_value    = '',
    int    $user_id      = 0
): void {
    $ip = get_client_ip();
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 512);
    wdb(
        "INSERT INTO audit_logs
            (user_id, username, role, action, target_table, target_id,
             old_value, new_value, ip_address, user_agent, timestamp)
         VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            $user_id ?: null,
            $username,
            $role,
            $action,
            $target_table,
            $target_id ?: null,
            $old_value,
            $new_value,
            $ip,
            $ua,
            date('Y-m-d H:i:s'),
        ]
    );
}

// ── Client IP Helper ─────────────────────────────────────────────────────
function get_client_ip(): string {
    // Trust X-Forwarded-For only if behind a known proxy; for direct access use REMOTE_ADDR
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// ── IP Allowlist Check ────────────────────────────────────────────────────
function ip_in_allowlist(string $ip): bool {
    $rows = qdb("SELECT ip_cidr FROM ip_allowlist WHERE active=1");
    if (!$rows) return true; // empty allowlist means no restriction
    foreach ($rows as $row) {
        if (ip_matches_cidr($ip, $row['ip_cidr'])) return true;
    }
    return false;
}

function ip_matches_cidr(string $ip, string $cidr): bool {
    if (!str_contains($cidr, '/')) {
        return $ip === $cidr;
    }
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;
    $ip_long  = ip2long($ip);
    $sub_long = ip2long($subnet);
    if ($ip_long === false || $sub_long === false) return false;
    $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
    return ($ip_long & $mask) === ($sub_long & $mask);
}

// ── TOTP ──────────────────────────────────────────────────────────────────
function totp_generate_secret(): string {
    $bytes = random_bytes(20);
    return base32_encode($bytes);
}

function totp_verify(string $secret, string $code, int $window = 1): bool {
    $key  = base32_decode($secret);
    $time = (int)floor(time() / 30);
    for ($i = -$window; $i <= $window; $i++) {
        if (totp_compute($key, $time + $i) === $code) return true;
    }
    return false;
}

function totp_compute(string $key, int $counter): string {
    $msg    = pack('N*', 0) . pack('N*', $counter);
    $hash   = hash_hmac('sha1', $msg, $key, true);
    $offset = ord($hash[19]) & 0x0f;
    $code   = (
        ((ord($hash[$offset])     & 0x7f) << 24) |
        ((ord($hash[$offset + 1]) & 0xff) << 16) |
        ((ord($hash[$offset + 2]) & 0xff) << 8)  |
        (ord($hash[$offset + 3])  & 0xff)
    ) % 1000000;
    return str_pad((string)$code, 6, '0', STR_PAD_LEFT);
}

function totp_qr_uri(string $secret, string $username): string {
    $label   = rawurlencode("IIDS:$username");
    $issuer  = rawurlencode('IIDS');
    return "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
}

function base32_encode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $output   = '';
    $buf      = 0;
    $bits     = 0;
    foreach (str_split($data) as $char) {
        $buf  = ($buf << 8) | ord($char);
        $bits += 8;
        while ($bits >= 5) {
            $bits   -= 5;
            $output .= $alphabet[($buf >> $bits) & 0x1f];
        }
    }
    if ($bits > 0) {
        $output .= $alphabet[($buf << (5 - $bits)) & 0x1f];
    }
    return $output;
}

function base32_decode(string $data): string {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $data     = strtoupper($data);
    $output   = '';
    $buf      = 0;
    $bits     = 0;
    foreach (str_split($data) as $char) {
        $val = strpos($alphabet, $char);
        if ($val === false) continue;
        $buf  = ($buf << 5) | $val;
        $bits += 5;
        if ($bits >= 8) {
            $bits   -= 8;
            $output .= chr(($buf >> $bits) & 0xff);
        }
    }
    return $output;
}

// ── Password History ─────────────────────────────────────────────────────
function save_password_history(int $user_id, string $hash): void {
    wdb("INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?,?,?)",
        [$user_id, $hash, date('Y-m-d H:i:s')]);
    // Keep only last PASSWORD_HISTORY entries
    wdb(
        "DELETE FROM password_history WHERE user_id=? AND id NOT IN (
            SELECT id FROM password_history WHERE user_id=? ORDER BY created_at DESC LIMIT ?
         )",
        [$user_id, $user_id, PASSWORD_HISTORY]
    );
}

// ── Admin Email Alert ────────────────────────────────────────────────────
function send_lockout_email(string $locked_username, string $ip): void {
    $admin_email = get_admin_email();
    if (!$admin_email) return;
    $subject = "IIDS: Account Locked — $locked_username";
    $body    = "Account '$locked_username' has been locked after " . MAX_LOGIN_ATTEMPTS .
               " failed login attempts from IP: $ip\n\nTime: " . date('Y-m-d H:i:s');
    @mail($admin_email, $subject, $body, "From: iids@localhost");
}

// ── Log cleanup helper ───────────────────────────────────────────────────
function cleanup_rate_limits(): void {
    // Remove entries older than 2 minutes to keep the table small
    $cutoff = date('Y-m-d H:i', time() - 120);
    wdb("DELETE FROM rate_limits WHERE window_start < ?", [$cutoff]);
}
