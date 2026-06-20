<?php
define('DB_PATH',        '/home/ids/ids/ids.db');
define('LOG_PATH',       '/home/ids/ids/logs/ids.log');
define('PCAP_DIR',       '/home/ids/ids/pcaps');
define('THRESHOLD_FILE', '/home/ids/ids/models/threshold.json');
define('SESSION_TIMEOUT', 1800);   // 30 minutes
define('MAX_NL_CALLS',    20);
define('IDS_IFACE',      'enp0s3');
define('IDS_INTERVAL',   30);

// Security policy constants
define('BCRYPT_COST',         12);
define('MAX_LOGIN_ATTEMPTS',   5);
define('LOCKOUT_MINUTES',     15);
define('RATE_LIMIT_LOGIN',    10);
define('RATE_LIMIT_API',     100);
define('PASSWORD_HISTORY',     5);
define('HTTPS_ENABLED', false);      // Set true after SSL cert is installed

function get_api_key(): string {
    $env = @file_get_contents('/home/ids/ids/.env');
    if ($env && preg_match('/ANTHROPIC_API_KEY\s*=\s*(\S+)/', $env, $m)) {
        return trim($m[1]);
    }
    return getenv('ANTHROPIC_API_KEY') ?: '';
}

function get_encryption_key(): string {
    $env = @file_get_contents('/home/ids/ids/.env');
    if ($env && preg_match('/ENCRYPTION_KEY\s*=\s*(\S+)/', $env, $m)) {
        $k = base64_decode(trim($m[1]));
        if (strlen($k) >= 32) return substr($k, 0, 32);
    }
    // Derive from a site-specific constant — NOT secure without a proper key in .env
    return hash('sha256', 'iids-fallback-' . DB_PATH, true);
}

function get_admin_email(): string {
    $env = @file_get_contents('/home/ids/ids/.env');
    if ($env && preg_match('/ADMIN_EMAIL\s*=\s*(\S+)/', $env, $m)) {
        return trim($m[1]);
    }
    return '';
}
