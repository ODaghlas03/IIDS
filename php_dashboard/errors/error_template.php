<?php
/**
 * Shared error page renderer
 * Never exposes stack traces, file paths, DB errors, or framework details.
 */
function render_error(int $code, string $title, string $message): never {
    http_response_code($code);
    // Log full details server-side only
    error_log("[IIDS $code] $title — IP:" . ($_SERVER['REMOTE_ADDR'] ?? '?') .
              " URI:" . ($_SERVER['REQUEST_URI'] ?? '?'));
    ?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>IIDS — <?= (int)$code ?></title>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
        body{display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
        .err-box{text-align:center;padding:40px;max-width:480px}
        .err-code{font-size:80px;font-weight:700;opacity:.15;line-height:1}
        .err-title{font-size:22px;font-weight:600;margin:12px 0 8px}
        .err-msg{font-size:14px;opacity:.6;margin-bottom:24px}
    </style>
</head>
<body>
<div class="err-box">
    <div class="err-code"><?= (int)$code ?></div>
    <div class="err-title"><?= htmlspecialchars($title) ?></div>
    <div class="err-msg"><?= htmlspecialchars($message) ?></div>
    <a href="/" class="btn btn-primary">← Return to Dashboard</a>
</div>
</body>
</html>
    <?php
    exit;
}
