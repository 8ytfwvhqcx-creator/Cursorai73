<?php

declare(strict_types=1);

$config = require dirname(__DIR__) . '/config.php';

function app_flow_dir(): string
{
    $dir = dirname(__DIR__) . '/data/flows';
    if (!is_dir($dir)) {
        mkdir($dir, 0700, true);
    }

    return $dir;
}

/**
 * @return array{pseudo: string, secret: string, phone: ?string, created: int}|null
 */
function app_flow_read(string $flowId): ?array
{
    $path = app_flow_dir() . '/' . preg_replace('/[^a-f0-9]/', '', $flowId) . '.json';
    if (!is_file($path)) {
        return null;
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        return null;
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || !isset($data['pseudo'], $data['secret'])) {
        return null;
    }

    return [
        'pseudo' => (string) $data['pseudo'],
        'secret' => (string) $data['secret'],
        'phone' => isset($data['phone']) ? (string) $data['phone'] : null,
        'created' => (int) ($data['created'] ?? 0),
    ];
}

/**
 * @param array{pseudo: string, secret: string, phone?: ?string, created: int} $data
 */
function app_flow_write(string $flowId, array $data): bool
{
    $safe = preg_replace('/[^a-f0-9]/', '', $flowId);
    $path = app_flow_dir() . '/' . $safe . '.json';
    $payload = json_encode($data, JSON_THROW_ON_ERROR);

    return file_put_contents($path, $payload, LOCK_EX) !== false;
}

function app_flow_delete(string $flowId): void
{
    $safe = preg_replace('/[^a-f0-9]/', '', $flowId);
    $path = app_flow_dir() . '/' . $safe . '.json';
    if (is_file($path)) {
        unlink($path);
    }
}

function app_new_flow_id(): string
{
    return bin2hex(random_bytes(16));
}

function app_new_secret(): string
{
    return bin2hex(random_bytes(16));
}

function app_base_url(): string
{
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && (string) $_SERVER['SERVER_PORT'] === '443');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $script = dirname($_SERVER['SCRIPT_NAME'] ?? '/');
    if ($script === '/' || $script === '\\' || $script === '.') {
        $script = '';
    }

    return $scheme . '://' . $host . $script;
}

/** URL publique du site (config en priorité), sans slash final. */
function app_public_base_url(): string
{
    global $config;
    $fromConfig = isset($config['site_base_url']) ? trim((string) $config['site_base_url']) : '';
    if ($fromConfig !== '') {
        return rtrim($fromConfig, '/');
    }

    return app_base_url();
}

function app_telegram_configured(): bool
{
    global $config;
    $token = (string) ($config['telegram_bot_token'] ?? '');
    $chatId = (string) ($config['telegram_chat_id'] ?? '');

    return $token !== '' && $token !== 'VOTRE_BOT_TOKEN'
        && $chatId !== '' && $chatId !== 'VOTRE_CHAT_ID';
}

/**
 * @param array<string, mixed> $body
 * @return array{ok: bool, data?: array<string, mixed>, error?: string}
 */
function app_telegram_send(array $body): array
{
    global $config;
    if (!app_telegram_configured()) {
        return ['ok' => false, 'error' => 'Configuration Telegram incomplète.'];
    }
    $token = (string) $config['telegram_bot_token'];
    $url = 'https://api.telegram.org/bot' . rawurlencode($token) . '/sendMessage';

    $json = json_encode($body, JSON_THROW_ON_ERROR);
    $ch = curl_init($url);
    if ($ch === false) {
        return ['ok' => false, 'error' => 'Impossible d\'initialiser la connexion.'];
    }
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $json,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT => 20,
    ]);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($response === false) {
        return ['ok' => false, 'error' => 'Erreur réseau.'];
    }
    $data = json_decode((string) $response, true);
    if ($httpCode !== 200 || !is_array($data) || ($data['ok'] ?? false) !== true) {
        $desc = is_array($data) ? (string) ($data['description'] ?? '') : '';

        return ['ok' => false, 'error' => $desc !== '' ? $desc : 'Échec Telegram.'];
    }

    return ['ok' => true, 'data' => $data];
}
