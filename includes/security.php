<?php
declare(strict_types=1);

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    session_name('boutique_antibot');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();

    if (empty($_SESSION['session_started'])) {
        session_regenerate_id(true);
        $_SESSION['session_started'] = time();
    }
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function client_ip_hash(): string
{
    return sha1((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf_token'];
}

function form_security_fields(string $formName): string
{
    $_SESSION['form_started_' . $formName] = time();

    return implode("\n", [
        '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">',
        '<input type="hidden" name="form_name" value="' . e($formName) . '">',
        '<input type="hidden" name="form_started" value="' . e((string) $_SESSION['form_started_' . $formName]) . '">',
        '<div class="honeypot" aria-hidden="true">',
        '    <label>Site web<input type="text" name="website" tabindex="-1" autocomplete="off"></label>',
        '</div>',
    ]);
}

function validate_form_security(string $formName, int $minimumSeconds = 2): array
{
    $errors = [];
    $postedToken = (string) ($_POST['csrf_token'] ?? '');

    if ($postedToken === '' || !hash_equals((string) ($_SESSION['csrf_token'] ?? ''), $postedToken)) {
        $errors[] = 'Session expiree ou formulaire invalide. Rechargez la page.';
    }

    if ((string) ($_POST['form_name'] ?? '') !== $formName) {
        $errors[] = 'Formulaire non reconnu.';
    }

    if (trim((string) ($_POST['website'] ?? '')) !== '') {
        $errors[] = 'Soumission bloquee par la protection anti-bot.';
    }

    $postedStarted = filter_input(INPUT_POST, 'form_started', FILTER_VALIDATE_INT);
    $sessionStarted = $_SESSION['form_started_' . $formName] ?? null;

    if (!$postedStarted || !$sessionStarted || (int) $sessionStarted !== $postedStarted) {
        $errors[] = 'Verification anti-bot impossible.';
    } elseif (time() - $postedStarted < $minimumSeconds) {
        $errors[] = 'Formulaire envoye trop vite. Merci de patienter quelques secondes.';
    }

    return $errors;
}

function rate_limit(string $action, int $maxAttempts = 8, int $windowSeconds = 300): ?string
{
    $key = 'rate_' . $action . '_' . client_ip_hash();
    $now = time();
    $attempts = $_SESSION[$key] ?? [];
    $attempts = array_values(array_filter(
        $attempts,
        static fn (int $timestamp): bool => $timestamp > $now - $windowSeconds
    ));

    if (count($attempts) >= $maxAttempts) {
        $_SESSION[$key] = $attempts;
        return 'Trop de tentatives. Reessayez dans quelques minutes.';
    }

    $attempts[] = $now;
    $_SESSION[$key] = $attempts;

    return null;
}
