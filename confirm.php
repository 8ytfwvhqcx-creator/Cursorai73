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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = isset($_POST['action']) ? (string) $_POST['action'] : '';
    if ($action === 'oui') {
        header('Location: phone.php', true, 302);
        exit;
    }
    if ($action === 'non') {
        app_flow_delete($flowId);
        unset($_SESSION['flow_id'], $_SESSION['flow_secret']);
        header('Location: index.php', true, 302);
        exit;
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
    <title>Confirmer votre profil — Snap+</title>
    <style><?= $css ?></style>
</head>
<body>
    <div class="card">
        <h1 class="title">Confirmez votre profil</h1>
        <p class="subtitle">Est-ce bien votre profil Snapchat ?</p>

        <div class="profile-box">
            <div class="snapcode" aria-hidden="true">
                <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
                    <path fill="#fff" stroke="#000" stroke-width="2.5" d="M50 8 C28 8 12 28 12 48 c0 8 3 16 8 22 C12 78 8 88 8 92 h84 c0-4-4-14-12-22 5-6 8-14 8-22 C88 28 72 8 50 8z M38 58 c4 6 10 10 12 10 s8-4 12-10"/>
                </svg>
            </div>
            <p class="pseudo-chip" style="margin:0"><?= htmlspecialchars($display, ENT_QUOTES, 'UTF-8') ?></p>
        </div>

        <form method="post" action="">
            <button type="submit" class="btn btn-primary" name="action" value="oui">OUI</button>
            <button type="submit" class="btn btn-secondary" name="action" value="non">NON</button>
        </form>
    </div>
</body>
</html>
