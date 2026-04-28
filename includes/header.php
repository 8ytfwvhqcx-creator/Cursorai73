<?php
$cartCount = cart_count();
$title = $pageTitle ?? 'Boutique PHP';
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="index, follow">
    <title><?php echo e($title); ?> - Boutique Sereine</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
    <header class="site-header">
        <nav class="nav container" aria-label="Navigation principale">
            <a class="brand" href="index.php">Boutique Sereine</a>
            <div class="nav-links">
                <a href="index.php">Accueil</a>
                <a href="products.php">Produits</a>
                <a href="cart.php">Panier <span class="badge"><?php echo (int) $cartCount; ?></span></a>
                <a href="contact.php">Contact</a>
            </div>
        </nav>
    </header>

    <main class="container page">
        <?php foreach (flash_messages() as $flash): ?>
            <div class="alert alert-<?php echo e($flash['type']); ?>" role="status">
                <?php echo e($flash['message']); ?>
            </div>
        <?php endforeach; ?>
