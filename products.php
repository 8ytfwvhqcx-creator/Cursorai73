<?php
declare(strict_types=1);

$pageTitle = 'Produits';
require __DIR__ . '/includes/bootstrap.php';
require __DIR__ . '/includes/header.php';
?>

<section class="page-heading">
    <p class="eyebrow">Catalogue</p>
    <h1>Tous nos produits</h1>
    <p>Une selection courte pour demarrer rapidement votre boutique PHP.</p>
</section>

<section class="product-grid">
    <?php foreach (all_products() as $product): ?>
        <article class="product-card">
            <div class="product-icon" aria-hidden="true"><?php echo e($product['icon']); ?></div>
            <div>
                <p class="eyebrow"><?php echo e($product['category']); ?></p>
                <h2><?php echo e($product['name']); ?></h2>
                <p><?php echo e($product['description']); ?></p>
            </div>
            <div class="card-footer">
                <strong><?php echo e(format_price($product['price_cents'])); ?></strong>
                <a class="button button-small" href="product.php?id=<?php echo e($product['id']); ?>">Voir</a>
            </div>
        </article>
    <?php endforeach; ?>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
