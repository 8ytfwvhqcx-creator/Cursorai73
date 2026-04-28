<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

$product = find_product((string) ($_GET['id'] ?? ''));

if ($product === null) {
    http_response_code(404);
    $pageTitle = 'Produit introuvable';
    require __DIR__ . '/includes/header.php';
    ?>
    <section class="panel">
        <p class="eyebrow">Erreur 404</p>
        <h1>Produit introuvable</h1>
        <p>Le produit demande n'existe pas ou n'est plus disponible.</p>
        <a class="button" href="products.php">Retour aux produits</a>
    </section>
    <?php
    require __DIR__ . '/includes/footer.php';
    exit;
}

$pageTitle = $product['name'];
require __DIR__ . '/includes/header.php';
?>

<article class="product-detail">
    <div class="product-visual product-visual-large" aria-hidden="true">
        <?php echo e($product['icon']); ?>
    </div>
    <div class="product-info">
        <p class="eyebrow"><?php echo e($product['category']); ?></p>
        <h1><?php echo e($product['name']); ?></h1>
        <p><?php echo e($product['description']); ?></p>
        <strong class="price"><?php echo format_price($product['price_cents']); ?></strong>

        <ul class="feature-list">
            <?php foreach ($product['features'] as $feature): ?>
                <li><?php echo e($feature); ?></li>
            <?php endforeach; ?>
        </ul>

        <form class="purchase-form" action="cart.php" method="post">
            <?php echo form_security_fields('cart'); ?>
            <input type="hidden" name="action" value="add">
            <input type="hidden" name="product_id" value="<?php echo e($product['id']); ?>">
            <label>
                Quantite
                <input type="number" name="quantity" value="1" min="1" max="10" required>
            </label>
            <button class="button" type="submit">Ajouter au panier</button>
        </form>
    </div>
</article>

<?php require __DIR__ . '/includes/footer.php'; ?>
