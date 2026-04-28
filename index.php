<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

$pageTitle = 'Accueil';
require __DIR__ . '/includes/header.php';
?>

<section class="hero">
    <div>
        <p class="eyebrow">Boutique en ligne</p>
        <h1>Vendez vos produits avec un site PHP simple et protege.</h1>
        <p>Catalogue, panier, formulaire de commande et controles anti-bot integres pour limiter les soumissions automatisees.</p>
        <div class="actions">
            <a class="button" href="products.php">Voir les produits</a>
            <a class="button button-light" href="contact.php">Nous contacter</a>
        </div>
    </div>
    <aside class="hero-card">
        <span class="badge">Anti-bot</span>
        <h2>CSRF + honeypot</h2>
        <p>Chaque formulaire sensible est protege par un jeton, un champ piege et une limite de tentatives.</p>
    </aside>
</section>

<section class="section">
    <div class="section-heading">
        <p class="eyebrow">Selection</p>
        <h2>Produits populaires</h2>
    </div>
    <div class="product-grid">
        <?php foreach (array_slice(all_products(), 0, 3) as $product): ?>
            <article class="product-card">
                <div class="product-icon" aria-hidden="true"><?php echo e($product['icon']); ?></div>
                <div>
                    <p class="eyebrow"><?php echo e($product['category']); ?></p>
                    <h3><?php echo e($product['name']); ?></h3>
                    <p><?php echo e($product['description']); ?></p>
                </div>
                <div class="product-footer">
                    <strong><?php echo e(format_price($product['price_cents'])); ?></strong>
                    <a href="product.php?id=<?php echo e($product['id']); ?>">Details</a>
                </div>
            </article>
        <?php endforeach; ?>
    </div>
</section>

<section class="trust-bar" aria-label="Avantages">
    <div>
        <strong>Simple</strong>
        <span>PHP sans framework</span>
    </div>
    <div>
        <strong>Responsive</strong>
        <span>Mobile et ordinateur</span>
    </div>
    <div>
        <strong>Protege</strong>
        <span>Anti-bot formulaire</span>
    </div>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
