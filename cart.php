<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $errors = validate_form_security('cart', 1);
    $action = (string) ($_POST['action'] ?? '');
    $productId = (string) ($_POST['product_id'] ?? '');
    $product = find_product($productId);

    if ($product === null) {
        $errors[] = 'Produit introuvable.';
    }

    if (!$errors && $product !== null) {
        if ($action === 'add') {
            $quantity = max(1, min(10, (int) ($_POST['quantity'] ?? 1)));
            add_to_cart($productId, $quantity);
            flash('Produit ajoute au panier.');
        } elseif ($action === 'update') {
            $quantity = max(0, min(20, (int) ($_POST['quantity'] ?? 0)));
            update_cart_item($productId, $quantity);
            flash('Panier mis a jour.');
        } elseif ($action === 'remove') {
            update_cart_item($productId, 0);
            flash('Produit retire du panier.');
        } else {
            $errors[] = 'Action invalide.';
        }
    }

    if (!$errors) {
        redirect('cart.php');
    }
}

$cartItems = get_cart_items();
$pageTitle = 'Panier';
include __DIR__ . '/includes/header.php';
?>

<section class="page-heading">
    <p class="eyebrow">Panier</p>
    <h1>Votre selection</h1>
    <p>Modifiez les quantites avant de passer commande.</p>
</section>

<?php foreach ($errors as $error): ?>
    <div class="alert alert-error"><?php echo e($error); ?></div>
<?php endforeach; ?>

<?php if (!$cartItems): ?>
    <section class="empty-state">
        <h2>Votre panier est vide.</h2>
        <p>Ajoutez un produit pour demarrer votre commande.</p>
        <a class="button" href="products.php">Voir les produits</a>
    </section>
<?php else: ?>
    <section class="cart-layout">
        <div class="cart-list">
            <?php foreach ($cartItems as $item): ?>
                <article class="cart-item">
                    <div class="cart-product">
                        <div class="product-icon" aria-hidden="true"><?php echo e($item['product']['icon']); ?></div>
                        <div>
                            <h2><?php echo e($item['product']['name']); ?></h2>
                            <p><?php echo e($item['product']['description']); ?></p>
                            <strong><?php echo e(format_price($item['product']['price_cents'])); ?></strong>
                        </div>
                    </div>
                    <form class="quantity-form" method="post" action="cart.php">
                        <?php echo form_security_fields('cart'); ?>
                        <input type="hidden" name="action" value="update">
                        <input type="hidden" name="product_id" value="<?php echo e($item['product']['id']); ?>">
                        <label>
                            Quantite
                            <input type="number" name="quantity" min="0" max="20" value="<?php echo (int) $item['quantity']; ?>">
                        </label>
                        <button class="button button-small" type="submit">Mettre a jour</button>
                    </form>
                    <form method="post" action="cart.php">
                        <?php echo form_security_fields('cart'); ?>
                        <input type="hidden" name="action" value="remove">
                        <input type="hidden" name="product_id" value="<?php echo e($item['product']['id']); ?>">
                        <button class="link-button" type="submit">Retirer</button>
                    </form>
                    <strong class="line-total"><?php echo e(format_price($item['subtotal'])); ?></strong>
                </article>
            <?php endforeach; ?>
        </div>

        <aside class="summary-card">
            <h2>Resume</h2>
            <div class="summary-line">
                <span>Sous-total</span>
                <strong><?php echo e(format_price(cart_subtotal())); ?></strong>
            </div>
            <div class="summary-line">
                <span>Livraison</span>
                <strong><?php echo e(cart_shipping() === 0 ? 'Offerte' : format_price(cart_shipping())); ?></strong>
            </div>
            <div class="summary-line summary-total">
                <span>Total</span>
                <strong><?php echo e(format_price(cart_total())); ?></strong>
            </div>
            <a class="button button-full" href="checkout.php">Passer commande</a>
        </aside>
    </section>
<?php endif; ?>

<?php include __DIR__ . '/includes/footer.php'; ?>
