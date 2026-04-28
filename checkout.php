<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

$cartItems = get_cart_items();

if (!$cartItems) {
    flash('Votre panier est vide.', 'error');
    redirect('cart.php');
}

$pageTitle = 'Commande';
$errors = [];
$fields = [
    'name' => '',
    'email' => '',
    'phone' => '',
    'address' => '',
    'city' => '',
    'postal_code' => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fields = [
        'name' => trim((string) ($_POST['name'] ?? '')),
        'email' => trim((string) ($_POST['email'] ?? '')),
        'phone' => trim((string) ($_POST['phone'] ?? '')),
        'address' => trim((string) ($_POST['address'] ?? '')),
        'city' => trim((string) ($_POST['city'] ?? '')),
        'postal_code' => trim((string) ($_POST['postal_code'] ?? '')),
    ];

    $errors = validate_form_security('checkout', 3);

    if ($fields['name'] === '' || strlen($fields['name']) < 2) {
        $errors[] = 'Le nom complet est obligatoire.';
    }

    if (!filter_var($fields['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'L adresse email est invalide.';
    }

    if ($fields['address'] === '') {
        $errors[] = 'L adresse de livraison est obligatoire.';
    }

    if ($fields['city'] === '') {
        $errors[] = 'La ville est obligatoire.';
    }

    if ($fields['postal_code'] === '') {
        $errors[] = 'Le code postal est obligatoire.';
    }

    if (!$errors) {
        $_SESSION['last_order'] = [
            'reference' => 'CMD-' . strtoupper(bin2hex(random_bytes(4))),
            'name' => $fields['name'],
            'email' => $fields['email'],
            'total' => cart_total(),
        ];

        clear_cart();
        redirect('order-success.php');
    }
}

require __DIR__ . '/includes/header.php';
?>

<section class="page-heading">
    <p class="eyebrow">Commande securisee</p>
    <h1>Finaliser votre achat</h1>
    <p>Les champs anti-bot sont invisibles pour les visiteurs, mais bloquent les soumissions automatiques les plus simples.</p>
</section>

<?php if ($errors): ?>
    <div class="alert alert-error" role="alert">
        <strong>Veuillez corriger :</strong>
        <ul>
            <?php foreach ($errors as $error): ?>
                <li><?= e($error) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<section class="checkout-layout">
    <form class="card form-card" method="post" action="checkout.php" novalidate>
        <?= form_security_fields('checkout') ?>

        <label>
            Nom complet
            <input type="text" name="name" value="<?= e($fields['name']) ?>" autocomplete="name" required>
        </label>

        <label>
            Email
            <input type="email" name="email" value="<?= e($fields['email']) ?>" autocomplete="email" required>
        </label>

        <label>
            Telephone
            <input type="tel" name="phone" value="<?= e($fields['phone']) ?>" autocomplete="tel">
        </label>

        <label>
            Adresse
            <input type="text" name="address" value="<?= e($fields['address']) ?>" autocomplete="street-address" required>
        </label>

        <div class="form-grid">
            <label>
                Ville
                <input type="text" name="city" value="<?= e($fields['city']) ?>" autocomplete="address-level2" required>
            </label>

            <label>
                Code postal
                <input type="text" name="postal_code" value="<?= e($fields['postal_code']) ?>" autocomplete="postal-code" required>
            </label>
        </div>

        <button class="button" type="submit">Confirmer la commande</button>
    </form>

    <aside class="card summary-card">
        <h2>Recapitulatif</h2>
        <?php foreach ($cartItems as $item): ?>
            <div class="summary-line">
                <span><?= e($item['product']['name']) ?> x <?= (int) $item['quantity'] ?></span>
                <strong><?= format_price($item['subtotal']) ?></strong>
            </div>
        <?php endforeach; ?>
        <div class="summary-line">
            <span>Livraison</span>
            <strong>Offerte</strong>
        </div>
        <div class="summary-line summary-total">
            <span>Total</span>
            <strong><?= format_price(cart_total()) ?></strong>
        </div>
    </aside>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
