<?php
declare(strict_types=1);

require_once __DIR__ . '/products.php';
require_once __DIR__ . '/security.php';

start_secure_session();

function cart(): array
{
    return $_SESSION['cart'] ?? [];
}

function cart_count(): int
{
    return array_sum(array_map('intval', cart()));
}

function add_to_cart(string $productId, int $quantity): void
{
    if (find_product($productId) === null) {
        return;
    }

    $quantity = max(1, min(10, $quantity));
    $_SESSION['cart'] ??= [];
    $_SESSION['cart'][$productId] = min(99, (int) ($_SESSION['cart'][$productId] ?? 0) + $quantity);
}

function update_cart_item(string $productId, int $quantity): void
{
    if (find_product($productId) === null) {
        return;
    }

    $_SESSION['cart'] ??= [];
    $quantity = max(0, min(99, $quantity));

    if ($quantity === 0) {
        unset($_SESSION['cart'][$productId]);
        return;
    }

    $_SESSION['cart'][$productId] = $quantity;
}

function get_cart_items(): array
{
    $items = [];

    foreach (cart() as $productId => $quantity) {
        $product = find_product((string) $productId);
        if ($product === null) {
            continue;
        }

        $quantity = (int) $quantity;
        $items[] = [
            'product' => $product,
            'quantity' => $quantity,
            'subtotal' => $product['price_cents'] * $quantity,
        ];
    }

    return $items;
}

function cart_subtotal(): int
{
    return array_reduce(
        get_cart_items(),
        static fn (int $total, array $item): int => $total + $item['subtotal'],
        0
    );
}

function cart_shipping(): int
{
    $subtotal = cart_subtotal();

    if ($subtotal === 0 || $subtotal >= 9000) {
        return 0;
    }

    return 490;
}

function cart_total(): int
{
    return cart_subtotal() + cart_shipping();
}

function flash(string $message = '', string $type = 'success'): ?array
{
    if ($message !== '') {
        $_SESSION['flash'] = ['message' => $message, 'type' => $type];
        return null;
    }

    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);

    return $flash;
}

function flash_messages(): array
{
    $flash = flash();

    return $flash === null ? [] : [$flash];
}

function redirect(string $path): never
{
    header('Location: ' . $path);
    exit;
}
