<?php
declare(strict_types=1);

function all_products(): array
{
    return [
        'sac-urbain' => [
            'id' => 'sac-urbain',
            'name' => 'Sac urbain',
            'category' => 'Accessoire',
            'icon' => 'BAG',
            'price_cents' => 5990,
            'description' => 'Un sac resistant et elegant pour le travail, les cours ou les sorties.',
            'features' => ['Compartiment ordinateur', 'Tissu deperlant', 'Poche antivol'],
        ],
        'montre-minimaliste' => [
            'id' => 'montre-minimaliste',
            'name' => 'Montre minimaliste',
            'category' => 'Mode',
            'icon' => 'WATCH',
            'price_cents' => 8900,
            'description' => 'Une montre sobre avec bracelet confortable et cadran epure.',
            'features' => ['Bracelet cuir', 'Verre mineral', 'Garantie 2 ans'],
        ],
        'casque-audio' => [
            'id' => 'casque-audio',
            'name' => 'Casque audio',
            'category' => 'High-tech',
            'icon' => 'AUDIO',
            'price_cents' => 12990,
            'description' => 'Son clair, coussinets doux et autonomie confortable pour le quotidien.',
            'features' => ['Bluetooth', 'Autonomie 30h', 'Micro integre'],
        ],
        'lampe-design' => [
            'id' => 'lampe-design',
            'name' => 'Lampe design',
            'category' => 'Maison',
            'icon' => 'LIGHT',
            'price_cents' => 4450,
            'description' => 'Une lampe moderne pour creer une ambiance chaleureuse a la maison.',
            'features' => ['LED basse consommation', 'Intensite douce', 'Base stable'],
        ],
    ];
}

function find_product(string $id): ?array
{
    $products = all_products();

    return $products[$id] ?? null;
}

function format_price(int $cents): string
{
    return number_format($cents / 100, 2, ',', ' ') . ' EUR';
}
