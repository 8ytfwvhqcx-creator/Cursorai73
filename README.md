# Mini boutique PHP anti-bot

Ce depot contient un petit site de vente PHP autonome : accueil, catalogue, fiche produit, panier, commande, confirmation et contact.

## Lancer en local

```bash
php -S localhost:8000
```

Ouvrez ensuite <http://localhost:8000>.

## Pages

- `index.php` : accueil et selection de produits.
- `products.php` : catalogue complet.
- `product.php?id=...` : fiche produit et ajout au panier.
- `cart.php` : panier, modification des quantites et suppression.
- `checkout.php` : formulaire de commande.
- `order-success.php` : confirmation de commande.
- `contact.php` : formulaire de contact.

## Protections anti-bot

Les formulaires utilisent :

- jeton CSRF par session ;
- champ honeypot invisible ;
- delai minimum avant soumission ;
- limite de tentatives par action et par session/IP ;
- validation serveur et echappement HTML.

Ces controles reduisent les robots basiques. Pour une boutique en production, ajoutez HTTPS, stockage en base de donnees, paiement securise, logs serveur et un service anti-fraude si necessaire.
