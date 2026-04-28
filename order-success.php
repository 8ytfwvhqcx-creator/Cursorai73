<?php
declare(strict_types=1);

$pageTitle = 'Commande confirmee';
require __DIR__ . '/includes/bootstrap.php';

$order = $_SESSION['last_order'] ?? null;
require __DIR__ . '/includes/header.php';
?>

<section class="page-heading">
    <p class="eyebrow">Merci</p>
    <h1>Votre commande est confirmee</h1>
    <p>Nous avons bien recu votre demande. Notre equipe vous recontactera pour finaliser le paiement et l'expedition.</p>
</section>

<?php if ($order === null): ?>
    <div class="alert alert-info">
        Aucune commande recente n'a ete trouvee dans cette session.
    </div>
<?php else: ?>
    <section class="panel confirmation">
        <h2>Recapitulatif</h2>
        <p><strong>Reference :</strong> <?php echo e((string) $order['reference']); ?></p>
        <p><strong>Client :</strong> <?php echo e((string) $order['name']); ?></p>
        <p><strong>Email :</strong> <?php echo e((string) $order['email']); ?></p>
        <p><strong>Total :</strong> <?php echo e(format_price((int) $order['total'])); ?></p>
        <a class="button" href="index.php">Retour a la boutique</a>
    </section>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
