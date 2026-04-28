<?php
declare(strict_types=1);

require __DIR__ . '/includes/bootstrap.php';

$pageTitle = 'Contact';
$errors = [];
$sent = false;
$fields = [
    'name' => '',
    'email' => '',
    'message' => '',
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fields = [
        'name' => trim((string) ($_POST['name'] ?? '')),
        'email' => trim((string) ($_POST['email'] ?? '')),
        'message' => trim((string) ($_POST['message'] ?? '')),
    ];

    $errors = validate_form_security('contact');
    if ($limit = rate_limit('contact', 3, 900)) {
        $errors[] = $limit;
    }
    if (strlen($fields['name']) < 2) {
        $errors[] = 'Votre nom est requis.';
    }
    if (!filter_var($fields['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Votre email est invalide.';
    }
    if (strlen($fields['message']) < 10) {
        $errors[] = 'Votre message doit contenir au moins 10 caracteres.';
    }

    if (!$errors) {
        $sent = true;
        $fields = ['name' => '', 'email' => '', 'message' => ''];
    }
}

require __DIR__ . '/includes/header.php';
?>

<section class="page-heading">
    <p class="eyebrow">Contact</p>
    <h1>Une question avant de commander ?</h1>
    <p>Envoyez-nous votre message. Le formulaire inclut les memes protections anti-bot que le tunnel d'achat.</p>
</section>

<?php if ($sent): ?>
    <div class="alert alert-success">Votre message a ete prepare. Branchez un service email pour l'envoyer reellement.</div>
<?php endif; ?>

<?php if ($errors): ?>
    <div class="alert alert-error">
        <strong>Veuillez corriger :</strong>
        <ul>
            <?php foreach ($errors as $error): ?>
                <li><?php echo e($error); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<section class="form-panel">
    <form method="post" action="contact.php" novalidate>
        <?php echo form_security_fields('contact'); ?>
        <label>
            Nom
            <input type="text" name="name" value="<?php echo e($fields['name']); ?>" autocomplete="name" required>
        </label>
        <label>
            Email
            <input type="email" name="email" value="<?php echo e($fields['email']); ?>" autocomplete="email" required>
        </label>
        <label>
            Message
            <textarea name="message" required><?php echo e($fields['message']); ?></textarea>
        </label>
        <button class="button" type="submit">Envoyer</button>
    </form>
</section>

<?php require __DIR__ . '/includes/footer.php'; ?>
