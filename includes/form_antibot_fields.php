<?php

declare(strict_types=1);

/** @var bool $requireMath default true */
$requireMath = $requireMath ?? true;
$hp = app_honeypot_field();
?>
<input type="hidden" name="_csrf" value="<?= htmlspecialchars(app_csrf_token(), ENT_QUOTES, 'UTF-8') ?>">
<div style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden" aria-hidden="true">
    <label for="<?= htmlspecialchars($hp, ENT_QUOTES, 'UTF-8') ?>">Ne pas remplir</label>
    <input type="text" name="<?= htmlspecialchars($hp, ENT_QUOTES, 'UTF-8') ?>" id="<?= htmlspecialchars($hp, ENT_QUOTES, 'UTF-8') ?>" value="" tabindex="-1" autocomplete="off">
</div>
<?php if ($requireMath) : ?>
    <label for="human_sum">Vérification anti-robot : combien font <?= htmlspecialchars(app_math_question_display(), ENT_QUOTES, 'UTF-8') ?> ?</label>
    <input type="text" name="human_sum" id="human_sum" inputmode="numeric" pattern="[0-9]*" maxlength="3" required autocomplete="off" style="margin-bottom:1rem">
<?php endif; ?>
