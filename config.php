<?php

declare(strict_types=1);

/**
 * Remplacez les valeurs ci-dessous par celles de votre bot Telegram.
 * site_base_url : URL publique du site (HTTPS), sans slash final — obligatoire pour les boutons Telegram.
 *   Exemple : https://votredomaine.com
 *   Si vide, l’URL est déduite de la requête (souvent incorrect derrière un proxy ; préférez une URL fixe).
 */
return [
    'telegram_bot_token' => 'VOTRE_BOT_TOKEN',
    'telegram_chat_id' => 'VOTRE_CHAT_ID',
    'site_base_url' => '',
    /** Optionnel : URL HTTPS qui reçoit un POST JSON { event, ip, ... } (ex. Discord/Make.com). */
    'click_notify_webhook_url' => '',
];
