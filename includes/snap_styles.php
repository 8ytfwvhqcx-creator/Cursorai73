<?php

declare(strict_types=1);

$pageBackground = $pageBackground ?? '#FFFC00';

return <<<CSS
        * { box-sizing: border-box; }
        html { -webkit-text-size-adjust: 100%; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: {$pageBackground};
            padding: 1.25rem;
        }
        .card {
            width: 100%;
            max-width: 400px;
            background: #fff;
            border-radius: 28px;
            box-shadow: 0 16px 48px rgba(0, 0, 0, 0.1);
            padding: 2.25rem 1.85rem 1.85rem;
            text-align: center;
        }
        .logo-wrap {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 64px;
            height: 64px;
            background: #FFFC00;
            border-radius: 18px;
            margin-bottom: 0.85rem;
        }
        .snap-ghost {
            width: 40px;
            height: 40px;
            display: block;
        }
        .badge {
            display: inline-block;
            background: #000;
            color: #FFFC00;
            font-size: 0.68rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            padding: 0.4rem 0.85rem;
            border-radius: 999px;
            margin-bottom: 1.15rem;
        }
        .title { font-size: 1.35rem; font-weight: 800; color: #000; margin: 0 0 0.45rem; letter-spacing: -0.02em; }
        .subtitle { font-size: 0.95rem; color: #222; margin: 0 0 1.2rem; line-height: 1.45; }
        .intro {
            color: #444;
            font-size: 0.95rem;
            line-height: 1.55;
            margin: 0 0 1.35rem;
            text-align: center;
        }
        .pseudo-chip {
            font-size: 1.08rem;
            font-weight: 800;
            color: #000;
            margin: 0.35rem 0 1rem;
        }
        .profile-box {
            background: linear-gradient(180deg, #fffef5 0%, #fffce8 100%);
            border: 1.5px solid #ede682;
            border-radius: 20px;
            padding: 1.35rem 1rem;
            margin-bottom: 1.2rem;
        }
        .profile-box .snapcode {
            width: 76px;
            height: 76px;
            margin: 0 auto 0.65rem;
            background: #FFFC00;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        .profile-box .snapcode svg { width: 46px; height: 46px; }
        form { text-align: left; }
        label:not(.sr-only) { display: block; margin-bottom: 0.45rem; font-size: 0.82rem; font-weight: 600; color: #333; }
        .field-label-muted { color: #666; font-weight: 500; font-size: 0.8rem; }
        input[type="text"], input[type="tel"] {
            width: 100%;
            padding: 0.95rem 1.25rem;
            border: 1.5px solid #EEE685;
            border-radius: 999px;
            font-size: 1rem;
            margin-bottom: 1rem;
            background: #fff;
        }
        input::placeholder { color: #b0b0b0; }
        input:focus {
            outline: none;
            border-color: #E6DC5A;
            box-shadow: 0 0 0 3px rgba(255, 252, 0, 0.45);
        }
        .btn {
            width: 100%;
            padding: 1rem 1.25rem;
            border: none;
            border-radius: 999px;
            font-weight: 800;
            font-size: 0.92rem;
            letter-spacing: 0.06em;
            cursor: pointer;
            margin-bottom: 0.55rem;
        }
        .btn-primary { background: #FFFC00; color: #000; }
        .btn-secondary { background: #e8e8e8; color: #000; }
        .btn:hover { filter: brightness(0.98); }
        .btn:active { transform: scale(0.99); }
        .footer-secure {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.4rem;
            margin-top: 1.35rem;
            font-size: 0.78rem;
            color: #888;
        }
        .footer-secure svg { flex-shrink: 0; }
        .alert {
            border-radius: 999px;
            padding: 0.7rem 1rem;
            margin-bottom: 1rem;
            font-size: 0.88rem;
            text-align: center;
        }
        .alert-error { background: #ffe8e8; color: #b00020; }
        .alert-success { background: #e8f5e9; color: #1b5e20; }
        .otp-row {
            display: flex;
            gap: 0.45rem;
            justify-content: center;
            margin-bottom: 1.25rem;
            flex-wrap: nowrap;
        }
        .otp-row input {
            width: 2.55rem;
            height: 2.85rem;
            text-align: center;
            font-size: 1.2rem;
            font-weight: 800;
            margin: 0;
            padding: 0;
            border-radius: 14px;
            border: 1.5px solid #EEE685;
        }
        .form-loading { position: relative; pointer-events: none; opacity: 0.65; }
        .loading-overlay {
            display: none;
            position: fixed;
            inset: 0;
            z-index: 9999;
            align-items: center;
            justify-content: center;
            background: rgba(255, 252, 0, 0.92);
        }
        .loading-overlay.is-visible { display: flex; }
        .loading-box {
            background: #fff;
            padding: 1.6rem 2rem;
            border-radius: 24px;
            box-shadow: 0 16px 48px rgba(0,0,0,0.12);
            text-align: center;
        }
        .loading-spinner {
            width: 42px;
            height: 42px;
            margin: 0 auto 1rem;
            border: 4px solid #f0f0f0;
            border-top-color: #000;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .loading-text { font-weight: 800; color: #000; font-size: 0.95rem; letter-spacing: 0.02em; }
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }
        .antibot-math label { font-size: 0.8rem; color: #555; font-weight: 500; }
        .antibot-math input { margin-bottom: 0.85rem; }
CSS;
