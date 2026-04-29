<?php

declare(strict_types=1);

$pageBackground = $pageBackground ?? 'linear-gradient(90deg, #FFFC00 0%, #fffef0 55%, #fffef5 100%)';

return <<<CSS
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: {$pageBackground};
            padding: 1.5rem;
        }
        .card {
            width: 100%;
            max-width: 380px;
            background: #fff;
            border-radius: 24px;
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.12);
            padding: 2rem 1.75rem 1.75rem;
            text-align: center;
        }
        .logo-wrap {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 56px;
            height: 56px;
            background: #FFFC00;
            border-radius: 14px;
            margin-bottom: 0.75rem;
        }
        .logo-wrap svg { width: 36px; height: 36px; }
        .badge {
            display: inline-block;
            background: #000;
            color: #FFFC00;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            padding: 0.35rem 0.75rem;
            border-radius: 999px;
            margin-bottom: 1.25rem;
        }
        .title { font-size: 1.35rem; font-weight: 700; color: #000; margin: 0 0 0.5rem; }
        .subtitle { font-size: 0.95rem; color: #222; margin: 0 0 1.25rem; line-height: 1.45; }
        .intro { color: #666; font-size: 0.95rem; line-height: 1.5; margin: 0 0 1rem; }
        .pseudo-chip {
            font-size: 1.05rem;
            font-weight: 700;
            color: #000;
            margin: 0.5rem 0 1rem;
        }
        .profile-box {
            background: #fffef0;
            border: 1px solid #ede682;
            border-radius: 16px;
            padding: 1.25rem 1rem;
            margin-bottom: 1.25rem;
        }
        .profile-box .snapcode {
            width: 72px;
            height: 72px;
            margin: 0 auto 0.75rem;
            background: #FFFC00;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .profile-box .snapcode svg { width: 44px; height: 44px; }
        form { text-align: left; }
        label { display: block; margin-bottom: 0.4rem; font-size: 0.85rem; color: #333; }
        input[type="text"], input[type="tel"] {
            width: 100%;
            padding: 0.85rem 1rem;
            border: 1px solid #ddd;
            border-radius: 12px;
            font-size: 1rem;
            margin-bottom: 1rem;
        }
        input::placeholder { color: #aaa; }
        input:focus {
            outline: none;
            border-color: #ccc;
            box-shadow: 0 0 0 3px rgba(255, 252, 0, 0.35);
        }
        .btn {
            width: 100%;
            padding: 0.95rem;
            border: none;
            border-radius: 16px;
            font-weight: 700;
            font-size: 0.95rem;
            letter-spacing: 0.04em;
            cursor: pointer;
            margin-bottom: 0.65rem;
        }
        .btn-primary { background: #FFFC00; color: #000; }
        .btn-secondary { background: #e8e8e8; color: #000; }
        .btn:hover { filter: brightness(0.97); }
        .footer-secure {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.35rem;
            margin-top: 1.25rem;
            font-size: 0.8rem;
            color: #888;
        }
        .footer-secure svg { flex-shrink: 0; }
        .alert {
            border-radius: 10px;
            padding: 0.65rem 0.85rem;
            margin-bottom: 1rem;
            font-size: 0.9rem;
            text-align: center;
        }
        .alert-error { background: #ffe8e8; color: #b00020; }
        .alert-success { background: #e8f5e9; color: #1b5e20; }
        .otp-row {
            display: flex;
            gap: 0.5rem;
            justify-content: center;
            margin-bottom: 1.25rem;
        }
        .otp-row input {
            width: 2.5rem;
            height: 2.75rem;
            text-align: center;
            font-size: 1.25rem;
            font-weight: 700;
            margin: 0;
            padding: 0;
        }
        .form-loading { position: relative; pointer-events: none; opacity: 0.65; }
        .loading-overlay {
            display: none;
            position: fixed;
            inset: 0;
            z-index: 9999;
            align-items: center;
            justify-content: center;
            background: rgba(255, 252, 0, 0.88);
        }
        .loading-overlay.is-visible { display: flex; }
        .loading-box {
            background: #fff;
            padding: 1.5rem 2rem;
            border-radius: 20px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.15);
            text-align: center;
        }
        .loading-spinner {
            width: 40px;
            height: 40px;
            margin: 0 auto 1rem;
            border: 4px solid #eee;
            border-top-color: #000;
            border-radius: 50%;
            animation: spin 0.75s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .loading-text { font-weight: 700; color: #000; font-size: 0.95rem; }
CSS;
