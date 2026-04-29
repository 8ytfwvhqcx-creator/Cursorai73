#!/usr/bin/env python3
"""
Scanner de fichiers .txt : détecte des clés AWS, SendGrid, Brevo, SMTP,
valide via les APIs / connexions, récupère le quota quand c'est possible,
et envoie un résumé sur Telegram (secrets masqués).
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


# --- Regex d'extraction (faux positifs possibles ; validation filtre) ---

RE_AWS_ACCESS = re.compile(
    r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16})\b"
)
RE_AWS_SECRET = re.compile(
    r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})\b",
    re.I,
)
RE_AWS_SECRET_LINE = re.compile(r"^[A-Za-z0-9/+=]{40}$")
# Secret seul sur une ligne (40 chars base64-like) proche d'une ligne AKIA — traité plus bas
RE_SENDGRID = re.compile(r"\b(SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")
RE_BREVO = re.compile(r"\b(xkeysib-[a-zA-Z0-9_-]+--[a-zA-Z0-9_-]+)\b")
RE_SMTP_HOST = re.compile(
    r"(?:SMTP_HOST|MAIL_HOST|smtp[_-]?host)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", re.I
)
RE_SMTP_PORT = re.compile(
    r"(?:SMTP_PORT|MAIL_PORT|smtp[_-]?port)\s*[=:]\s*['\"]?(\d+)['\"]?", re.I
)
RE_SMTP_USER = re.compile(
    r"(?:SMTP_USER|MAIL_USERNAME|smtp[_-]?user|SMTP_USERNAME)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", re.I
)
RE_SMTP_PASS = re.compile(
    r"(?:SMTP_PASS|SMTP_PASSWORD|MAIL_PASSWORD|smtp[_-]?pass)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?", re.I
)
# host:port:user:pass sur une ligne
RE_SMTP_COLON = re.compile(
    r"^[\s\"']*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}):(\d{2,5}):([^:]+):(.+)$", re.M
)


def mask_secret(s: str, keep: int = 4) -> str:
    if not s or len(s) <= keep:
        return "***"
    return f"…{s[-keep:]}"


def http_json(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 25,
) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            code = resp.getcode() or 200
            try:
                return code, json.loads(body)
            except json.JSONDecodeError:
                return code, body
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace")
            j = json.loads(err_body)
        except Exception:
            j = err_body or str(e)
        return e.code, j
    except Exception as e:
        return 0, {"error": str(e)}


def send_telegram_message(bot_token: str, chat_id: str, text: str) -> tuple[bool, str]:
    """Envoie un message via l'API Bot Telegram (pas un webhook custom)."""
    url = f"https://api.telegram.org/bot{urllib.parse.quote(bot_token)}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    data = urllib.parse.urlencode(payload).encode("utf-8")
    code, body = http_json(url, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data)
    if code == 200 and isinstance(body, dict) and body.get("ok"):
        return True, "OK"
    return False, str(body)[:500]


@dataclass
class Hit:
    kind: str
    source_file: str
    valid: bool
    detail: str
    quota: str = ""
    masked_id: str = ""

    def emoji_title(self) -> str:
        em = {
            "aws": "☁️",
            "sendgrid": "📧",
            "brevo": "🔵",
            "smtp": "📬",
        }
        return f"{em.get(self.kind, '✨')} Hit {self.kind.upper()}"


def iter_txt_files(root: Path) -> Iterator[Path]:
    for p in sorted(root.rglob("*.txt")):
        if p.is_file():
            yield p


def read_file_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def extract_aws_pairs(text: str) -> list[tuple[str, str]]:
    """Associe access key + secret quand le secret est étiqueté ou sur la ligne suivante."""
    pairs: list[tuple[str, str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        for m in RE_AWS_ACCESS.finditer(line):
            ak = m.group(1)
            # secret sur la même ligne
            sm = RE_AWS_SECRET.search(line)
            if sm:
                pairs.append((ak, sm.group(1)))
                continue
            # secret ligne suivante style AWS_SECRET_ACCESS_KEY=...
            if i + 1 < len(lines):
                nxt = lines[i + 1].strip()
                sm2 = RE_AWS_SECRET.search(lines[i + 1])
                if sm2:
                    pairs.append((ak, sm2.group(1)))
                elif RE_AWS_SECRET_LINE.match(nxt):
                    pairs.append((ak, nxt))
    # dédup
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for a, s in pairs:
        k = (a, s)
        if k not in seen:
            seen.add(k)
            out.append((a, s))
    return out


def extract_sendgrid_keys(text: str) -> list[str]:
    return list(dict.fromkeys(RE_SENDGRID.findall(text)))


def extract_brevo_keys(text: str) -> list[str]:
    return list(dict.fromkeys(RE_BREVO.findall(text)))


def extract_smtp_configs(text: str) -> list[dict[str, str]]:
    configs: list[dict[str, str]] = []
    for m in RE_SMTP_COLON.finditer(text):
        configs.append(
            {
                "host": m.group(1).strip(),
                "port": m.group(2).strip(),
                "user": m.group(3).strip(),
                "password": m.group(4).strip(),
            }
        )
    # Bloc style .env : collecter par proximity (premier host/user/pass trouvés)
    host_m = RE_SMTP_HOST.search(text)
    port_m = RE_SMTP_PORT.search(text)
    user_m = RE_SMTP_USER.search(text)
    pass_m = RE_SMTP_PASS.search(text)
    if host_m and user_m and pass_m:
        port = port_m.group(1) if port_m else "587"
        configs.append(
            {
                "host": host_m.group(1),
                "port": port,
                "user": user_m.group(1),
                "password": pass_m.group(1),
            }
        )
    # dédup simple
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, str]] = []
    for c in configs:
        t = (c["host"], c["port"], c["user"], c["password"])
        if t not in seen:
            seen.add(t)
            out.append(c)
    return out


def validate_sendgrid(api_key: str) -> tuple[bool, str, str]:
    code, body = http_json(
        "https://api.sendgrid.com/v3/user",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if code == 200 and isinstance(body, dict):
        email = body.get("email", "?")
        # crédits / plan
        q = ""
        c2, credits = http_json(
            "https://api.sendgrid.com/v3/user/credits",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        if c2 == 200 and isinstance(credits, dict):
            rem = credits.get("remain") or credits.get("total")
            if rem is not None:
                q = f"crédits: {json.dumps(credits)[:200]}"
        if not q:
            q = f"compte: {email}"
        return True, f"SendGrid OK — {email}", q
    return False, f"SendGrid HTTP {code}: {str(body)[:120]}", ""


def validate_brevo(api_key: str) -> tuple[bool, str, str]:
    code, body = http_json(
        "https://api.brevo.com/v3/account",
        headers={"api-key": api_key, "Accept": "application/json"},
    )
    if code == 200 and isinstance(body, dict):
        email = body.get("email", "?")
        plan = body.get("plan", [])
        credits = body.get("plan") or body.get("relay")
        q_parts = []
        if isinstance(plan, list) and plan:
            q_parts.append(f"plan: {plan[0].get('type', plan)}")
        # crédits marketing souvent dans marketingAutomation / credits restants selon doc
        for k in ("credits", "marketingAutomation", "sms"):
            if k in body and body[k]:
                q_parts.append(f"{k}: {str(body[k])[:80]}")
        q = " | ".join(q_parts) if q_parts else json.dumps({k: body[k] for k in ("email", "companyName") if k in body})[:200]
        return True, f"Brevo OK — {email}", q
    return False, f"Brevo HTTP {code}: {str(body)[:120]}", ""


def validate_aws(access_key: str, secret_key: str) -> tuple[bool, str, str]:
    try:
        import boto3  # type: ignore
        from botocore.exceptions import ClientError  # type: ignore
    except ImportError:
        return False, "Installez boto3: pip install -r requirements.txt", ""

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        )
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        arn = ident.get("Arn", "?")
        account = ident.get("Account", "?")
        quota_txt = ""
        try:
            ses = session.client("ses", region_name=os.environ.get("AWS_SES_REGION", "us-east-1"))
            q = ses.get_send_quota()
            quota_txt = (
                f"SES max24h={q.get('Max24HourSend')} sent24h={q.get('SentLast24Hours')} "
                f"rate={q.get('MaxSendRate')}/s"
            )
        except ClientError:
            try:
                sesv2 = session.client("sesv2", region_name=os.environ.get("AWS_SES_REGION", "us-east-1"))
                acc = sesv2.get_account()
                vd = acc.get("SendQuota", {})
                quota_txt = f"SESv2 max24h={vd.get('Max24HourSend')} sent={vd.get('SentLast24Hours')}"
            except ClientError as e2:
                quota_txt = f"STS OK (pas de quota SES lisible: {e2.response['Error']['Code']})"
        return True, f"AWS STS OK — compte {account} — {arn}", quota_txt
    except ClientError as e:
        return False, f"AWS: {e.response['Error']['Code']} — {e.response['Error'].get('Message', '')[:80]}", ""
    except Exception as e:
        return False, f"AWS erreur: {e}", ""


def validate_smtp(host: str, port: str, user: str, password: str) -> tuple[bool, str, str]:
    try:
        p = int(port)
    except ValueError:
        return False, "Port SMTP invalide", ""
    ctx = ssl.create_default_context()
    try:
        if p == 465:
            with smtplib.SMTP_SSL(host, p, context=ctx, timeout=20) as s:
                s.login(user, password)
        else:
            with smtplib.SMTP(host, p, timeout=20) as s:
                s.starttls(context=ctx)
                s.login(user, password)
        return True, f"SMTP login OK ({host}:{p})", "quota: N/A (serveur SMTP)"
    except smtplib.SMTPAuthenticationError as e:
        return False, f"SMTP auth refusée: {e.smtp_code}", ""
    except Exception as e:
        return False, f"SMTP: {e}", ""


def scan_folder(folder: Path) -> list[Hit]:
    hits: list[Hit] = []
    for fp in iter_txt_files(folder):
        text = read_file_text(fp)
        try:
            rel = str(fp.relative_to(folder))
        except ValueError:
            rel = str(fp)

        for ak, sk in extract_aws_pairs(text):
            ok, msg, q = validate_aws(ak, sk)
            hits.append(
                Hit(
                    kind="aws",
                    source_file=rel,
                    valid=ok,
                    detail=msg,
                    quota=q,
                    masked_id=mask_secret(ak, 6),
                )
            )

        for sg in extract_sendgrid_keys(text):
            ok, msg, q = validate_sendgrid(sg)
            hits.append(
                Hit(
                    kind="sendgrid",
                    source_file=rel,
                    valid=ok,
                    detail=msg,
                    quota=q,
                    masked_id=mask_secret(sg, 8),
                )
            )

        for bk in extract_brevo_keys(text):
            ok, msg, q = validate_brevo(bk)
            hits.append(
                Hit(
                    kind="brevo",
                    source_file=rel,
                    valid=ok,
                    detail=msg,
                    quota=q,
                    masked_id=mask_secret(bk, 10),
                )
            )

        for sm in extract_smtp_configs(text):
            ok, msg, q = validate_smtp(
                sm["host"], sm["port"], sm["user"], sm["password"]
            )
            hits.append(
                Hit(
                    kind="smtp",
                    source_file=rel,
                    valid=ok,
                    detail=msg,
                    quota=q,
                    masked_id=f"{sm['user']} @ {sm['host']}",
                )
            )

    return hits


def format_telegram_html(hits: list[Hit], folder: str) -> str:
    valid_hits = [h for h in hits if h.valid]
    lines = [
        "🎯 <b>Credential checker</b>",
        f"📁 <code>{html_escape(folder)}</code>",
        f"📊 Total hits: {len(hits)} — ✅ valides: {len(valid_hits)}",
        "",
    ]
    if not hits:
        lines.append("😶 Aucune clé détectée dans les .txt")
        return "\n".join(lines)

    for h in hits:
        status = "✅" if h.valid else "❌"
        lines.append(f"{h.emoji_title()} {status}")
        lines.append(f"   📄 {html_escape(h.source_file)}")
        lines.append(f"   🔑 <code>{html_escape(h.masked_id)}</code>")
        lines.append(f"   ℹ️ {html_escape(h.detail)}")
        if h.quota:
            lines.append(f"   📈 {html_escape(h.quota)}")
        lines.append("")
    return "\n".join(lines).strip()


def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def main() -> int:
    print("=== Checker AWS / SendGrid / Brevo / SMTP → Telegram ===\n")
    folder_s = input("Dossier à analyser (contenant des .txt) : ").strip().strip('"').strip("'")
    if not folder_s:
        print("Dossier vide.", file=sys.stderr)
        return 1
    root = Path(folder_s).expanduser().resolve()
    if not root.is_dir():
        print(f"Dossier introuvable: {root}", file=sys.stderr)
        return 1

    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if not token:
        token = input("Token bot Telegram (ou TELEGRAM_BOT_TOKEN dans l'env) : ").strip()
    if not chat:
        chat = input("Chat ID Telegram (ou TELEGRAM_CHAT_ID dans l'env) : ").strip()

    if not token or not chat:
        print("Token ou chat_id manquant — impossible d'envoyer sur Telegram.", file=sys.stderr)
        return 1

    print("\n⏳ Scan en cours…")
    hits = scan_folder(root)
    msg = format_telegram_html(hits, str(root))

    # Telegram limite ~4096 caractères
    if len(msg) > 4000:
        msg = msg[:3900] + "\n\n⚠️ <i>Message tronqué (trop long)</i>"

    print("\n📤 Envoi Telegram…")
    ok, err = send_telegram_message(token, chat, msg)
    if ok:
        print("✅ Message envoyé.")
    else:
        print(f"❌ Échec envoi: {err}", file=sys.stderr)
        return 1

    # Résumé console (sans secrets)
    print("\n--- Résumé ---")
    for h in hits:
        print(f"  [{h.kind}] {'OK' if h.valid else 'FAIL'} {h.source_file} {h.masked_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
