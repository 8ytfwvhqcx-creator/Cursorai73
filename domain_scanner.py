#!/usr/bin/env python3
"""
Scanner HTTP sur un domaine : teste une liste de chemins et signale des indices
AWS, SendGrid ou Brevo dans le corps ou les en-têtes de réponse.

Usage réservé aux systèmes dont vous êtes propriétaire ou pour lesquels vous
avez une autorisation écrite explicite. L'usage non autorisé est illégal.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# Clés AWS long terme (AKIA...) et session (ASIA...)
_RE_AWS_AKIA = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_RE_AWS_ASIA = re.compile(r"\b(ASIA[0-9A-Z]{16})\b")
_RE_AWS_SECRET = re.compile(
    r"(?i)(aws_secret_access_key|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)
_RE_AWS_ACCESS_LABEL = re.compile(
    r"(?i)(aws_access_key_id|access_key_id)\s*[=:]\s*['\"]?([A-Z0-9]{20})['\"]?"
)

# SendGrid API v3
_RE_SENDGRID = re.compile(r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b")
_RE_SENDGRID_LABEL = re.compile(r"(?i)(sendgrid[_-]?api[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?")

# Brevo (ex-Sendinblue)
_RE_BREVO = re.compile(r"\b(xkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16})\b")
_RE_BREVO_SMTP = re.compile(r"(?i)(smtp-relay\.brevo\.com|api\.brevo\.com)")


def redact_token(s: str, keep: int = 6) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return "***"
    return f"{s[:keep]}…{s[-keep:]}"


@dataclass
class Finding:
    kind: str
    detail: str
    redacted: str


@dataclass
class ScanResult:
    url: str
    status: int | None
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)


def analyze_text(text: str, headers: str) -> list[Finding]:
    findings: list[Finding] = []
    blob = text + "\n" + headers

    for m in _RE_AWS_AKIA.finditer(blob):
        findings.append(Finding("aws_access_key_id", m.group(1), redact_token(m.group(1))))
    for m in _RE_AWS_ASIA.finditer(blob):
        findings.append(Finding("aws_session_access_key_id", m.group(1), redact_token(m.group(1))))
    for m in _RE_AWS_SECRET.finditer(blob):
        findings.append(Finding("aws_secret_access_key", m.group(2), redact_token(m.group(2))))
    for m in _RE_AWS_ACCESS_LABEL.finditer(blob):
        findings.append(Finding("aws_access_key_id_labeled", m.group(2), redact_token(m.group(2))))

    for m in _RE_SENDGRID.finditer(blob):
        findings.append(Finding("sendgrid_api_key", m.group(1), redact_token(m.group(1))))
    for m in _RE_SENDGRID_LABEL.finditer(blob):
        findings.append(Finding("sendgrid_labeled", m.group(2), redact_token(m.group(2))))

    for m in _RE_BREVO.finditer(blob):
        findings.append(Finding("brevo_api_key", m.group(1), redact_token(m.group(1))))
    for m in _RE_BREVO_SMTP.finditer(blob):
        findings.append(Finding("brevo_host_mention", m.group(1), m.group(1)))

    # Dédupliquer par (kind, redacted)
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.kind, f.redacted)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def load_paths(path_file: Path) -> list[str]:
    raw = path_file.read_text(encoding="utf-8", errors="replace").splitlines()
    paths: list[str] = []
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "*" in line:
            continue
        paths.append(line)
    return paths


def fetch_one(url: str, timeout: float, insecure: bool) -> tuple[str, int | None, str, str, str | None]:
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "DomainScanner/1.0 (+research; authorized use only)",
            "Accept": "*/*",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.getcode() or 200
            hdr_lines = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            body = resp.read(2_000_000)
            text = body.decode("utf-8", errors="replace")
            return url, status, text, hdr_lines, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(500_000)
            text = body.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        hdr_lines = "\n".join(f"{k}: {v}" for k, v in (e.headers.items() if e.headers else []))
        return url, e.code, text, hdr_lines, None
    except Exception as ex:
        return url, None, "", "", str(ex)


def normalize_base(domain: str, use_https: bool) -> str:
    domain = domain.strip().rstrip("/")
    if domain.startswith("http://") or domain.startswith("https://"):
        return domain
    scheme = "https" if use_https else "http"
    return f"{scheme}://{domain}"


def main() -> int:
    p = argparse.ArgumentParser(
        description="Scanne un domaine sur une liste de chemins et détecte des fuites AWS / SendGrid / Brevo."
    )
    p.add_argument("--domain", "-d", required=True, help="Domaine ou URL de base (ex: example.com)")
    p.add_argument(
        "--paths-file",
        type=Path,
        default=Path(__file__).resolve().parent / "paths.txt",
        help="Fichier contenant un chemin par ligne",
    )
    p.add_argument("--timeout", type=float, default=12.0)
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--http", action="store_true", help="Utiliser http:// au lieu de https://")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Désactiver la vérification TLS (non recommandé)",
    )
    p.add_argument("--json", action="store_true", help="Sortie JSON")
    args = p.parse_args()

    base = normalize_base(args.domain, use_https=not args.http)
    paths = load_paths(args.paths_file)
    if not paths:
        print("Aucun chemin à tester (fichier vide ou uniquement des lignes avec *)", file=sys.stderr)
        return 1

    base_clean = base.rstrip("/")
    urls: list[str] = []
    for path in paths:
        path = path if path.startswith("/") else "/" + path
        urls.append(base_clean + path)

    results: list[ScanResult] = []

    def job(u: str) -> ScanResult:
        url, status, text, hdrs, err = fetch_one(u, args.timeout, args.insecure)
        if err:
            return ScanResult(url=url, status=status, error=err)
        findings = analyze_text(text, hdrs)
        return ScanResult(url=url, status=status, findings=findings)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(job, u): u for u in urls}
        for fut in as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda r: r.url)
    hits = [r for r in results if r.findings]

    if args.json:
        payload: list[dict[str, Any]] = []
        for r in results:
            item: dict[str, Any] = {"url": r.url, "status": r.status}
            if r.error:
                item["error"] = r.error
            if r.findings:
                item["findings"] = [
                    {"kind": f.kind, "redacted": f.redacted} for f in r.findings
                ]
            payload.append(item)
        print(json.dumps({"base": base, "results": payload, "hit_count": len(hits)}, indent=2))
    else:
        print(f"Base: {base}")
        print(f"Requêtes: {len(urls)} | Réponses avec indicateurs AWS/SendGrid/Brevo: {len(hits)}")
        for r in results:
            if not r.findings and not r.error:
                continue
            if r.error:
                print(f"[ERR] {r.status or '?'} {r.url} — {r.error}")
                continue
            for f in r.findings:
                print(f"[HIT] {r.status} {r.url} — {f.kind}: {f.redacted}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
