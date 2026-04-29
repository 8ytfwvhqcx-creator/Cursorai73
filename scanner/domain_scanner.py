#!/usr/bin/env python3
"""
Scanne un ou plusieurs domaines sur une liste de chemins HTTP(S) et signale
des indices AWS, SendGrid ou Brevo dans le corps ou les en-têtes des réponses.

Usage:
  python domain_scanner.py example.com
  python domain_scanner.py https://example.com --paths /path/to/paths.txt
  python domain_scanner.py a.com b.com --workers 20 --timeout 12
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Regex / mots-clés pour détecter des fuites ou références sensibles
PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "aws",
        "Clé d'accès AWS (AKIA/ASIA)",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "aws",
        "aws_access_key_id / secret (texte)",
        re.compile(
            r"(?i)aws_(?:access_key_id|secret_access_key)\s*[=:]\s*['\"]?[^\s'\"]+",
        ),
    ),
    (
        "aws",
        "Bloc credentials AWS (fichier .ini)",
        re.compile(r"(?is)\[\s*default\s*\].*(?:aws_access_key_id|aws_secret_access_key)"),
    ),
    (
        "sendgrid",
        "Clé API SendGrid (SG.xxx)",
        re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{10,}\b"),
    ),
    (
        "sendgrid",
        "Variable / mention SendGrid",
        re.compile(r"(?i)(?:sendgrid|SENDGRID_API_KEY|smtp\.sendgrid\.net)"),
    ),
    (
        "brevo",
        "Clé API Brevo (xkeysib-)",
        re.compile(r"\bxkeysib-[a-zA-Z0-9_-]{20,}\b"),
    ),
    (
        "brevo",
        "Mention Brevo / SMTP",
        re.compile(r"(?i)(?:\bbrevo\b|smtp-relay\.brevo\.com|BREVO_API_KEY)"),
    ),
]


def normalize_base(url_or_host: str) -> str:
    u = url_or_host.strip()
    if not u:
        raise ValueError("URL ou hôte vide")
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    parsed = urllib.parse.urlparse(u)
    if not parsed.netloc:
        raise ValueError(f"URL invalide: {url_or_host!r}")
    # Pas de chemin de base parasite
    return f"{parsed.scheme}://{parsed.netloc}"


def expand_path(path_line: str) -> list[str]:
    """Retourne une ou plusieurs URLs-path à tester (wildcard minimal)."""
    raw = path_line.strip()
    if not raw or raw.startswith("#"):
        return []
    if "*" in raw:
        # Ex. /static/js/main.*.js -> tenter main.js (bundles typiques)
        if "/main.*.js" in raw:
            return [raw.replace("main.*.js", "main.js")]
        return [raw.replace("*", "")]
    return [raw]


def load_paths(path_file: Path) -> list[str]:
    lines = path_file.read_text(encoding="utf-8", errors="replace").splitlines()
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        for p in expand_path(line):
            if p and p not in seen:
                seen.add(p)
                out.append(p)
    return out


def sniff_matches(text: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for family, label, rx in PATTERNS:
        m = rx.search(text)
        if m:
            snippet = m.group(0)
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            hits.append(
                {
                    "family": family,
                    "label": label,
                    "match": snippet,
                },
            )
    return hits


@dataclass
class ScanResult:
    url: str
    status: int | None
    error: str | None = None
    findings: list[dict[str, str]] = field(default_factory=list)
    content_type: str | None = None


def fetch_one(
    full_url: str,
    timeout: float,
    max_bytes: int,
    user_agent: str,
) -> tuple[int | None, dict[str, str], bytes, str | None]:
    req = urllib.request.Request(
        full_url,
        headers={
            "User-Agent": user_agent,
            "Accept": "*/*",
            "Connection": "close",
        },
        method="GET",
    )
    err: str | None = None
    status: int | None = None
    headers: dict[str, str] = {}
    body = b""
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            status = resp.getcode()
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = body[:max_bytes]
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = body[:max_bytes]
        except Exception:
            body = b""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception as e:
        err = str(e)[:500]
    return status, headers, body, err


def scan_url(
    full_url: str,
    timeout: float,
    max_bytes: int,
    user_agent: str,
) -> ScanResult:
    status, headers, body, err = fetch_one(full_url, timeout, max_bytes, user_agent)
    ct = headers.get("content-type")
    parts: list[str] = []
    for k, v in headers.items():
        parts.append(f"{k}: {v}")
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = body.decode("latin-1", errors="replace")
    blob = "\n".join(parts) + "\n\n" + text
    findings = sniff_matches(blob)
    return ScanResult(
        url=full_url,
        status=status,
        error=err,
        findings=findings,
        content_type=ct,
    )


def run_scan(
    bases: Iterable[str],
    paths: list[str],
    workers: int,
    timeout: float,
    max_bytes: int,
    user_agent: str,
) -> list[ScanResult]:
    tasks: list[str] = []
    for base in bases:
        b = normalize_base(base)
        for p in paths:
            if not p.startswith("/"):
                p = "/" + p
            tasks.append(urllib.parse.urljoin(b + "/", p.lstrip("/")))

    results: list[ScanResult] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {
            ex.submit(scan_url, u, timeout, max_bytes, user_agent): u for u in tasks
        }
        for fut in as_completed(futs):
            results.append(fut.result())
    results.sort(key=lambda r: r.url)
    return results


def main() -> int:
    default_paths = Path(__file__).resolve().parent / "paths.txt"
    p = argparse.ArgumentParser(
        description="Scan de chemins HTTP(S) pour indices AWS / SendGrid / Brevo.",
    )
    p.add_argument(
        "targets",
        nargs="+",
        help="Domaines ou URLs de base (ex: example.com ou https://example.com)",
    )
    p.add_argument(
        "--paths",
        type=Path,
        default=default_paths,
        help=f"Fichier liste de chemins (défaut: {default_paths})",
    )
    p.add_argument("--workers", type=int, default=16, help="Requêtes parallèles")
    p.add_argument("--timeout", type=float, default=10.0, help="Timeout HTTP (s)")
    p.add_argument(
        "--max-bytes",
        type=int,
        default=512_000,
        help="Octets max lus par réponse",
    )
    p.add_argument(
        "--json-out",
        type=Path,
        help="Écrire les résultats complets en JSON",
    )
    p.add_argument(
        "--only-hits",
        action="store_true",
        help="N'afficher que les URLs avec au moins une détection",
    )
    args = p.parse_args()

    if not args.paths.is_file():
        print(f"Fichier paths introuvable: {args.paths}", file=sys.stderr)
        return 2

    path_list = load_paths(args.paths)
    if not path_list:
        print("Aucun chemin à scanner.", file=sys.stderr)
        return 2

    ua = "DomainScanner/1.0 (+security research; respect robots.txt in production)"

    print(f"Chemins uniques: {len(path_list)} | Cibles: {len(args.targets)}", file=sys.stderr)
    results = run_scan(
        args.targets,
        path_list,
        workers=max(1, args.workers),
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        user_agent=ua,
    )

    hits = [r for r in results if r.findings]
    for r in results:
        if args.only_hits and not r.findings:
            continue
        line = f"{r.status}\t{r.url}"
        if r.error:
            line += f"\tERR {r.error}"
        print(line)
        for f in r.findings:
            print(f"  [{f['family']}] {f['label']}: {f['match']!r}")

    print(
        f"\nRésumé: {len(hits)} URL(s) avec détection(s) sur {len(results)} testées.",
        file=sys.stderr,
    )

    if args.json_out:
        payload = [
            {
                "url": r.url,
                "status": r.status,
                "error": r.error,
                "content_type": r.content_type,
                "findings": r.findings,
            }
            for r in results
        ]
        args.json_out.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"JSON: {args.json_out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
