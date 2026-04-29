#!/usr/bin/env python3
"""
Scanne un domaine sur une liste de chemins HTTP(S) et signale des indices
AWS, SendGrid et Brevo dans les réponses (usage légitime / audit autorisé uniquement).
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
from typing import Iterable
from urllib.parse import quote, urljoin, urlparse

# Références de motifs (clés / noms de variables typiques)
AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_ALT_PREFIX = re.compile(r"\b(?:ASIA|AIDA|AROA|AIPA|ANPA|ANVA|AGPA|AIDA)[0-9A-Z]{16}\b")
AWS_KEYWORDS = re.compile(
    r"(?i)\b(aws_access_key_id|aws_secret_access_key|amazonaws\.com|"
    r"\[default\]\s*aws_access_key_id)\b"
)
SENDGRID_KEY = re.compile(
    r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"
)
SENDGRID_KW = re.compile(r"(?i)\b(sendgrid|smtp\.sendgrid\.net)\b")
BREVO_KEY = re.compile(
    r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b", re.IGNORECASE
)
BREVO_KW = re.compile(
    r"(?i)\b(brevo|sendinblue|smtp-relay\.brevo\.com|smtp-relay\.sendinblue\.com)\b"
)

USER_AGENT = (
    "Mozilla/5.0 (compatible; DomainLeakCheck/1.0; +https://example.invalid)"
)


@dataclass
class Finding:
    url: str
    status: int | None
    categories: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None


def normalize_domain(raw: str) -> str:
    raw = raw.strip()
    if "://" in raw:
        p = urlparse(raw)
        host = p.netloc or p.path.split("/")[0]
        return host.rstrip("/") or raw
    return raw.rstrip("/")


def normalize_path_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if not line.startswith("/"):
        line = "/" + line
    # Chemins avec glob: on tente l'équivalent le plus courant
    if "*" in line:
        line = line.replace("main.*.js", "main.js")
        if "*" in line:
            return None
    return line


def load_paths(path_file: Path) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in path_file.read_text(encoding="utf-8", errors="replace").splitlines():
        p = normalize_path_line(line)
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def build_url(scheme: str, host: str, path: str) -> str:
    """Construit une URL; encode correctement query string si présente."""
    if "?" in path:
        base, q = path.split("?", 1)
        q = quote(q, safe="=&")
        path = f"{base}?{q}"
    return urljoin(f"{scheme}://{host}/", path.lstrip("/"))


def classify_body(text: str) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    checks = [
        ("aws", AWS_ACCESS_KEY, "aws_access_key_id (AKIA…)"),
        ("aws", AWS_ALT_PREFIX, "aws_access_key_id (préfixe STS/IAM)"),
        ("aws", AWS_KEYWORDS, "mot-clé / config AWS"),
        ("sendgrid", SENDGRID_KEY, "clé API SendGrid (SG.*)"),
        ("sendgrid", SENDGRID_KW, "mot-clé SendGrid"),
        ("brevo", BREVO_KEY, "clé API Brevo (xkeysib-…)"),
        ("brevo", BREVO_KW, "mot-clé Brevo / Sendinblue"),
    ]
    for cat, rx, label in checks:
        if rx.search(text):
            hits.setdefault(cat, []).append(label)
    # Dédupliquer libellés par catégorie
    for cat in list(hits):
        hits[cat] = sorted(set(hits[cat]))
    return hits


def fetch(
    url: str,
    timeout: float,
    insecure: bool,
    max_bytes: int,
) -> tuple[int | None, bytes, str | None]:
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = resp.getcode()
            data = resp.read(max_bytes + 1)
            if len(data) > max_bytes:
                data = data[:max_bytes]
            return code, data, None
    except urllib.error.HTTPError as e:
        try:
            data = e.read(max_bytes + 1)[:max_bytes]
        except Exception:
            data = b""
        return e.code, data, None
    except Exception as e:
        return None, b"", str(e)


def scan_one(
    url: str,
    timeout: float,
    insecure: bool,
    max_bytes: int,
    min_status: int,
) -> Finding:
    status, body, err = fetch(url, timeout, insecure, max_bytes)
    if err:
        return Finding(url=url, status=status, error=err)
    if status is None or status < min_status:
        return Finding(url=url, status=status)
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    cats = classify_body(text)
    return Finding(url=url, status=status, categories=cats)


def iter_urls(
    host: str,
    paths: Iterable[str],
    schemes: list[str],
) -> list[tuple[str, str]]:
    """Retourne (scheme, full_url) pour chaque combinaison."""
    out: list[tuple[str, str]] = []
    for scheme in schemes:
        for path in paths:
            out.append((scheme, build_url(scheme, host, path)))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan de chemins sur un domaine (AWS / SendGrid / Brevo)."
    )
    parser.add_argument(
        "domain",
        help="Domaine ou URL de base (ex: example.com)",
    )
    parser.add_argument(
        "-p",
        "--paths-file",
        type=Path,
        default=Path(__file__).resolve().parent / "paths.txt",
        help="Fichier listant un chemin par ligne (défaut: paths.txt à côté du script)",
    )
    parser.add_argument(
        "--https-only",
        action="store_true",
        help="Ne tester que https",
    )
    parser.add_argument(
        "--http-only",
        action="store_true",
        help="Ne tester que http",
    )
    parser.add_argument(
        "-j",
        "--workers",
        type=int,
        default=16,
        help="Requêtes parallèles (défaut: 16)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout par requête en secondes",
    )
    parser.add_argument(
        "--min-status",
        type=int,
        default=200,
        help="Ne garder que les réponses avec status >= cette valeur (défaut: 200)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Ne pas vérifier les certificats TLS",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=512_000,
        help="Taille max lue par réponse (défaut: 512 Ko)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Sortie JSON (une ligne par finding avec match)",
    )
    args = parser.parse_args()

    if args.https_only and args.http_only:
        print("Incompatible: --https-only et --http-only", file=sys.stderr)
        return 2

    host = normalize_domain(args.domain)
    if not host:
        print("Domaine vide.", file=sys.stderr)
        return 2

    if not args.paths_file.is_file():
        print(f"Fichier de chemins introuvable: {args.paths_file}", file=sys.stderr)
        return 2

    paths = load_paths(args.paths_file)
    if not paths:
        print("Aucun chemin à tester.", file=sys.stderr)
        return 2

    if args.https_only:
        schemes = ["https"]
    elif args.http_only:
        schemes = ["http"]
    else:
        schemes = ["https", "http"]

    jobs = iter_urls(host, paths, schemes)
    findings_with_hits: list[Finding] = []
    errors = 0

    def run(u: str) -> Finding:
        return scan_one(
            u,
            timeout=args.timeout,
            insecure=args.insecure,
            max_bytes=args.max_bytes,
            min_status=args.min_status,
        )

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(run, url): url for _, url in jobs}
        for fut in as_completed(futs):
            f = fut.result()
            if f.error:
                errors += 1
            if f.categories:
                findings_with_hits.append(f)

    findings_with_hits.sort(key=lambda x: x.url)

    if args.json:
        for f in findings_with_hits:
            print(
                json.dumps(
                    {
                        "url": f.url,
                        "status": f.status,
                        "matches": f.categories,
                    },
                    ensure_ascii=False,
                )
            )
    else:
        print(f"Cible: {host}  |  chemins: {len(paths)}  |  schémas: {', '.join(schemes)}")
        if not findings_with_hits:
            print("Aucun indicateur AWS / SendGrid / Brevo dans les corps analysés.")
        else:
            for f in findings_with_hits:
                print(f"\n[{f.status}] {f.url}")
                for cat, labels in sorted(f.categories.items()):
                    print(f"  {cat}: {', '.join(labels)}")
        if errors:
            print(f"\n({errors} requêtes en erreur réseau / timeout — non listées)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
