#!/usr/bin/env python3
"""
Scanne un domaine sur une liste de chemins (fichier paths.txt) et signale
les réponses contenant des indices AWS, SendGrid ou Brevo.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

import httpx

@dataclass
class FindHit:
    url: str
    status: int
    service: str  # aws | sendgrid | brevo
    pattern_name: str
    snippet: str

    def to_dict(self) -> dict:
        return asdict(self)


# --- Détection (corps de réponse, souvent en texte) ---
PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "aws",
        "akid_AKIA",
        re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    ),
    (
        "aws",
        "asida_ASIA",
        re.compile(r"ASIA[0-9A-Z]{16}", re.I),
    ),
    (
        "aws",
        "aws_access_key_id",
        re.compile(r"aws_access_key_id|AWS_ACCESS_KEY_ID", re.I),
    ),
    (
        "aws",
        "aws_secret",
        re.compile(
            r"aws_secret_access_key|AWS_SECRET_ACCESS_KEY|"
            r"aws_session_token|AWS_SESSION_TOKEN",
            re.I,
        ),
    ),
    (
        "aws",
        "s3_or_amazonaws",
        re.compile(r"amazonaws\.com|s3[.-][a-z0-9-]+\.amazonaws", re.I),
    ),
    (
        "sendgrid",
        "sg_api_key",
        re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ),
    (
        "sendgrid",
        "sendgrid_keyword",
        re.compile(
            r"SENDGRID|sendgrid_api|SendGrid-API-Key|mail\.sendgrid", re.I
        ),
    ),
    (
        "brevo",
        "xkeysib",
        re.compile(r"xkeysib-[a-z0-9]{64,}", re.I),
    ),
    (
        "brevo",
        "brevo_or_sendinblue",
        re.compile(
            r"BREVO|brevo[_-]?api|sendinblue|api-?brevo", re.I
        ),
    ),
]


def load_paths(path: Path) -> list[str]:
    lines: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        lines.append(line)
    # déduplication en gardant l'ordre
    seen: set[str] = set()
    out: list[str] = []
    for p in lines:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _snippet(text: str, match: re.Match[str], width: int = 120) -> str:
    start = max(0, match.start() - 40)
    end = min(len(text), match.end() + 40)
    s = text[start:end].replace("\n", " ").replace("\r", " ")
    if start > 0:
        s = "…" + s
    if end < len(text):
        s = s + "…"
    if len(s) > width:
        s = s[: width - 1] + "…"
    return s


def scan_body(url: str, status: int, body: str) -> list[FindHit]:
    hits: list[FindHit] = []
    if not body or len(body) > 5_000_000:
        return hits
    for service, name, pat in PATTERNS:
        m = pat.search(body)
        if m:
            hits.append(
                FindHit(
                    url=url,
                    status=status,
                    service=service,
                    pattern_name=name,
                    snippet=_snippet(body, m),
                )
            )
    return hits


async def fetch_one(
    client: httpx.AsyncClient,
    base: str,
    rel: str,
) -> list[FindHit]:
    if not rel.startswith("/"):
        rel = "/" + rel
    url = base.rstrip("/") + rel
    out: list[FindHit] = []
    try:
        r = await client.get(
            url,
            follow_redirects=True,
        )
    except (httpx.RequestError, OSError):
        return out

    if r.status_code == 404:
        return out

    cl = r.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > 1_000_000:
        return out

    ctype = (r.headers.get("content-type") or "").lower()
    if any(
        x in ctype
        for x in ("application/zip", "application/octet-stream", "image/", "application/pdf")
    ):
        return out
    if "text" not in ctype and "json" not in ctype and "xml" not in ctype:
        if r.status_code not in (200, 201):
            return out
    try:
        body = r.text
    except Exception:
        return out

    if len(body) > 2_000_000:
        body = body[:2_000_000]

    return scan_body(str(r.request.url), r.status_code, body)


async def run_scan(
    domain: str,
    paths: list[str],
    use_http: bool,
    verify_ssl: bool,
    concurrency: int,
) -> list[FindHit]:
    bases: list[str] = []
    d = domain.strip()
    if not d.startswith("http://") and not d.startswith("https://"):
        bases.append("https://" + d)
        if use_http:
            bases.append("http://" + d)
    else:
        bases.append(d.rstrip("/"))
        if use_http and d.startswith("https://"):
            bases.append(d.replace("https://", "http://", 1).rstrip("/"))

    all_hits: list[FindHit] = []
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=verify_ssl,
        timeout=httpx.Timeout(15.0, connect=10.0),
        headers={
            "User-Agent": "DomainServiceProbe/1.0 (admin security audit)",
        },
    ) as client:
        async def one(base: str, p: str) -> None:
            async with sem:
                hs = await fetch_one(client, base, p)
                all_hits.extend(hs)

        tasks: list[asyncio.Task[None]] = [asyncio.create_task(one(b, p)) for b in bases for p in paths]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    return all_hits


def main() -> int:
    p = argparse.ArgumentParser(
        description="Scan de chemins sur un domaine (AWS / SendGrid / Brevo)."
    )
    p.add_argument("domain", help="Domaine ou URL (ex: example.com)")
    p.add_argument(
        "-f",
        "--paths-file",
        type=Path,
        default=Path(__file__).resolve().parent / "paths.txt",
        help="Fichier de chemins (un par ligne)",
    )
    p.add_argument(
        "--http",
        action="store_true",
        help="Aussi tenter http:// (en plus de https://)",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Désactiver la vérification SSL",
    )
    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=20,
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Sortie JSON",
    )
    args = p.parse_args()

    if not args.paths_file.is_file():
        print(f"Fichier de chemins introuvable: {args.paths_file}", file=sys.stderr)
        return 2

    paths = load_paths(args.paths_file)
    if not paths:
        print("Aucun chemin dans le fichier.", file=sys.stderr)
        return 2

    hits = asyncio.run(
        run_scan(
            args.domain,
            paths,
            use_http=args.http,
            verify_ssl=not args.insecure,
            concurrency=max(1, min(args.concurrency, 200)),
        )
    )

    # dédup par (url, service, pattern_name) — garder le premier
    key_seen: set[tuple[str, str, str]] = set()
    unique: list[FindHit] = []
    for h in hits:
        k = (h.url, h.service, h.pattern_name)
        if k in key_seen:
            continue
        key_seen.add(k)
        unique.append(h)

    if args.json:
        print(json.dumps([h.to_dict() for h in unique], indent=2, ensure_ascii=False))
    else:
        if not unique:
            print("Aucun indice AWS / SendGrid / Brevo détecté dans les corps analysés.")
            return 0
        for h in unique:
            print(
                f"[{h.service.upper():8}] {h.status} {h.url}\n"
                f"  motif: {h.pattern_name}\n"
                f"  extrait: {h.snippet!r}\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
