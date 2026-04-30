#!/usr/bin/env python3
"""
Extrait les clés API SendGrid d'un fichier texte, optionnellement les valide
via l'API v3 et consulte les crédits (quota) si la clé est valide.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_BASE = "https://api.sendgrid.com/v3"

# SendGrid API keys commencent par SG. et contiennent typiquement deux segments séparés par un point.
_SENDGRID_KEY_PATTERN = re.compile(
    r"SG\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    re.MULTILINE,
)


def extract_sendgrid_keys(text: str) -> list[str]:
    """Retourne les clés uniques trouvées, dans l'ordre de première occurrence."""
    seen: set[str] = set()
    result: list[str] = []
    for m in _SENDGRID_KEY_PATTERN.finditer(text):
        key = m.group(0)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def mask_key(api_key: str, *, prefix: int = 6, suffix: int = 4) -> str:
    """Masque le milieu de la clé pour l'affichage."""
    if len(api_key) <= prefix + suffix + 3:
        return api_key[:prefix] + "…"
    return f"{api_key[:prefix]}…{api_key[-suffix:]}"


def _api_get(path: str, api_key: str, *, timeout: float) -> tuple[int, dict | None]:
    """GET JSON sur api.sendgrid.com. Retourne (code_http, corps_json ou None)."""
    url = f"{API_BASE}{path}"
    req = Request(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if resp.status == 204 or not raw.strip():
                return resp.status, {}
            return resp.status, json.loads(raw)
    except HTTPError as e:
        raw = ""
        if e.fp:
            raw = e.fp.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError:
            data = None
        return e.code, data
    except URLError as e:
        raise ConnectionError(str(e.reason)) from e


def validate_and_credits(api_key: str, *, timeout: float) -> dict:
    """
    Teste la clé sur /user/profile puis lit /user/credits si valide.
    Retourne un dict avec clés: ok (bool), profile_status, credits_status, credits_body, error_message.
    """
    status_p, body_p = _api_get("/user/profile", api_key, timeout=timeout)
    if status_p == 401:
        msg = None
        if isinstance(body_p, dict) and body_p.get("errors"):
            err0 = body_p["errors"][0]
            if isinstance(err0, dict) and err0.get("message"):
                msg = err0["message"]
        return {
            "ok": False,
            "profile_status": status_p,
            "credits_status": None,
            "credits_body": None,
            "error_message": msg or "Unauthorized",
        }
    if status_p != 200:
        return {
            "ok": False,
            "profile_status": status_p,
            "credits_status": None,
            "credits_body": None,
            "error_message": f"Profil HTTP {status_p}",
        }

    status_c, body_c = _api_get("/user/credits", api_key, timeout=timeout)
    return {
        "ok": True,
        "profile_status": status_p,
        "credits_status": status_c,
        "credits_body": body_c if isinstance(body_c, dict) else None,
        "error_message": None,
    }


def format_credits_summary(body: dict | None, credits_status: int | None) -> str:
    """Résumé lisible pour les crédits / erreur de permission."""
    if credits_status == 403:
        return "quota: refusé (403) — la clé n’a peut‑être pas le scope « user.credits.read »"
    if credits_status == 401:
        return "quota: 401 (inattendu après profil OK)"
    if credits_status is None or body is None:
        return "quota: non disponible"
    if credits_status != 200:
        return f"quota: erreur HTTP {credits_status}"

    parts = []
    for label, key in (
        ("restants", "remain"),
        ("total", "total"),
        ("utilisés", "used"),
        ("type", "type"),
        ("réinitialisation", "reset_frequency"),
    ):
        val = body.get(key)
        if val is not None:
            parts.append(f"{label}={val}")
    return "quota: " + (", ".join(parts) if parts else json.dumps(body, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extrait les clés SendGrid depuis un fichier texte ; "
            "optionnellement vérifie chaque clé et affiche le quota (crédits)."
        ),
    )
    parser.add_argument(
        "fichier",
        type=Path,
        help="Chemin du fichier texte à analyser",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Ne pas afficher le nombre de clés sur stderr",
    )
    parser.add_argument(
        "--keys-only",
        action="store_true",
        help="Uniquement extraire et imprimer les clés (pas d’appels API)",
    )
    parser.add_argument(
        "--no-mask",
        action="store_true",
        help="Afficher les clés en entier dans le rapport (par défaut masquées)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        metavar="SEC",
        help="Timeout HTTP par requête (défaut: 20)",
    )
    args = parser.parse_args()

    path = args.fichier
    if not path.is_file():
        print(f"Erreur : fichier introuvable ou non régulier : {path}", file=sys.stderr)
        return 1

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Erreur de lecture : {path} : {e}", file=sys.stderr)
        return 1

    keys = extract_sendgrid_keys(text)
    if not args.quiet:
        print(f"{len(keys)} clé(s) unique(s) trouvée(s).", file=sys.stderr)

    if args.keys_only:
        for k in keys:
            print(k)
        return 0

    mask = not args.no_mask
    exit_nonzero = False

    for key in keys:
        label = mask_key(key) if mask else key
        try:
            info = validate_and_credits(key, timeout=args.timeout)
        except ConnectionError as e:
            print(f"{label}\tinvalid\tconnexion\t{e}")
            exit_nonzero = True
            continue

        if not info["ok"]:
            msg = info["error_message"] or ""
            print(f"{label}\tinvalid\tHTTP {info['profile_status']}\t{msg}".strip())
            exit_nonzero = True
            continue

        quota_line = format_credits_summary(
            info["credits_body"],
            info["credits_status"],
        )
        print(f"{label}\tvalid\t{quota_line}")

    return 1 if exit_nonzero else 0


if __name__ == "__main__":
    raise SystemExit(main())
