#!/usr/bin/env python3
"""
Extrait toutes les clés API SendGrid d'un fichier texte.

Format habituel : SG.<segment>.<segment> (lettres, chiffres, tirets, underscores).
Les doublons sont retirés en conservant l'ordre d'apparition.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extrait les clés SendGrid (SG.*.*) d'un fichier texte.",
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

    for k in keys:
        print(k)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
