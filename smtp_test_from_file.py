#!/usr/bin/env python3
"""
Lit un fichier texte avec des blocs SMTP au format :
EMAIL: user@domain, HOST: smtp.example.com, PORT: 587, USER: user@domain, PASS: secret

Une configuration par ligne (lignes vides ignorées). Envoie un mail de test pour chaque entrée.
"""

from __future__ import annotations

import argparse
import re
import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

# Une ligne = un compte. Champs séparés par des virgules ; PASS est le dernier (éviter les virgules dans le mot de passe).
LINE_PATTERN = re.compile(
    r"""
    ^\s*
    EMAIL:\s*(?P<email>[^,]+?)\s*,\s*
    HOST:\s*(?P<host>[^,]+?)\s*,\s*
    PORT:\s*(?P<port>\d+)\s*,\s*
    USER:\s*(?P<user>[^,]+?)\s*,\s*
    PASS:\s*(?P<pass>.+?)\s*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_line(line: str) -> Optional[dict[str, str]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = LINE_PATTERN.match(line)
    if not m:
        return None
    return {
        "email": m.group("email").strip(),
        "host": m.group("host").strip(),
        "port": int(m.group("port")),
        "user": m.group("user").strip(),
        "pass": m.group("pass").strip(),
    }


def send_test_mail(cfg: dict, to_addr: str, dry_run: bool) -> None:
    port = cfg["port"]
    host = cfg["host"]

    msg = EmailMessage()
    msg["Subject"] = f"Test SMTP ({cfg['email']})"
    msg["From"] = cfg["email"]
    msg["To"] = to_addr
    msg.set_content(
        "Ceci est un message de test automatique.\n\n"
        f"Compte expéditeur : {cfg['email']}\n"
        f"Serveur : {host}:{port}\n"
    )

    if dry_run:
        print(f"[dry-run] OK parse + message pour {cfg['email']} -> {to_addr}")
        return

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=30) as smtp:
            smtp.login(cfg["user"], cfg["pass"])
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            if smtp.has_extn("STARTTLS"):
                smtp.starttls()
                smtp.ehlo()
            smtp.login(cfg["user"], cfg["pass"])
            smtp.send_message(msg)

    print(f"OK envoyé depuis {cfg['email']} ({host}:{port}) vers {to_addr}")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Teste des entrées SMTP depuis un fichier et envoie un mail de test."
    )
    p.add_argument(
        "fichier",
        type=Path,
        help="Fichier texte (une ligne par compte au format EMAIL:, HOST:, ...)",
    )
    p.add_argument(
        "--to",
        "-t",
        dest="to_addr",
        metavar="EMAIL",
        help="Adresse du destinataire du mail de test (sinon demandé interactivement)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Vérifie le parsing uniquement, sans connexion SMTP",
    )
    args = p.parse_args()

    if not args.fichier.is_file():
        print(f"Erreur : fichier introuvable : {args.fichier}", file=sys.stderr)
        return 1

    to_addr = args.to_addr
    if not to_addr:
        to_addr = input("Adresse e-mail du destinataire du test : ").strip()
    if not to_addr:
        print("Erreur : destinataire vide.", file=sys.stderr)
        return 1

    text = args.fichier.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    configs: list[dict] = []
    bad_lines: list[tuple[int, str]] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cfg = parse_line(line)
        if cfg:
            configs.append(cfg)
        else:
            bad_lines.append((i, line))

    if bad_lines:
        for num, content in bad_lines:
            print(f"Ligne {num} ignorée (format non reconnu) : {content[:80]}...", file=sys.stderr)

    if not configs:
        print("Aucune entrée SMTP valide dans le fichier.", file=sys.stderr)
        return 1

    print(f"{len(configs)} entrée(s) à tester, destinataire : {to_addr}")
    errors = 0
    for cfg in configs:
        try:
            send_test_mail(cfg, to_addr, args.dry_run)
        except Exception as e:
            errors += 1
            print(
                f"ÉCHEC {cfg['email']} ({cfg['host']}:{cfg['port']}) : {e}",
                file=sys.stderr,
            )

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
