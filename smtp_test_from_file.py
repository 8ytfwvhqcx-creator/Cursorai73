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


def _resolve_fichier_et_destinataire(
    positionnels: list[str],
) -> tuple[Path, str | None]:
    """
    Accepte :
      fichier
      fichier email
      email fichier
    Retourne (Path fichier, email destinataire ou None si à demander / --to).
    """
    n = len(positionnels)
    if n == 0:
        raise ValueError("Indiquez le fichier des comptes SMTP (et optionnellement l'e-mail du destinataire).")
    if n == 1:
        return Path(positionnels[0]), None
    if n == 2:
        a, b = positionnels[0], positionnels[1]
        a_mail = "@" in a
        b_mail = "@" in b
        pa, pb = Path(a), Path(b)
        if a_mail and not b_mail:
            return pb, a.strip()
        if b_mail and not a_mail:
            return pa, b.strip()
        if pa.is_file() and not pb.is_file():
            return pa, b.strip() if b_mail else None
        if pb.is_file() and not pa.is_file():
            return pb, a.strip() if a_mail else None
        if pa.is_file() and b_mail:
            return pa, b.strip()
        if pb.is_file() and a_mail:
            return pb, a.strip()
        raise ValueError(
            "Deux arguments : précisez le fichier et l'e-mail du destinataire "
            "(ordre libre : fichier puis e-mail, ou e-mail puis fichier)."
        )
    raise ValueError("Trop d'arguments positionnels ; attendu : fichier [e-mail] ou e-mail fichier.")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Teste des entrées SMTP depuis un fichier et envoie un mail de test.",
        epilog="Exemples : %(prog)s comptes.txt --to moi@exemple.fr | %(prog)s moi@exemple.fr comptes.txt | %(prog)s comptes.txt moi@exemple.fr",
    )
    p.add_argument(
        "positionnels",
        nargs="*",
        metavar="fichier|email",
        help="Fichier des comptes ; avec un 2e argument : e-mail destinataire (ordre libre avec le fichier).",
    )
    p.add_argument(
        "--to",
        "-t",
        dest="to_addr",
        metavar="EMAIL",
        help="Destinataire du test (prioritaire sur l'e-mail en argument positionnel)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Vérifie le parsing uniquement, sans connexion SMTP",
    )
    args = p.parse_args()

    try:
        fichier, to_pos = _resolve_fichier_et_destinataire(args.positionnels)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        p.print_usage(file=sys.stderr)
        return 1

    if not fichier.is_file():
        print(f"Erreur : fichier introuvable : {fichier}", file=sys.stderr)
        return 1

    to_addr = args.to_addr or to_pos
    if not to_addr:
        to_addr = input("Adresse e-mail du destinataire du test : ").strip()
    if not to_addr:
        print("Erreur : destinataire vide.", file=sys.stderr)
        return 1

    text = fichier.read_text(encoding="utf-8", errors="replace")
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
