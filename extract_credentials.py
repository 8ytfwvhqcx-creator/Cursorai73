#!/usr/bin/env python3
"""
Sélectionne un dossier via l'explorateur, parcourt les fichiers texte,
extrait les identifiants SMTP, AWS, Brevo et SendGrid, et les enregistre
dans des fichiers par catégorie.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import DefaultDict, Iterable, Set

def _require_tkinter():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except ImportError as e:
        print(
            "tkinter est requis pour le sélecteur de dossier. "
            "Sur Debian/Ubuntu: sudo apt install python3-tk",
            file=sys.stderr,
        )
        raise SystemExit(1) from e
    return tk, filedialog, messagebox

# Extensions considérées comme “fichiers texte”
TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".yaml",
    ".yml",
    ".json",
    ".xml",
    ".csv",
    ".log",
    ".sql",
    ".php",
    ".py",
    ".js",
    ".ts",
    ".html",
    ".htm",
    ".sh",
    ".bat",
    ".properties",
}

# Fichiers sans extension souvent utilisés pour la config
TEXT_BASE_NAMES = {".env", ".gitconfig", "Dockerfile", "Makefile"}


def iter_text_files(root: Path) -> Iterable[Path]:
    """Parcourt récursivement le dossier et produit les chemins de fichiers texte."""
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() in TEXT_EXTENSIONS:
            yield p
            continue
        if p.name in TEXT_BASE_NAMES or (p.name.startswith(".env") and "." not in p.name[1:]):
            yield p


# --- Motifs d'extraction (sensibles aux faux positifs réduits au possible) ---

# AWS Access Key ID (commence par AKIA, ASIA, AIDA, etc. — 20 caractères alphanum)
AWS_ACCESS_KEY_RE = re.compile(
    r"\b((?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16})\b"
)
# Clé secrète AWS classique: 40 caractères base64
AWS_SECRET_KEY_RE = re.compile(r"\b([A-Za-z0-9/+=]{40})\b")
# Paires style .env
AWS_KEY_ID_LINE = re.compile(
    r"(?i)aws[_\s-]*access[_\s-]*key[_\s-]*id\s*[=:]\s*['\"]?([A-Z0-9]{20})['\"]?"
)
AWS_SECRET_LINE = re.compile(
    r"(?i)aws[_\s-]*secret[_\s-]*access[_\s-]*key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)

# Brevo: clés API modernes
BREVO_XKEYSIB_RE = re.compile(r"\b(xkeysib-[a-zA-Z0-9_-]{64}-[a-zA-Z0-9]{16})\b")
# Anciennes clés / SMTP Brevo
BREVO_SMTP_MENTION = re.compile(
    r"(?i)(smtp-relay\.brevo\.com|smtp\.brevo\.com|api\.brevo\.com|brevo\.com)"
)

# SendGrid
SENDGRID_API_RE = re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43,})\b")
SENDGRID_MENTION = re.compile(r"(?i)(api\.sendgrid\.com|sendgrid\.com)")

# SMTP générique: URLs smtp:// user:pass@host:port
SMTP_URL_RE = re.compile(
    r"(?i)smtp[s]?://(?:([^:@/]+):([^@/]+)@)?([^:/?#]+)(?::(\d+))?"
)
# Lignes type SMTP_HOST=..., MAIL_PASSWORD=...
SMTP_LABEL_RE = re.compile(
    r"(?i)(?:smtp|mail)[_\s-]*(?:host|server|hostname|url)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
)
SMTP_USER_RE = re.compile(
    r"(?i)(?:smtp|mail)[_\s-]*(?:user|username|login)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
)
SMTP_PASS_RE = re.compile(
    r"(?i)(?:smtp|mail)[_\s-]*(?:pass|password|pwd)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
)
SMTP_PORT_RE = re.compile(
    r"(?i)(?:smtp|mail)[_\s-]*port\s*[=:]\s*['\"]?(\d{2,5})['\"]?"
)


def dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    seen: Set[str] = set()
    out: list[str] = []
    for x in items:
        x = x.strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def extract_from_content(content: str, rel_path: str) -> dict[str, list[str]]:
    """Retourne des listes par catégorie avec préfixe fichier pour le contexte."""
    lines_out: DefaultDict[str, list[str]] = defaultdict(list)
    prefix = f"[{rel_path}] "

    # AWS
    for m in AWS_ACCESS_KEY_RE.finditer(content):
        lines_out["aws"].append(prefix + f"access_key_id={m.group(1)}")
    for m in AWS_KEY_ID_LINE.finditer(content):
        lines_out["aws"].append(prefix + f"access_key_id={m.group(1)}")
    aws_secrets_from_lines: Set[str] = set()
    for m in AWS_SECRET_LINE.finditer(content):
        s = m.group(1)
        aws_secrets_from_lines.add(s)
        lines_out["aws"].append(prefix + f"secret_access_key={s}")
    for m in AWS_SECRET_KEY_RE.finditer(content):
        s = m.group(1)
        if s in aws_secrets_from_lines:
            continue
        # Éviter de traiter toute chaîne 40 car comme secret AWS si le contexte n'est pas pertinent
        if re.search(r"(?i)aws|secret|amazon", content[max(0, m.start() - 80) : m.end() + 80]):
            lines_out["aws"].append(prefix + f"secret_access_key?={s}")

    # Brevo
    for m in BREVO_XKEYSIB_RE.finditer(content):
        lines_out["brevo"].append(prefix + f"api_key={m.group(1)}")
    for m in BREVO_SMTP_MENTION.finditer(content):
        lines_out["brevo"].append(prefix + f"mention={m.group(1)}")

    # SendGrid
    for m in SENDGRID_API_RE.finditer(content):
        lines_out["sendgrid"].append(prefix + f"api_key={m.group(1)}")
    for m in SENDGRID_MENTION.finditer(content):
        lines_out["sendgrid"].append(prefix + f"mention={m.group(1)}")

    # SMTP
    for m in SMTP_URL_RE.finditer(content):
        user, pw, host, port = m.groups()
        if host and "localhost" not in host.lower():
            part = f"url host={host}"
            if port:
                part += f" port={port}"
            if user:
                part += f" user={user}"
            if pw:
                part += f" password={pw}"
            lines_out["smtp"].append(prefix + part)
    for m in SMTP_LABEL_RE.finditer(content):
        lines_out["smtp"].append(prefix + f"smtp_host={m.group(1)}")
    for m in SMTP_USER_RE.finditer(content):
        lines_out["smtp"].append(prefix + f"smtp_user={m.group(1)}")
    for m in SMTP_PASS_RE.finditer(content):
        lines_out["smtp"].append(prefix + f"smtp_password={m.group(1)}")
    for m in SMTP_PORT_RE.finditer(content):
        lines_out["smtp"].append(prefix + f"smtp_port={m.group(1)}")

    return {k: dedupe_preserve_order(v) for k, v in lines_out.items()}


def merge_results(
    global_store: DefaultDict[str, list[str]], per_file: dict[str, list[str]]
) -> None:
    for cat, items in per_file.items():
        global_store[cat].extend(items)


def pick_folder() -> Path | None:
    tk, filedialog, _ = _require_tkinter()
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title="Choisir le dossier contenant les fichiers texte")
    root.destroy()
    if not path:
        return None
    return Path(path)


def main() -> None:
    folder = pick_folder()
    if folder is None:
        print("Aucun dossier sélectionné.", file=sys.stderr)
        raise SystemExit(1)

    if not folder.is_dir():
        print(f"Dossier invalide: {folder}", file=sys.stderr)
        raise SystemExit(1)

    global_store: DefaultDict[str, list[str]] = defaultdict(list)
    files_read = 0

    for fpath in sorted(iter_text_files(folder)):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"Impossible de lire {fpath}: {e}", file=sys.stderr)
            continue
        rel = str(fpath.relative_to(folder))
        files_read += 1
        found = extract_from_content(text, rel)
        merge_results(global_store, found)

    # Dossier de sortie à côté du script
    out_dir = Path(__file__).resolve().parent / "extraction_output"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    categories = ("smtp", "aws", "brevo", "sendgrid")
    for cat in categories:
        items = dedupe_preserve_order(global_store.get(cat, []))
        out_file = out_dir / f"{cat}_{ts}.txt"
        header = (
            f"# Catégorie: {cat.upper()}\n"
            f"# Dossier source: {folder}\n"
            f"# Fichiers texte parcourus: {files_read}\n"
            f"# Lignes extraites: {len(items)}\n"
            f"---\n"
        )
        out_file.write_text(header + "\n".join(items) + "\n", encoding="utf-8")
        print(f"Écrit: {out_file} ({len(items)} entrées)")

    # Résumé GUI
    tk, _, messagebox = _require_tkinter()
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "Extraction terminée",
        f"Dossier analysé:\n{folder}\n\n"
        f"Fichiers lus: {files_read}\n"
        f"Résultats dans:\n{out_dir}\n"
        f"(fichiers smtp_*, aws_*, brevo_*, sendgrid_*_{ts}.txt)",
    )
    root.destroy()


if __name__ == "__main__":
    main()
