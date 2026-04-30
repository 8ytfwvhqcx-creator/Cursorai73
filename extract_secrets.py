#!/usr/bin/env python3
"""
Parcourt un dossier choisi via l'explorateur de fichiers, lit les fichiers texte
et extrait les motifs liés à SMTP, AWS, Brevo et SendGrid dans des fichiers
de sortie par catégorie.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ImportError as e:
    print(
        "tkinter est requis pour le sélecteur de dossier.\n"
        "Sur Debian/Ubuntu : sudo apt install python3-tk",
        file=sys.stderr,
    )
    raise SystemExit(1) from e

# Extensions considérées comme « texte » (ajustez si besoin)
TEXT_EXTENSIONS = {
    ".txt",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".config",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".csv",
    ".log",
    ".md",
    ".html",
    ".htm",
    ".php",
    ".js",
    ".ts",
    ".py",
    ".sh",
    ".sql",
    ".properties",
    "",
}

# --- Motifs d'extraction (ordre : catégorie -> liste de (nom, regex) ) ---
# Chaque regex doit avoir au moins un groupe de capture pour la valeur utile,
# ou matcher une ligne entière pertinente.

PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "smtp": [
        (
            "smtp_url",
            re.compile(
                r"(smtp://[^\s\"'<>]+|smtps://[^\s\"'<>]+)",
                re.IGNORECASE,
            ),
        ),
        (
            "smtp_host_line",
            re.compile(
                r"(?i).*\b(smtp\.[a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9][a-z0-9.-]*\.smtp\.[a-z0-9.-]+)\b.*",
            ),
        ),
        (
            "mail_env",
            re.compile(
                r"(?i)^\s*(MAIL_HOST|MAIL_SERVER|SMTP_HOST|SMTP_SERVER|SMTP_URL|"
                r"MAIL_SMTP|EMAIL_HOST|MAILER_HOST|SMTP_ADDRESS)\s*[=:]\s*['\"]?([^\s'\"#]+)['\"]?\s*$",
            ),
        ),
        (
            "smtp_port",
            re.compile(
                r"(?i)^\s*(MAIL_PORT|SMTP_PORT|EMAIL_PORT)\s*[=:]\s*['\"]?(\d+)['\"]?\s*$",
            ),
        ),
        (
            "smtp_user_pass",
            re.compile(
                r"(?i)^\s*(MAIL_USERNAME|MAIL_USER|SMTP_USER|SMTP_USERNAME|"
                r"EMAIL_USER|MAILER_USER)\s*[=:]\s*['\"]?([^\s'\"#]+)['\"]?\s*$",
            ),
        ),
        (
            "smtp_password",
            re.compile(
                r"(?i)^\s*(MAIL_PASSWORD|SMTP_PASS|SMTP_PASSWORD|EMAIL_PASSWORD|"
                r"MAILER_PASSWORD)\s*[=:]\s*['\"]?([^\s'\"#]+)['\"]?\s*$",
            ),
        ),
    ],
    "aws": [
        ("aws_access_key_id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("aws_session_key", re.compile(r"\b(ASIA[0-9A-Z]{16})\b")),
        (
            "aws_secret_key_line",
            re.compile(
                r"(?i).*(?:AWS_SECRET_ACCESS_KEY|aws_secret|SECRET_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            ),
        ),
        (
            "aws_env",
            re.compile(
                r"(?i)^\s*(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|"
                r"AWS_REGION|AWS_DEFAULT_REGION)\s*[=:]\s*['\"]?([^\s'\"#]+)['\"]?\s*$",
            ),
        ),
        (
            "ses_endpoint",
            re.compile(
                r"(email\.[a-z0-9-]+\.amazonaws\.com|"
                r"ses\.[a-z0-9-]+\.amazonaws\.com)",
                re.IGNORECASE,
            ),
        ),
    ],
    "brevo": [
        (
            "brevo_xkeysib",
            re.compile(r"\b(xkeysib-[a-zA-Z0-9_-]+)\b"),
        ),
        (
            "brevo_api_key_env",
            re.compile(
                r"(?i)^\s*(BREVO_API_KEY|SENDINBLUE_API_KEY|BREVO_KEY)\s*[=:]\s*"
                r"['\"]?([^\s'\"#]+)['\"]?\s*$",
            ),
        ),
        (
            "brevo_url",
            re.compile(r"(https?://api\.brevo\.com[^\s\"'<>]*)", re.IGNORECASE),
        ),
        (
            "sendinblue_url",
            re.compile(
                r"(https?://api\.sendinblue\.com[^\s\"'<>]*)",
                re.IGNORECASE,
            ),
        ),
    ],
    "sendgrid": [
        (
            "sendgrid_sg",
            re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b"),
        ),
        (
            "sendgrid_env",
            re.compile(
                r"(?i)^\s*(SENDGRID_API_KEY)\s*[=:]\s*['\"]?([^\s'\"#]+)['\"]?\s*$",
            ),
        ),
    ],
}


def is_probably_text_file(path: Path) -> bool:
    if not path.is_file():
        return False
    return path.suffix.lower() in TEXT_EXTENSIONS


def read_file_safe(path: Path, max_bytes: int = 5 * 1024 * 1024) -> str | None:
    try:
        data = path.read_bytes()
        if len(data) > max_bytes:
            data = data[:max_bytes]
        # Essai UTF-8 puis latin-1 pour ne pas perdre de binaire « texte »
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="replace")
    except OSError:
        return None


def extract_from_line(
    line: str,
) -> list[tuple[str, str, str]]:
    """
    Retourne une liste de (catégorie, label_motif, extrait).
    """
    out: list[tuple[str, str, str]] = []
    line_stripped = line.rstrip("\n\r")
    for category, rules in PATTERNS.items():
        for label, rx in rules:
            for m in rx.finditer(line_stripped):
                groups = m.groups()
                if groups:
                    # Prendre le dernier groupe non vide typiquement la valeur
                    value = next(
                        (g for g in reversed(groups) if g and g.strip()),
                        m.group(0),
                    )
                else:
                    value = m.group(0)
                value = value.strip()
                if value and len(value) >= 3:
                    out.append((category, label, value))
    return out


def collect_from_folder(root: Path) -> dict[str, set[str]]:
    by_category: dict[str, set[str]] = defaultdict(set)
    for path in sorted(root.rglob("*")):
        if not is_probably_text_file(path):
            continue
        content = read_file_safe(path)
        if content is None:
            continue
        rel = path.relative_to(root)
        for i, line in enumerate(content.splitlines(), 1):
            for category, label, value in extract_from_line(line):
                entry = f"[{rel}:{i}] [{label}] {value}"
                by_category[category].add(entry)
    return by_category


def pick_folder() -> Path | None:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title="Choisir le dossier contenant les fichiers à analyser")
    root.destroy()
    if not path:
        return None
    return Path(path)


def main() -> int:
    folder = pick_folder()
    if folder is None:
        print("Aucun dossier sélectionné.", file=sys.stderr)
        return 1
    if not folder.is_dir():
        print(f"Dossier invalide : {folder}", file=sys.stderr)
        return 1

    print(f"Analyse de : {folder.resolve()}")
    found = collect_from_folder(folder)

    out_dir = folder / "_extractions_secrets"
    out_dir.mkdir(exist_ok=True)

    files_written = []
    for category in ("smtp", "aws", "brevo", "sendgrid"):
        items = sorted(found.get(category, []))
        out_path = out_dir / f"{category}.txt"
        out_path.write_text(
            "\n".join(items) + ("\n" if items else ""),
            encoding="utf-8",
        )
        files_written.append((out_path, len(items)))

    msg_lines = [
        f"Dossier de sortie : {out_dir}",
        "",
        "Fichiers :",
    ]
    for p, n in files_written:
        msg_lines.append(f"  • {p.name} : {n} entrée(s) unique(s)")
    summary = "\n".join(msg_lines)
    print(summary)

    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo("Extraction terminée", summary)
    root.destroy()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
