#!/usr/bin/env python3
"""
Sélectionne un dossier via l’explorateur de fichiers, lit les fichiers texte,
extrait les correspondances SMTP génériques, AWS, Brevo et SendGrid,
puis enregistre les résultats (sans doublons) dans des fichiers .txt par catégorie.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from tkinter import Tk, filedialog
except ImportError:
    Tk = None  # type: ignore[misc, assignment]
    filedialog = None  # type: ignore[misc, assignment]


# Extensions considérées comme « texte » (ajustez si besoin)
TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".env",
    ".ini",
    ".cfg",
    ".conf",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".htm",
    ".md",
    ".sql",
    ".sh",
    ".py",
    ".php",
    ".js",
    ".ts",
    ".properties",
    "",
}

# --- Regex (ordre d’application : clés spécifiques avant SMTP large) ---

# SendGrid : clés API classiques SG.xxx.yyy
RE_SENDGRID = re.compile(
    r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
)

# Brevo (ex-Sendinblue) : préfixe xkeysib-
RE_BREVO = re.compile(
    r"\bxkeysib-[a-fA-F0-9]{64}-[a-zA-Z0-9]+\b",
)

# AWS Access Key ID (commence par AKIA, AIDA, ASIA, etc. — 20 caractères alphanum)
RE_AWS_ACCESS_KEY = re.compile(
    r"\b(?:AKIA|AIDA|ASIA|AROA|AIPA|ANPA|ANVA|AGPA)[A-Z0-9]{16}\b",
)

# Secret AWS : uniquement si étiqueté (évite les faux positifs sur chaînes aléatoires)
RE_AWS_SECRET_LABELED = re.compile(
    r"(?i)(?:aws_?secret_?access_?key|secret_?access_?key|awssecretkey)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
)

# URL SMTP smtp://user:pass@host:port
RE_SMTP_URL = re.compile(
    r"\bsmtp(?:s)?://[^\s\"'<>]+",
    re.IGNORECASE,
)

# Ligne type host:port:user:password (ports SMTP courants)
RE_SMTP_COLON = re.compile(
    r"(?m)^[^\s#:]{3,200}:(?:25|465|587|2525|26|2587):\S+:\S+$",
)

# Paires clé/valeur fréquentes pour SMTP
RE_SMTP_KV = re.compile(
    r"(?im)\b(?:SMTP|MAIL)_?(?:HOST|SERVER|URL|USER(?:NAME)?|PASSWORD|PASS|PORT)\s*[=:]\s*([^\s#\"']+)",
)


def iter_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if "_extractions_credentials" in p.parts:
            continue
        if p.suffix.lower() in TEXT_EXTENSIONS or p.suffix == "":
            try:
                if p.stat().st_size > 20 * 1024 * 1024:
                    continue
            except OSError:
                continue
            files.append(p)
    return sorted(files)


def read_safe(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    for enc in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def extract_sendgrid(text: str) -> set[str]:
    return set(RE_SENDGRID.findall(text))


def extract_brevo(text: str) -> set[str]:
    return set(RE_BREVO.findall(text))


def extract_aws(text: str) -> set[str]:
    found: set[str] = set()
    found.update(RE_AWS_ACCESS_KEY.findall(text))
    for m in RE_AWS_SECRET_LABELED.finditer(text):
        found.add(m.group(1))
    return found


def extract_smtp(text: str) -> set[str]:
    out: set[str] = set()
    out.update(RE_SMTP_URL.findall(text))
    for line in text.splitlines():
        line = line.strip()
        if RE_SMTP_COLON.match(line):
            out.add(line)
    for m in RE_SMTP_KV.finditer(text):
        val = m.group(1).strip("\"'")
        if val and len(val) > 2:
            out.add(m.group(0).strip())
    # Retirer ce qui ressemble déjà à une URL SendGrid/Brevo pour ne pas tout mélanger
    return {x for x in out if not RE_SENDGRID.search(x) and not RE_BREVO.search(x)}


def write_category(out_dir: Path, name: str, lines: set[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.txt"
    sorted_lines = sorted(lines, key=str.lower)
    path.write_text("\n".join(sorted_lines) + ("\n" if sorted_lines else ""), encoding="utf-8")
    return path


def pick_folder_dialog() -> str:
    if Tk is not None and filedialog is not None and (os.environ.get("DISPLAY") or sys.platform == "darwin"):
        root = Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(title="Choisir le dossier contenant les fichiers texte")
        root.destroy()
        if folder:
            return folder
    if sys.platform.startswith("linux") and shutil.which("zenity"):
        try:
            r = subprocess.run(
                ["zenity", "--file-selection", "--directory", "--title=Dossier à analyser"],
                capture_output=True,
                text=True,
                check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except OSError:
            pass
    return ""


def main() -> int:
    if len(sys.argv) > 1:
        folder = str(Path(sys.argv[1]).expanduser().resolve())
    else:
        folder = pick_folder_dialog()

    if not folder:
        print(
            "Aucun dossier : passez le chemin en argument (python3 credential_scanner.py /chemin), "
            "ou installez python3-tk / zenity pour le sélecteur graphique.",
            file=sys.stderr,
        )
        return 1

    src = Path(folder)
    out_dir = src / "_extractions_credentials"

    all_smtp: set[str] = set()
    all_aws: set[str] = set()
    all_brevo: set[str] = set()
    all_sendgrid: set[str] = set()

    files = iter_text_files(src)
    for fp in files:
        text = read_safe(fp)
        if not text:
            continue
        all_smtp.update(extract_smtp(text))
        all_aws.update(extract_aws(text))
        all_brevo.update(extract_brevo(text))
        all_sendgrid.update(extract_sendgrid(text))

    paths = [
        write_category(out_dir, "smtp", all_smtp),
        write_category(out_dir, "aws", all_aws),
        write_category(out_dir, "brevo", all_brevo),
        write_category(out_dir, "sendgrid", all_sendgrid),
    ]

    print(f"Dossier source : {src}")
    print(f"Sortie : {out_dir}")
    for p in paths:
        n = len(p.read_text(encoding="utf-8").splitlines()) if p.stat().st_size else 0
        print(f"  - {p.name} : {n} ligne(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
