#!/usr/bin/env python3
"""
Sélectionne un dossier via l'explorateur, lit les fichiers texte,
extrait les correspondances SMTP, AWS, Brevo et SendGrid,
et les enregistre dans des fichiers par catégorie.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# tkinter : apt install python3-tk sur Debian/Ubuntu si manquant
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except ImportError as e:
    print("Installez python3-tk pour le sélecteur de dossier.", file=sys.stderr)
    raise SystemExit(1) from e

TEXT_EXTENSIONS = {".txt", ".log", ".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".csv", ".md"}


def pick_folder() -> Path | None:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title="Choisir le dossier contenant les fichiers texte")
    root.destroy()
    if not path:
        return None
    return Path(path).resolve()


def read_text_files(base: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for p in base.rglob("*"):
        if not p.is_file():
            continue
        # ignorer les extensions non texte ; sans extension : on tente quand même
        if p.suffix and p.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        # ignorer binaires évidents
        if b"\x00" in raw[:4096]:
            continue
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        out.append((p, text))
    return out


# --- Motifs d'extraction (lignes ou extraits pertinents) ---

PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "sendgrid": [
        re.compile(r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", re.I),
        re.compile(
            r"(?i)sendgrid[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
        re.compile(r"(?i)api\.sendgrid\.com[^\s'\"]*"),
    ],
    "brevo": [
        re.compile(r"xkeysib-[a-zA-Z0-9]{20,}", re.I),
        re.compile(
            r"(?i)(?:brevo|sendinblue)[_-]?(?:api[_-]?)?key\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
        re.compile(r"(?i)smtp-relay\.brevo\.com[^\s'\"]*"),
        re.compile(r"(?i)api\.brevo\.com[^\s'\"]*"),
    ],
    "aws": [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(
            r"(?i)aws[_-]?(?:access[_-]?key[_-]?(?:id)?|secret[_-]?(?:access[_-]?)?key)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
        re.compile(
            r"(?i)(?:email-smtp|smtp)\.([a-z0-9-]+)\.amazonaws\.com[^\s'\"]*"
        ),
        re.compile(
            r"(?i)ses[_-]?(?:region|endpoint)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
    ],
    "smtp": [
        re.compile(
            r"(?i)(?:smtp|smtps)://[^\s'\"<>]+",
        ),
        re.compile(
            r"(?i)(?:smtp|mail)[_-]?(?:host|server|url)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
        re.compile(
            r"(?i)(?:smtp|mail)[_-]?user(?:name)?\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
        re.compile(
            r"(?i)(?:smtp|mail)[_-]?(?:pass(?:word)?|pwd)\s*[=:]\s*['\"]?([^\s'\"]+)['\"]?"
        ),
        re.compile(
            r"(?i)(?:smtp|mail)[_-]?port\s*[=:]\s*['\"]?([0-9]+)['\"]?"
        ),
        # hôtes SMTP courants dans une ligne
        re.compile(
            r"(?i)\b(?:smtp|mail)\.[a-z0-9.-]+\.[a-z]{2,}(?::[0-9]+)?\b"
        ),
    ],
}


def extract_matches(text: str, category: str) -> set[str]:
    found: set[str] = set()
    for pat in PATTERNS.get(category, []):
        for m in pat.finditer(text):
            whole = m.group(0).strip()
            if len(whole) >= 4:
                found.add(whole)
            if m.lastindex:
                for g in m.groups():
                    if g:
                        g = g.strip()
                        if len(g) >= 3 and g != whole:
                            found.add(g)
    return found


def process_folder(base: Path, output_dir: Path) -> dict[str, set[str]]:
    aggregated: dict[str, set[str]] = {
        "smtp": set(),
        "aws": set(),
        "brevo": set(),
        "sendgrid": set(),
    }

    for path, content in read_text_files(base):
        try:
            rel = path.relative_to(base)
        except ValueError:
            rel = path
        for cat in ("sendgrid", "brevo", "aws", "smtp"):
            hits = extract_matches(content, cat)
            for h in hits:
                aggregated[cat].add(f"{h}  # {rel}")

    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    summary_lines = [f"Extraction {ts} UTC", f"Dossier source: {base}", ""]

    for cat, items in aggregated.items():
        out_file = output_dir / f"{cat}.txt"
        sorted_items = sorted(items, key=str.lower)
        out_file.write_text("\n".join(sorted_items) + ("\n" if sorted_items else ""), encoding="utf-8")
        summary_lines.append(f"{cat}: {len(items)} entrée(s) -> {out_file.name}")

    (output_dir / "_resume.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return aggregated


def main() -> None:
    base = pick_folder()
    if base is None:
        print("Aucun dossier sélectionné.")
        raise SystemExit(0)

    out = base / "extraction_par_categorie"
    agg = process_folder(base, out)

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    lines = [f"Terminé. Fichiers dans :\n{out}\n"] + [f"  {k}: {len(v)}" for k, v in agg.items()]
    messagebox.showinfo("Extraction", "\n".join(lines))
    root.destroy()
    print("\n".join(lines))


if __name__ == "__main__":
    main()
