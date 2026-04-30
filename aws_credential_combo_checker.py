#!/usr/bin/env python3
"""
Lit un fichier texte, extrait les Access Key ID (AKIA… ou ASIA…) et les Secret Access Key,
forme toutes les combinaisons possibles (si clefs mélangées dans le fichier),
puis valide chaque paire avec STS GetCallerIdentity dans chaque région connue de STS.

Sans dépendances externes autres que boto3 (voir requirements-aws-credentials.txt).
"""

from __future__ import annotations

import argparse
import itertools
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import ClientError
except ImportError as e:
    print(
        "Installez boto3 : pip install -r requirements-aws-credentials.txt",
        file=sys.stderr,
    )
    raise SystemExit(1) from e

# Access Key ID IAM longue durée : AKIA… ; session temporaire : ASIA… (16 car. après le préfixe)
_ACCESS_KEY_ID_PATTERN = re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b")

# Secret Access Key : 40 caractères (alphabet base64 sans padding)
_SECRET_PATTERN = re.compile(r"\b([A-Za-z0-9+/]{40})\b")


def unique_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def extract_akias(text: str) -> list[str]:
    return unique_preserve_order(_ACCESS_KEY_ID_PATTERN.findall(text))


def extract_secrets(text: str) -> list[str]:
    return unique_preserve_order(_SECRET_PATTERN.findall(text))


def mask_access_key(aki: str) -> str:
    if len(aki) <= 8:
        return aki[:4] + "…"
    return f"{aki[:4]}…{aki[-4:]}"


def try_region_sts(
    access_key_id: str,
    secret_access_key: str,
    region: str,
    *,
    timeout: int,
) -> tuple[str, bool, str]:
    """
    Retourne (region, ok, message).
    message est vide si ok, sinon code ou courte description d’erreur.
    """
    client = boto3.client(
        "sts",
        region_name=region,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        config=Config(
            connect_timeout=timeout,
            read_timeout=timeout,
            retries={"max_attempts": 2, "mode": "standard"},
        ),
    )
    try:
        r = client.get_caller_identity()
        aid = r.get("Account", "")
        arn = r.get("Arn", "")
        return region, True, f"account={aid} arn={arn}"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "ClientError")
        return region, False, code
    except Exception as e:
        return region, False, type(e).__name__


def classify_pair_failure(codes_or_msgs: list[str]) -> str:
    """Si l’une des erreurs indique une paire invalide, on peut court-circuiter."""
    fatal = {"InvalidClientTokenId", "SignatureDoesNotMatch", "UnrecognizedClientException"}
    for c in codes_or_msgs:
        if c in fatal:
            return c
    return ""


def check_pair_all_regions(
    access_key_id: str,
    secret_access_key: str,
    regions: list[str],
    *,
    timeout: int,
    workers: int,
    stop_on_auth_failure: bool,
) -> tuple[bool, list[tuple[str, bool, str]]]:
    """
    Teste la paire dans chaque région. Si stop_on_auth_failure et première erreur
    d’identité/signature, arrête et marque la paire comme invalide.
    Retourne (pair_valid_anywhere, liste (region, ok, detail)).
    """
    results: list[tuple[str, bool, str]] = []
    pair_invalid = False

    if workers <= 1:
        for region in regions:
            reg, ok, msg = try_region_sts(
                access_key_id, secret_access_key, region, timeout=timeout
            )
            results.append((reg, ok, msg))
            if ok:
                continue
            if stop_on_auth_failure and classify_pair_failure([msg]):
                pair_invalid = True
                break
        any_ok = any(r[1] for r in results)
        return (not pair_invalid) and any_ok, results

    # Parallèle par région
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(
                try_region_sts,
                access_key_id,
                secret_access_key,
                region,
                timeout=timeout,
            ): region
            for region in regions
        }
        early_bad: str | None = None
        for fut in as_completed(futures):
            reg, ok, msg = fut.result()
            results.append((reg, ok, msg))
            if not ok and stop_on_auth_failure:
                bad = classify_pair_failure([msg])
                if bad:
                    early_bad = bad
                    break
        if early_bad:
            ex.shutdown(wait=False, cancel_futures=True)
            return False, sorted(results, key=lambda x: x[0])

    results.sort(key=lambda x: x[0])
    any_ok = any(r[1] for r in results)
    return any_ok, results


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Combine toutes les Access Key ID et tous les secrets trouvés dans un fichier, "
            "puis teste chaque paire avec STS dans chaque région."
        ),
    )
    parser.add_argument(
        "fichier",
        type=Path,
        help="Fichier texte contenant des AKIA et secrets mélangés",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=12,
        metavar="SEC",
        help="Timeout connexion/lecture par appel STS (défaut: 12)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        metavar="N",
        help="Taille du pool pour tester les régions en parallèle (défaut: 8)",
    )
    parser.add_argument(
        "--no-stop-on-auth-failure",
        action="store_true",
        help=(
            "Continuer à joindre les autres régions même après erreur "
            "InvalidClientTokenId / SignatureDoesNotMatch (plus lent)"
        ),
    )
    parser.add_argument(
        "--max-combos",
        type=int,
        default=50000,
        metavar="N",
        help="Refuse de lancer si (access keys × secrets) dépasse cette limite (défaut: 50000)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Ignorer la limite --max-combos (attention : explosion combinatoire)",
    )
    args = parser.parse_args()

    path = args.fichier
    if not path.is_file():
        print(f"Erreur : fichier introuvable : {path}", file=sys.stderr)
        return 1

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Erreur de lecture : {e}", file=sys.stderr)
        return 1

    akias = extract_akias(text)
    secrets = extract_secrets(text)

    print(
        f"Access Key ID uniques : {len(akias)}, secrets uniques (40 car.) : {len(secrets)}.",
        file=sys.stderr,
    )
    if not akias:
        print(
            "Aucune Access Key trouvée (AKIA… ou ASIA… + 16 caractères alphanumériques).",
            file=sys.stderr,
        )
        return 1
    if not secrets:
        print(
            "Aucun secret trouvé (format attendu : exactement 40 caractères [A-Za-z0-9+/]).",
            file=sys.stderr,
        )
        return 1

    n_combo = len(akias) * len(secrets)
    if n_combo > args.max_combos and not args.yes:
        print(
            f"Trop de combinaisons ({n_combo}) ; utilisez --yes ou réduisez le fichier.",
            file=sys.stderr,
        )
        return 1

    session = boto3.session.Session()
    regions = session.get_available_regions("sts")
    if not regions:
        print("Aucune région STS dans cette installation botocore.", file=sys.stderr)
        return 1

    print(f"Régions STS à tester : {len(regions)}.", file=sys.stderr)

    stop_on_auth = not args.no_stop_on_auth_failure
    exit_fail = False

    for i, (aki, secret) in enumerate(itertools.product(akias, secrets), start=1):
        label = mask_access_key(aki)
        print(f"\n--- Combinaison {i}/{n_combo} : {label} ---", file=sys.stderr)

        valid, rows = check_pair_all_regions(
            aki,
            secret,
            regions,
            timeout=args.timeout,
            workers=max(1, args.workers),
            stop_on_auth_failure=stop_on_auth,
        )

        if not valid:
            # Détail : première erreur fatale ou résumé
            fatal_codes = [
                r[2]
                for r in rows
                if not r[1] and classify_pair_failure([r[2]])
            ]
            if fatal_codes:
                print(f"{label}\tINVALID\t{fatal_codes[0]}")
            else:
                errs = [f"{r[0]}:{r[2]}" for r in rows if not r[1]][:5]
                tail = " …" if sum(1 for r in rows if not r[1]) > 5 else ""
                print(f"{label}\tINVALID\tregions_failed_sample={errs}{tail}")
            exit_fail = True
            continue

        ok_regions = [r for r in rows if r[1]]
        first_detail = ok_regions[0][2] if ok_regions else ""
        print(f"{label}\tVALID\tregions_ok={len(ok_regions)}/{len(rows)}\t{first_detail}")

        for reg, ok, msg in rows:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {reg}\t{msg}")

    return 1 if exit_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
