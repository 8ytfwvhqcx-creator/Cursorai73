#!/usr/bin/env python3
"""Pont TLS pour OpenBullet2 : exécute les requêtes avec tls_client (empreinte Chrome)
   pendant qu'OB2 parle en HTTP local sans TLS vers Poulpeo.

   Usage:
     pip install tls-client
     HTTPS_PROXY=http://user:pass@host:port python poulpeo_tls_bridge.py

   Puis dans la config OB2 : SET USEPROXY FALSE (le proxy est lu ici via HTTPS_PROXY).

   POST http://127.0.0.1:18765/exec
   Content-Type: application/json
   {
     "method": "POST",
     "url": "https://mobile.poulpeo.com/...",
     "headers": { "Authorization": "...", ... },
     "body": "realm=..."
   }

   Réponse : {"status": <int>, "text": "<corps brut>"}
"""
from typing import Optional, Tuple

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import tls_client
except ImportError:
    print("Installez: pip install tls-client", file=sys.stderr)
    sys.exit(1)

HOST = "127.0.0.1"
PORT = 18765


def new_session():
    s = tls_client.Session(
        client_identifier="chrome_131",
        random_tls_extension_order=True,
    )
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def run_request(method: str, url: str, headers: dict, body: Optional[str]) -> Tuple[int, str]:
    s = new_session()
    method = (method or "GET").upper()
    hdrs = {str(k): str(v) for k, v in (headers or {}).items()}
    data = body if body is not None else None
    if method == "GET":
        r = s.get(url, headers=hdrs)
    elif method == "POST":
        r = s.post(url, headers=hdrs, data=data)
    else:
        raise ValueError(f"Méthode non supportée: {method}")
    return int(r.status_code), r.text


class Handler(BaseHTTPRequestHandler):
    server_version = "PoulpeoTlsBridge/1"

    def log_message(self, fmt, *args):
        print(f"[bridge] {args[0] if args else fmt}")

    def do_POST(self):
        if self.path != "/exec":
            self.send_error(404, "use POST /exec")
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n) if n else b"{}"
            j = json.loads(raw.decode("utf-8"))
            status, text = run_request(
                j.get("method", "GET"),
                j["url"],
                j.get("headers") or {},
                j.get("body"),
            )
            out = json.dumps({"status": status, "text": text}, ensure_ascii=False)
            b = out.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        except Exception as e:
            err = json.dumps({"status": 0, "text": "", "error": str(e)}, ensure_ascii=False)
            b = err.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)


def main():
    httpd = HTTPServer((HOST, PORT), Handler)
    print(f"Poulpeo TLS bridge — http://{HOST}:{PORT}/exec (tls_client chrome_131)")
    print("Proxy: variable d'environnement HTTPS_PROXY ou HTTP_PROXY si besoin.")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
