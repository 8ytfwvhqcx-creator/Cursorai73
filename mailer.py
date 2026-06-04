import base64
import json
import os
import smtplib
import socket
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse


FILES = {
    "senders": "senders.txt",
    "subjects": "subjects.txt",
    "recipients": "recipients.txt",
    "html_folder": "contents",
    "report": "report.json",
}

HOST = os.getenv("SMTP_HOST", "smtp.postmarkapp.com")
PORT = int(os.getenv("SMTP_PORT", "587"))
USER = os.getenv("SMTP_USER", "")
PASS = os.getenv("SMTP_PASS", "")

SENDER_EMAILS = [
    "warren@webfly.io",
    "evolve-communities@webfly.io",
    "info@bracketforce.com",
    "evolve@webfly.io",
    "contact@webfly.io",
    "navi-care@webfly.io",
    "room@webfly.io",
    "grimbo-support@webfly.io",
    "info@webfly.io",
    "iamrunner@webfly.io",
]

# Proxy HTTP - format : http://user:pass@host:port
# Laisser USE_PROXY = False ou PROXY_URL vide pour connexion directe.
USE_PROXY = os.getenv("USE_PROXY", "false").lower() in {"1", "true", "yes"}
PROXY_URL = os.getenv("SMTP_PROXY_URL", "")


def parse_proxy_url(url):
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("PROXY_URL invalide - format : http://user:pass@host:port")
    return {
        "host": parsed.hostname,
        "port": parsed.port or 8080,
        "user": parsed.username or "",
        "password": parsed.password or "",
    }


def connect_via_http_proxy(dest_host, dest_port, proxy, timeout=30):
    """Tunnel SMTP via HTTP CONNECT."""
    sock = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)

    connect_lines = [
        f"CONNECT {dest_host}:{dest_port} HTTP/1.1",
        f"Host: {dest_host}:{dest_port}",
    ]

    if proxy["user"] or proxy["password"]:
        auth = base64.b64encode(
            f"{proxy['user']}:{proxy['password']}".encode()
        ).decode()
        connect_lines.append(f"Proxy-Authorization: Basic {auth}")

    connect_lines.extend(["Proxy-Connection: keep-alive", "", ""])
    sock.sendall("\r\n".join(connect_lines).encode())

    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200 " not in status_line:
        sock.close()
        raise OSError(f"Proxy CONNECT refuse : {status_line}")

    return sock


class ProxySMTP(smtplib.SMTP):
    """SMTP via tunnel HTTP CONNECT."""

    def __init__(self, host, port, proxy_url, timeout=30):
        self._smtp_host = host
        self._smtp_port = port
        self._proxy = parse_proxy_url(proxy_url)
        super().__init__(timeout=timeout)

    def connect(self, host="localhost", port=0, source_address=None):
        self.sock = connect_via_http_proxy(
            self._smtp_host,
            self._smtp_port,
            self._proxy,
            timeout=self.timeout,
        )
        self.file = self.sock.makefile("rb")
        (code, msg) = self.getreply()
        if code != 220:
            self.close()
            raise smtplib.SMTPConnectError(code, msg)
        return (code, msg)


def create_smtp_server(timeout=30):
    if not USER or not PASS:
        raise ValueError("SMTP_USER et SMTP_PASS doivent etre definis.")

    if USE_PROXY and PROXY_URL.strip():
        server = ProxySMTP(HOST, PORT, PROXY_URL, timeout=timeout)
        proxy = parse_proxy_url(PROXY_URL)
        print(f"Proxy HTTP : {proxy['host']}:{proxy['port']}")
    else:
        server = smtplib.SMTP(HOST, PORT, timeout=timeout)

    server.starttls()
    server.login(USER, PASS)
    return server


def setup():
    if not os.path.exists(FILES["html_folder"]):
        os.makedirs(FILES["html_folder"])

    for key, filename in FILES.items():
        if key != "html_folder" and not os.path.exists(filename):
            with open(filename, "w", encoding="utf-8") as f:
                if key == "report":
                    json.dump({"success": [], "errors": []}, f)
                else:
                    f.write("")


def load_list(filename):
    if not os.path.exists(filename):
        return []

    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def parse_recipient(line, mode):
    if mode == 1:
        return {
            "nom": "",
            "prenom": "",
            "email": line.strip(),
        }

    if mode == 2:
        parts = [x.strip() for x in line.split(",")]

        if len(parts) != 3:
            return None

        nom, prenom, email = parts

        return {
            "nom": nom,
            "prenom": prenom,
            "email": email,
        }

    return None


def ask_positive_int(label, default):
    try:
        value = int(input(label) or default)
    except Exception:
        value = default

    return max(value, 1)


def update_report(status, email, error=None):
    try:
        data = {"success": [], "errors": []}

        if os.path.exists(FILES["report"]):
            with open(FILES["report"], "r", encoding="utf-8") as f:
                try:
                    data = json.load(f)
                except Exception:
                    pass

        entry = {
            "email": email,
            "time": time.ctime(),
        }

        if status == "success":
            data["success"].append(entry)
        else:
            entry["error"] = str(error)
            data["errors"].append(entry)

        with open(FILES["report"], "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    except Exception:
        pass


def send_mail():
    setup()

    print("Choisir le mode recipients :")
    print("1 = email seulement")
    print("2 = nom,prenom,email")

    try:
        mode = int(input("Mode : ").strip())
        if mode not in [1, 2]:
            print("Mode invalide")
            return
    except Exception:
        print("Mode invalide")
        return

    senders = load_list(FILES["senders"])
    subjects = load_list(FILES["subjects"])
    recipients = load_list(FILES["recipients"])

    html_files = [
        f for f in os.listdir(FILES["html_folder"])
        if f.endswith(".html")
    ]

    if not recipients:
        print("Recipients vide")
        return

    if not html_files:
        print("Aucun html")
        return

    rot_sender = ask_positive_int("Rotate sender: ", 1)
    rot_sender_email = ask_positive_int("Rotate email expediteur: ", 1)
    rot_subject = ask_positive_int("Rotate subject: ", 1)
    rot_html = ask_positive_int("Rotate html: ", 1)
    delay = float(input("Delay: ") or 0.2)

    try:
        print("Connexion SMTP...")
        server = create_smtp_server(timeout=30)
        print(f"[OK] Connecte a {HOST}")
    except Exception as e:
        print(e)
        return

    success = 0

    for i, recipient_line in enumerate(recipients):
        recipient = parse_recipient(recipient_line, mode)

        if not recipient:
            print(f"[X] Format invalide : {recipient_line}")
            continue

        nom = recipient["nom"]
        prenom = recipient["prenom"]
        target_email = recipient["email"]

        try:
            sender_idx = (i // rot_sender) % len(senders) if senders else 0
            sender_email_idx = (i // rot_sender_email) % len(SENDER_EMAILS)
            subject_idx = (i // rot_subject) % len(subjects) if subjects else 0
            html_idx = (i // rot_html) % len(html_files)

            sender_email = SENDER_EMAILS[sender_email_idx]
            sender_name = (
                senders[sender_idx]
                if senders
                else sender_email.split("@")[0]
            )

            subject = (
                subjects[subject_idx]
                if subjects
                else "Information"
            )

            html_path = os.path.join(
                FILES["html_folder"],
                html_files[html_idx],
            )

            with open(html_path, "r", encoding="utf-8") as f:
                html_content = f.read()

            html_content = (
                html_content
                .replace("(nom)", nom)
                .replace("(prenom)", prenom)
            )

            msg = MIMEMultipart()
            msg["From"] = f"{sender_name} <{sender_email}>"
            msg["To"] = target_email
            msg["Subject"] = subject

            msg.attach(
                MIMEText(html_content, "html", "utf-8")
            )

            server.sendmail(
                sender_email,
                target_email,
                msg.as_string(),
            )

            success += 1

            print(
                f"[OK] {i + 1}/{len(recipients)} "
                f"{target_email} via {sender_email}"
            )

            update_report("success", target_email)

            time.sleep(delay)

        except Exception as e:
            print(f"[X] {target_email} : {e}")
            update_report("error", target_email, e)

    try:
        server.quit()
    except Exception:
        pass

    print(f"Termine : {success}")


if __name__ == "__main__":
    send_mail()
