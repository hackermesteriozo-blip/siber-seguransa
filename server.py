
import hashlib
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HOST = "127.0.0.1"
PORT = 8000
BASE_DIR = Path(__file__).resolve().parent
MAX_BODY = 16_384
TIMEOUT = 8

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def valid_domain(domain):
    domain = domain.strip().rstrip(".").lower()

    if not domain or len(domain) > 253:
        raise ValueError("Domínio vazio ou muito longo.")

    try:
        ipaddress.ip_address(domain)
        raise ValueError("Informe um nome de domínio, não um IP.")
    except ValueError as exc:
        if str(exc) == "Informe um nome de domínio, não um IP.":
            raise

    labels = domain.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
        ):
            raise ValueError("Nome de domínio inválido.")

    return domain


def public_addresses(domain):
    """Resolve um domínio e bloqueia destinos não públicos."""
    results = socket.getaddrinfo(
        domain, None, type=socket.SOCK_STREAM
    )

    addresses = sorted({item[4][0] for item in results})

    if not addresses:
        raise ValueError("O domínio não resolveu para um endereço.")

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError(
                "Destino não público bloqueado por segurança."
            )

    return addresses


def dns_lookup(domain):
    domain = valid_domain(domain)

    results = socket.getaddrinfo(
        domain, None, type=socket.SOCK_STREAM
    )

    addresses = sorted({item[4][0] for item in results})

    return {
        "domain": domain,
        "addresses": addresses,
        "count": len(addresses),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_headers(url):
    parsed = urlparse(url)

    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
    ):
        raise ValueError(
            "Use uma URL HTTPS pública, sem credenciais ou porta personalizada."
        )

    domain = valid_domain(parsed.hostname)
    addresses = public_addresses(domain)

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AnonCyberSec/1.0"},
        method="GET",
    )

    opener = urllib.request.build_opener(
        NoRedirect,
        urllib.request.HTTPSHandler(
            context=ssl.create_default_context()
        ),
    )

    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            status_code = response.status
            headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        # Redirecionamentos são relatados, não seguidos.
        if 300 <= exc.code < 400:
            return {
                "url": url,
                "status": exc.code,
                "redirect": True,
                "message": "Redirecionamento não seguido.",
                "headers": dict(exc.headers.items()),
                "resolved_addresses": addresses,
            }
        raise

    normalized = {key.lower(): value for key, value in headers.items()}
    present = {
        name: normalized[name]
        for name in SECURITY_HEADERS
        if name in normalized
    }

    missing = [
        name for name in SECURITY_HEADERS
        if name not in normalized
    ]

    return {
        "url": url,
        "status": status_code,
        "resolved_addresses": addresses,
        "security_headers_found": present,
        "security_headers_missing": missing,
        "note": "Cabeçalhos ausentes exigem avaliação contextual.",
    }


def check_tls(domain):
    domain = valid_domain(domain)
    addresses = public_addresses(domain)

    context = ssl.create_default_context()

    with socket.create_connection(
        (domain, 443), timeout=TIMEOUT
    ) as connection:
        with context.wrap_socket(
            connection, server_hostname=domain
        ) as secure:
            cert = secure.getpeercert()

            return {
                "domain": domain,
                "tls_version": secure.version(),
                "cipher": secure.cipher()[0],
                "certificate_subject": cert.get("subject"),
                "certificate_issuer": cert.get("issuer"),
                "valid_from": cert.get("notBefore"),
                "valid_until": cert.get("notAfter"),
                "resolved_addresses": addresses,
                "verification": "Certificado aceito pela validação TLS do Python.",
            }


def hash_content(content):
    raw = content.encode("utf-8")

    return {
        "algorithm": "SHA-256",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "note": "Hash do texto enviado, não de um arquivo do disco.",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AnonCyberSec/1.0"

    def send_json(self, status, data):
        body = json.dumps(
            data, ensure_ascii=False, indent=2
        ).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/health":
            return self.send_json(200, {
                "ok": True,
                "service": "ANON CYBERSEC PRO",
                "time": datetime.now(timezone.utc).isoformat(),
            })

        if self.path not in ("/", "/index.html"):
            return self.send_json(404, {"error": "Rota não encontrada."})

        index = BASE_DIR / "index.html"

        if not index.is_file():
            return self.send_json(500, {
                "error": "index.html não encontrado na pasta do servidor."
            })

        content = index.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self):
        routes = {
            "/api/dns": ("domain", dns_lookup),
            "/api/headers": ("url", check_headers),
            "/api/tls": ("domain", check_tls),
            "/api/hash": ("content", hash_content),
        }

        if self.path not in routes:
            return self.send_json(404, {"error": "Rota não encontrada."})

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length <= 0 or length > MAX_BODY:
                return self.send_json(413, {
                    "error": "Corpo vazio ou maior que o limite permitido."
                })

            if "application/json" not in self.headers.get("Content-Type", ""):
                return self.send_json(415, {
                    "error": "Envie os dados em formato JSON."
                })

            payload = json.loads(self.rfile.read(length))

            if not isinstance(payload, dict):
                return self.send_json(400, {
                    "error": "O corpo precisa ser um objeto JSON."
                })

            field, function = routes[self.path]
            value = payload.get(field)

            if not isinstance(value, str) or not value.strip():
                return self.send_json(400, {
                    "error": f"Campo obrigatório: {field}"
                })

            if len(value) > MAX_BODY:
                return self.send_json(413, {
                    "error": "O campo excedeu o limite permitido."
                })

            result = function(value.strip())
            return self.send_json(200, {
                "ok": True,
                "result": result,
            })

        except (ValueError, UnicodeError) as exc:
            return self.send_json(400, {"error": str(exc)})

        except socket.timeout:
            return self.send_json(504, {
                "error": "A consulta excedeu o tempo limite."
            })

        except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
            return self.send_json(502, {
                "error": "A consulta falhou.",
                "detail": str(exc)[:300],
            })

        except json.JSONDecodeError:
            return self.send_json(400, {
                "error": "JSON inválido."
            })

    def log_message(self, fmt, *args):
        print("[HTTP]", self.address_string(), fmt % args)


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True

    print("=" * 48)
    print(" ANON CYBERSEC PRO")
    print("=" * 48)
    print(f" Painel: http://{HOST}:{PORT}")
    print(" Backend: ativo")
    print(" Para encerrar: Ctrl+C")
    print("=" * 48)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando servidor...")
    finally:
        server.server_close()
