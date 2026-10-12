"""A throwaway HTTPS server for the image's TLS smoke test.

Runs inside the relay image (``--entrypoint /opt/venv/bin/python``) on an
internal Docker network. Port 8443 serves the certificate signed by the test
CA; port 8444 serves one signed by a second, untrusted CA. Both answer every
GET with ``200 ok``. Certificates and keys are read from ``/certs``.
"""

from __future__ import annotations

import http.server
import ssl
import sys
import threading

CERTS = "/certs"
PORTS = {8443: "trusted", 8444: "untrusted"}


class _Ok(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002  # base signature
        sys.stdout.write(f"{self.server.server_address[1]}: {format % args}\n")


def _serve(port: int, name: str) -> http.server.ThreadingHTTPServer:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(f"{CERTS}/{name}.pem", f"{CERTS}/{name}.key")
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), _Ok)  # noqa: S104  # container-internal
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    servers = [_serve(port, name) for port, name in PORTS.items()]
    for server in servers[1:]:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    sys.stdout.write(f"TLS smoke server listening on {sorted(PORTS)}\n")
    servers[0].serve_forever()


if __name__ == "__main__":
    main()
