"""Check the relay's TLS verification inside the image, against a local test server.

Runs inside the relay image (``--entrypoint /opt/venv/bin/python``) on an
internal Docker network with no route to the internet, next to
``tls_smoke_server.py``. ``tls.example.test`` and ``wrong.example.test`` both
name the server; its certificate covers only the first.

Uses the project's own client: :class:`SafeHttpClient` with ``ca_file``, the
same call the Home Assistant and webhook providers make for their ``ca_file``
option, plus the verifying context it builds (``load_ca_file``) for a direct
handshake that shows why a connection was refused. Checks:

- the default (certifi) context loads a non-empty trust store and rejects the
  test server;
- a request succeeds when the test CA is supplied as ``ca_file``;
- a certificate from another CA is rejected;
- a certificate for another hostname is rejected.
"""

from __future__ import annotations

import socket
import ssl
import sys
import time

from vrm_alert_relay.net import HttpTransportError, SafeHttpClient, load_ca_file
from vrm_alert_relay.net.client import _tls_context

CA_FILE = "/certs/ca.pem"
HOST = "tls.example.test"
WRONG_HOST = "wrong.example.test"
TRUSTED_PORT = 8443
UNTRUSTED_PORT = 8444
UNTRUSTED_ISSUER = 20  # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
HOSTNAME_MISMATCH = 62  # X509_V_ERR_HOSTNAME_MISMATCH


def _wait_for_server() -> None:
    deadline = time.monotonic() + 30
    while True:
        try:
            with socket.create_connection((HOST, TRUSTED_PORT), timeout=2):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


def _handshake_error(context: ssl.SSLContext, host: str, port: int) -> ssl.SSLCertVerificationError:
    """The verification error a handshake with ``context`` fails with."""
    with socket.create_connection((host, port), timeout=10) as raw:
        try:
            with context.wrap_socket(raw, server_hostname=host):
                pass
        except ssl.SSLCertVerificationError as error:
            return error
    sys.stderr.write(f"FAILED: handshake with {host}:{port} was accepted\n")
    raise SystemExit(1)


def _client_get(host: str, port: int) -> str:
    """``ok: <body>`` or ``refused: <cause>`` for a GET through SafeHttpClient."""
    with SafeHttpClient(ca_file=CA_FILE) as client:
        try:
            response = client.get(f"https://{host}:{port}/")
        except HttpTransportError as error:
            return f"refused: {error.cause}"
    return f"ok: {response.status_code} {response.text()}"


def main() -> None:
    _wait_for_server()
    failures: list[str] = []

    def report(ok: bool, line: str) -> None:  # noqa: FBT001  # local helper
        sys.stdout.write(f"{'ok' if ok else 'FAILED'}: {line}\n")
        if not ok:
            failures.append(line)

    default = _tls_context()
    stats = default.cert_store_stats()
    report(stats["x509_ca"] > 0, f"default (certifi) context loads {stats['x509_ca']} CAs")
    error = _handshake_error(default, HOST, TRUSTED_PORT)
    report(
        error.verify_code == UNTRUSTED_ISSUER,
        f"default context rejects the test CA: {error.verify_message}",
    )

    result = _client_get(HOST, TRUSTED_PORT)
    report(result == "ok: 200 ok", f"SafeHttpClient(ca_file) to {HOST}:{TRUSTED_PORT}: {result}")

    result = _client_get(HOST, UNTRUSTED_PORT)
    report(result.startswith("refused:"), f"untrusted certificate via SafeHttpClient: {result}")
    error = _handshake_error(load_ca_file(CA_FILE), HOST, UNTRUSTED_PORT)
    report(
        error.verify_code == UNTRUSTED_ISSUER,
        f"untrusted certificate handshake: {error.verify_message}",
    )

    result = _client_get(WRONG_HOST, TRUSTED_PORT)
    report(result.startswith("refused:"), f"hostname mismatch via SafeHttpClient: {result}")
    error = _handshake_error(load_ca_file(CA_FILE), WRONG_HOST, TRUSTED_PORT)
    report(
        error.verify_code == HOSTNAME_MISMATCH,
        f"hostname mismatch handshake: {error.verify_message}",
    )

    if failures:
        raise SystemExit(1)
    sys.stdout.write("TLS smoke checks passed\n")


if __name__ == "__main__":
    main()
