"""The optional, informational health endpoint (R28).

``GET /health`` (also ``/``) returns one small JSON document. It is served
by the standard library's HTTP server, one request at a time, on a daemon
thread, and binds to loopback unless the operator configures otherwise.
Other paths answer 404 and other methods 501; no CORS headers are sent.
The status code is always 200: the document informs, it does not gate.

The document holds counts, timestamps and flags only: no secrets, no
recipient names or addresses, no installation ids or site ids, and no
message text. The service publishes a fresh document after each cycle; the
server thread only ever reads the latest published bytes.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from datetime import datetime

    from vrm_alert_relay.delivery import DeliveryHealth

    from .relay import RelayStatus

__all__ = ["HEALTH_PATHS", "SCHEMA_VERSION", "HealthServer", "HealthState", "health_document"]

logger = logging.getLogger(__name__)

SCHEMA_VERSION: Final = 1
HEALTH_PATHS: Final = frozenset({"/", "/health"})
REQUEST_TIMEOUT_SECONDS: Final = 5.0
_NOT_FOUND: Final = b'{"error":"not found"}'


def _time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def health_document(
    *,
    version: str,
    dry_run: bool,
    status: RelayStatus,
    delivery: DeliveryHealth,
    cycle_failed: bool = False,
) -> dict[str, object]:
    """The health document; see docs/operations.md for the schema.

    ``status`` is ``degraded`` when the latest cycle raised, an installation is
    degraded, or state persistence is not healthy and durable; otherwise
    ``starting`` until the first cycle completes, then ``ok``.
    """
    monitoring_ok = status.degraded == 0 and not cycle_failed
    persistence_ok = delivery.persistence_healthy and delivery.durable_accounting
    if not (monitoring_ok and persistence_ok):
        overall = "degraded"
    elif status.cycles == 0:
        overall = "starting"
    else:
        overall = "ok"
    return {
        "schema": SCHEMA_VERSION,
        "status": overall,
        "version": version,
        "dry_run": dry_run,
        "started_at": _time(status.started_at),
        "monitoring": {
            "status": "ok" if monitoring_ok else "degraded",
            "cycles": status.cycles,
            "last_cycle_failed": cycle_failed,
            "last_cycle_at": _time(status.last_cycle_at),
            "last_successful_poll_at": _time(status.last_successful_poll_at),
            "installations": status.installations,
            "failing_installations": status.failing,
            "degraded_installations": status.degraded,
        },
        "state_persistence": {
            "healthy": delivery.persistence_healthy,
            "durable_accounting": delivery.durable_accounting,
            "error": delivery.persistence_error,
        },
        "delivery": {
            "queued": delivery.queued,
            "suppressed_pending": delivery.suppressed_pending,
            "suppressed_total": delivery.suppressed_total,
            "sent_last_hour": delivery.sent_last_hour,
            "sent_last_day": delivery.sent_last_day,
            "would_send_last_hour": delivery.dry_run_sent_last_hour,
            "would_send_last_day": delivery.dry_run_sent_last_day,
            "would_send_over_cap_total": delivery.dry_run_over_cap_total,
        },
    }


class HealthState:
    """The latest health document, published by the loop and read by the server."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._body = json.dumps({"schema": SCHEMA_VERSION, "status": "starting"}).encode()

    def publish(self, document: dict[str, object]) -> None:
        body = json.dumps(document, separators=(",", ":")).encode()
        with self._lock:
            self._body = body

    def body(self) -> bytes:
        with self._lock:
            return self._body


class _Handler(BaseHTTPRequestHandler):
    server_version = "vrm-alert-relay"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = REQUEST_TIMEOUT_SECONDS
    error_content_type = "text/plain; charset=utf-8"
    error_message_format = "%(code)d %(message)s\n"
    server: _HealthHTTPServer

    def version_string(self) -> str:
        return self.server_version

    def do_GET(self) -> None:  # name required by BaseHTTPRequestHandler
        self._respond(include_body=True)

    def do_HEAD(self) -> None:  # name required by BaseHTTPRequestHandler
        self._respond(include_body=False)

    def _respond(self, *, include_body: bool) -> None:
        path = self.path.split("?", 1)[0]
        if path in HEALTH_PATHS:
            status, body = 200, self.server.state.body()
        else:
            status, body = 404, _NOT_FOUND
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002  # base-class signature
        """Request lines are not logged; they could carry anything a client sends."""


class _HealthHTTPServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: HealthState) -> None:
        self.address_family = (
            socket.AF_INET6 if ipaddress.ip_address(address[0]).version == 6 else socket.AF_INET  # noqa: PLR2004  # IP version number
        )
        self.state = state
        super().__init__(address, _Handler)


class HealthServer:
    """Serves :class:`HealthState` on ``bind``:``port`` from a daemon thread."""

    def __init__(self, bind: str, port: int, state: HealthState) -> None:
        self._server = _HealthHTTPServer((bind, port), state)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.5},
            name="health-endpoint",
            daemon=True,
        )

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        self._thread.start()
        host, port = self.address
        logger.info(
            "health endpoint listening",
            extra={"event": "health.listening", "bind": host, "port": port},
        )

    def close(self) -> None:
        if self._thread.is_alive():
            self._server.shutdown()
            self._thread.join()
        self._server.server_close()
