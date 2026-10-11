from __future__ import annotations

import gzip
import json
import logging
import ssl
import traceback
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import TYPE_CHECKING, Any

import httpx
import pytest

from vrm_alert_relay.net import (
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES,
    Endpoint,
    HttpContentEncodingRefused,
    HttpDecodeError,
    HttpError,
    HttpRedirectRefused,
    HttpResponse,
    HttpStatusError,
    HttpTimeout,
    HttpTooLarge,
    HttpTransportError,
    InvalidHeaderError,
    InvalidRequestError,
    InvalidUrlError,
    RequestTooLargeError,
    SafeHttpClient,
    Timeouts,
)
from vrm_alert_relay.net import client as client_module
from vrm_alert_relay.net.transport import DnsTimeout, HardenedTransport

if TYPE_CHECKING:
    from conftest import StubTransport

BASE = "https://api.example.com/v1"
QUERY_CANARY = "fictitious-query-secret-0001"
BODY_CANARY = "fictitious-body-secret-0002"
HEADER_CANARY = "fictitious-header-secret-0003"
PATH_CANARY = "fictitious-path-secret-0004"
RECIPIENT = "2025550143"
CANARIES = (QUERY_CANARY, BODY_CANARY, HEADER_CANARY, PATH_CANARY, RECIPIENT)


class ChunkStream(httpx.SyncByteStream):
    """A response body yielding ``chunk`` up to ``count`` times (forever if None)."""

    def __init__(self, chunk: bytes, count: int | None = None) -> None:
        self.chunk = chunk
        self.count = count
        self.yielded = 0

    def __iter__(self) -> Iterator[bytes]:
        while self.count is None or self.yielded < self.count:
            self.yielded += 1
            yield self.chunk


class RaisingStream(httpx.SyncByteStream):
    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def __iter__(self) -> Iterator[bytes]:
        yield b"partial"
        raise self.exc


def ok(content: bytes = b"{}", **kwargs: Any) -> httpx.Response:
    return httpx.Response(200, content=content, **kwargs)


def assert_no_canaries(exc: BaseException) -> None:
    assert exc.__context__ is None
    assert exc.__cause__ is None
    rendered = [
        str(exc),
        repr(exc),
        repr(exc.args),
        "".join(traceback.format_exception(exc)),
    ]
    for text in rendered:
        for secret in CANARIES:
            assert secret not in text
        assert "?" not in text.split("\n")[0]


@pytest.fixture
def client() -> Iterator[SafeHttpClient]:
    with SafeHttpClient() as instance:
        yield instance


# Construction and hardening


def test_underlying_client_is_hardened(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    original = httpx.Client.__init__

    def spy(self: httpx.Client, *args: Any, **kwargs: Any) -> None:
        captured.update(kwargs)
        original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", spy)
    with SafeHttpClient():
        pass
    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False
    assert isinstance(captured["transport"], HardenedTransport)
    assert captured["headers"]["Accept-Encoding"] == "identity"
    timeout = captured["timeout"]
    assert (timeout.connect, timeout.read, timeout.write, timeout.pool) == (
        5.0,
        10.0,
        10.0,
        5.0,
    )


def test_tls_context_verifies_certificates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    context = client_module._tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_proxy_and_tls_environment_is_ignored(
    monkeypatch: pytest.MonkeyPatch, transport: StubTransport
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"):
        monkeypatch.setenv(name, "http://proxy.example.invalid:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/nonexistent")
    transport.respond(lambda request: ok())
    with SafeHttpClient() as client:
        client.get(BASE)
        assert client._client._mounts == {}
    assert transport.requests[0].url.host == "api.example.com"


def test_defaults() -> None:
    client = SafeHttpClient()
    assert client.timeouts == Timeouts(connect=5.0, read=10.0, write=10.0, pool=5.0, deadline=30.0)
    assert client.max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES == 1024 * 1024
    assert client.max_request_bytes == DEFAULT_MAX_REQUEST_BYTES == 64 * 1024
    client.close()
    assert client._client.is_closed


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_max_request_bytes_validation(limit: Any) -> None:
    with pytest.raises(ValueError, match="max_request_bytes must be a positive integer"):
        SafeHttpClient(max_request_bytes=limit)


@pytest.mark.parametrize(
    "body",
    [
        {"json": {"message": BODY_CANARY + "x" * DEFAULT_MAX_REQUEST_BYTES}},
        {"form": {"message": BODY_CANARY + "x" * DEFAULT_MAX_REQUEST_BYTES}},
        {
            "multipart": {
                "file": (
                    "a.bin",
                    BODY_CANARY.encode() * 5000,
                    "application/octet-stream",
                )
            }
        },
    ],
)
def test_oversize_request_body_rejected_before_io(
    client: SafeHttpClient, transport: StubTransport, body: dict[str, Any]
) -> None:
    with pytest.raises(RequestTooLargeError) as excinfo:
        client.post(f"{BASE}?token={QUERY_CANARY}", **body)
    assert isinstance(excinfo.value, InvalidRequestError)
    assert excinfo.value.limit == DEFAULT_MAX_REQUEST_BYTES
    assert str(excinfo.value) == f"request body exceeded 65536 bytes: POST {BASE}"
    assert_no_canaries(excinfo.value)
    assert transport.requests == []


def test_request_body_cap_is_inclusive_and_configurable(
    transport: StubTransport,
) -> None:
    transport.respond(lambda request: ok())
    with SafeHttpClient(max_request_bytes=100) as client:
        client.post(BASE, json="x" * 98)
        with pytest.raises(RequestTooLargeError):
            client.post(BASE, json="x" * 99)
    assert transport.requests[0].content == b'"' + b"x" * 98 + b'"'
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"connect": 0},
        {"read": -1},
        {"write": float("inf")},
        {"pool": float("nan")},
        {"deadline": True},
        {"connect": "5"},
    ],
)
def test_timeouts_validation(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="positive finite"):
        Timeouts(**kwargs)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_max_response_bytes_validation(limit: Any) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        SafeHttpClient(max_response_bytes=limit)


def test_default_and_custom_headers(transport: StubTransport) -> None:
    transport.respond(lambda request: ok())
    with SafeHttpClient(headers={"X-Client": "relay"}, user_agent="relay-test") as client:
        client.get(BASE, headers={"Authorization": f"Bearer {HEADER_CANARY}"})
    sent = transport.requests[0].headers
    assert sent["user-agent"] == "relay-test"
    assert sent["accept-encoding"] == "identity"
    assert sent["x-client"] == "relay"
    assert sent["authorization"] == f"Bearer {HEADER_CANARY}"


def test_constructor_validates_headers() -> None:
    with pytest.raises(InvalidHeaderError):
        SafeHttpClient(user_agent="relay\r\nX-Injected: 1")
    with pytest.raises(InvalidHeaderError):
        SafeHttpClient(headers={"X-Bad": "a\nb"})


# Successful requests


def test_get_returns_response(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(
        lambda request: ok(b'{"value": 42}', headers={"content-type": "application/json"})
    )
    response = client.get(Endpoint(BASE).join("installations", 123456))
    assert response.status_code == 200
    assert response.json() == {"value": 42}
    assert response.text() == '{"value": 42}'
    assert response.headers["content-type"] == "application/json"
    assert transport.requests[0].method == "GET"
    assert transport.requests[0].url.path == "/v1/installations/123456"


def test_accepts_string_target(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok(b"done"))
    assert client.request("get", f"{BASE}/x").content == b"done"
    assert transport.requests[0].method == "GET"


def test_head_and_no_content(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: httpx.Response(204))
    assert client.request("HEAD", BASE).content == b""
    assert client.request("DELETE", BASE).status_code == 204


def test_params_merge_with_endpoint_query(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok())
    client.get(
        f"{BASE}?api_username=user&method=getBalance",
        params={"api_password": BODY_CANARY},
    )
    client.get(BASE, params=[("a", 1), ("a", 2.5)])
    first = transport.requests[0].url.params
    assert first["api_username"] == "user"
    assert first["method"] == "getBalance"
    assert first["api_password"] == BODY_CANARY
    assert transport.requests[1].url.params.get_list("a") == ["1", "2.5"]


def test_invalid_params_rejected(client: SafeHttpClient, transport: StubTransport) -> None:
    with pytest.raises(InvalidRequestError, match="query parameter names"):
        client.get(BASE, params={"token": object()})  # type: ignore[dict-item]
    with pytest.raises(InvalidRequestError, match="query parameter names"):
        client.get(BASE, params=[(1, "x")])  # type: ignore[list-item]
    with pytest.raises(InvalidRequestError, match="pairs"):
        client.get(BASE, params=["token"])  # type: ignore[list-item]
    assert transport.requests == []


def test_unencodable_json_rejected(client: SafeHttpClient, transport: StubTransport) -> None:
    with pytest.raises(InvalidRequestError, match="could not be encoded"):
        client.post(BASE, json={"value": float("nan"), "pw": BODY_CANARY})
    assert transport.requests == []


def test_text_uses_declared_charset() -> None:
    latin = HttpResponse(
        200, httpx.Headers({"content-type": "text/plain; charset=latin-1"}), b"\xe9"
    )
    unknown = HttpResponse(
        200, httpx.Headers({"content-type": "text/plain; charset=nope"}), b"\xc3\xa9"
    )
    missing = HttpResponse(200, httpx.Headers(), b"\xff")
    assert latin.text() == "é"
    assert unknown.text() == "é"
    assert missing.text() == "\ufffd"


def test_json_decode_error_has_no_body() -> None:
    response = HttpResponse(200, httpx.Headers(), f"not json {BODY_CANARY}".encode())
    with pytest.raises(HttpDecodeError) as excinfo:
        response.json()
    assert_no_canaries(excinfo.value)
    deep = HttpResponse(200, httpx.Headers(), b"[" * 100_000)
    with pytest.raises(HttpDecodeError):
        deep.json()


def test_response_repr_hides_body_and_headers() -> None:
    response = HttpResponse(200, httpx.Headers({"set-cookie": HEADER_CANARY}), BODY_CANARY.encode())
    assert repr(response) == "HttpResponse(status_code=200)"


# Bodies


def test_json_body(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok())
    client.post(BASE, json={"message": "Battery low", "api_password": BODY_CANARY})
    request = transport.requests[0]
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.read()) == {
        "message": "Battery low",
        "api_password": BODY_CANARY,
    }


def test_form_body(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok())
    client.post(BASE, form={"api_password": BODY_CANARY, "dst": RECIPIENT})
    request = transport.requests[0]
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert request.read() == f"api_password={BODY_CANARY}&dst={RECIPIENT}".encode()


def test_multipart_body(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok())
    client.post(
        BASE,
        multipart={
            "api_password": BODY_CANARY,
            "message": "Battery low",
            "attachment": ("report.txt", b"soc=12", "text/plain"),
        },
    )
    request = transport.requests[0]
    assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    body = request.read()
    assert b'name="api_password"\r\n\r\n' + BODY_CANARY.encode() in body
    assert b'name="message"\r\n\r\nBattery low' in body
    assert b'name="attachment"; filename="report.txt"\r\nContent-Type: text/plain' in body
    assert b"soc=12" in body


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"json": {"a": 1}, "form": {"b": "2"}}, "only one"),
        ({"form": {"b": "2"}, "multipart": {"c": "3"}}, "only one"),
        ({"multipart": {}}, "at least one"),
        ({"multipart": {"f": ("name", "not-bytes", "text/plain")}}, "must be a str or"),
        ({"multipart": {"f": ("name", b"x")}}, "must be a str or"),
        ({"multipart": {1: "x"}}, "names must be strings"),
        ({"json": {"secret": object(), "pw": BODY_CANARY}}, "could not be encoded"),
    ],
)
def test_invalid_bodies_rejected_before_io(
    client: SafeHttpClient,
    transport: StubTransport,
    kwargs: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(InvalidRequestError, match=message) as excinfo:
        client.post(BASE, **kwargs)
    assert_no_canaries(excinfo.value)
    assert transport.requests == []


def test_multipart_content_type_validated(client: SafeHttpClient, transport: StubTransport) -> None:
    with pytest.raises(InvalidHeaderError):
        client.post(BASE, multipart={"f": ("name", b"x", "text/plain\r\nX-Injected: 1")})
    assert transport.requests == []


# Validation before I/O


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/v1",
        "file:///etc/passwd",
        "data:text/plain,hello",
        "ftp://api.example.com/",
        "https://user:pw@api.example.com/",
        "https:///v1",
    ],
)
def test_bad_urls_rejected_before_io(
    client: SafeHttpClient, transport: StubTransport, url: str
) -> None:
    with pytest.raises(InvalidUrlError):
        client.get(url)
    assert transport.requests == []


@pytest.mark.parametrize(
    "headers",
    [
        {"X-Test": "a\rb"},
        {"X-Test": "a\nb"},
        {"X-Test": "a\r\nX-Injected: 1"},
        {"X-Test": "a\x00b"},
        {"X-Test": "a\x1bb"},
        {"X-Test": "a\x7fb"},
        {"X-Test": "x" * 9000},
        {"X-Test": 5},
        {"Bad Name": "v"},
        {"X:Y": "v"},
        {"": "v"},
        {"X-\r\nInjected": "v"},
        {"Host": "evil.example"},
        {"Content-Length": "0"},
        {"Transfer-Encoding": "chunked"},
        {"Accept-Encoding": "gzip"},
        {"accept-encoding": "identity"},
    ],
)
def test_bad_headers_rejected_before_io(
    client: SafeHttpClient, transport: StubTransport, headers: dict[str, Any]
) -> None:
    with pytest.raises(InvalidHeaderError) as excinfo:
        client.get(BASE, headers=headers)
    assert transport.requests == []
    for value in headers.values():
        if isinstance(value, str) and len(value) > 1:
            assert value not in str(excinfo.value)


def test_tab_allowed_in_header_value(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok())
    client.get(BASE, headers={"X-Test": "a\tb"})
    assert transport.requests[0].headers["x-test"] == "a\tb"


@pytest.mark.parametrize("method", ["TRACE", "CONNECT", "OPTIONS", "", 5])
def test_unsupported_methods(client: SafeHttpClient, transport: StubTransport, method: Any) -> None:
    with pytest.raises(InvalidRequestError, match="method"):
        client.request(method, BASE)
    assert transport.requests == []


# Redirects and status codes


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307, 308])
def test_redirects_are_refused(
    client: SafeHttpClient, transport: StubTransport, status: int
) -> None:
    transport.respond(
        lambda request: httpx.Response(
            status, headers={"location": f"https://evil.example/?token={QUERY_CANARY}"}
        )
    )
    with pytest.raises(HttpRedirectRefused) as excinfo:
        client.get(f"{BASE}?token={QUERY_CANARY}")
    assert excinfo.value.status == status
    assert str(excinfo.value) == f"HTTP redirect refused ({status}): GET {BASE}"
    assert "evil.example" not in str(excinfo.value)
    assert len(transport.requests) == 1
    assert_no_canaries(excinfo.value)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 502, 503])
def test_status_errors(client: SafeHttpClient, transport: StubTransport, status: int) -> None:
    transport.respond(lambda request: httpx.Response(status, content=BODY_CANARY.encode()))
    with pytest.raises(HttpStatusError) as excinfo:
        client.post(f"{BASE}?token={QUERY_CANARY}", form={"api_password": BODY_CANARY})
    assert excinfo.value.status == status
    assert excinfo.value.retry_after is None
    assert excinfo.value.method == "POST"
    assert excinfo.value.target == BASE
    assert str(excinfo.value) == f"HTTP {status}: POST {BASE}"
    assert repr(excinfo.value) == f"HttpStatusError('HTTP {status}: POST {BASE}')"
    assert_no_canaries(excinfo.value)


def test_informational_status_is_an_error(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: httpx.Response(101))
    with pytest.raises(HttpStatusError):
        client.get(BASE)


_FUTURE = datetime.now(UTC) + timedelta(hours=1)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("120", 120.0),
        (" 0 ", 0.0),
        ("9999999999", 86400.0),
        ("Wed, 21 Oct 2015 07:28:00 GMT", 0.0),
        ("Sun, 06 Nov 1994 08:49:37 -0000", 0.0),
        ("soon", None),
        ("-5", None),
        ("", None),
    ],
)
def test_retry_after_parsing(
    client: SafeHttpClient,
    transport: StubTransport,
    header: str,
    expected: float | None,
) -> None:
    transport.respond(lambda request: httpx.Response(429, headers={"retry-after": header}))
    with pytest.raises(HttpStatusError) as excinfo:
        client.get(BASE)
    assert excinfo.value.retry_after == expected


def test_retry_after_future_date(client: SafeHttpClient, transport: StubTransport) -> None:
    header = format_datetime(_FUTURE, usegmt=True)
    transport.respond(lambda request: httpx.Response(503, headers={"retry-after": header}))
    with pytest.raises(HttpStatusError) as excinfo:
        client.get(BASE)
    assert excinfo.value.retry_after is not None
    assert 3000 < excinfo.value.retry_after <= 3600


# Timeouts and transport errors


@pytest.mark.parametrize(
    ("exc_type", "phase"),
    [
        (httpx.ConnectTimeout, "connect"),
        (httpx.ReadTimeout, "read"),
        (httpx.WriteTimeout, "write"),
        (httpx.PoolTimeout, "pool"),
        (DnsTimeout, "dns"),
        (httpx.TimeoutException, "unknown"),
    ],
)
def test_timeouts_are_mapped(
    client: SafeHttpClient,
    transport: StubTransport,
    exc_type: type[httpx.TimeoutException],
    phase: str,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc_type(f"timed out talking to {request.url} {HEADER_CANARY}", request=request)

    transport.respond(handler)
    with pytest.raises(HttpTimeout) as excinfo:
        client.get(f"{BASE}?token={QUERY_CANARY}", headers={"X-Key": HEADER_CANARY})
    assert excinfo.value.phase == phase
    assert str(excinfo.value) == f"HTTP timeout ({phase}): GET {BASE}"
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__context__ is None
    assert_no_canaries(excinfo.value)


@pytest.mark.parametrize(
    "exc_type",
    [httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, httpx.ProxyError],
)
def test_transport_errors_are_mapped(
    client: SafeHttpClient,
    transport: StubTransport,
    exc_type: type[httpx.TransportError],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc_type(f"failed: {request.url} {BODY_CANARY}", request=request)

    transport.respond(handler)
    with pytest.raises(HttpTransportError) as excinfo:
        client.post(f"{BASE}?token={QUERY_CANARY}", json={"pw": BODY_CANARY})
    assert excinfo.value.cause == exc_type.__name__
    assert str(excinfo.value) == f"HTTP transport error ({exc_type.__name__}): POST {BASE}"
    assert_no_canaries(excinfo.value)


@pytest.mark.parametrize(
    ("exc", "expected", "detail"),
    [
        (httpx.ReadTimeout(f"read timeout {QUERY_CANARY}"), HttpTimeout, "read"),
        (
            httpx.ReadError(f"connection reset {QUERY_CANARY}"),
            HttpTransportError,
            "ReadError",
        ),
    ],
)
def test_errors_while_streaming_body(
    client: SafeHttpClient,
    transport: StubTransport,
    exc: Exception,
    expected: type[HttpError],
    detail: str,
) -> None:
    transport.respond(lambda request: httpx.Response(200, stream=RaisingStream(exc)))
    with pytest.raises(expected) as excinfo:
        client.get(BASE)
    assert detail in str(excinfo.value)
    assert_no_canaries(excinfo.value)


class FailingCloseStream(ChunkStream):
    def close(self) -> None:
        raise httpx.ReadError(f"close failed {QUERY_CANARY}")


def test_close_failure_does_not_replace_error(
    client: SafeHttpClient, transport: StubTransport
) -> None:
    transport.respond(lambda request: httpx.Response(500, stream=FailingCloseStream(b"x", 1)))
    with pytest.raises(HttpStatusError) as excinfo:
        client.get(BASE)
    assert excinfo.value.status == 500
    assert_no_canaries(excinfo.value)


def test_secret_path_endpoint_hides_path_in_errors(
    client: SafeHttpClient, transport: StubTransport
) -> None:
    transport.respond(lambda request: httpx.Response(500))
    endpoint = Endpoint(f"https://hooks.example.com/hook/{PATH_CANARY}", secret_path=True)
    with pytest.raises(HttpStatusError) as excinfo:
        client.post(endpoint, json={"text": "Battery low"})
    assert str(excinfo.value) == "HTTP 500: POST https://hooks.example.com/[REDACTED]"
    assert transport.requests[0].url.path == f"/hook/{PATH_CANARY}"
    assert_no_canaries(excinfo.value)


# Response size cap and deadline


def test_declared_oversize_body_rejected_without_reading(
    client: SafeHttpClient, transport: StubTransport
) -> None:
    stream = ChunkStream(b"x" * 1024)
    transport.respond(
        lambda request: httpx.Response(
            200,
            headers={"content-length": str(DEFAULT_MAX_RESPONSE_BYTES + 1)},
            stream=stream,
        )
    )
    with pytest.raises(HttpTooLarge) as excinfo:
        client.get(BASE)
    assert excinfo.value.limit == DEFAULT_MAX_RESPONSE_BYTES
    assert stream.yielded == 0


def test_streamed_oversize_body_aborted(client: SafeHttpClient, transport: StubTransport) -> None:
    stream = ChunkStream(b"x" * 65536)
    transport.respond(lambda request: httpx.Response(200, stream=stream))
    with pytest.raises(HttpTooLarge, match="exceeded 1048576 bytes"):
        client.get(BASE)
    assert stream.yielded == DEFAULT_MAX_RESPONSE_BYTES // 65536 + 1


def test_understated_content_length_still_capped(transport: StubTransport) -> None:
    stream = ChunkStream(b"x" * 100, count=5)
    transport.respond(
        lambda request: httpx.Response(200, headers={"content-length": "garbage"}, stream=stream)
    )
    with SafeHttpClient(max_response_bytes=250) as client, pytest.raises(HttpTooLarge):
        client.get(BASE)
    assert stream.yielded == 3


def test_body_at_cap_is_accepted(transport: StubTransport) -> None:
    transport.respond(lambda request: httpx.Response(200, stream=ChunkStream(b"x" * 100, count=3)))
    with SafeHttpClient(max_response_bytes=300) as client:
        assert len(client.get(BASE).content) == 300


def test_per_request_cap_override(client: SafeHttpClient, transport: StubTransport) -> None:
    transport.respond(lambda request: ok(b"x" * 11))
    with pytest.raises(HttpTooLarge, match="exceeded 10 bytes"):
        client.get(BASE, max_response_bytes=10)
    with pytest.raises(ValueError, match="positive integer"):
        client.get(BASE, max_response_bytes=0)


class FakeClock:
    def __init__(self, step: float) -> None:
        self.now = 1000.0
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


def test_deadline_enforced_while_streaming(
    monkeypatch: pytest.MonkeyPatch, transport: StubTransport
) -> None:
    monkeypatch.setattr(client_module, "monotonic", FakeClock(step=4.0))
    stream = ChunkStream(b"x", count=None)
    transport.respond(lambda request: httpx.Response(200, stream=stream))
    with (
        SafeHttpClient(timeouts=Timeouts(deadline=10.0)) as client,
        pytest.raises(HttpTimeout) as excinfo,
    ):
        client.get(BASE)
    assert excinfo.value.phase == "deadline"
    assert stream.yielded == 2


def test_deadline_checked_before_reading_body(
    monkeypatch: pytest.MonkeyPatch, transport: StubTransport
) -> None:
    monkeypatch.setattr(client_module, "monotonic", FakeClock(step=60.0))
    stream = ChunkStream(b"x", count=1)
    transport.respond(lambda request: httpx.Response(200, stream=stream))
    with SafeHttpClient() as client, pytest.raises(HttpTimeout, match="deadline"):
        client.get(BASE)
    assert stream.yielded == 0


# Logging


def test_debug_log_has_no_secrets_or_body(
    client: SafeHttpClient, transport: StubTransport, caplog: pytest.LogCaptureFixture
) -> None:
    transport.respond(lambda request: ok(BODY_CANARY.encode()))
    with caplog.at_level(logging.DEBUG, logger="vrm_alert_relay.net"):
        client.post(
            f"{BASE}?token={QUERY_CANARY}",
            headers={"Authorization": HEADER_CANARY},
            form={"api_password": BODY_CANARY, "dst": RECIPIENT},
        )
    records = [r for r in caplog.records if r.name.startswith("vrm_alert_relay.net")]
    assert len(records) == 1
    record = records[0]
    assert record.getMessage() == "http request completed"
    assert record.args == ()
    extras = set(record.__dict__) - set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__)
    assert extras <= {
        "http_method",
        "http_target",
        "http_status",
        "http_bytes",
        "elapsed_ms",
        "message",
        "asctime",
    }
    assert record.__dict__["http_target"] == BASE
    assert record.__dict__["http_status"] == 200
    dumped = repr(record.__dict__)
    for secret in CANARIES:
        assert secret not in dumped


def test_library_loggers_cannot_emit_urls_or_headers(
    client: SafeHttpClient, transport: StubTransport, caplog: pytest.LogCaptureFixture
) -> None:
    transport.respond(lambda request: ok(headers={"set-cookie": HEADER_CANARY}))
    with caplog.at_level(logging.DEBUG):
        client.get(f"{BASE}?token={QUERY_CANARY}")
        logging.getLogger("httpx").info("HTTP Request: GET %s", QUERY_CANARY)
        logging.getLogger("httpcore.http11").debug("headers %s", HEADER_CANARY)
        logging.getLogger("httpx").warning("still visible")
    library = [r for r in caplog.records if r.name.startswith(("httpx", "httpcore"))]
    assert [r.getMessage() for r in library] == ["still visible"]
    assert QUERY_CANARY not in caplog.text
    assert HEADER_CANARY not in caplog.text


def test_library_logger_filter_installed_once() -> None:
    SafeHttpClient().close()
    SafeHttpClient().close()
    for name in client_module._LIBRARY_LOGGERS:
        filters = logging.getLogger(name).filters
        assert filters.count(client_module._LIBRARY_FILTER) == 1


# Compression


@pytest.mark.parametrize("encoding", ["gzip", "GZIP", "br", "deflate", "identity, gzip", "zstd"])
def test_compressed_response_refused_before_reading(
    client: SafeHttpClient, transport: StubTransport, encoding: str
) -> None:
    stream = ChunkStream(gzip.compress(b"\x00" * (32 * 1024 * 1024)), count=1)
    transport.respond(
        lambda request: httpx.Response(200, headers={"content-encoding": encoding}, stream=stream)
    )
    with pytest.raises(HttpContentEncodingRefused) as excinfo:
        client.get(f"{BASE}?token={QUERY_CANARY}")
    assert str(excinfo.value) == f"HTTP response content-encoding refused: GET {BASE}"
    assert stream.yielded == 0
    assert_no_canaries(excinfo.value)


@pytest.mark.parametrize("encoding", ["identity", "Identity", ""])
def test_identity_encoding_accepted(
    client: SafeHttpClient, transport: StubTransport, encoding: str
) -> None:
    transport.respond(lambda request: ok(b"plain", headers={"content-encoding": encoding}))
    assert client.get(BASE).content == b"plain"


def test_undeclared_compressed_body_is_never_decoded(
    client: SafeHttpClient, transport: StubTransport
) -> None:
    bomb = gzip.compress(b"\x00" * (32 * 1024 * 1024))
    assert len(bomb) < 64 * 1024
    transport.respond(lambda request: ok(bomb))
    response = client.get(BASE)
    assert response.content == bomb


def test_caller_cannot_override_accept_encoding() -> None:
    with pytest.raises(InvalidHeaderError, match="managed by the client"):
        SafeHttpClient(headers={"Accept-Encoding": "gzip, br"})
    with pytest.raises(InvalidHeaderError, match="managed by the client"):
        SafeHttpClient(headers={"ACCEPT-ENCODING": "identity"})


# Exception chaining


def test_validation_errors_have_no_context(client: SafeHttpClient) -> None:
    for call in (
        lambda: client.get("https://[::1/"),
        lambda: client.get("https://" + "é" * 70 + ".example/"),
        lambda: client.post(BASE, json={"value": float("nan")}),
        lambda: HttpResponse(200, httpx.Headers(), b"not json").json(),
    ):
        with pytest.raises(HttpError) as excinfo:
            call()
        assert excinfo.value.__context__ is None
        assert excinfo.value.__cause__ is None
        assert excinfo.value.__suppress_context__ is False
