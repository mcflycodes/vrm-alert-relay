from __future__ import annotations

import pytest

from vrm_alert_relay.net import Endpoint, InvalidUrlError
from vrm_alert_relay.net import endpoint as endpoint_module
from vrm_alert_relay.net.endpoint import MAX_URL_LENGTH

QUERY_CANARY = "fictitious-query-secret-0001"


@pytest.mark.parametrize(
    ("url", "display"),
    [
        ("https://example.com", "https://example.com/"),
        ("https://example.com/", "https://example.com/"),
        ("HTTPS://EXAMPLE.COM/Api", "https://example.com/Api"),
        ("https://example.com:8443/api/v1", "https://example.com:8443/api/v1"),
        ("https://192.0.2.10:8123/api", "https://192.0.2.10:8123/api"),
        ("https://[2001:db8::1]:8123/api", "https://[2001:db8::1]:8123/api"),
        ("https://bücher.example/x", "https://xn--bcher-kva.example/x"),
        ("https://homeassistant.local/api", "https://homeassistant.local/api"),
        ("https://home_assistant.lan:8123", "https://home_assistant.lan:8123/"),
        ("https://example.com./x", "https://example.com./x"),
    ],
)
def test_accepts_https_urls(url: str, display: str) -> None:
    endpoint = Endpoint(url)
    assert endpoint.display == display
    assert str(endpoint) == display
    assert repr(endpoint) == f"Endpoint({display!r})"


def test_accessors() -> None:
    endpoint = Endpoint("https://example.com:8443/api?k=v")
    assert endpoint.host == "example.com"
    assert endpoint.port == 8443
    assert endpoint.path == "/api"
    assert endpoint.url.query == b"k=v"
    assert endpoint.secret_path is False


def test_query_is_kept_but_never_displayed() -> None:
    endpoint = Endpoint(f"https://example.com/api?token={QUERY_CANARY}")
    assert QUERY_CANARY in str(endpoint.url)
    for text in (endpoint.display, str(endpoint), repr(endpoint)):
        assert QUERY_CANARY not in text
        assert "?" not in text


def test_secret_path_is_redacted() -> None:
    endpoint = Endpoint(
        "https://hooks.example.com/services/T000/B000/XXXX", secret_path=True
    )
    assert endpoint.display == "https://hooks.example.com/[REDACTED]"
    assert "T000" not in repr(endpoint)
    joined = endpoint.join("more")
    assert joined.secret_path is True
    assert joined.display == "https://hooks.example.com/[REDACTED]"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "file:///etc/passwd",
        "data:text/plain,hello",
        "ftp://example.com/",
        "javascript:alert(1)",
        "ws://example.com/",
        "example.com/path",
        "//example.com/path",
    ],
)
def test_rejects_non_https_schemes(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="scheme must be https"):
        Endpoint(url)


def test_unprintable_scheme_is_not_echoed() -> None:
    scheme = "x" * 40
    with pytest.raises(InvalidUrlError) as excinfo:
        Endpoint(f"{scheme}://example.com/")
    assert scheme not in str(excinfo.value)
    assert "unsupported scheme" in str(excinfo.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:fictitious-pass@example.com/",
        "https://user@example.com/",
        "https://@example.com/",
        "https://example.com@evil.example/",
    ],
)
def test_rejects_userinfo(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="userinfo") as excinfo:
        Endpoint(url)
    assert "fictitious-pass" not in repr(excinfo.value)


@pytest.mark.parametrize("url", ["https:///path", "https://:443/", "https:path"])
def test_rejects_empty_host(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="host"):
        Endpoint(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/a b",
        "https://example.com/\x00",
        "https://example.com/\r\nHost: evil.example",
        "https://example.com/\t",
        "https://example.com\\@evil.example/",
        " https://example.com/",
        "https://example.com/\x7f",
    ],
)
def test_rejects_whitespace_controls_and_backslashes(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="whitespace"):
        Endpoint(url)


def test_rejects_fragment() -> None:
    with pytest.raises(InvalidUrlError, match="fragment"):
        Endpoint("https://example.com/api#section")


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:0/",
        "https://example.com:99999/",
        "https://example.com:-1/",
        "https://example.com:notaport/",
    ],
)
def test_rejects_invalid_port(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="port"):
        Endpoint(url)


def test_default_port_is_normalized() -> None:
    assert Endpoint("https://example.com:443/api").display == "https://example.com/api"


@pytest.mark.parametrize(
    "url",
    [
        "https://ex<ample.com/",
        "https://exa%zzmple.com/",
        "https://exa^mple.com/",
        "https://ex|ample.com/",
        "https://-bad.example/",
        "https://bad-.example/",
        "https://a..b/",
        "https://xn--/",
        "https://[fe80::1%25eth0]/",
        "https://" + ("a" * 60 + ".") * 5 + "example/",
    ],
)
def test_rejects_invalid_hosts(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="valid hostname"):
        Endpoint(url)


@pytest.mark.parametrize(
    "url", ["https://[::1/", "https://[v1.x]/", "https://" + "é" * 70 + ".example/"]
)
def test_rejects_unparseable(url: str) -> None:
    with pytest.raises(InvalidUrlError, match="could not be parsed"):
        Endpoint(url)


def test_rejects_empty_long_and_non_string() -> None:
    with pytest.raises(InvalidUrlError, match="empty"):
        Endpoint("")
    with pytest.raises(InvalidUrlError, match="longer"):
        Endpoint("https://example.com/" + "a" * MAX_URL_LENGTH)
    with pytest.raises(InvalidUrlError, match="string"):
        Endpoint(b"https://example.com/")  # type: ignore[arg-type]


def test_invalid_url_error_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="https"):
        Endpoint("http://example.com/")


def test_join_appends_encoded_segments() -> None:
    base = Endpoint("https://example.com/api/v1")
    joined = base.join("installations", 123456, "stats")
    assert joined.path == "/api/v1/installations/123456/stats"
    assert joined.display == "https://example.com/api/v1/installations/123456/stats"
    assert base.path == "/api/v1"


def test_join_handles_trailing_slash_and_root() -> None:
    assert Endpoint("https://example.com/api/").join("x").path == "/api/x"
    assert Endpoint("https://example.com").join("x").path == "/x"


def test_join_without_segments_returns_same_endpoint() -> None:
    base = Endpoint("https://example.com/api")
    assert base.join() is base


def test_join_preserves_query_and_port() -> None:
    base = Endpoint("https://example.com:8443/api?k=v")
    joined = base.join("x")
    assert joined.url.query == b"k=v"
    assert joined.port == 8443


MALICIOUS_SEGMENTS = [
    "../admin",
    "..%2Fadmin",
    "//evil.example",
    "/evil.example",
    "@evil.example",
    "user@evil.example",
    "%2F%2Fevil.example",
    "%2e%2e",
    "x?token=injected",
    "x#fragment",
    "evil.example:443",
    "\\\\evil.example",
    "a\r\nHost: evil.example",
    "\x00",
    "https://evil.example/",
    "．．",
    "\u2025",
    "ünïcødé/✓",
    "..\u2215admin",
]


@pytest.mark.parametrize("segment", MALICIOUS_SEGMENTS)
def test_join_cannot_change_destination(segment: str) -> None:
    base = Endpoint("https://example.com:8443/api?k=v")
    joined = base.join(segment)
    assert joined.host == "example.com"
    assert joined.port == 8443
    assert joined.url.scheme == "https"
    assert joined.url.query == b"k=v"
    assert joined.path.startswith("/api/")
    tail = joined.path.removeprefix("/api/")
    assert "/" not in tail
    assert "?" not in tail
    assert "#" not in tail
    assert tail not in (".", "..")


@pytest.mark.parametrize(
    ("segment", "encoded"),
    [
        ("../admin", "..%2Fadmin"),
        ("//evil.example", "%2F%2Fevil.example"),
        ("@evil.example", "%40evil.example"),
        ("%2F", "%252F"),
        ("a b", "a%20b"),
        ("é", "%C3%A9"),
        ("x?y#z", "x%3Fy%23z"),
    ],
)
def test_join_percent_encodes(segment: str, encoded: str) -> None:
    assert Endpoint("https://example.com").join(segment).path == f"/{encoded}"


@pytest.mark.parametrize("segment", ["", ".", ".."])
def test_join_rejects_dot_and_empty_segments(segment: str) -> None:
    with pytest.raises(InvalidUrlError, match="empty"):
        Endpoint("https://example.com/api").join(segment)


@pytest.mark.parametrize("segment", [True, 1.5, None, b"x", ["x"]])
def test_join_rejects_non_str_int_segments(segment: object) -> None:
    with pytest.raises(InvalidUrlError, match="str or int"):
        Endpoint("https://example.com/api").join(segment)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("host", "valid"),
    [
        ("2001:db8::1", True),
        ("not:an:ipv6", False),
        ("fe80::1%eth0", False),
        ("example.com", True),
        ("a" * 64 + ".example", False),
    ],
)
def test_host_validation(host: str, valid: bool) -> None:
    assert endpoint_module._valid_host(host) is valid


def test_equality_and_hash() -> None:
    first = Endpoint("https://example.com/api")
    second = Endpoint("https://example.com/api")
    secret = Endpoint("https://example.com/api", secret_path=True)
    assert first == second
    assert hash(first) == hash(second)
    assert first != secret
    assert first != "https://example.com/api"
    assert len({first, second, secret}) == 2
