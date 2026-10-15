# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Bounded HTTP reads, retry ownership, and verified TLS contracts."""

import io
from email.message import Message
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, build_opener

import pytest

from vdiskprobe.errors import InvalidSourceError, RemoteSourceError

# Direct helper tests cover internal parsing and failure paths.
# noinspection PyProtectedMember
from vdiskprobe.http_source import HttpRangeReader, _build_ssl_context, _discover_ca_locations, is_http_url

URL = "https://example.com/disk"


class Response(io.BytesIO):
    """HTTP-like response that records bounded body reads and closure."""

    def __init__(self, status=206, body=b"abc", headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}
        self.read_sizes = []

    def getcode(self):
        return self.status

    def info(self):
        return self.headers

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


class Opener:
    """Return or raise each configured response in sequence."""

    def __init__(self, *responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = next(self.responses)
        if isinstance(response, BaseException):
            raise response
        return response


# Invalid URL literals exercise recognition without making requests.
# noinspection HttpUrlsUsage
@pytest.mark.parametrize(
    "value, expected",
    [
        (URL, True),
        ("HTTP://example.com/a", True),
        ("http:///a", False),
        ("ftp://example.com/a", False),
        (b"https://example.com/a", False),
        (None, False),
    ],
)
def test_url_recognition(value, expected):
    assert is_http_url(value) is expected


@pytest.mark.parametrize("status, offset, expected", [(206, 1, b"abc"), (200, 0, b"abc"), (416, 100, b"")])
def test_bounded_range_read(status, offset, expected):
    response = Response(status, b"abcdef", {"Content-Range": "bytes */100" if status == 416 else "bytes 1-3/100"})
    opener = Opener(response)
    reader = HttpRangeReader(URL, opener=opener)
    assert reader.read(offset, 3) == expected
    assert response.closed
    assert response.read_sizes == [3]
    request, timeout = opener.requests[0]
    assert request.get_header("Range") == f"bytes={offset}-{offset + 2}"
    assert request.get_header("Accept-encoding") == "identity"
    assert request.get_header("User-agent").startswith("vdiskprobe/")
    assert timeout == 10.0
    assert reader.size() == 100


def test_nonzero_offset_requires_range_support():
    response = Response(200, b"x" * 1000)
    reader = HttpRangeReader(URL, opener=Opener(response))
    with pytest.raises(RemoteSourceError, match="did not honour"):
        reader.read(12, 4)
    assert response.closed
    assert response.read_sizes == [4]


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_retry_exhaustion_closes_responses(status):
    bodies = [Response(status) for _ in range(4)]
    errors = [HTTPError(URL, status, "retry", Message(), body) for body in bodies]
    opener = Opener(*errors)
    sleeps = []
    with pytest.raises(RemoteSourceError):
        HttpRangeReader(URL, opener=opener, sleep_func=sleeps.append).read(0, 1)
    assert len(opener.requests) == 4
    assert sleeps == [0.25, 0.5, 1.0]
    assert all(body.closed for body in bodies)


@pytest.mark.parametrize("error", [URLError("offline"), OSError("offline")])
def test_transport_retry_recovers(error):
    response = Response()
    opener = Opener(error, response)
    sleeps = []
    assert HttpRangeReader(URL, opener=opener, sleep_func=sleeps.append).read(0, 2) == b"ab"
    assert sleeps == [0.25]
    assert response.closed


def test_status_response_retry_and_nonretryable_error():
    responses = [Response(503), Response()]
    sleeps = []
    assert HttpRangeReader(URL, opener=Opener(*responses), sleep_func=sleeps.append).read(0, 1) == b"a"
    assert sleeps == [0.25]
    assert all(r.closed for r in responses)
    body = Response(404)
    with pytest.raises(RemoteSourceError, match="404"):
        HttpRangeReader(
            URL, opener=Opener(HTTPError(URL, 404, "missing", Message(), body)), sleep_func=sleeps.append
        ).read(0, 1)
    assert body.closed
    assert sleeps == [0.25]


@pytest.mark.parametrize("status", [403, 405, 501])
def test_size_probe_before_head_with_unsupported_head(status):
    get = Response(200, b"a")
    head = Response(status, b"")
    opener = Opener(get, HTTPError(URL, status, "unsupported", Message(), head))
    reader = HttpRangeReader(URL, opener=opener)
    assert reader.size() is reader.size() is None
    assert [r.get_method() for r, _ in opener.requests] == ["GET", "HEAD"]
    assert get.read_sizes == [1]
    assert head.read_sizes == [0]
    assert get.closed and head.closed


@pytest.mark.parametrize(
    "responses, expected",
    [
        ([Response(206, b"a", {"Content-Range": "bytes 0-0/42"})], 42),
        ([Response(200, b"a", {"Content-Length": "42"})], 42),
        ([Response(200, b"")], 0),
        ([Response(416, b"", {"Content-Range": "bytes */0"})], 0),
        ([Response(200, b"a", {"Content-Length": "invalid"}), Response(200, b"", {"Content-Length": "91"})], 91),
    ],
)
def test_size_discovery_paths(responses, expected):
    reader = HttpRangeReader(URL, opener=Opener(*responses))
    assert reader.size() == expected
    assert reader.size() == expected
    assert all(r.closed for r in responses)


def test_prefix_without_content_length_and_zero_reads():
    reader = HttpRangeReader(URL, opener=Opener(Response(200, b"abc")))
    assert reader.read(0, 10) == b"abc"
    assert reader.size() == 3
    assert reader.read(0, 0) == b""
    with pytest.raises(InvalidSourceError):
        HttpRangeReader("ftp://example.com/disk")
    with pytest.raises(ValueError):
        HttpRangeReader(URL, max_retries=-1)


def test_tls_context_verifies_peer():
    context = _build_ssl_context(environ={})
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_trust_store_precedence(tmp_path):
    env_file = tmp_path / "env.pem"
    default_file = tmp_path / "default.pem"
    env_file.touch()
    default_file.touch()
    defaults = SimpleNamespace(cafile=str(default_file), capath=None)
    env = {"SSL_CERT_FILE": str(env_file), "SSL_CERT_DIR": str(tmp_path)}
    assert _discover_ca_locations(environ=env, verify_paths=defaults) == (str(env_file), str(tmp_path))
    loaded = []
    context = SimpleNamespace(load_verify_locations=lambda **kw: loaded.append(kw))
    assert _build_ssl_context(environ=env, verify_paths=defaults, context_factory=lambda: context) is context
    assert loaded == [{"cafile": str(env_file), "capath": str(tmp_path)}]
    for env_name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        assert _discover_ca_locations(environ={env_name: str(env_file)}, verify_paths=defaults)[0] == str(env_file)


def test_real_loopback_range_and_ignored_range(monkeypatch):
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")

    class Handler(BaseHTTPRequestHandler):
        # BaseHTTPRequestHandler dispatches HTTP verbs to these exact method names.
        # noinspection PyPep8Naming
        def do_GET(self):
            payload = b"abcdef"
            start, end = map(int, self.headers["Range"][6:].split("-"))
            ranged = self.path == "/range"
            self.send_response(206 if ranged else 200)
            self.send_header("Content-Length", str(end - start + 1 if ranged else len(payload)))
            if ranged:
                self.send_header("Content-Range", f"bytes {start}-{end}/{len(payload)}")
            self.end_headers()
            self.wfile.write(payload[start : end + 1] if ranged else payload)

        # Match the standard-library callback signature, including its parameter name.
        # noinspection PyShadowingBuiltins
        def log_message(self, format, *args):
            pass

    # Handler inherits the request-handler constructor; the real server exercises it below.
    # noinspection PyTypeChecker
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        opener = build_opener(ProxyHandler({}))
        prefix = f"http://127.0.0.1:{server.server_port}"
        reader = HttpRangeReader(prefix + "/range", opener=opener)
        assert reader.read(1, 3) == b"bcd"
        assert reader.size() == 6
        with pytest.raises(RemoteSourceError):
            HttpRangeReader(prefix + "/ignored").read(1, 3)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("content_range", [None, "bytes 0-0/*"])
@pytest.mark.parametrize("head_status, expected", [(200, 10000), (405, None)])
def test_partial_length_is_not_total_size(content_range, head_status, expected):
    headers = {"Content-Length": "1"}
    if content_range:
        headers["Content-Range"] = content_range
    probe = Response(206, b"x", headers)
    head = Response(head_status, b"", {"Content-Length": "10000"} if head_status == 200 else {})
    opener = Opener(probe, head)
    assert HttpRangeReader(URL, opener=opener).size() == expected
    assert [r.get_method() for r, _ in opener.requests] == ["GET", "HEAD"]
    assert probe.closed and head.closed


@pytest.mark.parametrize(
    "content_range",
    [
        "bytes 0-2/100",
        " bytes 0-2/100 ",
        "bytes 80-83/100",
        "bytes 80-79/100",
        "bytes 80-82/82",
        pytest.param("bytes " + "9" * 5000 + "-82/100", id="oversized-integer"),
    ],
)
def test_contradictory_partial_range_is_rejected(content_range):
    response = Response(206, b"abc", {"Content-Range": content_range})
    reader = HttpRangeReader(URL, opener=Opener(response))
    with pytest.raises(RemoteSourceError, match="Content-Range"):
        reader.read(80, 3)
    assert response.closed


def test_size_probe_rejects_wrong_range_start():
    response = Response(206, b"x", {"Content-Range": "bytes 80-80/100"})
    with pytest.raises(RemoteSourceError, match="Content-Range"):
        HttpRangeReader(URL, opener=Opener(response)).size()
    assert response.closed


@pytest.mark.parametrize("content_range", ["bytes 80-81/100", "bytes 80-81/*", None])
def test_short_partial_read_remains_usable(content_range):
    headers = {} if content_range is None else {"Content-Range": content_range}
    response = Response(206, b"a", headers)
    assert HttpRangeReader(URL, opener=Opener(response)).read(80, 3) == b"a"
    assert response.closed


def test_url_encoding_failure_is_not_retried():
    failure = UnicodeEncodeError("ascii", "磁盘", 0, 2, "ordinal not in range(128)")
    opener = Opener(failure)
    sleeps = []
    with pytest.raises(RemoteSourceError, match="ascii") as exc:
        HttpRangeReader(URL, opener=opener, sleep_func=sleeps.append).read(0, 8)
    assert exc.value.__cause__ is failure
    assert len(opener.requests) == 1
    assert sleeps == []


def test_percent_encoded_url_is_preserved():
    url = URL + "/%E7%A3%81%E7%9B%98.qcow2"
    opener = Opener(Response(206, b"abc", {"Content-Range": "bytes 0-2/3"}))
    assert HttpRangeReader(url, opener=opener).read(0, 3) == b"abc"
    request, _ = opener.requests[0]
    assert request.full_url == url
    assert request.selector == "/disk/%E7%A3%81%E7%9B%98.qcow2"
