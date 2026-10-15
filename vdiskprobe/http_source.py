# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""HTTP/HTTPS-backed byte source helpers."""

import http.client
import os
import re
import ssl
import time
from collections.abc import Callable
from typing import Any
import urllib.request
import urllib.error
import urllib.parse
from vdiskprobe.errors import InvalidSourceError, RangeNotSupportedError, RemoteSourceError
from vdiskprobe.log import get_logger
from vdiskprobe.version import __version__

LOG = get_logger("http")
_UNKNOWN_SIZE = object()
_CA_FILE_ENV_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")
_CA_DIR_ENV_VARS = ("SSL_CERT_DIR",)
_COMMON_CA_FILES = (
    "/etc/ssl/cert.pem",
    "/private/etc/ssl/cert.pem",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",
)
_COMMON_CA_DIRS = ("/etc/ssl/certs", "/private/etc/ssl/certs")


def is_http_url(value: Any) -> bool:
    """Return whether a value is an HTTP or HTTPS URL."""
    if not isinstance(value, str):
        return False
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError as exc:
        raise InvalidSourceError("invalid source URL: {0}".format(exc)) from exc
    return (parsed.scheme or "").lower() in ("http", "https") and bool(parsed.netloc)


class HttpRangeReader:
    """Random-access reader backed by HTTP range requests."""

    DEFAULT_TIMEOUT = 10.0
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_RETRY_BACKOFF = 0.25
    RETRYABLE_STATUS_CODES = frozenset((408, 429, 500, 502, 503, 504))

    def __init__(
        self,
        url: str,
        timeout: float | None = DEFAULT_TIMEOUT,
        max_retries: int | None = DEFAULT_MAX_RETRIES,
        retry_backoff: float | None = DEFAULT_RETRY_BACKOFF,
        opener: Any = None,
        sleep_func: Callable[[float], object] | None = None,
    ) -> None:
        """Initialise the HTTP-backed reader."""
        if not is_http_url(url):
            # URL syntax only; this literal is never used for a network request.
            # noinspection HttpUrlsUsage
            raise InvalidSourceError("reader URL must use http:// or https://")
        retries = self.DEFAULT_MAX_RETRIES if max_retries is None else int(max_retries)
        if retries < 0:
            raise ValueError("max_retries must be >= 0")
        self.url = url
        self.name = url
        self.timeout = self.DEFAULT_TIMEOUT if timeout is None else float(timeout)
        self.max_retries = retries
        self.retry_backoff = self.DEFAULT_RETRY_BACKOFF if retry_backoff is None else float(retry_backoff)
        self._opener = opener or _build_default_opener()
        self._sleep = sleep_func or time.sleep
        self._size = _UNKNOWN_SIZE

    def read(self, offset: int, size: int) -> bytes:
        """Read up to ``size`` bytes from ``offset``."""
        if size <= 0:
            return b""
        start = int(offset)
        length = int(size)
        end = start + int(length) - 1
        status, headers, data = self._request(
            "GET", headers={"Range": "bytes={0}-{1}".format(start, end)}, read_size=length, allow_statuses=(416,)
        )
        if status == 206:
            _validate_content_range(headers, start, length)
        total_size = _content_range_total(_header_value(headers, "Content-Range"))
        if status == 416 and total_size is not None and start < total_size:
            raise RemoteSourceError("HTTP 416 contradicts the requested byte range")
        if total_size is not None:
            self._size = total_size
        if status == 416:
            return b""
        if status == 206:
            return data
        if status == 200:
            content_length = _parse_non_negative_int(_header_value(headers, "Content-Length"))
            if offset != 0:
                raise RangeNotSupportedError("HTTP server did not honour a byte-range request for {0}".format(self.url))
            if content_length is not None:
                self._size = content_length
            elif len(data) < length:
                self._size = int(len(data))
            return data
        raise RemoteSourceError("unexpected HTTP status {0} for {1}".format(status, self.url))

    def size(self) -> int | None:
        """Return the total content length when it can be discovered."""
        if self._size is _UNKNOWN_SIZE:
            self._size = self._discover_size()
        return self._size

    def _discover_size(self) -> int | None:
        """Discover the remote object size without downloading the body."""
        status, headers, data = self._request("GET", headers={"Range": "bytes=0-0"}, read_size=1, allow_statuses=(416,))
        if status == 206:
            _validate_content_range(headers, 0, 1)
        total_size = _content_range_total(_header_value(headers, "Content-Range"))
        if status == 416 and total_size is not None and total_size > 0:
            raise RemoteSourceError("HTTP 416 contradicts the size-discovery byte range")
        if total_size is not None:
            return total_size
        if status == 416:
            return total_size
        content_length = _parse_non_negative_int(_header_value(headers, "Content-Length"))
        if status == 200 and content_length is not None:
            return content_length
        if status == 200 and (not data):
            return 0
        head_status, head_headers, _ = self._request("HEAD", read_size=0, allow_statuses=(403, 405, 501))
        if head_status == 200:
            return _parse_non_negative_int(_header_value(head_headers, "Content-Length"))
        return None

    def _request(
        self,
        method: str,
        headers: dict[str, str] | None = None,
        read_size: int | None = None,
        allow_statuses: tuple = (),
    ) -> tuple:
        """Issue an HTTP request with bounded retries."""
        attempts = self.max_retries + 1
        for attempt in range(attempts):
            request = self._build_request(method, headers=headers)
            try:
                response = self._opener.open(request, timeout=self.timeout)
                try:
                    status = response.getcode() or 200
                    response_headers = response.info()
                    data = response.read() if read_size is None else response.read(read_size)
                finally:
                    response.close()
                if status in self.RETRYABLE_STATUS_CODES and attempt + 1 < attempts:
                    self._retry(attempt, "status={0}".format(status))
                    continue
                return status, response_headers, data
            except urllib.error.HTTPError as exc:
                try:
                    if exc.code in allow_statuses:
                        try:
                            payload = exc.read() if read_size is None else exc.read(read_size)
                        finally:
                            exc.close()
                        return exc.code, getattr(exc, "headers", None) or getattr(exc, "hdrs", None), payload
                    if exc.code in self.RETRYABLE_STATUS_CODES and attempt + 1 < attempts:
                        self._retry(attempt, "status={0}".format(exc.code))
                        continue
                    raise RemoteSourceError("unable to read {0}: HTTP {1}".format(self.url, exc.code))
                finally:
                    exc.close()
            except UnicodeError as exc:
                raise RemoteSourceError("unable to encode request URL: {0}".format(exc)) from exc
            except (
                OSError,
                urllib.error.URLError,
                http.client.HTTPException,
            ) as exc:
                if attempt + 1 < attempts:
                    self._retry(attempt, _error_text(exc))
                    continue
                raise RemoteSourceError("unable to read {0}: {1}".format(self.url, _error_text(exc)))
        raise RemoteSourceError("unable to read {0}: no request attempts configured".format(self.url))

    def _build_request(self, method: str, headers: dict[str, str] | None = None) -> urllib.request.Request:
        """Build a request with the standard headers we need."""
        base_headers = {"Accept-Encoding": "identity", "User-Agent": "vdiskprobe/{0}".format(__version__)}
        if headers:
            base_headers.update(headers)
        return urllib.request.Request(self.url, headers=base_headers, method=method)

    def _retry(self, attempt: int, reason: str) -> None:
        """Sleep before the next retry attempt."""
        delay = self.retry_backoff * 2**attempt
        LOG.debug("retrying url=%s attempt=%s reason=%s delay=%s", self.url, attempt + 2, reason, delay)
        if delay > 0:
            self._sleep(delay)


def _validate_content_range(headers: Any, offset: int, size: int) -> None:
    """Reject a supplied byte interval that contradicts the requested range."""
    value = _header_value(headers, "Content-Range")
    match = re.fullmatch(r"bytes\s+(\d+)-(\d+)/(\d+|\*)", str(value).strip(), re.IGNORECASE)
    if match is None:
        return
    try:
        start, end = int(match[1]), int(match[2])
        total = None if match[3] == "*" else int(match[3])
    except ValueError as exc:
        raise RemoteSourceError("unusable HTTP Content-Range integer") from exc
    if start != offset or end < start or end >= offset + size or (total is not None and end >= total):
        raise RemoteSourceError("HTTP Content-Range contradicts the requested byte range")


def _header_value(headers: Any, name: str) -> Any:
    """Look up an HTTP header value defensively."""
    if headers is None:
        return None
    getter: Callable[[str], Any] | None = getattr(headers, "get", None)
    if getter is None:
        return None
    # The None case returns above; the remaining header getter is callable.
    # noinspection PyCallingNonCallable
    value = getter(name)
    if value is not None:
        return value
    # The same guarded getter supports a lower-case header lookup.
    # noinspection PyCallingNonCallable
    return getter(name.lower())


def _parse_non_negative_int(value: Any) -> int | None:
    """Parse a non-negative integer header value."""
    if value in (None, ""):
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if parsed < 0:
        return None
    return parsed


def _content_range_total(value: Any) -> int | None:
    """Extract the total size from a ``Content-Range`` header."""
    if not value:
        return None
    content_range = str(value)
    if "/" not in content_range:
        return None
    total_text = content_range.rsplit("/", 1)[1].strip()
    if total_text == "*":
        return None
    return _parse_non_negative_int(total_text)


def _error_text(exc: BaseException) -> str:
    """Return a compact textual description for an exception."""
    reason = getattr(exc, "reason", None)
    if reason is not None and reason is not exc:
        return str(reason)
    return str(exc)


def _build_default_opener() -> Any:
    """Build the default opener with an explicit HTTPS context."""
    context = _build_ssl_context()
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))


def _build_ssl_context(environ=None, verify_paths=None, context_factory=None, isfile=None, isdir=None):
    """Build a verified SSL context using configured and system CA bundles."""
    factory = context_factory or ssl.create_default_context
    context = factory()
    cafile, capath = _discover_ca_locations(environ=environ, verify_paths=verify_paths, isfile=isfile, isdir=isdir)
    if cafile is not None or capath is not None:
        context.load_verify_locations(cafile=cafile, capath=capath)
        LOG.debug("using HTTPS trust store cafile=%s capath=%s", cafile, capath)
    return context


def _discover_ca_locations(environ=None, verify_paths=None, isfile=None, isdir=None):
    """Discover CA bundle locations from env vars, OpenSSL defaults, and common paths."""
    if environ is None:
        environment = os.environ
    else:
        environment = environ
    environment_get = getattr(environment, "get")
    defaults = ssl.get_default_verify_paths() if verify_paths is None else verify_paths
    file_exists = os.path.isfile if isfile is None else isfile
    dir_exists = os.path.isdir if isdir is None else isdir
    cafile_candidates = []
    capath_candidates = []
    for env_name in _CA_FILE_ENV_VARS:
        _append_candidate(cafile_candidates, environment_get(env_name))
    for env_name in _CA_DIR_ENV_VARS:
        _append_candidate(capath_candidates, environment_get(env_name))
    _append_candidate(cafile_candidates, getattr(defaults, "cafile", None))
    _append_candidate(capath_candidates, getattr(defaults, "capath", None))
    cafile_candidates.extend(_COMMON_CA_FILES)
    capath_candidates.extend(_COMMON_CA_DIRS)
    cafile = _first_existing_path(cafile_candidates, file_exists)
    capath = _first_existing_path(capath_candidates, dir_exists)
    return cafile, capath


def _append_candidate(candidates: list, value: Any) -> None:
    """Append a non-empty candidate path."""
    if value:
        candidates.append(value)


def _first_existing_path(candidates, exists):
    """Return the first candidate path that exists."""
    for candidate in candidates:
        if exists(candidate):
            return candidate
    return None
