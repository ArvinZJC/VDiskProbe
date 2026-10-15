# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Failure and fallback contracts for adapters and entry points."""

import io
import logging
import os
import runpy
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from tests.test_http_source import Opener, Response, URL
from vdiskprobe import configure_logging
from vdiskprobe.errors import InvalidSourceError, RemoteSourceError

# Direct helper tests cover internal parsing and failure paths.
# noinspection PyProtectedMember
from vdiskprobe.http_source import HttpRangeReader, _build_ssl_context, _discover_ca_locations
from vdiskprobe.source import ByteSource


def test_module_entry_point_and_import(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["vdiskprobe", "--list-formats"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("vdiskprobe", run_name="__main__")
    assert exc.value.code == 0
    assert "qcow2" in capsys.readouterr().out
    runpy.run_module("vdiskprobe.__main__", run_name="module_import_check")
    assert capsys.readouterr().out == ""


def test_logging_default_level_preserves_existing_handler():
    logger = logging.getLogger("vdiskprobe")
    previous = logger.handlers[:], logger.level, logger.propagate
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    try:
        logger.handlers[:] = [handler]
        configure_logging(level=None, propagate=True)
        logger.info("existing handler still works")
        assert output.getvalue() == "existing handler still works\n"
        assert logger.level == logging.INFO
    finally:
        logger.handlers[:], logger.level, logger.propagate = previous


def test_unusable_random_access_method_rejected():
    with pytest.raises(InvalidSourceError):
        ByteSource(SimpleNamespace(read_at=None)).read(0, 1)


def test_size_method_with_required_argument_falls_back_to_length():
    source = ByteSource(SimpleNamespace(read=lambda o, s: b"", size=lambda required: 8, length=12))
    assert source.get_size() == 12


@pytest.mark.parametrize("failure", ["tell", "seek_end", "restore"])
def test_size_discovery_handles_seek_failures(failure):
    class Reader:
        position = 3

        @staticmethod
        def read(_size):
            return b""

        def tell(self):
            if failure == "tell":
                raise OSError("position unavailable")
            return self.position

        def seek(self, offset, whence):
            if whence == os.SEEK_END:
                if failure == "seek_end":
                    raise OSError("size unavailable")
                self.position = 20
            else:
                if failure == "restore":
                    raise OSError("restore unavailable")
                self.position = offset

    reader = Reader()
    source = ByteSource(reader)
    assert source.get_size() == (20 if failure == "restore" else None)
    if failure == "seek_end":
        assert reader.position == 3


def test_http_full_response_length_is_cached():
    response = Response(200, b"abcd", {"Content-Length": "40"})
    opener = Opener(response)
    reader = HttpRangeReader(URL, opener=opener)
    assert reader.read(0, 2) == b"ab"
    assert reader.size() == 40
    assert len(opener.requests) == 1


@pytest.mark.parametrize("status", [201, 503])
def test_http_unexpected_final_status_closes_response(status):
    response = Response(status)
    with pytest.raises(RemoteSourceError, match=f"status {status}"):
        HttpRangeReader(URL, max_retries=0, opener=Opener(response)).read(0, 1)
    assert response.closed


def test_unsatisfied_range_without_total_remains_unknown():
    response = Response(416, b"")
    assert HttpRangeReader(URL, opener=Opener(response)).size() is None
    assert response.closed


def test_transport_exhaustion_and_zero_backoff():
    opener = Opener(URLError("offline"), URLError("offline"))
    sleeps = []
    with pytest.raises(RemoteSourceError, match="offline"):
        HttpRangeReader(URL, max_retries=1, retry_backoff=0, opener=opener, sleep_func=sleeps.append).read(0, 1)
    assert len(opener.requests) == 2
    assert sleeps == []


def test_reader_with_no_remaining_attempts_fails_without_network():
    opener = Opener()
    reader = HttpRangeReader(URL, opener=opener)
    reader.max_retries = -1
    with pytest.raises(RemoteSourceError, match="no request attempts"):
        reader.read(0, 1)
    assert opener.requests == []


@pytest.mark.parametrize("headers", [None, object(), {"content-range": "invalid", "content-length": "-1"}])
def test_unusable_headers_do_not_invent_size(headers):
    response = Response(206, b"x")
    response.headers = headers
    head = Response(200, b"")
    assert HttpRangeReader(URL, opener=Opener(response, head)).size() is None
    assert response.closed and head.closed


def test_unknown_ca_locations_retain_default_context():
    context = _build_ssl_context(
        environ={}, verify_paths=SimpleNamespace(), isfile=lambda p: False, isdir=lambda p: False
    )
    import ssl

    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
    assert _discover_ca_locations(
        environ={"SSL_CERT_FILE": "/missing"},
        verify_paths=SimpleNamespace(),
        isfile=lambda p: p == "/etc/ssl/cert.pem",
        isdir=lambda p: p == "/etc/ssl/certs",
    ) == ("/etc/ssl/cert.pem", "/etc/ssl/certs")
