# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Transport failures while consuming allowed HTTP error responses."""

import io
from http.client import IncompleteRead
from urllib.error import HTTPError

import pytest

from tests.test_http_source import Opener, URL
from vdiskprobe.errors import RemoteSourceError
from vdiskprobe.http_source import HttpRangeReader


class FailingBody(io.BytesIO):
    """Fail during body consumption, after the HTTP status is available."""

    def __init__(self, error):
        super().__init__()
        self.error = error

    def read(self, size=-1):
        raise self.error


@pytest.mark.parametrize("operation", ["read", "size"])
@pytest.mark.parametrize("error_type", [TimeoutError, OSError, IncompleteRead])
@pytest.mark.parametrize("recover", [False, True])
def test_allowed_error_body_uses_transport_retry_policy(operation, error_type, recover):
    bodies = [
        FailingBody(error_type(b"body failed")),
        io.BytesIO() if recover else FailingBody(error_type(b"body failed")),
    ]
    errors = [HTTPError(URL, 416, "range", {"Content-Range": "bytes */0"}, body) for body in bodies]
    # A later call after exhaustion must discover size afresh, not reuse false EOF.
    later = io.BytesIO()
    opener = Opener(*errors, HTTPError(URL, 416, "range", {"Content-Range": "bytes */0"}, later))
    pauses = []

    def sleep(delay):
        assert bodies[0].closed
        pauses.append(delay)

    reader = HttpRangeReader(URL, opener=opener, max_retries=1, sleep_func=sleep)

    def inspect():
        return reader.read(0, 8) if operation == "read" else reader.size()

    if recover:
        assert inspect() == (b"" if operation == "read" else 0)
    else:
        with pytest.raises(RemoteSourceError) as caught:
            inspect()
        assert caught.value.__context__ is bodies[-1].error
        assert str(bodies[-1].error) in str(caught.value)
    assert len(opener.requests) == 2
    assert pauses == [0.25]
    assert all(body.closed for body in bodies)
    assert reader.size() == 0
    assert len(opener.requests) == (2 if recover else 3)
    if not recover:
        assert later.closed


@pytest.mark.parametrize("operation", ["read", "size"])
def test_allowed_error_body_without_retries_maps_transport_error(operation):
    body = FailingBody(TimeoutError("body timed out"))
    opener = Opener(HTTPError(URL, 416, "range", {"Content-Range": "bytes */0"}, body))
    pauses = []
    reader = HttpRangeReader(URL, opener=opener, max_retries=0, sleep_func=pauses.append)
    with pytest.raises(RemoteSourceError, match="body timed out"):
        reader.read(0, 8) if operation == "read" else reader.size()
    assert body.closed
    assert len(opener.requests) == 1
    assert pauses == []
