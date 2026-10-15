# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Regression coverage for short reads, range refusal and logging transitions."""

import io
import logging
import struct
from types import SimpleNamespace

import pytest

from tests.test_http_source import Opener, Response, URL
from vdiskprobe import ByteSource, DetectorRegistry, FormatDetector, configure_logging, detect
from vdiskprobe.errors import RangeNotSupportedError, RemoteSourceError
from vdiskprobe.http_source import HttpRangeReader


def test_short_prefix_preserves_later_bytes_and_exact_cache():
    payload = b"a" * 512 + b"later"
    requests = []

    def read(offset, size):
        requests.append((offset, size))
        return payload[offset : offset + min(size, 512)]

    source = ByteSource(SimpleNamespace(read=read))
    assert source.read(0, 65536) == payload[:512]
    assert source.read(512, 5) == b"later"
    assert source.read(0, 65536) == payload[:512]
    assert requests == [(0, 65536), (512, 5)]


def test_unknown_short_descriptor_capacity_is_not_partial():
    payload = b"# Disk DescriptorFile\nRW 2 FLAT first\n" + b"#padding\n" * 100 + b"RW 3 FLAT last\n"
    reader = SimpleNamespace(read=lambda offset, size: payload[offset : offset + min(size, 512)])
    info = detect(reader)
    assert info.format == "vmdk"
    assert info.virtual_size is None


@pytest.mark.parametrize(
    "prefix, expected",
    [
        (b"LUKS\xba\xbe", "luks"),
        (b"Bochs Virtual HD Image", "bochs"),
        (b"WithoutFreeSpace", "parallels"),
        (b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop ", "cloop"),
        (b"vhdxfile", "vhdx"),
    ],
)
def test_header_match_survives_range_refusal(prefix, expected):
    payload = prefix.ljust(300000, b"\0")
    responses = [Response(200, payload, {"Content-Length": str(len(payload))}) for _ in range(12)]
    assert detect(HttpRangeReader(URL, opener=Opener(*responses))).format == expected


def test_range_refusal_does_not_become_raw():
    responses = [Response(200, b"x" * 100000, {"Content-Length": "100000"}) for _ in range(12)]
    with pytest.raises(RemoteSourceError):
        detect(HttpRangeReader(URL, opener=Opener(*responses)))


def test_range_refusal_without_fallback_preserves_error():
    class NeedsRange(FormatDetector):
        def detect(self, source):
            source.read(100, 1)

    reader = HttpRangeReader(URL, opener=Opener(Response(200, b"x" * 200, {"Content-Length": "200"})))
    with pytest.raises(RemoteSourceError):
        detect(reader, registry=DetectorRegistry([NeedsRange()]))


def test_outer_vhd_precedes_guest_signature():
    payload = bytearray(100000)
    payload[:6] = b"LUKS\xba\xbe"
    payload[-512:-504] = b"conectix"
    struct.pack_into(">Q", payload, len(payload) - 496, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">I", payload, len(payload) - 452, 2)
    assert detect(io.BytesIO(payload)).format == "vpc"


def test_propagation_removes_only_package_handler(monkeypatch):
    logger = logging.getLogger("vdiskprobe")
    root = logging.getLogger()
    dedicated, inherited, application = io.StringIO(), io.StringIO(), io.StringIO()
    monkeypatch.setattr(logger, "handlers", [])
    monkeypatch.setattr(logger, "level", logger.level)
    monkeypatch.setattr(logger, "propagate", logger.propagate)
    monkeypatch.setattr(root, "handlers", [logging.StreamHandler(inherited)])
    configure_logging(logging.DEBUG, stream=dedicated)
    logger.addHandler(logging.StreamHandler(application))
    configure_logging(logging.DEBUG, propagate=True)
    logger.warning("one message")
    assert dedicated.getvalue() == ""
    assert inherited.getvalue() == application.getvalue() == "one message\n"


def test_transport_failure_is_not_deferred():
    payload = b"LUKS\xba\xbe" + b"\0" * 99994
    responses = [
        Response(206, payload, {"Content-Range": "bytes 0-32/100000"}),
        Response(206, payload, {"Content-Range": "bytes 0-55/100000"}),
        Response(206, payload, {"Content-Range": "bytes 0-65535/100000"}),
        OSError("backend failed"),
    ]
    with pytest.raises(RemoteSourceError, match="backend failed"):
        detect(HttpRangeReader(URL, opener=Opener(*responses), max_retries=0))


@pytest.mark.parametrize("headers", [{"Content-Length": "36"}, {}])
def test_short_cloop_keeps_recognition_without_optional_ranges(headers):
    payload = b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop "
    responses = [Response(200, payload, headers) for _ in range(20)]
    info = detect(HttpRangeReader(URL, opener=Opener(*responses)))
    assert info.format == "cloop"
    assert info.virtual_size is info.cluster_size is None


def test_short_descriptor_keeps_recognition_when_end_probe_is_refused():
    payload = b"# Disk DescriptorFile\nRW 2 FLAT disk\n"

    def read(offset, size):
        if offset:
            raise RangeNotSupportedError("range refused")
        return payload[:size]

    info = detect(SimpleNamespace(read=read))
    assert info.format == "vmdk"
    assert info.virtual_size is None


@pytest.mark.parametrize("operation", ["read", "size", "detect"])
def test_unsatisfied_range_cannot_contradict_source_length(operation):
    response = Response(416, b"", {"Content-Range": "bytes */100"})
    reader = HttpRangeReader(URL, opener=Opener(response))
    with pytest.raises(RemoteSourceError, match="416"):
        if operation == "read":
            reader.read(0, 1)
        elif operation == "size":
            reader.size()
        else:
            detect(reader)
    assert response.closed


@pytest.mark.parametrize("extent", [b"RW\n2 FLAT disk", b"RW 2\nFLAT disk", b"RW 2\r\nFLAT disk"])
def test_vmdk_extent_fields_cannot_cross_lines(extent):
    info = detect(io.BytesIO(b"# Disk DescriptorFile\n" + extent + b"\n"))
    assert info.format == "vmdk"
    assert info.virtual_size is None


def test_vmdk_horizontal_whitespace_and_crlf():
    payload = b"# Disk DescriptorFile\r\n\t RW\t2\tFLAT disk\r\n  rdonly 3 ZERO\r\n"
    assert detect(io.BytesIO(payload)).virtual_size == 2560


def test_vmdk_blank_lines_within_descriptor_window():
    payload = b"# Disk DescriptorFile\nRW 2 FLAT disk\n" + b"\n" * 65000 + b"# end\n"
    requests = []

    def read(offset, size):
        requests.append((offset, size))
        return payload[offset : offset + size]

    info = detect(SimpleNamespace(read=read, size=len(payload)))
    assert info.format == "vmdk"
    assert info.virtual_size == 1024
    assert max(size for _, size in requests) <= 65536
