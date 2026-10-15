# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Reader dispatch, conversion, caching and resource contracts."""

import io
from types import SimpleNamespace

import pytest

from tests._helpers import CountingReader, ValueReader
from vdiskprobe.errors import InvalidSourceError
from vdiskprobe.source import ByteSource


@pytest.mark.parametrize(
    "value, expected",
    [(None, b""), (b"abc", b"abc"), (bytearray(b"abc"), b"abc"), (memoryview(b"abc"), b"abc"), ("\xff", b"\xff")],
)
def test_reader_conversion(value, expected):
    assert ByteSource(ValueReader(value)).read(0, 3) == expected


def test_provider_conversion_and_textual_fallback():
    class Fallback:
        def __str__(self):
            return "fallback"

    for method in ("tobytes", "tostring"):
        for payload in (b"abc", "abc"):
            value = SimpleNamespace(**{method: lambda: payload})
            assert ByteSource(ValueReader(value)).read(0, 3) == b"abc"
    assert ByteSource(ValueReader(Fallback())).read(0, 8) == b"fallback"
    with pytest.raises(UnicodeEncodeError):
        ByteSource(ValueReader("\u20ac")).read(0, 1)


@pytest.mark.parametrize("method", ["read_at", "pread", "read_range", "read"])
def test_random_access_methods(method):
    calls = []

    def read(offset, size):
        calls.append((offset, size))
        return b"abcdef"[offset : offset + size]

    source = ByteSource(SimpleNamespace(**{method: read}))
    assert source.read(1, 3) == b"bcd"
    assert calls == [(1, 3)]


def test_dispatch_precedence():
    reader = SimpleNamespace(
        read_at=lambda o, s: b"a", pread=lambda o, s: b"b", read_range=lambda o, s: b"c", read=lambda *a: b"d"
    )
    assert ByteSource(reader).read(0, 1) == b"a"
    del reader.read_at
    assert ByteSource(reader).read(0, 1) == b"b"
    del reader.pread
    assert ByteSource(reader).read(0, 1) == b"c"
    stream = io.BytesIO(b"abcdef")
    stream.seek(2)
    assert ByteSource(stream).read(0, 3) == b"abc"
    assert stream.tell() == 2
    assert not stream.closed


def test_read_failure_restores_cursor():
    class Broken(io.BytesIO):
        def read(self, size=-1):
            raise OSError("broken")

    reader = Broken(b"abcdef")
    reader.seek(3)
    with pytest.raises(OSError, match="broken"):
        ByteSource(reader).read(0, 2)
    assert reader.tell() == 3
    assert not reader.closed


def test_cache_prefix_growth_and_failure():
    reader = CountingReader(b"abcdef")
    source = ByteSource(reader)
    assert source.read(0, 3) == b"abc"
    assert source.read(1, 2) == b"bc"
    reader.fail_next = True
    with pytest.raises(OSError):
        source.read(0, 6)
    assert source.read(0, 3) == b"abc"
    assert reader.requests == [(0, 3), (0, 6)]
    assert source.read(0, 6) == b"abcdef"
    assert source.read(2, 3) == b"cde"
    assert len(reader.requests) == 3


def test_short_exact_and_large_read_cache():
    reader = CountingReader(b"abc")
    source = ByteSource(reader)
    assert source.read(0, 6) == b"abc"
    assert source.read(1, 4) == b"bc"
    assert reader.requests == [(0, 6), (1, 4)]
    reader = CountingReader(b"a" * 70000)
    source = ByteSource(reader)
    assert source.read(10, 3) == source.read(10, 3) == b"aaa"
    assert reader.requests == [(10, 3)]
    source.read(0, 65537)
    source.read(0, 65537)
    assert len(reader.requests) == 3


def test_invalid_readers_and_sizes():
    for reader in (None, object()):
        with pytest.raises(InvalidSourceError):
            ByteSource(reader)
    source = ByteSource(ValueReader(b"abcdef"))
    for offset, size in ((-1, 1), (0, -1)):
        with pytest.raises(ValueError):
            source.read(offset, size)
    assert source.read(0, 0) == b""
    assert source.read(0, 2) == b"ab"
    assert "ByteSource" in repr(source)
    with pytest.raises(InvalidSourceError):
        ByteSource(SimpleNamespace(read=lambda n: b"x")).read(0, 1)


@pytest.mark.parametrize("attribute", ["size", "length"])
@pytest.mark.parametrize("callable_value", [True, False])
def test_size_attributes(attribute, callable_value):
    value = lambda: 2**40
    reader = SimpleNamespace(read=lambda o, s: b"", **{attribute: value if callable_value else 2**40})
    assert ByteSource(reader).get_size() == 2**40


def test_size_fallbacks_and_unknown_cache():
    class Sized(ValueReader):
        def __len__(self):
            return 42

    assert ByteSource(Sized(b"")).get_size() == 42
    reader = io.BytesIO(b"abcdef")
    reader.seek(2)
    assert ByteSource(reader).get_size() == 6
    assert reader.tell() == 2
    calls = []
    reader = SimpleNamespace(read=lambda o, s: b"", size=lambda: calls.append(1))
    source = ByteSource(reader)
    assert source.get_size() is source.get_size() is None
    assert calls == [1]
    assert source.get_disk_size() is None
    reader = SimpleNamespace(read=lambda o, s: b"", size=None, length=7)
    assert ByteSource(reader).get_size() == 7


def test_disk_allocation_and_logical_size(monkeypatch):
    reader = SimpleNamespace(read=lambda o, s: b"", fileno=lambda: 12)
    monkeypatch.setattr("vdiskprobe.source.os.fstat", lambda fd: SimpleNamespace(st_blocks=8, st_size=9000))
    source = ByteSource(reader)
    assert source.get_size() == 9000
    assert source.get_disk_size() == 4096
    monkeypatch.setattr("vdiskprobe.source.os.fstat", lambda fd: SimpleNamespace(st_size=9000))
    assert ByteSource(reader).get_disk_size() == 9000
