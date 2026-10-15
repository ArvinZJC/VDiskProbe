# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Public API dispatch, exports and ownership."""

import io
from importlib.metadata import version
import struct

import pytest

import vdiskprobe
from vdiskprobe import api
from vdiskprobe.errors import InvalidSourceError
from vdiskprobe.detectors.base import DetectorRegistry, FormatDetector
from vdiskprobe.source import ByteSource
from tests._helpers import CountingReader


class CustomDetector(FormatDetector):
    format_name = "custom"
    priority = 1

    def detect(self, source):
        return self.build_info(source)


def test_unicode_path_and_caller_owned_stream(tmp_path):
    path = tmp_path / "磁盘.qcow2"
    path.write_bytes(b"QFI\xfb" + struct.pack(">I", 3))
    info = api.detect_path(path)
    assert info.format == "qcow2"
    assert info.source_name == str(path)
    with path.open("rb") as handle:
        handle.seek(2)
        assert api.detect(handle).format == "qcow2"
        assert handle.tell() == 2
        assert not handle.closed
    with pytest.raises(OSError):
        api.detect_path(tmp_path / "missing")


def test_public_api_exports():
    expected = {
        "ByteSource",
        "DetectorRegistry",
        "FormatDetector",
        "ImageInfo",
        "VDiskProbeError",
        "InvalidSourceError",
        "RemoteSourceError",
        "build_default_registry",
        "configure_logging",
        "detect",
        "detect_path",
        "detect_url",
        "get_logger",
        "inspect_source",
    }
    assert set(vdiskprobe.__all__) == expected
    assert all(hasattr(vdiskprobe, name) for name in expected)
    assert vdiskprobe.__version__ == version("vdiskprobe")
    assert not hasattr(vdiskprobe, "get_default_registry")


def test_custom_registry_and_existing_source():
    source = ByteSource(io.BytesIO(b"x"), name="label")
    registry = DetectorRegistry([CustomDetector()])
    assert api.detect(source, registry, "ignored").source_name == "label"
    assert api.inspect_source(source, registry).format == "custom"


def test_default_registry_cached_and_fresh_registry_independent():
    assert api.get_default_registry() is api.get_default_registry()
    first, second = api.build_default_registry(), api.build_default_registry()
    first.register(CustomDetector())
    assert api.detect(io.BytesIO(b"x"), first).format == "custom"
    assert api.detect(io.BytesIO(b"x"), second).format == "raw"


def test_http_routing_and_names(monkeypatch):
    urls = []

    def factory(url):
        urls.append(url)
        return CountingReader(b"QFI\xfb" + struct.pack(">I", 3))

    monkeypatch.setattr(api, "_HTTP_READER_CLASS", factory)
    for detect in (api.detect_url, api.detect_path):
        info = detect("https://example.com/disk")
        assert info.format == "qcow2"
        assert info.source_name == "https://example.com/disk"
        assert detect("https://example.com/disk", DetectorRegistry([CustomDetector()])).format == "custom"
    assert len(urls) == 4
    for value in (b"https://example.com/disk", "ftp://example.com/disk", "local.img"):
        with pytest.raises(InvalidSourceError):
            # Invalid input is intentional: verify rejection at the API boundary.
            # noinspection PyTypeChecker
            api.detect_url(value)


@pytest.mark.parametrize("failing", [False, True])
def test_library_opened_file_is_closed(monkeypatch, failing):
    handle = io.BytesIO(b"abc")
    # Inject a module-local replacement for the built-in open used by detect_path.
    # noinspection PyUnresolvedReferences
    monkeypatch.setattr(api, "open", lambda *a, **kw: handle, raising=False)
    if failing:

        class Broken(FormatDetector):
            def detect(self, source):
                raise OSError("failed")

        with pytest.raises(OSError):
            api.detect_path("disk", DetectorRegistry([Broken()]))
    else:
        assert api.detect_path("disk").format == "raw"
    assert handle.closed
