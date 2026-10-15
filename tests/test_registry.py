# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Detector extension and ordering contracts."""

import io

import pytest

from vdiskprobe.detectors.base import DetectorRegistry, FormatDetector
from vdiskprobe.source import ByteSource


class NamedDetector(FormatDetector):
    """Record whether dispatch visits a named matching detector."""

    aliases = ("alias",)
    description = "test detector"
    read_only = True

    def __init__(self, name, priority=100):
        self.format_name = name
        self.priority = priority
        self.visits = 0

    def detect(self, source):
        self.visits += 1
        return self.build_info(source)


def test_stable_priority_and_first_match():
    first, second = NamedDetector("first"), NamedDetector("second")
    registry = DetectorRegistry([first, second])
    source = ByteSource(io.BytesIO(b"abc"), name="disk")
    assert registry.detect(source).format == "first"
    assert (first.visits, second.visits) == (1, 0)
    earlier = NamedDetector("earlier", 10)
    assert registry.register(earlier) is earlier
    assert registry.detect(source).format == "earlier"
    assert registry.describe_formats()[0] == {
        "format": "earlier",
        "description": "test detector",
        "aliases": ["alias"],
        "read_only": True,
    }


def test_result_source_metadata_and_overrides():
    detector = NamedDetector("test")
    source = ByteSource(io.BytesIO(b"abc"), name="disk")
    info = detector.build_info(source)
    assert (info.file_size, info.disk_size, info.source_name) == (3, None, "disk")
    assert info.detector == "NamedDetector"
    assert info.aliases == ("alias",)
    info = detector.build_info(source, 0.5, {"version": 2}, "override", 8, 4, 16, 2)
    assert (info.format, info.file_size, info.disk_size, info.virtual_size, info.cluster_size) == (
        "override",
        8,
        4,
        16,
        2,
    )
    assert info.confidence == 0.5
    assert info.details == {"version": 2}


def test_exhausted_registry_and_abstract_detector():
    source = ByteSource(io.BytesIO(b""))
    with pytest.raises(RuntimeError):
        DetectorRegistry().detect(source)
    with pytest.raises(NotImplementedError):
        FormatDetector().detect(source)


def test_registry_propagates_source_error():
    class Reader(FormatDetector):
        def detect(self, source):
            source.read(0, 1)

    class Broken:
        def read(self, offset, size):
            raise OSError("failed read")

    with pytest.raises(OSError, match="failed read"):
        DetectorRegistry([Reader()]).detect(ByteSource(Broken()))
