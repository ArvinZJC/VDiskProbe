# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Boundary and regression checks for built-in parsing."""

import io
import struct

import pytest

from tests._helpers import CountingReader, ValueReader
from vdiskprobe.detectors import build_default_registry

# Direct helper tests cover internal parsing and failure paths.
# noinspection PyProtectedMember
from vdiskprobe.detectors import _format_helpers as helpers
from vdiskprobe.source import ByteSource


def inspect(payload):
    return build_default_registry().detect(ByteSource(io.BytesIO(payload)))


def test_short_qcow_header_preserves_recognition():
    info = inspect(b"QFI\xfb" + struct.pack(">I", 3))
    assert info.format == "qcow2"
    assert info.details == {"version": 3}
    assert info.virtual_size is info.cluster_size is None
    assert inspect(b"QFI\xfb" + struct.pack(">I", 4)).format == "raw"
    assert inspect(b"QFI").format == "raw"


def test_confidence_aliases_order_and_request_counts():
    registry = build_default_registry()
    assert [m["format"] for m in registry.describe_formats()] == [
        "qcow",
        "qcow2",
        "qed",
        "vmdk",
        "vdi",
        "vpc",
        "vhdx",
        "luks",
        "bochs",
        "parallels",
        "cloop",
        "dmg",
        "raw",
    ]
    descriptor = inspect(b"# Disk DescriptorFile\nRW 2 FLAT x\nRDONLY 3 FLAT y\nNOACCESS 4 ZERO\n")
    assert (descriptor.format, descriptor.confidence, descriptor.virtual_size) == ("vmdk", 0.95, 4608)
    assert inspect(b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop other").confidence == 0.95
    assert inspect(b"conectix").aliases == ("vhd",)
    source = CountingReader(b"QFI\xfb" + struct.pack(">I", 3) + b"\0" * 64)
    assert registry.detect(ByteSource(source)).format == "qcow2"
    assert source.requests == [(0, 33)]
    source = CountingReader(b"x" * (1024 * 1024))
    info = registry.detect(ByteSource(source))
    assert (info.format, info.confidence, info.virtual_size) == ("raw", 0.1, 1048576)
    assert len(source.requests) <= 5
    assert registry.detect(ByteSource(ValueReader(b""))).virtual_size is None


@pytest.mark.parametrize(
    "value, valid", [(0, False), (4095, False), (4096, True), (8193, False), (67108864, True), (134217728, False)]
)
def test_qed_cluster_bounds(value, valid):
    assert helpers.is_valid_qed_cluster_size(value) is valid


@pytest.mark.parametrize("bits, expected", [(-1, None), (0, 1), (63, 2**63), (64, None)])
def test_cluster_bit_bounds(bits, expected):
    assert helpers.cluster_size_from_bits(bits) == expected


@pytest.mark.parametrize(
    "name, payload, expected",
    [
        ("read_u8", b"\xff", 255),
        ("read_u16be", b"\x01\x02", 258),
        ("read_u16le", b"\x01\x02", 513),
        ("read_u32be", b"\0\0\x01\0", 256),
        ("read_u32le", b"\0\x01\0\0", 256),
        ("read_u64be", b"\0" * 6 + b"\x01\0", 256),
        ("read_u64le", b"\0\x01" + b"\0" * 6, 256),
    ],
)
def test_endian_helpers(name, payload, expected):
    assert getattr(helpers, name)(payload) == expected


def test_secondary_dmg_trailer_and_short_metadata():
    payload = bytearray(2048)
    payload[1024:1028] = b"koly"
    struct.pack_into(">Q", payload, 1024 + 0x1EC, 12)
    info = inspect(payload)
    assert (info.format, info.virtual_size, info.details["trailer_offset"]) == ("dmg", 6144, 1024)
    assert helpers.vpc_footer_virtual_size(b"") is None
    assert helpers.vpc_footer_disk_type(b"") is None
    assert helpers.vpc_dynamic_cluster_size(b"") is None
    assert helpers.bochs_header_sizes(b"") == (None, None)
    assert helpers.cloop_sizes(ByteSource(io.BytesIO(b""))) == (None, None)


def test_parallels_extended_sizes_and_sparse_bochs():
    payload = bytearray(64)
    payload[:16] = b"WithouFreSpacExt"
    struct.pack_into("<I", payload, 28, 8)
    struct.pack_into("<Q", payload, 36, 2**32 + 3)
    info = inspect(payload)
    assert info.details == {"extended": True}
    assert info.virtual_size == (2**32 + 3) * 512
    assert info.cluster_size == 4096
    assert info.read_only
    info = inspect(struct.pack("<I", 0x02468ACE))
    assert (info.format, info.details, info.read_only) == ("bochs", {"subformat": "sparse"}, True)


def test_vhdx_metadata_reads_only_required_known_fields():
    """Untrusted item lengths must not turn header inspection into a huge read."""
    import uuid

    metadata = 0x50000
    payload = bytearray(metadata + 256)
    payload[:8] = b"vhdxfile"
    payload[0x30000:0x30004] = b"regi"
    struct.pack_into("<I", payload, 0x30008, 1)
    payload[0x30010:0x30020] = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
    struct.pack_into("<Q", payload, 0x30020, metadata)
    struct.pack_into("<I", payload, 0x30028, 0xFFFFFFFF)
    payload[metadata : metadata + 8] = b"metadata"
    struct.pack_into("<H", payload, metadata + 10, 2)
    payload[metadata + 32 : metadata + 48] = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
    struct.pack_into("<II", payload, metadata + 48, 128, 0xFFFFFF00)
    payload[metadata + 64 : metadata + 80] = b"unknown-field-id"
    struct.pack_into("<II", payload, metadata + 80, 132, 0xFFFFFF00)
    struct.pack_into("<I", payload, metadata + 128, 65536)
    reader = CountingReader(payload)
    result = build_default_registry().detect(ByteSource(reader))
    assert result.format == "vhdx"
    assert result.cluster_size == 65536
    assert max(size for _, size in reader.requests) <= 65536
    assert not any(offset == metadata + 132 for offset, _ in reader.requests)


def test_oversized_descriptor_metadata_remains_unknown():
    payload = b"# Disk DescriptorFile\nRW 2 FLAT valid\nRW " + b"9" * 5000 + b" FLAT huge\n"
    info = inspect(payload)
    assert (info.format, info.confidence) == ("vmdk", 0.95)
    assert info.virtual_size is None
    # Multiplication can cross the interpreter's decimal serialisation limit.
    payload = b"# Disk DescriptorFile\nRW " + b"9" * 4300 + b" FLAT huge\n"
    assert inspect(payload).virtual_size is None
