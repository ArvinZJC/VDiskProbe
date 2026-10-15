# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Optional metadata boundaries must preserve recognition without invented sizes."""

import io
import struct
import sys
import uuid
from types import SimpleNamespace

import pytest

from tests.test_format_helpers import inspect

# Direct helper tests cover internal parsing and failure paths.
# noinspection PyProtectedMember
from vdiskprobe.detectors import _format_helpers as helpers
from vdiskprobe.detectors.formats import DmgDetector, LuksDetector
from vdiskprobe.source import ByteSource


def test_zero_and_absent_optional_sizes():
    assert helpers.nonzero(0) is None
    assert helpers.sector_bytes(None) is None
    assert helpers.vmdk_sparse_sizes(b"KDMV") == (None, None)
    assert helpers.vmdk_descriptor_virtual_size(b"# Disk DescriptorFile") is None
    assert helpers.vpc_subformat_from_type(3) == "dynamic"
    assert helpers.vpc_subformat_from_type(4) == "differencing"
    assert helpers.vpc_subformat_from_type(99) is None
    assert inspect(b"QED\0" + b"\0" * 52).cluster_size is None
    vdi = bytearray(72)
    struct.pack_into("<I", vdi, 64, 0xBEDA107F)
    info = inspect(vdi)
    assert info.format == "vdi"
    assert info.virtual_size is info.cluster_size is None


def test_descriptor_bound_when_interpreter_limit_disabled():
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(0)
        assert helpers.vmdk_descriptor_virtual_size(b"RW " + b"9" * 4300 + b" FLAT disk") is None
    finally:
        sys.set_int_max_str_digits(previous)


def test_legacy_sparse_vmdk_sizes():
    header = bytearray(20)
    header[:4] = b"COWD"
    struct.pack_into("<II", header, 12, 10, 2)
    info = inspect(header)
    assert (info.format, info.virtual_size, info.cluster_size) == ("vmdk", 5120, 1024)


@pytest.mark.parametrize("version, known_size, payload_offset", [(2, 2048, 1), (1, None, 1), (1, 108, 1)])
def test_luks_without_usable_payload_size(version, known_size, payload_offset):
    header = bytearray(108)
    header[:6] = b"LUKS\xba\xbe"
    struct.pack_into(">H", header, 6, version)
    struct.pack_into(">I", header, 104, payload_offset)
    reader = SimpleNamespace(read=lambda o, s: header[o : o + s], size=known_size)
    info = LuksDetector().detect(ByteSource(reader))
    assert info is not None
    assert info.format == "luks"
    assert info.details == {"version": version}
    assert info.virtual_size is None


def test_dmg_small_source_and_truncated_trailer():
    assert DmgDetector().detect(ByteSource(io.BytesIO(b"x" * 512))) is None
    reader = SimpleNamespace(read=lambda o, s: b"koly", size=1024)
    info = DmgDetector().detect(ByteSource(reader))
    assert info is not None
    assert (info.format, info.virtual_size, info.details) == ("dmg", None, {"trailer_offset": 512})


@pytest.mark.parametrize("block_size", [0, 513, 67109376])
def test_cloop_invalid_blocks_remain_unknown(block_size):
    source = ByteSource(io.BytesIO(b"\0" * 128 + struct.pack(">II", block_size, 2)))
    assert helpers.cloop_sizes(source) == (None, None)


def test_bochs_v1_and_unknown_version():
    header = bytearray(92)
    struct.pack_into("<I", header, 64, 65536)
    struct.pack_into("<I", header, 80, 4096)
    struct.pack_into("<Q", header, 84, 1048576)
    assert helpers.bochs_header_sizes(header) == (1048576, 4096)
    struct.pack_into("<I", header, 64, 7)
    assert helpers.bochs_header_sizes(header) == (None, 4096)


def vhdx_reader(
    region_count=1,
    region_offset=0x50000,
    region_length=4096,
    entry_count=1,
    entries=None,
    metadata_signature=b"metadata",
    region_entries=None,
    payloads=None,
):
    """Create a sparse random-access source with independently encoded table fields."""
    region = b"regi" + b"\0" * 4 + struct.pack("<I", region_count) + b"\0" * 4
    region_entry = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
    region_entry += struct.pack("<QII", region_offset, region_length, 0)
    header = metadata_signature + b"\0\0" + struct.pack("<H", entry_count) + b"\0" * 20
    chunks = {
        196608: region,
        196624: region_entry if region_entries is None else region_entries,
        region_offset: header,
        region_offset + 32: entries or b"",
    }
    chunks.update(payloads or {})
    return ByteSource(SimpleNamespace(read=lambda offset, size: chunks.get(offset, b"")[:size]))


@pytest.mark.parametrize(
    "source",
    [
        vhdx_reader(region_count=2048),
        vhdx_reader(region_count=0),
        vhdx_reader(region_entries=b"short"),
        vhdx_reader(region_entries=b"\0" * 32),
        vhdx_reader(region_offset=0),
        vhdx_reader(region_length=0),
    ],
)
def test_vhdx_invalid_region_tables_have_no_metadata(source):
    assert helpers.vhdx_metadata_sizes(source) == (None, None)


@pytest.mark.parametrize(
    "source",
    [
        vhdx_reader(metadata_signature=b"invalid!"),
        vhdx_reader(entry_count=2048),
        vhdx_reader(entries=b"short"),
        vhdx_reader(entry_count=0),
    ],
)
def test_vhdx_invalid_metadata_tables_have_no_sizes(source):
    assert helpers.vhdx_metadata_sizes(source) == (None, None)


@pytest.mark.parametrize(
    "guid,length,offset,body",
    [
        ("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", 0, 128, b""),
        ("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", 4, 4094, b""),
        ("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", 3, 128, b"123"),
        ("CAA16737-FA36-4D43-B3B6-33F0AA44E76B", 4, 128, b"123"),
        ("2FA54224-CD1B-4876-B211-5DBED83BF4B8", 7, 128, b"1234567"),
        ("2FA54224-CD1B-4876-B211-5DBED83BF4B8", 8, 128, b"1234567"),
    ],
)
def test_vhdx_invalid_or_truncated_item_has_no_size(guid, length, offset, body):
    entry = uuid.UUID(guid).bytes_le + struct.pack("<IIII", offset, length, 0, 0)
    source = vhdx_reader(entries=entry, payloads={0x50000 + offset: body})
    assert helpers.vhdx_metadata_sizes(source) == (None, None)


def test_vdi_version_word_keeps_major_and_minor_in_order():
    header = bytearray(72)
    struct.pack_into("<II", header, 64, 0xBEDA107F, 0x00010002)
    info = inspect(header)
    assert info.format == "vdi"
    assert info.details == {"major_version": 1, "minor_version": 2}


def test_differencing_vhd_is_not_relabelled_by_dynamic_header():
    header = bytearray(1024)
    header[:8] = b"conectix"
    struct.pack_into(">Q", header, 48, 1048576)
    struct.pack_into(">I", header, 60, 4)
    header[512:520] = b"cxsparse"
    struct.pack_into(">I", header, 544, 4096)
    info = inspect(header)
    assert info.format == "vpc"
    assert info.details == {"subformat": "differencing"}
    assert (info.virtual_size, info.cluster_size) == (1048576, 4096)


@pytest.mark.parametrize("limit", [640, 4300])
def test_vmdk_aggregate_extent_overflow_returns_unknown(limit):
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(limit)
        payload = (b"RW " + b"9" * limit + b" FLAT disk\n") * 2
        assert helpers.vmdk_descriptor_virtual_size(payload) is None
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize(
    "major,minor,offset,length,expected",
    [
        (0, 2, 352, 384, (1048576, 65536)),
        (0, 2, 352, 364, (1048576, 65536)),
        (0, 2, 352, 363, (None, None)),
        (1, 0, 368, 384, (1048576, 65536)),
        (1, 1, 368, 384, (1048576, 65536)),
        (2, 0, 368, 384, (None, None)),
        (0, 1, 368, 384, (None, None)),
    ],
)
def test_vdi_metadata_uses_only_known_version_layout(major, minor, offset, length, expected):
    header = bytearray(b"\x01" * 384)
    struct.pack_into("<II", header, 64, 0xBEDA107F, major << 16 | minor)
    struct.pack_into("<QI", header, offset, 1048576, 65536)
    info = inspect(header[:length])
    assert info.format == "vdi"
    assert info.details == {"major_version": major, "minor_version": minor}
    assert (info.virtual_size, info.cluster_size) == expected


@pytest.mark.parametrize("known_size", [True, False])
def test_large_descriptor_does_not_report_partial_capacity(known_size):
    payload = b"# Disk DescriptorFile\nRW 2 FLAT first\n" + b"#padding\n" * 8000 + b"RW 3 FLAT last\n"
    reader = SimpleNamespace(read=lambda o, s: payload[o : o + s])
    if known_size:
        reader.size = len(payload)
    from vdiskprobe import detect

    info = detect(reader)
    assert info.format == "vmdk"
    assert info.virtual_size is None


def test_descriptor_exact_window_with_known_end_retains_size():
    payload = b"# Disk DescriptorFile\nRW 2 FLAT first\n"
    payload += b"#" * (65536 - len(payload))
    assert inspect(payload).virtual_size == 1024


def test_vhd_reads_declared_dynamic_header_offset():
    header = bytearray(2048)
    header[:8] = b"conectix"
    struct.pack_into(">Q", header, 16, 1024)
    struct.pack_into(">I", header, 60, 3)
    header[1024:1032] = b"cxsparse"
    struct.pack_into(">I", header, 1056, 2097152)
    info = inspect(header)
    assert info.details == {"subformat": "dynamic"}
    assert info.cluster_size == 2097152


@pytest.mark.parametrize("offset", [2**64 - 1, sys.maxsize - 10, 0x50000])
def test_vhdx_unreadable_metadata_offset_keeps_recognition(offset):
    header = bytearray(262144)
    header[:8] = b"vhdxfile"
    header[196608:196612] = b"regi"
    struct.pack_into("<I", header, 196616, 1)
    header[196624:196640] = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
    struct.pack_into("<QI", header, 196640, offset, 4096)
    info = inspect(header)
    assert info.format == "vhdx"
    assert info.virtual_size is info.cluster_size is None


def test_fixed_vhd_sentinel_does_not_parse_payload_as_dynamic_header():
    header = bytearray(1024)
    header[:8] = b"conectix"
    struct.pack_into(">Q", header, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">I", header, 60, 2)
    header[512:520] = b"cxsparse"
    struct.pack_into(">I", header, 544, 2097152)
    info = inspect(header)
    assert info.details == {"subformat": "fixed"}
    assert info.cluster_size is None


def test_vhd_trailing_footer_follows_dynamic_header_pointer():
    header = bytearray(2048)
    header[1536:1544] = b"conectix"
    struct.pack_into(">Q", header, 1536 + 16, 1024)
    struct.pack_into(">I", header, 1536 + 60, 4)
    header[1024:1032] = b"cxsparse"
    struct.pack_into(">I", header, 1056, 2097152)
    info = inspect(header)
    assert info.details == {"subformat": "differencing"}
    assert info.cluster_size == 2097152


def test_short_descriptor_without_source_length_retains_capacity():
    from vdiskprobe import detect

    payload = b"# Disk DescriptorFile\nRW 2 FLAT disk\n"
    info = detect(SimpleNamespace(read=lambda o, s: payload[o : o + s]))
    assert info.format == "vmdk"
    assert info.virtual_size == 1024
