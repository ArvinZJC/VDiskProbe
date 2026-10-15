# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Parsing helpers for built-in image format detectors."""

import re
import struct
import sys
import uuid

from vdiskprobe.errors import RangeNotSupportedError
from vdiskprobe.source import ByteSource

CLOOP_HEADER_OFFSET = 128
CLOOP_MAX_BLOCK_SIZE = 64 * 1024 * 1024
DMG_SECTOR_COUNT_OFFSET = 492
SECTOR_SIZE = 512
VHDX_FILE_PARAMETERS_GUID = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
VHDX_METADATA_REGION_GUID = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
VHDX_REGION_TABLE_OFFSETS = (196608, 262144)
VHDX_VIRTUAL_DISK_SIZE_GUID = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8").bytes_le
VHDX_MAX_TABLE_ENTRIES = 2047
VHDX_METADATA_TABLE_ENTRY_SIZE = 32
VMDK_DESCRIPTOR_READ_SIZE = 64 * 1024
QCOW_MAGIC = b"QFI\xfb"
QED_MAGIC = b"QED\x00"
VHDX_MAGIC = b"vhdxfile"
VDI_SIGNATURE = 3201962111
VMDK_MAGICS = (b"KDMV", b"COWD", b"VMDK")
VPC_COOKIES = (b"conectix", b"connectix")
VPC_DYNAMIC_COOKIE = b"cxsparse"
PARALLELS_MAGICS = (b"WithoutFreeSpace", b"WithouFreSpacExt")
BOCHS_MAGIC: bytes = b"Bochs Virtual HD Image"
BOCHS_SPARSE_MAGIC = 38177486
LUKS_MAGIC = b"LUKS\xba\xbe"
DMG_MAGIC = b"koly"
CLOOP_MAGIC = b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n"
VMDK_EXTENT_RE = re.compile(b"^[ \\t]*(?:RW|RDONLY|NOACCESS)[ \\t]+(\\d+)[ \\t]+\\S+", re.IGNORECASE | re.MULTILINE)


def read_u32be(data: bytes) -> int:
    """Read a big-endian unsigned 32-bit integer."""
    return struct.unpack(">I", data)[0]


def read_u16be(data: bytes) -> int:
    """Read a big-endian unsigned 16-bit integer."""
    return struct.unpack(">H", data)[0]


def read_u64be(data: bytes) -> int:
    """Read a big-endian unsigned 64-bit integer."""
    return struct.unpack(">Q", data)[0]


def read_u8(data: bytes) -> int:
    """Read an unsigned 8-bit integer."""
    return struct.unpack("B", data)[0]


def read_u32le(data: bytes) -> int:
    """Read a little-endian unsigned 32-bit integer."""
    return struct.unpack("<I", data)[0]


def read_u64le(data: bytes) -> int:
    """Read a little-endian unsigned 64-bit integer."""
    return struct.unpack("<Q", data)[0]


def read_u16le(data: bytes) -> int:
    """Read a little-endian unsigned 16-bit integer."""
    return struct.unpack("<H", data)[0]


def nonzero(value: int | None) -> int | None:
    """Return an integer value only when it carries useful metadata."""
    if value:
        return value
    return None


def sector_bytes(sectors: int | None) -> int | None:
    """Convert a sector count to bytes."""
    if sectors is None:
        return None
    return int(str(sectors)) * SECTOR_SIZE


def is_power_of_two(value: int) -> bool:
    """Return whether a positive integer is a power of two."""
    return value > 0 and (not value & value - 1)


def is_valid_qed_cluster_size(value: int) -> bool:
    """Return whether a QED cluster size is in the valid format range."""
    return 4096 <= value <= 64 * 1024 * 1024 and is_power_of_two(value)


def looks_like_vmdk_descriptor(data: bytes) -> bool:
    """Check whether text resembles a VMDK descriptor file."""
    cleaned = data.replace(b"\x00", b"")
    if b"# Disk DescriptorFile" in cleaned:
        return True
    return b"createType=" in cleaned and b"CID=" in cleaned


def startswith_any(data: bytes, candidates: tuple) -> bool:
    """Check whether a string starts with any candidate prefix."""
    for candidate in candidates:
        if data.startswith(candidate):
            return True
    return False


def vmdk_descriptor_virtual_size(data: bytes) -> int | None:
    """Extract a virtual disk size from VMDK descriptor extent lines."""
    total_sectors = 0
    digit_limit = sys.get_int_max_str_digits() or sys.int_info.default_max_str_digits
    for match in VMDK_EXTENT_RE.finditer(data.replace(b"\x00", b"")):
        digits = match.group(1)
        if len(digits) > digit_limit:
            return None
        total_sectors += int(digits)
    result = total_sectors * SECTOR_SIZE if total_sectors else None
    if result is not None:
        try:
            if len(str(result)) > digit_limit:
                return None
        except ValueError:
            return None
    return result


def vmdk_sparse_sizes(header: bytes) -> tuple[int | None, int | None]:
    """Extract VMDK sparse extent capacity and grain size when present."""
    if header.startswith(b"KDMV") and len(header) >= 28:
        return sector_bytes(nonzero(read_u64le(header[12:20]))), sector_bytes(nonzero(read_u64le(header[20:28])))
    if header[:4] in (b"COWD", b"VMDK") and len(header) >= 20:
        return sector_bytes(nonzero(read_u32le(header[12:16]))), sector_bytes(nonzero(read_u32le(header[16:20])))
    return None, None


def vdi_header_sizes(header: bytes, major: int, minor: int) -> tuple[int | None, int | None]:
    """Read size fields only from recognised VDI header layouts."""
    if (major, minor) == (0, 2):
        offset = 352
    elif major == 1:
        offset = 368
    else:
        return None, None
    if len(header) < offset + 12:
        return None, None
    return nonzero(read_u64le(header[offset : offset + 8])), nonzero(read_u32le(header[offset + 8 : offset + 12]))


def vpc_footer_virtual_size(footer: bytes) -> int | None:
    """Extract the current VHD size from a 512-byte footer."""
    if len(footer) < 56:
        return None
    return nonzero(read_u64be(footer[48:56]))


def vpc_footer_disk_type(footer: bytes) -> int | None:
    """Extract the VHD disk type code when available."""
    if len(footer) < 64:
        return None
    return nonzero(read_u32be(footer[60:64]))


def vpc_subformat_from_type(disk_type: int | None) -> str | None:
    """Map a VHD footer disk type to a readable subformat name."""
    if disk_type == 2:
        return "fixed"
    if disk_type == 3:
        return "dynamic"
    if disk_type == 4:
        return "differencing"
    return None


def vpc_dynamic_cluster_size(dynamic_header: bytes) -> int | None:
    """Extract the VHD dynamic block size when a dynamic header is present."""
    if len(dynamic_header) < 36 or dynamic_header[:8] != VPC_DYNAMIC_COOKIE:
        return None
    return nonzero(read_u32be(dynamic_header[32:36]))


def read_optional_metadata(source: ByteSource, offset: int, size: int) -> bytes:
    """Skip metadata probes outside the source or the platform's seek range."""
    if offset > sys.maxsize - size:
        return b""
    source_size = source.get_size()
    if source_size is not None and offset >= source_size:
        return b""
    try:
        return source.read(offset, size)
    except RangeNotSupportedError:
        return b""


def vpc_dynamic_header(source: ByteSource, footer: bytes) -> bytes:
    """Follow the VHD footer's dynamic-header pointer when available."""
    offset = read_u64be(footer[16:24]) if len(footer) >= 24 else 0
    if offset == 0xFFFFFFFFFFFFFFFF:
        return b""
    return read_optional_metadata(source, offset or 512, 36)


def vhdx_metadata_region(source: ByteSource) -> tuple[int, int] | None:
    """Return the VHDX metadata region entry from either region table copy."""
    for table_offset in VHDX_REGION_TABLE_OFFSETS:
        header = read_optional_metadata(source, table_offset, 16)
        if len(header) < 16 or header[:4] != b"regi":
            continue
        entry_count = read_u32le(header[8:12])
        if entry_count > VHDX_MAX_TABLE_ENTRIES:
            continue
        entries = read_optional_metadata(source, table_offset + 16, entry_count * 32)
        for index in range(entry_count):
            entry = entries[index * 32 : (index + 1) * 32]
            if len(entry) < 32 or entry[:16] != VHDX_METADATA_REGION_GUID:
                continue
            offset = read_u64le(entry[16:24])
            length = read_u32le(entry[24:28])
            if offset and length:
                return offset, length
    return None


def vhdx_metadata_sizes(source: ByteSource) -> tuple[int | None, int | None]:
    """Extract VHDX virtual disk and payload block sizes from metadata."""
    metadata_region = vhdx_metadata_region(source)
    if metadata_region is None:
        return None, None
    metadata_offset, metadata_length = metadata_region
    header = read_optional_metadata(source, metadata_offset, 32)
    if len(header) < 32 or header[:8] != b"metadata":
        return None, None
    entry_count = read_u16le(header[10:12])
    if entry_count > VHDX_MAX_TABLE_ENTRIES:
        return None, None
    virtual_size = None
    cluster_size = None
    entries = read_optional_metadata(source, metadata_offset + 32, entry_count * VHDX_METADATA_TABLE_ENTRY_SIZE)
    for index in range(entry_count):
        entry = entries[index * VHDX_METADATA_TABLE_ENTRY_SIZE : (index + 1) * VHDX_METADATA_TABLE_ENTRY_SIZE]
        if len(entry) < VHDX_METADATA_TABLE_ENTRY_SIZE:
            continue
        item_id = entry[:16]
        item_offset = read_u32le(entry[16:20])
        item_length = read_u32le(entry[20:24])
        if item_length == 0 or item_offset + item_length > metadata_length:
            continue
        if item_id == VHDX_FILE_PARAMETERS_GUID and item_length >= 4:
            item = read_optional_metadata(source, metadata_offset + item_offset, 4)
            if len(item) >= 4:
                cluster_size = nonzero(read_u32le(item))
        elif item_id == VHDX_VIRTUAL_DISK_SIZE_GUID and item_length >= 8:
            item = read_optional_metadata(source, metadata_offset + item_offset, 8)
            if len(item) >= 8:
                virtual_size = nonzero(read_u64le(item))
    return virtual_size, cluster_size


def bochs_header_sizes(header: bytes) -> tuple[int | None, int | None]:
    """Extract Bochs growing-image size metadata."""
    if len(header) < 84:
        return None, None
    version = read_u32le(header[64:68])
    cluster_size = nonzero(read_u32le(header[80:84]))
    virtual_size = None
    if version == 65536 and len(header) >= 92:
        virtual_size = nonzero(read_u64le(header[84:92]))
    elif version == 131072 and len(header) >= 96:
        virtual_size = nonzero(read_u64le(header[88:96]))
    return virtual_size, cluster_size


def cloop_sizes(source: ByteSource) -> tuple[int | None, int | None]:
    """Extract cloop block count and block size when the header is complete."""
    header = read_optional_metadata(source, CLOOP_HEADER_OFFSET, 8)
    if len(header) < 8:
        return None, None
    cluster_size = read_u32be(header[:4])
    block_count = read_u32be(header[4:8])
    if cluster_size == 0 or cluster_size % SECTOR_SIZE or cluster_size > CLOOP_MAX_BLOCK_SIZE:
        return None, None
    return int(block_count) * cluster_size, cluster_size


def cluster_size_from_bits(cluster_bits: int) -> int | None:
    """Convert a qcow cluster bit count to bytes."""
    if cluster_bits < 0 or cluster_bits > 63:
        return None
    return int(1) << cluster_bits
