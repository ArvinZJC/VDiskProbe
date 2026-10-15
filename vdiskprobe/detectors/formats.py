# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Built-in image format detectors."""

from vdiskprobe.detectors._format_helpers import (
    BOCHS_MAGIC,
    BOCHS_SPARSE_MAGIC,
    CLOOP_MAGIC,
    DMG_MAGIC,
    DMG_SECTOR_COUNT_OFFSET,
    LUKS_MAGIC,
    PARALLELS_MAGICS,
    QCOW_MAGIC,
    QED_MAGIC,
    VDI_SIGNATURE,
    VHDX_MAGIC,
    VMDK_DESCRIPTOR_READ_SIZE,
    VMDK_MAGICS,
    VPC_COOKIES,
    VPC_DYNAMIC_COOKIE,
    bochs_header_sizes as _bochs_header_sizes,
    cloop_sizes as _cloop_sizes,
    cluster_size_from_bits as _cluster_size_from_bits,
    is_valid_qed_cluster_size as _is_valid_qed_cluster_size,
    looks_like_vmdk_descriptor as _looks_like_vmdk_descriptor,
    nonzero as _nonzero,
    read_u16be as _read_u16be,
    read_u16le as _read_u16le,
    read_u32be as _read_u32be,
    read_u32le as _read_u32le,
    read_u64be as _read_u64be,
    read_u64le as _read_u64le,
    read_u8 as _read_u8,
    sector_bytes as _sector_bytes,
    startswith_any as _startswith_any,
    vdi_header_sizes as _vdi_header_sizes,
    vhdx_metadata_sizes as _vhdx_metadata_sizes,
    vmdk_descriptor_virtual_size as _vmdk_descriptor_virtual_size,
    vmdk_sparse_sizes as _vmdk_sparse_sizes,
    vpc_dynamic_cluster_size as _vpc_dynamic_cluster_size,
    vpc_dynamic_header as _vpc_dynamic_header,
    vpc_footer_disk_type as _vpc_footer_disk_type,
    vpc_footer_virtual_size as _vpc_footer_virtual_size,
    vpc_subformat_from_type as _vpc_subformat_from_type,
)
from vdiskprobe.detectors.base import FormatDetector
from vdiskprobe.source import ByteSource
from vdiskprobe.errors import RangeNotSupportedError
from vdiskprobe.info import ImageInfo


class QcowV1Detector(FormatDetector):
    """Detector for the legacy qcow v1 format."""

    format_name = "qcow"
    description = "Legacy QEMU copy-on-write image (qcow v1)"
    priority = 10

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect qcow v1 images."""
        header = source.read(0, 33)
        if len(header) < 8 or header[:4] != QCOW_MAGIC:
            return None
        if _read_u32be(header[4:8]) != 1:
            return None
        virtual_size = None
        cluster_size = None
        if len(header) >= 33:
            virtual_size = _read_u64be(header[24:32])
            cluster_size = _cluster_size_from_bits(_read_u8(header[32:33]))
        return self.build_info(source, details={"version": 1}, virtual_size=virtual_size, cluster_size=cluster_size)


class Qcow2Detector(FormatDetector):
    """Detector for qcow2 images."""

    format_name = "qcow2"
    description = "QEMU copy-on-write image (qcow2)"
    priority = 11

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect qcow2 images."""
        header = source.read(0, 32)
        if len(header) < 8 or header[:4] != QCOW_MAGIC:
            return None
        version = _read_u32be(header[4:8])
        if version not in (2, 3):
            return None
        virtual_size = None
        cluster_size = None
        if len(header) >= 32:
            virtual_size = _read_u64be(header[24:32])
            cluster_size = _cluster_size_from_bits(_read_u32be(header[20:24]))
        return self.build_info(
            source, details={"version": version}, virtual_size=virtual_size, cluster_size=cluster_size
        )


class QedDetector(FormatDetector):
    """Detector for QED images."""

    format_name = "qed"
    description = "QEMU enhanced disk image"
    priority = 20

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect QED images."""
        header = source.read(0, 56)
        if len(header) >= 4 and header[:4] == QED_MAGIC:
            cluster_size = None
            virtual_size = None
            if len(header) >= 56:
                candidate_cluster_size = _read_u32le(header[4:8])
                if _is_valid_qed_cluster_size(candidate_cluster_size):
                    cluster_size = candidate_cluster_size
                virtual_size = _nonzero(_read_u64le(header[48:56]))
            return self.build_info(source, virtual_size=virtual_size, cluster_size=cluster_size)
        return None


class VmdkDetector(FormatDetector):
    """Detector for VMware VMDK images."""

    format_name = "vmdk"
    description = "VMware virtual disk image"
    priority = 30

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect VMDK images."""
        header = source.read(0, VMDK_DESCRIPTOR_READ_SIZE)
        if len(header) >= 4 and header[:4] in VMDK_MAGICS:
            virtual_size, cluster_size = _vmdk_sparse_sizes(header)
            return self.build_info(source, virtual_size=virtual_size, cluster_size=cluster_size)
        if _looks_like_vmdk_descriptor(header):
            source_size = source.get_size()
            try:
                complete = (
                    source_size == len(header)
                    if source_size is not None
                    else len(header) < VMDK_DESCRIPTOR_READ_SIZE and not source.read(len(header), 1)
                )
            except RangeNotSupportedError:
                complete = False
            return self.build_info(
                source,
                confidence=0.95,
                details={"descriptor": True},
                virtual_size=_vmdk_descriptor_virtual_size(header) if complete else None,
            )
        return None


class VdiDetector(FormatDetector):
    """Detector for VirtualBox VDI images."""

    format_name = "vdi"
    description = "VirtualBox disk image"
    priority = 40

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect VDI images."""
        header = source.read(0, 384)
        if len(header) < 72:
            return None
        if _read_u32le(header[64:68]) != VDI_SIGNATURE:
            return None
        major, minor = _read_u16le(header[70:72]), _read_u16le(header[68:70])
        virtual_size, cluster_size = _vdi_header_sizes(header, major, minor)
        return self.build_info(
            source,
            details={"major_version": major, "minor_version": minor},
            virtual_size=virtual_size,
            cluster_size=cluster_size,
        )


class VpcDetector(FormatDetector):
    """Detector for VPC and VHD images."""

    format_name = "vpc"
    aliases = ("vhd",)
    description = "Microsoft Virtual PC / VHD image"
    priority = 50

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect VPC/VHD images."""
        footer = source.read(0, 512)
        fallback = "footer"
        if not _startswith_any(footer[:9], VPC_COOKIES):
            size = source.get_size()
            if not isinstance(size, int) or size < 512:
                return None
            footer = source.read(size - 512, 512)
            if not _startswith_any(footer[:9], VPC_COOKIES):
                return None
            fallback = "fixed"
        disk_type = _vpc_footer_disk_type(footer)
        dynamic_header = _vpc_dynamic_header(source, footer)
        has_dynamic_header = len(dynamic_header) >= 8 and dynamic_header[:8] == VPC_DYNAMIC_COOKIE
        cluster_size = _vpc_dynamic_cluster_size(dynamic_header)
        subformat = _vpc_subformat_from_type(disk_type) or ("dynamic" if has_dynamic_header else fallback)
        return self.build_info(
            source,
            details={"subformat": subformat},
            virtual_size=_vpc_footer_virtual_size(footer),
            cluster_size=cluster_size,
        )


class VhdxDetector(FormatDetector):
    """Detector for VHDX images."""

    format_name = "vhdx"
    description = "Microsoft VHDX image"
    priority = 60

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect VHDX images."""
        if source.read(0, 8) == VHDX_MAGIC:
            virtual_size, cluster_size = _vhdx_metadata_sizes(source)
            return self.build_info(source, virtual_size=virtual_size, cluster_size=cluster_size)
        return None


class LuksDetector(FormatDetector):
    """Detector for LUKS images."""

    format_name = "luks"
    description = "LUKS encrypted block image"
    priority = 70

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect LUKS images."""
        header = source.read(0, 108)
        if len(header) >= 6 and header[:6] == LUKS_MAGIC:
            virtual_size = None
            details = {}
            if len(header) >= 108:
                version = _read_u16be(header[6:8])
                details["version"] = version
                if version == 1:
                    payload_offset = _read_u32be(header[104:108])
                    source_size = source.get_size()
                    if isinstance(source_size, int):
                        payload_start = _sector_bytes(payload_offset)
                        if isinstance(payload_start, int) and source_size >= payload_start:
                            virtual_size = source_size - payload_start
            return self.build_info(source, details=details, virtual_size=virtual_size)
        return None


class BochsDetector(FormatDetector):
    """Detector for Bochs images."""

    format_name = "bochs"
    description = "Bochs disk image"
    read_only = True
    priority = 80

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect Bochs images."""
        header = source.read(0, 512)
        if len(header) >= len(BOCHS_MAGIC) and header.startswith(BOCHS_MAGIC):
            virtual_size, cluster_size = _bochs_header_sizes(header)
            return self.build_info(source, virtual_size=virtual_size, cluster_size=cluster_size)
        if len(header) >= 4 and _read_u32le(header[:4]) == BOCHS_SPARSE_MAGIC:
            return self.build_info(source, details={"subformat": "sparse"})
        return None


class ParallelsDetector(FormatDetector):
    """Detector for Parallels images."""

    format_name = "parallels"
    description = "Parallels expandable disk image"
    read_only = True
    priority = 90

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect Parallels images."""
        header = source.read(0, 64)
        if header[:16] in PARALLELS_MAGICS:
            extended = header[:16] == b"WithouFreSpacExt"
            details = {"extended": extended}
            virtual_size = None
            cluster_size = None
            if len(header) >= 44:
                tracks = _read_u32le(header[28:32])
                sectors = _read_u64le(header[36:44])
                if not extended:
                    sectors &= 4294967295
                virtual_size = _sector_bytes(_nonzero(sectors))
                cluster_size = _sector_bytes(_nonzero(tracks))
            return self.build_info(source, details=details, virtual_size=virtual_size, cluster_size=cluster_size)
        return None


class CloopDetector(FormatDetector):
    """Detector for compressed loop images."""

    format_name = "cloop"
    description = "Compressed Loop image"
    read_only = True
    priority = 100

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect cloop images."""
        header = source.read(0, len(CLOOP_MAGIC))
        if header == CLOOP_MAGIC:
            virtual_size, cluster_size = _cloop_sizes(source)
            return self.build_info(source, virtual_size=virtual_size, cluster_size=cluster_size)
        if header.startswith(b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop "):
            virtual_size, cluster_size = _cloop_sizes(source)
            return self.build_info(source, confidence=0.95, virtual_size=virtual_size, cluster_size=cluster_size)
        return None


class DmgDetector(FormatDetector):
    """Detector for DMG images."""

    format_name = "dmg"
    description = "Apple disk image (UDIF)"
    read_only = True
    priority = 110

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect DMG images."""
        size = source.get_size()
        if not isinstance(size, int) or size < 512:
            return None
        for trailer_offset in (size - 512, size - 1024):
            if trailer_offset < 0:
                continue
            trailer = source.read(trailer_offset, 512)
            if trailer[:4] == DMG_MAGIC:
                virtual_size = None
                if len(trailer) >= DMG_SECTOR_COUNT_OFFSET + 8:
                    virtual_size = _sector_bytes(
                        _nonzero(_read_u64be(trailer[DMG_SECTOR_COUNT_OFFSET : DMG_SECTOR_COUNT_OFFSET + 8]))
                    )
                return self.build_info(source, details={"trailer_offset": trailer_offset}, virtual_size=virtual_size)
        return None


class RawDetector(FormatDetector):
    """Fallback detector for raw images."""

    format_name = "raw"
    description = "Raw disk image (fallback when no known signature matches)"
    priority = 1000

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Return a low-confidence raw fallback."""
        return self.build_info(source, confidence=0.1, virtual_size=source.get_size())


BUILTIN_DETECTORS = [
    QcowV1Detector(),
    Qcow2Detector(),
    QedDetector(),
    VmdkDetector(),
    VdiDetector(),
    VpcDetector(),
    VhdxDetector(),
    LuksDetector(),
    BochsDetector(),
    ParallelsDetector(),
    CloopDetector(),
    DmgDetector(),
    RawDetector(),
]
