# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Detection tests for VDiskProbe."""

import io
import struct
import unittest
import uuid
from vdiskprobe import ByteSource, detect
from vdiskprobe.detectors import build_default_registry
from tests._helpers import to_bytes


def put_bytes(payload, offset, data):
    """Write bytes into a synthetic image payload."""
    payload[offset : offset + len(data)] = data


class RandomAccessReader:
    """Simple random-access reader used by the tests."""

    def __init__(self, data, name=None):
        """Initialise the test reader.

        Parameters
        ----------
        data : bytes or bytearray
            Byte payload exposed by the reader.
        name : object, optional
            Friendly source name.
        """
        self._data = data
        self.name = name or "random-access"

    def read(self, offset, size):
        """Read bytes from the synthetic payload."""
        return self._data[offset : offset + size]

    def size(self):
        """Return the total synthetic payload size."""
        return len(self._data)


class DetectionTests(unittest.TestCase):
    """Test cases for format detection."""

    def setUp(self):
        """Create a fresh detector registry for each test."""
        self.registry = build_default_registry()

    def test_seekable_file_objects_keep_position(self):
        """Ensure seekable file objects retain their original cursor."""
        handle = io.BytesIO(b"abcdefgh")
        handle.seek(3)
        source = ByteSource(handle, name="memory")
        self.assertEqual(b"abcd", source.read(0, 4))
        self.assertEqual(3, handle.tell())

    def test_qcow_v1_detection(self):
        """Detect qcow v1 images."""
        info = detect(io.BytesIO(b"QFI\xfb" + struct.pack(">I", 1)), registry=self.registry, name="qcow")
        self.assertEqual("qcow", info.format)
        self.assertEqual(1, info.details["version"])

    def test_qcow_v1_size_metadata(self):
        """Extract qcow v1 size metadata when the header is complete."""
        payload = bytearray(b"\x00" * 64)
        payload[0:4] = b"QFI\xfb"
        payload[4:8] = struct.pack(">I", 1)
        payload[24:32] = struct.pack(">Q", 1024 * 1024 * 1024)
        payload[32] = 12
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="qcow")
        self.assertEqual(1024 * 1024 * 1024, info.virtual_size)
        self.assertEqual(4096, info.cluster_size)
        self.assertEqual(len(payload), info.file_size)
        self.assertIsNone(info.disk_size)

    def test_qcow2_detection(self):
        """Detect qcow2 images."""
        info = detect(io.BytesIO(b"QFI\xfb" + struct.pack(">I", 3)), registry=self.registry, name="qcow2")
        self.assertEqual("qcow2", info.format)
        self.assertEqual(3, info.details["version"])

    def test_qcow2_size_metadata(self):
        """Extract qcow2 virtual size and cluster size."""
        virtual_size = 10 * 1024 * 1024 * 1024
        payload = bytearray(b"\x00" * 512)
        payload[0:4] = b"QFI\xfb"
        payload[4:8] = struct.pack(">I", 3)
        payload[20:24] = struct.pack(">I", 16)
        payload[24:32] = struct.pack(">Q", virtual_size)
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="qcow2")
        payload_dict = info.to_dict()
        self.assertEqual("qcow2", info.format)
        self.assertEqual(virtual_size, info.virtual_size)
        self.assertEqual(65536, info.cluster_size)
        self.assertEqual(len(payload), info.file_size)
        self.assertIsNone(info.disk_size)
        self.assertEqual(len(payload), payload_dict["file_size"])
        self.assertEqual(virtual_size, payload_dict["virtual_size"])
        self.assertEqual(65536, payload_dict["cluster_size"])

    def test_qed_size_metadata(self):
        """Extract QED virtual size and cluster size."""
        virtual_size = 8 * 1024 * 1024 * 1024
        payload = bytearray(b"\x00" * 64)
        put_bytes(payload, 0, b"QED\x00")
        put_bytes(payload, 4, struct.pack("<I", 65536))
        put_bytes(payload, 48, struct.pack("<Q", virtual_size))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.qed")
        self.assertEqual("qed", info.format)
        self.assertEqual(virtual_size, info.virtual_size)
        self.assertEqual(65536, info.cluster_size)
        self.assertEqual(len(payload), info.file_size)
        self.assertIsNone(info.disk_size)

    def test_vmdk_sparse_size_metadata(self):
        """Extract VMDK sparse capacity and grain size."""
        payload = bytearray(b"\x00" * 512)
        put_bytes(payload, 0, b"KDMV")
        put_bytes(payload, 4, struct.pack("<I", 1))
        put_bytes(payload, 12, struct.pack("<Q", 4096))
        put_bytes(payload, 20, struct.pack("<Q", 128))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.vmdk")
        self.assertEqual("vmdk", info.format)
        self.assertEqual(4096 * 512, info.virtual_size)
        self.assertEqual(128 * 512, info.cluster_size)

    def test_signature_based_formats(self):
        """Detect several signature-based formats."""
        cases = [
            ("qed", b"QED\x00rest"),
            ("vmdk", b"KDMVrest"),
            ("vhdx", b"vhdxfilerest"),
            ("luks", b"LUKS\xba\xberest"),
            ("bochs", b"Bochs Virtual HD Image" + b"\x00" * 32),
            ("parallels", b"WithoutFreeSpace"),
            ("cloop", b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n"),
        ]
        for expected, payload in cases:
            info = detect(io.BytesIO(payload), registry=self.registry, name=expected)
            self.assertEqual(expected, info.format)

    def test_vmdk_descriptor_detection(self):
        """Detect descriptor-only VMDK files."""
        payload = b'# Disk DescriptorFile\nversion=1\nCID=fffffffe\ncreateType="monolithicFlat"\n'
        payload += b'RW 2048 FLAT "descriptor-flat.vmdk" 0\n'
        info = detect(io.BytesIO(payload), registry=self.registry, name="descriptor.vmdk")
        self.assertEqual("vmdk", info.format)
        self.assertTrue(info.details["descriptor"])
        self.assertEqual(2048 * 512, info.virtual_size)

    def test_vdi_detection(self):
        """Detect VDI images."""
        payload = bytearray(b"\x00" * 512)
        payload[0:8] = b"test.vdi"
        payload[64:68] = struct.pack("<I", 3201962111)
        payload[68:70] = struct.pack("<H", 1)
        payload[70:72] = struct.pack("<H", 1)
        payload[368:376] = struct.pack("<Q", 4 * 1024 * 1024 * 1024)
        payload[376:380] = struct.pack("<I", 1024 * 1024)
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.vdi")
        self.assertEqual("vdi", info.format)
        self.assertEqual(1, info.details["major_version"])
        self.assertEqual(4 * 1024 * 1024 * 1024, info.virtual_size)
        self.assertEqual(1024 * 1024, info.cluster_size)

    def test_vpc_footer_detection_with_random_access_reader(self):
        """Detect footer-based VPC images with a custom reader."""
        payload = bytearray(b"\x00" * 1024)
        put_bytes(payload, 512, b"conectix")
        put_bytes(payload, 512 + 48, struct.pack(">Q", 32 * 1024 * 1024))
        put_bytes(payload, 512 + 60, struct.pack(">I", 2))
        reader = RandomAccessReader(payload, name="disk.vhd")
        info = detect(reader, registry=self.registry)
        self.assertEqual("vpc", info.format)
        self.assertEqual("fixed", info.details["subformat"])
        self.assertEqual(32 * 1024 * 1024, info.virtual_size)
        self.assertEqual(len(payload), info.file_size)
        self.assertIsNone(info.disk_size)

    def test_vpc_dynamic_size_metadata(self):
        """Extract dynamic VHD current size and block size."""
        payload = bytearray(b"\x00" * 1024)
        put_bytes(payload, 0, b"conectix")
        put_bytes(payload, 48, struct.pack(">Q", 64 * 1024 * 1024))
        put_bytes(payload, 60, struct.pack(">I", 3))
        put_bytes(payload, 512, b"cxsparse")
        put_bytes(payload, 512 + 32, struct.pack(">I", 2 * 1024 * 1024))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="dynamic.vhd")
        self.assertEqual("vpc", info.format)
        self.assertEqual("dynamic", info.details["subformat"])
        self.assertEqual(64 * 1024 * 1024, info.virtual_size)
        self.assertEqual(2 * 1024 * 1024, info.cluster_size)

    def test_vhdx_size_metadata(self):
        """Extract VHDX metadata-region virtual size and block size."""
        metadata_region_guid = uuid.UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E").bytes_le
        file_parameters_guid = uuid.UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B").bytes_le
        virtual_size_guid = uuid.UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8").bytes_le
        payload = bytearray(b"\x00" * 458752)
        metadata_offset = 327680
        metadata_length = 131072
        block_size_offset = 65536
        virtual_size_offset = 65544
        put_bytes(payload, 0, b"vhdxfile")
        put_bytes(payload, 196608, b"regi")
        put_bytes(payload, 196616, struct.pack("<I", 1))
        put_bytes(payload, 196624, metadata_region_guid)
        put_bytes(payload, 196640, struct.pack("<Q", metadata_offset))
        put_bytes(payload, 196648, struct.pack("<I", metadata_length))
        put_bytes(payload, metadata_offset, b"metadata")
        put_bytes(payload, metadata_offset + 10, struct.pack("<H", 2))
        put_bytes(payload, metadata_offset + 32, file_parameters_guid)
        put_bytes(payload, metadata_offset + 48, struct.pack("<I", block_size_offset))
        put_bytes(payload, metadata_offset + 52, struct.pack("<I", 8))
        put_bytes(payload, metadata_offset + 64, virtual_size_guid)
        put_bytes(payload, metadata_offset + 80, struct.pack("<I", virtual_size_offset))
        put_bytes(payload, metadata_offset + 84, struct.pack("<I", 8))
        put_bytes(payload, metadata_offset + block_size_offset, struct.pack("<I", 2 * 1024 * 1024))
        put_bytes(payload, metadata_offset + virtual_size_offset, struct.pack("<Q", 128 * 1024 * 1024))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.vhdx")
        self.assertEqual("vhdx", info.format)
        self.assertEqual(128 * 1024 * 1024, info.virtual_size)
        self.assertEqual(2 * 1024 * 1024, info.cluster_size)

    def test_luks1_size_metadata(self):
        """Extract LUKS1 encrypted payload size."""
        payload = bytearray(b"\x00" * 4096)
        put_bytes(payload, 0, b"LUKS\xba\xbe")
        put_bytes(payload, 6, struct.pack(">H", 1))
        put_bytes(payload, 104, struct.pack(">I", 2))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.luks")
        self.assertEqual("luks", info.format)
        self.assertEqual(1, info.details["version"])
        self.assertEqual(4096 - 2 * 512, info.virtual_size)

    def test_bochs_size_metadata(self):
        """Extract Bochs growing-image disk and extent sizes."""
        payload = bytearray(b"\x00" * 512)
        put_bytes(payload, 0, b"Bochs Virtual HD Image")
        put_bytes(payload, 64, struct.pack("<I", 131072))
        put_bytes(payload, 68, struct.pack("<I", 512))
        put_bytes(payload, 80, struct.pack("<I", 65536))
        put_bytes(payload, 88, struct.pack("<Q", 20 * 1024 * 1024))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.bochs")
        self.assertEqual("bochs", info.format)
        self.assertEqual(20 * 1024 * 1024, info.virtual_size)
        self.assertEqual(65536, info.cluster_size)

    def test_parallels_size_metadata(self):
        """Extract Parallels sector count and track size."""
        payload = bytearray(b"\x00" * 64)
        put_bytes(payload, 0, b"WithoutFreeSpace")
        put_bytes(payload, 28, struct.pack("<I", 128))
        put_bytes(payload, 36, struct.pack("<Q", 8192))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.hds")
        self.assertEqual("parallels", info.format)
        self.assertEqual(8192 * 512, info.virtual_size)
        self.assertEqual(128 * 512, info.cluster_size)

    def test_cloop_size_metadata(self):
        """Extract cloop block count and block size."""
        payload = bytearray(b"\x00" * 144)
        put_bytes(payload, 0, b"#!/bin/sh\n#V2.0 Format\nmodprobe cloop file=$0 && mount -r -t iso9660 /dev/cloop $1\n")
        put_bytes(payload, 128, struct.pack(">I", 65536))
        put_bytes(payload, 132, struct.pack(">I", 10))
        info = detect(io.BytesIO(to_bytes(payload)), registry=self.registry, name="disk.cloop")
        self.assertEqual("cloop", info.format)
        self.assertEqual(10 * 65536, info.virtual_size)
        self.assertEqual(65536, info.cluster_size)

    def test_dmg_trailer_detection(self):
        """Detect DMG images through their trailer signature."""
        payload = bytearray(b"\x00" * 2048)
        put_bytes(payload, 2048 - 512, b"koly")
        put_bytes(payload, 2048 - 512 + 492, struct.pack(">Q", 4096))
        reader = RandomAccessReader(payload, name="disk.dmg")
        info = detect(reader, registry=self.registry)
        self.assertEqual("dmg", info.format)
        self.assertEqual(4096 * 512, info.virtual_size)

    def test_raw_fallback(self):
        """Fall back to raw when no detector matches."""
        info = detect(io.BytesIO(b"plain-data"), registry=self.registry, name="raw.img")
        self.assertEqual("raw", info.format)
        self.assertLess(info.confidence, 0.5)

    def test_registry_describes_formats(self):
        """Expose registry metadata for built-in formats."""
        formats = [item["format"] for item in self.registry.describe_formats()]
        self.assertIn("qcow2", formats)
        self.assertIn("raw", formats)


if __name__ == "__main__":
    unittest.main()
