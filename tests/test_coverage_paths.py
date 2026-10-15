# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Core result, error and logging contracts."""

import io
import logging

from vdiskprobe.errors import InvalidSourceError, RemoteSourceError, VDiskProbeError
from vdiskprobe.info import ImageInfo
from vdiskprobe.log import configure_logging, get_logger


def test_image_info_serialization_contract():
    info = ImageInfo("qcow2", "description", confidence=None, file_size=2**40)
    payload = info.to_dict()
    assert set(payload) == {
        "aliases",
        "confidence",
        "cluster_size",
        "description",
        "details",
        "detector",
        "disk_size",
        "file_size",
        "format",
        "read_only",
        "source_name",
        "virtual_size",
    }
    assert payload["file_size"] == 2**40
    assert payload["virtual_size"] is None
    assert payload["aliases"] == []
    assert payload["confidence"] == 1.0
    assert payload["detector"] == "unknown"
    assert "qcow2" in repr(info)


def test_result_mutability_and_copy():
    info = ImageInfo("raw", "fallback", aliases=["plain"], details={"size": 1})
    info.format = "custom"
    payload = info.to_dict()
    assert payload["format"] == "custom"
    assert info.aliases == ("plain",)
    assert payload["details"] is not info.details
    assert payload["aliases"] == ["plain"]


def test_error_hierarchy():
    assert issubclass(InvalidSourceError, VDiskProbeError)
    assert issubclass(RemoteSourceError, VDiskProbeError)


def test_logging_configuration():
    logger = get_logger()
    previous = (logger.handlers[:], logger.level, logger.propagate)
    root_handlers = logging.getLogger().handlers[:]
    try:
        logger.handlers.clear()
        assert any(isinstance(h, logging.NullHandler) for h in get_logger().handlers)
        assert get_logger("detectors").name == "vdiskprobe.detectors"
        output = io.StringIO()
        configure_logging(logging.INFO, output)
        configure_logging(logging.INFO, output)
        logger.info("visible message")
        assert output.getvalue().count("visible message") == 1
        assert len([h for h in logger.handlers if isinstance(h, logging.StreamHandler)]) == 1
        configure_logging(propagate=True)
        assert logger.propagate
        assert not any(isinstance(h, logging.NullHandler) for h in logger.handlers)
        assert logging.getLogger().handlers == root_handlers
    finally:
        logger.handlers[:], logger.level, logger.propagate = previous


def test_package_import_installs_null_handler_without_configuring_root():
    import subprocess
    import sys

    code = (
        "import logging; original = list(logging.getLogger().handlers); "
        "import vdiskprobe; "
        "assert any(isinstance(h, logging.NullHandler) for h in logging.getLogger('vdiskprobe').handlers); "
        "assert logging.getLogger().handlers == original"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
