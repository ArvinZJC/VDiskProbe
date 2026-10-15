# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Detector registry and built-in formats."""

from vdiskprobe.detectors.base import DetectorRegistry, FormatDetector
from vdiskprobe.detectors.formats import BUILTIN_DETECTORS


def build_default_registry() -> DetectorRegistry:
    """Return an independent registry containing the built-in detectors."""
    return DetectorRegistry(BUILTIN_DETECTORS)
