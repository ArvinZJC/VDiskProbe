# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Error hierarchy for VDiskProbe."""


class VDiskProbeError(Exception):
    """Base exception for VDiskProbe failures."""


class InvalidSourceError(VDiskProbeError):
    """Raised when a supplied byte source does not meet the reader contract."""


class RemoteSourceError(VDiskProbeError):
    """Raised when a remote byte source cannot be inspected safely."""


class RangeNotSupportedError(RemoteSourceError):
    """Raised when a remote server ignores a required byte range."""
