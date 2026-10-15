# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""High-level convenience API for VDiskProbe."""

import os

from vdiskprobe.detectors import build_default_registry as _build_default_registry
from vdiskprobe.detectors.base import DetectorRegistry
from vdiskprobe.errors import InvalidSourceError
from vdiskprobe.http_source import HttpRangeReader, is_http_url
from vdiskprobe.info import ImageInfo
from vdiskprobe.source import ByteSource

_DEFAULT_REGISTRY = None
_HTTP_READER_CLASS = HttpRangeReader


def get_default_registry() -> DetectorRegistry:
    """Return the process-wide default detector registry.

    Returns
    -------
    DetectorRegistry
        Detector registry instance populated with the built-in detectors.
    """
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = _build_default_registry()
    return _DEFAULT_REGISTRY


def inspect_source(source: object, registry: DetectorRegistry | None = None, name: str | None = None) -> ImageInfo:
    """Inspect an arbitrary byte source.

    Parameters
    ----------
    source : object
        Seekable file-like object, random-access reader, or ``ByteSource``.
    registry : DetectorRegistry, optional
        Explicit detector registry. The built-in default registry is used
        when omitted.
    name : str, optional
        Friendly source name shown in detection results.

    Returns
    -------
    ImageInfo
        Detected image information record.
    """
    byte_source = source if isinstance(source, ByteSource) else ByteSource(source, name=name)
    active_registry = registry or get_default_registry()
    return active_registry.detect(byte_source)


def detect(source: object, registry: DetectorRegistry | None = None, name: str | None = None) -> ImageInfo:
    """Detect the image format of an arbitrary byte source.

    Parameters
    ----------
    source : object
        Seekable file-like object, random-access reader, or ``ByteSource``.
    registry : DetectorRegistry, optional
        Explicit detector registry.
    name : str, optional
        Friendly source name shown in the resulting ``ImageInfo``.

    Returns
    -------
    ImageInfo
        Detected image information record.
    """
    return inspect_source(source, registry=registry, name=name)


def detect_url(url: str, registry: DetectorRegistry | None = None) -> ImageInfo:
    """Detect the image format of an HTTP or HTTPS URL."""
    if not is_http_url(url):
        # URL syntax only; this literal is never used for a network request.
        # noinspection HttpUrlsUsage
        raise InvalidSourceError("url must use http:// or https://")
    reader = _HTTP_READER_CLASS(url)
    return inspect_source(reader, registry=registry, name=url)


def detect_path(path: str | os.PathLike[str], registry: DetectorRegistry | None = None) -> ImageInfo:
    """Detect the image format of a filesystem path or HTTP/HTTPS URL.

    Parameters
    ----------
    path : str
        Path or URL to an image file.
    registry : DetectorRegistry, optional
        Explicit detector registry.

    Returns
    -------
    ImageInfo
        Detected image information record.
    """
    # Both str and PathLike[str] are valid; PyCharm cannot resolve the generic union overload.
    # noinspection PyTypeChecker
    path = os.fspath(path)
    if is_http_url(path):
        return detect_url(path, registry=registry)
    with open(path, "rb") as handle:
        info = inspect_source(handle, registry=registry, name=path)
    return info


def build_default_registry() -> DetectorRegistry:
    """Create a new detector registry with the built-in detectors.

    Returns
    -------
    DetectorRegistry
        Fresh detector registry instance.
    """
    return _build_default_registry()
