# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Detection result models."""

from collections.abc import Iterable, Mapping
from typing import Any


class ImageInfo:
    """Mutable detection result with JSON-friendly serialisation.

    Parameters
    ----------
    format_name : str
        Canonical image format name.
    description : str
        Human-readable format description.
    confidence : float, optional
        Confidence score between ``0`` and ``1``.
    read_only : bool, optional
        Whether the format is treated as read-only by QEMU.
    detector : str, optional
        Detector class name that produced the result.
    source_name : str, optional
        Friendly source label.
    details : dict, optional
        Additional structured metadata.
    aliases : sequence, optional
        Alternative format names.
    file_size : int, optional
        Logical source length in bytes when known.
    disk_size : int, optional
        Host disk allocation in bytes when known.
    virtual_size : int, optional
        Guest-visible image size in bytes when known.
    cluster_size : int, optional
        Image cluster size in bytes when known.
    """

    def __init__(
        self,
        format_name: str,
        description: str,
        confidence: float | None = 1.0,
        read_only: bool = False,
        detector: str | None = None,
        source_name: str | None = None,
        details: Mapping[str, Any] | None = None,
        aliases: Iterable[str] | None = None,
        file_size: Any = None,
        disk_size: Any = None,
        virtual_size: Any = None,
        cluster_size: Any = None,
    ) -> None:
        """Initialise an image information record.

        Parameters
        ----------
        format_name : str
            Canonical image format name.
        description : str
            Human-readable format description.
        confidence : float, optional
            Confidence score between ``0`` and ``1``.
        read_only : bool, optional
            Whether the format is treated as read-only.
        detector : str, optional
            Detector class name.
        source_name : str, optional
            Friendly source label.
        details : dict, optional
            Additional structured metadata.
        aliases : tuple, optional
            Alternative format names.
        file_size : object, optional
            Logical source length in bytes.
        disk_size : object, optional
            Host disk allocation in bytes.
        virtual_size : object, optional
            Guest-visible image size in bytes.
        cluster_size : object, optional
            Image cluster size in bytes.
        """
        self.format = format_name
        self.description = description
        if confidence is None:
            confidence = 1.0
        self.confidence = float(confidence)
        self.read_only = bool(read_only)
        self.detector = detector or "unknown"
        self.source_name = source_name
        self.details = details or {}
        self.aliases = tuple(aliases or ())
        self.file_size = _optional_int(file_size)
        self.disk_size = _optional_int(disk_size)
        self.virtual_size = _optional_int(virtual_size)
        self.cluster_size = _optional_int(cluster_size)

    def to_dict(self) -> dict[str, object]:
        """Convert the result into a JSON-friendly dictionary.

        Returns
        -------
        dict
            Serialisable representation of the image information.
        """
        return {
            "aliases": list(self.aliases),
            "confidence": self.confidence,
            "cluster_size": self.cluster_size,
            "description": self.description,
            "details": dict(self.details),
            "detector": self.detector,
            "disk_size": self.disk_size,
            "file_size": self.file_size,
            "format": self.format,
            "read_only": self.read_only,
            "source_name": self.source_name,
            "virtual_size": self.virtual_size,
        }

    def __repr__(self) -> str:
        """Return a debugging representation.

        Returns
        -------
        str
            Debugging representation.
        """
        return "ImageInfo(format={0!r}, detector={1!r})".format(self.format, self.detector)


def _optional_int(value: Any) -> int | None:
    """Convert optional metadata values to integers.

    Parameters
    ----------
    value : object
        Candidate integer value.

    Returns
    -------
    int
        ``int`` value or ``None``.
    """
    if value is None:
        return None
    return int(str(value))
