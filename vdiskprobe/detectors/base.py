# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Base classes for format detectors."""

from collections.abc import Iterable, Mapping
from typing import Any, TypedDict
from vdiskprobe.errors import RangeNotSupportedError
from vdiskprobe.info import ImageInfo
from vdiskprobe.log import get_logger
from vdiskprobe.source import ByteSource


class DetectorMetadata(TypedDict):
    """Static metadata exposed when listing registered formats."""

    aliases: list[str]
    description: str
    format: str | None
    read_only: bool


LOG = get_logger("detectors")


class FormatDetector:
    """Base class for a format detector."""

    format_name = None
    aliases = ()
    description = ""
    read_only = False
    priority = 100

    def detect(self, source: ByteSource) -> ImageInfo | None:
        """Detect a format from a byte source.

        Parameters
        ----------
        source : ByteSource
            Byte source to inspect.

        Returns
        -------
        object
            ``ImageInfo`` instance or ``None`` when the detector does not
            match.
        """
        raise NotImplementedError

    def build_info(
        self,
        source: ByteSource,
        confidence: float = 1.0,
        details: Mapping[str, Any] | None = None,
        format_name: str | None = None,
        file_size: Any = None,
        disk_size: Any = None,
        virtual_size: Any = None,
        cluster_size: Any = None,
    ) -> ImageInfo:
        """Build a normalised detection result.

        Parameters
        ----------
        source : ByteSource
            Byte source being inspected.
        confidence : float, optional
            Confidence score for the match.
        details : dict, optional
            Additional structured metadata.
        format_name : str, optional
            Explicit format name override.
        file_size : object, optional
            Logical source length in bytes.
        disk_size : object, optional
            Host disk allocation in bytes.
        virtual_size : object, optional
            Guest-visible image size in bytes.
        cluster_size : object, optional
            Image cluster size in bytes.

        Returns
        -------
        ImageInfo
            Detection result.
        """
        if file_size is None:
            file_size = source.get_size()
        if disk_size is None:
            disk_size = source.get_disk_size()
        return ImageInfo(
            format_name or self.format_name,
            self.description,
            confidence=confidence,
            read_only=self.read_only,
            detector=self.__class__.__name__,
            source_name=source.name,
            details=details,
            aliases=self.aliases,
            file_size=file_size,
            disk_size=disk_size,
            virtual_size=virtual_size,
            cluster_size=cluster_size,
        )

    def metadata(self) -> DetectorMetadata:
        """Return static detector metadata.

        Returns
        -------
        dict
            Format description payload.
        """
        return {
            "aliases": list(self.aliases),
            "description": self.description,
            "format": self.format_name,
            "read_only": self.read_only,
        }


class DetectorRegistry:
    """Ordered collection of format detectors."""

    def __init__(self, detectors: Iterable[FormatDetector] | None = None) -> None:
        """Initialise the registry.

        Parameters
        ----------
        detectors : iterable, optional
            Initial detector sequence.
        """
        self._detectors = []
        for detector in detectors or []:
            self.register(detector)

    def register(self, detector: FormatDetector) -> FormatDetector:
        """Register a detector and keep the registry sorted by priority.

        Parameters
        ----------
        detector : FormatDetector
            Detector instance to add.

        Returns
        -------
        FormatDetector
            Registered detector.
        """
        self._detectors.append(detector)
        self._detectors.sort(key=lambda item: item.priority)
        return detector

    def detect(self, source: ByteSource) -> ImageInfo:
        """Detect the format of a source with the registered detectors.

        Parameters
        ----------
        source : ByteSource
            Byte source to inspect.

        Returns
        -------
        ImageInfo
            First matching detection result.

        Raises
        ------
        RuntimeError
            If the registry does not include a fallback detector.
        """
        range_error = None
        for detector in self._detectors:
            if range_error is not None and detector.format_name == "raw":
                raise range_error
            LOG.debug("trying detector=%s source=%s", detector.__class__.__name__, source.name)
            try:
                info = detector.detect(source)
            except RangeNotSupportedError as exc:
                range_error = exc
                continue
            if info is not None:
                LOG.debug(
                    "detector=%s matched format=%s source=%s", detector.__class__.__name__, info.format, source.name
                )
                return info
        if range_error is not None:
            raise range_error
        raise RuntimeError("registry does not include a fallback raw detector")

    def describe_formats(self) -> list[DetectorMetadata]:
        """Describe the registered formats.

        Returns
        -------
        list
            List of detector metadata dictionaries.
        """
        return [detector.metadata() for detector in self._detectors if detector.format_name]
