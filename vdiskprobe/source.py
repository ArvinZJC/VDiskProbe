# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Byte source adapter abstractions."""

import os
from collections.abc import Callable
from typing import Any
from vdiskprobe.errors import InvalidSourceError


class ByteSource:
    """Adapt file-like objects and random-access readers to a common interface.

    Parameters
    ----------
    reader : object
        Underlying reader object.
    name : str, optional
        Friendly source name.
    """

    RANDOM_ACCESS_METHODS = ("read_at", "pread", "read_range")
    CACHEABLE_READ_LIMIT = 64 * 1024

    def __init__(self, reader: Any, name: str | None = None) -> None:
        """Initialise the byte source adapter.

        Parameters
        ----------
        reader : object
            Underlying reader object.
        name : str, optional
            Friendly source name.

        Raises
        ------
        InvalidSourceError
            If the reader does not implement any supported access pattern.
        """
        if reader is None:
            raise InvalidSourceError("reader cannot be None")
        if not hasattr(reader, "read"):
            for method_name in self.RANDOM_ACCESS_METHODS:
                if hasattr(reader, method_name):
                    break
            else:
                raise InvalidSourceError("reader must provide read(), seek()+read(), or a random-access method")
        self._reader = reader
        self._cache = {}
        self._prefix_data = b""
        self._prefix_size = 0
        self._size = None
        self._size_known = False
        self._disk_size = None
        self._disk_size_known = False
        self.name = name or getattr(reader, "name", None)

    def __repr__(self) -> str:
        """Return a debugging representation.

        Returns
        -------
        str
            Debugging representation.
        """
        return "ByteSource(name={0!r})".format(self.name)

    def read(self, offset: int, size: int) -> bytes:
        """Read bytes from the source without changing the caller-visible cursor.

        Parameters
        ----------
        offset : int
            Byte offset to start reading from.
        size : int
            Number of bytes to read.

        Returns
        -------
        bytes
            Byte string containing up to ``size`` bytes.

        Raises
        ------
        ValueError
            If ``offset`` or ``size`` is negative.
        """
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if size < 0:
            raise ValueError("size must be >= 0")
        if size == 0:
            return b""
        cacheable = size <= self.CACHEABLE_READ_LIMIT
        cache_key = (offset, size)
        if cacheable:
            if offset + size <= self._prefix_size:
                return self._prefix_data[offset : offset + size]
            if cache_key in self._cache:
                return self._cache[cache_key]
        data = self._read_uncached(offset, size)
        data = _coerce_bytes(data)
        if len(data) > size:
            data = data[:size]
        if cacheable:
            self._cache[cache_key] = data
            if offset == 0 and len(data) > self._prefix_size:
                self._prefix_data = data
                self._prefix_size = len(data)
        return data

    def get_size(self) -> int | None:
        """Return the total source size when discoverable.

        Returns
        -------
        object
            ``int`` byte size or ``None`` when unknown.
        """
        if not self._size_known:
            self._size = self._discover_size()
            self._size_known = True
        return self._size

    def get_disk_size(self) -> int | None:
        """Return the host disk allocation when discoverable.

        Returns
        -------
        object
            ``int`` byte size or ``None`` when discovery is not possible.
        """
        if not self._disk_size_known:
            self._disk_size = self._discover_disk_size()
            self._disk_size_known = True
        return self._disk_size

    def _read_uncached(self, offset: int, size: int) -> Any:
        """Read bytes directly from the underlying reader.

        Parameters
        ----------
        offset : int
            Byte offset to start reading from.
        size : int
            Number of bytes to read.

        Returns
        -------
        object
            Raw byte payload returned by the wrapped reader.

        Raises
        ------
        InvalidSourceError
            If the wrapped object does not support any recognised access
            pattern.
        """
        for method_name in self.RANDOM_ACCESS_METHODS:
            method: Callable[..., Any] | None = getattr(self._reader, method_name, None)
            if method is None:
                continue
            # Missing methods are skipped above; this is the reader protocol call.
            # noinspection PyCallingNonCallable
            return method(offset, size)
        if hasattr(self._reader, "seek") and hasattr(self._reader, "tell"):
            position = self._reader.tell()
            try:
                self._reader.seek(offset, os.SEEK_SET)
                return self._reader.read(size)
            finally:
                self._reader.seek(position, os.SEEK_SET)
        if hasattr(self._reader, "read"):
            try:
                return self._reader.read(offset, size)
            except TypeError:
                pass
        raise InvalidSourceError(
            "reader must support seek()+read(), read(offset, size), read_at(), pread(), or read_range()"
        )

    def _discover_size(self) -> int | None:
        """Discover the total source size.

        Returns
        -------
        object
            ``int`` byte size or ``None`` when discovery is not possible.
        """
        candidates = ("size", "length")
        for name in candidates:
            candidate = getattr(self._reader, name, None)
            if candidate is None:
                continue
            try:
                # callable() guards the invocation of a dynamic size provider.
                # noinspection PyCallingNonCallable
                value = candidate() if callable(candidate) else candidate
            except TypeError:
                continue
            if value is not None:
                return int(str(value))
        try:
            return int(len(self._reader))
        except (AttributeError, TypeError):
            pass
        fileno: Callable[[], int] | None = getattr(self._reader, "fileno", None)
        if fileno is not None:
            try:
                # fileno is guarded against None above; discovery failures are handled below.
                # noinspection PyCallingNonCallable
                return int(os.fstat(fileno()).st_size)
            except (IOError, OSError, TypeError, ValueError):
                pass
        if hasattr(self._reader, "seek") and hasattr(self._reader, "tell"):
            position = None
            try:
                position = self._reader.tell()
                self._reader.seek(0, os.SEEK_END)
                return int(self._reader.tell())
            except (IOError, OSError, TypeError, ValueError):
                return None
            finally:
                if position is not None:
                    try:
                        self._reader.seek(position, os.SEEK_SET)
                    except (IOError, OSError, TypeError, ValueError):
                        pass
        return None

    def _discover_disk_size(self) -> int | None:
        """Discover the host disk allocation.

        Returns
        -------
        object
            ``int`` allocated byte size, or ``None`` when allocation cannot
            be inspected.
        """
        fileno: Callable[[], int] | None = getattr(self._reader, "fileno", None)
        if fileno is not None:
            try:
                # fileno is guarded against None above; discovery failures are handled below.
                # noinspection PyCallingNonCallable
                stat_result = os.fstat(fileno())
                blocks = getattr(stat_result, "st_blocks", None)
                if blocks is not None:
                    return int(str(blocks)) * 512
                return int(stat_result.st_size)
            except (IOError, OSError, TypeError, ValueError):
                pass
        return None


def _coerce_bytes(data: Any) -> bytes:
    """Normalise reader results to bytes at the input boundary.

    Parameters
    ----------
    data : object
        Byte container, text with a Latin-1 byte mapping, or a provider.

    Returns
    -------
    bytes
        Normalised payload; ``None`` denotes an empty read.
    """
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("latin-1")
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    for name in ("tobytes", "tostring"):
        method: Callable[..., Any] | None = getattr(data, name, None)
        if method is not None:
            # The None case is excluded; invoke the optional byte-conversion protocol.
            # noinspection PyCallingNonCallable
            result = method()
            return result.encode("latin-1") if isinstance(result, str) else bytes(result)
    return str(data).encode("latin-1")
