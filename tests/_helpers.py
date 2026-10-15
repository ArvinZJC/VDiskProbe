# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Synthetic readers and binary payload helpers."""


class CountingReader:
    """Expose a stable payload and record random-access requests."""

    def __init__(self, payload):
        self.payload = payload
        self.requests = []
        self.fail_next = False

    def read(self, offset, size):
        self.requests.append((offset, size))
        if self.fail_next:
            self.fail_next = False
            raise OSError("read failed")
        return self.payload[offset : offset + size]

    def size(self):
        return len(self.payload)


class ValueReader:
    """Return an injected value for boundary conversion tests."""

    def __init__(self, value):
        self.value = value

    def read(self, _offset, _size):
        return self.value


def to_bytes(values):
    """Convert synthetic buffers to immutable bytes."""
    return bytes(values)
