# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Command-line interface for VDiskProbe."""

import argparse
from decimal import Decimal
import json
import logging
import os
import sys
from typing import TextIO

from vdiskprobe.info import ImageInfo
from vdiskprobe.api import detect_path, get_default_registry
from vdiskprobe.errors import VDiskProbeError
from vdiskprobe.log import configure_logging
from vdiskprobe.version import __version__

SIZE_UNITS = ("bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns
    -------
    argparse.ArgumentParser
        Configured parser instance.
    """
    parser = argparse.ArgumentParser(
        prog="vdiskprobe", description="Detect VM image formats using VDiskProbe.", add_help=False
    )
    parser.add_argument("-h", "--help", action="help", help="Show this message and exit.")
    parser.add_argument("path", nargs="?", help="Path or HTTP/HTTPS URL to the VM image.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument("--list-formats", action="store_true", help="List built-in formats and exit.")
    parser.add_argument(
        "-V", "--version", action="version", version="%(prog)s {0}".format(__version__), help="Print version and exit."
    )
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Increase log verbosity. Repeat for debug logs."
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Only log errors.")
    return parser


def resolve_log_level(args: argparse.Namespace) -> int:
    """Resolve the effective CLI log level.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    int
        Logging level constant.
    """
    if args.quiet:
        return logging.ERROR
    if args.verbose >= 2:
        return logging.DEBUG
    if args.verbose == 1:
        return logging.INFO
    return logging.WARNING


def format_size(value: int) -> str:
    """Format a byte count with an IEC unit and the exact byte value."""
    size = int(value)
    abs_size = abs(size)
    unit_index = 0
    try:
        scaled = float(abs_size)
    except OverflowError:
        scaled = Decimal(abs_size)
    while unit_index + 1 < len(SIZE_UNITS) and scaled >= 1024.0:
        scaled /= 1024
        unit_index += 1
    if unit_index == 0:
        readable = "{0} bytes".format(size)
    else:
        if scaled >= 100 or scaled == int(scaled):
            number = format(scaled, ".0f")
        elif scaled >= 10:
            number = format(scaled, ".1f")
        else:
            number = format(scaled, ".2f")
        if "." in number:
            number = number.rstrip("0").rstrip(".")
        if size < 0:
            number = "-{0}".format(number)
        readable = "{0} {1}".format(number, SIZE_UNITS[unit_index])
    return "{0} ({1} bytes)".format(readable, size)


def print_formats(stream: TextIO) -> None:
    """Write the built-in detector list to a stream.

    Parameters
    ----------
    stream : object
        Text output stream.
    """
    write = getattr(stream, "write")
    registry = get_default_registry()
    for metadata in registry.describe_formats():
        aliases = metadata.get("aliases") or []
        alias_suffix = ""
        if aliases:
            alias_suffix = " (aliases: {0})".format(", ".join(aliases))
        mode = "read-only" if metadata.get("read_only") else "read-write"
        line = "{0}: {1} [{2}]{3}".format(metadata["format"], metadata["description"], mode, alias_suffix)
        write(line)
        write(os.linesep)


def print_human(info: ImageInfo, stream: TextIO) -> None:
    """Write a human-readable detection report.

    Parameters
    ----------
    info : ImageInfo
        Detected image information record.
    stream : object
        Text output stream.
    """
    write = getattr(stream, "write")
    lines = [
        "path: {0}".format(info.source_name or "<unknown>"),
        "format: {0}".format(info.format),
        "description: {0}".format(info.description),
    ]
    if info.virtual_size is not None:
        lines.append("virtual_size: {0}".format(format_size(info.virtual_size)))
    if info.file_size is not None:
        lines.append("file_size: {0}".format(format_size(info.file_size)))
    if info.disk_size is not None:
        lines.append("disk_size: {0}".format(format_size(info.disk_size)))
    if info.cluster_size is not None:
        lines.append("cluster_size: {0}".format(format_size(info.cluster_size)))
    lines.extend(
        [
            "read_only: {0}".format("yes" if info.read_only else "no"),
            "confidence: {0:.2f}".format(info.confidence),
            "detector: {0}".format(info.detector),
        ]
    )
    if info.aliases:
        lines.append("aliases: {0}".format(", ".join(info.aliases)))
    if info.details:
        for key in sorted(info.details):
            lines.append("{0}: {1}".format(key, info.details[key]))
    write(os.linesep.join(lines))
    write(os.linesep)


def main(argv: list[str] | None = None) -> int:
    """Run the VDiskProbe CLI.

    Parameters
    ----------
    argv : list, optional
        Command-line argument list. ``None`` means to use ``sys.argv``.

    Returns
    -------
    int
        Process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(resolve_log_level(args))
    if args.list_formats:
        print_formats(sys.stdout)
        return 0
    if not args.path:
        parser.error("the following arguments are required: path")
    try:
        info = detect_path(args.path)
    except OSError as exc:
        sys.stderr.write("vdiskprobe: unable to read {0}: {1}{2}".format(args.path, exc, os.linesep))
        return 1
    except VDiskProbeError as exc:
        sys.stderr.write("vdiskprobe: {0}{1}".format(exc, os.linesep))
        return 1
    if args.json:
        payload = json.dumps(info.to_dict(), sort_keys=True, indent=2)
        sys.stdout.write(payload)
        sys.stdout.write(os.linesep)
    else:
        print_human(info, sys.stdout)
    return 0
