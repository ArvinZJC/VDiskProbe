# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""CLI flags, output, diagnostics and subprocess entry points."""

import io
import json
import logging
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from vdiskprobe.version import __version__

from vdiskprobe import cli
from vdiskprobe.errors import InvalidSourceError
from vdiskprobe.info import ImageInfo


@pytest.fixture(autouse=True)
def isolate_logger():
    logger = logging.getLogger("vdiskprobe")
    state = logger.handlers[:], logger.level, logger.propagate
    logger.handlers.clear()
    yield
    logger.handlers[:], logger.level, logger.propagate = state


@pytest.mark.parametrize(
    "args, level",
    [([], logging.WARNING), (["-v"], logging.INFO), (["-vv"], logging.DEBUG), (["-vvv", "-q"], logging.ERROR)],
)
def test_log_levels(args, level):
    assert cli.resolve_log_level(cli.build_parser().parse_args(args)) == level


@pytest.mark.parametrize(
    "args, code", [([], 2), (["-v"], 2), (["-h"], 0), (["--help"], 0), (["-V"], 0), (["--version"], 0)]
)
def test_parser_exits(args, code, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == code
    output = capsys.readouterr()
    if code == 0:
        assert "vdiskprobe" in output.out
    else:
        assert output.err and not output.out


def test_json_output(tmp_path, capsys):
    path = tmp_path / "disk.qcow2"
    path.write_bytes(b"QFI\xfb" + struct.pack(">I", 3))
    assert cli.main([str(path), "--json"]) == 0
    out, err = capsys.readouterr()
    payload = json.loads(out)
    assert payload["format"] == "qcow2"
    assert payload["file_size"] == 8
    assert payload["virtual_size"] is None
    assert payload["source_name"] == str(path)
    assert out == json.dumps(payload, sort_keys=True, indent=2) + os.linesep
    assert err == ""


def test_list_formats_precedes_json(capsys):
    assert cli.main(["--list-formats", "--json"]) == 0
    out, err = capsys.readouterr()
    assert len(out.splitlines()) == 13
    assert out.startswith("qcow:")
    assert "(aliases: vhd)" in out
    assert "raw:" in out
    assert not err


def test_human_output_and_optional_fields():
    info = ImageInfo(
        "custom", "description", 0.95, True, "Custom", "disk", {"z": 2, "a": 1}, ["alias"], 1024, 512, 2**40, 4096
    )
    stream = io.StringIO()
    cli.print_human(info, stream)
    text = stream.getvalue()
    assert "file_size: 1 KiB (1024 bytes)" in text
    assert "virtual_size: 1 TiB (1099511627776 bytes)" in text
    assert "confidence: 0.95" in text
    assert "read_only: yes" in text
    assert "aliases: alias" in text
    assert text.index("a: 1") < text.index("z: 2")
    stream = io.StringIO()
    cli.print_human(ImageInfo("raw", "raw"), stream)
    assert "file_size:" not in stream.getvalue()
    assert "path: <unknown>" in stream.getvalue()


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, "0 bytes (0 bytes)"),
        (1536, "1.5 KiB (1536 bytes)"),
        (-1536, "-1.5 KiB (-1536 bytes)"),
        (12345, "12.1 KiB (12345 bytes)"),
        (102400, "100 KiB (102400 bytes)"),
    ],
)
def test_size_formatting(value, expected):
    assert cli.format_size(value) == expected


@pytest.mark.parametrize("error", [OSError("missing"), InvalidSourceError("invalid")])
def test_errors_stay_on_stderr(monkeypatch, error, capsys):
    def fail(_path):
        raise error

    # Patch the imported function where the CLI looks it up.
    # noinspection PyUnresolvedReferences
    monkeypatch.setattr(cli, "detect_path", fail)
    assert cli.main(["disk"]) == 1
    out, err = capsys.readouterr()
    assert not out
    assert "vdiskprobe:" in err
    assert str(error) in err


def test_unexpected_programming_errors_propagate(monkeypatch):
    def fail(_path):
        raise RuntimeError("bug")

    # Patch the imported function where the CLI looks it up.
    # noinspection PyUnresolvedReferences
    monkeypatch.setattr(cli, "detect_path", fail)
    with pytest.raises(RuntimeError, match="bug"):
        cli.main(["disk"])


def test_subprocess_entry_points(tmp_path):
    path = tmp_path / "disk.qcow2"
    path.write_bytes(b"QFI\xfb" + struct.pack(">I", 3))
    executable = Path(sys.executable).parent / ("vdiskprobe.exe" if os.name == "nt" else "vdiskprobe")
    for command in ([str(executable)], [sys.executable, "-m", "vdiskprobe"]):
        result = subprocess.run(command + ["--version"], capture_output=True, text=True, check=True)
        assert result.stdout.strip() == f"vdiskprobe {__version__}"
        result = subprocess.run(command + [str(path), "--json"], capture_output=True, text=True, check=True)
        assert json.loads(result.stdout)["format"] == "qcow2"
        result = subprocess.run(command + ["--help"], capture_output=True, text=True, check=True)
        assert "--list-formats" in result.stdout


def test_large_descriptor_size_does_not_overflow_human_output(tmp_path, capsys):
    path = tmp_path / "huge.vmdk"
    path.write_bytes(b"# Disk DescriptorFile\nRW " + b"9" * 400 + b" FLAT huge\n")
    assert cli.main([str(path)]) == 0
    out, err = capsys.readouterr()
    assert "format: vmdk" in out
    assert str(int("9" * 400) * 512) + " bytes)" in out
    assert not err


def test_malformed_url_is_a_source_error(capsys):
    # URL syntax only; this literal is never used for a network request.
    # noinspection HttpUrlsUsage
    assert cli.main(["http://[bad"]) == 1
    out, err = capsys.readouterr()
    assert not out
    assert "URL" in err


def test_unescaped_unicode_url_is_a_source_error(monkeypatch, capsys):
    from urllib.request import ProxyHandler, build_opener
    from vdiskprobe import api
    from vdiskprobe.http_source import HttpRangeReader

    monkeypatch.setattr(
        api, "_HTTP_READER_CLASS", lambda url: HttpRangeReader(url, opener=build_opener(ProxyHandler({})))
    )
    # Encoding fails before connecting; port 1 is never contacted.
    assert cli.main(["http://127.0.0.1:1/磁盘.qcow2"]) == 1
    out, err = capsys.readouterr()
    assert not out
    assert "vdiskprobe:" in err
    assert "ascii" in err
