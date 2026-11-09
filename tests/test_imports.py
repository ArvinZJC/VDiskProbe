# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Exercise import boundaries in interpreters without preloaded dependencies."""

import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest


def run_python(code, *args):
    """Run a fresh interpreter with the normal import policy."""
    env = os.environ.copy()
    env.pop("PYTHON_LAZY_IMPORTS", None)
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code), *map(str, args)],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def test_public_exports_and_registry_first_use():
    run_python("""
        import sys
        import vdiskprobe

        lazy = sys.version_info >= (3, 15)
        assert ('vdiskprobe.detectors.formats' in sys.modules) is not lazy
        for name in vdiskprobe.__all__:
            assert getattr(vdiskprobe, name) is not None, name
        assert isinstance(vdiskprobe.__version__, str)
        assert ('vdiskprobe.detectors.formats' in sys.modules) is not lazy
        registry = vdiskprobe.build_default_registry()
        assert 'vdiskprobe.detectors.formats' in sys.modules
        assert [item['format'] for item in registry.describe_formats()] == [
            'qcow', 'qcow2', 'qed', 'vmdk', 'vdi', 'vpc', 'vhdx',
            'luks', 'bochs', 'parallels', 'cloop', 'dmg', 'raw',
        ]
        assert registry is not vdiskprobe.build_default_registry()
    """)


def test_local_detection_does_not_load_transport(tmp_path):
    path = tmp_path / "disk.qcow2"
    path.write_bytes(b"QFI\xfb\x00\x00\x00\x03")
    run_python(
        """
        import sys
        from io import BytesIO
        from pathlib import Path
        from vdiskprobe import detect, detect_path
        from vdiskprobe.http_source import is_http_url

        assert is_http_url('https://example.com/disk')
        assert not is_http_url('disk.qcow2')
        assert detect(BytesIO(b'QFI\\xfb\\x00\\x00\\x00\\x03')).format == 'qcow2'
        assert detect_path(Path(sys.argv[1])).format == 'qcow2'
        lazy = sys.version_info >= (3, 15)
        for name in ('http.client', 'urllib.request', 'ssl'):
            assert (name in sys.modules) is not lazy, name
    """,
        path,
    )


def test_transport_first_use_and_annotations():
    run_python("""
        import sys
        from vdiskprobe.http_source import HttpRangeReader

        lazy = sys.version_info >= (3, 15)
        assert ('urllib.request' in sys.modules) is not lazy
        reader = HttpRangeReader('https://example.com/disk')
        for name in ('urllib.request', 'http.client', 'ssl'):
            assert name in sys.modules, name
        request = reader._build_request('GET', {'Range': 'bytes=0-7'})
        assert request.full_url == 'https://example.com/disk'
        assert request.get_header('Range') == 'bytes=0-7'
        import typing
        from urllib.request import Request
        assert typing.get_type_hints(HttpRangeReader._build_request)['return'] is Request
    """)


@pytest.mark.parametrize("argument", ["--help", "--version", "--list-formats"])
def test_cli_import_boundaries(argument):
    output = run_python(
        """
        import sys
        from vdiskprobe.cli import main

        try:
            assert main([sys.argv[1]]) == 0
        except SystemExit as exc:
            assert exc.code == 0
        if sys.version_info >= (3, 15):
            assert 'ssl' not in sys.modules
            assert 'urllib.request' not in sys.modules
            assert ('vdiskprobe.detectors.formats' in sys.modules) == (sys.argv[1] == '--list-formats')
    """,
        argument,
    )
    assert {"--help": "usage:", "--version": "vdiskprobe ", "--list-formats": "qcow2:"}[argument] in output
