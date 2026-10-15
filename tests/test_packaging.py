# Copyright (c) 2026 IsArvin.
# This file is part of VDiskProbe. Please refer to the LICENCE file for licence information.

"""Build and exercise distributable artefacts outside the checkout."""

from email.parser import BytesParser
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tomllib
import zipfile

import pytest

pytestmark = pytest.mark.packaging
ROOT = Path(__file__).resolve().parents[1]
PROJECT_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def run(command, cwd, env=None):
    """Run an artefact operation with useful failure output."""
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def create_environment(directory):
    """Create an isolated interpreter for an installation check."""
    environment = directory / "environment"
    run([sys.executable, "-m", "venv", str(environment)], directory)
    bindir = environment / ("Scripts" if os.name == "nt" else "bin")
    python = bindir / ("python.exe" if os.name == "nt" else "python")
    return environment, bindir, python


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory):
    directory = tmp_path_factory.mktemp("artifacts")
    run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(directory)], ROOT)
    return {"wheel": next(directory.glob("*.whl")), "sdist": next(directory.glob("*.tar.gz"))}


def test_artifact_contents_and_metadata(artifacts):
    with zipfile.ZipFile(artifacts["wheel"]) as wheel:
        names = wheel.namelist()
        metadata = BytesParser().parsebytes(wheel.read(next(n for n in names if n.endswith(".dist-info/METADATA"))))
        assert metadata["Name"] == "vdiskprobe"
        assert metadata["Version"] == PROJECT_VERSION
        assert metadata["Requires-Python"] == ">=3.11"
        assert all("extra ==" in value for value in metadata.get_all("Requires-Dist", []))
        assert metadata["Provides-Extra"] == "dev"
        entries = wheel.read(next(n for n in names if n.endswith("/entry_points.txt"))).decode()
        assert "vdiskprobe = vdiskprobe.cli:main" in entries
        for doc in ("README.md", "CHANGELOG.md", "LICENCE"):
            assert any(n.endswith("/" + doc) for n in names), doc
        assert "vdiskprobe/cli.py" in names
        assert not any(n.startswith("tests/") for n in names)
    with tarfile.open(artifacts["sdist"]) as archive:
        names += archive.getnames()
        for doc in ("README.md", "CHANGELOG.md", "LICENCE", "pyproject.toml"):
            assert any(n.endswith("/" + doc) for n in archive.getnames()), doc
    assert not any(
        part in n.split("/")
        for n in names
        for part in (".idea", ".superpowers", "superpowers", "venv", ".venv", ".git")
    )


@pytest.mark.parametrize("kind", ["wheel", "sdist"])
def test_clean_artifact_install(artifacts, tmp_path, kind):
    environment, bindir, python = create_environment(tmp_path)
    executable = bindir / ("vdiskprobe.exe" if os.name == "nt" else "vdiskprobe")
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    run(
        [str(python), "-m", "pip", "install", "--disable-pip-version-check", "--no-deps", str(artifacts[kind])],
        tmp_path,
        env,
    )
    module_path = run([str(python), "-c", "import vdiskprobe; print(vdiskprobe.__file__)"], tmp_path, env).strip()
    assert Path(module_path).is_relative_to(environment)
    payload = tmp_path / "磁盘.qcow2"
    payload.write_bytes(b"QFI\xfb" + struct.pack(">I", 3))
    for command in ([str(executable)], [str(python), "-m", "vdiskprobe"]):
        assert run(command + ["--version"], tmp_path, env).strip() == f"vdiskprobe {PROJECT_VERSION}"
        result = json.loads(run(command + [str(payload), "--json"], tmp_path, env))
        assert result["format"] == "qcow2"
        assert result["file_size"] == 8
        assert result["virtual_size"] is None
        assert result["source_name"] == str(payload)


def test_toml_version_bump_reaches_installed_package_and_cli(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for name in ("README.md", "CHANGELOG.md", "LICENCE"):
        shutil.copy2(ROOT / name, project / name)
    shutil.copytree(ROOT / "vdiskprobe", project / "vdiskprobe", ignore=shutil.ignore_patterns("__pycache__"))
    config = (ROOT / "pyproject.toml").read_text()
    config = config.replace(f'version = "{PROJECT_VERSION}"', 'version = "9.8.7.dev6"')
    (project / "pyproject.toml").write_text(config)
    run([sys.executable, "-m", "build", "--wheel", "--no-isolation"], project)
    environment, bindir, python = create_environment(tmp_path)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    wheel = next((project / "dist").glob("*.whl"))
    run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], tmp_path, env)
    code = (
        "import json, vdiskprobe; from importlib.metadata import version; "
        "print(json.dumps([vdiskprobe.__version__, version('vdiskprobe')]))"
    )
    assert json.loads(run([str(python), "-c", code], tmp_path, env)) == ["9.8.7.dev6", "9.8.7.dev6"]
    assert run([str(python), "-m", "vdiskprobe", "--version"], tmp_path, env).strip() == "vdiskprobe 9.8.7.dev6"
