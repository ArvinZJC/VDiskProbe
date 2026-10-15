# VDiskProbe

VDiskProbe is a dependency-free Python library and CLI for detecting virtual disk image formats and reading available size metadata. It accepts local paths, binary file objects, custom random-access readers, and HTTP/HTTPS URLs.

VDiskProbe supports standard CPython 3.11–3.15. Detection reads headers and metadata; it does not mount, convert, decrypt, or validate an entire image.

## Architecture

The distribution, import package, and command are named `vdiskprobe`. Public APIs are re-exported from `vdiskprobe/__init__.py` and follow this flow:

```text
reader/path -> ByteSource -> DetectorRegistry -> ImageInfo
```

`ByteSource` adapts readers, `DetectorRegistry` selects a detector, and `ImageInfo` holds its result. Detector classes live in `vdiskprobe/detectors/formats.py`; binary parsing helpers live in `vdiskprobe/detectors/_format_helpers.py`.

## Installation

Install from a source checkout using a supported Python interpreter:

```bash
python -m pip install .
```

A built wheel or source archive can also be installed with `python -m pip install <artefact-path>`.

## Formats and metadata

Built-in formats, in detection order: `qcow`, `qcow2`, `qed`, `vmdk`, `vdi`, `vpc` (alias `vhd`), `vhdx`, `luks`, `bochs`, `parallels`, `cloop`, `dmg`, and `raw`.

Results include the format, description, confidence, detector, aliases, source name, format-specific details, and these optional byte counts:

| Field          | Meaning                                               |
| -------------- | ----------------------------------------------------- |
| `file_size`    | Logical source length.                                |
| `disk_size`    | Host filesystem allocation when available.            |
| `virtual_size` | Guest-visible size derived from image metadata.       |
| `cluster_size` | Allocation unit or block size recorded by the format. |

Unknown values are `None` in Python and `null` in JSON. On systems without filesystem block counts, `disk_size` falls back to logical file size. The content length of a remote image does not indicate how much disk space it occupies on the server.

`raw` is a fallback with confidence `0.1`, meaning no recognised signature matched. It is not proof of a raw image. VMDK descriptor and cloop script heuristics use `0.95`; other recognised signatures use `1.0`. VMDK extent counts beyond the interpreter's configured decimal-conversion limit (or its default limit when disabled) yield an unknown virtual size rather than a partial total. Descriptor capacity is also unknown when the source is known to extend beyond the bytes read, or a descriptor of unknown length fills the 64 KiB inspection window. A shorter read from a source of unknown length requires an end-of-source probe before reporting capacity. Recognition can succeed on a short header without optional metadata and does not prove that the image is complete or uncorrupted. The `read_only` field describes format metadata; VDiskProbe itself only reads.

## Command line

```bash
vdiskprobe disk.qcow2
vdiskprobe disk.qcow2 --json
python -m vdiskprobe disk.qcow2 --json
vdiskprobe --list-formats
vdiskprobe --version
```

A path may also be an HTTP/HTTPS URL. `-v` enables info logging, `-vv` enables debug logging, and `-q` selects errors only and takes precedence over verbosity. Results go to stdout and diagnostics to stderr. Exit statuses are `0` for success, `1` for source errors, and `2` for invalid arguments. `--list-formats` takes precedence over inspection and `--json`.

## Python API

```python
from pathlib import Path
from vdiskprobe import detect, detect_path

info = detect_path(Path("disk.qcow2"))
print(info.format, info.virtual_size)
print(info.to_dict())

with open("disk.qcow2", "rb") as stream:
    info = detect(stream, name="disk.qcow2")
```

`detect` and `inspect_source` accept a reader or an existing `ByteSource`, plus an optional `registry` and `name`. `detect_path` accepts a text path, `PathLike[str]`, or HTTP/HTTPS URL; `detect_url` accepts only HTTP/HTTPS URLs. Use `io.BytesIO(payload)` for in-memory bytes.

Seekable readers retain their cursor. Caller-owned readers remain open; files and HTTP responses opened by the library are closed after use. A reader should expose stable contents during inspection; shared-reader thread safety and concurrent source mutation are not guaranteed.

### Custom readers

Provide `read_at(offset, size)`, `pread(offset, size)`, `read_range(offset, size)`, `seek`/`tell`/`read(size)`, or `read(offset, size)`, in that precedence order. Here `pread` takes the offset first, unlike `os.pread`.

```python
from vdiskprobe import detect

class RangeReader:
    def __init__(self, payload):
        self.payload = payload

    def read(self, offset, size):
        return self.payload[offset:offset + size]

    def size(self):
        return len(self.payload)

info = detect(RangeReader(b"QFI\xfb\x00\x00\x00\x03"))
assert info.format == "qcow2"
```

Optional size sources are `size` or `length` attributes or methods, `len(reader)`, a file descriptor, or seeking to the end of the source. `ByteSource.read` rejects negative offsets and sizes and returns at most the requested bytes. Reads up to 64 KiB can reuse cached prefixes and exact ranges. A short read caches only the bytes returned; it does not establish the end of the source.

Binary readers are preferred. At the adapter boundary, `bytearray` and `memoryview` objects are converted to `bytes`, `None` means an empty read, and text is encoded as Latin-1 without replacing unencodable characters. `tobytes()`/`tostring()` providers and conversion of other objects to text are also supported. Unencodable text raises an encoding error. Backend authentication, application-level retries, and SDK integration remain the caller's responsibility.

### HTTP and HTTPS

```python
from vdiskprobe import detect_url

info = detect_url("https://example.com/disk.qcow2")
print(info.format, info.virtual_size)
```

URL paths must be percent-encoded where necessary. URL encoding failures raise `RemoteSourceError` without retrying.

For explicit timeout and retry settings, construct `HttpRangeReader` from `vdiskprobe.http_source` and pass it to `detect(reader)`.

HTTP requests use bounded byte ranges and identity encoding. Three retries allow at most four attempts for a transient failure, with exponential backoff beginning at 0.25 seconds. Remote size discovery uses a one-byte GET before falling back to HEAD. A supplied byte interval that contradicts the request raises `RemoteSourceError`; absent range metadata and unknown totals retain the size-discovery fallbacks.

A server that ignores ranges can still support a header match at offset zero. A refused range lets detection continue to later signatures; unavailable optional metadata remains unknown. If no signature matches, the refused range raises `RangeNotSupportedError` (a `RemoteSourceError` subclass in `vdiskprobe.errors`) rather than producing a raw result. Other transport failures propagate immediately. VDiskProbe never downloads the full image to simulate random access. Footer-based detection also depends on discovering source length.

TLS certificate and hostname verification stay enabled. Trust-store discovery checks `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and `SSL_CERT_DIR`, then Python/OpenSSL defaults and common system paths. Redirects and proxy settings from the environment follow the standard library’s behaviour.

### Custom detectors, errors, and logging

```python
from io import BytesIO
from vdiskprobe import FormatDetector, build_default_registry, detect

class ExampleDetector(FormatDetector):
    format_name = "example"
    description = "Example image"
    priority = 5

    def detect(self, source):
        if source.read(0, 4) == b"EXMP":
            return self.build_info(source)
        return None

registry = build_default_registry()
registry.register(ExampleDetector())
info = detect(BytesIO(b"EXMP"), registry=registry)
assert info.format == "example"
```

Lower priorities run first; equal priorities retain registration order. The first match wins. Keep raw as the final fallback when creating a registry yourself; if no detector matches, the registry raises `RuntimeError`. Source failures propagate rather than becoming a raw result; refused HTTP ranges follow the bounded detection behaviour described above.

`InvalidSourceError` and `RemoteSourceError` inherit from `VDiskProbeError`. Local I/O failures can raise `OSError`. Logging uses a `NullHandler` until configured; call `configure_logging()` to attach a stream handler. Library logging does not configure the application's root logger.

```python
import logging
from vdiskprobe import configure_logging

configure_logging(logging.DEBUG)
```

For applications that already configure ancestor handlers, use `configure_logging(logging.DEBUG, propagate=True)`. Enabling propagation removes the package stream handler and null handlers, whilst preserving application handlers. Repeated stream configuration reuses an existing package stream handler; it does not replace its stream. `get_logger(name)` is intended for package modules. Applications using the library should use their own `logging.getLogger(__name__)`.

## Development

Run commands from the repository root with a supported Python interpreter. Create and activate an isolated environment, then install the development tools:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Use the activation command appropriate for your shell. Development tools belong in the `dev` extra in `pyproject.toml`.

### Required checks

After every Python change, all four checks must pass: Black, fewer than 1000 lines per Python file, the complete test suite with 100% source statement and branch coverage, and Git whitespace validation. A failed or unavailable check means verification is incomplete.

Black reads its settings from `pyproject.toml`. Format the Python files, then check them:

```bash
python -m black vdiskprobe tests
python -m black --check vdiskprobe tests
```

Check every tracked or unignored Python file, including tests and scripts. This prints files with 1000 or more lines and exits with a non-zero status if any exist:

```bash
python - <<'PYTHON'
from pathlib import Path
import subprocess

paths = subprocess.check_output([
    "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.py"
]).decode().split("\0")
failures = []
for name in sorted(set(paths)):
    if name and Path(name).is_file():
        count = len(Path(name).read_text(encoding="utf-8").splitlines())
        if count >= 1000:
            failures.append(f"{name}: {count} lines")
print("\n".join(failures), end="\n" if failures else "")
raise SystemExit(bool(failures))
PYTHON
```

The default pytest command enforces the coverage gate from `pyproject.toml`, measuring only `vdiskprobe`. Tests use synthetic disk headers, injected readers, and a loopback HTTP server. Keep assertions meaningful; coverage alone does not prove correctness.

```bash
python -m pytest
git diff --check
```

For a focused test run without the whole-package coverage gate:

```bash
python -m pytest --no-cov tests/test_detection.py
python -m pytest --no-cov tests/test_detection.py -k qcow2
```

Focused runs do not replace the required full-suite check. When coverage fails, inspect the missing paths in HTML or export XML for tooling:

```bash
python -m coverage html
python -m coverage xml
```

Open `htmlcov/index.html` for the HTML report. Both report commands retain the configured 100% threshold and can exit with a non-zero status while still writing their reports.

### Builds and compatibility

Build a wheel and source distribution, then run the explicit packaging checks:

```bash
python -m build
python -m pytest -m packaging -o addopts='' tests/test_packaging.py
```

Packaging tests are excluded from the default suite. They inspect distribution contents and metadata, install both artefacts in separate clean environments, and exercise imports and both CLI entry points outside the checkout. pip must be able to obtain the build dependencies, either from a package index or a local wheel cache.

Repeat the full suite and packaging checks on each supported Python minor when changing compatibility or packaging. Support tracks stable Python releases that have not reached end of life; check the Python release lifecycle when updating the supported range. Keep syntax and dependencies compatible with the minimum version listed above. Other implementations and free-threaded builds need separate validation.

### Versioning

Versions must follow PEP 440, for example `0.1.0`, `1.0.0a1`, or `1.0.0.dev1`. The single source of truth is `[project].version` in `pyproject.toml`. `vdiskprobe/version.py` reads the installed distribution metadata using `importlib.metadata`, and the package re-exports that value as `__version__`. Install the package before importing it; an editable development install is sufficient. After changing the version, rerun `python -m pip install -e '.[dev]'` to refresh editable-install metadata, or rebuild and reinstall the distribution.
