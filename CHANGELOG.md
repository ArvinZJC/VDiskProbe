# Changelog

## Unreleased

- Keep VMDK extent fields on one line, preventing false capacities and repeated scanning of blank lines.

- Reject HTTP 416 responses that contradict the advertised source length instead of returning an unverified raw result.

- Preserve later bytes after short reads and avoid reporting partial VMDK descriptor capacities.
- Continue header detection when HTTP ranges are refused, leaving unavailable optional metadata unknown without masking transport failures or guessing raw.
- Remove the package stream handler when enabling logging propagation to avoid duplicate messages.

- Report URL encoding failures as source errors without retrying; preserve percent-encoded URLs.
- Keep VMDK descriptor capacity unknown when the bounded read does not contain the complete descriptor.
- Follow VHD dynamic-header offsets and ignore unavailable VHD/VHDX metadata probes without losing format recognition.
- Report malformed URLs as source errors instead of exposing URL-parser tracebacks.
- Read the runtime version from installed package metadata, with the release version defined in `pyproject.toml`; importing requires an installed package.
- Read legacy VDI 0.2 sizes from their version-specific offsets and leave sizes unknown for unsupported layouts.
- Report VDI major/minor versions in the correct order and preserve the differencing VHD subformat when a dynamic header is present.
- Return unknown VMDK size when the sum of individually valid extent counts exceeds decimal conversion limits.
- Reject supplied HTTP partial-response intervals that contradict the requested byte range or total length.
- Add a Python library and CLI for inspecting 13 virtual disk image formats from local files, binary streams, custom random-access readers, and HTTP/HTTPS URLs.
- Report available logical, allocated, virtual, and cluster sizes with format-specific metadata and JSON output.
- Provide an extensible detector registry, cached byte reads, bounded HTTP retries, and verified HTTPS connections.
- Package with pip and `pyproject.toml`, targeting CPython 3.11–3.15 without runtime dependencies.
- Limit VHDX metadata payload reads to the fields needed for size extraction, including when item lengths are oversized.
- Keep HTTP object size unknown until a total length is available; do not treat partial-response length as image length.
- Preserve VMDK recognition with unknown size for oversized decimal metadata, and format large representable sizes without float overflow.
- Install the default package logging handler at import without configuring application logging.
