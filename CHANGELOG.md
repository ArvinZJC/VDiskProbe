# Changelog

## 1.0.0 — 2026-10-16

- Introduce a dependency-free Python library and CLI for CPython 3.11–3.15, distributed as a wheel and source archive.
- Detect 13 virtual disk image formats from local paths, binary streams, custom random-access readers, and HTTP/HTTPS URLs: qcow, qcow2, qed, vmdk, vdi, vpc (vhd), vhdx, luks, bochs, parallels, cloop, dmg, and raw as a low-confidence fallback.
- Report available logical, allocated, virtual, and cluster sizes, format-specific metadata, and detection confidence through the Python API and text or JSON CLI output. Leave unavailable or incomplete metadata unknown.
- Provide an extensible detector registry and cached, bounded byte reads. Preserve caller-owned streams and seek positions, including when readers return short data.
- Support bounded HTTP range requests, transient-failure retries, and verified HTTPS connections. Continue header recognition when ranges are refused, reject contradictory range metadata, and report source failures without guessing a raw format or downloading an entire image.
- Handle truncated headers, oversized decimal metadata, and incomplete VMDK descriptors without reporting partial capacities. Support legacy VDI layouts and VHD dynamic-header offsets while retaining format recognition when optional metadata is unavailable.
- Expose both `vdiskprobe` and `python -m vdiskprobe`, with format listing, version reporting, logging controls, and defined exit statuses. Read the runtime version from installed package metadata.
- Provide opt-in logging configuration without configuring application logging, and avoid duplicate package messages when propagation is enabled.
