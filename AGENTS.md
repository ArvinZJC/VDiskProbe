# Agent Instructions

## Read first

- Read [README.md](README.md) for the product scope, architecture, public contracts, supported runtimes, and development workflow. Preserve those contracts when changing implementation details.
- Follow the README guidance on [required checks](README.md#required-checks), [builds and compatibility](README.md#builds-and-compatibility), and [versioning](README.md#versioning). Keep it consistent with `pyproject.toml`.
- Keep each topic in one place: README covers usage and development; this file sets out agent working rules and editing conventions. Link to existing guidance instead of repeating it.

## Coding conventions

- Write documentation, docstrings, and comments in clear, natural English. Preserve API names, external identifiers, and quoted text.
- Use `bytes` for binary data and `str` for text; encode and decode explicitly at defined boundaries.
- Use modern type annotations supported by the minimum Python version and numpydoc-style docstrings for public APIs.
- Prefer explicit imports. Combine imports from the same module when readable; use aliases only to clarify ambiguous names. Do not use wildcard imports.
- Prioritise correctness, then measured performance, before cosmetic refactoring.
- Avoid unnecessary duplication and excessive branching, particularly in byte parsing and detector dispatch.

## Working rules

- Keep module boundaries stable and reuse parsing helpers and `FormatDetector.build_info(...)`. Add recognition, metadata, short-read, failure-path, and precedence tests when extending detection.
- Use local fixtures for transport tests. Add meaningful assertions for missing behaviour; do not lower quality thresholds, omit runtime modules, or add coverage exclusions merely to pass checks.
- Treat demonstrated regressions in byte reads, detector dispatch, and parsing hot paths as release blockers. Substantiate performance claims with measurements.
- After Python changes, run every required check linked above before handing over the work. For documentation-only changes, check whitespace and links; also validate affected examples or developer commands. A failed or unavailable check blocks a completion claim: report the failure and remaining work explicitly.
- Keep public files, examples, fixtures, package metadata, and Git messages free of internal project names, paths, URLs, and operational data. Store any private cross-repository mapping outside this repository.
- Keep working specifications in `docs/superpowers/specs/` and implementation plans in `docs/superpowers/plans/`. These directories are ignored; never commit or force-add their contents.

## Changelog policy

- Collect user-visible and runtime-facing changes under an undated `## Unreleased` heading in `CHANGELOG.md`.
- Exclude internal-only test, coverage, formatting, ignore-file, and agent-workflow changes unless they materially affect users.
- Keep entries newest-first. At release time, replace `Unreleased` with the version and date; do not retain an empty section.
- Describe changes relative to the immediately preceding release. The first release may describe the initial features and public API.
- Verify release versions and dates against Git tags and the version source defined in the README versioning policy.
- If older entries need archiving, move complete major-series sections into linked `changelogs/*.md` files without duplicating or rewriting their entries.

## Commit style

- Use exactly one subject prefix: `feat:`, `fix:`, `docs:`, `style:`, `build:`, `refactor:`, `revert:`, `test:`, `perf:`, `ci:`, or `chore:`.
- Keep the subject concise: use a short phrase with no trailing punctuation.
- Use a subject line only; do not add a commit body.

## File headers

- Every Python file starts with the project copyright header, followed by a blank line before its module docstring or code.
- Do not add an encoding declaration or a Python interpreter shebang.
- Copyright years are managed by the PyCharm copyright profile. Preserve existing generated year ranges rather than changing them by hand.
- The PyCharm copyright template is:

```text
Copyright (c) $originalComment.match("Copyright \\(c\\) (\d+)", 1, "-", "$today.year")$today.year IsArvin.
This file is part of $project.name. Please refer to the LICENCE file for licence information.
```
