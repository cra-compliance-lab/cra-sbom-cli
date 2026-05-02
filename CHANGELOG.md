# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-01

### Added
- Initial standalone release.
- Shell entry point `bin/cra-sbom-report` with colored terminal summary.
- Bundled compliance engine, evidence catalogue, SBOM parser, enrichment
  wrappers (grype, sbomqs), and PDF exporter — extracted from the
  CRA SBOM Platform.
- One-command installer (`install.sh`) for macOS, Debian/Ubuntu, Fedora/RHEL,
  Arch, and openSUSE.
- Optional `pip install .` path via `pyproject.toml`.
- Documentation: `docs/INSTALLATION.md`, `docs/USAGE.md`, `docs/COMPLIANCE.md`.

### Known limitations
- No `evidence_snapshot` section in the PDF (that requires a database; the
  catalogue fallback is rendered instead).
- SPDX 3.0 documents are detected and rejected with a hard-fail message.
- Without `grype` / `sbomqs` installed, the corresponding sections of the
  report show `unavailable`. The verdict is unaffected.
