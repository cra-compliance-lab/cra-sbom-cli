# cra-sbom-cli

> CRA-aligned SBOM compliance reporter — one shell command, one PDF, one terminal summary.

`cra-sbom-cli` reads a CycloneDX or SPDX SBOM from disk, runs the same
content checks the [CRA SBOM Platform](#provenance) runs server-side, and
emits two outputs:

- **A colored terminal summary** — verdict, counts, top failures, top
  warnings, normative basis, PDF location.
- **A detailed PDF** — every requirement check, the manual-evidence
  catalogue, generation diagnostics, and an explicit assessment-scope
  disclaimer.

It works offline. The only hard dependency is Python 3.10+ and the
`reportlab` package; everything else is optional and degrades cleanly.

---

## Quick start

```bash
git clone https://github.com/cra-compliance-lab/cra-sbom-cli
cd cra-sbom-cli
./install.sh
cra-sbom-report path/to/sbom.json
```

Sample output (TTY, abbreviated):

```
╭────────────────────────────────────────────────────────────╮
│ CRA-Aligned SBOM Assessment                                │
│ Source: cosign-source-cyclonedx.json                       │
╰────────────────────────────────────────────────────────────╯

  Verdict:    ✓ PASS
  Format:     cyclonedx
  Components: 247
  Mode:       standard

  Counts:
    Passed 14    Failed 0    Warnings 2    Manual 6

Enrichment
  grype:  14 matches
  sbomqs: see PDF for full output

Warnings (top 5)
  ⚠ PRE-7-RQ-05  Per-build / per-release regeneration  Cannot be proven from SBOM content alone…
  ⚠ 5.3.8.5      Asset-to-SBOM completeness            Full completeness cannot be proven from…

Normative basis
  - EU CRA Regulation (EU) 2024/2847
  - prEN 40000-1-3:2025
  - BSI TR-03183-2 v2.1.0

Detailed PDF: ./cra-sbom-report-2026-05-01-225318-45840000.pdf
```

The detailed PDF includes per-component findings, manual-evidence catalogue
items with normative references, and the structured assessment-scope panel.

---

## Installation

### Supported platforms

| OS                          | Tested | Package manager |
|---|---|---|
| macOS (Apple Silicon, Intel) | yes | Homebrew |
| Ubuntu / Debian              | yes | apt-get  |
| Fedora / RHEL / CentOS       | yes | dnf / yum |
| Arch / Manjaro               | yes | pacman   |
| openSUSE                     | yes | zypper   |
| Windows native               | **no** — use **WSL2** with one of the Linux distros above |

### One-command install

```bash
git clone https://github.com/cra-compliance-lab/cra-sbom-cli
cd cra-sbom-cli
./install.sh
```

The installer:

1. Detects your OS and package manager.
2. Verifies Python 3.10+.
3. Installs `reportlab` for the current user (no sudo).
4. **Asks before** installing `grype`, `sbomqs`, `jq` — never silent.
5. Symlinks `bin/cra-sbom-report` to `~/.local/bin/cra-sbom-report`.
6. Verifies with `cra-sbom-report --help`.

### Install variants

```bash
./install.sh --system        # symlink to /usr/local/bin (uses sudo)
./install.sh --no-symlink    # install deps only; invoke ./bin/cra-sbom-report directly
./install.sh --yes           # answer yes to every prompt (CI)
```

### Manual install

If you'd rather install everything yourself, see
[docs/INSTALLATION.md](docs/INSTALLATION.md).

### `pip install`

The package is also pip-installable (handy for venvs):

```bash
pip install .
cra-sbom-report --help
```

---

## Usage

```text
cra-sbom-report <sbom-file> [options]

Arguments
  <sbom-file>           CycloneDX (JSON/XML) or SPDX (JSON/tag-value)

Options
  --enhanced            Run enhanced-mode checks (hash algorithm/strength)
  --no-enrich           Skip grype + sbomqs (offline / fast mode)
  --output <path>       PDF output path. Default: ./cra-sbom-report-<ts>-<id>.pdf
  --json <path>         Also write the raw report JSON to this path
  -h, --help            Show this help and exit
```

### Examples

```bash
# Standard run; PDF lands in cwd with a timestamp name
cra-sbom-report sbom.cyclonedx.json

# Enhanced mode, custom output paths
cra-sbom-report sbom.json \
    --enhanced \
    --output reports/sbom-cra.pdf \
    --json   reports/sbom-cra.json

# Offline / fast — useful in CI where grype's vuln DB pull would be slow
cra-sbom-report sbom.spdx.json --no-enrich
```

For a full walkthrough, see [docs/USAGE.md](docs/USAGE.md).

---

## What it actually checks

The compliance engine runs hand-coded checks derived from three published
normative sources:

- **EU CRA Regulation (EU) 2024/2847**
- **prEN 40000-1-3:2025**
- **BSI TR-03183-2 v2.1.0**

There are two registers:

- **Automatic checks** (around 15 per scan) — format, version, metadata,
  per-component name/version/supplier/identifier, dependency-graph integrity,
  hash algorithm + strength (in `--enhanced`).
- **Manual evidence catalogue** — items the SBOM cannot prove on its own
  (per-build regeneration, vuln-handling procedure, incident reporting,
  CSAF/VEX, etc.). These appear in the PDF for an auditor to attach
  evidence against.

A real CRA conformity claim requires **both** layers. PASS verdict alone is
insufficient by design — every report includes that disclaimer.

Full details: [docs/COMPLIANCE.md](docs/COMPLIANCE.md).

---

## Output

| Output | Where |
|---|---|
| Terminal summary | stdout (ANSI when TTY, plain when piped) |
| Detailed PDF | `--output <path>` (default: `./cra-sbom-report-<ts>-<id>.pdf`) |
| Raw report JSON | `--json <path>` (optional; useful for CI gates) |

### CI integration

Exit code is `0` for "tool ran successfully" — verdict (PASS/FAIL) lives
in the JSON. To gate on verdict in CI:

```bash
cra-sbom-report sbom.json --json result.json
verdict=$(jq -r '.verdict' result.json)
[[ "$verdict" == "PASS" ]] || exit 1
```

---

## Limitations

- **PASS ≠ CRA-compliant.** Automated checks cover SBOM *content*; full
  conformity additionally requires the manual evidence catalogued in the
  report.
- **No evidence snapshot.** The platform's database-backed evidence
  attachments don't exist offline. The PDF shows the catalogue with no
  attached-status overlay.
- **SPDX 3.0** is detected and rejected with a hard-fail message — re-export
  as SPDX 2.3 or CycloneDX 1.5+.
- **No SBOM signing or webhook fan-out.** Offline-first design.

---

## Provenance

This CLI's compliance logic is bundled out of the
[CRA SBOM Platform](#) backend (`backend/app/services/`). Updating the
platform's checks does **not** automatically update this CLI; treat both
as separate codepaths that need to be kept in sync.

The bundled modules:

| File | Origin |
|---|---|
| `cra_sbom_cli/compliance_engine.py`   | `backend/app/services/compliance_engine.py` |
| `cra_sbom_cli/evidence_catalogue.py`  | `backend/app/services/evidence_catalogue.py` |
| `cra_sbom_cli/enrichment.py`          | `backend/app/services/enrichment.py` |
| `cra_sbom_cli/report_export.py`       | `backend/app/services/report_export.py` |
| `cra_sbom_cli/sbom_parser.py`         | `backend/app/services/sbom_parser.py` |
| `cra_sbom_cli/command_runner.py`      | `backend/app/services/command_runner.py` |

Cross-imports were rewritten to relative paths; no other changes.

---

## Contributing

Issues and PRs welcome. For changes that touch the compliance logic or PDF
layout, please match the upstream platform — drift between the two surfaces
will confuse users.

## License

MIT — see [LICENSE](LICENSE).
