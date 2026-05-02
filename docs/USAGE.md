# Usage

## Synopsis

```text
cra-sbom-report <sbom-file> [options]
```

## Arguments

| Arg | Required | Description |
|---|---|---|
| `<sbom-file>` | yes | Path to the SBOM. Auto-detects format. |

### Supported SBOM formats

| Format | Versions | Notes |
|---|---|---|
| CycloneDX JSON   | 1.2 – 1.6 | Most common; native format |
| CycloneDX XML    | 1.2 – 1.6 | Auto-converted to JSON internally |
| SPDX JSON        | 2.x       | Triggers SPDX-specific check branch |
| SPDX tag-value   | (`.spdx`) | Minimal parser; sufficient for CRA checks |
| **SPDX 3.0 JSON** | —         | **Detected and rejected** — re-export as 2.3 or CycloneDX |

## Options

| Flag | Description |
|---|---|
| `--enhanced` | Run enhanced-mode checks (`PRE-7-RQ-07-RE`): hash algorithm, hash strength, hash coverage. |
| `--no-enrich` | Skip `grype` and `sbomqs`. Useful in offline / fast-CI contexts. |
| `--output <path>` | PDF destination. Default: `./cra-sbom-report-<ts>-<id>.pdf`. Parent dir is created. |
| `--json <path>` | Also write the raw report dict as JSON. |
| `-h`, `--help` | Show help and exit. |

## Examples

### 1. Single SBOM, default output

```bash
cra-sbom-report sbom.cyclonedx.json
```

Writes `./cra-sbom-report-<timestamp>-<short-uuid>.pdf` and prints the
summary.

### 2. Enhanced mode + custom paths

```bash
cra-sbom-report sbom.json \
    --enhanced \
    --output reports/sbom-cra.pdf \
    --json   reports/sbom-cra.json
```

### 3. Offline — no external network calls

```bash
cra-sbom-report sbom.json --no-enrich
```

### 4. CI gate on verdict

```bash
cra-sbom-report sbom.json --json result.json --no-enrich
verdict=$(jq -r '.verdict' result.json)
if [[ "$verdict" != "PASS" ]]; then
    echo "::error::SBOM failed CRA content checks"
    exit 1
fi
```

### 5. Process a directory of SBOMs

```bash
mkdir -p reports
for sbom in sboms/*.json; do
    name=$(basename "$sbom" .json)
    cra-sbom-report "$sbom" \
        --output "reports/${name}.pdf" \
        --json   "reports/${name}.json" \
        --no-enrich
done
```

### 6. With a fresh SBOM from `syft`

```bash
syft dir:./my-project -o cyclonedx-json=./my-project.sbom.json
cra-sbom-report ./my-project.sbom.json
```

### 7. Container image SBOM

```bash
syft myorg/myimage:1.2.3 -o cyclonedx-json=./image.sbom.json
cra-sbom-report ./image.sbom.json
```

## Output details

### Terminal summary

When stdout is a TTY:

- Header banner with the source filename
- Verdict block (green PASS / red FAIL)
- Format, components, mode
- Counts row: passed / failed / warnings / manual
- Hard-fail reason (when set)
- Enrichment line: grype match count, sbomqs status
- Top 5 failed checks (when `failed > 0`)
- Top 5 warnings (when `warnings > 0`)
- Normative basis list
- Notes (deferred warnings about missing optional tools)
- Output paths

When stdout is **not** a TTY (piped, redirected), colors are disabled and
emoji glyphs are replaced with ASCII (`✓` → blank, `⚠` → `!`, `•` → `*`).

### PDF

A 2–3 page A4 document with:

1. Title + assessment-scope disclaimer
2. Top metric table: SBOM Quality (verdict) | CRA Conformity | Passed | Failed | Warnings | Manual
3. Hard-fail panel (when applicable)
4. Generation Details key/value table
5. Requirement Checks — every check, status-color-coded, with evidence lists
6. Manual Evidence section — catalogue items keyed by stable IDs
7. Normative Basis footer

Layout matches what the platform produces server-side.

### JSON (`--json`)

The full report dict, including:

```json
{
  "format": "cyclonedx",
  "verdict": "PASS",
  "hard_fail_reason": null,
  "component_count": 247,
  "assessment_scope": "sbom-content-only",
  "assessment_statement": "...",
  "confidence": "content-only",
  "counts": { "passed": 14, "failed": 0, "warnings": 2, "manual_items": 6 },
  "checks": [ { "requirement": "...", "title": "...", "status": "PASS", "detail": "...", "evidence": [...] }, ... ],
  "manual_evidence": [...],
  "manual_evidence_items": [...],
  "normative_basis": [...],
  "enrichment": { "grype": {...}, "sbomqs": {...} },
  "generation": { "scan_id": "...", "scan_time_utc": "...", ... }
}
```

The schema is shared with the CRA SBOM Platform's report stored in its
`compliance_reports.result_json` column.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Tool ran successfully (verdict can still be PASS or FAIL) |
| 1 | Usage error |
| 2 | SBOM file not found |
| 3 | SBOM parse failed |
| 4 | Missing required dependency (`python3`, `reportlab`) |
| 5 | Python helper crashed |

A FAIL **verdict** does not produce a non-zero exit code — see the CI gate
example for how to act on it.
