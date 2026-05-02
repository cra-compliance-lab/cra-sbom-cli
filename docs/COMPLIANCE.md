# What this tool checks (and what it doesn't)

This document explains the compliance logic line by line so a security
engineer or auditor can predict the verdict before running the tool.

## Normative basis

Every report cites three published documents as its basis:

- **EU CRA Regulation (EU) 2024/2847** — the legal text
- **prEN 40000-1-3:2025** — the European standard implementing CRA
- **BSI TR-03183-2 v2.1.0** — the German technical guideline

Requirement IDs you'll see in the report (e.g. `PRE-7-RQ-04`) come from
these documents.

## Two registers

The tool emits two kinds of findings:

1. **Automatic checks** — emit `PASS`, `FAIL`, or `WARN` based on SBOM content.
2. **Manual evidence catalogue items** — things SBOMs cannot prove on
   their own. They appear as entries in the PDF that an auditor must
   attach evidence against.

A PASS verdict on the automatic checks **alone** is not a CRA conformity
claim. Both registers must be satisfied.

---

## Automatic checks

### Format & version

| ID | Title | Logic |
|---|---|---|
| PRE-7-RQ-04 | (CycloneDX) Structural validation | `bomFormat == "CycloneDX"`, `specVersion`, `metadata` object exists, components/dependencies arrays where present. |
| PRE-7-RQ-04 | CycloneDX Version | `specVersion >= 1.4` (numeric major.minor compare; pre-release suffixes tolerated). |
| PRE-7-RQ-04 | (SPDX) Structural validation | `spdxVersion`, `SPDXID`, `dataLicense`, `creationInfo` object, packages/relationships arrays where present. |
| PRE-7-RQ-04 | SPDX Version | `spdxVersion >= 2.3`. |
| PRE-7-RQ-04 | SBOM Format (hard-fail) | Unknown format ⇒ hard-fail with `unknown-format`. SPDX 3.0 ⇒ hard-fail with `spdx-3-not-supported`. |

### Metadata completeness

| ID | Title | Logic |
|---|---|---|
| PRE-7-RQ-06 | SBOM Author | (CycloneDX) `metadata.authors[0].name` OR `metadata.manufacturer.name` OR `metadata.supplier.name`. (SPDX) `creationInfo.creators[0]`. |
| PRE-7-RQ-06 | Timestamp | ISO-8601 string. CycloneDX: `metadata.timestamp`. SPDX: `creationInfo.created`. |
| PRE-7-RQ-06 | SBOM Document Version | (CycloneDX) `version` field present. (SPDX) `documentVersion`/`sbomVersion`/governance annotation — falls back to a WARN since SPDX has no canonical field. |
| PRE-7-RQ-06 | Primary Component | (CycloneDX) `metadata.component.name` and `.version`. |
| PRE-7-RQ-06 | Document Metadata (SPDX) | `name` and `documentNamespace`. |

### Component / package completeness

| ID | Title | Logic |
|---|---|---|
| PRE-7-RQ-02 | Component / Package List | At least one item in `components`/`packages`. Empty list ⇒ hard-fail with `empty-inventory`. |
| PRE-7-RQ-02 | Component Names (CycloneDX only) | Every `components[*].name` is non-empty. |
| PRE-7-RQ-02 | Component / Package Versions | Every item has `version` (CycloneDX) or `versionInfo` (SPDX). |
| PRE-7-RQ-02 | Component / Package Supplier | Every item has `supplier.name` (CycloneDX) or `supplier != "NOASSERTION"` (SPDX). |
| PRE-7-RQ-07 | Unique Identifier | Every item has at least one of: `purl`, `cpe`, `bom-ref` (CycloneDX), or an external reference of type `purl`/`cpe23Type`/`swh` (SPDX). |

### Dependency graph

| ID | Title | Logic |
|---|---|---|
| PRE-7-RQ-03 | Dependency Graph / Relationships | Non-empty `dependencies`/`relationships` array. |
| PRE-7-RQ-07 | Reference Integrity | Every `ref` / `dependsOn` / `spdxElementId` / `relatedSpdxElement` resolves to a known component/package (max 25 unresolved samples reported). |
| PRE-7-RQ-07 | Component Relationship Coverage | Every non-root component appears as either side of at least one dependency edge. |

### Enhanced mode (`--enhanced`) — `PRE-7-RQ-07-RE`

| Title | Logic |
|---|---|
| Supplier Hash Algorithm | Every present hash declares `alg` (CycloneDX) or `algorithm` (SPDX). |
| Supplier Hash Strength | Algorithm ∈ {SHA-256, SHA-384, SHA-512, SHA3-256/384/512, BLAKE2B-*, BLAKE3}. Anything weaker (MD5, SHA-1, CRC) is FAIL. |
| Supplier Hash Coverage | Warning-level. Reports the proportion of items that include hashes; cannot prove "supplier provided hashes" from content alone. |

### Always-on warnings

These never produce FAIL on their own — they're explicit prompts to look
elsewhere for evidence.

| ID | Title | Reason |
|---|---|---|
| PRE-7-RQ-05 | Per-build / per-release regeneration | Cannot be proven from SBOM content; needs CI/CD logs. |
| 5.3.8.5      | Asset-to-SBOM completeness            | Cannot be proven from SBOM content; needs build/release artifact comparison. |

---

## Manual evidence catalogue

These items appear in the PDF for every scan. They have **stable IDs** so
auditors can attach evidence against them in a downstream system.

| ID | Title | Required? | Normative basis |
|---|---|---|---|
| `cra.per_build_regeneration`       | Per-build / per-release SBOM regeneration  | yes | CRA PRE-7-RQ-05 |
| `cra.error_correction`             | Error correction and revised SBOM publication | yes | CRA Annex I §1(3) |
| `cra.asset_to_sbom_completeness`   | Asset-to-SBOM completeness                 | yes | prEN 40000-1-3 §5.3.8.5 |
| `cra.vuln_handling_process`        | Vulnerability handling procedure           | yes | CRA Annex I §2 |
| `cra.incident_reporting`           | Incident reporting procedure (24h/72h ENISA) | yes | CRA Article 14 |
| `cra.csaf_vex`                     | CSAF / VEX publication (enhanced products) | no  | CRA Annex III |
| `cdx.transitive_completeness`      | Transitive dependency completeness         | no  | CRA PRE-7-RQ-07-RE — only in `--enhanced` |
| `spdx.document_version_governance` | SPDX document version governance           | no  | CRA PRE-7-RQ-06 · SPDX 2.3 — only for SPDX inputs |

---

## Verdict logic

```
verdict = "FAIL" if hard_fail_reason else ("PASS" if failed == 0 else "FAIL")
```

`hard_fail_reason` is set by:

| Condition | Reason string |
|---|---|
| Unrecognized SBOM format | `unknown-format` |
| SPDX 3.0 detected | `spdx-3-not-supported` |
| Zero components/packages | `empty-inventory` |

Warnings never produce FAIL.

## Enrichment (informational only)

Two external tools are invoked when available; their findings appear in
the PDF but **do not** affect the verdict.

| Tool | What it provides |
|---|---|
| `grype` | Count of known-vulnerability matches against the SBOM |
| `sbomqs` | Numeric quality score (Interlynk) |

When the binary is missing, the tool reports `unavailable` and the rest of
the report continues.

---

## What the tool does NOT do

- It does not download SBOMs, fetch images, or clone repos. Input must be
  a local file. (The full platform handles GitHub URLs, container images,
  firmware binaries, etc.)
- It does not write to a database, send webhooks, or sign SBOMs. Those are
  platform-only features.
- It does not assess **process** compliance — vuln-handling cadence,
  incident-reporting drills, change-management workflow. Those obligations
  live in the manual-evidence catalogue.
- It does not produce a CRA conformity declaration. The output is an
  *input* to that decision.
