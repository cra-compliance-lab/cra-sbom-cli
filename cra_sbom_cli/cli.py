"""Orchestrator: parse SBOM, run engine, run enrichment, render PDF.

Mirrors the worker.tasks.process_artifact_job flow from the CRA SBOM
Platform but for an offline single-file SBOM. Emits the report dict as
JSON on stdout so the wrapping shell script can drive the terminal
summary.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .compliance_engine import evaluate_cra_compliance
from .enrichment import run_grype, run_sbomqs
from .report_export import export_report_pdf
from .sbom_parser import SbomParseError, parse_sbom_file


def _materialize_json_copy(parse_result, source_path: Path) -> Path:
    """For non-JSON inputs (CycloneDX XML, SPDX tag-value), write a JSON
    copy alongside the source so grype/sbomqs (which expect JSON) work.
    """
    if parse_result.detected_kind in ("cyclonedx-xml", "spdx-tag-value"):
        json_copy = source_path.with_suffix(".converted.json")
        json_copy.write_text(json.dumps(parse_result.sbom, indent=2), encoding="utf-8")
        return json_copy
    return source_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cra-sbom-report",
        description="Run CRA-aligned compliance checks on an SBOM and emit a PDF report.",
    )
    parser.add_argument("sbom", type=Path, help="Path to the SBOM file (CycloneDX or SPDX).")
    parser.add_argument(
        "--enhanced",
        action="store_true",
        help="Run enhanced-mode checks (hash algorithm + strength + coverage).",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip grype + sbomqs enrichment (offline mode).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination path for the PDF report.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional path to also write the raw report JSON.",
    )
    args = parser.parse_args(argv)

    sbom_path: Path = args.sbom.resolve()
    if not sbom_path.is_file():
        print(f"error: SBOM file not found: {sbom_path}", file=sys.stderr)
        return 2

    try:
        parse_result = parse_sbom_file(sbom_path)
    except SbomParseError as exc:
        print(f"error: failed to parse SBOM: {exc}", file=sys.stderr)
        return 3

    raw = parse_result.sbom

    result = evaluate_cra_compliance(raw, enhanced_mode=args.enhanced)

    enrichment_target = _materialize_json_copy(parse_result, sbom_path)
    enrichment: dict = {}
    if args.no_enrich:
        enrichment["grype"] = {"tool": "grype", "status": "skipped", "reason": "--no-enrich"}
        enrichment["sbomqs"] = {"tool": "sbomqs", "status": "skipped", "reason": "--no-enrich"}
    else:
        enrichment["grype"] = run_grype(enrichment_target)
        enrichment["sbomqs"] = run_sbomqs(enrichment_target)

    result["enrichment"] = enrichment
    result["generation"] = {
        "tool_used": "uploaded",
        "strategy": "cli",
        "format": parse_result.format_family,
        "detected_input_kind": parse_result.detected_kind,
        "source_filename": sbom_path.name,
        "source_path": str(sbom_path),
        "component_count": result.get("component_count", 0),
        "scan_id": uuid.uuid4().hex,
        "scan_time_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }

    output_pdf = args.output.resolve()
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    export_report_pdf(result, output_pdf)

    if args.json is not None:
        json_path = args.json.resolve()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    sys.stdout.write(json.dumps(result))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
