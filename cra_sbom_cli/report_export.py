import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


# ---------------------------------------------------------------------------
# JSON export


def export_report_json(report_payload: dict, target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    return target_path


# ---------------------------------------------------------------------------
# Shared styles


def _styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#162030"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#0d6f5f"),
            spaceBefore=8,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#2f3b4d"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Muted",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#617089"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Warn",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#9b1b1b"),
        )
    )
    return styles


# ---------------------------------------------------------------------------
# Top metric row: SBOM Quality + CRA Conformity (the UI's two badges)


def _conformity_state(report_payload: dict) -> tuple[str, str]:
    """Return (label, bg_hex) for the CRA Conformity column.

    Mirrors the React logic on the report page: if the SBOM itself failed,
    conformity can't be claimed; otherwise it's driven by the evidence
    snapshot's required_complete flag. Reports without a snapshot fall back
    to "EVIDENCE INCOMPLETE" — we can't infer coverage from live state in
    a frozen PDF.
    """
    verdict = report_payload.get("verdict")
    if verdict == "FAIL":
        return "SBOM FAILED", "#ffe8e8"
    snapshot = report_payload.get("evidence_snapshot") or {}
    if snapshot.get("required_complete"):
        return "EVIDENCE COMPLETE", "#e3f6f2"
    return "EVIDENCE INCOMPLETE", "#fff6e3"


def _metric_table(report_payload: dict, styles):
    counts = report_payload.get("counts", {})
    verdict = report_payload.get("verdict", "UNKNOWN")
    conformity_label, conformity_bg = _conformity_state(report_payload)

    rows = [
        [
            Paragraph("<b>SBOM Quality</b>", styles["BodySmall"]),
            Paragraph("<b>CRA Conformity</b>", styles["BodySmall"]),
            Paragraph("<b>Passed</b>", styles["BodySmall"]),
            Paragraph("<b>Failed</b>", styles["BodySmall"]),
            Paragraph("<b>Warnings</b>", styles["BodySmall"]),
            Paragraph("<b>Manual</b>", styles["BodySmall"]),
        ],
        [
            Paragraph(verdict, styles["BodySmall"]),
            Paragraph(conformity_label, styles["BodySmall"]),
            Paragraph(str(counts.get("passed", 0)), styles["BodySmall"]),
            Paragraph(str(counts.get("failed", 0)), styles["BodySmall"]),
            Paragraph(str(counts.get("warnings", 0)), styles["BodySmall"]),
            Paragraph(str(counts.get("manual_items", 0)), styles["BodySmall"]),
        ],
    ]
    table = Table(
        rows,
        colWidths=[30 * mm, 38 * mm, 22 * mm, 22 * mm, 22 * mm, 22 * mm],
    )
    verdict_bg = colors.HexColor("#e3f6f2") if verdict == "PASS" else colors.HexColor("#ffe8e8")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2fa")),
                ("BACKGROUND", (0, 1), (0, 1), verdict_bg),
                ("BACKGROUND", (1, 1), (1, 1), colors.HexColor(conformity_bg)),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8dfeb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _hard_fail_explanation(reason: str) -> str:
    mapping = {
        "empty-inventory": (
            "The SBOM parsed correctly but contains zero components. A compliant "
            "SBOM must enumerate the product inventory; an empty SBOM cannot "
            "satisfy CRA content requirements."
        ),
        "unknown-format": (
            "The uploaded file was not recognized as CycloneDX or SPDX. Re-export "
            "from your build system in CycloneDX 1.4+ JSON/XML or SPDX 2.3 "
            "JSON/tag-value."
        ),
        "spdx-3-not-supported": (
            "SPDX 3.0 documents are detected but not yet evaluated. Re-export as "
            "SPDX 2.3 or CycloneDX 1.5+ to proceed."
        ),
    }
    return mapping.get(reason, "A blocking condition prevented this SBOM from being assessed.")


def _hard_fail_panel(report_payload: dict, styles):
    reason = report_payload.get("hard_fail_reason")
    if not reason:
        return None
    panel_rows = [
        [
            Paragraph(
                f"<b>Why the verdict is FAIL</b><br/><br/>{_hard_fail_explanation(reason)}"
                f"<br/><br/><i>Hard-fail reason: {reason}</i>",
                styles["Warn"],
            )
        ]
    ]
    table = Table(panel_rows, colWidths=[176 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff4f4")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#f0c4c4")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


# ---------------------------------------------------------------------------
# KV + checks (unchanged from the previous revision)


def _kv_table(title: str, items: dict, styles):
    rows = [[Paragraph("<b>Field</b>", styles["BodySmall"]), Paragraph("<b>Value</b>", styles["BodySmall"])]]
    for key, value in items.items():
        rows.append(
            [
                Paragraph(str(key), styles["BodySmall"]),
                Paragraph(str(value).replace("\n", "<br/>"), styles["BodySmall"]),
            ]
        )
    table = Table(rows, colWidths=[45 * mm, 130 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2fa")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8dfeb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return [Paragraph(title, styles["SectionTitle"]), table]


def _check_rows(report_payload: dict, styles):
    rows = [
        [
            Paragraph("<b>Requirement</b>", styles["BodySmall"]),
            Paragraph("<b>Check</b>", styles["BodySmall"]),
            Paragraph("<b>Status</b>", styles["BodySmall"]),
            Paragraph("<b>Detail</b>", styles["BodySmall"]),
        ]
    ]

    for check in report_payload.get("checks", []):
        evidence = check.get("evidence") or []
        detail_text = check.get("detail", "")
        if evidence:
            limited = evidence[:12]
            extra = len(evidence) - len(limited)
            bullet_block = "<br/>".join([f"- {item}" for item in limited])
            if extra > 0:
                bullet_block += f"<br/>... and {extra} more"
            detail_text = f"{detail_text}<br/><br/>{bullet_block}"
        rows.append(
            [
                Paragraph(str(check.get("requirement", "")), styles["BodySmall"]),
                Paragraph(str(check.get("title", "")), styles["BodySmall"]),
                Paragraph(str(check.get("status", "")), styles["BodySmall"]),
                Paragraph(detail_text.replace("\n", "<br/>"), styles["BodySmall"]),
            ]
        )

    table = Table(rows, colWidths=[28 * mm, 42 * mm, 20 * mm, 95 * mm], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8dfeb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for index, check in enumerate(report_payload.get("checks", []), start=1):
        status = check.get("status")
        if status == "PASS":
            style_cmds.append(("BACKGROUND", (2, index), (2, index), colors.HexColor("#e3f6f2")))
        elif status == "FAIL":
            style_cmds.append(("BACKGROUND", (2, index), (2, index), colors.HexColor("#ffe8e8")))
        else:
            style_cmds.append(("BACKGROUND", (2, index), (2, index), colors.HexColor("#fff6e3")))
    table.setStyle(TableStyle(style_cmds))
    return table


# ---------------------------------------------------------------------------
# Evidence snapshot (new section)


_STATUS_LABEL = {
    "attached": "ATTACHED",
    "attested": "ATTESTED",
    "not_applicable": "N/A",
    "pending": "PENDING",
}
_STATUS_BG = {
    "attached": colors.HexColor("#e3f6f2"),
    "attested": colors.HexColor("#e3f6f2"),
    "not_applicable": colors.HexColor("#fff6e3"),
    "pending": colors.HexColor("#ffe8e8"),
}


def _evidence_snapshot_section(report_payload: dict, styles):
    """Return (optional) list of flowables for the evidence-snapshot section.

    Prefers the frozen `evidence_snapshot`. If that's absent (older reports
    from before the snapshotting feature landed) falls back to rendering the
    structured `manual_evidence_items` list WITHOUT any status info so it's
    obvious the print is pre-snapshot.
    """
    snapshot = report_payload.get("evidence_snapshot") or {}
    items = snapshot.get("items") or []
    if items:
        covered = snapshot.get("required_covered", 0)
        total = snapshot.get("required_total", 0)
        snap_at = snapshot.get("snapshotted_at", "")
        header = (
            f"Evidence snapshot as of <b>{snap_at}</b> · "
            f"{covered}/{total} required items covered"
        )
        flowables = [
            Paragraph("Manual Evidence (Snapshot)", styles["SectionTitle"]),
            Paragraph(header, styles["Muted"]),
            Spacer(1, 2 * mm),
            _evidence_snapshot_table(items, styles),
        ]
        return flowables

    # Graceful fallback — the structured catalogue list without status overlay.
    manual_items = report_payload.get("manual_evidence_items") or []
    if manual_items:
        return [
            Paragraph("Manual Evidence Required", styles["SectionTitle"]),
            Paragraph(
                "This report predates the evidence-snapshot feature; status of each "
                "item is not captured below. See the platform UI for current coverage.",
                styles["Muted"],
            ),
            Spacer(1, 2 * mm),
            _evidence_catalogue_table(manual_items, styles),
        ]

    # Last-ditch fallback — the pre-catalogue free-text list.
    legacy = report_payload.get("manual_evidence") or []
    if legacy:
        flowables = [Paragraph("Manual Evidence Required", styles["SectionTitle"])]
        for line in legacy:
            flowables.append(Paragraph(f"- {line}", styles["BodySmall"]))
        return flowables

    return []


def _truncate(value: str, cap: int) -> str:
    if value and len(value) > cap:
        return value[:cap] + "…"
    return value or ""


def _evidence_snapshot_table(items: list[dict], styles):
    rows = [
        [
            Paragraph("<b>Requirement</b>", styles["BodySmall"]),
            Paragraph("<b>Scope</b>", styles["BodySmall"]),
            Paragraph("<b>Status</b>", styles["BodySmall"]),
            Paragraph("<b>Evidence</b>", styles["BodySmall"]),
        ]
    ]
    status_cell_cmds: list[tuple[str, tuple[int, int], tuple[int, int], object]] = []

    for idx, item in enumerate(items, start=1):
        catalogue = item.get("catalogue") or {}
        status = item.get("status") or "pending"
        evidence_bits: list[str] = []
        if item.get("original_filename"):
            evidence_bits.append(f"file: <b>{item['original_filename']}</b>")
        file_hash = item.get("file_sha256")
        if file_hash:
            evidence_bits.append(f"sha256: {_truncate(file_hash, 16)}")
        if item.get("note"):
            evidence_bits.append(f"note: <i>{_truncate(item['note'], 200)}</i>")
        if item.get("updated_at"):
            evidence_bits.append(f"updated: {_truncate(item['updated_at'], 25)}")
        evidence_text = "<br/>".join(evidence_bits) if evidence_bits else "—"

        rows.append(
            [
                Paragraph(
                    f"<b>{catalogue.get('title', item.get('requirement_id', ''))}</b>"
                    f"<br/><font color='#617089'>{catalogue.get('normative_basis', '')}</font>",
                    styles["BodySmall"],
                ),
                Paragraph(
                    "REQUIRED" if catalogue.get("required") else "OPTIONAL",
                    styles["BodySmall"],
                ),
                Paragraph(_STATUS_LABEL.get(status, status.upper()), styles["BodySmall"]),
                Paragraph(evidence_text, styles["BodySmall"]),
            ]
        )
        status_cell_cmds.append(
            ("BACKGROUND", (2, idx), (2, idx), _STATUS_BG.get(status, colors.white))
        )

    table = Table(
        rows,
        colWidths=[55 * mm, 20 * mm, 22 * mm, 83 * mm],
        repeatRows=1,
    )
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2fa")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8dfeb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    style_cmds.extend(status_cell_cmds)
    table.setStyle(TableStyle(style_cmds))
    return table


def _evidence_catalogue_table(items: list[dict], styles):
    rows = [
        [
            Paragraph("<b>Requirement</b>", styles["BodySmall"]),
            Paragraph("<b>Scope</b>", styles["BodySmall"]),
            Paragraph("<b>Normative Basis</b>", styles["BodySmall"]),
        ]
    ]
    for item in items:
        rows.append(
            [
                Paragraph(f"<b>{item.get('title', '')}</b><br/>{item.get('description', '')}", styles["BodySmall"]),
                Paragraph("REQUIRED" if item.get("required") else "OPTIONAL", styles["BodySmall"]),
                Paragraph(item.get("normative_basis", ""), styles["BodySmall"]),
            ]
        )
    table = Table(rows, colWidths=[85 * mm, 20 * mm, 75 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf2fa")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d8dfeb")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


# ---------------------------------------------------------------------------
# Top-level PDF export


def export_report_pdf(report_payload: dict, target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()
    doc = SimpleDocTemplate(
        str(target_path),
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )

    story = []
    story.append(Paragraph("CRA-Aligned SBOM Assessment Report", styles["ReportTitle"]))
    story.append(
        Paragraph(
            "Automated SBOM content assessment aligned to CRA-related requirements. "
            "SBOM Quality reflects automated checks; CRA Conformity additionally "
            "requires the manual evidence listed below.",
            styles["Muted"],
        )
    )
    story.append(Spacer(1, 5 * mm))
    story.append(_metric_table(report_payload, styles))

    hard_fail = _hard_fail_panel(report_payload, styles)
    if hard_fail is not None:
        story.append(Spacer(1, 4 * mm))
        story.append(hard_fail)

    story.append(Spacer(1, 4 * mm))

    if report_payload.get("assessment_statement"):
        story.append(Paragraph("Assessment Scope", styles["SectionTitle"]))
        story.append(Paragraph(str(report_payload.get("assessment_statement")), styles["BodySmall"]))
        story.append(Spacer(1, 4 * mm))

    generation = report_payload.get("generation") or {}
    if generation:
        story.extend(_kv_table("Generation Details", generation, styles))
        story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("Requirement Checks", styles["SectionTitle"]))
    story.append(_check_rows(report_payload, styles))
    story.append(Spacer(1, 4 * mm))

    # Evidence section: snapshot if we have one, catalogue fallback, then
    # legacy string list as the last resort.
    evidence_flowables = _evidence_snapshot_section(report_payload, styles)
    if evidence_flowables:
        story.extend(evidence_flowables)
        story.append(Spacer(1, 4 * mm))

    norms = report_payload.get("normative_basis") or []
    if norms:
        story.append(Paragraph("Normative Basis", styles["SectionTitle"]))
        for item in norms:
            story.append(Paragraph(f"- {item}", styles["BodySmall"]))

    doc.build(story)
    return target_path
