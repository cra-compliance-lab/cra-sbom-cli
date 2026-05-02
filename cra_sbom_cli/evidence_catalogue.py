"""Stable catalogue of manual-evidence items required for CRA conformity.

The compliance engine currently emits manual-evidence reminders as free-form
strings. That prose is fine for a human reader but gives us nothing to hang
attachment state off — we can't say "requirement X is now covered" without a
stable handle. This module introduces those handles.

Each catalogue entry is keyed by a dotted id that survives across releases.
Engine checks reference the id; routes expose the full entry; the Evidence
table stores one row per (project, id); the UI renders item.title /
item.description / item.normative_basis.

Adding an entry: append to CATALOGUE below and update evaluate_cra_compliance
in compliance_engine.py to emit the new id when appropriate. Never renumber
or rename an existing id — it would orphan stored evidence rows.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    title: str
    description: str
    normative_basis: str
    required: bool

    def as_dict(self) -> dict:
        return asdict(self)


CATALOGUE: dict[str, EvidenceItem] = {
    "cra.per_build_regeneration": EvidenceItem(
        id="cra.per_build_regeneration",
        title="Per-build / per-release SBOM regeneration",
        description=(
            "Evidence that a fresh SBOM is produced for every release artifact, "
            "not once per product. Typically a CI/CD pipeline log, release checklist, "
            "or build-system manifest tying each SBOM to the commit it was built from."
        ),
        normative_basis="CRA PRE-7-RQ-05",
        required=True,
    ),
    "cra.error_correction": EvidenceItem(
        id="cra.error_correction",
        title="Error correction and revised SBOM publication",
        description=(
            "Documented procedure for correcting errors discovered in a published SBOM "
            "and distributing the corrected version to downstream consumers."
        ),
        normative_basis="CRA Annex I §1(3)",
        required=True,
    ),
    "cra.asset_to_sbom_completeness": EvidenceItem(
        id="cra.asset_to_sbom_completeness",
        title="Asset-to-SBOM completeness",
        description=(
            "Evidence comparing the shipped product assets (binaries, firmware partitions, "
            "container layers) against the SBOM contents to demonstrate that every component "
            "that reaches the customer is enumerated."
        ),
        normative_basis="prEN 40000-1-3 §5.3.8.5",
        required=True,
    ),
    "cra.vuln_handling_process": EvidenceItem(
        id="cra.vuln_handling_process",
        title="Vulnerability handling procedure",
        description=(
            "Published process for receiving, triaging, and responding to vulnerability "
            "reports, including the coordinated-disclosure contact channel."
        ),
        normative_basis="CRA Annex I §2",
        required=True,
    ),
    "cra.incident_reporting": EvidenceItem(
        id="cra.incident_reporting",
        title="Incident reporting procedure",
        description=(
            "Demonstrated capability to report actively exploited vulnerabilities within "
            "the CRA windows (24h early warning, 72h notification, final report) to ENISA "
            "and to affected users."
        ),
        normative_basis="CRA Article 14",
        required=True,
    ),
    "cra.csaf_vex": EvidenceItem(
        id="cra.csaf_vex",
        title="CSAF / VEX publication (enhanced products)",
        description=(
            "For products classified as 'important' or 'critical' under CRA, machine-readable "
            "CSAF or VEX documents describing the affected-status of known vulnerabilities. "
            "Not required for Class I / unclassified products."
        ),
        normative_basis="CRA Annex III",
        required=False,
    ),
    "cdx.transitive_completeness": EvidenceItem(
        id="cdx.transitive_completeness",
        title="Transitive dependency completeness",
        description=(
            "Build artifacts (lockfiles, dependency manifests, package manager output) "
            "demonstrating that the SBOM's dependency graph captures every transitive "
            "dependency and not only the direct ones."
        ),
        normative_basis="CRA PRE-7-RQ-07-RE",
        required=False,
    ),
    "spdx.document_version_governance": EvidenceItem(
        id="spdx.document_version_governance",
        title="SPDX document version governance",
        description=(
            "SPDX 2.x has no canonical 'document version' field. If you ship SPDX, document "
            "the internal convention (e.g. a custom annotation or external metadata file) "
            "used to version successive SPDX documents for the same product."
        ),
        normative_basis="CRA PRE-7-RQ-06 · SPDX 2.3",
        required=False,
    ),
}


ALWAYS_EMITTED = (
    "cra.per_build_regeneration",
    "cra.error_correction",
    "cra.asset_to_sbom_completeness",
    "cra.vuln_handling_process",
    "cra.incident_reporting",
    "cra.csaf_vex",
)


def items_for_format(sbom_format: str, enhanced_mode: bool) -> list[EvidenceItem]:
    """The catalogue items the compliance engine should surface for a given scan."""
    items: list[EvidenceItem] = [CATALOGUE[item_id] for item_id in ALWAYS_EMITTED]
    if enhanced_mode:
        items.append(CATALOGUE["cdx.transitive_completeness"])
    if sbom_format == "spdx":
        items.append(CATALOGUE["spdx.document_version_governance"])
    return items


def is_known_requirement(requirement_id: str) -> bool:
    return requirement_id in CATALOGUE


def get(requirement_id: str) -> EvidenceItem:
    return CATALOGUE[requirement_id]


__all__ = [
    "CATALOGUE",
    "EvidenceItem",
    "get",
    "is_known_requirement",
    "items_for_format",
]
