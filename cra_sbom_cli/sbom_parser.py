"""Multi-format SBOM parser.

Detects the SBOM flavor from raw bytes and parses it into a CycloneDX-shaped
Python dict (the platform's internal representation). For SPDX inputs, the dict
retains SPDX shape (spdxVersion + packages + relationships) so the compliance
engine's SPDX branch can consume it unchanged.

Supported inputs:
    - CycloneDX JSON  (1.2 - 1.6)
    - CycloneDX XML   (1.2 - 1.6, namespace-aware)
    - SPDX JSON       (2.x; 3.0 detected and reported)
    - SPDX tag-value  (.spdx; minimal parser, good enough for CRA checks)

Anything else raises SbomParseError with a message aimed at the end user.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


class SbomParseError(ValueError):
    """Raised when an uploaded SBOM cannot be parsed."""


@dataclass
class ParseResult:
    sbom: dict
    detected_kind: str  # one of: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-tag-value, spdx-3-json
    format_family: str  # "cyclonedx" | "spdx"
    notes: list[str]


_CDX_XML_NS_RE = re.compile(r"http://cyclonedx\.org/schema/bom/([\d.]+)")


def detect_sbom_kind(raw: bytes, filename: str | None = None) -> str:
    """Sniff the SBOM kind from raw bytes.

    Returns one of: cyclonedx-json, cyclonedx-xml, spdx-json, spdx-3-json,
    spdx-tag-value, or "unknown".
    """
    if not raw:
        return "unknown"

    stripped = raw.lstrip()
    # BOM-stripped sniff
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:].lstrip()

    head = stripped[:4096].decode("utf-8", errors="replace")

    if stripped[:1] in (b"{", b"["):
        # JSON of some flavor. Cheap string sniff before full parse.
        if '"bomFormat"' in head and "CycloneDX" in head:
            return "cyclonedx-json"
        if '"spdxVersion"' in head:
            return "spdx-json"
        if '"@context"' in head and "spdx.org" in head.lower():
            return "spdx-3-json"
        return "unknown"

    if stripped[:1] == b"<":
        if "cyclonedx.org/schema/bom" in head:
            return "cyclonedx-xml"
        return "unknown"

    # Tag-value SPDX starts with "SPDXVersion:" (possibly after comments).
    first_nonblank = next((line for line in head.splitlines() if line.strip() and not line.strip().startswith("#")), "")
    if first_nonblank.startswith("SPDXVersion:"):
        return "spdx-tag-value"

    # Filename hint as last resort.
    if filename:
        lower = filename.lower()
        if lower.endswith(".spdx"):
            return "spdx-tag-value"
        if lower.endswith(".cdx.xml") or lower.endswith(".bom.xml"):
            return "cyclonedx-xml"

    return "unknown"


def parse_sbom(raw: bytes, filename: str | None = None) -> ParseResult:
    """Parse an SBOM from raw bytes. Raises SbomParseError on failure.

    For CycloneDX, returns a CycloneDX-shaped dict (bomFormat, specVersion, ...).
    For SPDX, returns an SPDX-shaped dict (spdxVersion, packages, relationships).
    """
    kind = detect_sbom_kind(raw, filename=filename)
    if kind == "unknown":
        raise SbomParseError(
            "Could not determine SBOM format. Supported formats: CycloneDX "
            "(JSON/XML), SPDX (JSON or tag-value .spdx)."
        )

    if kind == "cyclonedx-json":
        return _parse_cdx_json(raw)
    if kind == "cyclonedx-xml":
        return _parse_cdx_xml(raw)
    if kind == "spdx-json":
        return _parse_spdx_json(raw)
    if kind == "spdx-3-json":
        raise SbomParseError(
            "SPDX 3.0 documents are detected but not yet supported. "
            "Export your SBOM in SPDX 2.3 or CycloneDX 1.5+ and re-upload."
        )
    if kind == "spdx-tag-value":
        return _parse_spdx_tag_value(raw)

    raise SbomParseError(f"Unhandled SBOM kind: {kind}")


def parse_sbom_file(path: Path) -> ParseResult:
    return parse_sbom(path.read_bytes(), filename=path.name)


# ---------------------------------------------------------------------------
# CycloneDX JSON


def _parse_cdx_json(raw: bytes) -> ParseResult:
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SbomParseError(f"Malformed CycloneDX JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(doc, dict):
        raise SbomParseError("CycloneDX JSON must be an object at the top level.")
    if doc.get("bomFormat") != "CycloneDX":
        raise SbomParseError("Missing or invalid 'bomFormat': expected 'CycloneDX'.")
    if not doc.get("specVersion"):
        raise SbomParseError("CycloneDX SBOM is missing 'specVersion'.")
    return ParseResult(sbom=doc, detected_kind="cyclonedx-json", format_family="cyclonedx", notes=[])


# ---------------------------------------------------------------------------
# CycloneDX XML  (minimal translator to the JSON shape)


def _parse_cdx_xml(raw: bytes) -> ParseResult:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise SbomParseError(f"Malformed CycloneDX XML: {exc}") from exc

    ns_match = _CDX_XML_NS_RE.search(root.tag) or (_CDX_XML_NS_RE.search("".join(root.attrib.values())))
    if not ns_match:
        raise SbomParseError("XML does not appear to be CycloneDX (no cyclonedx.org/schema/bom namespace).")
    spec_version = ns_match.group(1)

    def local(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    def text(elem, name: str) -> str:
        child = next((c for c in elem if local(c.tag) == name), None)
        return (child.text or "").strip() if child is not None and child.text else ""

    def supplier_name(elem) -> str:
        sup = next((c for c in elem if local(c.tag) == "supplier"), None)
        return text(sup, "name") if sup is not None else ""

    def build_component(elem) -> dict:
        component: dict = {
            "type": elem.attrib.get("type", "library"),
            "name": text(elem, "name"),
            "version": text(elem, "version"),
        }
        bom_ref = elem.attrib.get("bom-ref") or ""
        if bom_ref:
            component["bom-ref"] = bom_ref
        purl = text(elem, "purl")
        if purl:
            component["purl"] = purl
        cpe = text(elem, "cpe")
        if cpe:
            component["cpe"] = cpe
        sup = supplier_name(elem)
        if sup:
            component["supplier"] = {"name": sup}
        return component

    metadata_elem = next((c for c in root if local(c.tag) == "metadata"), None)
    metadata: dict = {}
    if metadata_elem is not None:
        ts = text(metadata_elem, "timestamp")
        if ts:
            metadata["timestamp"] = ts
        authors_elem = next((c for c in metadata_elem if local(c.tag) == "authors"), None)
        if authors_elem is not None:
            authors = [{"name": text(a, "name")} for a in authors_elem if local(a.tag) == "author"]
            if authors:
                metadata["authors"] = authors
        component_elem = next((c for c in metadata_elem if local(c.tag) == "component"), None)
        if component_elem is not None:
            metadata["component"] = build_component(component_elem)

    components_elem = next((c for c in root if local(c.tag) == "components"), None)
    components = (
        [build_component(c) for c in components_elem if local(c.tag) == "component"]
        if components_elem is not None
        else []
    )

    dependencies_elem = next((c for c in root if local(c.tag) == "dependencies"), None)
    dependencies: list[dict] = []
    if dependencies_elem is not None:
        for dep in dependencies_elem:
            if local(dep.tag) != "dependency":
                continue
            entry = {
                "ref": dep.attrib.get("ref", ""),
                "dependsOn": [child.attrib.get("ref", "") for child in dep if local(child.tag) == "dependency"],
            }
            dependencies.append(entry)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": root.attrib.get("serialNumber", ""),
        "version": int(root.attrib.get("version", "1") or "1"),
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }
    return ParseResult(
        sbom=doc,
        detected_kind="cyclonedx-xml",
        format_family="cyclonedx",
        notes=["Converted from CycloneDX XML to internal JSON representation."],
    )


# ---------------------------------------------------------------------------
# SPDX JSON


def _parse_spdx_json(raw: bytes) -> ParseResult:
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise SbomParseError(f"Malformed SPDX JSON: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(doc, dict):
        raise SbomParseError("SPDX JSON must be an object at the top level.")
    if not doc.get("spdxVersion"):
        raise SbomParseError("Missing 'spdxVersion' — not an SPDX document.")
    return ParseResult(sbom=doc, detected_kind="spdx-json", format_family="spdx", notes=[])


# ---------------------------------------------------------------------------
# SPDX tag-value (.spdx)


_SPDX_EXTERNAL_REF_RE = re.compile(r"^\s*(\S+)\s+(\S+)\s+(.+?)\s*$")


def _parse_spdx_tag_value(raw: bytes) -> ParseResult:
    text = raw.decode("utf-8-sig", errors="replace")
    lines = [line for line in text.splitlines()]

    doc: dict = {
        "spdxVersion": "",
        "SPDXID": "",
        "dataLicense": "",
        "name": "",
        "documentNamespace": "",
        "creationInfo": {"creators": [], "created": ""},
        "packages": [],
        "relationships": [],
    }
    current_pkg: dict | None = None

    def flush_pkg() -> None:
        nonlocal current_pkg
        if current_pkg is not None:
            doc["packages"].append(current_pkg)
            current_pkg = None

    notes: list[str] = []

    def field(line: str) -> tuple[str, str] | None:
        if ":" not in line:
            return None
        key, _, value = line.partition(":")
        return key.strip(), value.strip()

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parsed = field(line)
        if parsed is None:
            continue
        key, value = parsed

        if key == "PackageName":
            flush_pkg()
            current_pkg = {
                "name": value,
                "SPDXID": "",
                "versionInfo": "",
                "supplier": "",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [],
            }
            continue

        if current_pkg is not None:
            if key == "SPDXID":
                current_pkg["SPDXID"] = value
                continue
            if key == "PackageVersion":
                current_pkg["versionInfo"] = value
                continue
            if key == "PackageSupplier":
                current_pkg["supplier"] = value
                continue
            if key == "PackageDownloadLocation":
                current_pkg["downloadLocation"] = value
                continue
            if key == "FilesAnalyzed":
                current_pkg["filesAnalyzed"] = value.lower() == "true"
                continue
            if key == "PackageLicenseConcluded":
                current_pkg["licenseConcluded"] = value
                continue
            if key == "PackageLicenseDeclared":
                current_pkg["licenseDeclared"] = value
                continue
            if key == "ExternalRef":
                match = _SPDX_EXTERNAL_REF_RE.match(value)
                if match:
                    category, ref_type, locator = match.groups()
                    current_pkg["externalRefs"].append(
                        {
                            "referenceCategory": category,
                            "referenceType": ref_type,
                            "referenceLocator": locator,
                        }
                    )
                continue

        if key == "SPDXVersion":
            doc["spdxVersion"] = value
        elif key == "DataLicense":
            doc["dataLicense"] = value
        elif key == "SPDXID":
            doc["SPDXID"] = value
        elif key == "DocumentName":
            doc["name"] = value
        elif key == "DocumentNamespace":
            doc["documentNamespace"] = value
        elif key == "Creator":
            doc["creationInfo"]["creators"].append(value)
        elif key == "Created":
            doc["creationInfo"]["created"] = value
        elif key == "Relationship":
            parts = value.split()
            if len(parts) == 3:
                doc["relationships"].append(
                    {
                        "spdxElementId": parts[0],
                        "relationshipType": parts[1],
                        "relatedSpdxElement": parts[2],
                    }
                )
            else:
                notes.append(f"Skipped malformed Relationship line: {line!r}")

    flush_pkg()

    if not doc["spdxVersion"]:
        raise SbomParseError("SPDX tag-value file is missing 'SPDXVersion:'.")

    notes.append("Converted from SPDX tag-value (.spdx) to JSON representation.")
    return ParseResult(sbom=doc, detected_kind="spdx-tag-value", format_family="spdx", notes=notes)


__all__ = [
    "ParseResult",
    "SbomParseError",
    "detect_sbom_kind",
    "parse_sbom",
    "parse_sbom_file",
]
