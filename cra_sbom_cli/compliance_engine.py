from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass
class CheckResult:
    requirement: str
    title: str
    status: str
    detail: str
    evidence: list[str] | None = None


def _cdx_label(item: dict) -> str:
    name = item.get("name") or "<unnamed>"
    version = item.get("version") or "<no-version>"
    identifier = item.get("purl") or item.get("cpe") or item.get("bom-ref") or "<no-id>"
    return f"{name}@{version} [{identifier}]"


def _spdx_label(item: dict) -> str:
    name = item.get("name") or "<unnamed>"
    version = item.get("versionInfo") or "<no-version>"
    identifier = item.get("SPDXID") or "<no-spdxid>"
    return f"{name}@{version} [{identifier}]"


def _is_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


_VERSION_NUMERIC_RE = re.compile(r"^\d+")

# Allowlist of hash algorithms considered strong enough for tamper-evidence
# in a CRA-aligned SBOM. Anything else (MD5, SHA-1, CRC, etc.) is a FAIL.
# Algorithm names are normalized to upper-case for comparison and the "SHA-"
# prefix is tolerated on either side of the comparison.
_STRONG_HASH_ALGORITHMS = frozenset(
    {
        "SHA-256", "SHA256",
        "SHA-384", "SHA384",
        "SHA-512", "SHA512",
        "SHA3-256", "SHA3-384", "SHA3-512",
        "BLAKE2B-256", "BLAKE2B-384", "BLAKE2B-512",
        "BLAKE3",
    }
)


def _hash_algorithm_is_strong(alg: str) -> bool:
    if not alg:
        return False
    return alg.strip().upper().replace("_", "-") in _STRONG_HASH_ALGORITHMS


def _version_ge(left: str, right: str) -> bool:
    """Compare two major.minor version strings, tolerating pre-release suffixes.

    "1.5", "1.5.0", "1.5.1-beta", "1.5-rc1" all parse as (1, 5).
    Returns False only when the left side has no leading numeric parts.
    """

    def head(value: str) -> tuple[int, int]:
        parts: list[int] = []
        for chunk in value.split(".")[:2]:
            match = _VERSION_NUMERIC_RE.match(chunk)
            if not match:
                break
            parts.append(int(match.group(0)))
        if not parts:
            return (-1, -1)
        if len(parts) == 1:
            parts.append(0)
        return (parts[0], parts[1])

    left_head = head(left)
    right_head = head(right)
    if left_head == (-1, -1):
        return False
    return left_head >= right_head


def _warn(requirement: str, title: str, detail: str, evidence: list[str] | None = None) -> CheckResult:
    return CheckResult(requirement, title, "WARN", detail, evidence)


def _validate_cyclonedx_structure(sbom: dict) -> CheckResult:
    required = []
    if sbom.get("bomFormat") != "CycloneDX":
        required.append("bomFormat=CycloneDX")
    if not sbom.get("specVersion"):
        required.append("specVersion")
    if not isinstance(sbom.get("metadata"), dict):
        required.append("metadata")
    if "components" in sbom and not isinstance(sbom.get("components"), list):
        required.append("components(array)")
    if "dependencies" in sbom and not isinstance(sbom.get("dependencies"), list):
        required.append("dependencies(array)")
    if required:
        return CheckResult("PRE-7-RQ-04", "CycloneDX Structural Validation", "FAIL", f"Missing or invalid fields: {', '.join(required)}")
    return CheckResult("PRE-7-RQ-04", "CycloneDX Structural Validation", "PASS", "Basic CycloneDX structure is valid")


def _validate_spdx_structure(sbom: dict) -> CheckResult:
    required = []
    if not sbom.get("spdxVersion"):
        required.append("spdxVersion")
    if not sbom.get("SPDXID"):
        required.append("SPDXID")
    if not sbom.get("dataLicense"):
        required.append("dataLicense")
    if not isinstance(sbom.get("creationInfo"), dict):
        required.append("creationInfo")
    if "packages" in sbom and not isinstance(sbom.get("packages"), list):
        required.append("packages(array)")
    if "relationships" in sbom and not isinstance(sbom.get("relationships"), list):
        required.append("relationships(array)")
    if required:
        return CheckResult("PRE-7-RQ-04", "SPDX Structural Validation", "FAIL", f"Missing or invalid fields: {', '.join(required)}")
    return CheckResult("PRE-7-RQ-04", "SPDX Structural Validation", "PASS", "Basic SPDX structure is valid")


def _get_cdx_component_ref(component: dict) -> str:
    return component.get("bom-ref") or component.get("purl") or component.get("cpe") or ""


def _extract_spdx_document_version(sbom: dict) -> str:
    annotation_hits = [
        item.get("comment", "")
        for item in sbom.get("annotations") or []
        if "sbom version:" in (item.get("comment", "").lower())
    ]
    if annotation_hits:
        return annotation_hits[0]
    for key in ("documentVersion", "sbomVersion"):
        if sbom.get(key):
            return str(sbom.get(key))
    return ""


def _check_cyclonedx(sbom: dict, enhanced_mode: bool) -> tuple[list[CheckResult], list[str]]:
    checks: list[CheckResult] = []
    manual: list[str] = []

    checks.append(_validate_cyclonedx_structure(sbom))

    version = str(sbom.get("specVersion", ""))
    if version and _version_ge(version, "1.4"):
        checks.append(CheckResult("PRE-7-RQ-04", "CycloneDX Version", "PASS", f"{version} >= 1.4"))
    else:
        checks.append(CheckResult("PRE-7-RQ-04", "CycloneDX Version", "FAIL", f"Invalid or old version: {version}"))

    metadata = sbom.get("metadata", {})
    authors = metadata.get("authors") or []
    author = ""
    if authors and isinstance(authors, list):
        author = authors[0].get("name", "")
    if not author:
        author = metadata.get("manufacturer", {}).get("name", "") or metadata.get("supplier", {}).get("name", "")

    if author:
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Author", "PASS", author))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Author", "FAIL", "Missing metadata authors/manufacturer/supplier"))

    timestamp = metadata.get("timestamp", "")
    if timestamp and _is_iso8601(timestamp):
        checks.append(CheckResult("PRE-7-RQ-06", "Timestamp", "PASS", timestamp))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "Timestamp", "FAIL", "Missing or invalid ISO8601 timestamp"))

    document_version = sbom.get("version")
    if document_version not in (None, ""):
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Document Version", "PASS", f"Document version present: {document_version}"))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Document Version", "FAIL", "Missing SBOM document version"))

    root = metadata.get("component") or {}
    if root.get("name") and root.get("version"):
        checks.append(CheckResult("PRE-7-RQ-06", "Primary Component", "PASS", f"{root['name']}@{root['version']}"))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "Primary Component", "FAIL", "Missing root component name/version"))

    components = sbom.get("components") or []
    if not components:
        checks.append(CheckResult("PRE-7-RQ-02", "Component List", "FAIL", "No components found"))
    else:
        checks.append(CheckResult("PRE-7-RQ-02", "Component List", "PASS", f"{len(components)} components"))

    missing_name = [item for item in components if not item.get("name")]
    missing_version = [item for item in components if not item.get("version")]
    missing_supplier = [item for item in components if not (item.get("supplier", {}) or {}).get("name")]
    missing_id = [
        item
        for item in components
        if not item.get("purl") and not item.get("cpe") and not item.get("bom-ref")
    ]

    checks.append(
        CheckResult(
            "PRE-7-RQ-02",
            "Component Names",
            "PASS" if not missing_name else "FAIL",
            "All components named" if not missing_name else f"{len(missing_name)} missing names",
            None if not missing_name else [_cdx_label(item) for item in missing_name],
        )
    )
    checks.append(
        CheckResult(
            "PRE-7-RQ-02",
            "Component Versions",
            "PASS" if not missing_version else "FAIL",
            "All components versioned" if not missing_version else f"{len(missing_version)} missing versions",
            None if not missing_version else [_cdx_label(item) for item in missing_version],
        )
    )
    checks.append(
        CheckResult(
            "PRE-7-RQ-02",
            "Component Supplier",
            "PASS" if not missing_supplier else "FAIL",
            "All components have supplier" if not missing_supplier else f"{len(missing_supplier)} missing supplier",
            None if not missing_supplier else [_cdx_label(item) for item in missing_supplier],
        )
    )
    checks.append(
        CheckResult(
            "PRE-7-RQ-07",
            "Unique Identifier",
            "PASS" if not missing_id else "FAIL",
            "All components have purl/cpe/bom-ref" if not missing_id else f"{len(missing_id)} missing identifiers",
            None if not missing_id else [_cdx_label(item) for item in missing_id],
        )
    )

    dependencies = sbom.get("dependencies") or []
    if dependencies:
        checks.append(CheckResult("PRE-7-RQ-03", "Dependency Graph", "PASS", f"{len(dependencies)} entries"))
    else:
        checks.append(CheckResult("PRE-7-RQ-03", "Dependency Graph", "FAIL", "No dependency graph found"))

    component_refs = {ref for ref in (_get_cdx_component_ref(item) for item in components) if ref}
    root_ref = _get_cdx_component_ref(root)
    if root_ref:
        component_refs.add(root_ref)

    dependency_refs = set()
    unknown_refs: list[str] = []
    for relation in dependencies:
        ref = relation.get("ref")
        if ref:
            dependency_refs.add(ref)
            if ref not in component_refs:
                unknown_refs.append(ref)
        for dep in relation.get("dependsOn") or []:
            dependency_refs.add(dep)
            if dep not in component_refs:
                unknown_refs.append(dep)

    orphan_components = sorted(ref for ref in component_refs if ref and ref not in dependency_refs and ref != root_ref)
    if not unknown_refs:
        checks.append(CheckResult("PRE-7-RQ-07", "Dependency Reference Integrity", "PASS", "All dependency references resolve to known components"))
    else:
        checks.append(CheckResult("PRE-7-RQ-07", "Dependency Reference Integrity", "FAIL", f"{len(unknown_refs)} dependency reference(s) do not resolve to known components", sorted(set(unknown_refs))[:25]))

    if not orphan_components:
        checks.append(CheckResult("PRE-7-RQ-07", "Component Relationship Coverage", "PASS", "All non-root components participate in dependency relationships"))
    else:
        checks.append(CheckResult("PRE-7-RQ-07", "Component Relationship Coverage", "FAIL", f"{len(orphan_components)} non-root component(s) are not connected in dependency relationships", orphan_components[:25]))

    if enhanced_mode:
        hashes_without_algorithm = [
            _cdx_label(item)
            for item in components
            if item.get("hashes") and any(not hash_item.get("alg") for hash_item in item.get("hashes") or [])
        ]
        if hashes_without_algorithm:
            checks.append(CheckResult("PRE-7-RQ-07-RE", "Supplier Hash Algorithm", "FAIL", f"{len(hashes_without_algorithm)} component(s) include hashes without an algorithm", hashes_without_algorithm[:25]))
        else:
            checks.append(CheckResult("PRE-7-RQ-07-RE", "Supplier Hash Algorithm", "PASS", "All present hashes include an algorithm"))

        weak_hash_hits: list[str] = []
        for item in components:
            for hash_item in item.get("hashes") or []:
                alg = hash_item.get("alg")
                if alg and not _hash_algorithm_is_strong(alg):
                    weak_hash_hits.append(f"{_cdx_label(item)} uses {alg}")
        if weak_hash_hits:
            checks.append(
                CheckResult(
                    "PRE-7-RQ-07-RE",
                    "Supplier Hash Strength",
                    "FAIL",
                    f"{len(weak_hash_hits)} component hash(es) use algorithms below SHA-256.",
                    weak_hash_hits[:25],
                )
            )
        else:
            checks.append(
                CheckResult(
                    "PRE-7-RQ-07-RE",
                    "Supplier Hash Strength",
                    "PASS",
                    "All present hashes use SHA-256 or stronger.",
                )
            )

        components_with_hashes = [item for item in components if item.get("hashes")]
        if components_with_hashes:
            checks.append(_warn("PRE-7-RQ-07-RE", "Supplier Hash Coverage", f"{len(components_with_hashes)}/{len(components)} components include hashes. CRA requires hashes when supplier-provided, which cannot be fully proven from SBOM content alone."))
        else:
            checks.append(_warn("PRE-7-RQ-07-RE", "Supplier Hash Coverage", "No component hashes present. This is not an automatic failure unless supplier-provided hashes were available."))
        manual.append("Transitive dependency completeness still requires build/manifest evidence review")

    checks.append(_warn("PRE-7-RQ-05", "Per-build / per-release regeneration", "Cannot be proven from SBOM content alone; requires CI/CD or release evidence."))
    checks.append(_warn("5.3.8.5", "Asset-to-SBOM completeness", "Full completeness cannot be proven from SBOM content alone without asset/build comparison evidence."))

    return checks, manual


def _check_spdx(sbom: dict, enhanced_mode: bool) -> tuple[list[CheckResult], list[str]]:
    checks: list[CheckResult] = []
    manual: list[str] = []

    checks.append(_validate_spdx_structure(sbom))

    version = str(sbom.get("spdxVersion", ""))
    normalized = version.replace("SPDX-", "")
    if normalized and _version_ge(normalized, "2.3"):
        checks.append(CheckResult("PRE-7-RQ-04", "SPDX Version", "PASS", version))
    else:
        checks.append(CheckResult("PRE-7-RQ-04", "SPDX Version", "FAIL", f"Invalid or old version: {version}"))

    creators = (sbom.get("creationInfo") or {}).get("creators") or []
    author = creators[0] if creators else ""
    if author:
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Author", "PASS", author))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Author", "FAIL", "Missing creationInfo.creators"))

    timestamp = (sbom.get("creationInfo") or {}).get("created", "")
    if timestamp and _is_iso8601(timestamp):
        checks.append(CheckResult("PRE-7-RQ-06", "Timestamp", "PASS", timestamp))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "Timestamp", "FAIL", "Missing or invalid ISO8601 timestamp"))

    document_version = _extract_spdx_document_version(sbom)
    if document_version:
        checks.append(CheckResult("PRE-7-RQ-06", "SBOM Document Version", "PASS", f"Document version present: {document_version}"))
    else:
        checks.append(_warn("PRE-7-RQ-06", "SBOM Document Version", "SPDX has no universal native document version field; use a governed custom property or annotation."))

    if sbom.get("name") and sbom.get("documentNamespace"):
        checks.append(CheckResult("PRE-7-RQ-06", "Document Metadata", "PASS", "Name and namespace present"))
    else:
        checks.append(CheckResult("PRE-7-RQ-06", "Document Metadata", "FAIL", "Missing name or namespace"))

    packages = sbom.get("packages") or []
    if not packages:
        checks.append(CheckResult("PRE-7-RQ-02", "Package List", "FAIL", "No packages found"))
    else:
        checks.append(CheckResult("PRE-7-RQ-02", "Package List", "PASS", f"{len(packages)} packages"))

    missing_version = [item for item in packages if not item.get("versionInfo")]
    missing_supplier = [item for item in packages if not item.get("supplier") or item.get("supplier") == "NOASSERTION"]
    missing_id = [
        item
        for item in packages
        if not any((ref.get("referenceType") in {"purl", "cpe23Type", "swh"}) for ref in item.get("externalRefs") or [])
    ]

    checks.append(
        CheckResult(
            "PRE-7-RQ-02",
            "Package Versions",
            "PASS" if not missing_version else "FAIL",
            "All packages versioned" if not missing_version else f"{len(missing_version)} missing versions",
            None if not missing_version else [_spdx_label(item) for item in missing_version],
        )
    )
    checks.append(
        CheckResult(
            "PRE-7-RQ-02",
            "Package Supplier",
            "PASS" if not missing_supplier else "FAIL",
            "All packages have supplier" if not missing_supplier else f"{len(missing_supplier)} missing supplier",
            None if not missing_supplier else [_spdx_label(item) for item in missing_supplier],
        )
    )
    checks.append(
        CheckResult(
            "PRE-7-RQ-07",
            "Unique Identifier",
            "PASS" if not missing_id else "FAIL",
            "All packages have external identifiers" if not missing_id else f"{len(missing_id)} missing identifiers",
            None if not missing_id else [_spdx_label(item) for item in missing_id],
        )
    )

    relationships = sbom.get("relationships") or []
    if relationships:
        checks.append(CheckResult("PRE-7-RQ-03", "Dependency Relationships", "PASS", f"{len(relationships)} relationships"))
    else:
        checks.append(CheckResult("PRE-7-RQ-03", "Dependency Relationships", "FAIL", "No relationships found"))

    package_ids = {item.get("SPDXID") for item in packages if item.get("SPDXID")}
    relationship_ids = set()
    unresolved_refs: list[str] = []
    for relation in relationships:
        left = relation.get("spdxElementId")
        right = relation.get("relatedSpdxElement")
        if left and left != "SPDXRef-DOCUMENT":
            relationship_ids.add(left)
            if left not in package_ids:
                unresolved_refs.append(left)
        if right and right != "SPDXRef-DOCUMENT":
            relationship_ids.add(right)
            if right not in package_ids:
                unresolved_refs.append(right)

    orphan_packages = sorted(package_id for package_id in package_ids if package_id not in relationship_ids)
    if not unresolved_refs:
        checks.append(CheckResult("PRE-7-RQ-07", "Relationship Reference Integrity", "PASS", "All SPDX relationships resolve to known packages"))
    else:
        checks.append(CheckResult("PRE-7-RQ-07", "Relationship Reference Integrity", "FAIL", f"{len(unresolved_refs)} SPDX relationship reference(s) do not resolve to known packages", sorted(set(unresolved_refs))[:25]))

    if not orphan_packages:
        checks.append(CheckResult("PRE-7-RQ-07", "Package Relationship Coverage", "PASS", "All packages participate in SPDX relationships"))
    else:
        checks.append(CheckResult("PRE-7-RQ-07", "Package Relationship Coverage", "FAIL", f"{len(orphan_packages)} package(s) are not connected in SPDX relationships", orphan_packages[:25]))

    if enhanced_mode:
        checksums_without_algorithm = [
            _spdx_label(item)
            for item in packages
            if item.get("checksums") and any(not checksum.get("algorithm") for checksum in item.get("checksums") or [])
        ]
        if checksums_without_algorithm:
            checks.append(CheckResult("PRE-7-RQ-07-RE", "Supplier Hash Algorithm", "FAIL", f"{len(checksums_without_algorithm)} package(s) include checksums without an algorithm", checksums_without_algorithm[:25]))
        else:
            checks.append(CheckResult("PRE-7-RQ-07-RE", "Supplier Hash Algorithm", "PASS", "All present checksums include an algorithm"))

        weak_spdx_hits: list[str] = []
        for item in packages:
            for checksum in item.get("checksums") or []:
                alg = checksum.get("algorithm")
                if alg and not _hash_algorithm_is_strong(alg):
                    weak_spdx_hits.append(f"{_spdx_label(item)} uses {alg}")
        if weak_spdx_hits:
            checks.append(
                CheckResult(
                    "PRE-7-RQ-07-RE",
                    "Supplier Hash Strength",
                    "FAIL",
                    f"{len(weak_spdx_hits)} package checksum(s) use algorithms below SHA-256.",
                    weak_spdx_hits[:25],
                )
            )
        else:
            checks.append(
                CheckResult(
                    "PRE-7-RQ-07-RE",
                    "Supplier Hash Strength",
                    "PASS",
                    "All present checksums use SHA-256 or stronger.",
                )
            )

        packages_with_checksums = [item for item in packages if item.get("checksums")]
        if packages_with_checksums:
            checks.append(_warn("PRE-7-RQ-07-RE", "Supplier Hash Coverage", f"{len(packages_with_checksums)}/{len(packages)} packages include checksums. CRA requires hashes when supplier-provided, which cannot be fully proven from SBOM content alone."))
        else:
            checks.append(_warn("PRE-7-RQ-07-RE", "Supplier Hash Coverage", "No package checksums present. This is not an automatic failure unless supplier-provided hashes were available."))
        manual.append("Transitive dependency completeness still requires build/manifest evidence review")

    checks.append(_warn("PRE-7-RQ-05", "Per-build / per-release regeneration", "Cannot be proven from SBOM content alone; requires CI/CD or release evidence."))
    checks.append(_warn("5.3.8.5", "Asset-to-SBOM completeness", "Full completeness cannot be proven from SBOM content alone without asset/build comparison evidence."))
    manual.append("SPDX document version convention should be defined and governed in process evidence")
    return checks, manual


def _detect_component_count(sbom: dict) -> int:
    if sbom.get("bomFormat") == "CycloneDX":
        return len(sbom.get("components") or [])
    if sbom.get("spdxVersion"):
        return len(sbom.get("packages") or [])
    return 0


def _is_spdx_3_doc(sbom: dict) -> bool:
    context = sbom.get("@context")
    if isinstance(context, str) and "spdx.org" in context.lower():
        return True
    if isinstance(context, list) and any("spdx.org" in str(item).lower() for item in context):
        return True
    return False


def evaluate_cra_compliance(sbom: dict, enhanced_mode: bool = False) -> dict:
    from . import evidence_catalogue

    checks: list[CheckResult] = []
    manual = [
        "Per-release/per-build SBOM regeneration must be evidenced by CI/CD records",
        "Error correction and revised SBOM publication must be demonstrated by process evidence",
        "CSAF/VEX publication should be assessed separately for enhanced products",
    ]
    hard_fail_reason: str | None = None

    if sbom.get("bomFormat") == "CycloneDX":
        format_checks, format_manual = _check_cyclonedx(sbom, enhanced_mode)
        checks.extend(format_checks)
        manual.extend(format_manual)
        sbom_format = "cyclonedx"
    elif sbom.get("spdxVersion"):
        format_checks, format_manual = _check_spdx(sbom, enhanced_mode)
        checks.extend(format_checks)
        manual.extend(format_manual)
        sbom_format = "spdx"
    elif _is_spdx_3_doc(sbom):
        checks.append(
            CheckResult(
                "PRE-7-RQ-04",
                "SBOM Format",
                "FAIL",
                "SPDX 3.0 documents are not yet supported. Re-export in SPDX 2.3 or CycloneDX 1.5+.",
            )
        )
        sbom_format = "spdx-3"
        hard_fail_reason = "spdx-3-not-supported"
    else:
        checks.append(
            CheckResult(
                "PRE-7-RQ-04",
                "SBOM Format",
                "FAIL",
                "Unrecognized SBOM format. Expected CycloneDX (bomFormat) or SPDX (spdxVersion).",
            )
        )
        sbom_format = "unknown"
        hard_fail_reason = "unknown-format"

    component_count = _detect_component_count(sbom)
    if sbom_format in ("cyclonedx", "spdx") and component_count == 0:
        checks.append(
            CheckResult(
                "PRE-7-RQ-02",
                "Non-empty Inventory",
                "FAIL",
                "SBOM contains zero components/packages. A compliant SBOM must enumerate the product inventory.",
            )
        )
        hard_fail_reason = hard_fail_reason or "empty-inventory"

    passed = len([item for item in checks if item.status == "PASS"])
    failed = len([item for item in checks if item.status == "FAIL"])
    warnings = len([item for item in checks if item.status == "WARN"])

    if hard_fail_reason is not None:
        verdict = "FAIL"
    else:
        verdict = "PASS" if failed == 0 else "FAIL"

    manual_items_structured = [
        item.as_dict() for item in evidence_catalogue.items_for_format(sbom_format, enhanced_mode)
    ]

    return {
        "format": sbom_format,
        "verdict": verdict,
        "hard_fail_reason": hard_fail_reason,
        "component_count": component_count,
        "assessment_scope": "sbom-content-only",
        "assessment_statement": "This result reflects automated CRA-aligned SBOM content checks. It is not a full CRA conformity determination and does not prove lifecycle or process compliance on its own.",
        "confidence": "content-only",
        "counts": {
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            # We now report the catalogue-backed count so the UI metric matches
            # the number of requirement cards actually shown.
            "manual_items": len(manual_items_structured),
        },
        "checks": [item.__dict__ for item in checks],
        # Backwards-compat string list for existing stored reports / old UIs.
        "manual_evidence": manual,
        # New structured form with stable ids + normative basis. Future clients
        # should prefer this over manual_evidence.
        "manual_evidence_items": manual_items_structured,
        "normative_basis": [
            "EU CRA Regulation (EU) 2024/2847",
            "prEN 40000-1-3:2025",
            "BSI TR-03183-2 v2.1.0",
        ],
    }
