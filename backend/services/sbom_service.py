"""
SBOM (Software Bill of Materials) generation service.
Supports CycloneDX and SPDX formats for compliance and supply chain security.
"""
import uuid
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from backend import models
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Package URL type mapping for ecosystems
ECOSYSTEM_PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Maven": "maven",
    "Go": "golang",
    "RubyGems": "gem",
    "crates.io": "cargo",
    "Packagist": "composer",
}


def _generate_purl(dep: models.Dependency) -> str:
    """Generate Package URL (purl) for a dependency."""
    purl_type = ECOSYSTEM_PURL_TYPE.get(dep.ecosystem, "generic")
    name = dep.name.replace("/", "%2F")
    version = dep.version or "unknown"
    return f"pkg:{purl_type}/{name}@{version}"


def _generate_bom_ref(dep: models.Dependency) -> str:
    """Generate a unique BOM reference for a component."""
    return f"{dep.ecosystem or 'unknown'}-{dep.name}-{dep.version or 'unknown'}"


def generate_cyclonedx(
    db: Session,
    project: models.Project,
    include_vulnerabilities: bool = True
) -> Dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM for a project."""
    dependencies = db.query(models.Dependency).filter(
        models.Dependency.project_id == project.id
    ).all()
    
    components = []
    for dep in dependencies:
        component = {
            "type": "library",
            "bom-ref": _generate_bom_ref(dep),
            "name": dep.name,
            "version": dep.version or "unknown",
            "purl": _generate_purl(dep),
        }
        if dep.ecosystem:
            component["group"] = dep.ecosystem
        if dep.manifest_path:
            component["evidence"] = {"occurrences": [{"location": dep.manifest_path}]}
        components.append(component)
    
    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": {"components": [{"type": "application", "name": "VRAgent", "version": "1.0.0"}]},
            "component": {"type": "application", "name": project.name, "description": project.description or ""}
        },
        "components": components,
    }
    
    if include_vulnerabilities:
        vulns = db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project.id).all()
        if vulns:
            vuln_list = []
            for vuln in vulns:
                affected = []
                if vuln.dependency:
                    affected.append({"ref": _generate_bom_ref(vuln.dependency)})
                entry = {
                    "id": vuln.external_id or f"VRAGENT-{vuln.id}",
                    "source": {"name": vuln.source or "OSV"},
                    "description": vuln.description or vuln.title,
                    "affects": affected,
                }
                if vuln.cvss_score:
                    entry["ratings"] = [{"score": vuln.cvss_score, "severity": vuln.severity, "method": "CVSSv3"}]
                vuln_list.append(entry)
            sbom["vulnerabilities"] = vuln_list
    
    logger.info(f"Generated CycloneDX SBOM for project {project.id} with {len(components)} components")
    return sbom


def generate_spdx(db: Session, project: models.Project) -> Dict[str, Any]:
    """Generate an SPDX 2.3 SBOM for a project."""
    dependencies = db.query(models.Dependency).filter(models.Dependency.project_id == project.id).all()
    
    packages = [{
        "SPDXID": "SPDXRef-RootPackage",
        "name": project.name,
        "versionInfo": "1.0.0",
        "downloadLocation": project.git_url or "NOASSERTION",
        "filesAnalyzed": False,
        "primaryPackagePurpose": "APPLICATION",
    }]
    
    relationships = []
    for idx, dep in enumerate(dependencies):
        spdx_id = f"SPDXRef-Package-{idx}"
        packages.append({
            "SPDXID": spdx_id,
            "name": dep.name,
            "versionInfo": dep.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": _generate_purl(dep)}],
            "primaryPackagePurpose": "LIBRARY",
            "supplier": f"Organization: {dep.ecosystem}" if dep.ecosystem else "NOASSERTION",
        })
        relationships.append({"spdxElementId": "SPDXRef-RootPackage", "relatedSpdxElement": spdx_id, "relationshipType": "DEPENDS_ON"})
    
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM for {project.name}",
        "documentNamespace": f"https://vragent.local/spdx/{project.id}/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.utcnow().isoformat() + "Z",
            "creators": ["Tool: VRAgent-1.0.0"],
            "licenseListVersion": "3.21"
        },
        "packages": packages,
        "relationships": relationships,
    }
    
    logger.info(f"Generated SPDX SBOM for project {project.id} with {len(packages)-1} packages")
    return sbom


def get_sbom(db: Session, project_id: int, sbom_format: str = "cyclonedx", include_vulnerabilities: bool = True) -> Dict[str, Any]:
    """Generate SBOM for a project in the specified format."""
    project = db.get(models.Project, project_id)
    if not project:
        raise ValueError(f"Project {project_id} not found")
    
    if sbom_format.lower() == "cyclonedx":
        return generate_cyclonedx(db, project, include_vulnerabilities)
    elif sbom_format.lower() == "spdx":
        return generate_spdx(db, project)
    else:
        raise ValueError(f"Unsupported SBOM format: {sbom_format}. Use 'cyclonedx' or 'spdx'")
