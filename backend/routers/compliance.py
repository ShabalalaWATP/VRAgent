"""
Compliance & CVE Router

API endpoints for CVE lookups, CWE details, CVSS calculation,
and compliance framework mappings (OWASP, PCI-DSS, HIPAA).
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import logging

from backend.core.auth import get_current_active_user
from backend.models.models import User

from backend.services.cve_compliance_service import (
    # CWE
    get_cwe_details,
    get_cwes_for_technique,
    get_mitigations_for_technique,
    search_cwes,
    get_cwe_statistics,
    TECHNIQUE_CWE_MAPPING,
    
    # CVSS
    calculate_cvss_for_finding,
    parse_cvss_vector,
    calculate_cvss_score,
    
    # Compliance
    get_compliance_for_technique,
    get_all_compliance_frameworks,
    get_owasp_requirement,
    get_pci_dss_requirement,
    get_hipaa_requirement,
    
    # CVE
    search_cves_for_technique,
    get_cve_details,
    get_known_cves_for_technique,
    
    # Integration
    enrich_finding_sync,
    enrich_findings_batch,
    generate_security_report,
    get_compliance_summary_for_findings,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", tags=["Compliance & CVE"])


# =============================================================================
# REQUEST MODELS
# =============================================================================

class CVSSCalculateRequest(BaseModel):
    """Request to calculate CVSS score."""
    technique: str = Field(..., description="Fuzzing technique name")
    requires_auth: bool = Field(default=False, description="Requires authentication")
    requires_user_interaction: bool = Field(default=False, description="Requires user interaction")
    local_only: bool = Field(default=False, description="Only locally exploitable")


class CVSSVectorRequest(BaseModel):
    """Request to parse and calculate CVSS from vector string."""
    vector_string: str = Field(
        ..., 
        description="CVSS 3.1 vector string",
        examples=["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]
    )


class EnrichFindingRequest(BaseModel):
    """Request to enrich a finding."""
    finding: Dict = Field(..., description="Finding to enrich")
    technique: str = Field(..., description="Technique that found this issue")


class EnrichFindingsBatchRequest(BaseModel):
    """Request to enrich multiple findings."""
    findings: List[Dict] = Field(..., description="Findings to enrich")
    include_cves: bool = Field(default=False, description="Include CVE lookups (slower)")


class ComplianceSummaryRequest(BaseModel):
    """Request for compliance summary."""
    findings: List[Dict] = Field(..., description="Findings to analyze")


# =============================================================================
# CWE ENDPOINTS
# =============================================================================

@router.get("/cwe/{cwe_id}")
async def get_cwe_by_id(
    cwe_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get CWE details by ID (e.g., 'CWE-89' or '89')."""
    cwe = get_cwe_details(cwe_id)
    if not cwe:
        raise HTTPException(status_code=404, detail=f"CWE {cwe_id} not found")
    return cwe.to_dict()


@router.get("/cwe/technique/{technique}")
async def get_cwes_by_technique(
    technique: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get all CWEs associated with a fuzzing technique."""
    cwes = get_cwes_for_technique(technique)
    return {
        "technique": technique,
        "cwes": [cwe.to_dict() for cwe in cwes],
        "mitigations": get_mitigations_for_technique(technique),
    }


@router.get("/cwe/search")
async def search_cwe_database(
    q: str = Query(..., description="Search query"),
    current_user: User = Depends(get_current_active_user)
):
    """Search CWEs by name or description."""
    results = search_cwes(q)
    return {
        "query": q,
        "results": [cwe.to_dict() for cwe in results],
        "count": len(results),
    }


@router.get("/cwe/statistics")
async def get_cwe_stats(
    current_user: User = Depends(get_current_active_user)
):
    """Get CWE database statistics."""
    return get_cwe_statistics()


@router.get("/cwe/mappings")
async def get_technique_cwe_mappings(
    current_user: User = Depends(get_current_active_user)
):
    """Get all technique-to-CWE mappings."""
    return {
        "mappings": TECHNIQUE_CWE_MAPPING,
        "total_techniques": len(TECHNIQUE_CWE_MAPPING),
    }


# =============================================================================
# CVSS ENDPOINTS
# =============================================================================

@router.post("/cvss/calculate")
async def calculate_cvss(
    request: CVSSCalculateRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Calculate CVSS score for a technique with adjustments."""
    return calculate_cvss_for_finding(
        technique=request.technique,
        requires_auth=request.requires_auth,
        requires_user_interaction=request.requires_user_interaction,
        local_only=request.local_only,
    )


@router.post("/cvss/parse")
async def parse_cvss_vector_endpoint(
    request: CVSSVectorRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Parse CVSS vector string and calculate score."""
    vector = parse_cvss_vector(request.vector_string)
    if not vector:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid CVSS vector: {request.vector_string}"
        )
    
    score = calculate_cvss_score(vector)
    return {
        "input_vector": request.vector_string,
        "parsed_vector": vector.to_vector_string(),
        **score,
    }


# =============================================================================
# COMPLIANCE FRAMEWORK ENDPOINTS
# =============================================================================

@router.get("/frameworks")
async def get_frameworks(
    current_user: User = Depends(get_current_active_user)
):
    """Get all compliance frameworks with their requirements."""
    return get_all_compliance_frameworks()


@router.get("/frameworks/owasp")
async def get_owasp_top_10(
    current_user: User = Depends(get_current_active_user)
):
    """Get OWASP Top 10 2021 requirements."""
    frameworks = get_all_compliance_frameworks()
    return frameworks["OWASP_Top_10_2021"]


@router.get("/frameworks/owasp/{requirement_id}")
async def get_owasp_by_id(
    requirement_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get specific OWASP requirement (e.g., 'A01' or 'A01:2021')."""
    req = get_owasp_requirement(requirement_id)
    if not req:
        raise HTTPException(status_code=404, detail=f"OWASP requirement {requirement_id} not found")
    return req.to_dict()


@router.get("/frameworks/pci-dss")
async def get_pci_dss_requirements(
    current_user: User = Depends(get_current_active_user)
):
    """Get PCI-DSS 4.0 requirements."""
    frameworks = get_all_compliance_frameworks()
    return frameworks["PCI_DSS_4_0"]


@router.get("/frameworks/pci-dss/{requirement_id}")
async def get_pci_dss_by_id(
    requirement_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get specific PCI-DSS requirement (e.g., '6.5.1')."""
    req = get_pci_dss_requirement(requirement_id)
    if not req:
        raise HTTPException(status_code=404, detail=f"PCI-DSS requirement {requirement_id} not found")
    return req.to_dict()


@router.get("/frameworks/hipaa")
async def get_hipaa_requirements(
    current_user: User = Depends(get_current_active_user)
):
    """Get HIPAA Security Rule requirements."""
    frameworks = get_all_compliance_frameworks()
    return frameworks["HIPAA"]


@router.get("/frameworks/hipaa/{requirement_id}")
async def get_hipaa_by_id(
    requirement_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get specific HIPAA requirement."""
    req = get_hipaa_requirement(requirement_id)
    if not req:
        raise HTTPException(status_code=404, detail=f"HIPAA requirement {requirement_id} not found")
    return req.to_dict()


@router.get("/frameworks/technique/{technique}")
async def get_compliance_by_technique(
    technique: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get all compliance requirements for a fuzzing technique."""
    return {
        "technique": technique,
        "compliance": get_compliance_for_technique(technique),
    }


# =============================================================================
# CVE ENDPOINTS
# =============================================================================

@router.get("/cve/technique/{technique}")
async def get_cves_by_technique(
    technique: str,
    use_api: bool = Query(default=False, description="Query NVD API (slower)"),
    current_user: User = Depends(get_current_active_user)
):
    """Get known CVEs for a fuzzing technique."""
    if use_api:
        cves = await search_cves_for_technique(technique, use_api=True)
    else:
        cves = get_known_cves_for_technique(technique)
    
    return {
        "technique": technique,
        "cves": cves,
        "count": len(cves),
        "source": "nvd_api" if use_api else "local_cache",
    }


@router.get("/cve/{cve_id}")
async def get_cve_by_id(
    cve_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get CVE details from NVD API."""
    cve = await get_cve_details(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return cve


# =============================================================================
# FINDING ENRICHMENT ENDPOINTS
# =============================================================================

@router.post("/enrich/finding")
async def enrich_single_finding(
    request: EnrichFindingRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Enrich a single finding with CWE, CVSS, CVE, and compliance data."""
    enriched = enrich_finding_sync(request.finding, request.technique)
    return enriched


@router.post("/enrich/batch")
async def enrich_findings(
    request: EnrichFindingsBatchRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Enrich multiple findings with security data.
    
    Set include_cves=True to fetch CVE data from NVD API (slower).
    """
    enriched = await enrich_findings_batch(
        request.findings,
        include_cves=request.include_cves,
    )
    return {
        "findings": enriched,
        "count": len(enriched),
        "cves_included": request.include_cves,
    }


@router.post("/summary")
async def get_compliance_summary(
    request: ComplianceSummaryRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Generate compliance summary from findings."""
    return get_compliance_summary_for_findings(request.findings)


@router.post("/report")
async def generate_report(
    request: ComplianceSummaryRequest,
    include_compliance: bool = Query(default=True),
    current_user: User = Depends(get_current_active_user)
):
    """Generate comprehensive security report from findings."""
    return generate_security_report(
        request.findings,
        include_compliance=include_compliance,
    )
