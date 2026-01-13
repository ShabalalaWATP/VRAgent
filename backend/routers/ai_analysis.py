"""
AI Security Analysis Router

Provides REST API endpoints for AI-powered security analysis:
- Exploit chain analysis
- Root cause analysis
- Impact assessment
- Remediation prioritization
- Comprehensive analysis
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime

from backend.services.ai_security_analysis_service import (
    get_chain_analyzer,
    get_root_cause_analyzer,
    get_impact_assessor,
    get_prioritizer,
    analyze_findings_comprehensive,
)

router = APIRouter(prefix="/ai-analysis")


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class Finding(BaseModel):
    """A security finding to analyze."""
    id: str = Field(..., description="Unique finding identifier")
    technique: str = Field(..., description="Vulnerability technique (e.g., sql_injection)")
    severity: str = Field("medium", description="Severity level: critical, high, medium, low, info")
    url: Optional[str] = Field(None, description="Affected URL/endpoint")
    parameter: Optional[str] = Field(None, description="Affected parameter")
    payload: Optional[str] = Field(None, description="Exploit payload used")
    description: Optional[str] = Field(None, description="Finding description")


class AnalyzeFindingsRequest(BaseModel):
    """Request to analyze findings."""
    findings: List[Finding] = Field(..., min_items=1)


class BusinessContext(BaseModel):
    """Business context for impact assessment."""
    data_sensitivity: str = Field("medium", description="Data sensitivity: high, medium, low")
    system_criticality: str = Field("medium", description="System criticality: critical, high, medium, low")
    industry: Optional[str] = Field(None, description="Industry sector")
    compliance_frameworks: Optional[List[str]] = Field(None, description="Applicable frameworks")


class ImpactRequest(BaseModel):
    """Request for impact assessment."""
    findings: List[Finding]
    business_context: Optional[BusinessContext] = None


class ComprehensiveAnalysisRequest(BaseModel):
    """Request for comprehensive analysis."""
    findings: List[Finding] = Field(..., min_items=1)
    business_context: Optional[BusinessContext] = None
    include_chains: bool = Field(True, description="Include exploit chain analysis")
    include_root_causes: bool = Field(True, description="Include root cause analysis")
    include_impact: bool = Field(True, description="Include impact assessment")
    include_remediation: bool = Field(True, description="Include remediation plan")


# =============================================================================
# EXPLOIT CHAIN ENDPOINTS
# =============================================================================

@router.post("/exploit-chains")
async def analyze_exploit_chains(request: AnalyzeFindingsRequest) -> Dict:
    """
    Analyze findings to identify potential exploit chains.
    
    An exploit chain is a sequence of vulnerabilities that can be
    combined to achieve greater impact than individual vulnerabilities.
    """
    try:
        findings = [f.model_dump() for f in request.findings]
        analyzer = get_chain_analyzer()
        chains = analyzer.analyze_findings(findings)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "findings_analyzed": len(findings),
            "chains_identified": len(chains),
            "exploit_chains": [c.to_dict() for c in chains],
            "summary": {
                "highest_risk_chain": chains[0].to_dict() if chains else None,
                "total_chains": len(chains),
                "max_impact_score": max((c.total_impact_score for c in chains), default=0),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exploit-chains/relationships")
async def get_chain_relationships() -> Dict:
    """Get the known technique chain relationships."""
    from services.ai_security_analysis_service import ExploitChainAnalyzer
    
    return {
        "status": "success",
        "chain_relationships": ExploitChainAnalyzer.CHAIN_RELATIONSHIPS,
        "impact_multipliers": {
            f"{k[0]} -> {k[1]}": v 
            for k, v in ExploitChainAnalyzer.CHAIN_IMPACT_MULTIPLIERS.items()
        },
    }


# =============================================================================
# ROOT CAUSE ENDPOINTS
# =============================================================================

@router.post("/root-causes")
async def analyze_root_causes(request: AnalyzeFindingsRequest) -> Dict:
    """
    Analyze findings to identify root causes.
    
    Multiple findings often share the same underlying root cause.
    Fixing the root cause resolves multiple vulnerabilities.
    """
    try:
        findings = [f.model_dump() for f in request.findings]
        analyzer = get_root_cause_analyzer()
        root_causes = analyzer.analyze_findings(findings)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "findings_analyzed": len(findings),
            "root_causes_identified": len(root_causes),
            "root_causes": [rc.to_dict() for rc in root_causes],
            "summary": {
                "primary_root_cause": root_causes[0].to_dict() if root_causes else None,
                "total_findings_covered": sum(len(rc.affected_findings) for rc in root_causes),
                "fix_complexity_distribution": {
                    "Low": len([rc for rc in root_causes if rc.fix_complexity == "Low"]),
                    "Medium": len([rc for rc in root_causes if rc.fix_complexity == "Medium"]),
                    "High": len([rc for rc in root_causes if rc.fix_complexity == "High"]),
                },
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/root-causes/categories")
async def get_root_cause_categories() -> Dict:
    """Get available root cause categories."""
    from services.ai_security_analysis_service import RootCauseCategory
    
    return {
        "status": "success",
        "categories": [
            {
                "value": cat.value,
                "name": cat.name.replace("_", " ").title(),
            }
            for cat in RootCauseCategory
        ],
    }


# =============================================================================
# IMPACT ASSESSMENT ENDPOINTS
# =============================================================================

@router.post("/impact")
async def assess_impact(request: ImpactRequest) -> Dict:
    """
    Assess the business and technical impact of findings.
    
    Optionally provide business context to get more accurate
    business impact scores.
    """
    try:
        findings = [f.model_dump() for f in request.findings]
        business_ctx = request.business_context.model_dump() if request.business_context else None
        
        assessor = get_impact_assessor()
        results = assessor.assess_findings_batch(findings, business_ctx)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            **results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/impact/single")
async def assess_single_impact(
    finding: Finding,
    business_context: Optional[BusinessContext] = None,
) -> Dict:
    """Assess impact of a single finding."""
    try:
        finding_dict = finding.model_dump()
        business_ctx = business_context.model_dump() if business_context else None
        
        assessor = get_impact_assessor()
        assessment = assessor.assess_finding(finding_dict, business_ctx)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "assessment": assessment.to_dict(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/impact/categories")
async def get_impact_categories() -> Dict:
    """Get available impact categories."""
    from services.ai_security_analysis_service import ImpactCategory
    
    return {
        "status": "success",
        "categories": [
            {
                "value": cat.value,
                "name": cat.name.replace("_", " ").title(),
            }
            for cat in ImpactCategory
        ],
    }


# =============================================================================
# REMEDIATION ENDPOINTS
# =============================================================================

@router.post("/remediation")
async def prioritize_remediation(request: AnalyzeFindingsRequest) -> Dict:
    """
    Generate a prioritized remediation plan.
    
    Prioritizes fixes based on:
    - Risk score
    - Fix effort
    - Number of findings addressed
    - Dependencies
    """
    try:
        findings = [f.model_dump() for f in request.findings]
        prioritizer = get_prioritizer()
        items = prioritizer.prioritize(findings)
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "findings_analyzed": len(findings),
            "remediation_items": len(items),
            "remediation_plan": [item.to_dict() for item in items],
            "summary": {
                "quick_wins": [item.to_dict() for item in items if item.quick_win],
                "quick_win_count": len([item for item in items if item.quick_win]),
                "total_risk_reduction": round(sum(item.risk_reduction for item in items), 1),
                "effort_distribution": {
                    "Code fix": len([i for i in items if i.fix_type == "Code fix"]),
                    "Configuration": len([i for i in items if i.fix_type == "Configuration"]),
                    "Architecture": len([i for i in items if i.fix_type == "Architecture"]),
                },
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/remediation/effort-estimates")
async def get_effort_estimates() -> Dict:
    """Get effort estimates by technique."""
    from services.ai_security_analysis_service import RemediationPrioritizer
    
    return {
        "status": "success",
        "effort_estimates": RemediationPrioritizer.EFFORT_ESTIMATES,
    }


# =============================================================================
# COMPREHENSIVE ANALYSIS ENDPOINT
# =============================================================================

@router.post("/comprehensive")
async def comprehensive_analysis(request: ComprehensiveAnalysisRequest) -> Dict:
    """
    Perform comprehensive AI security analysis.
    
    Includes all analysis types:
    - Exploit chain analysis
    - Root cause analysis
    - Impact assessment
    - Remediation prioritization
    """
    try:
        findings = [f.model_dump() for f in request.findings]
        business_ctx = request.business_context.model_dump() if request.business_context else None
        
        # Full analysis
        results = analyze_findings_comprehensive(findings, business_ctx)
        
        # Filter based on request
        if not request.include_chains:
            results.pop("exploit_chains", None)
        if not request.include_root_causes:
            results.pop("root_causes", None)
        if not request.include_impact:
            results.pop("impact_assessment", None)
        if not request.include_remediation:
            results.pop("remediation_plan", None)
        
        return {
            "status": "success",
            **results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# ATTACK STAGE INFO
# =============================================================================

@router.get("/attack-stages")
async def get_attack_stages() -> Dict:
    """Get attack stages and technique mappings."""
    from services.ai_security_analysis_service import AttackStage, TECHNIQUE_ATTACK_STAGE
    
    return {
        "status": "success",
        "attack_stages": [
            {
                "value": stage.value,
                "name": stage.name.replace("_", " ").title(),
            }
            for stage in AttackStage
        ],
        "technique_mappings": {
            tech: [s.value for s in stages]
            for tech, stages in TECHNIQUE_ATTACK_STAGE.items()
        },
    }


# =============================================================================
# TECHNIQUE INFO
# =============================================================================

@router.get("/techniques")
async def get_technique_info() -> Dict:
    """Get all technique analysis information."""
    from services.ai_security_analysis_service import (
        TECHNIQUE_ATTACK_STAGE,
        TECHNIQUE_ROOT_CAUSES,
        TECHNIQUE_IMPACTS,
    )
    
    techniques = set(TECHNIQUE_ATTACK_STAGE.keys()) | set(TECHNIQUE_ROOT_CAUSES.keys()) | set(TECHNIQUE_IMPACTS.keys())
    
    technique_info = {}
    for tech in sorted(techniques):
        technique_info[tech] = {
            "attack_stages": [s.value for s in TECHNIQUE_ATTACK_STAGE.get(tech, [])],
            "root_causes": [
                {"category": rc[0].value, "title": rc[1], "fix": rc[2]}
                for rc in TECHNIQUE_ROOT_CAUSES.get(tech, [])
            ],
            "impact": TECHNIQUE_IMPACTS.get(tech, {}),
        }
    
    return {
        "status": "success",
        "technique_count": len(techniques),
        "techniques": technique_info,
    }
