"""
Fuzzer Reports Router

REST API endpoints for generating and exporting security reports from fuzzing sessions.
"""

from fastapi import APIRouter, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum

from backend.core.auth import get_current_active_user
from backend.models.models import User

from backend.services.fuzzer_report_service import (
    get_report_generator,
    ReportFormat,
    ReportType,
    SeverityLevel,
)
from backend.services.agentic_fuzzer_service import get_session, get_saved_sessions

router = APIRouter(prefix="/fuzzer-reports")


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ReportTypeEnum(str, Enum):
    """Report type options."""
    executive = "executive"
    technical = "technical"
    compliance = "compliance"
    full = "full"


class ReportFormatEnum(str, Enum):
    """Report format options."""
    json = "json"
    html = "html"
    markdown = "markdown"
    pdf = "pdf"


class GenerateReportRequest(BaseModel):
    """Request to generate a report from session data."""
    session_id: str = Field(..., description="Fuzzing session ID")
    report_type: ReportTypeEnum = Field(
        default=ReportTypeEnum.full,
        description="Type of report to generate"
    )
    format: ReportFormatEnum = Field(
        default=ReportFormatEnum.html,
        description="Output format"
    )
    include_chains: bool = Field(
        default=True,
        description="Include exploit chain analysis"
    )
    include_root_causes: bool = Field(
        default=True,
        description="Include root cause analysis"
    )
    organization: Optional[str] = Field(
        None,
        description="Organization name for the report"
    )
    assessor: Optional[str] = Field(
        None,
        description="Assessor/analyst name"
    )


class FindingInput(BaseModel):
    """A finding to include in the report."""
    id: Optional[str] = None
    title: Optional[str] = None
    technique: str
    severity: str = "medium"
    url: str
    parameter: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    payload: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None


class GenerateFromFindingsRequest(BaseModel):
    """Request to generate a report from raw findings."""
    findings: List[FindingInput] = Field(..., min_items=1)
    targets: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    report_type: ReportTypeEnum = Field(default=ReportTypeEnum.full)
    format: ReportFormatEnum = Field(default=ReportFormatEnum.html)
    organization: Optional[str] = None
    assessor: Optional[str] = None
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None


# =============================================================================
# REPORT GENERATION ENDPOINTS
# =============================================================================

@router.post("/generate")
async def generate_report(
    request: GenerateReportRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate a security report from a fuzzing session.
    
    Returns the report in the requested format.
    """
    # Get session data
    session = get_session(request.session_id)
    if not session:
        # Try saved sessions
        saved = get_saved_sessions()
        session_data = None
        for s in saved:
            if s.get("session_id") == request.session_id:
                session_data = s
                break
        
        if not session_data:
            raise HTTPException(status_code=404, detail="Session not found")
    else:
        session_data = session.to_dict()
    
    # Generate report
    generator = get_report_generator()
    
    report_type_map = {
        ReportTypeEnum.executive: ReportType.EXECUTIVE,
        ReportTypeEnum.technical: ReportType.TECHNICAL,
        ReportTypeEnum.compliance: ReportType.COMPLIANCE,
        ReportTypeEnum.full: ReportType.FULL,
    }
    
    format_map = {
        ReportFormatEnum.json: ReportFormat.JSON,
        ReportFormatEnum.html: ReportFormat.HTML,
        ReportFormatEnum.markdown: ReportFormat.MARKDOWN,
        ReportFormatEnum.pdf: ReportFormat.PDF,
    }
    
    try:
        report = generator.generate_report(
            session_data=session_data,
            report_type=report_type_map[request.report_type],
            include_chains=request.include_chains,
            include_root_causes=request.include_root_causes,
            organization=request.organization,
            assessor=request.assessor,
        )
        
        # Export to requested format
        output = generator.export_report(report, format_map[request.format])
        
        # Return appropriate response type
        if request.format == ReportFormatEnum.html:
            return HTMLResponse(content=output)
        elif request.format == ReportFormatEnum.markdown:
            return Response(
                content=output,
                media_type="text/markdown",
                headers={"Content-Disposition": f"attachment; filename=report-{report.metadata.report_id}.md"}
            )
        elif request.format == ReportFormatEnum.pdf:
            return HTMLResponse(content=output)  # Print-friendly HTML
        else:  # JSON
            return {"report": report.to_dict()}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


@router.post("/generate-from-findings")
async def generate_report_from_findings(
    request: GenerateFromFindingsRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate a report from raw findings data.
    
    Use this endpoint when you have findings from sources other
    than a fuzzing session.
    """
    generator = get_report_generator()
    
    # Build session-like data structure
    now = datetime.now()
    session_data = {
        "findings": [f.model_dump() for f in request.findings],
        "targets": [{"url": t} for t in request.targets] if request.targets else [],
        "techniques": request.techniques,
        "start_time": request.scan_start or now,
        "end_time": request.scan_end or now,
        "total_requests": len(request.findings) * 10,  # Estimate
    }
    
    report_type_map = {
        ReportTypeEnum.executive: ReportType.EXECUTIVE,
        ReportTypeEnum.technical: ReportType.TECHNICAL,
        ReportTypeEnum.compliance: ReportType.COMPLIANCE,
        ReportTypeEnum.full: ReportType.FULL,
    }
    
    format_map = {
        ReportFormatEnum.json: ReportFormat.JSON,
        ReportFormatEnum.html: ReportFormat.HTML,
        ReportFormatEnum.markdown: ReportFormat.MARKDOWN,
        ReportFormatEnum.pdf: ReportFormat.PDF,
    }
    
    try:
        report = generator.generate_report(
            session_data=session_data,
            report_type=report_type_map[request.report_type],
            organization=request.organization,
            assessor=request.assessor,
        )
        
        output = generator.export_report(report, format_map[request.format])
        
        if request.format == ReportFormatEnum.html:
            return HTMLResponse(content=output)
        elif request.format == ReportFormatEnum.markdown:
            return Response(
                content=output,
                media_type="text/markdown",
            )
        else:
            return {"report": report.to_dict()}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


# =============================================================================
# REPORT INFO ENDPOINTS
# =============================================================================

@router.get("/types")
async def get_report_types():
    """Get available report types and their descriptions."""
    return {
        "types": [
            {
                "id": "executive",
                "name": "Executive Summary",
                "description": "High-level summary for management with risk ratings and key findings",
            },
            {
                "id": "technical",
                "name": "Technical Report",
                "description": "Detailed technical findings with methodology and evidence",
            },
            {
                "id": "compliance",
                "name": "Compliance Report",
                "description": "Compliance-focused report mapping findings to frameworks",
            },
            {
                "id": "full",
                "name": "Full Report",
                "description": "Complete report with all sections",
            },
        ]
    }


@router.get("/formats")
async def get_report_formats():
    """Get available export formats."""
    return {
        "formats": [
            {
                "id": "json",
                "name": "JSON",
                "description": "Structured JSON data for programmatic access",
                "mime_type": "application/json",
            },
            {
                "id": "html",
                "name": "HTML",
                "description": "Formatted HTML report for viewing in browser",
                "mime_type": "text/html",
            },
            {
                "id": "markdown",
                "name": "Markdown",
                "description": "Markdown format for documentation systems",
                "mime_type": "text/markdown",
            },
            {
                "id": "pdf",
                "name": "PDF (Print-friendly HTML)",
                "description": "Print-friendly HTML that can be saved as PDF",
                "mime_type": "text/html",
            },
        ]
    }


@router.get("/severity-levels")
async def get_severity_levels():
    """Get severity level definitions."""
    return {
        "levels": [
            {
                "id": "critical",
                "name": "Critical",
                "score_range": "9.0-10.0",
                "color": "#dc3545",
                "description": "Immediate exploitation possible with severe impact",
            },
            {
                "id": "high",
                "name": "High",
                "score_range": "7.0-8.9",
                "color": "#fd7e14",
                "description": "Significant vulnerability requiring urgent attention",
            },
            {
                "id": "medium",
                "name": "Medium",
                "score_range": "4.0-6.9",
                "color": "#ffc107",
                "description": "Moderate risk that should be addressed",
            },
            {
                "id": "low",
                "name": "Low",
                "score_range": "0.1-3.9",
                "color": "#17a2b8",
                "description": "Minor issue with limited impact",
            },
            {
                "id": "info",
                "name": "Informational",
                "score_range": "0.0",
                "color": "#6c757d",
                "description": "Information disclosure or best practice recommendation",
            },
        ]
    }


# =============================================================================
# QUICK REPORT ENDPOINTS
# =============================================================================

@router.get("/sessions/{session_id}/summary")
async def get_session_summary(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a quick summary of a session without generating a full report.
    """
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session_data = session.to_dict()
    findings = session_data.get("findings", [])
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "medium").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Calculate risk score
    total_weight = (
        severity_counts["critical"] * 10 +
        severity_counts["high"] * 7.5 +
        severity_counts["medium"] * 5 +
        severity_counts["low"] * 2.5 +
        severity_counts["info"] * 0.5
    )
    
    import math
    risk_score = min(10.0, total_weight / (1 + math.log10(len(findings) + 1))) if findings else 0
    
    # Determine risk rating
    if risk_score >= 9.0:
        risk_rating = "Critical"
    elif risk_score >= 7.0:
        risk_rating = "High"
    elif risk_score >= 4.0:
        risk_rating = "Medium"
    else:
        risk_rating = "Low"
    
    return {
        "session_id": session_id,
        "status": session_data.get("status", "unknown"),
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "risk_score": round(risk_score, 1),
            "risk_rating": risk_rating,
            "targets_tested": len(session_data.get("targets", [])),
            "techniques_used": len(session_data.get("techniques", [])),
        },
        "top_findings": [
            {
                "title": f.get("title", f.get("technique", "Unknown")),
                "severity": f.get("severity", "medium"),
                "url": f.get("url", "N/A"),
            }
            for f in sorted(findings, key=lambda x: {
                "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
            }.get(x.get("severity", "medium").lower(), 5))[:5]
        ],
    }


@router.get("/sessions/{session_id}/executive")
async def get_executive_summary(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate just the executive summary for a session.
    
    Faster than generating a full report when you only need the summary.
    """
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    generator = get_report_generator()
    session_data = session.to_dict()
    
    try:
        # Convert findings
        findings = generator._convert_findings(session_data.get("findings", []))
        
        # Generate executive summary only
        executive = generator.executive_generator.generate(findings)
        
        return {
            "session_id": session_id,
            "executive_summary": executive.to_dict(),
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Summary generation failed: {str(e)}")


# =============================================================================
# TEMPLATE ENDPOINTS
# =============================================================================

@router.get("/templates")
async def get_report_templates():
    """Get available report templates/presets."""
    return {
        "templates": [
            {
                "id": "pentest_report",
                "name": "Penetration Test Report",
                "description": "Standard penetration testing report format",
                "report_type": "full",
                "sections": ["executive_summary", "methodology", "findings", "remediation"],
            },
            {
                "id": "executive_brief",
                "name": "Executive Brief",
                "description": "One-page executive summary",
                "report_type": "executive",
                "sections": ["executive_summary", "top_risks"],
            },
            {
                "id": "compliance_audit",
                "name": "Compliance Audit Report",
                "description": "Compliance-focused assessment report",
                "report_type": "compliance",
                "sections": ["executive_summary", "compliance_status", "findings", "recommendations"],
            },
            {
                "id": "technical_findings",
                "name": "Technical Findings Report",
                "description": "Detailed technical findings for developers",
                "report_type": "technical",
                "sections": ["methodology", "findings", "evidence", "remediation"],
            },
        ]
    }
