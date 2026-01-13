from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend import models
from backend.core.database import get_db
from backend.core.auth import get_current_user
from backend.schemas import Finding, Report


def verify_project_access(db: Session, project_id: int, user_id: int) -> bool:
    """Check if user has access to the project."""
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        return False
    
    # Owner always has access
    if project.owner_id == user_id:
        return True
    
    # Check collaborator access
    collaborator = db.query(models.ProjectCollaborator).filter(
        models.ProjectCollaborator.project_id == project_id,
        models.ProjectCollaborator.user_id == user_id
    ).first()
    
    return collaborator is not None


# Chat models
class ChatMessage(BaseModel):
    role: str
    content: str


class ReportChatRequest(BaseModel):
    message: str
    conversation_history: List[ChatMessage] = []
    context_tab: str = "findings"  # "findings" or "exploitability"


class ReportChatResponse(BaseModel):
    response: str
    error: Optional[str] = None

router = APIRouter()


@router.get("", response_model=list[Report])
def list_reports(
    project_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """List all reports for a project. Called via /projects/{project_id}/reports"""
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    reports = db.query(models.Report).filter(models.Report.project_id == project_id).all()
    return reports


@router.get("/{report_id}", response_model=Report)
def get_report(
    project_id: int,
    report_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.delete("/{report_id}")
def delete_report(
    project_id: int,
    report_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    db.delete(report)
    db.commit()
    return {"status": "deleted"}


@router.get("/{report_id}/findings", response_model=list[Finding])
def list_findings(
    project_id: int,
    report_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    findings = db.query(models.Finding).filter(models.Finding.scan_run_id == report.scan_run_id).all()
    return findings


@router.get("/{report_id}/attack-chains")
def get_attack_chains(
    project_id: int,
    report_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
) -> List[Dict[str, Any]]:
    """Get attack chains identified by AI analysis for a report."""
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Attack chains are stored in report.data
    attack_chains = report.data.get("attack_chains", []) if report.data else []
    return attack_chains


@router.get("/{report_id}/ai-insights")
def get_ai_insights(
    project_id: int,
    report_id: int, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get AI analysis insights including false positives and severity adjustments."""
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # AI summary is stored in report.data
    ai_summary = report.data.get("ai_analysis_summary", {}) if report.data else {}
    attack_chains = report.data.get("attack_chains", []) if report.data else []
    
    return {
        "attack_chains": attack_chains,
        "false_positive_count": ai_summary.get("false_positive_count", 0),
        "severity_adjustments": ai_summary.get("severity_adjusted_count", 0),
        "findings_analyzed": ai_summary.get("findings_analyzed", 0),
        "false_positives": ai_summary.get("false_positives", []),
    }


@router.post("/{report_id}/chat", response_model=ReportChatResponse)
async def chat_about_report(
    project_id: int,
    report_id: int, 
    request: ReportChatRequest, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Chat with Gemini about a VR Scan report's findings and exploitability analysis.
    
    Allows users to ask follow-up questions about security findings, attack chains,
    and exploit scenarios.
    """
    if not verify_project_access(db, project_id, current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    from backend.core.config import settings
    
    if not settings.gemini_api_key:
        return ReportChatResponse(
            response="",
            error="Chat unavailable: GEMINI_API_KEY not configured"
        )
    
    # Get the report
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Get findings
    findings = db.query(models.Finding).filter(models.Finding.scan_run_id == report.scan_run_id).all()
    
    # Get exploitability scenarios
    exploit_scenarios = db.query(models.ExploitScenario).filter(
        models.ExploitScenario.report_id == report_id
    ).all()
    
    try:
        from google import genai
        from google.genai import types
        import json
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build findings summary
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            severity = (f.severity or "info").lower()
            if severity in findings_by_severity:
                findings_by_severity[severity].append({
                    "type": f.type,
                    "title": f.title,
                    "file": f.file_path,
                    "line": f.start_line,
                    "description": f.description[:300] if f.description else None,
                    "cwe_id": f.cwe_id,
                    "cve_id": f.cve_id,
                })
        
        # Build exploit scenarios summary
        exploit_data = []
        for es in exploit_scenarios:
            exploit_data.append({
                "title": es.title,
                "severity": es.severity,
                "attack_narrative": es.attack_narrative[:500] if es.attack_narrative else None,
                "impact": es.impact,
                "mitigation": es.mitigation[:300] if es.mitigation else None,
                "cvss_score": es.cvss_score,
            })
        
        # Get AI analysis summary and attack chains from report data
        ai_summary = report.data.get("ai_analysis_summary", {}) if report.data else {}
        attack_chains = report.data.get("attack_chains", []) if report.data else []
        
        # Build the context prompt
        context = f"""You are a helpful security analyst assistant. You have access to a vulnerability scan report and should answer questions about it.

## SCAN REPORT CONTEXT

### Report Overview
- Report ID: {report.id}
- Project: {report.project.name if report.project else 'Unknown'}
- Created: {report.created_at}
- Total Findings: {len(findings)}

### Findings Summary by Severity
- Critical: {len(findings_by_severity['critical'])} findings
- High: {len(findings_by_severity['high'])} findings
- Medium: {len(findings_by_severity['medium'])} findings
- Low: {len(findings_by_severity['low'])} findings
- Info: {len(findings_by_severity['info'])} findings

### Critical & High Findings (Details)
{json.dumps(findings_by_severity['critical'][:10] + findings_by_severity['high'][:15], indent=2)}

### Medium Findings (Sample)
{json.dumps(findings_by_severity['medium'][:10], indent=2)}

### AI Analysis Summary
- False Positives Identified: {ai_summary.get('false_positive_count', 0)}
- Severity Adjustments: {ai_summary.get('severity_adjusted_count', 0)}

### Attack Chains Identified
{json.dumps(attack_chains[:5], indent=2) if attack_chains else "No attack chains identified."}

### Exploit Scenarios ({len(exploit_data)} total)
{json.dumps(exploit_data[:10], indent=2) if exploit_data else "No exploit scenarios generated yet."}

---

Answer the user's question based on this security scan report. Be helpful, specific, and reference the findings when relevant. 
- If asked about specific vulnerabilities, reference the CWE/CVE IDs when available.
- For remediation questions, provide actionable code-level fixes when possible.
- For risk assessment questions, consider the attack chains and exploit scenarios.
- Keep responses concise but technically accurate.
- If asked about something not in the data, let them know what information is available."""

        # Build conversation history
        conversation = [{"role": "user", "parts": [{"text": context}]}]
        conversation.append({"role": "model", "parts": [{"text": "I understand. I have access to this vulnerability scan report with its findings, attack chains, and exploit scenarios. I'm ready to answer questions about the security analysis. What would you like to know?"}]})
        
        # Add prior conversation
        for msg in request.conversation_history:
            conversation.append({
                "role": "user" if msg.role == "user" else "model",
                "parts": [{"text": msg.content}]
            })
        
        # Add current message
        conversation.append({
            "role": "user",
            "parts": [{"text": request.message}]
        })
        
        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=conversation,
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=2048,
            )
        )
        
        return ReportChatResponse(response=response.text)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return ReportChatResponse(
            response="",
            error=f"Chat error: {str(e)}"
        )
