import json
from collections import defaultdict
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend import models
from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.core.mermaid_icons import WEBAPP_DIAGRAM_ICONS, get_webapp_diagram_prompt_icons
from backend.services import export_service, sbom_service
from backend.schemas import Report, Finding

logger = get_logger(__name__)

router = APIRouter()


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


def _get_report(db: Session, report_id: int) -> models.Report:
    """Fetch report or raise 404."""
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}", response_model=Report)
def get_report(report_id: int, db: Session = Depends(get_db)):
    """Get a single report by ID."""
    return _get_report(db, report_id)


@router.get("/{report_id}/findings", response_model=list[Finding])
def get_report_findings(report_id: int, db: Session = Depends(get_db)):
    """Get all findings for a report."""
    report = _get_report(db, report_id)
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    return findings


@router.delete("/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    """Delete a report and its associated findings."""
    report = _get_report(db, report_id)
    
    # Delete associated exploit scenarios
    db.query(models.ExploitScenario).filter(
        models.ExploitScenario.report_id == report_id
    ).delete()
    
    # Delete associated findings
    db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).delete()
    
    # Delete the report
    db.delete(report)
    db.commit()
    
    logger.info(f"Deleted report {report_id}")
    return {"status": "deleted", "report_id": report_id}


@router.get("/{report_id}/findings/{finding_id}/snippet")
def get_finding_code_snippet(
    report_id: int, 
    finding_id: int, 
    context_lines: int = Query(5, ge=0, le=20, description="Number of context lines before and after"),
    db: Session = Depends(get_db)
):
    """
    Get the code snippet for a specific finding.
    
    Returns the vulnerable code with surrounding context lines.
    """
    report = _get_report(db, report_id)
    
    finding = db.query(models.Finding).filter(
        models.Finding.id == finding_id,
        models.Finding.scan_run_id == report.scan_run_id
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Check if code_snippet is already in details (e.g., from semgrep)
    if finding.details and finding.details.get("code_snippet"):
        return {
            "finding_id": finding_id,
            "file_path": finding.file_path,
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "code_snippet": finding.details["code_snippet"],
            "source": "cached"
        }
    
    # Try to get from code chunks
    if finding.file_path and finding.start_line:
        # Look for matching code chunk
        chunk = db.query(models.CodeChunk).filter(
            models.CodeChunk.project_id == report.project_id,
            models.CodeChunk.file_path.contains(finding.file_path.split("/")[-1])  # Match by filename
        ).filter(
            models.CodeChunk.start_line <= finding.start_line,
            models.CodeChunk.end_line >= (finding.end_line or finding.start_line)
        ).first()
        
        if chunk:
            return {
                "finding_id": finding_id,
                "file_path": finding.file_path,
                "start_line": chunk.start_line,
                "end_line": chunk.end_line,
                "code_snippet": chunk.code,
                "language": chunk.language,
                "source": "code_chunk"
            }
    
    # If no code snippet available, return the details we have
    return {
        "finding_id": finding_id,
        "file_path": finding.file_path,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "code_snippet": None,
        "details": finding.details,
        "source": "none"
    }


@router.get("/{report_id}/export/markdown")
def export_markdown(report_id: int, db: Session = Depends(get_db)):
    """Export report as Markdown with full AI summaries and exploit scenarios."""
    try:
        report, findings = export_service.get_report_with_findings(db, report_id)
        content = export_service.generate_markdown(report, findings, db=db, include_ai_summaries=True)
        logger.info(f"Exported markdown for report {report_id}")
        return Response(
            content=content,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.md"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{report_id}/export/pdf")
def export_pdf(report_id: int, db: Session = Depends(get_db)):
    """Export report as PDF with full AI summaries and exploit scenarios."""
    try:
        report, findings = export_service.get_report_with_findings(db, report_id)
        content = export_service.generate_pdf(report, findings, db=db, include_ai_summaries=True)
        logger.info(f"Exported PDF for report {report_id}")
        return Response(
            content=content,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.pdf"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{report_id}/export/docx")
def export_docx(report_id: int, db: Session = Depends(get_db)):
    """Export report as DOCX with full AI summaries and exploit scenarios."""
    try:
        report, findings = export_service.get_report_with_findings(db, report_id)
        content = export_service.generate_docx(report, findings, db=db, include_ai_summaries=True)
        logger.info(f"Exported DOCX for report {report_id}")
        return Response(
            content=content,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f"attachment; filename=report_{report_id}.docx"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{report_id}/export/sbom/cyclonedx")
def export_sbom_cyclonedx(
    report_id: int,
    include_vulnerabilities: bool = Query(True, description="Include vulnerability data in SBOM"),
    db: Session = Depends(get_db)
):
    """
    Export project SBOM in CycloneDX 1.5 format.
    
    CycloneDX is a lightweight SBOM standard designed for security contexts.
    Includes dependency inventory and optionally vulnerability data.
    """
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    try:
        sbom = sbom_service.get_sbom(db, report.project_id, "cyclonedx", include_vulnerabilities)
        content = json.dumps(sbom, indent=2)
        logger.info(f"Exported CycloneDX SBOM for report {report_id}")
        return Response(
            content=content,
            media_type="application/vnd.cyclonedx+json",
            headers={"Content-Disposition": f"attachment; filename=sbom_{report_id}_cyclonedx.json"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{report_id}/export/sbom/spdx")
def export_sbom_spdx(report_id: int, db: Session = Depends(get_db)):
    """
    Export project SBOM in SPDX 2.3 format.
    
    SPDX is an ISO standard (ISO/IEC 5962:2021) for software bill of materials.
    """
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    try:
        sbom = sbom_service.get_sbom(db, report.project_id, "spdx")
        content = json.dumps(sbom, indent=2)
        logger.info(f"Exported SPDX SBOM for report {report_id}")
        return Response(
            content=content,
            media_type="application/spdx+json",
            headers={"Content-Disposition": f"attachment; filename=sbom_{report_id}_spdx.json"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{report_id}/codebase/summary")
async def get_codebase_ai_summary(report_id: int, db: Session = Depends(get_db)):
    """
    Get an AI-generated summary of the codebase.
    
    Uses Gemini to analyze the codebase structure and provide insights about:
    - What the project does
    - Main technologies and frameworks
    - Code quality observations
    - Basic statistics
    """
    from backend.core.config import settings
    
    report = _get_report(db, report_id)
    project_id = report.project_id
    
    # Get project info
    project = db.get(models.Project, project_id)
    
    # Get all code chunks for context
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == project_id
    ).all()
    
    # Get findings for this report
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    
    # Build file metadata for statistics
    file_metadata = defaultdict(lambda: {"lines": 0, "language": None})
    for chunk in chunks:
        file_metadata[chunk.file_path]["language"] = chunk.language
        if chunk.end_line:
            file_metadata[chunk.file_path]["lines"] = max(
                file_metadata[chunk.file_path]["lines"],
                chunk.end_line
            )
    
    # Calculate statistics
    total_files = len(file_metadata)
    total_lines = sum(m["lines"] for m in file_metadata.values())
    languages = {}
    for m in file_metadata.values():
        lang = m["language"] or "Unknown"
        languages[lang] = languages.get(lang, 0) + 1
    
    # Get sample file paths for context
    sample_paths = list(file_metadata.keys())[:30]
    
    # Get sample code snippets (first 5 chunks, truncated)
    sample_code = []
    for chunk in chunks[:5]:
        sample_code.append({
            "path": chunk.file_path,
            "language": chunk.language,
            "preview": chunk.code[:500] if chunk.code else ""
        })
    
    # Build severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    finding_types = {}
    for f in findings:
        sev = (f.severity or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        ftype = f.type or "unknown"
        finding_types[ftype] = finding_types.get(ftype, 0) + 1
    
    # Build the prompt for app/codebase summary - DETAILED VERSION
    app_prompt = f"""You are a senior software architect analyzing a codebase. Provide a comprehensive overview of what this application does.

Project Name: {project.name if project else 'Unknown'}

FILES ANALYZED ({total_files} files, {total_lines:,} lines of code):
{chr(10).join(sample_paths)}
{"..." if len(file_metadata) > 30 else ""}

LANGUAGE BREAKDOWN:
{chr(10).join(f"- {lang}: {count} files" for lang, count in sorted(languages.items(), key=lambda x: -x[1]))}

SAMPLE CODE SNIPPETS:
{chr(10).join(f"--- {s['path']} ({s['language']}) ---{chr(10)}{s['preview']}..." for s in sample_code)}

Write a detailed, well-structured analysis. Format your response EXACTLY like this example:

**Purpose & Functionality**
A brief 2-3 sentence description of what this application does and its target users.

**Technology Stack**
• Frontend: React, TypeScript
• Backend: Python, FastAPI
• Database: PostgreSQL
• Other: Docker, Redis

**Architecture**
Describe the overall structure in 2-3 sentences, then list key patterns:
• Pattern 1 - brief explanation
• Pattern 2 - brief explanation

**Key Components**
• **Component Name** - what it does
• **Another Component** - what it does
• **Third Component** - what it does

FORMATTING RULES:
- Use **bold** only for section headers and component names
- Use • bullet points for lists
- Keep descriptions concise - one line per item
- No numbered lists in this section"""

    # Build findings details for security summary
    findings_details = []
    for f in findings[:15]:  # Limit to first 15 for prompt size
        detail = {
            "severity": f.severity,
            "type": f.type,
            "file": f.file_path,
            "line": f.start_line,
            "summary": f.summary[:200] if f.summary else "",
        }
        if f.details:
            if f.details.get("rule_id"):
                detail["rule"] = f.details["rule_id"]
            if f.details.get("secret_type"):
                detail["secret_type"] = f.details["secret_type"]
        findings_details.append(detail)

    security_prompt = f"""You are an elite penetration tester and red team operator. Analyze these vulnerabilities and explain how an attacker would exploit this application.

Project: {project.name if project else 'Unknown'}
Total Files Scanned: {total_files}

FINDINGS SUMMARY:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Info: {severity_counts['info']}
Total: {len(findings)} findings

Finding Types: {', '.join(f"{k} ({v})" for k, v in sorted(finding_types.items(), key=lambda x: -x[1]))}

DETAILED FINDINGS:
{chr(10).join(f"- [{f['severity'].upper()}] {f['type']}: {f['summary']} (in {f['file']}:{f.get('line', '?')})" for f in findings_details)}

Write from an attacker's perspective. Format your response EXACTLY like this:

**Overall Risk Assessment**
RISK LEVEL: CRITICAL/HIGH/MEDIUM/LOW
One sentence justification of the risk level.

**Primary Attack Vectors**
• **Vector Name** - Brief description of the attack surface
• **Another Vector** - Brief description
• **Third Vector** - Brief description

**Exploitation Strategy**
Step-by-step attack plan:
1. **Initial Access** - How to get in (specific vulnerability)
2. **Establish Foothold** - What to do once inside
3. **Privilege Escalation** - How to gain more access
4. **Achieve Objective** - Final goal (data exfil, RCE, etc.)

**Potential Impact**
• Data Exposure: What sensitive data is at risk
• System Compromise: Level of access achievable
• Business Impact: Real-world consequences

**Quick Wins**
Easiest exploits for immediate results:
1. First easy exploit - why it's easy
2. Second easy exploit - why it's easy
3. Third easy exploit - why it's easy

FORMATTING RULES:
- Use **bold** for section headers and key terms only
- Use • bullets for unordered lists
- Use numbered lists (1. 2. 3.) for sequential steps
- Be specific about techniques, no generic advice
- Think like a hacker. No remediation advice."""

    # Call Gemini if available
    app_summary = None
    security_summary = None
    
    # Check if we have cached summaries in report.data
    if report.data and report.data.get("ai_summaries"):
        cached = report.data["ai_summaries"]
        app_summary = cached.get("app_summary")
        security_summary = cached.get("security_summary")
        logger.info(f"Using cached AI summaries for report {report_id}")
    elif settings.gemini_api_key:
        try:
            from google import genai
            
            client = genai.Client(api_key=settings.gemini_api_key)
            
            # Generate app summary
            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=app_prompt
            )
            if response and response.text:
                app_summary = response.text
                logger.info(f"Generated app summary for report {report_id}")
            
            # Generate security summary (only if there are findings)
            if len(findings) > 0:
                response = client.models.generate_content(
                    model=settings.gemini_model_id,
                    contents=security_prompt
                )
                if response and response.text:
                    security_summary = response.text
                    logger.info(f"Generated security summary for report {report_id}")
            
            # Cache the summaries in report.data
            if app_summary or security_summary:
                report_data = report.data or {}
                report_data["ai_summaries"] = {
                    "app_summary": app_summary,
                    "security_summary": security_summary
                }
                report.data = report_data
                db.commit()
                logger.info(f"Cached AI summaries for report {report_id}")
                    
        except Exception as e:
            logger.error(f"Failed to generate AI summaries: {e}")
    
    return {
        "report_id": report_id,
        "project_name": project.name if project else "Unknown",
        "statistics": {
            "total_files": total_files,
            "total_lines": total_lines,
            "languages": languages,
            "findings_by_severity": severity_counts,
            "findings_by_type": dict(sorted(finding_types.items(), key=lambda x: -x[1])[:10]),
            "total_findings": len(findings)
        },
        "app_summary": app_summary,
        "security_summary": security_summary,
        "has_app_summary": app_summary is not None,
        "has_security_summary": security_summary is not None
    }


@router.get("/{report_id}/codebase/diagram")
async def get_codebase_diagram(report_id: int, db: Session = Depends(get_db)):
    """
    Get an AI-generated Mermaid architecture diagram for the codebase.
    
    Uses Gemini to analyze the codebase structure and generate a visual
    architecture diagram showing:
    - Main modules and components
    - Entry points and data flow
    - Dependencies between components
    - Technology-specific patterns
    
    This is a human-friendly overview of how the application works,
    NOT a security-focused diagram (that's the Attack Surface Map).
    
    Returns Mermaid flowchart code with icons from available icon packs.
    """
    from backend.core.config import settings
    
    report = _get_report(db, report_id)
    project_id = report.project_id
    
    # Check for cached diagram in report.data
    if report.data and report.data.get("codebase_diagram"):
        cached = report.data["codebase_diagram"]
        logger.info(f"Using cached codebase diagram for report {report_id}")
        return {
            "report_id": report_id,
            "diagram": cached.get("mermaid_code"),
            "diagram_type": cached.get("diagram_type", "flowchart"),
            "cached": True
        }
    
    # Get project info
    project = db.get(models.Project, project_id)
    
    # Get all code chunks for context
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == project_id
    ).all()
    
    # Get dependencies for understanding the app
    dependencies = db.query(models.Dependency).filter(
        models.Dependency.project_id == project_id
    ).all()
    
    # Get all findings to understand which files are most important
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    
    # Build file metadata with finding counts (like AI summaries do)
    file_metadata = defaultdict(lambda: {"lines": 0, "language": None, "path": "", "chunks": [], "finding_count": 0})
    for chunk in chunks:
        file_metadata[chunk.file_path]["language"] = chunk.language
        file_metadata[chunk.file_path]["path"] = chunk.file_path
        file_metadata[chunk.file_path]["chunks"].append(chunk)
        if chunk.end_line:
            file_metadata[chunk.file_path]["lines"] = max(
                file_metadata[chunk.file_path]["lines"],
                chunk.end_line
            )
    
    # Count findings per file to identify important files
    for finding in findings:
        if finding.file_path and finding.file_path in file_metadata:
            file_metadata[finding.file_path]["finding_count"] += 1
    
    # Calculate statistics
    total_files = len(file_metadata)
    total_lines = sum(m["lines"] for m in file_metadata.values())
    languages = {}
    for m in file_metadata.values():
        lang = m["language"] or "Unknown"
        languages[lang] = languages.get(lang, 0) + 1
    
    # Build folder structure for context
    folders = set()
    for path in file_metadata.keys():
        parts = path.split("/")
        for i in range(1, len(parts)):
            folders.add("/".join(parts[:i]))
    
    # PRIORITY FILE SELECTION (same strategy as AI summaries)
    # 1. Files with most findings (these are the critical/active files)
    files_by_findings = sorted(file_metadata.items(), key=lambda x: x[1]["finding_count"], reverse=True)
    priority_files_with_findings = [f for f in files_by_findings if f[1]["finding_count"] > 0][:15]
    
    # 2. Largest files (by line count) - these define the app's structure
    files_by_size = sorted(file_metadata.items(), key=lambda x: x[1]["lines"], reverse=True)
    
    # 3. Architecture files (entry points, configs, main files)
    key_patterns = ["main", "app", "index", "config", "router", "service", "model", "view", "controller", "api", "handler", "routes", "server"]
    architecture_files = []
    for path in file_metadata.keys():
        filename = path.split("/")[-1].lower()
        for pattern in key_patterns:
            if pattern in filename:
                architecture_files.append(path)
                break
    
    # Combine: priority files + large files + architecture files (deduplicated)
    seen_paths = set()
    significant_files = []
    
    # First: files with findings (up to 15)
    for path, meta in priority_files_with_findings:
        if path not in seen_paths:
            seen_paths.add(path)
            full_code = ""
            for chunk in sorted(meta["chunks"], key=lambda c: c.start_line or 0):
                full_code += (chunk.code or "") + "\n"
            significant_files.append({
                "path": path,
                "language": meta["language"],
                "lines": meta["lines"],
                "finding_count": meta["finding_count"],
                "code_preview": full_code[:4000]
            })
    
    # Second: largest files (up to 10 more)
    for path, meta in files_by_size:
        if path not in seen_paths and len(significant_files) < 25:
            seen_paths.add(path)
            full_code = ""
            for chunk in sorted(meta["chunks"], key=lambda c: c.start_line or 0):
                full_code += (chunk.code or "") + "\n"
            significant_files.append({
                "path": path,
                "language": meta["language"],
                "lines": meta["lines"],
                "finding_count": meta["finding_count"],
                "code_preview": full_code[:4000]
            })
    
    # Third: architecture files (up to 5 more)
    for path in architecture_files:
        if path not in seen_paths and len(significant_files) < 30:
            meta = file_metadata[path]
            seen_paths.add(path)
            full_code = ""
            for chunk in sorted(meta["chunks"], key=lambda c: c.start_line or 0):
                full_code += (chunk.code or "") + "\n"
            significant_files.append({
                "path": path,
                "language": meta["language"],
                "lines": meta["lines"],
                "finding_count": meta["finding_count"],
                "code_preview": full_code[:4000]
            })
    
    key_files = architecture_files
    
    # Get sample file contents for better understanding - up to 20 files with 2500 chars each
    sample_contents = []
    for sig_file in significant_files[:20]:
        sample_contents.append(f"--- {sig_file['path']} ({sig_file['lines']} lines) ---\n{sig_file['code_preview'][:2500]}")
    
    # Detect tech stack from languages and file names
    tech_stack = []
    lang_str = str(languages).lower()
    if "python" in lang_str:
        tech_stack.append("Python")
    if "php" in lang_str:
        tech_stack.append("PHP")
    if "javascript" in lang_str or "typescript" in lang_str:
        tech_stack.append("JavaScript/TypeScript")
    file_paths_str = str(list(file_metadata.keys())).lower()
    if "react" in file_paths_str or "jsx" in file_paths_str or "tsx" in file_paths_str:
        tech_stack.append("React")
    if "vue" in file_paths_str:
        tech_stack.append("Vue")
    if "angular" in file_paths_str:
        tech_stack.append("Angular")
    code_sample = " ".join(c.code or "" for c in chunks[:20]).lower()
    if "fastapi" in code_sample:
        tech_stack.append("FastAPI")
    if "flask" in code_sample:
        tech_stack.append("Flask")
    if "django" in code_sample:
        tech_stack.append("Django")
    if "express" in code_sample:
        tech_stack.append("Express.js")
    if "laravel" in code_sample or "illuminate" in code_sample:
        tech_stack.append("Laravel")
    if "symfony" in code_sample:
        tech_stack.append("Symfony")
    if "codeigniter" in code_sample:
        tech_stack.append("CodeIgniter")
    if "wordpress" in code_sample or "wp_" in code_sample:
        tech_stack.append("WordPress")
    if "drupal" in code_sample:
        tech_stack.append("Drupal")
    if "docker" in file_paths_str:
        tech_stack.append("Docker")
    if "java" in lang_str:
        tech_stack.append("Java")
    if "spring" in code_sample:
        tech_stack.append("Spring")
    if "ruby" in lang_str:
        tech_stack.append("Ruby")
    if "rails" in code_sample:
        tech_stack.append("Rails")
    if "go" in lang_str or "golang" in lang_str:
        tech_stack.append("Go")
    if "rust" in lang_str:
        tech_stack.append("Rust")
    if "csharp" in lang_str or "c#" in lang_str:
        tech_stack.append("C#")
    if "aspnet" in code_sample or "asp.net" in code_sample:
        tech_stack.append("ASP.NET")
    if "mysql" in code_sample:
        tech_stack.append("MySQL")
    if "postgres" in code_sample or "postgresql" in code_sample:
        tech_stack.append("PostgreSQL")
    if "mongodb" in code_sample:
        tech_stack.append("MongoDB")
    if "redis" in code_sample:
        tech_stack.append("Redis")
    
    # Dependencies context for understanding the app
    dep_context = ""
    if dependencies:
        dep_ecosystems = defaultdict(list)
        for d in dependencies:
            dep_ecosystems[d.ecosystem or "unknown"].append(d.name)
        dep_context = f"""
KEY DEPENDENCIES:
{chr(10).join(f"- {eco}: {', '.join(deps[:15])}{'...' if len(deps) > 15 else ''}" for eco, deps in dep_ecosystems.items())}
"""
    
    # Get agentic scan synthesis data from report.data (if available)
    synthesis_context = ""
    report_data = report.data or {}
    scan_stats = report_data.get("scan_stats", {})
    synthesis_data = scan_stats.get("synthesis", {})
    if synthesis_data:
        synthesis_context = f"""
## AGENTIC ANALYSIS (Deep Scan Insights)
App Description: {synthesis_data.get('app_description', 'N/A')}
Architecture Pattern: {synthesis_data.get('architecture_pattern', 'N/A')}
Key Components: {', '.join(synthesis_data.get('key_components', [])[:10]) if synthesis_data.get('key_components') else 'N/A'}
Data Flow: {synthesis_data.get('data_flow_summary', 'N/A')}
External Integrations: {', '.join(synthesis_data.get('external_integrations', [])[:8]) if synthesis_data.get('external_integrations') else 'N/A'}
"""
    
    # Build the prompt for diagram generation with Mermaid icon packs
    diagram_prompt = f"""You are a software architect creating a code architecture diagram for a web/software application.

## PROJECT INFORMATION
Name: {project.name if project else 'Unknown'}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Total Files: {total_files}
Lines of Code: {total_lines:,}

## LANGUAGES
{chr(10).join(f"- {lang}: {count} files" for lang, count in sorted(languages.items(), key=lambda x: -x[1])[:8])}

## PROJECT STRUCTURE
{chr(10).join(f"- {f}/" for f in sorted(folders) if "/" not in f)}

## KEY FILES ({len(key_files)} architecture files identified)
{chr(10).join(f"- {f}" for f in sorted(key_files)[:30])}
{dep_context}
{synthesis_context}
## SOURCE CODE SAMPLES
{chr(10).join(sample_contents[:12])}

## YOUR TASK
Create a Mermaid diagram showing the app's architecture. Show:
1. Main layers (UI/Frontend, API/Backend, Business Logic, Data Layer)
2. Key components and their relationships
3. Data flow between components
4. External service connections (if any)

{get_webapp_diagram_prompt_icons()}

Output a valid Mermaid flowchart diagram. Use subgraphs for different layers.
Use plain text labels with emojis for subgraph titles (NO icons in subgraph labels).
Use the icon block syntax for individual nodes: NodeId@{{ icon: "prefix:name", form: "square", label: "Label" }}

IMPORTANT: Output ONLY the Mermaid code, no explanations. Start with ```mermaid and end with ```.

Example structure:
```mermaid
flowchart TB
    subgraph UI["🖥️ User Interface"]
        Browser@{{ icon: "fa:globe", form: "square", label: "Web Browser" }}
        Mobile@{{ icon: "fa:mobile", form: "square", label: "Mobile App" }}
    end
    subgraph Frontend["⚛️ Frontend Layer"]
        ReactApp@{{ icon: "fab:react", form: "square", label: "React Application" }}
        Components@{{ icon: "fab:js", form: "square", label: "UI Components" }}
    end
    subgraph Backend["🔧 Backend API"]
        APIServer@{{ icon: "mdi:api", form: "square", label: "REST API" }}
        AuthService@{{ icon: "fa:lock", form: "square", label: "Authentication" }}
        BusinessLogic@{{ icon: "mdi:cog", form: "square", label: "Business Logic" }}
    end
    subgraph Data["💾 Data Layer"]
        Database@{{ icon: "mdi:elephant", form: "square", label: "PostgreSQL" }}
        Cache@{{ icon: "mdi:memory", form: "square", label: "Redis Cache" }}
    end
    subgraph External["☁️ External Services"]
        EmailService@{{ icon: "mdi:email", form: "square", label: "Email Provider" }}
        CloudStorage@{{ icon: "fa:cloud", form: "square", label: "Cloud Storage" }}
    end
    
    Browser --> ReactApp
    Mobile --> APIServer
    ReactApp --> APIServer
    APIServer --> AuthService
    APIServer --> BusinessLogic
    BusinessLogic --> Database
    BusinessLogic --> Cache
    BusinessLogic --> EmailService
    BusinessLogic --> CloudStorage
```

Generate a diagram for THIS app based on the actual code structure provided. 
Tech Stack Detected: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Use the appropriate icons from the list above for the detected technologies."""
    
    mermaid_code = None
    
    # Generate diagram using Gemini (Ollama support can be added later for offline use)
    if settings.gemini_api_key:
        try:
            from google import genai
            
            client = genai.Client(api_key=settings.gemini_api_key)
            
            response = client.models.generate_content(
                model=settings.gemini_model_id,
                contents=diagram_prompt
            )
            
            if response and response.text:
                diagram = response.text.strip()
                
                # Extract just the mermaid code (same as APK Analyzer)
                if "```mermaid" in diagram:
                    start = diagram.find("```mermaid")
                    end = diagram.find("```", start + 10)
                    if end > start:
                        diagram = diagram[start + 10:end].strip()
                elif diagram.startswith("```"):
                    diagram = diagram[3:]
                    if diagram.endswith("```"):
                        diagram = diagram[:-3]
                    diagram = diagram.strip()
                
                # Validate it starts with flowchart
                if diagram.startswith("flowchart"):
                    mermaid_code = diagram
                    logger.info(f"Generated codebase diagram for report {report_id}")
                    
                    # Cache the diagram in report.data
                    report_data = report.data or {}
                    report_data["codebase_diagram"] = {
                        "mermaid_code": mermaid_code,
                        "diagram_type": "flowchart",
                        "generated_by": "gemini"
                    }
                    report.data = report_data
                    db.commit()
                    logger.info(f"Cached codebase diagram for report {report_id}")
                else:
                    logger.warning(f"AI generated invalid diagram (doesn't start with flowchart): {diagram[:100]}")
                    
        except Exception as e:
            logger.error(f"Error generating diagram with Gemini: {e}")
    else:
        logger.warning("No AI configured (set GEMINI_API_KEY), using fallback diagram")
    
    # Return fallback diagram if AI generation failed (clean simple structure)
    if not mermaid_code:
        top_folders = [f for f in folders if "/" not in f][:8]
        project_name = (project.name if project else 'Project').replace('"', "'").replace('[', '').replace(']', '')
        
        mermaid_code = f'''flowchart TB
    subgraph Project["{project_name}"]
'''
        for folder in top_folders:
            safe_id = folder.replace('-', '_').replace('.', '_').replace(' ', '_')
            mermaid_code += f'        {safe_id}["{folder}/"]\n'
        
        mermaid_code += "    end\n"
        
        # Add connections between folders if there are common patterns
        if "frontend" in [f.lower() for f in top_folders] and "backend" in [f.lower() for f in top_folders]:
            mermaid_code += "    frontend --> backend\n"
        if "src" in [f.lower() for f in top_folders]:
            mermaid_code += "    src --> |contains| Project\n"
    
    return {
        "report_id": report_id,
        "diagram": mermaid_code,
        "diagram_type": "flowchart",
        "cached": False
    }


@router.get("/{report_id}/codebase")
def get_codebase_structure(report_id: int, db: Session = Depends(get_db)):
    """
    Get the codebase structure as a tree with file metadata.
    
    Returns a hierarchical view of the analyzed codebase including:
    - Folder structure
    - File metadata (language, line count, chunk count)
    - Finding counts per file
    """
    report = _get_report(db, report_id)
    project_id = report.project_id
    
    # Get all code chunks grouped by file
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == project_id
    ).all()
    
    # Get findings grouped by file
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    
    # Build file metadata
    file_metadata = defaultdict(lambda: {
        "chunks": 0,
        "lines": 0,
        "language": None,
        "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    })
    
    for chunk in chunks:
        path = chunk.file_path
        file_metadata[path]["chunks"] += 1
        file_metadata[path]["language"] = chunk.language
        if chunk.end_line:
            file_metadata[path]["lines"] = max(
                file_metadata[path]["lines"], 
                chunk.end_line
            )
    
    # Add findings count per file
    for finding in findings:
        if finding.file_path:
            severity = finding.severity.lower() if finding.severity else "info"
            if severity in file_metadata[finding.file_path]["findings"]:
                file_metadata[finding.file_path]["findings"][severity] += 1
            file_metadata[finding.file_path]["findings"]["total"] += 1
    
    # Build tree structure
    def build_tree(paths_with_meta):
        tree = {}
        for path, meta in paths_with_meta.items():
            parts = path.split("/")
            current = tree
            for i, part in enumerate(parts[:-1]):
                if part not in current:
                    current[part] = {"_type": "folder", "_children": {}}
                current = current[part]["_children"]
            
            # Add file node
            filename = parts[-1]
            current[filename] = {
                "_type": "file",
                "path": path,
                "language": meta["language"],
                "lines": meta["lines"],
                "chunks": meta["chunks"],
                "findings": meta["findings"]
            }
        return tree
    
    # Convert tree to list format for frontend
    def tree_to_list(tree, parent_path=""):
        result = []
        for name, node in sorted(tree.items()):
            if name.startswith("_"):
                continue
            
            current_path = f"{parent_path}/{name}" if parent_path else name
            
            if node.get("_type") == "folder":
                children = tree_to_list(node.get("_children", {}), current_path)
                # Calculate folder totals
                folder_findings = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
                file_count = 0
                for child in children:
                    if child["type"] == "file":
                        file_count += 1
                        for key in folder_findings:
                            folder_findings[key] += child.get("findings", {}).get(key, 0)
                    else:
                        file_count += child.get("file_count", 0)
                        for key in folder_findings:
                            folder_findings[key] += child.get("findings", {}).get(key, 0)
                
                result.append({
                    "name": name,
                    "path": current_path,
                    "type": "folder",
                    "children": children,
                    "file_count": file_count,
                    "findings": folder_findings
                })
            else:
                result.append({
                    "name": name,
                    "path": node.get("path", current_path),
                    "type": "file",
                    "language": node.get("language"),
                    "lines": node.get("lines", 0),
                    "chunks": node.get("chunks", 0),
                    "findings": node.get("findings", {})
                })
        
        return result
    
    tree = build_tree(dict(file_metadata))
    structure = tree_to_list(tree)
    
    # Get summary stats
    total_files = len(file_metadata)
    total_lines = sum(m["lines"] for m in file_metadata.values())
    languages = list(set(m["language"] for m in file_metadata.values() if m["language"]))
    
    return {
        "report_id": report_id,
        "project_id": project_id,
        "summary": {
            "total_files": total_files,
            "total_lines": total_lines,
            "languages": languages,
            "total_findings": len(findings)
        },
        "tree": structure
    }


@router.get("/{report_id}/codebase/file")
def get_file_content(
    report_id: int,
    file_path: str = Query(..., description="The file path to retrieve"),
    db: Session = Depends(get_db)
):
    """
    Get the FULL code content for a specific file.
    
    Reads the actual file from the project zip/directory to ensure 100% content is returned.
    Falls back to stored chunks if the file is not accessible.
    """
    import zipfile
    from pathlib import Path
    
    report = _get_report(db, report_id)
    project = report.project
    
    # Get findings for this file
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id,
        models.Finding.file_path == file_path
    ).all()
    
    # Build finding highlights (line -> severity mapping)
    finding_lines = {}
    for f in findings:
        if f.start_line:
            end = f.end_line or f.start_line
            for line in range(f.start_line, end + 1):
                if line not in finding_lines or _severity_rank(f.severity) > _severity_rank(finding_lines[line]["severity"]):
                    finding_lines[line] = {
                        "severity": f.severity,
                        "type": f.type,
                        "summary": f.summary
                    }
    
    # Language detection helper
    def detect_language(ext: str) -> str:
        lang_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".tsx": "typescriptreact", ".jsx": "javascriptreact",
            ".java": "java", ".kt": "kotlin", ".go": "go",
            ".rs": "rust", ".rb": "ruby", ".php": "php",
            ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
            ".cs": "csharp", ".swift": "swift",
            ".html": "html", ".css": "css", ".scss": "scss",
            ".json": "json", ".yaml": "yaml", ".yml": "yaml",
            ".xml": "xml", ".sql": "sql", ".sh": "shell",
            ".md": "markdown", ".txt": "plaintext",
        }
        return lang_map.get(ext.lower(), "plaintext")
    
    # Try to read the actual file for 100% content
    full_content = None
    language = None
    
    if project.upload_path:
        upload_path = Path(project.upload_path)
        
        # Check if it's a zip file
        if upload_path.suffix.lower() == '.zip' and upload_path.exists():
            try:
                with zipfile.ZipFile(upload_path, 'r') as zf:
                    # Try to find the file in the zip
                    # file_path might be "DVWA/login.php" but in zip it could be under a root folder
                    
                    # Try exact match first
                    zip_names = zf.namelist()
                    target_file = None
                    
                    # Normalize file_path
                    normalized_path = file_path.lstrip("/").replace("\\", "/")
                    
                    # Strategy 1: Exact match
                    if normalized_path in zip_names:
                        target_file = normalized_path
                    
                    # Strategy 2: Try with common zip root folder patterns
                    if not target_file:
                        for name in zip_names:
                            # Check if file matches after first directory component
                            # e.g., "DVWA-master/DVWA/login.php" matches "DVWA/login.php"
                            parts = name.split("/", 1)
                            if len(parts) > 1 and parts[1] == normalized_path:
                                target_file = name
                                break
                            # Also try direct suffix match
                            if name.endswith("/" + normalized_path) or name == normalized_path:
                                target_file = name
                                break
                    
                    if target_file:
                        # Read file content from zip
                        content_bytes = zf.read(target_file)
                        full_content = content_bytes.decode('utf-8', errors='replace')
                        
                        # Detect language
                        ext = Path(target_file).suffix
                        language = detect_language(ext)
                        
            except Exception as e:
                logger.warning(f"Failed to read file from zip {upload_path}: {e}")
        
        # If not a zip, try direct file access (folder-based project)
        elif upload_path.is_dir():
            normalized_path = file_path.lstrip("/").replace("\\", "/")
            
            # Strategy 1: Direct path
            possible_paths = [
                upload_path / normalized_path,
            ]
            
            # Strategy 2: Check immediate subdirectories (common when extracted)
            for subdir in upload_path.iterdir():
                if subdir.is_dir():
                    possible_paths.append(subdir / normalized_path)
            
            # Strategy 3: Search recursively for the file if simple paths don't work
            for try_path in possible_paths:
                if try_path.exists() and try_path.is_file():
                    try:
                        full_content = try_path.read_text(encoding='utf-8', errors='replace')
                        language = detect_language(try_path.suffix)
                        break
                    except Exception as e:
                        logger.warning(f"Failed to read file {try_path}: {e}")
            
            # Strategy 4: If still not found, search by filename as last resort
            if full_content is None:
                filename = normalized_path.split("/")[-1]
                for found_path in upload_path.rglob(filename):
                    if found_path.is_file():
                        # Verify it's the right file by checking path suffix matches
                        if str(found_path).replace("\\", "/").endswith(normalized_path):
                            try:
                                full_content = found_path.read_text(encoding='utf-8', errors='replace')
                                language = detect_language(found_path.suffix)
                                break
                            except Exception as e:
                                logger.warning(f"Failed to read file {found_path}: {e}")
    
    # If we got full content, return it as a single chunk
    if full_content is not None:
        lines = full_content.split('\n')
        return {
            "file_path": file_path,
            "language": language,
            "chunks": [{
                "start_line": 1,
                "end_line": len(lines),
                "code": full_content
            }],
            "findings": [{"line": line, **info} for line, info in finding_lines.items()],
            "total_lines": len(lines),
            "source": "disk"  # Indicates full file from source
        }
    
    # Fallback: use stored chunks from database
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == report.project_id,
        models.CodeChunk.file_path == file_path
    ).order_by(models.CodeChunk.start_line).all()
    
    if not chunks:
        # Try partial match (for paths that might differ slightly)
        filename = file_path.split("/")[-1]
        chunks = db.query(models.CodeChunk).filter(
            models.CodeChunk.project_id == report.project_id,
            models.CodeChunk.file_path.contains(filename)
        ).order_by(models.CodeChunk.start_line).all()
    
    if not chunks:
        raise HTTPException(status_code=404, detail="File not found in codebase")
    
    # Concatenate chunks
    code_parts = []
    language = chunks[0].language if chunks else None
    
    for chunk in chunks:
        code_parts.append({
            "start_line": chunk.start_line,
            "end_line": chunk.end_line,
            "code": chunk.code
        })
    
    return {
        "file_path": file_path,
        "language": language,
        "chunks": code_parts,
        "findings": [{"line": line, **info} for line, info in finding_lines.items()],
        "total_lines": max(c.end_line for c in chunks) if chunks else 0,
        "source": "chunks"  # Indicates assembled from stored chunks
    }


def _severity_rank(severity: str) -> int:
    """Get numeric rank for severity for comparison."""
    ranks = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return ranks.get((severity or "info").lower(), 0)


@router.get("/{report_id}/dependencies")
def get_dependencies(report_id: int, db: Session = Depends(get_db)):
    """
    Get dependency information for the project.
    
    Returns both external dependencies (from manifest files) and 
    internal imports between files for visualization.
    """
    import re
    
    report = _get_report(db, report_id)
    project_id = report.project_id
    
    # Get external dependencies from the database
    external_deps = db.query(models.Dependency).filter(
        models.Dependency.project_id == project_id
    ).all()
    
    # Get all code chunks to analyze internal imports
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == project_id
    ).all()
    
    # Parse imports from code chunks
    internal_imports = []
    import_patterns = {
        "python": [
            r'^import\s+(\S+)',
            r'^from\s+(\S+)\s+import',
        ],
        "javascript": [
            r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
        ],
        "typescript": [
            r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
        ],
        "java": [
            r'^import\s+([\w.]+)',
        ],
        "go": [
            r'import\s+[\'"]([^\'"]+)[\'"]',
            r'import\s+\w+\s+[\'"]([^\'"]+)[\'"]',
        ],
    }
    
    file_imports = defaultdict(set)
    for chunk in chunks:
        lang = (chunk.language or "").lower()
        patterns = import_patterns.get(lang, [])
        
        for pattern in patterns:
            matches = re.findall(pattern, chunk.code, re.MULTILINE)
            for match in matches:
                # Check if it's a relative/internal import
                if match.startswith(".") or match.startswith("./") or match.startswith("../"):
                    file_imports[chunk.file_path].add(match)
                elif "/" in match and not match.startswith("@"):
                    # Could be internal path
                    file_imports[chunk.file_path].add(match)
    
    # Build graph nodes and edges
    files = list(set(c.file_path for c in chunks))
    file_set = set(files)
    
    edges = []
    for source_file, imports in file_imports.items():
        for imp in imports:
            # Try to resolve the import to an actual file
            for target_file in files:
                # Simple matching - check if import matches end of file path
                imp_clean = imp.replace("./", "").replace("../", "")
                if target_file.endswith(imp_clean) or target_file.endswith(imp_clean + ".py") or \
                   target_file.endswith(imp_clean + ".js") or target_file.endswith(imp_clean + ".ts"):
                    edges.append({
                        "source": source_file,
                        "target": target_file,
                        "type": "internal"
                    })
    
    # Check for vulnerabilities linked to dependencies and build CVE map
    vulnerable_deps = set()
    dep_vulns = defaultdict(list)  # dep_id -> list of CVE info
    vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.project_id == project_id,
        models.Vulnerability.dependency_id.isnot(None)
    ).all()
    for v in vulns:
        vulnerable_deps.add(v.dependency_id)
        dep_vulns[v.dependency_id].append({
            "cve_id": v.external_id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
        })
    
    return {
        "report_id": report_id,
        "external_dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "manifest_path": d.manifest_path,
                "has_vulnerabilities": d.id in vulnerable_deps,
                "vulnerabilities": dep_vulns.get(d.id, []),  # Include CVE details!
            }
            for d in external_deps
        ],
        "internal_imports": edges,
        "files": files,
        "summary": {
            "total_external": len(external_deps),
            "vulnerable_count": len(vulnerable_deps),
            "total_cves": len(vulns),
            "total_internal_edges": len(edges),
            "total_files": len(files),
            "ecosystems": list(set(d.ecosystem for d in external_deps if d.ecosystem))
        }
    }


@router.get("/{report_id}/vulnerabilities")
def get_vulnerabilities(report_id: int, db: Session = Depends(get_db)):
    """
    Get detailed CVE/CWE vulnerability information for the report.
    
    Returns:
    - All CVEs found in dependencies with full details
    - CWE breakdown from static analysis findings
    - EPSS scores and KEV status where available
    - Affected packages and fix versions
    """
    report = _get_report(db, report_id)
    project_id = report.project_id
    
    # Get all vulnerabilities from dependencies (CVEs)
    vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.project_id == project_id
    ).all()
    
    # Get all findings for CWE analysis
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    
    # Get dependencies for context
    deps = db.query(models.Dependency).filter(
        models.Dependency.project_id == project_id
    ).all()
    dep_map = {d.id: d for d in deps}
    
    # Build CVE list with full details
    cve_list = []
    for v in vulns:
        dep = dep_map.get(v.dependency_id)
        cve_entry = {
            "id": v.id,
            "cve_id": v.external_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "source": v.source,
            "package": {
                "name": dep.name if dep else "unknown",
                "version": dep.version if dep else "unknown",
                "ecosystem": dep.ecosystem if dep else "unknown",
            } if dep else None,
        }
        cve_list.append(cve_entry)
    
    # Sort by CVSS score (highest first)
    cve_list.sort(key=lambda x: x.get("cvss_score") or 0, reverse=True)
    
    # Build CWE breakdown from findings
    cwe_counts = defaultdict(lambda: {"count": 0, "findings": [], "severity_breakdown": defaultdict(int)})
    
    # CWE names mapping
    cwe_names = {
        "CWE-22": "Path Traversal",
        "CWE-78": "OS Command Injection",
        "CWE-79": "Cross-site Scripting (XSS)",
        "CWE-89": "SQL Injection",
        "CWE-90": "LDAP Injection",
        "CWE-94": "Code Injection",
        "CWE-95": "Eval Injection",
        "CWE-98": "PHP File Inclusion",
        "CWE-200": "Information Exposure",
        "CWE-259": "Hard-coded Password",
        "CWE-287": "Authentication Issues",
        "CWE-295": "Certificate Validation",
        "CWE-306": "Missing Authentication",
        "CWE-319": "Cleartext Transmission",
        "CWE-326": "Weak Encryption",
        "CWE-327": "Broken Crypto Algorithm",
        "CWE-328": "Weak Hash",
        "CWE-330": "Insufficient Randomness",
        "CWE-338": "Weak PRNG",
        "CWE-352": "Cross-Site Request Forgery",
        "CWE-400": "Resource Exhaustion",
        "CWE-434": "Unrestricted File Upload",
        "CWE-502": "Insecure Deserialization",
        "CWE-601": "Open Redirect",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-614": "Sensitive Cookie Without Secure",
        "CWE-643": "XPath Injection",
        "CWE-693": "Protection Mechanism Failure",
        "CWE-732": "Incorrect Permission Assignment",
        "CWE-770": "Resource Allocation Limits",
        "CWE-798": "Hard-coded Credentials",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
    }
    
    import re
    
    def extract_cwes(raw_cwe) -> list:
        """Extract CWE IDs from various formats (string, list, etc.)"""
        if not raw_cwe:
            return []
        
        cwes = []
        # Handle list of CWEs
        if isinstance(raw_cwe, list):
            for item in raw_cwe:
                cwes.extend(extract_cwes(item))
            return cwes
        
        # Handle string
        if isinstance(raw_cwe, str):
            # Find all CWE patterns like CWE-79, CWE-89, etc.
            matches = re.findall(r'CWE-?\d+', raw_cwe.upper())
            for match in matches:
                # Normalize to CWE-XXX format
                num = re.search(r'\d+', match)
                if num:
                    cwes.append(f"CWE-{num.group()}")
            return cwes
        
        # Handle number
        if isinstance(raw_cwe, (int, float)):
            return [f"CWE-{int(raw_cwe)}"]
        
        return []
    
    for f in findings:
        # Extract CWE from finding details or type
        cwe_ids = []
        details = f.details or {}
        
        # Check various places where CWE might be stored
        if details.get("cwe"):
            cwe_ids.extend(extract_cwes(details["cwe"]))
        if details.get("cwe_id"):
            cwe_ids.extend(extract_cwes(details["cwe_id"]))
        if details.get("metadata", {}).get("cwe"):
            cwe_ids.extend(extract_cwes(details["metadata"]["cwe"]))
        if "CWE-" in f.type.upper():
            cwe_ids.extend(extract_cwes(f.type))
        
        # Deduplicate
        cwe_ids = list(set(cwe_ids))
        
        for cwe_id in cwe_ids:
            cwe_counts[cwe_id]["count"] += 1
            cwe_counts[cwe_id]["severity_breakdown"][f.severity.lower()] += 1
            cwe_counts[cwe_id]["findings"].append({
                "id": f.id,
                "file_path": f.file_path,
                "line": f.start_line,
                "severity": f.severity,
                "summary": f.summary[:100] if f.summary else "",
            })
    
    # Build CWE list with names
    cwe_list = []
    for cwe_id, data in cwe_counts.items():
        cwe_list.append({
            "cwe_id": cwe_id,
            "name": cwe_names.get(cwe_id, "Unknown"),
            "count": data["count"],
            "severity_breakdown": dict(data["severity_breakdown"]),
            "findings": data["findings"][:5],  # First 5 findings as examples
            "mitre_url": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
        })
    
    # Sort by count (most common first)
    cwe_list.sort(key=lambda x: x["count"], reverse=True)
    
    # Build severity summary for CVEs
    cve_severity = defaultdict(int)
    for cve in cve_list:
        sev = (cve.get("severity") or "unknown").lower()
        cve_severity[sev] += 1
    
    # Build severity summary for findings/CWEs
    finding_severity = defaultdict(int)
    for f in findings:
        finding_severity[f.severity.lower()] += 1
    
    return {
        "report_id": report_id,
        "cves": {
            "items": cve_list,
            "total": len(cve_list),
            "by_severity": dict(cve_severity),
            "critical_count": sum(1 for c in cve_list if (c.get("cvss_score") or 0) >= 9.0),
            "high_count": sum(1 for c in cve_list if 7.0 <= (c.get("cvss_score") or 0) < 9.0),
        },
        "cwes": {
            "items": cwe_list,
            "total": len(cwe_list),
            "unique_cwes": len(cwe_list),
            "total_findings_with_cwe": sum(c["count"] for c in cwe_list),
        },
        "summary": {
            "total_cves": len(cve_list),
            "total_cwes": len(cwe_list),
            "total_findings": len(findings),
            "findings_by_severity": dict(finding_severity),
            "most_common_cwe": cwe_list[0]["cwe_id"] if cwe_list else None,
            "highest_cvss": max((c.get("cvss_score") or 0) for c in cve_list) if cve_list else None,
        }
    }


@router.get("/{report_id}/diff/{compare_report_id}")
def get_scan_diff(report_id: int, compare_report_id: int, db: Session = Depends(get_db)):
    """
    Compare two scan reports to show what changed.
    
    Returns:
    - New findings (in current but not in compare)
    - Fixed findings (in compare but not in current)
    - Changed files (modified between scans)
    - New files (added since compare)
    - Removed files (deleted since compare)
    """
    report = _get_report(db, report_id)
    compare_report = _get_report(db, compare_report_id)
    
    # Ensure same project
    if report.project_id != compare_report.project_id:
        raise HTTPException(status_code=400, detail="Reports must be from the same project")
    
    # Get findings for both reports
    current_findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id
    ).all()
    compare_findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == compare_report.scan_run_id
    ).all()
    
    # Create fingerprints for findings (file + line + type)
    def finding_fingerprint(f):
        return f"{f.file_path}:{f.start_line}:{f.type}"
    
    current_fps = {finding_fingerprint(f): f for f in current_findings}
    compare_fps = {finding_fingerprint(f): f for f in compare_findings}
    
    # Find new and fixed findings
    new_finding_fps = set(current_fps.keys()) - set(compare_fps.keys())
    fixed_finding_fps = set(compare_fps.keys()) - set(current_fps.keys())
    
    new_findings = [
        {
            "id": current_fps[fp].id,
            "type": current_fps[fp].type,
            "severity": current_fps[fp].severity,
            "summary": current_fps[fp].summary,
            "file_path": current_fps[fp].file_path,
            "start_line": current_fps[fp].start_line,
        }
        for fp in new_finding_fps
    ]
    
    fixed_findings = [
        {
            "id": compare_fps[fp].id,
            "type": compare_fps[fp].type,
            "severity": compare_fps[fp].severity,
            "summary": compare_fps[fp].summary,
            "file_path": compare_fps[fp].file_path,
            "start_line": compare_fps[fp].start_line,
        }
        for fp in fixed_finding_fps
    ]
    
    # Get files for both scans
    current_chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == report.project_id
    ).all()
    # Note: For simplicity, we use the same chunks since project hasn't changed
    # In a real implementation with versioned code, we'd track file hashes
    
    current_files = set(c.file_path for c in current_chunks)
    
    # Build file change summary
    files_with_new_findings = set(f["file_path"] for f in new_findings)
    files_with_fixed_findings = set(f["file_path"] for f in fixed_findings)
    
    # Count findings changes by severity
    severity_changes = {
        "critical": {"new": 0, "fixed": 0},
        "high": {"new": 0, "fixed": 0},
        "medium": {"new": 0, "fixed": 0},
        "low": {"new": 0, "fixed": 0},
        "info": {"new": 0, "fixed": 0},
    }
    
    for f in new_findings:
        sev = (f["severity"] or "info").lower()
        if sev in severity_changes:
            severity_changes[sev]["new"] += 1
    
    for f in fixed_findings:
        sev = (f["severity"] or "info").lower()
        if sev in severity_changes:
            severity_changes[sev]["fixed"] += 1
    
    return {
        "report_id": report_id,
        "compare_report_id": compare_report_id,
        "current_report_date": report.created_at.isoformat() if report.created_at else None,
        "compare_report_date": compare_report.created_at.isoformat() if compare_report.created_at else None,
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "summary": {
            "total_new": len(new_findings),
            "total_fixed": len(fixed_findings),
            "files_with_new_findings": len(files_with_new_findings),
            "files_with_fixed_findings": len(files_with_fixed_findings),
            "severity_changes": severity_changes,
            "net_change": len(new_findings) - len(fixed_findings),
        },
        "changed_files": list(files_with_new_findings | files_with_fixed_findings),
    }


@router.post("/{report_id}/chat", response_model=ReportChatResponse)
async def chat_about_report(report_id: int, request: ReportChatRequest, db: Session = Depends(get_db)):
    """
    Chat with Gemini about a VR Scan report's findings and exploitability analysis.
    
    Allows users to ask follow-up questions about security findings, attack chains,
    and exploit scenarios.
    """
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
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build findings summary
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            severity = (f.severity or "info").lower()
            if severity in findings_by_severity:
                # Extract details from the JSON field
                details = f.details or {}
                findings_by_severity[severity].append({
                    "type": f.type,
                    "summary": f.summary,
                    "file": f.file_path,
                    "line": f.start_line,
                    "details": str(details)[:300] if details else None,
                    "cwe_id": details.get("cwe_id") or details.get("cwe"),
                    "cve_id": details.get("cve_id") or details.get("cve"),
                })
        
        # Build exploit scenarios summary
        exploit_data = []
        for es in exploit_scenarios:
            exploit_data.append({
                "title": es.title,
                "severity": es.severity,
                "attack_narrative": es.narrative[:500] if es.narrative else None,
                "impact": es.impact,
                "mitigation": es.mitigation_notes[:300] if es.mitigation_notes else None,
                "preconditions": es.preconditions,
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


@router.get("/{report_id}/file-trends/{file_path:path}")
def get_file_trends(report_id: int, file_path: str, db: Session = Depends(get_db)):
    """
    Get finding count trends for a specific file across recent scans.
    Returns the last N reports for the same project with finding counts for this file.
    """
    report = _get_report(db, report_id)
    
    # Get the last 10 reports for this project (most recent first)
    reports = db.query(models.Report).filter(
        models.Report.project_id == report.project_id
    ).order_by(models.Report.created_at.desc()).limit(10).all()
    
    # For each report, count findings in this file
    trends = []
    for r in reversed(reports):  # Oldest to newest for chart
        finding_count = db.query(func.count(models.Finding.id)).filter(
            models.Finding.scan_run_id == r.scan_run_id,
            models.Finding.file_path == file_path
        ).scalar() or 0
        
        # Get severity breakdown
        severity_counts = {}
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = db.query(func.count(models.Finding.id)).filter(
                models.Finding.scan_run_id == r.scan_run_id,
                models.Finding.file_path == file_path,
                func.lower(models.Finding.severity) == sev
            ).scalar() or 0
            if count > 0:
                severity_counts[sev] = count
        
        trends.append({
            "report_id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finding_count": finding_count,
            "severity_counts": severity_counts,
        })
    
    return {
        "file_path": file_path,
        "trends": trends,
        "current_report_id": report_id,
    }


@router.get("/{report_id}/todos")
def get_todos(report_id: int, db: Session = Depends(get_db)):
    """
    Scan code chunks for TODO, FIXME, HACK, XXX, BUG, NOTE comments.
    Returns a list of all comment markers found with line numbers.
    """
    import re
    
    report = _get_report(db, report_id)
    
    # Get all code chunks for this project
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == report.project_id
    ).all()
    
    # Patterns to match (case insensitive)
    patterns = {
        "TODO": re.compile(r'(?:#|//|/\*|\*|--|\'\'\'|"""|<!--|;)\s*TODO[:\s](.+?)(?:\*/|-->|\n|$)', re.IGNORECASE),
        "FIXME": re.compile(r'(?:#|//|/\*|\*|--|\'\'\'|"""|<!--|;)\s*FIXME[:\s](.+?)(?:\*/|-->|\n|$)', re.IGNORECASE),
        "HACK": re.compile(r'(?:#|//|/\*|\*|--|\'\'\'|"""|<!--|;)\s*HACK[:\s](.+?)(?:\*/|-->|\n|$)', re.IGNORECASE),
        "XXX": re.compile(r'(?:#|//|/\*|\*|--|\'\'\'|"""|<!--|;)\s*XXX[:\s](.+?)(?:\*/|-->|\n|$)', re.IGNORECASE),
        "BUG": re.compile(r'(?:#|//|/\*|\*|--|\'\'\'|"""|<!--|;)\s*BUG[:\s](.+?)(?:\*/|-->|\n|$)', re.IGNORECASE),
        "NOTE": re.compile(r'(?:#|//|/\*|\*|--|\'\'\'|"""|<!--|;)\s*NOTE[:\s](.+?)(?:\*/|-->|\n|$)', re.IGNORECASE),
    }
    
    todos = []
    
    for chunk in chunks:
        if not chunk.code:
            continue
            
        lines = chunk.code.split('\n')
        for line_offset, line in enumerate(lines):
            line_num = (chunk.start_line or 1) + line_offset
            
            for marker, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    # Get the text after the marker
                    text = match.group(1).strip() if match.lastindex else ""
                    # Fallback: grab rest of line after marker
                    if not text:
                        idx = line.upper().find(marker)
                        if idx >= 0:
                            text = line[idx + len(marker):].strip().lstrip(':').strip()
                    
                    todos.append({
                        "type": marker,
                        "file_path": chunk.file_path,
                        "line": line_num,
                        "text": text[:200],  # Limit length
                        "full_line": line.strip()[:300],
                    })
    
    # Sort by file, then by line
    todos.sort(key=lambda x: (x["file_path"], x["line"]))
    
    # Summary counts
    summary = {}
    for t in todos:
        summary[t["type"]] = summary.get(t["type"], 0) + 1
    
    # Group by file
    by_file = {}
    for t in todos:
        if t["file_path"] not in by_file:
            by_file[t["file_path"]] = []
        by_file[t["file_path"]].append(t)
    
    return {
        "total": len(todos),
        "summary": summary,
        "by_file": by_file,
        "items": todos,
    }


async def _validate_secrets_with_gemini(secrets: list, max_batch: int = 50) -> dict:
    """
    Use Gemini to validate detected secrets and filter false positives.
    Returns a dict mapping secret index to validation result.
    """
    from backend.core.config import settings
    
    if not settings.gemini_api_key or not secrets:
        return {}
    
    try:
        from google import genai
        from google.genai import types
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Limit batch size to avoid token limits
        secrets_to_validate = secrets[:max_batch]
        
        # Build the prompt with secrets info
        secrets_info = []
        for i, s in enumerate(secrets_to_validate):
            secrets_info.append(f"""
[{i}] Type: {s['type']}
    File: {s['file_path']}
    Line: {s['line']}
    Value: {s['value']}
    Context: {s['full_line']}
""")
        
        prompt = f"""You are a security expert analyzing code for hardcoded secrets and credentials.

I have detected the following potential secrets in a codebase. For each one, determine if it's:
1. A REAL secret that should be flagged (actual API key, password, credential, etc.)
2. A FALSE POSITIVE (placeholder, example value, test data, documentation, environment variable reference, etc.)

For each secret, provide:
- is_real: true/false
- confidence: 0.0-1.0 (how confident you are)
- reason: brief explanation
- risk_level: "critical", "high", "medium", "low", or "none" (if false positive)

Respond in JSON format like this:
{{
  "validations": [
    {{"index": 0, "is_real": true, "confidence": 0.95, "reason": "Appears to be a production API key", "risk_level": "high"}},
    {{"index": 1, "is_real": false, "confidence": 0.9, "reason": "This is an example placeholder value", "risk_level": "none"}}
  ]
}}

SECRETS TO ANALYZE:
{''.join(secrets_info)}

Important considerations:
- Values like "your_api_key_here", "changeme", "password123", "test", "example" are usually placeholders
- Environment variable references like "${{API_KEY}}" or "process.env.SECRET" are not hardcoded secrets
- Look for context clues in the surrounding code line
- Real AWS keys start with AKIA and are 20 chars
- Real JWT tokens have 3 base64 parts separated by dots
- Email addresses in test files or example code are usually not sensitive
- IP addresses like 127.0.0.1, 0.0.0.0, or 192.168.x.x are typically not sensitive

Analyze each carefully and respond with ONLY the JSON object."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=[types.Content(role="user", parts=[types.Part(text=prompt)])],
            config=types.GenerateContentConfig(
                temperature=0.1,  # Low temperature for consistent analysis
                response_mime_type="application/json",
            ),
        )
        
        # Parse the response
        import json
        result_text = response.text.strip()
        # Handle markdown code blocks
        if result_text.startswith("```"):
            result_text = result_text.split("```")[1]
            if result_text.startswith("json"):
                result_text = result_text[4:]
        
        result = json.loads(result_text)
        
        # Build validation map
        validation_map = {}
        for v in result.get("validations", []):
            idx = v.get("index")
            if idx is not None and idx < len(secrets_to_validate):
                validation_map[idx] = {
                    "is_real": v.get("is_real", True),
                    "confidence": v.get("confidence", 0.5),
                    "reason": v.get("reason", ""),
                    "ai_risk_level": v.get("risk_level", "medium"),
                }
        
        return validation_map
        
    except Exception as e:
        logger.error(f"Gemini validation failed: {e}")
        return {}


@router.get("/{report_id}/secrets")
async def get_secrets(
    report_id: int, 
    use_ai: bool = Query(True, description="Use Gemini AI to validate and filter false positives"),
    db: Session = Depends(get_db)
):
    """
    Scan code chunks for potential secrets, credentials, and sensitive data.
    Detects: emails, API keys, passwords, phone numbers, usernames, tokens, etc.
    
    When use_ai=True, uses Gemini to validate findings and filter false positives.
    """
    import re
    
    report = _get_report(db, report_id)
    
    # Get all code chunks for this project
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == report.project_id
    ).all()
    
    # Comprehensive patterns for sensitive data detection (PII + credentials)
    patterns = {
        # === CREDENTIALS & API KEYS ===
        "email": re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
        "api_key": re.compile(r'(?:api[_-]?key|apikey|api_secret|access[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', re.IGNORECASE),
        "password": re.compile(r'(?:password|passwd|pwd|secret|credential)["\']?\s*[:=]\s*["\']?([^\s"\']{4,})["\']?', re.IGNORECASE),
        "token": re.compile(r'(?:token|bearer|auth[_-]?token|access[_-]?token|refresh[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', re.IGNORECASE),
        "aws_key": re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
        "aws_secret": re.compile(r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', re.IGNORECASE),
        "private_key": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "github_token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'),
        "url_with_creds": re.compile(r'(?:https?|ftp)://[^:]+:[^@]+@[^\s]+'),
        "connection_string": re.compile(r'(?:mongodb|mysql|postgres|redis|amqp|mssql)://[^\s"\']+', re.IGNORECASE),
        "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+'),
        "stripe_key": re.compile(r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}'),
        "google_api": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
        "openai_key": re.compile(r'sk-[A-Za-z0-9]{48,}'),
        "anthropic_key": re.compile(r'sk-ant-[A-Za-z0-9_-]{40,}'),
        "generic_secret": re.compile(r'(?:secret|private|confidential)[_-]?(?:key|token|password)?["\']?\s*[:=]\s*["\']?([^\s"\']{8,})["\']?', re.IGNORECASE),
        
        # === PII - PERSONALLY IDENTIFIABLE INFORMATION ===
        "phone": re.compile(r'(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}'),
        "phone_intl": re.compile(r'\+[1-9]\d{6,14}'),  # International phone format
        "ssn": re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'),  # Social Security Number
        "credit_card": re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'),  # Visa, MC, Amex, Discover
        "ip_address": re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        
        # === USERNAMES & IDENTIFIERS ===
        "username": re.compile(r'(?:username|user_name|user|login)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{3,30})["\']', re.IGNORECASE),
        "user_id": re.compile(r'(?:user_id|userid|uid|account_id)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{4,})["\']?', re.IGNORECASE),
        
        # === PERSONAL NAMES (in assignments/configs) ===
        "hardcoded_name": re.compile(r'(?:name|full_name|first_name|last_name|author|owner|contact)["\']?\s*[:=]\s*["\']([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)["\']', re.IGNORECASE),
        
        # === ADDRESSES ===
        "address": re.compile(r'(?:address|street|addr)["\']?\s*[:=]\s*["\'](\d+\s+[A-Za-z\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)[,\s]+[A-Za-z\s]+)["\']', re.IGNORECASE),
        
        # === DATABASE CREDENTIALS ===
        "db_password": re.compile(r'(?:db_password|database_password|mysql_password|postgres_password|mongo_password)["\']?\s*[:=]\s*["\']?([^\s"\']{4,})["\']?', re.IGNORECASE),
        "db_user": re.compile(r'(?:db_user|database_user|mysql_user|postgres_user|mongo_user)["\']?\s*[:=]\s*["\']?([^\s"\']{2,})["\']?', re.IGNORECASE),
    }
    
    # Files to skip (binary, images, etc.)
    skip_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.zip', '.tar', '.gz', '.pdf'}
    
    secrets = []
    seen_values = set()  # Deduplicate
    
    for chunk in chunks:
        if not chunk.code or not chunk.file_path:
            continue
        
        # Skip binary files
        ext = '.' + chunk.file_path.split('.')[-1].lower() if '.' in chunk.file_path else ''
        if ext in skip_extensions:
            continue
            
        lines = chunk.code.split('\n')
        for line_offset, line in enumerate(lines):
            line_num = (chunk.start_line or 1) + line_offset
            
            # Skip comments that are just documentation about secrets
            line_lower = line.lower()
            if 'example' in line_lower or 'sample' in line_lower or 'placeholder' in line_lower:
                continue
            
            for secret_type, pattern in patterns.items():
                matches = pattern.finditer(line)
                for match in matches:
                    # Get the actual value
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    # Skip common false positives
                    if value.lower() in {'password', 'secret', 'token', 'api_key', 'your_', 'xxx', 'example', 'test', 'placeholder', 'changeme', 'root', 'admin', 'user', 'localhost'}:
                        continue
                    if len(value) < 4:
                        continue
                    # Skip common test/placeholder IP addresses
                    if secret_type == 'ip_address' and value in {'127.0.0.1', '0.0.0.0', '255.255.255.255', '192.168.1.1', '10.0.0.1'}:
                        continue
                    
                    # Dedupe by value
                    dedup_key = f"{secret_type}:{value}"
                    if dedup_key in seen_values:
                        continue
                    seen_values.add(dedup_key)
                    
                    # NO MASKING - show actual secret value for security audit purposes
                    secrets.append({
                        "type": secret_type,
                        "file_path": chunk.file_path,
                        "line": line_num,
                        "value": value,  # Full unmasked value
                        "masked_value": value,  # Same as value (no masking)
                        "full_line": line.strip()[:300],
                        "severity": _get_secret_severity(secret_type),
                    })
    
    # Use Gemini to validate secrets and filter false positives
    ai_validated = False
    ai_error = None
    filtered_count = 0
    
    if use_ai and secrets:
        try:
            validation_map = await _validate_secrets_with_gemini(secrets)
            
            if validation_map:
                ai_validated = True
                validated_secrets = []
                
                for i, s in enumerate(secrets):
                    validation = validation_map.get(i)
                    if validation:
                        s["ai_validated"] = True
                        s["ai_is_real"] = validation["is_real"]
                        s["ai_confidence"] = validation["confidence"]
                        s["ai_reason"] = validation["reason"]
                        s["ai_risk_level"] = validation["ai_risk_level"]
                        
                        # Only include if AI thinks it's real OR confidence is low
                        if validation["is_real"] or validation["confidence"] < 0.7:
                            validated_secrets.append(s)
                        else:
                            filtered_count += 1
                    else:
                        # No validation for this one (beyond batch limit), include it
                        s["ai_validated"] = False
                        validated_secrets.append(s)
                
                secrets = validated_secrets
        except Exception as e:
            ai_error = str(e)
            logger.error(f"AI validation error: {e}")
    
    # Sort by severity (critical first), then by type
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    secrets.sort(key=lambda x: (severity_order.get(x.get("ai_risk_level", x["severity"]), 4), x["type"], x["file_path"]))
    
    # Summary counts
    summary = {}
    for s in secrets:
        summary[s["type"]] = summary.get(s["type"], 0) + 1
    
    # Group by file
    by_file = {}
    for s in secrets:
        if s["file_path"] not in by_file:
            by_file[s["file_path"]] = []
        by_file[s["file_path"]].append(s)
    
    # Group by type for easy filtering
    by_type = {}
    for s in secrets:
        if s["type"] not in by_type:
            by_type[s["type"]] = []
        by_type[s["type"]].append(s)
    
    return {
        "total": len(secrets),
        "summary": summary,
        "by_file": by_file,
        "by_type": by_type,
        "items": secrets,
        "ai_validated": ai_validated,
        "ai_filtered_count": filtered_count,
        "ai_error": ai_error,
    }


def _get_secret_severity(secret_type: str) -> str:
    """Assign severity based on secret type (credentials + PII)."""
    # Critical - immediate risk of account compromise or data breach
    critical = {
        "private_key", "aws_secret", "password", "connection_string", 
        "url_with_creds", "db_password", "credit_card", "ssn"
    }
    # High - significant security risk
    high = {
        "api_key", "token", "aws_key", "github_token", "stripe_key", 
        "slack_webhook", "jwt", "openai_key", "anthropic_key", "db_user"
    }
    # Medium - potential security concern
    medium = {
        "google_api", "generic_secret", "username", "user_id", 
        "hardcoded_name", "address"
    }
    # Low - PII that may need protection but lower risk
    # email, phone, phone_intl, ip_address
    
    if secret_type in critical:
        return "critical"
    elif secret_type in high:
        return "high"
    elif secret_type in medium:
        return "medium"
    return "low"


@router.get("/{report_id}/search-code")
def search_code(
    report_id: int, 
    q: str = Query(..., min_length=2, description="Search query"),
    db: Session = Depends(get_db)
):
    """
    Full-text search across code content in the codebase.
    Returns matching lines with context.
    """
    import re
    
    report = _get_report(db, report_id)
    
    # Get all code chunks for this project
    chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == report.project_id
    ).all()
    
    results = []
    query_lower = q.lower()
    
    for chunk in chunks:
        if not chunk.code:
            continue
        
        lines = chunk.code.split('\n')
        for line_offset, line in enumerate(lines):
            if query_lower in line.lower():
                line_num = (chunk.start_line or 1) + line_offset
                
                # Get context (1 line before and after)
                context_before = lines[line_offset - 1] if line_offset > 0 else None
                context_after = lines[line_offset + 1] if line_offset < len(lines) - 1 else None
                
                results.append({
                    "file_path": chunk.file_path,
                    "line": line_num,
                    "content": line.strip(),
                    "context_before": context_before.strip() if context_before else None,
                    "context_after": context_after.strip() if context_after else None,
                    "language": chunk.language,
                })
        
        # Limit results to prevent huge responses
        if len(results) >= 100:
            break
    
    return {
        "query": q,
        "total": len(results),
        "results": results[:100],
        "truncated": len(results) >= 100,
    }


class ExplainCodeRequest(BaseModel):
    file_path: str
    code: str
    language: str = None


@router.post("/{report_id}/explain-code")
def explain_code(report_id: int, request: ExplainCodeRequest, db: Session = Depends(get_db)):
    """
    Use AI to explain what a code file does.
    """
    from google import genai
    from google.genai import types
    
    report = _get_report(db, report_id)
    
    # Get findings for this file to provide context
    findings = db.query(models.Finding).filter(
        models.Finding.scan_run_id == report.scan_run_id,
        models.Finding.file_path == request.file_path
    ).all()
    
    findings_context = ""
    if findings:
        findings_context = f"\n\n## Security Findings in this file ({len(findings)} total):\n"
        for f in findings[:10]:
            findings_context += f"- Line {f.start_line}: [{f.severity}] {f.type} - {f.summary[:100]}\n"
    
    try:
        client = genai.Client()
        
        prompt = f"""You are a code analysis assistant. Explain what this code file does in a clear, concise way.

## File: {request.file_path}
## Language: {request.language or 'Unknown'}

```{request.language or ''}
{request.code[:15000]}
```
{findings_context}

Provide:
1. **Purpose**: What does this file/module do? (1-2 sentences)
2. **Key Components**: Main functions/classes and what they do
3. **Data Flow**: How data moves through this code
4. **Dependencies**: What external libraries/modules it uses
5. **Security Notes**: Any security-relevant observations based on the code and findings

Keep the explanation concise but informative. Use bullet points."""

        response = client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.3,
                max_output_tokens=1500,
            )
        )
        
        return {
            "file_path": request.file_path,
            "explanation": response.text,
            "findings_count": len(findings),
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "file_path": request.file_path,
            "explanation": None,
            "error": f"Failed to generate explanation: {str(e)}",
        }
