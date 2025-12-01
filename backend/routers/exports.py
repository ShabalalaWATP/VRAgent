import json
from collections import defaultdict
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend import models
from backend.core.database import get_db
from backend.core.logging import get_logger
from backend.services import export_service, sbom_service
from backend.schemas import Report, Finding

logger = get_logger(__name__)

router = APIRouter()


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
