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
    
    # Check for vulnerabilities linked to dependencies
    vulnerable_deps = set()
    vulns = db.query(models.Vulnerability).filter(
        models.Vulnerability.project_id == project_id,
        models.Vulnerability.dependency_id.isnot(None)
    ).all()
    for v in vulns:
        vulnerable_deps.add(v.dependency_id)
    
    return {
        "report_id": report_id,
        "external_dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "manifest_path": d.manifest_path,
                "has_vulnerabilities": d.id in vulnerable_deps
            }
            for d in external_deps
        ],
        "internal_imports": edges,
        "files": files,
        "summary": {
            "total_external": len(external_deps),
            "vulnerable_count": len(vulnerable_deps),
            "total_internal_edges": len(edges),
            "total_files": len(files),
            "ecosystems": list(set(d.ecosystem for d in external_deps if d.ecosystem))
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
            model="gemini-2.0-flash",
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
            model="gemini-2.0-flash",
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
