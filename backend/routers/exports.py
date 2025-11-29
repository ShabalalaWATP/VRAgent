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
    """Export report as Markdown."""
    try:
        report, findings = export_service.get_report_with_findings(db, report_id)
        content = export_service.generate_markdown(report, findings)
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
    """Export report as PDF."""
    try:
        report, findings = export_service.get_report_with_findings(db, report_id)
        content = export_service.generate_pdf(report, findings)
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
    """Export report as DOCX."""
    try:
        report, findings = export_service.get_report_with_findings(db, report_id)
        content = export_service.generate_docx(report, findings)
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
