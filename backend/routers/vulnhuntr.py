"""
VulnHuntr Router - LLM-Powered Vulnerability Hunting API

Endpoints for running VulnHuntr analysis on projects.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import json

from ..services.vulnhuntr_service import (
    vulnhuntr_service,
    generate_vulnhuntr_markdown,
    result_to_dict,
    VulnHuntrResult
)
from ..core.logging import get_logger
from backend.core.auth import get_current_active_user
from backend.core.file_validator import sanitize_filename
from backend.models.models import User

logger = get_logger(__name__)

router = APIRouter(prefix="/vulnhuntr", tags=["vulnhuntr"])

# ============================================================================
# Request/Response Models
# ============================================================================

class VulnHuntrRequest(BaseModel):
    """Request to run VulnHuntr analysis"""
    project_path: str
    file_extensions: List[str] = [".py"]
    max_files: int = 500
    deep_analysis: bool = True

class VulnHuntrQuickScanRequest(BaseModel):
    """Request for quick code snippet analysis"""
    code: str
    filename: str = "snippet.py"
    language: str = "python"

class VulnHuntrResponse(BaseModel):
    """Response from VulnHuntr analysis"""
    success: bool
    scan_id: str
    total_files_scanned: int
    sources_found: int
    sinks_found: int
    vulnerabilities_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_duration_seconds: float
    vulnerabilities: List[Dict[str, Any]]
    statistics: Dict[str, Any]

# In-memory storage for scan results (in production, use database)
_scan_results: Dict[str, VulnHuntrResult] = {}


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/analyze", response_model=VulnHuntrResponse)
async def analyze_project(request: VulnHuntrRequest, current_user: User = Depends(get_current_active_user)):
    """
    Run VulnHuntr analysis on a project.
    
    Traces user input through call chains to identify remotely exploitable vulnerabilities.
    
    - **project_path**: Path to the project directory
    - **file_extensions**: File extensions to analyze (default: .py)
    - **max_files**: Maximum number of files to process
    - **deep_analysis**: Whether to use LLM for deep analysis
    """
    # Validate project path
    if not os.path.exists(request.project_path):
        raise HTTPException(status_code=404, detail=f"Project path not found: {request.project_path}")
    
    if not os.path.isdir(request.project_path):
        raise HTTPException(status_code=400, detail="Project path must be a directory")
    
    try:
        logger.info(f"VulnHuntr: Starting analysis of {request.project_path}")
        
        result = await vulnhuntr_service.analyze_project(
            project_path=request.project_path,
            file_extensions=request.file_extensions,
            max_files=request.max_files,
            deep_analysis=request.deep_analysis
        )
        
        # Store result for later retrieval
        _scan_results[result.scan_id] = result
        
        # Convert to response
        stats = result.statistics.get("by_severity", {})
        
        return VulnHuntrResponse(
            success=True,
            scan_id=result.scan_id,
            total_files_scanned=result.total_files_scanned,
            sources_found=result.sources_found,
            sinks_found=result.sinks_found,
            vulnerabilities_count=len(result.vulnerabilities),
            critical_count=stats.get("critical", 0),
            high_count=stats.get("high", 0),
            medium_count=stats.get("medium", 0),
            low_count=stats.get("low", 0),
            scan_duration_seconds=result.scan_duration_seconds,
            vulnerabilities=result_to_dict(result)["vulnerabilities"],
            statistics=result.statistics
        )
        
    except Exception as e:
        logger.error(f"VulnHuntr: Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{scan_id}")
async def get_scan_results(scan_id: str, current_user: User = Depends(get_current_active_user)):
    """Get results from a previous VulnHuntr scan"""
    if scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    
    result = _scan_results[scan_id]
    return result_to_dict(result)


@router.get("/results/{scan_id}/markdown")
async def get_scan_markdown(scan_id: str, current_user: User = Depends(get_current_active_user)):
    """Get VulnHuntr results as Markdown report"""
    if scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
    
    result = _scan_results[scan_id]
    markdown = generate_vulnhuntr_markdown(result)
    
    return Response(
        content=markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=vulnhuntr_{scan_id}.md"}
    )


@router.post("/quick-scan")
async def quick_scan_code(request: VulnHuntrQuickScanRequest, current_user: User = Depends(get_current_active_user)):
    """
    Quick scan a code snippet for vulnerabilities.
    
    Useful for analyzing individual files or code blocks.
    """
    import tempfile
    import shutil

    # Create temporary directory with the code
    temp_dir = tempfile.mkdtemp(prefix="vulnhuntr_")

    try:
        # Sanitize filename to prevent path traversal attacks
        safe_filename = sanitize_filename(request.filename, preserve_extension=True)
        # Write code to temp file
        file_path = os.path.join(temp_dir, safe_filename)
        with open(file_path, 'w') as f:
            f.write(request.code)
        
        # Run analysis
        result = await vulnhuntr_service.analyze_project(
            project_path=temp_dir,
            file_extensions=[f".{request.language}" if not request.language.startswith('.') else request.language],
            max_files=1,
            deep_analysis=True
        )
        
        return {
            "success": True,
            "vulnerabilities_count": len(result.vulnerabilities),
            "sources_found": result.sources_found,
            "sinks_found": result.sinks_found,
            "vulnerabilities": result_to_dict(result)["vulnerabilities"],
        }
        
    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("/patterns")
async def get_vulnerability_patterns(current_user: User = Depends(get_current_active_user)):
    """
    Get the list of vulnerability patterns that VulnHuntr checks for.
    
    Returns source patterns (user input points) and sink patterns (dangerous functions).
    """
    from ..services.vulnhuntr_service import PYTHON_SOURCES, PYTHON_SINKS
    
    return {
        "sources": {
            source_type: len(patterns) 
            for source_type, patterns in PYTHON_SOURCES.items()
        },
        "sinks": {
            sink_name: {
                "patterns_count": len(info["patterns"]),
                "vulnerability_type": info["vuln_type"],
                "cwe": info["cwe"],
                "severity": info["severity"]
            }
            for sink_name, info in PYTHON_SINKS.items()
        },
        "vulnerability_types": list(set(
            info["vuln_type"] for info in PYTHON_SINKS.values()
        ))
    }


@router.get("/stats")
async def get_vulnhuntr_stats(current_user: User = Depends(get_current_active_user)):
    """Get statistics about VulnHuntr scans"""
    total_scans = len(_scan_results)
    total_vulns = sum(len(r.vulnerabilities) for r in _scan_results.values())
    
    type_counts = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for result in _scan_results.values():
        for vuln in result.vulnerabilities:
            type_counts[vuln.vulnerability_type] = type_counts.get(vuln.vulnerability_type, 0) + 1
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
    
    return {
        "total_scans": total_scans,
        "total_vulnerabilities_found": total_vulns,
        "by_type": type_counts,
        "by_severity": severity_counts,
        "recent_scans": [
            {
                "scan_id": r.scan_id,
                "project": r.project_path,
                "timestamp": r.timestamp,
                "vulns": len(r.vulnerabilities)
            }
            for r in list(_scan_results.values())[-10:]
        ]
    }
