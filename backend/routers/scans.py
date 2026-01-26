from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from pathlib import Path
import tempfile
import shutil
import zipfile
from datetime import datetime

from backend import models
from backend.core.database import get_db
from backend.core.auth import get_current_active_user
from backend.core.logging import get_logger
from backend.models.models import User
from backend.schemas import ScanRun
from backend.services import project_service, git_service
from backend.tasks.jobs import enqueue_scan

router = APIRouter()
logger = get_logger(__name__)


class ScanOptions(BaseModel):
    """Options for triggering a security scan"""
    enhanced_scan: bool = False   # Enhanced mode: 80→30→12 files (off by default)


class QuickScanResponse(BaseModel):
    """Response for quick scan operations"""
    project_id: int
    project_name: str
    scan_run_id: int
    message: str


class QuickCloneRequest(BaseModel):
    """Request for quick clone and scan"""
    repo_url: str
    branch: Optional[str] = None
    enhanced_scan: bool = False


@router.post("/{project_id}/scan", response_model=ScanRun)
def trigger_scan(
    project_id: int, 
    options: Optional[ScanOptions] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Verify user has access to project
    if project.owner_id != current_user.id:
        from backend.models.models import ProjectCollaborator
        from sqlalchemy import and_
        collab = db.query(ProjectCollaborator).filter(
            and_(
                ProjectCollaborator.project_id == project_id,
                ProjectCollaborator.user_id == current_user.id,
                ProjectCollaborator.status == "accepted"
            )
        ).first()
        if not collab:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Store scan options - agentic AI is always enabled
    scan_options = {
        "include_agentic": True  # Always run agentic AI scan
    }
    if options and options.enhanced_scan:
        scan_options["enhanced_scan"] = True
    
    scan_run = models.ScanRun(
        project_id=project.id, 
        status="queued",
        options=scan_options if scan_options else None
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    enqueue_scan(project.id, scan_run.id)
    return scan_run


@router.get("/scan-runs/{scan_run_id}", response_model=ScanRun)
def get_scan_status(
    scan_run_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    scan = db.query(models.ScanRun).get(scan_run_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    # Verify user has access to the project
    project = project_service.get_project(db, scan.project_id)
    if project and project.owner_id != current_user.id:
        from backend.models.models import ProjectCollaborator
        from sqlalchemy import and_
        collab = db.query(ProjectCollaborator).filter(
            and_(
                ProjectCollaborator.project_id == scan.project_id,
                ProjectCollaborator.user_id == current_user.id,
                ProjectCollaborator.status == "accepted"
            )
        ).first()
        if not collab:
            raise HTTPException(status_code=403, detail="Access denied")
    return scan

@router.get("/scan-runs/{scan_run_id}/progress")
def get_scan_progress(
    scan_run_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the current scan progress (HTTP fallback for WebSocket).
    
    Returns the last known progress state for polling when WebSocket fails.
    """
    from backend.services.websocket_service import manager
    import json
    
    # First check if scan exists
    scan = db.query(models.ScanRun).get(scan_run_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found")
    
    # Verify user has access to the project
    project = project_service.get_project(db, scan.project_id)
    if project and project.owner_id != current_user.id:
        from backend.models.models import ProjectCollaborator
        from sqlalchemy import and_
        collab = db.query(ProjectCollaborator).filter(
            and_(
                ProjectCollaborator.project_id == scan.project_id,
                ProjectCollaborator.user_id == current_user.id,
                ProjectCollaborator.status == "accepted"
            )
        ).first()
        if not collab:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Try to get cached WebSocket progress
    cached = manager.get_cached_progress(scan_run_id)
    if cached:
        return json.loads(cached)
    
    # Fallback to database status
    return {
        "scan_run_id": scan.id,
        "project_id": scan.project_id,
        "phase": "complete" if scan.status == "completed" else "failed" if scan.status == "failed" else scan.status,
        "progress": 100 if scan.status in ("completed", "failed") else 50,
        "message": f"Scan {scan.status}",
        "timestamp": scan.finished_at.isoformat() if scan.finished_at else scan.started_at.isoformat() if scan.started_at else None
    }


# ============================================================================
# Quick Scan Endpoints (standalone, no project required)
# ============================================================================

@router.post("/quick-scan/upload", response_model=QuickScanResponse)
async def quick_scan_upload(
    file: UploadFile = File(...),
    enhanced_scan: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Upload code and immediately start a scan without creating a project first.
    Automatically creates a project named after the uploaded file.
    """
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only zip uploads are supported")
    
    # Create project name from filename
    project_name = file.filename.replace(".zip", "")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_name = f"Quick Scan - {project_name} ({timestamp})"
    
    # Create the project
    from backend.schemas import ProjectCreate
    project_in = ProjectCreate(name=project_name, description="Created via Quick Scan")
    project = project_service.create_project(db, project_in, owner_id=current_user.id)
    
    # Save the upload
    tmp_dir = Path(tempfile.mkdtemp(prefix="quick_upload_"))
    dest = tmp_dir / file.filename
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    project_service.save_upload(db, project, str(dest))
    
    # Create and start scan
    scan_options = {"include_agentic": True}
    if enhanced_scan:
        scan_options["enhanced_scan"] = True
    
    scan_run = models.ScanRun(
        project_id=project.id,
        status="queued",
        options=scan_options
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    enqueue_scan(project.id, scan_run.id)
    
    logger.info(f"Quick scan started: project={project.id}, scan_run={scan_run.id}")
    
    return QuickScanResponse(
        project_id=project.id,
        project_name=project.name,
        scan_run_id=scan_run.id,
        message="Upload received and scan started"
    )


@router.post("/quick-scan/clone", response_model=QuickScanResponse)
async def quick_scan_clone(
    request: QuickCloneRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Clone a repository and immediately start a scan without creating a project first.
    Automatically creates a project named after the repository.
    """
    try:
        # Clone the repository
        logger.info(f"Quick scan cloning repository: {request.repo_url}")
        result = git_service.clone_repository(
            repo_url=request.repo_url,
            branch=request.branch,
            depth=1,
        )
        
        if not result.success:
            raise HTTPException(status_code=400, detail=result.error or "Clone failed")
        
        # Create project from repo name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_name = f"Quick Scan - {result.repo_name} ({timestamp})"
        
        from backend.schemas import ProjectCreate
        project_in = ProjectCreate(
            name=project_name, 
            description=f"Cloned from {request.repo_url}",
            git_url=request.repo_url
        )
        project = project_service.create_project(db, project_in, owner_id=current_user.id)
        
        # Create zip from cloned repo
        tmp_dir = Path(tempfile.mkdtemp(prefix="quick_clone_"))
        zip_path = tmp_dir / f"{result.repo_name}.zip"
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            clone_path = Path(result.path)
            for file_path in clone_path.rglob("*"):
                if ".git" in file_path.parts:
                    continue
                if file_path.is_file():
                    arcname = file_path.relative_to(clone_path)
                    zipf.write(file_path, arcname)
        
        git_service.cleanup_clone(result.path)
        project_service.save_upload(db, project, str(zip_path))
        
        # Update git_url
        project.git_url = request.repo_url
        db.add(project)
        db.commit()
        
        # Create and start scan
        scan_options = {"include_agentic": True}
        if request.enhanced_scan:
            scan_options["enhanced_scan"] = True
        
        scan_run = models.ScanRun(
            project_id=project.id,
            status="queued",
            options=scan_options
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)
        enqueue_scan(project.id, scan_run.id)
        
        logger.info(f"Quick scan from clone started: project={project.id}, scan_run={scan_run.id}, repo={result.repo_name}")
        
        return QuickScanResponse(
            project_id=project.id,
            project_name=project.name,
            scan_run_id=scan_run.id,
            message=f"Repository {result.repo_name} cloned and scan started"
        )
        
    except git_service.InvalidRepoURLError as e:
        logger.warning(f"Invalid repository URL: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except git_service.GitCloneError as e:
        logger.error(f"Git clone error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Unexpected error during quick clone: {e}")
        raise HTTPException(status_code=500, detail=f"Clone failed: {str(e)}")