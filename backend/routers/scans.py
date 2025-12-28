from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session

from backend import models
from backend.core.database import get_db
from backend.schemas import ScanRun
from backend.services import project_service
from backend.tasks.jobs import enqueue_scan

router = APIRouter()


class ScanOptions(BaseModel):
    """Options for triggering a security scan"""
    enhanced_scan: bool = False   # Enhanced mode: 80→30→12 files (off by default)


@router.post("/{project_id}/scan", response_model=ScanRun)
def trigger_scan(
    project_id: int, 
    options: Optional[ScanOptions] = None,
    db: Session = Depends(get_db)
):
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
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
def get_scan_status(scan_run_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanRun).get(scan_run_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan run not found")
    return scan

@router.get("/scan-runs/{scan_run_id}/progress")
def get_scan_progress(scan_run_id: int, db: Session = Depends(get_db)):
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