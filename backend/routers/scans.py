from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend import models
from backend.core.database import get_db
from backend.schemas import ScanRun
from backend.services import project_service
from backend.tasks.jobs import enqueue_scan

router = APIRouter()


@router.post("/{project_id}/scan", response_model=ScanRun)
def trigger_scan(project_id: int, db: Session = Depends(get_db)):
    project = project_service.get_project(db, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    scan_run = models.ScanRun(project_id=project.id, status="queued")
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
