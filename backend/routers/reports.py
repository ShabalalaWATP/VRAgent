from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend import models
from backend.core.database import get_db
from backend.schemas import Finding, Report

router = APIRouter()


@router.get("", response_model=list[Report])
def list_reports(project_id: int, db: Session = Depends(get_db)):
    """List all reports for a project. Called via /projects/{project_id}/reports"""
    reports = db.query(models.Report).filter(models.Report.project_id == project_id).all()
    return reports


@router.get("/{report_id}", response_model=Report)
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.delete("/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    db.delete(report)
    db.commit()
    return {"status": "deleted"}


@router.get("/{report_id}/findings", response_model=list[Finding])
def list_findings(report_id: int, db: Session = Depends(get_db)):
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    findings = db.query(models.Finding).filter(models.Finding.scan_run_id == report.scan_run_id).all()
    return findings
