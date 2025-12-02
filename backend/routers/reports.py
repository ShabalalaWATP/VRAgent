from typing import List, Dict, Any

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


@router.get("/{report_id}/attack-chains")
def get_attack_chains(report_id: int, db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Get attack chains identified by AI analysis for a report."""
    report = db.get(models.Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Attack chains are stored in report.data
    attack_chains = report.data.get("attack_chains", []) if report.data else []
    return attack_chains


@router.get("/{report_id}/ai-insights")
def get_ai_insights(report_id: int, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Get AI analysis insights including false positives and severity adjustments."""
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
