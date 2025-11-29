from collections import Counter
from typing import Dict, List

from sqlalchemy.orm import Session

from backend import models


def calculate_risk(findings: List[models.Finding]) -> float:
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    total = 0
    for f in findings:
        total += weights.get(f.severity.lower(), 1) if f.severity else 1
    return round(total / max(len(findings), 1), 2)


def build_report_summary(findings: List[models.Finding]) -> Dict:
    severity_counts = Counter([f.severity for f in findings])
    affected_packages = [
        f.details.get("dependency") for f in findings if f.details and f.details.get("dependency")
    ]
    code_issues = [
        {"file": f.file_path, "summary": f.summary, "severity": f.severity}
        for f in findings
        if f.type == "code_pattern"
    ]
    return {
        "severity_counts": dict(severity_counts),
        "affected_packages": affected_packages,
        "code_issues": code_issues,
    }


def create_report(
    db: Session, project: models.Project, scan_run: models.ScanRun, findings: List[models.Finding]
) -> models.Report:
    report = models.Report(
        project_id=project.id,
        scan_run_id=scan_run.id,
        title=f"Security report for {project.name}",
        summary="Automated scan summary",
        overall_risk_score=calculate_risk(findings),
        data=build_report_summary(findings),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
