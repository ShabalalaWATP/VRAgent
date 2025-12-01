import math
from collections import Counter
from typing import Dict, List

from sqlalchemy.orm import Session

from backend import models


def calculate_risk(findings: List[models.Finding]) -> float:
    """Calculate risk score on a 0-100 scale based on severity distribution.
    
    Formula accounts for:
    - Severity weights (critical=40, high=25, medium=10, low=2)
    - Diminishing returns for many findings of same severity
    - Caps at 100
    """
    if not findings:
        return 0.0
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity.lower() if f.severity else "info")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Base impact scores with diminishing returns (sqrt to prevent linear scaling)
    critical_score = min(40, 40 * (1 - math.exp(-severity_counts["critical"] * 0.3)))  # Caps around 40
    high_score = min(30, 30 * (1 - math.exp(-severity_counts["high"] * 0.1)))  # Caps around 30  
    medium_score = min(20, 20 * (1 - math.exp(-severity_counts["medium"] * 0.15)))  # Caps around 20
    low_score = min(10, 10 * (1 - math.exp(-severity_counts["low"] * 0.2)))  # Caps around 10
    
    # Any critical = minimum 50 score
    base_score = critical_score + high_score + medium_score + low_score
    
    # If any criticals exist, ensure minimum 50
    if severity_counts["critical"] > 0:
        base_score = max(base_score, 50)
    elif severity_counts["high"] > 0:
        base_score = max(base_score, 25)
    
    return round(min(100, base_score), 1)


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
