import math
from collections import Counter
from typing import Dict, List

from sqlalchemy.orm import Session

from backend import models


def calculate_risk(findings: List[models.Finding], exclude_filtered: bool = True) -> float:
    """Calculate risk score on a 0-100 scale based on severity distribution.
    
    Formula accounts for:
    - Severity weights (critical=40, high=25, medium=10, low=2)
    - Diminishing returns for many findings of same severity
    - Caps at 100
    - EXCLUDES findings filtered out by AI analysis (likely false positives)
    
    Args:
        findings: List of Finding models
        exclude_filtered: If True, excludes findings marked as filtered_out by AI
    """
    if not findings:
        return 0.0
    
    # Filter out findings marked as false positives by AI analysis
    active_findings = findings
    if exclude_filtered:
        active_findings = [
            f for f in findings 
            if not (f.details and f.details.get("ai_analysis", {}).get("filtered_out", False))
        ]
    
    # If all findings were filtered, return minimal score
    if not active_findings:
        return 5.0  # Minimal score to indicate scan ran
    
    # Count by severity using ACTIVE findings only
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in active_findings:
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


def build_report_summary(findings: List[models.Finding], attack_chains: List[Dict] = None, ai_summary: Dict = None, scan_stats: Dict = None) -> Dict:
    # Separate active and filtered findings for transparency
    active_findings = [
        f for f in findings 
        if not (f.details and f.details.get("ai_analysis", {}).get("filtered_out", False))
    ]
    filtered_findings_list = [
        f for f in findings 
        if f.details and f.details.get("ai_analysis", {}).get("filtered_out", False)
    ]
    
    # Report counts for ACTIVE findings (excludes filtered)
    severity_counts = Counter([f.severity for f in active_findings])
    # Also track total counts including filtered for transparency
    total_severity_counts = Counter([f.severity for f in findings])
    
    affected_packages = [
        f.details.get("dependency") for f in active_findings if f.details and f.details.get("dependency")
    ]
    code_issues = [
        {"file": f.file_path, "summary": f.summary, "severity": f.severity}
        for f in active_findings
        if f.type == "code_pattern"
    ]
    
    # Count AI analysis stats from findings
    false_positive_count = 0
    severity_adjusted_count = 0
    false_positives = []
    filtered_findings = []  # Findings filtered out by AI analysis
    
    # Count transitive and reachability stats from findings
    transitive_vuln_count = 0
    unreachable_vuln_count = 0
    severity_downgraded_count = 0
    agentic_findings_count = 0
    
    for f in findings:
        ai_analysis = f.details.get("ai_analysis") if f.details else None
        
        # Count agentic findings
        if f.type.startswith("agentic-") or (f.details and f.details.get("source") == "agentic_ai"):
            agentic_findings_count += 1
        
        if ai_analysis:
            if ai_analysis.get("is_false_positive"):
                false_positive_count += 1
                false_positives.append({
                    "finding_id": f.id,
                    "summary": f.summary,
                    "reason": ai_analysis.get("false_positive_reason"),
                    "file_path": f.file_path,
                    "filtered_out": ai_analysis.get("filtered_out", False),
                })
            
            # Track filtered findings separately
            if ai_analysis.get("filtered_out"):
                filtered_findings.append({
                    "finding_id": f.id,
                    "summary": f.summary,
                    "type": f.type,
                    "severity": f.severity,
                    "fp_score": ai_analysis.get("false_positive_score", 0),
                    "reason": ai_analysis.get("false_positive_reason"),
                    "file_path": f.file_path,
                })
            
            if ai_analysis.get("severity_adjusted"):
                severity_adjusted_count += 1
        
        # Check for transitive dependency info
        if f.details and f.details.get("is_transitive"):
            transitive_vuln_count += 1
        
        # Check for reachability info
        if f.details and f.details.get("reachability"):
            if not f.details["reachability"].get("is_reachable"):
                unreachable_vuln_count += 1
        
        # Check for severity downgrade
        if f.details and f.details.get("severity_downgraded"):
            severity_downgraded_count += 1
    
    return {
        "severity_counts": dict(severity_counts),  # Active findings only
        "total_severity_counts": dict(total_severity_counts),  # All findings for transparency
        "active_findings_count": len(active_findings),
        "total_findings_count": len(findings),
        "filtered_out_count": len(filtered_findings_list),
        "affected_packages": affected_packages,
        "code_issues": code_issues,
        "attack_chains": attack_chains or [],
        "ai_analysis_summary": {
            "false_positive_count": false_positive_count,
            "severity_adjusted_count": severity_adjusted_count,
            "false_positives": false_positives[:20],  # Limit to 20 for report
            "filtered_findings": filtered_findings[:20],  # Limit to 20 for report
            "filtered_count": len(filtered_findings),
            "agentic_findings_count": agentic_findings_count,
            **(ai_summary or {}),
        },
        "scan_stats": {
            **(scan_stats or {}),
            "transitive_vulnerabilities": transitive_vuln_count,
            "unreachable_vulnerabilities": unreachable_vuln_count,
            "severity_downgrades": severity_downgraded_count,
        },
    }


def create_report(
    db: Session, 
    project: models.Project, 
    scan_run: models.ScanRun, 
    findings: List[models.Finding],
    attack_chains: List[Dict] = None,
    ai_summary: Dict = None,
    scan_stats: Dict = None,
) -> models.Report:
    report = models.Report(
        project_id=project.id,
        scan_run_id=scan_run.id,
        title=f"Security report for {project.name}",
        summary="Automated scan summary",
        overall_risk_score=calculate_risk(findings),
        data=build_report_summary(findings, attack_chains, ai_summary, scan_stats),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
