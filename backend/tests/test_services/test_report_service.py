"""
Tests for report service.
"""
import pytest

from backend.services.report_service import (
    calculate_risk,
    build_report_summary,
    create_report,
)
from backend import models


class TestCalculateRisk:
    """Tests for risk calculation."""
    
    def test_critical_has_highest_weight(self):
        """Critical findings should have highest weight."""
        critical = [models.Finding(type="test", severity="critical", summary="test")]
        high = [models.Finding(type="test", severity="high", summary="test")]
        
        critical_score = calculate_risk(critical)
        high_score = calculate_risk(high)
        
        assert critical_score > high_score
    
    def test_empty_findings_returns_zero(self):
        """Empty findings list should return low risk score."""
        score = calculate_risk([])
        assert score == 0.0
    
    def test_mixed_severities(self):
        """Should calculate average weighted score."""
        findings = [
            models.Finding(type="test", severity="high", summary="test"),
            models.Finding(type="test", severity="low", summary="test"),
        ]
        score = calculate_risk(findings)
        # (7 + 1) / 2 = 4.0
        assert score == 4.0
    
    def test_handles_none_severity(self):
        """Should handle findings with None severity."""
        findings = [
            models.Finding(type="test", severity=None, summary="test"),
        ]
        score = calculate_risk(findings)
        assert score == 1.0  # Default weight


class TestBuildReportSummary:
    """Tests for report summary building."""
    
    def test_counts_severities(self):
        """Should count findings by severity."""
        findings = [
            models.Finding(type="test", severity="high", summary="test"),
            models.Finding(type="test", severity="high", summary="test"),
            models.Finding(type="test", severity="low", summary="test"),
        ]
        
        summary = build_report_summary(findings)
        
        assert summary["severity_counts"]["high"] == 2
        assert summary["severity_counts"]["low"] == 1
    
    def test_extracts_affected_packages(self):
        """Should extract affected packages from details."""
        findings = [
            models.Finding(
                type="dependency_vuln",
                severity="medium",
                summary="test",
                details={"dependency": "requests"},
            ),
        ]
        
        summary = build_report_summary(findings)
        
        assert "requests" in summary["affected_packages"]
    
    def test_extracts_code_issues(self):
        """Should extract code pattern issues."""
        findings = [
            models.Finding(
                type="code_pattern",
                severity="high",
                file_path="main.py",
                summary="Use of eval",
            ),
        ]
        
        summary = build_report_summary(findings)
        
        assert len(summary["code_issues"]) == 1
        assert summary["code_issues"][0]["file"] == "main.py"


class TestCreateReport:
    """Tests for report creation."""
    
    def test_creates_report(self, db, sample_project, sample_scan_run):
        """Should create and persist a report."""
        findings = [
            models.Finding(
                project_id=sample_project.id,
                scan_run_id=sample_scan_run.id,
                type="test",
                severity="medium",
                summary="Test finding",
            ),
        ]
        db.add_all(findings)
        db.commit()
        
        report = create_report(db, sample_project, sample_scan_run, findings)
        
        assert report.id is not None
        assert report.project_id == sample_project.id
        assert report.scan_run_id == sample_scan_run.id
    
    def test_calculates_risk_score(self, db, sample_project, sample_scan_run):
        """Should calculate and store risk score."""
        findings = [
            models.Finding(
                project_id=sample_project.id,
                scan_run_id=sample_scan_run.id,
                type="test",
                severity="high",
                summary="High severity finding",
            ),
        ]
        db.add_all(findings)
        db.commit()
        
        report = create_report(db, sample_project, sample_scan_run, findings)
        
        assert report.overall_risk_score is not None
        assert report.overall_risk_score > 0
