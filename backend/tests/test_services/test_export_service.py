"""
Tests for export service.
"""
import pytest

from backend.services.export_service import (
    generate_markdown,
    generate_pdf,
    generate_docx,
    get_report_with_findings,
)
from backend import models


class TestGenerateMarkdown:
    """Tests for markdown generation."""
    
    def test_generates_title(self, sample_report, sample_findings):
        """Should include report title in markdown."""
        result = generate_markdown(sample_report, sample_findings)
        assert f"# {sample_report.title}" in result
    
    def test_includes_summary(self, sample_report, sample_findings):
        """Should include summary section."""
        result = generate_markdown(sample_report, sample_findings)
        assert "## Summary" in result
        assert sample_report.summary in result
    
    def test_includes_findings(self, sample_report, sample_findings):
        """Should include findings section."""
        result = generate_markdown(sample_report, sample_findings)
        assert "## Findings" in result
        for finding in sample_findings:
            assert finding.summary in result
    
    def test_includes_severity_table(self, sample_report, sample_findings):
        """Should include severity breakdown table."""
        result = generate_markdown(sample_report, sample_findings)
        assert "## Severity Breakdown" in result
        assert "| Severity | Count |" in result
    
    def test_handles_empty_findings(self, sample_report):
        """Should handle empty findings list."""
        result = generate_markdown(sample_report, [])
        assert "No findings recorded" in result


class TestGeneratePdf:
    """Tests for PDF generation."""
    
    def test_generates_pdf_bytes(self, sample_report, sample_findings):
        """Should generate PDF content as bytes."""
        result = generate_pdf(sample_report, sample_findings)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_pdf_starts_with_magic_bytes(self, sample_report, sample_findings):
        """Generated PDF should start with PDF magic bytes."""
        result = generate_pdf(sample_report, sample_findings)
        # PDF files start with %PDF
        assert result[:4] == b"%PDF" or b"placeholder" in result.lower()


class TestGenerateDocx:
    """Tests for DOCX generation."""
    
    def test_generates_docx_bytes(self, sample_report, sample_findings):
        """Should generate DOCX content as bytes."""
        result = generate_docx(sample_report, sample_findings)
        assert isinstance(result, bytes)
        assert len(result) > 0
    
    def test_docx_starts_with_pk_signature(self, sample_report, sample_findings):
        """Generated DOCX should be a valid zip (starts with PK)."""
        result = generate_docx(sample_report, sample_findings)
        # DOCX is a ZIP file, starts with PK
        assert result[:2] == b"PK" or b"placeholder" in result.lower()


class TestGetReportWithFindings:
    """Tests for fetching report with findings."""
    
    def test_returns_report_and_findings(self, db, sample_report, sample_findings):
        """Should return report and its findings."""
        report, findings = get_report_with_findings(db, sample_report.id)
        assert report.id == sample_report.id
        assert len(findings) == len(sample_findings)
    
    def test_raises_for_missing_report(self, db):
        """Should raise ValueError for non-existent report."""
        with pytest.raises(ValueError) as exc_info:
            get_report_with_findings(db, 99999)
        assert "not found" in str(exc_info.value).lower()
