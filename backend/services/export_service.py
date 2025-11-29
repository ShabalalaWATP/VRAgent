"""
Report export service - generates PDF, DOCX, and Markdown reports.
"""
from io import BytesIO
from typing import List, Dict, Any

from sqlalchemy.orm import Session

from backend import models
from backend.core.logging import get_logger

logger = get_logger(__name__)


def generate_markdown(report: models.Report, findings: List[models.Finding]) -> str:
    """
    Generate a Markdown report.
    
    Args:
        report: Report model
        findings: List of findings for the report
        
    Returns:
        Markdown string
    """
    lines = [
        f"# {report.title}",
        "",
        f"**Generated:** {report.created_at.strftime('%Y-%m-%d %H:%M:%S') if report.created_at else 'N/A'}",
        f"**Overall Risk Score:** {report.overall_risk_score or 'N/A'}",
        "",
        "## Summary",
        "",
        report.summary or "No summary available.",
        "",
    ]
    
    # Add severity breakdown
    if report.data and report.data.get("severity_counts"):
        lines.extend([
            "## Severity Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        for severity, count in report.data["severity_counts"].items():
            lines.append(f"| {severity} | {count} |")
        lines.append("")
    
    # Add findings
    lines.extend([
        "## Findings",
        "",
    ])
    
    if not findings:
        lines.append("No findings recorded.")
    else:
        for i, finding in enumerate(findings, 1):
            lines.extend([
                f"### {i}. {finding.summary}",
                "",
                f"- **Type:** {finding.type}",
                f"- **Severity:** {finding.severity}",
            ])
            if finding.file_path:
                lines.append(f"- **File:** `{finding.file_path}`")
            if finding.start_line:
                lines.append(f"- **Line:** {finding.start_line}")
            if finding.details:
                lines.append(f"- **Details:** {finding.details}")
            lines.append("")
    
    # Add affected packages
    if report.data and report.data.get("affected_packages"):
        lines.extend([
            "## Affected Dependencies",
            "",
        ])
        for pkg in report.data["affected_packages"]:
            if pkg:
                lines.append(f"- {pkg}")
        lines.append("")
    
    return "\n".join(lines)


def generate_pdf(report: models.Report, findings: List[models.Finding]) -> bytes:
    """
    Generate a PDF report.
    
    Args:
        report: Report model
        findings: List of findings for the report
        
    Returns:
        PDF bytes
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    except ImportError:
        logger.error("reportlab not installed, returning placeholder PDF")
        return b"%PDF-1.4 placeholder - install reportlab for real PDF generation"
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=12
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=8
    )
    
    story = []
    
    # Title
    story.append(Paragraph(report.title, title_style))
    story.append(Spacer(1, 12))
    
    # Summary
    story.append(Paragraph("Summary", heading_style))
    story.append(Paragraph(report.summary or "No summary available.", styles['Normal']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Risk Score:</b> {report.overall_risk_score or 'N/A'}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Severity breakdown table
    if report.data and report.data.get("severity_counts"):
        story.append(Paragraph("Severity Breakdown", heading_style))
        table_data = [["Severity", "Count"]]
        for severity, count in report.data["severity_counts"].items():
            table_data.append([severity, str(count)])
        
        table = Table(table_data, colWidths=[2*inch, 1*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(table)
        story.append(Spacer(1, 12))
    
    # Findings
    story.append(Paragraph("Findings", heading_style))
    if not findings:
        story.append(Paragraph("No findings recorded.", styles['Normal']))
    else:
        for i, finding in enumerate(findings, 1):
            story.append(Paragraph(f"<b>{i}. {finding.summary}</b>", styles['Normal']))
            story.append(Paragraph(f"Type: {finding.type} | Severity: {finding.severity}", styles['Normal']))
            if finding.file_path:
                story.append(Paragraph(f"File: {finding.file_path}", styles['Normal']))
            story.append(Spacer(1, 6))
    
    doc.build(story)
    logger.info(f"Generated PDF report for report {report.id}")
    return buffer.getvalue()


def generate_docx(report: models.Report, findings: List[models.Finding]) -> bytes:
    """
    Generate a DOCX report.
    
    Args:
        report: Report model
        findings: List of findings for the report
        
    Returns:
        DOCX bytes
    """
    try:
        from docx import Document
        from docx.shared import Inches, Pt
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        logger.error("python-docx not installed, returning placeholder DOCX")
        return b"PK placeholder - install python-docx for real DOCX generation"
    
    doc = Document()
    
    # Title
    title = doc.add_heading(report.title, 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    # Summary section
    doc.add_heading("Summary", level=1)
    doc.add_paragraph(report.summary or "No summary available.")
    doc.add_paragraph(f"Overall Risk Score: {report.overall_risk_score or 'N/A'}")
    
    # Severity breakdown
    if report.data and report.data.get("severity_counts"):
        doc.add_heading("Severity Breakdown", level=1)
        table = doc.add_table(rows=1, cols=2)
        table.style = 'Table Grid'
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = "Severity"
        hdr_cells[1].text = "Count"
        
        for severity, count in report.data["severity_counts"].items():
            row_cells = table.add_row().cells
            row_cells[0].text = severity
            row_cells[1].text = str(count)
    
    # Findings section
    doc.add_heading("Findings", level=1)
    if not findings:
        doc.add_paragraph("No findings recorded.")
    else:
        for i, finding in enumerate(findings, 1):
            doc.add_heading(f"{i}. {finding.summary}", level=2)
            doc.add_paragraph(f"Type: {finding.type}")
            doc.add_paragraph(f"Severity: {finding.severity}")
            if finding.file_path:
                doc.add_paragraph(f"File: {finding.file_path}")
            if finding.start_line:
                doc.add_paragraph(f"Line: {finding.start_line}")
            if finding.details:
                doc.add_paragraph(f"Details: {finding.details}")
    
    # Affected packages
    if report.data and report.data.get("affected_packages"):
        doc.add_heading("Affected Dependencies", level=1)
        for pkg in report.data["affected_packages"]:
            if pkg:
                doc.add_paragraph(pkg, style='List Bullet')
    
    buffer = BytesIO()
    doc.save(buffer)
    logger.info(f"Generated DOCX report for report {report.id}")
    return buffer.getvalue()


def get_report_with_findings(db: Session, report_id: int) -> tuple[models.Report, List[models.Finding]]:
    """
    Fetch a report and its associated findings.
    
    Args:
        db: Database session
        report_id: Report ID to fetch
        
    Returns:
        Tuple of (report, findings)
        
    Raises:
        ValueError: If report not found
    """
    report = db.get(models.Report, report_id)
    if not report:
        raise ValueError(f"Report {report_id} not found")
    
    findings = (
        db.query(models.Finding)
        .filter(models.Finding.scan_run_id == report.scan_run_id)
        .order_by(
            # Order by severity (critical first)
            models.Finding.severity.desc(),
            models.Finding.id
        )
        .all()
    )
    
    return report, findings
