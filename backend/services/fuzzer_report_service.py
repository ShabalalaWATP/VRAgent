"""
Fuzzer Advanced Reporting Service

Provides comprehensive report generation for agentic fuzzer results:
- Part 1: Report Data Models & Templates
- Part 2: Executive Summary Generator
- Part 3: Technical Report Generator
- Part 4: Export Formats (PDF/HTML/JSON/Markdown)
- Part 5: Integration with other services

Generates professional security assessment reports from fuzzing findings.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime
import json
import html
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# PART 1: REPORT DATA MODELS & TEMPLATES
# =============================================================================

class ReportFormat(Enum):
    """Available report output formats."""
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    PDF = "pdf"  # Requires additional dependencies


class ReportType(Enum):
    """Types of reports that can be generated."""
    EXECUTIVE = "executive"  # High-level summary for management
    TECHNICAL = "technical"  # Detailed technical findings
    COMPLIANCE = "compliance"  # Compliance-focused report
    FULL = "full"  # Complete report with all sections


class SeverityLevel(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReportFinding:
    """A finding formatted for reporting."""
    id: str
    title: str
    severity: SeverityLevel
    technique: str
    description: str
    url: str
    parameter: Optional[str]
    evidence: str
    impact: str
    remediation: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    compliance_mappings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "technique": self.technique,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "compliance_mappings": self.compliance_mappings,
        }


@dataclass
class ReportMetadata:
    """Metadata for the report."""
    report_id: str
    report_type: ReportType
    generated_at: datetime
    scan_start: datetime
    scan_end: datetime
    scan_duration_seconds: int
    target_count: int
    targets: List[str]
    techniques_used: List[str]
    total_requests: int
    organization: Optional[str] = None
    assessor: Optional[str] = None
    version: str = "1.0"
    
    def to_dict(self) -> Dict:
        return {
            "report_id": self.report_id,
            "report_type": self.report_type.value,
            "generated_at": self.generated_at.isoformat(),
            "scan_start": self.scan_start.isoformat(),
            "scan_end": self.scan_end.isoformat(),
            "scan_duration_seconds": self.scan_duration_seconds,
            "target_count": self.target_count,
            "targets": self.targets,
            "techniques_used": self.techniques_used,
            "total_requests": self.total_requests,
            "organization": self.organization,
            "assessor": self.assessor,
            "version": self.version,
        }


@dataclass
class ExecutiveSummary:
    """Executive summary section of the report."""
    risk_rating: str  # Critical, High, Medium, Low
    risk_score: float  # 0-10
    key_findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    top_risks: List[str]
    immediate_actions: List[str]
    assessment_overview: str
    business_impact: str
    
    def to_dict(self) -> Dict:
        return {
            "risk_rating": self.risk_rating,
            "risk_score": self.risk_score,
            "key_findings_count": self.key_findings_count,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "top_risks": self.top_risks,
            "immediate_actions": self.immediate_actions,
            "assessment_overview": self.assessment_overview,
            "business_impact": self.business_impact,
        }


@dataclass
class TechnicalDetails:
    """Technical details section of the report."""
    methodology: str
    tools_used: List[str]
    scope: Dict[str, Any]
    limitations: List[str]
    findings_by_category: Dict[str, List[ReportFinding]]
    attack_chains: List[Dict]
    root_causes: List[Dict]
    
    def to_dict(self) -> Dict:
        return {
            "methodology": self.methodology,
            "tools_used": self.tools_used,
            "scope": self.scope,
            "limitations": self.limitations,
            "findings_by_category": {
                cat: [f.to_dict() for f in findings]
                for cat, findings in self.findings_by_category.items()
            },
            "attack_chains": self.attack_chains,
            "root_causes": self.root_causes,
        }


@dataclass
class ComplianceSection:
    """Compliance section of the report."""
    frameworks_assessed: List[str]
    compliance_status: Dict[str, Dict]  # Framework -> {passed, failed, na}
    failed_controls: List[Dict]
    recommendations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "frameworks_assessed": self.frameworks_assessed,
            "compliance_status": self.compliance_status,
            "failed_controls": self.failed_controls,
            "recommendations": self.recommendations,
        }


@dataclass
class RemediationPlan:
    """Remediation plan section of the report."""
    priority_order: List[Dict]
    quick_wins: List[Dict]
    estimated_total_effort: str
    timeline_recommendations: Dict[str, List[str]]
    
    def to_dict(self) -> Dict:
        return {
            "priority_order": self.priority_order,
            "quick_wins": self.quick_wins,
            "estimated_total_effort": self.estimated_total_effort,
            "timeline_recommendations": self.timeline_recommendations,
        }


@dataclass
class SecurityReport:
    """Complete security assessment report."""
    metadata: ReportMetadata
    executive_summary: ExecutiveSummary
    technical_details: Optional[TechnicalDetails]
    compliance: Optional[ComplianceSection]
    remediation_plan: Optional[RemediationPlan]
    findings: List[ReportFinding]
    appendices: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "metadata": self.metadata.to_dict(),
            "executive_summary": self.executive_summary.to_dict(),
            "technical_details": self.technical_details.to_dict() if self.technical_details else None,
            "compliance": self.compliance.to_dict() if self.compliance else None,
            "remediation_plan": self.remediation_plan.to_dict() if self.remediation_plan else None,
            "findings": [f.to_dict() for f in self.findings],
            "appendices": self.appendices,
        }


# =============================================================================
# PART 2: EXECUTIVE SUMMARY GENERATOR
# =============================================================================

class ExecutiveSummaryGenerator:
    """Generates executive summaries from findings."""
    
    # Risk rating thresholds
    RISK_THRESHOLDS = {
        "Critical": 9.0,
        "High": 7.0,
        "Medium": 4.0,
        "Low": 0.0,
    }
    
    # Severity weights for risk score calculation
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 10.0,
        SeverityLevel.HIGH: 7.5,
        SeverityLevel.MEDIUM: 5.0,
        SeverityLevel.LOW: 2.5,
        SeverityLevel.INFO: 0.5,
    }
    
    def generate(self, findings: List[ReportFinding]) -> ExecutiveSummary:
        """Generate executive summary from findings."""
        # Count by severity
        severity_counts = self._count_by_severity(findings)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings, severity_counts)
        
        # Determine risk rating
        risk_rating = self._determine_risk_rating(risk_score)
        
        # Extract top risks
        top_risks = self._extract_top_risks(findings)
        
        # Generate immediate actions
        immediate_actions = self._generate_immediate_actions(findings, severity_counts)
        
        # Generate overview
        overview = self._generate_overview(findings, severity_counts, risk_rating)
        
        # Generate business impact
        business_impact = self._generate_business_impact(findings, severity_counts)
        
        return ExecutiveSummary(
            risk_rating=risk_rating,
            risk_score=round(risk_score, 1),
            key_findings_count=len(findings),
            critical_count=severity_counts.get(SeverityLevel.CRITICAL, 0),
            high_count=severity_counts.get(SeverityLevel.HIGH, 0),
            medium_count=severity_counts.get(SeverityLevel.MEDIUM, 0),
            low_count=severity_counts.get(SeverityLevel.LOW, 0),
            info_count=severity_counts.get(SeverityLevel.INFO, 0),
            top_risks=top_risks,
            immediate_actions=immediate_actions,
            assessment_overview=overview,
            business_impact=business_impact,
        )
    
    def _count_by_severity(self, findings: List[ReportFinding]) -> Dict[SeverityLevel, int]:
        """Count findings by severity."""
        counts = {level: 0 for level in SeverityLevel}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts
    
    def _calculate_risk_score(
        self, 
        findings: List[ReportFinding], 
        severity_counts: Dict[SeverityLevel, int]
    ) -> float:
        """Calculate overall risk score (0-10)."""
        if not findings:
            return 0.0
        
        # Base score from severity distribution
        total_weight = sum(
            self.SEVERITY_WEIGHTS[level] * count
            for level, count in severity_counts.items()
        )
        
        # Normalize to 0-10 scale
        # More findings = higher score, but with diminishing returns
        import math
        normalized = min(10.0, total_weight / (1 + math.log10(len(findings) + 1)))
        
        # Boost for critical findings
        if severity_counts.get(SeverityLevel.CRITICAL, 0) > 0:
            normalized = min(10.0, normalized + 2.0)
        
        return normalized
    
    def _determine_risk_rating(self, risk_score: float) -> str:
        """Determine risk rating from score."""
        for rating, threshold in self.RISK_THRESHOLDS.items():
            if risk_score >= threshold:
                return rating
        return "Low"
    
    def _extract_top_risks(self, findings: List[ReportFinding], limit: int = 5) -> List[str]:
        """Extract top risk descriptions."""
        # Sort by severity (critical first)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))
        
        top_risks = []
        for finding in sorted_findings[:limit]:
            risk = f"{finding.severity.value.upper()}: {finding.title}"
            if finding.cvss_score:
                risk += f" (CVSS {finding.cvss_score})"
            top_risks.append(risk)
        
        return top_risks
    
    def _generate_immediate_actions(
        self, 
        findings: List[ReportFinding],
        severity_counts: Dict[SeverityLevel, int]
    ) -> List[str]:
        """Generate immediate action recommendations."""
        actions = []
        
        if severity_counts.get(SeverityLevel.CRITICAL, 0) > 0:
            actions.append("URGENT: Address all critical findings within 24-48 hours")
            
            # Specific actions for critical finding types
            critical_techniques = set(
                f.technique for f in findings if f.severity == SeverityLevel.CRITICAL
            )
            if "sql_injection" in critical_techniques or "command_injection" in critical_techniques:
                actions.append("Implement emergency input validation on affected endpoints")
            if "auth_bypass" in critical_techniques:
                actions.append("Review and reinforce authentication mechanisms immediately")
        
        if severity_counts.get(SeverityLevel.HIGH, 0) > 0:
            actions.append("Schedule remediation for high-severity findings within 1 week")
        
        if severity_counts.get(SeverityLevel.MEDIUM, 0) > 2:
            actions.append("Plan systematic remediation of medium-severity findings")
        
        if not actions:
            actions.append("Continue regular security monitoring and testing")
        
        return actions
    
    def _generate_overview(
        self,
        findings: List[ReportFinding],
        severity_counts: Dict[SeverityLevel, int],
        risk_rating: str
    ) -> str:
        """Generate assessment overview text."""
        total = len(findings)
        critical = severity_counts.get(SeverityLevel.CRITICAL, 0)
        high = severity_counts.get(SeverityLevel.HIGH, 0)
        
        overview = f"The security assessment identified {total} security finding(s). "
        
        if risk_rating == "Critical":
            overview += f"The overall risk rating is CRITICAL with {critical} critical-severity vulnerability(ies) requiring immediate attention. "
        elif risk_rating == "High":
            overview += f"The overall risk rating is HIGH with {critical + high} significant vulnerability(ies) that should be prioritized for remediation. "
        elif risk_rating == "Medium":
            overview += "The overall risk rating is MEDIUM. While no critical vulnerabilities were found, several issues require attention. "
        else:
            overview += "The overall risk rating is LOW. The application demonstrates reasonable security posture. "
        
        # Add technique summary
        techniques = set(f.technique for f in findings)
        if techniques:
            overview += f"Vulnerabilities span {len(techniques)} different attack categories."
        
        return overview
    
    def _generate_business_impact(
        self,
        findings: List[ReportFinding],
        severity_counts: Dict[SeverityLevel, int]
    ) -> str:
        """Generate business impact statement."""
        critical = severity_counts.get(SeverityLevel.CRITICAL, 0)
        high = severity_counts.get(SeverityLevel.HIGH, 0)
        
        impacts = []
        
        # Check for data breach risks
        data_breach_techniques = ["sql_injection", "idor", "path_traversal", "xxe"]
        has_data_breach_risk = any(
            f.technique in data_breach_techniques 
            for f in findings 
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        )
        if has_data_breach_risk:
            impacts.append("potential data breach and regulatory compliance violations")
        
        # Check for system compromise
        rce_techniques = ["command_injection", "ssti", "deserialization"]
        has_rce_risk = any(f.technique in rce_techniques for f in findings)
        if has_rce_risk:
            impacts.append("complete system compromise through remote code execution")
        
        # Check for auth issues
        auth_techniques = ["auth_bypass", "idor"]
        has_auth_risk = any(
            f.technique in auth_techniques 
            for f in findings 
            if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        )
        if has_auth_risk:
            impacts.append("unauthorized access to sensitive resources and user accounts")
        
        if not impacts:
            return "The identified vulnerabilities present limited direct business impact but should still be addressed to maintain security posture."
        
        impact_text = "The identified vulnerabilities could lead to: " + "; ".join(impacts) + ". "
        
        if critical > 0:
            impact_text += "Immediate action is required to prevent potential security incidents."
        elif high > 0:
            impact_text += "Prompt remediation is recommended to reduce organizational risk."
        
        return impact_text


# =============================================================================
# PART 3: TECHNICAL REPORT GENERATOR
# =============================================================================

class TechnicalReportGenerator:
    """Generates detailed technical report sections."""
    
    METHODOLOGY_TEMPLATE = """
The security assessment was conducted using automated agentic fuzzing with LLM-driven 
payload generation and analysis. The methodology follows industry best practices including:

1. **Reconnaissance**: Automated analysis of target endpoints to identify attack surface
2. **Vulnerability Discovery**: Systematic testing using {technique_count} fuzzing techniques
3. **Exploitation Validation**: Verification of discovered vulnerabilities with proof-of-concept
4. **Impact Assessment**: Evaluation of potential business and technical impact
5. **Remediation Guidance**: Specific recommendations for each identified vulnerability

Testing was conducted over {duration} with {request_count} HTTP requests made to {target_count} target(s).
"""
    
    def generate(
        self,
        findings: List[ReportFinding],
        metadata: ReportMetadata,
        attack_chains: Optional[List[Dict]] = None,
        root_causes: Optional[List[Dict]] = None,
    ) -> TechnicalDetails:
        """Generate technical details section."""
        # Generate methodology
        methodology = self._generate_methodology(metadata)
        
        # Categorize findings
        findings_by_category = self._categorize_findings(findings)
        
        # Define scope
        scope = self._generate_scope(metadata)
        
        # List limitations
        limitations = self._generate_limitations()
        
        return TechnicalDetails(
            methodology=methodology,
            tools_used=[
                "VRAgent Agentic Fuzzer",
                "LLM-powered payload generation (Gemini/OpenAI)",
                "Custom vulnerability detection engine",
            ],
            scope=scope,
            limitations=limitations,
            findings_by_category=findings_by_category,
            attack_chains=attack_chains or [],
            root_causes=root_causes or [],
        )
    
    def _generate_methodology(self, metadata: ReportMetadata) -> str:
        """Generate methodology description."""
        duration = f"{metadata.scan_duration_seconds // 60} minutes"
        if metadata.scan_duration_seconds >= 3600:
            duration = f"{metadata.scan_duration_seconds / 3600:.1f} hours"
        
        return self.METHODOLOGY_TEMPLATE.format(
            technique_count=len(metadata.techniques_used),
            duration=duration,
            request_count=metadata.total_requests,
            target_count=metadata.target_count,
        )
    
    def _categorize_findings(self, findings: List[ReportFinding]) -> Dict[str, List[ReportFinding]]:
        """Categorize findings by technique type."""
        categories = {
            "Injection Vulnerabilities": [],
            "Authentication & Authorization": [],
            "Data Exposure": [],
            "Server-Side Issues": [],
            "Other": [],
        }
        
        category_map = {
            "sql_injection": "Injection Vulnerabilities",
            "xss": "Injection Vulnerabilities",
            "command_injection": "Injection Vulnerabilities",
            "ssti": "Injection Vulnerabilities",
            "xxe": "Injection Vulnerabilities",
            "header_injection": "Injection Vulnerabilities",
            "auth_bypass": "Authentication & Authorization",
            "idor": "Authentication & Authorization",
            "path_traversal": "Data Exposure",
            "ssrf": "Server-Side Issues",
            "deserialization": "Server-Side Issues",
            "business_logic": "Other",
            "race_condition": "Other",
        }
        
        for finding in findings:
            category = category_map.get(finding.technique, "Other")
            categories[category].append(finding)
        
        # Remove empty categories
        return {cat: findings for cat, findings in categories.items() if findings}
    
    def _generate_scope(self, metadata: ReportMetadata) -> Dict[str, Any]:
        """Generate scope definition."""
        return {
            "targets": metadata.targets,
            "techniques": metadata.techniques_used,
            "time_period": {
                "start": metadata.scan_start.isoformat(),
                "end": metadata.scan_end.isoformat(),
            },
            "type": "Automated security assessment (black-box)",
        }
    
    def _generate_limitations(self) -> List[str]:
        """Generate list of assessment limitations."""
        return [
            "Testing was limited to the provided target URLs and may not cover all application functionality",
            "Time-constrained testing may not discover all vulnerabilities",
            "Automated testing may produce false positives requiring manual verification",
            "Authentication-protected areas were only tested if credentials were provided",
            "Rate limiting and WAF rules may have prevented some test payloads from reaching the application",
        ]


# =============================================================================
# PART 4: EXPORT FORMATS
# =============================================================================

class ReportExporter:
    """Exports reports to various formats."""
    
    def export(self, report: SecurityReport, format: ReportFormat) -> str:
        """Export report to specified format."""
        if format == ReportFormat.JSON:
            return self._export_json(report)
        elif format == ReportFormat.HTML:
            return self._export_html(report)
        elif format == ReportFormat.MARKDOWN:
            return self._export_markdown(report)
        elif format == ReportFormat.PDF:
            return self._export_pdf(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json(self, report: SecurityReport) -> str:
        """Export to JSON."""
        return json.dumps(report.to_dict(), indent=2, default=str)
    
    def _export_markdown(self, report: SecurityReport) -> str:
        """Export to Markdown."""
        md = []
        
        # Title
        md.append(f"# Security Assessment Report")
        md.append(f"**Report ID:** {report.metadata.report_id}")
        md.append(f"**Generated:** {report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
        md.append("")
        
        # Executive Summary
        md.append("## Executive Summary")
        md.append("")
        md.append(f"**Overall Risk Rating:** {report.executive_summary.risk_rating}")
        md.append(f"**Risk Score:** {report.executive_summary.risk_score}/10")
        md.append("")
        md.append("### Severity Breakdown")
        md.append("")
        md.append(f"| Severity | Count |")
        md.append(f"|----------|-------|")
        md.append(f"| Critical | {report.executive_summary.critical_count} |")
        md.append(f"| High | {report.executive_summary.high_count} |")
        md.append(f"| Medium | {report.executive_summary.medium_count} |")
        md.append(f"| Low | {report.executive_summary.low_count} |")
        md.append(f"| Info | {report.executive_summary.info_count} |")
        md.append("")
        md.append("### Assessment Overview")
        md.append("")
        md.append(report.executive_summary.assessment_overview)
        md.append("")
        md.append("### Business Impact")
        md.append("")
        md.append(report.executive_summary.business_impact)
        md.append("")
        
        if report.executive_summary.immediate_actions:
            md.append("### Immediate Actions Required")
            md.append("")
            for action in report.executive_summary.immediate_actions:
                md.append(f"- {action}")
            md.append("")
        
        # Findings
        md.append("## Security Findings")
        md.append("")
        
        for i, finding in enumerate(report.findings, 1):
            md.append(f"### {i}. {finding.title}")
            md.append("")
            md.append(f"**Severity:** {finding.severity.value.upper()}")
            if finding.cvss_score:
                md.append(f"**CVSS Score:** {finding.cvss_score}")
            if finding.cwe_id:
                md.append(f"**CWE:** {finding.cwe_id} - {finding.cwe_name}")
            md.append(f"**URL:** `{finding.url}`")
            if finding.parameter:
                md.append(f"**Parameter:** `{finding.parameter}`")
            md.append("")
            md.append("**Description:**")
            md.append(finding.description)
            md.append("")
            md.append("**Evidence:**")
            md.append(f"```")
            md.append(finding.evidence)
            md.append(f"```")
            md.append("")
            md.append("**Impact:**")
            md.append(finding.impact)
            md.append("")
            md.append("**Remediation:**")
            md.append(finding.remediation)
            md.append("")
            md.append("---")
            md.append("")
        
        # Remediation Plan
        if report.remediation_plan:
            md.append("## Remediation Plan")
            md.append("")
            md.append(f"**Estimated Total Effort:** {report.remediation_plan.estimated_total_effort}")
            md.append("")
            
            if report.remediation_plan.quick_wins:
                md.append("### Quick Wins")
                md.append("")
                for qw in report.remediation_plan.quick_wins:
                    md.append(f"- **{qw.get('title', 'N/A')}** ({qw.get('estimated_effort', 'N/A')})")
                md.append("")
            
            md.append("### Priority Order")
            md.append("")
            for i, item in enumerate(report.remediation_plan.priority_order, 1):
                md.append(f"{i}. **{item.get('title', 'N/A')}** - {item.get('estimated_effort', 'N/A')}")
            md.append("")
        
        # Appendix - Metadata
        md.append("## Appendix A: Assessment Metadata")
        md.append("")
        md.append(f"- **Scan Start:** {report.metadata.scan_start}")
        md.append(f"- **Scan End:** {report.metadata.scan_end}")
        md.append(f"- **Duration:** {report.metadata.scan_duration_seconds} seconds")
        md.append(f"- **Total Requests:** {report.metadata.total_requests}")
        md.append(f"- **Targets Tested:** {report.metadata.target_count}")
        md.append("")
        md.append("**Techniques Used:**")
        for tech in report.metadata.techniques_used:
            md.append(f"- {tech}")
        
        return "\n".join(md)
    
    def _export_html(self, report: SecurityReport) -> str:
        """Export to HTML."""
        # Severity colors
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }
        
        html_parts = []
        
        # HTML Header
        html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 { color: #2c3e50; }
        .header {
            border-bottom: 3px solid #3498db;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .risk-badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 1.2em;
        }
        .risk-critical { background: var(--critical); }
        .risk-high { background: var(--high); }
        .risk-medium { background: var(--medium); color: #333; }
        .risk-low { background: var(--low); }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 15px;
            margin: 20px 0;
        }
        .summary-card {
            text-align: center;
            padding: 15px;
            border-radius: 8px;
            color: white;
        }
        .summary-card.critical { background: var(--critical); }
        .summary-card.high { background: var(--high); }
        .summary-card.medium { background: var(--medium); color: #333; }
        .summary-card.low { background: var(--low); }
        .summary-card.info { background: var(--info); }
        .summary-card .count { font-size: 2em; font-weight: bold; }
        .finding {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px;
            color: white;
        }
        .finding-header.critical { background: var(--critical); }
        .finding-header.high { background: var(--high); }
        .finding-header.medium { background: var(--medium); color: #333; }
        .finding-header.low { background: var(--low); }
        .finding-header.info { background: var(--info); }
        .finding-body { padding: 20px; }
        .finding-meta { 
            background: #f8f9fa;
            padding: 10px 15px;
            font-size: 0.9em;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Consolas', monospace;
        }
        pre {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .action-list {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        th { background: #3498db; color: white; }
        tr:nth-child(even) { background: #f2f2f2; }
    </style>
</head>
<body>
""")
        
        # Header
        html_parts.append(f"""
<div class="header">
    <h1>🔒 Security Assessment Report</h1>
    <p><strong>Report ID:</strong> {html.escape(report.metadata.report_id)}</p>
    <p><strong>Generated:</strong> {report.metadata.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
""")
        
        # Executive Summary
        risk_class = report.executive_summary.risk_rating.lower()
        html_parts.append(f"""
<h2>Executive Summary</h2>
<p><span class="risk-badge risk-{risk_class}">Risk Rating: {report.executive_summary.risk_rating}</span>
   <span style="margin-left: 15px;">Risk Score: <strong>{report.executive_summary.risk_score}/10</strong></span>
</p>

<div class="summary-grid">
    <div class="summary-card critical">
        <div class="count">{report.executive_summary.critical_count}</div>
        <div>Critical</div>
    </div>
    <div class="summary-card high">
        <div class="count">{report.executive_summary.high_count}</div>
        <div>High</div>
    </div>
    <div class="summary-card medium">
        <div class="count">{report.executive_summary.medium_count}</div>
        <div>Medium</div>
    </div>
    <div class="summary-card low">
        <div class="count">{report.executive_summary.low_count}</div>
        <div>Low</div>
    </div>
    <div class="summary-card info">
        <div class="count">{report.executive_summary.info_count}</div>
        <div>Info</div>
    </div>
</div>

<h3>Assessment Overview</h3>
<p>{html.escape(report.executive_summary.assessment_overview)}</p>

<h3>Business Impact</h3>
<p>{html.escape(report.executive_summary.business_impact)}</p>
""")
        
        # Immediate Actions
        if report.executive_summary.immediate_actions:
            html_parts.append('<div class="action-list"><h3>⚠️ Immediate Actions Required</h3><ul>')
            for action in report.executive_summary.immediate_actions:
                html_parts.append(f"<li>{html.escape(action)}</li>")
            html_parts.append('</ul></div>')
        
        # Findings
        html_parts.append("<h2>Security Findings</h2>")
        
        for i, finding in enumerate(report.findings, 1):
            sev_class = finding.severity.value
            html_parts.append(f"""
<div class="finding">
    <div class="finding-header {sev_class}">
        <h3 style="margin: 0;">{i}. {html.escape(finding.title)}</h3>
    </div>
    <div class="finding-meta">
        <strong>Severity:</strong> {finding.severity.value.upper()}
        {f' | <strong>CVSS:</strong> {finding.cvss_score}' if finding.cvss_score else ''}
        {f' | <strong>CWE:</strong> {finding.cwe_id}' if finding.cwe_id else ''}
        | <strong>URL:</strong> <code>{html.escape(finding.url)}</code>
        {f' | <strong>Parameter:</strong> <code>{html.escape(finding.parameter)}</code>' if finding.parameter else ''}
    </div>
    <div class="finding-body">
        <h4>Description</h4>
        <p>{html.escape(finding.description)}</p>
        
        <h4>Evidence</h4>
        <pre>{html.escape(finding.evidence)}</pre>
        
        <h4>Impact</h4>
        <p>{html.escape(finding.impact)}</p>
        
        <h4>Remediation</h4>
        <p>{html.escape(finding.remediation)}</p>
    </div>
</div>
""")
        
        # Close HTML
        html_parts.append("""
</body>
</html>
""")
        
        return "".join(html_parts)
    
    def _export_pdf(self, report: SecurityReport) -> str:
        """Export to PDF (returns HTML that can be printed to PDF)."""
        # For now, return HTML with print-friendly styles
        # Full PDF generation would require weasyprint or reportlab
        html_content = self._export_html(report)
        
        # Add print-friendly styles
        print_styles = """
        <style media="print">
            body { font-size: 12pt; }
            .finding { page-break-inside: avoid; }
            pre { white-space: pre-wrap; }
        </style>
        """
        
        return html_content.replace("</head>", f"{print_styles}</head>")


# =============================================================================
# PART 5: INTEGRATION - REPORT GENERATOR
# =============================================================================

class FuzzerReportGenerator:
    """Main class for generating fuzzer reports."""
    
    def __init__(self):
        self.executive_generator = ExecutiveSummaryGenerator()
        self.technical_generator = TechnicalReportGenerator()
        self.exporter = ReportExporter()
        self._report_counter = 0
    
    def _generate_report_id(self) -> str:
        """Generate unique report ID."""
        self._report_counter += 1
        return f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{self._report_counter:04d}"
    
    def generate_report(
        self,
        session_data: Dict,
        report_type: ReportType = ReportType.FULL,
        include_chains: bool = True,
        include_root_causes: bool = True,
        organization: Optional[str] = None,
        assessor: Optional[str] = None,
    ) -> SecurityReport:
        """
        Generate a complete security report from session data.
        
        Args:
            session_data: Fuzzing session data with findings
            report_type: Type of report to generate
            include_chains: Include exploit chain analysis
            include_root_causes: Include root cause analysis
            organization: Organization name for report
            assessor: Assessor name for report
            
        Returns:
            SecurityReport object
        """
        # Convert raw findings to ReportFinding objects
        findings = self._convert_findings(session_data.get("findings", []))
        
        # Generate metadata
        metadata = self._create_metadata(session_data, report_type, organization, assessor)
        
        # Generate executive summary
        executive_summary = self.executive_generator.generate(findings)
        
        # Generate technical details if not executive-only report
        technical_details = None
        if report_type in (ReportType.TECHNICAL, ReportType.FULL):
            attack_chains = session_data.get("attack_chains", []) if include_chains else []
            root_causes = session_data.get("root_causes", []) if include_root_causes else []
            technical_details = self.technical_generator.generate(
                findings, metadata, attack_chains, root_causes
            )
        
        # Generate compliance section if applicable
        compliance = None
        if report_type in (ReportType.COMPLIANCE, ReportType.FULL):
            compliance = self._generate_compliance_section(findings)
        
        # Generate remediation plan
        remediation_plan = self._generate_remediation_plan(findings)
        
        return SecurityReport(
            metadata=metadata,
            executive_summary=executive_summary,
            technical_details=technical_details,
            compliance=compliance,
            remediation_plan=remediation_plan,
            findings=findings,
        )
    
    def export_report(
        self,
        report: SecurityReport,
        format: ReportFormat = ReportFormat.HTML
    ) -> str:
        """Export report to specified format."""
        return self.exporter.export(report, format)
    
    def _convert_findings(self, raw_findings: List[Dict]) -> List[ReportFinding]:
        """Convert raw findings to ReportFinding objects."""
        findings = []
        
        for raw in raw_findings:
            severity_str = raw.get("severity", "medium").lower()
            try:
                severity = SeverityLevel(severity_str)
            except ValueError:
                severity = SeverityLevel.MEDIUM
            
            finding = ReportFinding(
                id=raw.get("id", f"finding-{len(findings)+1}"),
                title=raw.get("title", raw.get("technique", "Unknown Vulnerability")),
                severity=severity,
                technique=raw.get("technique", "unknown"),
                description=raw.get("description", "No description provided"),
                url=raw.get("url", "N/A"),
                parameter=raw.get("parameter"),
                evidence=raw.get("evidence", raw.get("payload", "No evidence captured")),
                impact=raw.get("impact", self._generate_impact_text(raw.get("technique", ""))),
                remediation=raw.get("remediation", self._generate_remediation_text(raw.get("technique", ""))),
                cvss_score=raw.get("cvss_score"),
                cvss_vector=raw.get("cvss_vector"),
                cwe_id=raw.get("cwe_id"),
                cwe_name=raw.get("cwe_name"),
                compliance_mappings=raw.get("compliance_mappings", []),
            )
            findings.append(finding)
        
        # Sort by severity
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4,
        }
        findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        return findings
    
    def _create_metadata(
        self,
        session_data: Dict,
        report_type: ReportType,
        organization: Optional[str],
        assessor: Optional[str],
    ) -> ReportMetadata:
        """Create report metadata."""
        now = datetime.now()
        scan_start = session_data.get("start_time", now)
        scan_end = session_data.get("end_time", now)
        
        if isinstance(scan_start, str):
            scan_start = datetime.fromisoformat(scan_start)
        if isinstance(scan_end, str):
            scan_end = datetime.fromisoformat(scan_end)
        
        return ReportMetadata(
            report_id=self._generate_report_id(),
            report_type=report_type,
            generated_at=now,
            scan_start=scan_start,
            scan_end=scan_end,
            scan_duration_seconds=int((scan_end - scan_start).total_seconds()),
            target_count=len(session_data.get("targets", [])),
            targets=[t.get("url", t) if isinstance(t, dict) else str(t) for t in session_data.get("targets", [])],
            techniques_used=session_data.get("techniques", []),
            total_requests=session_data.get("total_requests", 0),
            organization=organization,
            assessor=assessor,
        )
    
    def _generate_impact_text(self, technique: str) -> str:
        """Generate impact text for a technique."""
        impacts = {
            "sql_injection": "An attacker could extract, modify, or delete data from the database. In severe cases, this could lead to complete database compromise or server-side code execution.",
            "xss": "An attacker could execute malicious scripts in victims' browsers, potentially stealing session tokens, defacing the website, or redirecting users to malicious sites.",
            "command_injection": "An attacker could execute arbitrary system commands on the server, potentially leading to complete server compromise, data theft, or use of the server for further attacks.",
            "path_traversal": "An attacker could read sensitive files from the server, potentially exposing configuration files, source code, or user data.",
            "idor": "An attacker could access or modify resources belonging to other users, potentially leading to unauthorized data access or account takeover.",
            "ssrf": "An attacker could make the server send requests to internal resources, potentially accessing internal services, cloud metadata, or bypassing firewalls.",
            "auth_bypass": "An attacker could bypass authentication controls and gain unauthorized access to protected resources or user accounts.",
        }
        return impacts.get(technique, "This vulnerability could allow an attacker to compromise application security.")
    
    def _generate_remediation_text(self, technique: str) -> str:
        """Generate remediation text for a technique."""
        remediations = {
            "sql_injection": "Use parameterized queries or prepared statements. Implement input validation with allowlists. Consider using an ORM framework.",
            "xss": "Implement context-aware output encoding. Use Content Security Policy headers. Sanitize user input before rendering.",
            "command_injection": "Avoid using system shell commands where possible. If necessary, use parameterized APIs and validate/sanitize all input.",
            "path_traversal": "Validate and canonicalize file paths. Use allowlists for permitted files. Avoid passing user input directly to file system operations.",
            "idor": "Implement proper authorization checks for all resource access. Use indirect references or UUIDs instead of sequential IDs.",
            "ssrf": "Validate and allowlist destination URLs. Block access to internal IP ranges. Use a web application firewall.",
            "auth_bypass": "Review and strengthen authentication logic. Use established authentication frameworks. Implement multi-factor authentication for sensitive operations.",
        }
        return remediations.get(technique, "Review and remediate according to security best practices for this vulnerability type.")
    
    def _generate_compliance_section(self, findings: List[ReportFinding]) -> ComplianceSection:
        """Generate compliance section."""
        frameworks = ["OWASP Top 10", "PCI-DSS", "HIPAA"]
        
        # Simple compliance mapping
        failed_controls = []
        for finding in findings:
            if finding.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH):
                if finding.technique in ("sql_injection", "xss", "command_injection"):
                    failed_controls.append({
                        "framework": "OWASP Top 10",
                        "control": "A03:2021 - Injection",
                        "finding": finding.title,
                    })
                if finding.technique in ("auth_bypass", "idor"):
                    failed_controls.append({
                        "framework": "OWASP Top 10",
                        "control": "A01:2021 - Broken Access Control",
                        "finding": finding.title,
                    })
        
        return ComplianceSection(
            frameworks_assessed=frameworks,
            compliance_status={
                "OWASP Top 10": {
                    "status": "Failed" if failed_controls else "Passed",
                    "failed_controls": len([f for f in failed_controls if f["framework"] == "OWASP Top 10"]),
                },
            },
            failed_controls=failed_controls,
            recommendations=[
                "Address all critical and high-severity findings to improve compliance posture",
                "Implement regular security testing as part of the development lifecycle",
                "Consider third-party penetration testing for compliance validation",
            ],
        )
    
    def _generate_remediation_plan(self, findings: List[ReportFinding]) -> RemediationPlan:
        """Generate remediation plan."""
        # Group by severity for prioritization
        priority_order = []
        quick_wins = []
        
        for finding in findings:
            item = {
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value,
                "estimated_effort": self._estimate_effort(finding),
            }
            priority_order.append(item)
            
            # Quick wins: medium severity with low effort
            if finding.severity in (SeverityLevel.MEDIUM, SeverityLevel.HIGH):
                if self._is_quick_fix(finding.technique):
                    quick_wins.append(item)
        
        # Timeline recommendations
        timeline = {
            "immediate_24h": [f.title for f in findings if f.severity == SeverityLevel.CRITICAL],
            "within_1_week": [f.title for f in findings if f.severity == SeverityLevel.HIGH],
            "within_2_weeks": [f.title for f in findings if f.severity == SeverityLevel.MEDIUM],
            "within_1_month": [f.title for f in findings if f.severity == SeverityLevel.LOW],
        }
        
        return RemediationPlan(
            priority_order=priority_order,
            quick_wins=quick_wins[:5],  # Top 5 quick wins
            estimated_total_effort=self._estimate_total_effort(findings),
            timeline_recommendations=timeline,
        )
    
    def _estimate_effort(self, finding: ReportFinding) -> str:
        """Estimate remediation effort."""
        effort_map = {
            "sql_injection": "4-8 hours",
            "xss": "2-4 hours",
            "command_injection": "4-8 hours",
            "path_traversal": "2-4 hours",
            "idor": "4-8 hours",
            "auth_bypass": "1-3 days",
        }
        return effort_map.get(finding.technique, "4-8 hours")
    
    def _is_quick_fix(self, technique: str) -> bool:
        """Check if technique typically has quick fixes."""
        quick_fixes = ["xss", "path_traversal", "header_injection"]
        return technique in quick_fixes
    
    def _estimate_total_effort(self, findings: List[ReportFinding]) -> str:
        """Estimate total remediation effort."""
        # Simple heuristic based on count and severity
        critical_high = sum(1 for f in findings if f.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH))
        medium_low = sum(1 for f in findings if f.severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW))
        
        total_hours = critical_high * 8 + medium_low * 4
        
        if total_hours < 8:
            return "Less than 1 day"
        elif total_hours < 40:
            return f"{total_hours // 8}-{(total_hours // 8) + 1} days"
        else:
            return f"{total_hours // 40}-{(total_hours // 40) + 1} weeks"


# Singleton instance
_report_generator: Optional[FuzzerReportGenerator] = None


def get_report_generator() -> FuzzerReportGenerator:
    """Get singleton report generator instance."""
    global _report_generator
    if _report_generator is None:
        _report_generator = FuzzerReportGenerator()
    return _report_generator


# Module exports
__all__ = [
    # Enums
    "ReportFormat",
    "ReportType",
    "SeverityLevel",
    
    # Data classes
    "ReportFinding",
    "ReportMetadata",
    "ExecutiveSummary",
    "TechnicalDetails",
    "ComplianceSection",
    "RemediationPlan",
    "SecurityReport",
    
    # Generators
    "ExecutiveSummaryGenerator",
    "TechnicalReportGenerator",
    "ReportExporter",
    "FuzzerReportGenerator",
    
    # Factory
    "get_report_generator",
]
