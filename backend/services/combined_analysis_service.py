"""
Combined Analysis Service

Aggregates data from Security Scans, Reverse Engineering reports, and Network Analysis
to generate comprehensive cross-analysis reports using Gemini AI.
"""

import json
import base64
import re
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import or_, func

from backend.core.config import settings
from backend.core.logging import get_logger
from backend.models import models
from backend.schemas.combined_analysis import (
    CombinedAnalysisRequest,
    SelectedScan,
    AvailableScansResponse,
    AvailableScanItem,
    CombinedAnalysisReportResponse,
    ReportSection,
    CrossAnalysisFinding,
    ExploitDevelopmentArea,
)

logger = get_logger(__name__)

# Initialize Gemini client
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
    except ImportError:
        logger.warning("google-genai not installed, Combined Analysis AI features disabled")


def get_available_scans(db: Session, project_id: int) -> AvailableScansResponse:
    """
    Get all available scans/reports for a project that can be included in combined analysis.
    """
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise ValueError(f"Project {project_id} not found")
    
    response = AvailableScansResponse(
        project_id=project_id,
        project_name=project.name,
    )
    
    # Security Scans (Reports from scan runs)
    reports = db.query(models.Report).filter(
        models.Report.project_id == project_id
    ).order_by(models.Report.created_at.desc()).all()
    
    for report in reports:
        # Count findings for this report
        findings_count = db.query(models.Finding).filter(
            models.Finding.scan_run_id == report.scan_run_id
        ).count() if report.scan_run_id else 0
        
        # Get severity breakdown
        severity_counts = report.data.get("severity_counts", {}) if report.data else {}
        risk_level = _score_to_risk_level(report.overall_risk_score)
        
        response.security_scans.append(AvailableScanItem(
            scan_type="security_scan",
            scan_id=report.id,
            title=report.title or f"Security Scan {report.id}",
            created_at=report.created_at,
            summary=f"Risk Score: {report.overall_risk_score or 'N/A'}, Findings: {findings_count}",
            risk_level=risk_level,
            findings_count=findings_count,
        ))
    
    # Network Analysis Reports (non-SSL)
    network_reports = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type != "ssl"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()
    
    for nr in network_reports:
        findings_count = len(nr.findings_data) if nr.findings_data else 0
        response.network_reports.append(AvailableScanItem(
            scan_type="network_report",
            scan_id=nr.id,
            title=nr.title or f"{nr.analysis_type.upper()} Analysis {nr.id}",
            created_at=nr.created_at,
            summary=f"Type: {nr.analysis_type}, Risk: {nr.risk_level or 'N/A'}",
            risk_level=nr.risk_level,
            findings_count=findings_count,
        ))
    
    # SSL/TLS Scans (separate category for visibility)
    ssl_scans = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type == "ssl"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()
    
    for ssl in ssl_scans:
        findings_count = len(ssl.findings_data) if ssl.findings_data else 0
        # Extract targets from raw_data
        targets = []
        if ssl.raw_data and isinstance(ssl.raw_data, dict):
            targets = ssl.raw_data.get("targets", [])
        target_summary = ", ".join(targets[:3]) if targets else "N/A"
        if len(targets) > 3:
            target_summary += f" (+{len(targets) - 3} more)"
        
        response.ssl_scans.append(AvailableScanItem(
            scan_type="ssl_scan",
            scan_id=ssl.id,
            title=ssl.title or f"SSL/TLS Scan {ssl.id}",
            created_at=ssl.created_at,
            summary=f"Targets: {target_summary}, Risk: {ssl.risk_level or 'N/A'}",
            risk_level=ssl.risk_level,
            findings_count=findings_count,
        ))
    
    # DNS Reconnaissance Scans
    dns_scans = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type == "dns"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()
    
    for dns in dns_scans:
        # Extract domain and stats from report_data
        report_data = dns.report_data or {}
        domain = report_data.get("domain", "Unknown")
        total_records = report_data.get("total_records", 0)
        total_subdomains = report_data.get("total_subdomains", 0)
        takeover_risks = report_data.get("takeover_risks", [])
        
        # Count findings: takeover risks + dangling CNAMEs + security issues
        findings_count = len(takeover_risks)
        if report_data.get("dangling_cnames"):
            findings_count += len(report_data.get("dangling_cnames", []))
        if report_data.get("zone_transfer_possible"):
            findings_count += 1
        
        response.dns_scans.append(AvailableScanItem(
            scan_type="dns_scan",
            scan_id=dns.id,
            title=dns.title or f"DNS Scan: {domain}",
            created_at=dns.created_at,
            summary=f"Domain: {domain}, Records: {total_records}, Subdomains: {total_subdomains}",
            risk_level=dns.risk_level,
            findings_count=findings_count,
        ))
    
    # Traceroute Scans
    traceroute_scans = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type == "traceroute"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()
    
    for tr in traceroute_scans:
        report_data = tr.report_data or {}
        result = report_data.get("result", {})
        target = result.get("target", "Unknown")
        total_hops = result.get("total_hops", 0)
        completed = result.get("completed", False)
        
        # Count findings from AI analysis
        ai_analysis = report_data.get("ai_analysis", {})
        findings_count = len(ai_analysis.get("security_observations", [])) if isinstance(ai_analysis, dict) else 0
        
        response.traceroute_scans.append(AvailableScanItem(
            scan_type="traceroute_scan",
            scan_id=tr.id,
            title=tr.title or f"Traceroute to {target}",
            created_at=tr.created_at,
            summary=f"Target: {target}, Hops: {total_hops}, Completed: {completed}",
            risk_level=tr.risk_level,
            findings_count=findings_count,
        ))
    
    # Reverse Engineering Reports
    re_reports = db.query(models.ReverseEngineeringReport).filter(
        models.ReverseEngineeringReport.project_id == project_id
    ).order_by(models.ReverseEngineeringReport.created_at.desc()).all()
    
    for re in re_reports:
        findings_count = len(re.security_issues) if re.security_issues else 0
        if re.decompiled_code_findings:
            findings_count += len(re.decompiled_code_findings)
        
        response.re_reports.append(AvailableScanItem(
            scan_type="re_report",
            scan_id=re.id,
            title=re.title or f"{re.analysis_type.upper()} Analysis {re.id}",
            created_at=re.created_at,
            summary=f"Type: {re.analysis_type}, File: {re.filename or 'N/A'}",
            risk_level=re.risk_level,
            findings_count=findings_count,
        ))
    
    # Fuzzing Sessions
    fuzzing_sessions = db.query(models.FuzzingSession).filter(
        models.FuzzingSession.project_id == project_id
    ).order_by(models.FuzzingSession.created_at.desc()).all()
    
    for fs in fuzzing_sessions:
        findings_count = len(fs.findings) if fs.findings else 0
        risk_level = _fuzzing_to_risk_level(fs)
        
        response.fuzzing_sessions.append(AvailableScanItem(
            scan_type="fuzzing_session",
            scan_id=fs.id,
            title=fs.name or f"Fuzzing Session {fs.id}",
            created_at=fs.created_at,
            summary=f"Target: {fs.target_url}, Status: {fs.status}",
            risk_level=risk_level,
            findings_count=findings_count,
        ))
    
    # Agentic Fuzzer Reports (AI-driven fuzzing with LLM decision making)
    agentic_fuzzer_reports = db.query(models.AgenticFuzzerReport).filter(
        models.AgenticFuzzerReport.project_id == project_id
    ).order_by(models.AgenticFuzzerReport.created_at.desc()).all()
    
    for afr in agentic_fuzzer_reports:
        # Count total findings
        findings_count = (
            (afr.findings_critical or 0) +
            (afr.findings_high or 0) +
            (afr.findings_medium or 0) +
            (afr.findings_low or 0) +
            (afr.findings_info or 0)
        )
        
        # Determine risk level
        if afr.findings_critical and afr.findings_critical > 0:
            risk_level = "Critical"
        elif afr.findings_high and afr.findings_high > 0:
            risk_level = "High"
        elif afr.findings_medium and afr.findings_medium > 0:
            risk_level = "Medium"
        elif afr.findings_low and afr.findings_low > 0:
            risk_level = "Low"
        else:
            risk_level = "Clean"
        
        response.agentic_fuzzer_reports.append(AvailableScanItem(
            scan_type="agentic_fuzzer_report",
            scan_id=afr.id,
            title=afr.title or f"Agentic Fuzzer Report {afr.id}",
            created_at=afr.created_at,
            summary=f"Target: {afr.target_url}, Iterations: {afr.total_iterations or 0}, Profile: {afr.scan_profile or 'Default'}",
            risk_level=risk_level,
            findings_count=findings_count,
        ))
    
    response.total_available = (
        len(response.security_scans) +
        len(response.network_reports) +
        len(response.ssl_scans) +
        len(response.dns_scans) +
        len(response.traceroute_scans) +
        len(response.re_reports) +
        len(response.fuzzing_sessions) +
        len(response.agentic_fuzzer_reports)
    )
    
    return response


def _score_to_risk_level(score: Optional[float]) -> str:
    """Convert numeric risk score to risk level string."""
    if score is None:
        return "Unknown"
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Clean"


def _fuzzing_to_risk_level(session: models.FuzzingSession) -> str:
    """Determine risk level from fuzzing session."""
    if not session.findings:
        return "Clean"
    
    findings = session.findings
    severities = [f.get("severity", "low").lower() for f in findings if isinstance(f, dict)]
    
    if any(s == "critical" for s in severities):
        return "Critical"
    if any(s == "high" for s in severities):
        return "High"
    if any(s == "medium" for s in severities):
        return "Medium"
    return "Low"


def _fetch_security_scan_data(db: Session, report_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a security scan report."""
    report = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report:
        return {"error": f"Report {report_id} not found"}
    
    # Get findings
    findings = []
    if report.scan_run_id:
        db_findings = db.query(models.Finding).filter(
            models.Finding.scan_run_id == report.scan_run_id
        ).all()
        
        for f in db_findings:
            findings.append({
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "summary": f.summary,
                "details": f.details,
                "is_duplicate": f.is_duplicate,
            })
    
    # Get exploit scenarios - include ALL fields for complete exploitability analysis
    exploit_scenarios = []
    db_scenarios = db.query(models.ExploitScenario).filter(
        models.ExploitScenario.report_id == report_id
    ).all()
    
    for es in db_scenarios:
        exploit_scenarios.append({
            "title": es.title,
            "severity": es.severity,
            "narrative": es.narrative,
            "preconditions": es.preconditions,  # Attack preconditions/requirements
            "impact": es.impact,
            "poc_outline": es.poc_outline,
            "poc_scripts": es.poc_scripts,  # Executable PoC code by language
            "attack_complexity": es.attack_complexity,
            "exploit_maturity": es.exploit_maturity,  # PoC, Functional, High
            "mitigation_notes": es.mitigation_notes,
        })
    
    # Extract additional data from report.data if available (codebase mapper, attack surface, etc.)
    report_data = report.data or {}
    
    return {
        "report_id": report_id,
        "title": report.title,
        "created_at": str(report.created_at),
        "overall_risk_score": report.overall_risk_score,
        "summary": report.summary,
        "severity_counts": report_data.get("severity_counts", {}),
        "ai_analysis_summary": report_data.get("ai_analysis_summary", {}),
        "attack_chains": report_data.get("attack_chains", []),
        # Codebase structure/architecture from agentic scan
        "codebase_map": report_data.get("codebase_map", ""),
        "codebase_diagram": report_data.get("codebase_diagram", ""),
        "architecture_diagram": report_data.get("architecture_diagram", ""),
        # Attack surface analysis
        "attack_surface_map": report_data.get("attack_surface_map", ""),
        "attack_surface_summary": report_data.get("attack_surface_summary", ""),
        "identified_entry_points": report_data.get("identified_entry_points", []),
        # Exploitability assessment
        "exploitability_assessment": report_data.get("exploitability_assessment", ""),
        # AI insights
        "ai_insights": report_data.get("ai_insights", {}),
        "findings": findings,
        "exploit_scenarios": exploit_scenarios,
        "findings_count": len(findings),
    }


def _fetch_network_report_data(db: Session, report_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a network analysis report."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == report_id
    ).first()
    if not report:
        return {"error": f"Network report {report_id} not found"}
    
    return {
        "report_id": report_id,
        "title": report.title,
        "analysis_type": report.analysis_type,
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "risk_score": report.risk_score,
        "summary_data": report.summary_data,
        "findings_data": report.findings_data,
        "ai_report": report.ai_report,
        "report_data": report.report_data,
        "filename": report.filename,
    }


def _fetch_ssl_scan_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from an SSL/TLS scan report."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == scan_id,
        models.NetworkAnalysisReport.analysis_type == "ssl"
    ).first()
    if not report:
        return {"error": f"SSL scan {scan_id} not found"}
    
    # Extract key SSL-specific data from raw_data
    raw_data = report.raw_data or {}
    targets = raw_data.get("targets", [])
    results = raw_data.get("results", [])
    
    # Extract SSL findings for analysis
    ssl_findings = []
    for result in results:
        host = result.get("host", "unknown")
        port = result.get("port", 443)
        
        # Protocol info
        protocols = result.get("protocols_supported", {})
        
        # Certificate info
        cert = result.get("certificate", {})
        cert_chain = result.get("certificate_chain", [])
        
        # Vulnerabilities
        vulns = result.get("vulnerabilities", [])
        findings = result.get("findings", [])
        
        # Attack analysis
        offensive = result.get("offensive_analysis", {})
        
        ssl_findings.append({
            "host": host,
            "port": port,
            "protocols": protocols,
            "certificate": {
                "subject": cert.get("subject", {}),
                "issuer": cert.get("issuer", {}),
                "valid_from": cert.get("valid_from"),
                "valid_until": cert.get("valid_until"),
                "is_expired": cert.get("is_expired", False),
                "is_self_signed": cert.get("is_self_signed", False),
                "key_size": cert.get("key_size"),
                "signature_algorithm": cert.get("signature_algorithm"),
            },
            "chain_length": len(cert_chain),
            "vulnerabilities": vulns,
            "findings": findings,
            "offensive_analysis": offensive,
        })
    
    return {
        "report_id": scan_id,
        "title": report.title,
        "analysis_type": "ssl",
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "risk_score": report.risk_score,
        "targets": targets,
        "ssl_findings": ssl_findings,
        "findings_data": report.findings_data,
        "ai_report": report.ai_report,
        "summary_data": report.summary_data,
    }


def _fetch_dns_scan_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a DNS reconnaissance scan report."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == scan_id,
        models.NetworkAnalysisReport.analysis_type == "dns"
    ).first()
    if not report:
        return {"error": f"DNS scan {scan_id} not found"}
    
    # Extract DNS-specific data from report_data
    report_data = report.report_data or {}
    
    # Core DNS data
    domain = report_data.get("domain", "Unknown")
    records = report_data.get("records", [])
    nameservers = report_data.get("nameservers", [])
    mail_servers = report_data.get("mail_servers", [])
    subdomains = report_data.get("subdomains", [])
    unique_ips = report_data.get("unique_ips", [])
    
    # Security analysis
    security = report_data.get("security", {})
    zone_transfer_possible = report_data.get("zone_transfer_possible", False)
    
    # Advanced reconnaissance data
    takeover_risks = report_data.get("takeover_risks", [])
    dangling_cnames = report_data.get("dangling_cnames", [])
    cloud_providers = report_data.get("cloud_providers", [])
    asn_info = report_data.get("asn_info", [])
    ct_logs = report_data.get("ct_logs", [])
    has_wildcard = report_data.get("has_wildcard", False)
    wildcard_ips = report_data.get("wildcard_ips", [])
    infrastructure_summary = report_data.get("infrastructure_summary", {})
    
    # Build findings list from various sources
    findings = []
    
    # Zone transfer vulnerability
    if zone_transfer_possible:
        findings.append({
            "type": "zone_transfer",
            "severity": "critical",
            "title": "DNS Zone Transfer Allowed",
            "description": f"Zone transfer (AXFR) is allowed on {domain}, exposing all DNS records"
        })
    
    # Subdomain takeover risks
    for risk in takeover_risks:
        findings.append({
            "type": "subdomain_takeover",
            "severity": risk.get("risk_level", "medium"),
            "title": f"Potential Subdomain Takeover: {risk.get('subdomain')}",
            "description": f"CNAME points to {risk.get('cname_target')} ({risk.get('provider')})",
            "is_vulnerable": risk.get("is_vulnerable", False)
        })
    
    # Dangling CNAMEs
    for dc in dangling_cnames:
        findings.append({
            "type": "dangling_cname",
            "severity": "medium",
            "title": f"Dangling CNAME: {dc.get('subdomain')}",
            "description": f"Points to {dc.get('cname')} which doesn't resolve"
        })
    
    # Email security issues
    if security:
        if not security.get("has_spf"):
            findings.append({
                "type": "email_security",
                "severity": "high",
                "title": "Missing SPF Record",
                "description": "Domain lacks SPF record, vulnerable to email spoofing"
            })
        if not security.get("has_dmarc"):
            findings.append({
                "type": "email_security",
                "severity": "high",
                "title": "Missing DMARC Record",
                "description": "Domain lacks DMARC record, email authentication not enforced"
            })
    
    return {
        "report_id": scan_id,
        "title": report.title,
        "analysis_type": "dns",
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "domain": domain,
        "total_records": len(records),
        "total_subdomains": len(subdomains),
        "nameservers": nameservers,
        "mail_servers": mail_servers,
        "unique_ips": unique_ips[:20],  # Limit for context
        "zone_transfer_possible": zone_transfer_possible,
        "security": security,
        "takeover_risks": takeover_risks,
        "dangling_cnames": dangling_cnames,
        "cloud_providers": cloud_providers,
        "asn_info": asn_info[:10],  # Limit for context
        "ct_logs_count": len(ct_logs),
        "has_wildcard": has_wildcard,
        "wildcard_ips": wildcard_ips,
        "infrastructure_summary": infrastructure_summary,
        "findings": findings,
        "findings_count": len(findings),
        "subdomains_sample": subdomains[:20],  # Sample for context
        "ai_report": report.ai_report,
    }


def _fetch_traceroute_scan_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a traceroute scan report."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == scan_id,
        models.NetworkAnalysisReport.analysis_type == "traceroute"
    ).first()
    if not report:
        return {"error": f"Traceroute scan {scan_id} not found"}
    
    report_data = report.report_data or {}
    result = report_data.get("result", {})
    ai_analysis = report_data.get("ai_analysis", {})
    
    # Core traceroute data
    target = result.get("target", "Unknown")
    target_ip = result.get("target_ip")
    hops = result.get("hops", [])
    total_hops = result.get("total_hops", 0)
    completed = result.get("completed", False)
    duration_ms = result.get("duration_ms", 0)
    platform = result.get("platform", "unknown")
    
    # Analyze hops for key metrics
    timeout_hops = [h for h in hops if h.get("is_timeout")]
    high_latency_hops = [h for h in hops if h.get("avg_rtt_ms") and h["avg_rtt_ms"] > 100]
    packet_loss_hops = [h for h in hops if h.get("packet_loss", 0) > 20]
    
    # Extract unique IPs from path
    path_ips = [h.get("ip_address") for h in hops if h.get("ip_address")]
    
    # Analyze hostnames for network inference
    hostnames = [h.get("hostname") for h in hops if h.get("hostname")]
    
    # Build findings from analysis
    findings = []
    
    # Timeout findings
    if len(timeout_hops) > 3:
        findings.append({
            "type": "network_filtering",
            "severity": "medium",
            "title": f"Multiple Timeouts ({len(timeout_hops)} hops)",
            "description": "Multiple hops are filtering ICMP/UDP probes, possible firewall presence"
        })
    
    # High latency findings
    for hop in high_latency_hops[:5]:
        findings.append({
            "type": "high_latency",
            "severity": "low" if hop.get("avg_rtt_ms", 0) < 200 else "medium",
            "title": f"High Latency at Hop {hop.get('hop_number')}",
            "description": f"{hop.get('ip_address', 'Unknown')} - {hop.get('avg_rtt_ms', 0):.1f}ms"
        })
    
    # Packet loss findings
    for hop in packet_loss_hops[:5]:
        findings.append({
            "type": "packet_loss",
            "severity": "medium" if hop.get("packet_loss", 0) < 50 else "high",
            "title": f"Packet Loss at Hop {hop.get('hop_number')}",
            "description": f"{hop.get('ip_address', 'Unknown')} - {hop.get('packet_loss', 0):.0f}% loss"
        })
    
    # Path not completed
    if not completed:
        findings.append({
            "type": "unreachable",
            "severity": "high",
            "title": "Target Not Reached",
            "description": f"Traceroute did not reach {target} - possible filtering or routing issue"
        })
    
    # Get security observations from AI
    if isinstance(ai_analysis, dict):
        for obs in ai_analysis.get("security_observations", []):
            if isinstance(obs, dict):
                findings.append({
                    "type": "ai_observation",
                    "severity": obs.get("severity", "info"),
                    "title": obs.get("observation", "Security Observation"),
                    "description": obs.get("details", "")
                })
    
    return {
        "report_id": scan_id,
        "title": report.title,
        "analysis_type": "traceroute",
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "target": target,
        "target_ip": target_ip,
        "total_hops": total_hops,
        "completed": completed,
        "duration_ms": duration_ms,
        "platform": platform,
        "hops": hops[:30],  # Limit for context
        "path_ips": path_ips,
        "hostnames": hostnames,
        "timeout_count": len(timeout_hops),
        "high_latency_count": len(high_latency_hops),
        "packet_loss_count": len(packet_loss_hops),
        "findings": findings,
        "findings_count": len(findings),
        "ai_analysis": ai_analysis,
    }


def _fetch_re_report_data(db: Session, report_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a reverse engineering report."""
    report = db.query(models.ReverseEngineeringReport).filter(
        models.ReverseEngineeringReport.id == report_id
    ).first()
    if not report:
        return {"error": f"RE report {report_id} not found"}
    
    return {
        "report_id": report_id,
        "title": report.title,
        "analysis_type": report.analysis_type,
        "created_at": str(report.created_at),
        "filename": report.filename,
        "risk_level": report.risk_level,
        "risk_score": report.risk_score,
        "file_type": report.file_type,
        "architecture": report.architecture,
        "is_packed": report.is_packed,
        "package_name": report.package_name,
        "suspicious_indicators": report.suspicious_indicators,
        "permissions": report.permissions,
        "security_issues": report.security_issues,
        "ai_analysis_structured": report.ai_analysis_structured,
        "ai_security_report": report.ai_security_report,
        "ai_threat_model": report.ai_threat_model,
        "decompiled_code_findings": report.decompiled_code_findings,
        "decompiled_code_summary": report.decompiled_code_summary,
        "cve_scan_results": report.cve_scan_results,
        "sensitive_data_findings": report.sensitive_data_findings,
        "verification_results": report.verification_results,
    }


def _fetch_fuzzing_session_data(db: Session, session_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a fuzzing session."""
    session = db.query(models.FuzzingSession).filter(
        models.FuzzingSession.id == session_id
    ).first()
    if not session:
        return {"error": f"Fuzzing session {session_id} not found"}
    
    return {
        "session_id": session_id,
        "name": session.name,
        "description": session.description,
        "target_url": session.target_url,
        "method": session.method,
        "status": session.status,
        "created_at": str(session.created_at),
        "config": session.config,
        "total_requests": session.total_requests,
        "interesting_count": session.interesting_count,
        "findings": session.findings,
        "analysis": session.analysis,
    }


def _fetch_agentic_fuzzer_report_data(db: Session, report_id: int) -> Dict[str, Any]:
    """Fetch detailed data from an agentic fuzzer report (LLM-driven scanning)."""
    report = db.query(models.AgenticFuzzerReport).filter(
        models.AgenticFuzzerReport.id == report_id
    ).first()
    if not report:
        return {"error": f"Agentic fuzzer report {report_id} not found"}
    
    return {
        "report_id": report_id,
        "session_id": report.session_id,
        "title": report.title,
        "target_url": report.target_url,
        "scan_profile": report.scan_profile,
        "started_at": str(report.started_at) if report.started_at else None,
        "completed_at": str(report.completed_at) if report.completed_at else None,
        "duration_seconds": report.duration_seconds,
        "total_iterations": report.total_iterations,
        "total_requests": report.total_requests,
        "findings_critical": report.findings_critical,
        "findings_high": report.findings_high,
        "findings_medium": report.findings_medium,
        "findings_low": report.findings_low,
        "findings_info": report.findings_info,
        "duplicates_filtered": report.duplicates_filtered,
        "executive_summary": report.executive_summary,
        "ai_report": report.ai_report,
        "findings": report.findings,
        "techniques_used": report.techniques_used,
        "correlation_analysis": report.correlation_analysis,
        "engine_stats": report.engine_stats,
        "crawl_results": report.crawl_results,
    }


def _aggregate_scan_data(db: Session, selected_scans: List[SelectedScan]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """
    Aggregate data from all selected scans.
    Returns (aggregated_data, scan_type_counts)
    """
    aggregated = {
        "security_scans": [],
        "network_reports": [],
        "ssl_scans": [],
        "dns_scans": [],
        "traceroute_scans": [],
        "re_reports": [],
        "fuzzing_sessions": [],
        "agentic_fuzzer_reports": [],
    }
    
    counts = {
        "security_scan": 0,
        "network_report": 0,
        "ssl_scan": 0,
        "dns_scan": 0,
        "traceroute_scan": 0,
        "re_report": 0,
        "fuzzing_session": 0,
        "agentic_fuzzer_report": 0,
    }
    
    for scan in selected_scans:
        if scan.scan_type == "security_scan":
            data = _fetch_security_scan_data(db, scan.scan_id)
            aggregated["security_scans"].append(data)
            counts["security_scan"] += 1
        elif scan.scan_type == "network_report":
            data = _fetch_network_report_data(db, scan.scan_id)
            aggregated["network_reports"].append(data)
            counts["network_report"] += 1
        elif scan.scan_type == "ssl_scan":
            data = _fetch_ssl_scan_data(db, scan.scan_id)
            aggregated["ssl_scans"].append(data)
            counts["ssl_scan"] += 1
        elif scan.scan_type == "dns_scan":
            data = _fetch_dns_scan_data(db, scan.scan_id)
            aggregated["dns_scans"].append(data)
            counts["dns_scan"] += 1
        elif scan.scan_type == "traceroute_scan":
            data = _fetch_traceroute_scan_data(db, scan.scan_id)
            aggregated["traceroute_scans"].append(data)
            counts["traceroute_scan"] += 1
        elif scan.scan_type == "re_report":
            data = _fetch_re_report_data(db, scan.scan_id)
            aggregated["re_reports"].append(data)
            counts["re_report"] += 1
        elif scan.scan_type == "fuzzing_session":
            data = _fetch_fuzzing_session_data(db, scan.scan_id)
            aggregated["fuzzing_sessions"].append(data)
            counts["fuzzing_session"] += 1
        elif scan.scan_type == "agentic_fuzzer_report":
            data = _fetch_agentic_fuzzer_report_data(db, scan.scan_id)
            aggregated["agentic_fuzzer_reports"].append(data)
            counts["agentic_fuzzer_report"] += 1
    
    return aggregated, counts


# ============================================================================
# Source Code Deep Dive - Analyze project source based on findings
# ============================================================================

def _extract_indicators_from_findings(aggregated_data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """
    Extract searchable indicators from all findings across scan types.
    Returns dict with categories: file_paths, endpoints, function_names, patterns, credentials, ips_hosts
    """
    indicators: Dict[str, Set[str]] = {
        "file_paths": set(),
        "endpoints": set(),
        "function_names": set(),
        "patterns": set(),
        "credentials": set(),
        "ips_hosts": set(),
        "vulnerability_types": set(),
    }
    
    # Extract from security scans
    for scan in aggregated_data.get("security_scans", []):
        for finding in scan.get("findings", []):
            # File paths
            if finding.get("file_path"):
                indicators["file_paths"].add(finding["file_path"])
                # Extract filename without path
                filename = finding["file_path"].split("/")[-1].split("\\")[-1]
                if filename:
                    indicators["file_paths"].add(filename)
            
            # Vulnerability types
            if finding.get("type"):
                indicators["vulnerability_types"].add(finding["type"])
            
            # Extract patterns from details
            details = finding.get("details", {})
            if isinstance(details, dict):
                # Look for function/method names
                for key in ["function", "method", "handler", "function_name", "method_name"]:
                    if details.get(key):
                        indicators["function_names"].add(details[key])
                
                # Look for endpoints
                for key in ["endpoint", "url", "path", "route"]:
                    if details.get(key):
                        indicators["endpoints"].add(details[key])
        
        # Extract from attack chains
        for chain in scan.get("attack_chains", []):
            if isinstance(chain, dict):
                for step in chain.get("steps", []):
                    if isinstance(step, dict):
                        if step.get("file_path"):
                            indicators["file_paths"].add(step["file_path"])
                        if step.get("function"):
                            indicators["function_names"].add(step["function"])
    
    # Extract from network reports
    for nr in aggregated_data.get("network_reports", []):
        findings_data = nr.get("findings_data", [])
        if isinstance(findings_data, list):
            for finding in findings_data:
                if isinstance(finding, dict):
                    # IPs and hosts
                    for key in ["ip", "host", "src_ip", "dst_ip", "server", "target"]:
                        if finding.get(key):
                            indicators["ips_hosts"].add(str(finding[key]))
                    
                    # Credentials found in network traffic
                    for key in ["username", "password", "api_key", "token", "credential"]:
                        if finding.get(key):
                            indicators["credentials"].add(str(finding[key]))
                    
                    # URLs/endpoints
                    for key in ["url", "endpoint", "path", "uri"]:
                        if finding.get(key):
                            indicators["endpoints"].add(str(finding[key]))
        
        # Check AI report for additional indicators
        ai_report = nr.get("ai_report", {})
        if isinstance(ai_report, dict):
            # Credential exposure section
            cred_exposure = ai_report.get("credential_exposure", {})
            if isinstance(cred_exposure, dict):
                for cred in cred_exposure.get("credentials_found", []):
                    if isinstance(cred, dict):
                        if cred.get("username"):
                            indicators["credentials"].add(cred["username"])
                        if cred.get("value"):
                            indicators["credentials"].add(cred["value"])
            
            # Hosts analysis
            hosts = ai_report.get("hosts_analysis", {})
            if isinstance(hosts, dict):
                for host in hosts.get("hosts", []):
                    if isinstance(host, dict) and host.get("ip"):
                        indicators["ips_hosts"].add(host["ip"])
    
    # Extract from RE reports
    for re_report in aggregated_data.get("re_reports", []):
        # Sensitive data findings
        sensitive_data = re_report.get("sensitive_data_findings", [])
        if isinstance(sensitive_data, list):
            for item in sensitive_data:
                if isinstance(item, dict):
                    if item.get("file_path"):
                        indicators["file_paths"].add(item["file_path"])
                    if item.get("value"):
                        indicators["credentials"].add(str(item["value"])[:50])
        
        # Security issues
        security_issues = re_report.get("security_issues", [])
        if isinstance(security_issues, list):
            for issue in security_issues:
                if isinstance(issue, dict):
                    if issue.get("location"):
                        indicators["file_paths"].add(issue["location"])
                    if issue.get("type"):
                        indicators["vulnerability_types"].add(issue["type"])
        
        # Decompiled code findings
        decompiled_findings = re_report.get("decompiled_code_findings", [])
        if isinstance(decompiled_findings, list):
            for finding in decompiled_findings:
                if isinstance(finding, dict):
                    if finding.get("class_name"):
                        indicators["function_names"].add(finding["class_name"])
                    if finding.get("method"):
                        indicators["function_names"].add(finding["method"])
    
    # Extract from fuzzing sessions
    for fs in aggregated_data.get("fuzzing_sessions", []):
        # Target URL
        if fs.get("target_url"):
            indicators["endpoints"].add(fs["target_url"])
        
        # Findings from fuzzing
        findings = fs.get("findings", [])
        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    if finding.get("url"):
                        indicators["endpoints"].add(finding["url"])
                    if finding.get("endpoint"):
                        indicators["endpoints"].add(finding["endpoint"])
                    if finding.get("parameter"):
                        indicators["patterns"].add(finding["parameter"])
    
    # Extract from DNS scans
    for dns_scan in aggregated_data.get("dns_scans", []):
        # Domain
        if dns_scan.get("domain"):
            indicators["ips_hosts"].add(dns_scan["domain"])
        
        # IPs
        for ip in dns_scan.get("unique_ips", []):
            if ip:
                indicators["ips_hosts"].add(ip)
        
        # Subdomains
        for subdomain in dns_scan.get("subdomains_sample", []):
            if isinstance(subdomain, dict):
                if subdomain.get("name"):
                    indicators["ips_hosts"].add(subdomain["name"])
                for sub_ip in subdomain.get("ips", []):
                    indicators["ips_hosts"].add(sub_ip)
            elif isinstance(subdomain, str):
                indicators["ips_hosts"].add(subdomain)
        
        # Nameservers
        for ns in dns_scan.get("nameservers", []):
            if isinstance(ns, dict) and ns.get("name"):
                indicators["ips_hosts"].add(ns["name"])
            elif isinstance(ns, str):
                indicators["ips_hosts"].add(ns)
        
        # Mail servers
        for mx in dns_scan.get("mail_servers", []):
            if isinstance(mx, dict) and mx.get("host"):
                indicators["ips_hosts"].add(mx["host"])
            elif isinstance(mx, str):
                indicators["ips_hosts"].add(mx)
        
        # Takeover risks - service providers
        for risk in dns_scan.get("takeover_risks", []):
            if isinstance(risk, dict):
                if risk.get("subdomain"):
                    indicators["ips_hosts"].add(risk["subdomain"])
                if risk.get("cname_target"):
                    indicators["ips_hosts"].add(risk["cname_target"])
        
        # Vulnerability types from DNS findings
        for finding in dns_scan.get("findings", []):
            if isinstance(finding, dict) and finding.get("type"):
                indicators["vulnerability_types"].add(finding["type"])
    
    # Extract from traceroute scans
    for tr_scan in aggregated_data.get("traceroute_scans", []):
        # Target
        if tr_scan.get("target"):
            indicators["ips_hosts"].add(tr_scan["target"])
        if tr_scan.get("target_ip"):
            indicators["ips_hosts"].add(tr_scan["target_ip"])
        
        # Path IPs
        for ip in tr_scan.get("path_ips", []):
            if ip:
                indicators["ips_hosts"].add(ip)
        
        # Hostnames from hops
        for hostname in tr_scan.get("hostnames", []):
            if hostname:
                indicators["ips_hosts"].add(hostname)
        
        # IPs from hops
        for hop in tr_scan.get("hops", []):
            if isinstance(hop, dict):
                if hop.get("ip_address"):
                    indicators["ips_hosts"].add(hop["ip_address"])
                if hop.get("hostname"):
                    indicators["ips_hosts"].add(hop["hostname"])
    
    # Clean up - remove empty strings and limit sizes
    for key in indicators:
        indicators[key] = {v for v in indicators[key] if v and len(v) > 2 and len(v) < 200}
    
    return indicators


def _search_source_code_for_indicators(
    db: Session,
    project_id: int,
    indicators: Dict[str, Set[str]],
    max_chunks: int = 50,
) -> List[Dict[str, Any]]:
    """
    Search project's CodeChunks for code related to the extracted indicators.
    Returns list of relevant code snippets with context.
    """
    relevant_code: List[Dict[str, Any]] = []
    seen_chunks: Set[int] = set()
    
    # Build search terms
    search_terms: List[str] = []
    
    # Add file paths (search by filename)
    for fp in list(indicators.get("file_paths", []))[:20]:
        search_terms.append(fp)
    
    # Add function names
    for fn in list(indicators.get("function_names", []))[:15]:
        search_terms.append(fn)
    
    # Add endpoints (extract path segments)
    for ep in list(indicators.get("endpoints", []))[:15]:
        # Extract meaningful path parts
        path_parts = ep.replace("http://", "").replace("https://", "").split("/")
        for part in path_parts:
            if part and len(part) > 3 and not part.startswith("api"):
                search_terms.append(part)
    
    # Add credentials (search for where they might be defined)
    for cred in list(indicators.get("credentials", []))[:10]:
        if len(cred) > 4:  # Only meaningful credentials
            search_terms.append(cred)
    
    # Add IPs/hosts
    for host in list(indicators.get("ips_hosts", []))[:10]:
        search_terms.append(host)
    
    # Add vulnerability type patterns for code search
    vuln_code_patterns = {
        "sql_injection": ["execute", "query", "cursor", "SELECT", "INSERT", "UPDATE", "DELETE"],
        "xss": ["innerHTML", "document.write", "eval", "dangerouslySetInnerHTML"],
        "command_injection": ["exec", "system", "popen", "subprocess", "shell"],
        "path_traversal": ["open(", "read_file", "include", "require"],
        "hardcoded_credentials": ["password", "secret", "api_key", "token", "credential"],
        "insecure_crypto": ["MD5", "SHA1", "DES", "ECB"],
    }
    
    for vuln_type in indicators.get("vulnerability_types", []):
        vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")
        for pattern_key, patterns in vuln_code_patterns.items():
            if pattern_key in vuln_lower:
                search_terms.extend(patterns[:3])
    
    # Remove duplicates and limit
    search_terms = list(set(search_terms))[:50]
    
    if not search_terms:
        logger.info("No search terms extracted from findings for source code analysis")
        return []
    
    logger.info(f"Searching source code with {len(search_terms)} terms: {search_terms[:10]}...")
    
    # Query CodeChunks
    for term in search_terms:
        if len(relevant_code) >= max_chunks:
            break
        
        try:
            # Search in code content and file path
            chunks = db.query(models.CodeChunk).filter(
                models.CodeChunk.project_id == project_id,
                or_(
                    models.CodeChunk.code.ilike(f"%{term}%"),
                    models.CodeChunk.file_path.ilike(f"%{term}%"),
                )
            ).limit(5).all()
            
            for chunk in chunks:
                if chunk.id in seen_chunks:
                    continue
                seen_chunks.add(chunk.id)
                
                if len(relevant_code) >= max_chunks:
                    break
                
                relevant_code.append({
                    "file_path": chunk.file_path,
                    "language": chunk.language,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "code": chunk.code[:3000],  # Limit code size
                    "matched_term": term,
                    "summary": chunk.summary,
                })
        except Exception as e:
            logger.warning(f"Error searching for term '{term}': {e}")
            continue
    
    logger.info(f"Found {len(relevant_code)} relevant source code chunks")
    return relevant_code


def _build_source_code_context(relevant_code: List[Dict[str, Any]]) -> str:
    """Build a formatted string of relevant source code for the AI prompt."""
    if not relevant_code:
        return ""
    
    context_parts = ["""
## SOURCE CODE DEEP DIVE
Based on findings from the scans, here is relevant source code from the project that may contain 
related vulnerabilities, attack surface areas, or security-critical implementations:
"""]
    
    # Group by file path
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for code in relevant_code:
        fp = code.get("file_path", "unknown")
        if fp not in by_file:
            by_file[fp] = []
        by_file[fp].append(code)
    
    for file_path, chunks in list(by_file.items())[:30]:  # Limit files
        context_parts.append(f"\n### File: `{file_path}`")
        
        for chunk in chunks[:3]:  # Limit chunks per file
            lang = chunk.get("language", "")
            start = chunk.get("start_line", "?")
            end = chunk.get("end_line", "?")
            matched = chunk.get("matched_term", "")
            code_text = chunk.get("code", "")
            
            context_parts.append(f"""
**Lines {start}-{end}** (matched: `{matched}`)
```{lang}
{code_text[:2000]}
```
""")
    
    return "\n".join(context_parts)


def _build_analysis_prompt(
    aggregated_data: Dict[str, Any],
    project_info: Optional[str],
    user_requirements: Optional[str],
    supporting_docs_text: Optional[str],
    source_code_context: Optional[str],
    options: Dict[str, bool],
    data_counts: Optional[Dict[str, int]] = None,
) -> str:
    """Build the comprehensive analysis prompt for Gemini."""
    
    prompt = """You are an elite penetration tester and security researcher creating an EXTREMELY DETAILED security assessment report.

## YOUR ROLE AND OBJECTIVES

You are writing this report for security professionals AND beginners who want to understand EXACTLY how to exploit the vulnerabilities found.
You will analyze data from multiple security tools including:
- Static Application Security Testing (SAST) findings
- Network analysis (PCAP, Nmap, SSL/TLS, DNS)
- Reverse engineering analysis (Binary, APK, Docker)
- Fuzzing results
- Relevant source code from the project codebase
- User-provided supporting documentation (CRITICAL - analyze these thoroughly!)

## CRITICAL REQUIREMENTS

**YOU MUST:**
1. Generate an EXTREMELY DETAILED report - minimum 5000+ words of analysis
2. Provide STEP-BY-STEP exploitation guides that a COMPLETE BEGINNER could follow (numbered steps: Step 1, Step 2, Step 3, etc.)
3. Write ACTUAL WORKING PROOF-OF-CONCEPT (PoC) SCRIPTS for each exploitable vulnerability
4. Include exact commands, curl requests, Python scripts, or other executable code
5. Explain each vulnerability as if teaching someone who has NEVER done pentesting before (assume ZERO prior knowledge)
6. Cross-reference ALL provided documentation - if PDFs or docs are provided, REFERENCE THEM SPECIFICALLY
7. Create detailed attack narratives showing the full exploitation flow
8. Provide tool recommendations with exact command syntax
9. Include PREREQUISITES (what tools to install, how to set up the environment) before each exploit
10. Use the EXPLOIT SCENARIOS from the exploitability analysis as your primary guide for attacks

**BEGINNER-FRIENDLY FORMAT FOR EACH VULNERABILITY:**
```
## Vulnerability: [Name]
### What is this? (Plain English)
[Explain like I'm 5 - no jargon]

### Why should I care? (Real-world impact)
[What could an attacker actually do?]

### Prerequisites (Tools & Setup)
Step 1: Install [tool] using: [exact command]
Step 2: Configure [setting] by: [exact steps]

### Exploitation Steps (Follow Along)
Step 1: [Exact action with command/code]
Step 2: [Next action]
Step 3: [Continue until exploited]

### Proof-of-Concept Script
[Working code with comments explaining each line]

### How do I know it worked?
[What to look for to confirm success]

### How to fix it
[Remediation steps]
```

**FOR EACH VULNERABILITY YOU MUST PROVIDE:**
- What it is (beginner-friendly explanation - NO JARGON)
- Why it's dangerous (real-world impact scenarios)
- Prerequisites and tool installation steps
- Exact numbered steps to reproduce/exploit it (Step 1, Step 2, Step 3...)
- Working PoC code (Python, curl, bash, etc.) with LINE-BY-LINE comments
- How to verify successful exploitation (what output to expect)
- Defense evasion techniques if applicable
- Remediation steps

"""
    
    # Add project info if provided
    if project_info:
        prompt += f"""
## PROJECT CONTEXT (User Provided)
{project_info}

"""
    
    # Add user requirements if provided - CRITICAL SECTION
    if user_requirements:
        prompt += f"""
## ⚠️ CRITICAL: USER REQUIREMENTS (YOU MUST ADDRESS ALL OF THESE) ⚠️

The user has SPECIFICALLY requested the following. You MUST address EVERY point in detail:

{user_requirements}

**IMPORTANT: The above requirements are your PRIMARY DIRECTIVE. Structure your entire response to fulfill these specific requests. If the user asks for PoC scripts, provide WORKING CODE. If they ask for beginner-friendly explanations, assume ZERO prior knowledge.**

"""
    
    # Add supporting documents if provided - CRITICAL SECTION
    if supporting_docs_text:
        prompt += f"""
## 📄 SUPPORTING DOCUMENTATION (ANALYZE THOROUGHLY)

The user has provided the following documentation. You MUST:
1. Read and analyze ALL of this documentation carefully
2. Reference specific sections from these documents in your analysis
3. Correlate findings from scans with information in these documents
4. Use this documentation to provide more targeted exploitation guidance
5. If these contain architecture diagrams, API specs, or other technical details - USE THEM

{supporting_docs_text}

**END OF SUPPORTING DOCUMENTATION**

"""
    
    # Add source code context from deep dive analysis
    if source_code_context:
        prompt += source_code_context
        prompt += "\n"
    
    # Add security scan data
    if aggregated_data["security_scans"]:
        prompt += """
## SECURITY SCAN DATA (SAST/Code Analysis)
"""
        for i, scan in enumerate(aggregated_data["security_scans"], 1):
            prompt += f"""
### Security Scan {i}: {scan.get('title', 'Unknown')}
- Risk Score: {scan.get('overall_risk_score', 'N/A')}
- Severity Breakdown: {json.dumps(scan.get('severity_counts', {}))}
- Total Findings: {scan.get('findings_count', 0)}

"""
            findings = scan.get("findings", [])
            # Sort by severity priority
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "info").lower(), 5))
            
            # Group findings by severity for better organization
            findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for f in sorted_findings:
                sev = f.get("severity", "info").lower()
                if sev in findings_by_severity:
                    findings_by_severity[sev].append(f)
                else:
                    findings_by_severity["info"].append(f)
            
            # Include ALL findings with FULL details - no truncation
            for severity_level in ["critical", "high", "medium", "low"]:
                sev_findings = findings_by_severity.get(severity_level, [])
                if sev_findings:
                    prompt += f"""
## {severity_level.upper()} SEVERITY FINDINGS ({len(sev_findings)} total):
"""
                    for idx, f in enumerate(sev_findings, 1):
                        details = f.get("details", {})
                        details_str = ""
                        if isinstance(details, dict):
                            # Extract key details
                            for key, val in details.items():
                                if val and key not in ["code_snippet", "vulnerable_code"]:
                                    if isinstance(val, str) and len(val) > 500:
                                        val = val[:500] + "..."
                                    details_str += f"  - {key}: {val}\n"
                            # Include code snippet separately with full content
                            if details.get("code_snippet"):
                                details_str += f"  - Vulnerable Code:\n```\n{details['code_snippet'][:1500]}\n```\n"
                            if details.get("vulnerable_code"):
                                details_str += f"  - Vulnerable Code:\n```\n{details['vulnerable_code'][:1500]}\n```\n"
                        elif isinstance(details, str):
                            details_str = f"  - Details: {details[:1000]}\n"
                        
                        prompt += f"""
### Finding {idx}: [{f.get('severity', 'Unknown').upper()}] {f.get('type', 'Unknown')}
- **Summary:** {f.get('summary', 'No summary')}
- **File:** {f.get('file_path', 'N/A')} (Line {f.get('start_line', 'N/A')})
{details_str}
"""
            
            # Add attack chains if available
            attack_chains = scan.get("attack_chains", [])
            if attack_chains:
                prompt += f"""
**Attack Chains Identified:**
{json.dumps(attack_chains[:5], indent=2)}
"""
            
            # Add exploit scenarios if available - INCLUDE ALL with full details
            exploit_scenarios = scan.get("exploit_scenarios", [])
            if exploit_scenarios:
                prompt += f"""
**🎯 EXPLOIT SCENARIOS (Exploitability Analysis) - TOTAL COUNT: {len(exploit_scenarios)} - YOU MUST INCLUDE ALL {len(exploit_scenarios)} IN YOUR OUTPUT:**
"""
                for idx, es in enumerate(exploit_scenarios, 1):  # Include ALL scenarios with numbering
                    prompt += f"""
### Exploit #{idx} of {len(exploit_scenarios)}: {es.get('title', 'Unknown')} [{es.get('severity', 'Unknown').upper()}]
- **Attack Complexity:** {es.get('attack_complexity', 'N/A')}
- **Exploit Maturity:** {es.get('exploit_maturity', 'N/A')}
- **Preconditions:** {es.get('preconditions', 'N/A')}
- **Narrative:** {es.get('narrative', 'No narrative provided')}
- **Impact:** {es.get('impact', 'No impact specified')}
- **PoC Outline:** {es.get('poc_outline', 'No PoC outline')}
- **Mitigation Notes:** {es.get('mitigation_notes', 'No mitigation notes')}
"""
                    # Include PoC scripts if available
                    poc_scripts = es.get('poc_scripts')
                    if poc_scripts and isinstance(poc_scripts, dict):
                        prompt += "- **PoC Scripts:**\n"
                        for lang, code in poc_scripts.items():
                            prompt += f"  - {lang}:\n```{lang}\n{code[:2000]}\n```\n"
            
            # Add codebase map/structure if available
            codebase_map = scan.get("codebase_map")
            if codebase_map:
                prompt += f"""
**🗺️ CODEBASE STRUCTURE & ARCHITECTURE:**
{codebase_map}
"""
            
            # Add architecture diagram if available
            architecture_diagram = scan.get("architecture_diagram")
            if architecture_diagram:
                prompt += f"""
**📐 ARCHITECTURE DIAGRAM:**
```mermaid
{architecture_diagram}
```
"""
            
            # Add codebase diagram if available
            codebase_diagram = scan.get("codebase_diagram")
            if codebase_diagram:
                prompt += f"""
**📊 CODEBASE RELATIONSHIP DIAGRAM:**
```mermaid
{codebase_diagram}
```
"""
            
            # Add attack surface analysis if available
            attack_surface_summary = scan.get("attack_surface_summary")
            if attack_surface_summary:
                prompt += f"""
**🎯 ATTACK SURFACE SUMMARY:**
{attack_surface_summary}
"""
            
            # Add attack surface map if available
            attack_surface_map = scan.get("attack_surface_map")
            if attack_surface_map:
                prompt += f"""
**🌐 ATTACK SURFACE MAP:**
```mermaid
{attack_surface_map}
```
"""
            
            # Add identified entry points if available
            entry_points = scan.get("identified_entry_points", [])
            if entry_points:
                prompt += """
**🚪 IDENTIFIED ENTRY POINTS:**
"""
                for ep in entry_points[:20]:
                    auth_status = "🔓 NO AUTH" if not ep.get('auth', True) else "🔐 Auth required"
                    risk = ep.get('risk', 'medium').upper()
                    prompt += f"- [{risk}] {ep.get('method', 'GET')} {ep.get('route', '/')} - {auth_status}\n"
            
            # Add exploitability assessment if available
            exploitability_assessment = scan.get("exploitability_assessment")
            if exploitability_assessment:
                prompt += f"""
**⚔️ EXPLOITABILITY ASSESSMENT:**
{exploitability_assessment}
"""
            
            # Add AI insights if available
            ai_insights = scan.get("ai_insights", {})
            if ai_insights:
                prompt += f"""
**🤖 AI ANALYSIS INSIGHTS:**
{json.dumps(ai_insights, indent=2)[:3000]}
"""
    
    # Add network analysis data
    if aggregated_data["network_reports"]:
        prompt += """
## NETWORK ANALYSIS DATA
"""
        for i, nr in enumerate(aggregated_data["network_reports"], 1):
            prompt += f"""
### Network Report {i}: {nr.get('title', 'Unknown')} ({nr.get('analysis_type', 'unknown')})
- Risk Level: {nr.get('risk_level', 'N/A')}
- Risk Score: {nr.get('risk_score', 'N/A')}
"""
            if nr.get("summary_data"):
                prompt += f"""
**Summary:**
{json.dumps(nr.get('summary_data'), indent=2)[:2000]}
"""
            if nr.get("findings_data"):
                prompt += f"""
**Findings:**
{json.dumps(nr.get('findings_data')[:15], indent=2)}
"""
            if nr.get("ai_report"):
                ai_report = nr.get("ai_report")
                if isinstance(ai_report, dict):
                    filtered_report = {k: v for k, v in ai_report.items() if k in ['executive_summary', 'risk_assessment', 'key_findings']}
                    prompt += f"""
**AI Analysis Highlights:**
{json.dumps(filtered_report, indent=2)[:3000]}
"""
    
    # Add RE analysis data
    if aggregated_data["re_reports"]:
        prompt += """
## REVERSE ENGINEERING ANALYSIS DATA
"""
        for i, re in enumerate(aggregated_data["re_reports"], 1):
            prompt += f"""
### RE Report {i}: {re.get('title', 'Unknown')} ({re.get('analysis_type', 'unknown')})
- File: {re.get('filename', 'N/A')}
- Risk Level: {re.get('risk_level', 'N/A')}
- Architecture: {re.get('architecture', 'N/A')}
- File Type: {re.get('file_type', 'N/A')}
- Is Packed: {re.get('is_packed', 'N/A')}
"""
            if re.get("suspicious_indicators"):
                prompt += f"""
**Suspicious Indicators:**
{json.dumps(re.get('suspicious_indicators')[:10], indent=2)}
"""
            if re.get("security_issues"):
                prompt += f"""
**Security Issues:**
{json.dumps(re.get('security_issues')[:15], indent=2)}
"""
            if re.get("ai_analysis_structured"):
                prompt += f"""
**AI Analysis:**
{json.dumps(re.get('ai_analysis_structured'), indent=2)[:3000]}
"""
            if re.get("sensitive_data_findings"):
                prompt += f"""
**Sensitive Data Found:**
{json.dumps(re.get('sensitive_data_findings')[:10], indent=2)}
"""
            if re.get("cve_scan_results"):
                prompt += f"""
**CVE Scan Results:**
{json.dumps(re.get('cve_scan_results')[:10], indent=2)}
"""
    
    # Add SSL/TLS scan data - CRITICAL for correlating with network and code vulnerabilities
    if aggregated_data.get("ssl_scans"):
        prompt += """
## SSL/TLS SECURITY SCAN DATA
"""
        for i, ssl in enumerate(aggregated_data["ssl_scans"], 1):
            prompt += f"""
### SSL/TLS Scan {i}: {ssl.get('title', 'Unknown')}
- Risk Level: {ssl.get('risk_level', 'N/A')}
- Risk Score: {ssl.get('risk_score', 'N/A')}
- Targets: {', '.join(ssl.get('targets', [])[:5])}
"""
            # SSL findings for each target
            ssl_findings = ssl.get("ssl_findings", [])
            if ssl_findings:
                for sf in ssl_findings[:5]:
                    host = sf.get("host", "unknown")
                    port = sf.get("port", 443)
                    prompt += f"""
**Target: {host}:{port}**
- Protocols: {json.dumps(sf.get('protocols', {}))}
- Certificate:
  - Subject: {sf.get('certificate', {}).get('subject', 'N/A')}
  - Issuer: {sf.get('certificate', {}).get('issuer', 'N/A')}
  - Valid Until: {sf.get('certificate', {}).get('valid_until', 'N/A')}
  - Is Expired: {sf.get('certificate', {}).get('is_expired', False)}
  - Is Self-Signed: {sf.get('certificate', {}).get('is_self_signed', False)}
  - Key Size: {sf.get('certificate', {}).get('key_size', 'N/A')}
  - Signature Algorithm: {sf.get('certificate', {}).get('signature_algorithm', 'N/A')}
"""
                    # Vulnerabilities found
                    vulns = sf.get("vulnerabilities", [])
                    if vulns:
                        prompt += f"""
**🔴 SSL Vulnerabilities:**
{json.dumps(vulns[:10], indent=2)}
"""
                    # Findings
                    findings = sf.get("findings", [])
                    if findings:
                        prompt += f"""
**SSL Findings:**
{json.dumps(findings[:10], indent=2)}
"""
                    # Offensive analysis
                    offensive = sf.get("offensive_analysis", {})
                    if offensive:
                        prompt += f"""
**Offensive Analysis (Attack Potential):**
{json.dumps(offensive, indent=2)[:2000]}
"""
            # General findings from SSL scan
            if ssl.get("findings_data"):
                prompt += f"""
**All SSL Findings:**
{json.dumps(ssl.get('findings_data')[:15], indent=2)}
"""
            # AI report if available
            if ssl.get("ai_report"):
                ai_report = ssl.get("ai_report")
                if isinstance(ai_report, dict):
                    filtered = {k: v for k, v in ai_report.items() if k in ['executive_summary', 'risk_assessment', 'key_findings', 'attack_surface']}
                    if filtered:
                        prompt += f"""
**AI Analysis Highlights:**
{json.dumps(filtered, indent=2)[:2000]}
"""
    
    # Add fuzzing data
    if aggregated_data["fuzzing_sessions"]:
        prompt += """
## FUZZING ANALYSIS DATA
"""
        for i, fs in enumerate(aggregated_data["fuzzing_sessions"], 1):
            prompt += f"""
### Fuzzing Session {i}: {fs.get('name', 'Unknown')}
- Target: {fs.get('target_url', 'N/A')}
- Method: {fs.get('method', 'N/A')}
- Status: {fs.get('status', 'N/A')}
- Total Requests: {fs.get('total_requests', 0)}
- Interesting Findings: {fs.get('interesting_count', 0)}
"""
            if fs.get("findings"):
                prompt += f"""
**Findings:**
{json.dumps(fs.get('findings')[:15], indent=2)}
"""
            if fs.get("analysis"):
                prompt += f"""
**Analysis:**
{json.dumps(fs.get('analysis'), indent=2)[:2000]}
"""
    
    # Add DNS reconnaissance data
    if aggregated_data["dns_scans"]:
        prompt += """
## DNS RECONNAISSANCE DATA
"""
        for i, dns in enumerate(aggregated_data["dns_scans"], 1):
            prompt += f"""
### DNS Scan {i}: {dns.get('domain', 'Unknown')}
- Risk Level: {dns.get('risk_level', 'N/A')}
- Total Records: {dns.get('total_records', 0)}
- Total Subdomains: {dns.get('total_subdomains', 0)}
- Zone Transfer Possible: {dns.get('zone_transfer_possible', False)}
- Has Wildcard: {dns.get('has_wildcard', False)}
"""
            # Nameservers
            if dns.get("nameservers"):
                ns_list = dns.get("nameservers", [])[:5]
                ns_str = ", ".join([ns.get("name", str(ns)) if isinstance(ns, dict) else str(ns) for ns in ns_list])
                prompt += f"""
**Nameservers:** {ns_str}
"""
            # Mail servers
            if dns.get("mail_servers"):
                mx_list = dns.get("mail_servers", [])[:5]
                mx_str = ", ".join([mx.get("host", str(mx)) if isinstance(mx, dict) else str(mx) for mx in mx_list])
                prompt += f"""
**Mail Servers:** {mx_str}
"""
            # Security analysis
            security = dns.get("security", {})
            if security:
                prompt += f"""
**Email Security:**
- SPF Record: {security.get('has_spf', 'N/A')} {f"({security.get('spf_record', '')[:100]})" if security.get('spf_record') else ''}
- DMARC Record: {security.get('has_dmarc', 'N/A')}
- DKIM: {security.get('has_dkim', 'N/A')}
- DNSSEC: {security.get('dnssec_enabled', 'N/A')}
"""
            # Subdomain takeover risks
            takeover_risks = dns.get("takeover_risks", [])
            if takeover_risks:
                prompt += f"""
**🚨 SUBDOMAIN TAKEOVER RISKS ({len(takeover_risks)} identified):**
{json.dumps(takeover_risks[:10], indent=2)}
"""
            # Dangling CNAMEs
            dangling = dns.get("dangling_cnames", [])
            if dangling:
                prompt += f"""
**Dangling CNAMEs ({len(dangling)}):**
{json.dumps(dangling[:10], indent=2)}
"""
            # Cloud providers
            cloud_providers = dns.get("cloud_providers", [])
            if cloud_providers:
                prompt += f"""
**Cloud Providers Detected:** {', '.join(cloud_providers)}
"""
            # ASN info
            asn_info = dns.get("asn_info", [])
            if asn_info:
                prompt += f"""
**ASN Information:**
{json.dumps(asn_info[:5], indent=2)}
"""
            # Infrastructure summary
            infra = dns.get("infrastructure_summary", {})
            if infra:
                prompt += f"""
**Infrastructure Summary:**
{json.dumps(infra, indent=2)[:1000]}
"""
            # Findings
            findings = dns.get("findings", [])
            if findings:
                prompt += f"""
**DNS Security Findings ({len(findings)}):**
{json.dumps(findings, indent=2)}
"""
            # Sample subdomains
            subdomains = dns.get("subdomains_sample", [])
            if subdomains:
                prompt += f"""
**Subdomain Sample ({len(subdomains)} shown, {dns.get('total_subdomains', 0)} total):**
{json.dumps(subdomains[:15], indent=2)}
"""
            # AI report if available
            if dns.get("ai_report"):
                ai_report = dns.get("ai_report")
                if isinstance(ai_report, dict):
                    filtered = {k: v for k, v in ai_report.items() if k in ['executive_summary', 'risk_assessment', 'attack_surface', 'remediation_roadmap']}
                    if filtered:
                        prompt += f"""
**AI Analysis Highlights:**
{json.dumps(filtered, indent=2)[:2000]}
"""
    
    # Add Traceroute data
    if aggregated_data["traceroute_scans"]:
        prompt += """
## TRACEROUTE NETWORK PATH DATA
"""
        for i, tr in enumerate(aggregated_data["traceroute_scans"], 1):
            prompt += f"""
### Traceroute {i}: {tr.get('target', 'Unknown')}
- Target IP: {tr.get('target_ip', 'N/A')}
- Total Hops: {tr.get('total_hops', 0)}
- Completed: {tr.get('completed', False)}
- Duration: {tr.get('duration_ms', 0):.0f}ms
- Platform: {tr.get('platform', 'unknown')}
- Timeout Hops: {tr.get('timeout_count', 0)}
- High Latency Hops: {tr.get('high_latency_count', 0)}
- Packet Loss Hops: {tr.get('packet_loss_count', 0)}
"""
            # Network path
            hops = tr.get("hops", [])
            if hops:
                prompt += """
**Network Path:**
"""
                for hop in hops[:20]:
                    if isinstance(hop, dict):
                        hop_num = hop.get("hop_number", "?")
                        ip = hop.get("ip_address", "*")
                        hostname = hop.get("hostname", "")
                        rtt = hop.get("avg_rtt_ms")
                        loss = hop.get("packet_loss", 0)
                        
                        if hop.get("is_timeout"):
                            prompt += f"  {hop_num}. * * * (timeout)\n"
                        else:
                            rtt_str = f"{rtt:.1f}ms" if rtt else "N/A"
                            loss_str = f" [{loss:.0f}% loss]" if loss > 0 else ""
                            hostname_str = f" ({hostname})" if hostname and hostname != ip else ""
                            prompt += f"  {hop_num}. {ip}{hostname_str} - {rtt_str}{loss_str}\n"
            
            # Path IPs for correlation
            path_ips = tr.get("path_ips", [])
            if path_ips:
                prompt += f"""
**Path IPs:** {', '.join(path_ips[:15])}
"""
            # Hostnames for network inference
            hostnames = tr.get("hostnames", [])
            if hostnames:
                prompt += f"""
**Hostnames (for network inference):** {', '.join(hostnames[:10])}
"""
            # Findings
            findings = tr.get("findings", [])
            if findings:
                prompt += f"""
**Traceroute Findings ({len(findings)}):**
{json.dumps(findings[:10], indent=2)}
"""
            # AI analysis
            ai_analysis = tr.get("ai_analysis", {})
            if isinstance(ai_analysis, dict):
                if ai_analysis.get("summary"):
                    prompt += f"""
**Summary:** {ai_analysis.get('summary')}
"""
                if ai_analysis.get("network_segments"):
                    prompt += f"""
**Network Segments:**
{json.dumps(ai_analysis.get('network_segments', [])[:5], indent=2)}
"""
                if ai_analysis.get("security_observations"):
                    prompt += f"""
**Security Observations:**
{json.dumps(ai_analysis.get('security_observations', [])[:10], indent=2)}
"""
    
    # Output format instructions - MUCH MORE DETAILED
    prompt += """

## OUTPUT FORMAT

Generate an EXTREMELY DETAILED JSON response. This report should be comprehensive enough to serve as a complete penetration test report.

```json
{
    "executive_summary": "A detailed 5-10 paragraph executive summary covering: 1) Overall security posture 2) Most critical findings 3) Attack scenarios identified 4) Immediate risks 5) Recommended prioritization. Be VERY thorough and specific - this should be multiple paragraphs.",
    
    "overall_risk_level": "Critical|High|Medium|Low|Clean",
    "overall_risk_score": 0-100,
    "risk_justification": "Multi-paragraph explanation of why this risk level was assigned, referencing specific findings and their combined impact",
    
    "total_findings_analyzed": <number>,
    
    "report_sections": [
        {
            "title": "Section Title",
            "content": "VERY detailed content - multiple paragraphs with technical depth. Include code examples where relevant.",
            "section_type": "text|list|table|code",
            "severity": "Critical|High|Medium|Low|Info"
        }
    ],
    
    "beginner_attack_guide": [
        {
            "attack_name": "Name of the attack (e.g., 'SQL Injection on Login Endpoint')",
            "difficulty_level": "Beginner|Intermediate|Advanced",
            "estimated_time": "How long this attack takes (e.g., '15-30 minutes')",
            "prerequisites": ["What you need to know/have before attempting"],
            "tools_needed": [
                {
                    "tool": "Tool name (e.g., 'curl', 'Burp Suite', 'sqlmap')",
                    "installation": "How to install (e.g., 'pip install sqlmap')",
                    "purpose": "What this tool does in the attack"
                }
            ],
            "step_by_step_guide": [
                {
                    "step_number": 1,
                    "title": "Step title",
                    "explanation": "Detailed explanation of what we're doing and why - explain like teaching a complete beginner",
                    "command_or_action": "The exact command or action to take",
                    "expected_output": "What you should see if it works",
                    "troubleshooting": "Common issues and how to fix them"
                }
            ],
            "success_indicators": ["How to know the attack worked"],
            "what_you_can_do_after": "What access/capabilities you gain from this attack"
        }
    ],
    
    "poc_scripts": [
        {
            "vulnerability_name": "Name of the vulnerability this exploits",
            "language": "python|bash|javascript|curl|powershell",
            "description": "What this script does - detailed explanation",
            "usage_instructions": "How to run this script with example commands",
            "script_code": "The FULL, WORKING script code - not pseudocode, actual executable code",
            "expected_output": "What successful exploitation looks like",
            "customization_notes": "How to modify for different targets/scenarios"
        }
    ],
    
    "cross_analysis_findings": [
        {
            "title": "Cross-Domain Finding Title",
            "description": "Detailed explanation of how this finding spans multiple scan types",
            "severity": "Critical|High|Medium|Low",
            "sources": ["security_scan", "network_report", "re_report", "fuzzing_session"],
            "source_details": [{"type": "...", "finding": "...", "reference": "..."}],
            "exploitability_score": 0.0-1.0,
            "exploit_narrative": "Tell the story of how an attacker would exploit this - from initial access to impact",
            "exploit_guidance": "Technical step-by-step exploitation guide",
            "poc_available": true,
            "remediation": "Detailed fix with code examples if applicable"
        }
    ],
"""
    
    if options.get("include_attack_surface_map", True):
        prompt += """
    "attack_surface_diagram": "A DETAILED Mermaid flowchart diagram showing the complete attack surface and exploitation paths. Include all entry points, vulnerable components, and data flows. Use proper Mermaid syntax with descriptive labels.",
    
    "attack_chains": [
        {
            "chain_name": "Descriptive name for this attack chain",
            "entry_point": "Where the attack starts",
            "steps": [
                {
                    "step": 1,
                    "action": "What the attacker does",
                    "vulnerability_used": "Which vulnerability enables this",
                    "outcome": "What access/capability is gained"
                }
            ],
            "final_impact": "What the attacker achieves at the end",
            "likelihood": "High|Medium|Low",
            "diagram": "Mermaid diagram for this specific chain"
        }
    ],
"""
    
    if options.get("include_exploit_recommendations", True):
        prompt += """
    "exploit_development_areas": [
        {
            "title": "Exploit Development Opportunity",
            "description": "Detailed description - what makes this exploitable and why it's interesting",
            "vulnerability_chain": ["vuln1", "vuln2"],
            "attack_vector": "Network|Local|Physical|Adjacent",
            "complexity": "Low|Medium|High",
            "impact": "Detailed impact description - what can an attacker do?",
            "prerequisites": ["Everything needed before exploitation"],
            "poc_guidance": "DETAILED step-by-step PoC development guide with actual commands and code",
            "full_poc_script": "If applicable, the complete PoC script",
            "testing_notes": "How to safely test this exploit",
            "detection_evasion": "How to avoid detection while exploiting"
        }
    ],
"""
    
    if options.get("include_risk_prioritization", True):
        prompt += """
    "prioritized_vulnerabilities": [
        {
            "rank": 1,
            "title": "Vulnerability title",
            "severity": "Critical|High|Medium|Low",
            "cvss_estimate": "Estimated CVSS score if applicable",
            "exploitability": "Easy|Medium|Hard",
            "impact": "Detailed impact description",
            "source": "Which scan type found this",
            "affected_component": "What system/file/endpoint is affected",
            "exploitation_steps": ["Step 1", "Step 2", "..."],
            "poc_available": "Yes - see poc_scripts section | No",
            "remediation_priority": "Immediate|Short-term|Long-term",
            "remediation_steps": ["Detailed fix step 1", "Step 2", "..."],
            "references": ["CVE numbers, documentation links, etc."]
        }
    ],
    
    "source_code_findings": [
        {
            "file_path": "Path to the vulnerable file",
            "issue_type": "Type of vulnerability found",
            "severity": "Critical|High|Medium|Low",
            "description": "Detailed description of the issue - explain what's wrong and why it's dangerous",
            "vulnerable_code_snippet": "The actual vulnerable code",
            "line_numbers": "Exact line range",
            "exploitation_example": "How to exploit this specific code",
            "related_scan_findings": ["How this relates to other findings"],
            "secure_code_fix": "The corrected code that fixes the vulnerability",
            "remediation": "Full remediation guidance"
        }
    ],
    
    "documentation_analysis": "If supporting documents were provided, include a section analyzing them and how they relate to findings. Reference specific documents and sections."
"""
    
    prompt += """
}
```

## ⚠️⚠️⚠️ CRITICAL REQUIREMENTS - READ CAREFULLY ⚠️⚠️⚠️

### ABSOLUTE REQUIREMENTS (FAILURE TO COMPLY = FAILED RESPONSE):

1. **INCLUDE ALL VULNERABILITIES**: 
   - COUNT the exploit scenarios provided in the input (there should be around 7)
   - Your `prioritized_vulnerabilities` array MUST contain AT LEAST the same number of items
   - DO NOT truncate. DO NOT summarize. Include EVERY vulnerability.
   - If there are 7 exploit scenarios in the input, you MUST have AT LEAST 7 items in prioritized_vulnerabilities

2. **CROSS-ANALYSIS FINDINGS MUST BE SUBSTANTIAL**:
   - Each finding needs DETAILED description (3+ sentences minimum)
   - Include the FULL exploit_narrative telling the complete attack story
   - Include the FULL exploit_guidance with step-by-step exploitation
   - DO NOT give one-sentence descriptions. This is a professional penetration test report.

3. **POC SCRIPTS ARE MANDATORY**:
   - For EVERY Critical and High severity vulnerability, provide a working PoC script
   - Scripts must be EXECUTABLE - not pseudocode, not descriptions
   - Include Python scripts with requests library for web attacks
   - Include exact curl commands that can be copy-pasted
   - Include SQL injection payloads that work

4. **STEP-BY-STEP ATTACK GUIDES**:
   - For each major vulnerability, provide a beginner_attack_guide entry
   - Each guide MUST have at least 5 numbered steps
   - Each step MUST include: step_number, title, explanation, command_or_action, expected_output
   - Write as if teaching someone who has NEVER done security testing

5. **EXPLOIT SCENARIOS FROM INPUT = YOUR OUTPUT**:
   - Look at the "EXPLOIT SCENARIOS" section in the input data
   - EVERY single exploit scenario MUST appear in your output
   - Expand each one with MORE detail, not less
   - Include the PoC scripts that were provided - they should appear in your poc_scripts array

6. **LENGTH REQUIREMENTS**:
   - executive_summary: At least 500 words
   - Each cross_analysis_finding description: At least 100 words
   - Each poc_scripts entry: At least 20 lines of actual code
   - Each beginner_attack_guide: At least 5 detailed steps

7. **DO NOT**:
   - Truncate the response early
   - Say "and more..." or "etc."
   - Skip vulnerabilities to save space
   - Provide vague descriptions
   - Return empty arrays when data was provided

### VERIFICATION CHECKLIST (Check before responding):
□ Did I include ALL exploit scenarios from the input?
□ Does prioritized_vulnerabilities have the same count as input exploit scenarios (or more)?
□ Did I provide working PoC code for Critical/High findings?
□ Did I write detailed step-by-step guides?
□ Is each cross_analysis_finding at least 100 words?
□ Did I include mermaid diagrams?

Generate your COMPREHENSIVE JSON response now. This report will be used for an actual security assessment. DETAIL IS MANDATORY."""
    
    # Add MANDATORY OUTPUT COUNTS section with actual data counts
    if data_counts:
        prompt += f"""

## 🚨🚨🚨 MANDATORY OUTPUT COUNTS - YOU WILL FAIL IF YOU DON'T MEET THESE 🚨🚨🚨

Based on the input data provided, your response MUST contain:

**EXACT MINIMUM COUNTS (NON-NEGOTIABLE):**

| Output Field | MINIMUM Required | Your Input Has |
|--------------|------------------|----------------|
| prioritized_vulnerabilities | **{data_counts.get('min_prioritized_vulns', 7)}** items | {data_counts.get('total_findings', 0)} findings, {data_counts.get('total_exploit_scenarios', 0)} exploit scenarios |
| poc_scripts | **{data_counts.get('min_poc_scripts', 5)}** scripts | {data_counts.get('critical_high_count', 0)} Critical/High findings |
| beginner_attack_guide | **{data_counts.get('min_attack_guides', 5)}** guides | {data_counts.get('total_exploit_scenarios', 0)} exploit scenarios |
| cross_analysis_findings | **{data_counts.get('min_cross_findings', 3)}** findings | Multiple scan types to correlate |
| attack_chains | **3** chains minimum | Multiple vulnerabilities to chain |
| exploit_development_areas | **{data_counts.get('total_exploit_scenarios', 3)}** areas | {data_counts.get('total_exploit_scenarios', 0)} exploit scenarios in input |

**IF YOUR RESPONSE HAS FEWER ITEMS THAN THE MINIMUM, IT WILL BE REJECTED.**

For each poc_script, you MUST provide at least 30 lines of working Python/bash/curl code.
For each beginner_attack_guide, you MUST provide at least 7 detailed steps.
For each prioritized_vulnerability, you MUST provide exploitation_steps array with 5+ steps.

COUNT YOUR OUTPUT BEFORE SUBMITTING. VERIFY YOU MEET THE MINIMUMS ABOVE.
"""
    
    return prompt


async def generate_combined_analysis(
    db: Session,
    request: CombinedAnalysisRequest,
    user_id: Optional[int] = None,
) -> models.CombinedAnalysisReport:
    """
    Generate a comprehensive combined analysis report.
    """
    if not genai_client:
        raise ValueError("Gemini AI not configured - cannot generate analysis")
    
    # Verify project exists
    project = db.query(models.Project).filter(models.Project.id == request.project_id).first()
    if not project:
        raise ValueError(f"Project {request.project_id} not found")
    
    # Create the report record
    db_report = models.CombinedAnalysisReport(
        project_id=request.project_id,
        title=request.title,
        created_by=user_id,
        selected_scans=[s.model_dump() for s in request.selected_scans],
        project_info=request.project_info,
        user_requirements=request.user_requirements,
        report_options={
            "include_exploit_recommendations": request.include_exploit_recommendations,
            "include_attack_surface_map": request.include_attack_surface_map,
            "include_risk_prioritization": request.include_risk_prioritization,
        },
        status="processing",
    )
    
    # Handle supporting documents
    if request.supporting_documents:
        docs_metadata = []
        for doc in request.supporting_documents:
            docs_metadata.append({
                "filename": doc.filename,
                "content_type": doc.content_type,
                "description": doc.description,
            })
        db_report.supporting_documents = docs_metadata
    
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    
    try:
        # Aggregate all scan data
        aggregated_data, scan_counts = _aggregate_scan_data(db, request.selected_scans)
        
        # Log detailed aggregation info
        for scan in aggregated_data.get("security_scans", []):
            findings_count = len(scan.get("findings", []))
            exploit_scenarios_count = len(scan.get("exploit_scenarios", []))
            logger.info(f"Security scan '{scan.get('title')}': {findings_count} findings, {exploit_scenarios_count} exploit scenarios")
            
            # Log severity breakdown
            severity_breakdown = {}
            for f in scan.get("findings", []):
                sev = f.get("severity", "unknown").lower()
                severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            logger.info(f"  Severity breakdown: {severity_breakdown}")
            
            # Log exploit scenarios
            for es in scan.get("exploit_scenarios", []):
                logger.info(f"  Exploit scenario: {es.get('title')} [{es.get('severity')}]")
                if es.get('poc_scripts'):
                    logger.info(f"    Has PoC scripts: {list(es.get('poc_scripts', {}).keys())}")
        
        # Process supporting documents text - extract full content from PDFs and other docs
        supporting_docs_text = None
        if request.supporting_documents:
            docs_text_parts = []
            for doc in request.supporting_documents:
                try:
                    content = base64.b64decode(doc.content_base64).decode("utf-8", errors="ignore")
                    # Allow much larger document content - up to 125,000 characters per document
                    doc_content = content[:125000]
                    doc_description = f" - {doc.description}" if doc.description else ""
                    docs_text_parts.append(f"### Document: {doc.filename}{doc_description}\n\n{doc_content}")
                    logger.info(f"Processed supporting document: {doc.filename} ({len(doc_content)} chars)")
                except Exception as e:
                    logger.warning(f"Could not decode document {doc.filename}: {e}")
            if docs_text_parts:
                supporting_docs_text = "\n\n---\n\n".join(docs_text_parts)
                logger.info(f"Total supporting documentation: {len(supporting_docs_text)} chars from {len(docs_text_parts)} documents")
        
        # Source Code Deep Dive - Extract indicators from findings and search codebase
        logger.info("Performing source code deep dive analysis...")
        indicators = _extract_indicators_from_findings(aggregated_data)
        indicator_counts = {k: len(v) for k, v in indicators.items()}
        logger.info(f"Extracted indicators: {indicator_counts}")
        
        relevant_source_code = _search_source_code_for_indicators(
            db, request.project_id, indicators, max_chunks=50
        )
        source_code_context = _build_source_code_context(relevant_source_code)
        
        # Calculate actual counts from data for mandatory output requirements
        total_findings = 0
        total_exploit_scenarios = 0
        critical_high_count = 0
        for scan in aggregated_data.get("security_scans", []):
            total_findings += len(scan.get("findings", []))
            total_exploit_scenarios += len(scan.get("exploit_scenarios", []))
            for f in scan.get("findings", []):
                if f.get("severity", "").lower() in ["critical", "high"]:
                    critical_high_count += 1
        
        data_counts = {
            "total_findings": total_findings,
            "total_exploit_scenarios": total_exploit_scenarios,
            "critical_high_count": critical_high_count,
            "min_prioritized_vulns": max(total_exploit_scenarios, 7),
            "min_poc_scripts": max(min(critical_high_count, 10), 5),
            "min_attack_guides": max(total_exploit_scenarios, 5),
            "min_cross_findings": max(total_exploit_scenarios - 2, 3),
        }
        logger.info(f"Data counts for mandatory output: {data_counts}")
        
        # Build the analysis prompt
        options = {
            "include_exploit_recommendations": request.include_exploit_recommendations,
            "include_attack_surface_map": request.include_attack_surface_map,
            "include_risk_prioritization": request.include_risk_prioritization,
        }
        
        prompt = _build_analysis_prompt(
            aggregated_data,
            request.project_info,
            request.user_requirements,
            supporting_docs_text,
            source_code_context,
            options,
            data_counts,
        )
        
        # =====================================================================
        # MULTI-AGENT REPORT GENERATION
        # Run multiple focused AI agents in parallel for better quality
        # =====================================================================
        import asyncio
        from google.genai import types
        
        logger.info("Starting MULTI-AGENT report generation...")
        logger.info(f"Data counts: {data_counts}")
        
        # Run all agents in parallel for speed
        logger.info("Launching 9 parallel AI agents...")
        
        # Pass user requirements to agents that benefit from customization
        user_reqs = request.user_requirements or ""
        
        (
            exec_summary_result,
            poc_scripts,
            attack_guides,
            prioritized_vulns,
            cross_findings,
            attack_diagram,
            attack_chains,
            exploit_dev_areas,
            source_code_findings,
        ) = await asyncio.gather(
            _agent_executive_summary(genai_client, aggregated_data, data_counts, user_reqs),
            _agent_poc_scripts(genai_client, aggregated_data, data_counts, user_reqs),
            _agent_attack_guides(genai_client, aggregated_data, data_counts, user_reqs),
            _agent_prioritized_vulns(genai_client, aggregated_data, data_counts, user_reqs),
            _agent_cross_analysis(genai_client, aggregated_data, data_counts),
            _agent_attack_surface_diagram(genai_client, aggregated_data),
            _agent_attack_chains(genai_client, aggregated_data),
            _agent_exploit_development(genai_client, aggregated_data, data_counts),
            _agent_source_code_findings(genai_client, aggregated_data, relevant_source_code, data_counts),
            return_exceptions=True,  # Don't fail if one agent fails
        )
        
        # Log results from each agent
        logger.info("Multi-agent results:")
        logger.info(f"  - executive_summary: {len(exec_summary_result.get('executive_summary', '')) if isinstance(exec_summary_result, dict) else 'ERROR'}")
        logger.info(f"  - poc_scripts: {len(poc_scripts) if isinstance(poc_scripts, list) else 'ERROR'}")
        logger.info(f"  - attack_guides: {len(attack_guides) if isinstance(attack_guides, list) else 'ERROR'}")
        logger.info(f"  - prioritized_vulns: {len(prioritized_vulns) if isinstance(prioritized_vulns, list) else 'ERROR'}")
        logger.info(f"  - cross_findings: {len(cross_findings) if isinstance(cross_findings, list) else 'ERROR'}")
        logger.info(f"  - attack_diagram: {len(attack_diagram) if isinstance(attack_diagram, str) else 'ERROR'}")
        logger.info(f"  - attack_chains: {len(attack_chains) if isinstance(attack_chains, list) else 'ERROR'}")
        logger.info(f"  - exploit_dev_areas: {len(exploit_dev_areas) if isinstance(exploit_dev_areas, list) else 'ERROR'}")
        logger.info(f"  - source_code_findings: {len(source_code_findings) if isinstance(source_code_findings, list) else 'ERROR'}")
        
        # Handle exceptions from agents
        if isinstance(exec_summary_result, Exception):
            logger.error(f"Executive summary agent failed: {exec_summary_result}")
            exec_summary_result = {}
        if isinstance(poc_scripts, Exception):
            logger.error(f"PoC scripts agent failed: {poc_scripts}")
            poc_scripts = []
        if isinstance(attack_guides, Exception):
            logger.error(f"Attack guides agent failed: {attack_guides}")
            attack_guides = []
        if isinstance(prioritized_vulns, Exception):
            logger.error(f"Prioritized vulns agent failed: {prioritized_vulns}")
            prioritized_vulns = []
        if isinstance(cross_findings, Exception):
            logger.error(f"Cross findings agent failed: {cross_findings}")
            cross_findings = []
        if isinstance(attack_diagram, Exception):
            logger.error(f"Attack diagram agent failed: {attack_diagram}")
            attack_diagram = ""
        if isinstance(attack_chains, Exception):
            logger.error(f"Attack chains agent failed: {attack_chains}")
            attack_chains = []
        if isinstance(exploit_dev_areas, Exception):
            logger.error(f"Exploit dev areas agent failed: {exploit_dev_areas}")
            exploit_dev_areas = []
        if isinstance(source_code_findings, Exception):
            logger.error(f"Source code findings agent failed: {source_code_findings}")
            source_code_findings = []
        
        # Calculate total findings analyzed
        total_findings = 0
        for scan in aggregated_data["security_scans"]:
            total_findings += scan.get("findings_count", 0)
        for nr in aggregated_data["network_reports"]:
            if nr.get("findings_data"):
                total_findings += len(nr.get("findings_data", []))
        for re in aggregated_data["re_reports"]:
            if re.get("security_issues"):
                total_findings += len(re.get("security_issues", []))
            if re.get("decompiled_code_findings"):
                total_findings += len(re.get("decompiled_code_findings", []))
        for fs in aggregated_data["fuzzing_sessions"]:
            if fs.get("findings"):
                total_findings += len(fs.get("findings", []))
        
        # Combine all agent results
        db_report.status = "completed"
        db_report.executive_summary = exec_summary_result.get("executive_summary", "") if isinstance(exec_summary_result, dict) else ""
        db_report.overall_risk_level = exec_summary_result.get("overall_risk_level", "High") if isinstance(exec_summary_result, dict) else "High"
        db_report.overall_risk_score = exec_summary_result.get("overall_risk_score", 85) if isinstance(exec_summary_result, dict) else 85
        db_report.risk_justification = exec_summary_result.get("risk_justification", "") if isinstance(exec_summary_result, dict) else ""
        db_report.total_findings_analyzed = total_findings
        db_report.scans_included = len(request.selected_scans)
        db_report.scan_types_breakdown = scan_counts
        
        # Build Detailed Exploit Scenarios section from aggregated security scan data
        exploit_scenarios_content = []
        for scan in aggregated_data["security_scans"]:
            exploit_scenarios = scan.get("exploit_scenarios", [])
            if exploit_scenarios:
                for idx, es in enumerate(exploit_scenarios, 1):
                    severity = es.get('severity', 'Unknown').upper()
                    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")
                    
                    scenario_md = f"""### {severity_emoji} {es.get('title', 'Unknown Exploit')}

**Severity:** {severity} | **Attack Complexity:** {es.get('attack_complexity', 'N/A')} | **Exploit Maturity:** {es.get('exploit_maturity', 'N/A')}

**Preconditions:**
{es.get('preconditions', 'None specified')}

**Attack Narrative:**
{es.get('narrative', 'No narrative provided')}

**Impact:**
{es.get('impact', 'No impact specified')}

**PoC Outline:**
{es.get('poc_outline', 'No PoC outline available')}

**Mitigation:**
{es.get('mitigation_notes', 'No mitigation notes')}

"""
                    # Add PoC scripts if available
                    poc_scripts_data = es.get('poc_scripts')
                    if poc_scripts_data and isinstance(poc_scripts_data, dict):
                        scenario_md += "**Proof of Concept Scripts:**\n\n"
                        for lang, code in poc_scripts_data.items():
                            scenario_md += f"```{lang}\n{code[:3000]}\n```\n\n"
                    
                    exploit_scenarios_content.append(scenario_md)
        
        # Create report_sections with Detailed Exploit Scenarios
        report_sections = []
        if exploit_scenarios_content:
            report_sections.append({
                "title": "🎯 Detailed Exploit Scenarios",
                "content": "\n---\n\n".join(exploit_scenarios_content),
                "section_type": "text",
                "severity": "Critical"
            })
        
        db_report.report_sections = report_sections
        db_report.cross_analysis_findings = cross_findings if isinstance(cross_findings, list) else []
        db_report.attack_surface_diagram = attack_diagram if isinstance(attack_diagram, str) else ""
        db_report.attack_chains = attack_chains if isinstance(attack_chains, list) else []
        db_report.beginner_attack_guide = attack_guides if isinstance(attack_guides, list) else []
        db_report.poc_scripts = poc_scripts if isinstance(poc_scripts, list) else []
        db_report.exploit_development_areas = exploit_dev_areas if isinstance(exploit_dev_areas, list) else []
        db_report.prioritized_vulnerabilities = prioritized_vulns if isinstance(prioritized_vulns, list) else []
        db_report.source_code_findings = source_code_findings if isinstance(source_code_findings, list) else []
        db_report.documentation_analysis = ""
        
        # Store raw responses for debugging
        db_report.raw_ai_response = json.dumps({
            "multi_agent": True,
            "exec_summary": exec_summary_result if isinstance(exec_summary_result, dict) else str(exec_summary_result),
            "poc_count": len(poc_scripts) if isinstance(poc_scripts, list) else 0,
            "guides_count": len(attack_guides) if isinstance(attack_guides, list) else 0,
        })
        
        db.commit()
        db.refresh(db_report)
        
        return db_report
        
    except Exception as e:
        logger.error(f"Error generating combined analysis: {e}")
        db_report.status = "failed"
        db_report.error_message = str(e)
        db.commit()
        raise


def _parse_ai_response(raw_response: str) -> Dict[str, Any]:
    """Parse the AI response, handling JSON extraction from markdown code blocks."""
    import re
    
    # Try to extract JSON from code blocks
    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw_response)
    if json_match:
        json_str = json_match.group(1).strip()
    else:
        # Try parsing the whole response as JSON
        json_str = raw_response.strip()
    
    try:
        return json.loads(json_str)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse AI response as JSON: {e}")
        # Return a minimal structure
        return {
            "executive_summary": raw_response[:2000],
            "overall_risk_level": "Unknown",
            "overall_risk_score": 0,
            "risk_justification": "Could not parse AI response",
            "report_sections": [],
            "cross_analysis_findings": [],
        }


# =====================================================================
# MULTI-AGENT REPORT GENERATION
# Each agent focuses on a specific part of the report for better quality
# =====================================================================

async def _agent_executive_summary(
    genai_client,
    aggregated_data: Dict[str, Any],
    data_counts: Dict[str, int],
    user_requirements: str = "",
) -> Dict[str, Any]:
    """Agent 1: Generate executive summary and overall risk assessment with MARKDOWN formatting."""
    from google.genai import types
    
    # Build focused prompt for executive summary
    findings_summary = []
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for scan in aggregated_data.get("security_scans", []):
        findings_summary.append(f"- {scan.get('title')}: {len(scan.get('findings', []))} findings")
        for f in scan.get("findings", []):
            sev = f.get("severity", "Medium")
            if sev in severity_counts:
                severity_counts[sev] += 1
    
    # Add user requirements context
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
The client has specifically requested:
{user_requirements}

Please ensure your summary addresses these specific requirements.
"""
    
    prompt = f"""You are an elite security consultant writing an EXECUTIVE SUMMARY for a penetration test report.

## INPUT DATA SUMMARY
- Total Findings: {data_counts.get('total_findings', 0)}
- Critical Findings: {severity_counts['Critical']}
- High Findings: {severity_counts['High']}
- Medium Findings: {severity_counts['Medium']}
- Low Findings: {severity_counts['Low']}
- Exploit Scenarios Identified: {data_counts.get('total_exploit_scenarios', 0)}

Scans Analyzed:
{chr(10).join(findings_summary)}
{user_req_section}

## YOUR TASK
Generate a CONCISE executive summary. This is a HIGH-LEVEL OVERVIEW only.

IMPORTANT: 
- Do NOT include detailed exploit scenarios or step-by-step instructions
- Do NOT list every vulnerability in detail
- The detailed information is in OTHER SECTIONS of the report
- Focus on: Overall posture, key risks, business impact, and top recommendations

Return a JSON object (ONLY valid JSON, nothing else):
```json
{{
    "executive_summary": "## Security Assessment Overview\\n\\nOpening paragraph summarizing overall security posture...\\n\\n## Key Risk Areas\\n\\n**1. Critical Authentication Issues:** Brief description...\\n\\n**2. Injection Vulnerabilities:** Brief description...\\n\\n**3. Sensitive Data Exposure:** Brief description...\\n\\n## Business Impact\\n\\nExplain the potential business impact in 2-3 paragraphs...\\n\\n## Priority Recommendations\\n\\n1. **Immediate Action Required:** Fix critical auth issues\\n2. **Short-term:** Address injection vulnerabilities\\n3. **Medium-term:** Implement security controls\\n\\n## Conclusion\\n\\nClosing paragraph with overall assessment...",
    "overall_risk_level": "Critical",
    "overall_risk_score": 95,
    "risk_justification": "This risk level is assigned because the application has {severity_counts['Critical']} critical and {severity_counts['High']} high severity vulnerabilities that can be exploited for unauthorized access. The combination of authentication weaknesses and injection flaws creates multiple attack paths."
}}
```

FORMATTING REQUIREMENTS:
- Use \\n for newlines in JSON strings
- Use ## for main section headers
- Use **bold** for emphasis and numbered points
- Keep it to 500-700 words (NOT 800+, this is an overview)
- Do NOT include "Detailed Exploit Scenarios" section - that's handled separately
- Do NOT include step-by-step attack instructions - those are in other sections

Generate ONLY the JSON object, nothing else."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.6,
                max_output_tokens=16384,
            ),
        )
        result = _parse_ai_response(response.text)
        if result and result.get("executive_summary"):
            return result
        # Fallback if parsing fails
        logger.warning("Executive summary agent returned invalid response, using raw text")
        return {
            "executive_summary": response.text[:5000],
            "overall_risk_level": "High",
            "overall_risk_score": 85,
            "risk_justification": "See executive summary for details."
        }
    except Exception as e:
        logger.error(f"Agent executive_summary failed: {e}")
        return {}


async def _agent_poc_scripts(
    genai_client,
    aggregated_data: Dict[str, Any],
    data_counts: Dict[str, int],
    user_requirements: str = "",
) -> List[Dict[str, Any]]:
    """Agent 2: Generate detailed PoC scripts for each critical/high vulnerability."""
    from google.genai import types
    
    # Extract exploit scenarios with their existing PoC scripts
    exploit_scenarios = []
    for scan in aggregated_data.get("security_scans", []):
        for es in scan.get("exploit_scenarios", []):
            exploit_scenarios.append({
                "title": es.get("title"),
                "description": es.get("description", "")[:300],
                "severity": es.get("severity"),
                "existing_poc": es.get("poc_scripts", {}),
            })
    
    # Add user requirements section if provided
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
The tester has specifically requested:
{user_requirements}

Tailor your PoC scripts to address these specific needs.
"""
    
    prompt = f"""You are an expert penetration tester creating WORKING PROOF-OF-CONCEPT SCRIPTS.

## EXPLOIT SCENARIOS (with existing PoC hints)
{json.dumps(exploit_scenarios[:7], indent=2)}
{user_req_section}

## YOUR TASK
Create COMPLETE, EXECUTABLE Python scripts for each exploit scenario.

IMPORTANT: Return ONLY a valid JSON array. No markdown, no explanation, just JSON.

[
  {{
    "vulnerability_name": "SQL Injection Authentication Bypass",
    "language": "python",
    "description": "Exploits SQL injection to bypass login and extract data",
    "usage_instructions": "python sqli_exploit.py http://target.com/login",
    "script_code": "#!/usr/bin/env python3\\n# SQL Injection PoC Script\\nimport requests\\nimport sys\\n\\ndef exploit_sqli(target_url):\\n    # Payload to bypass authentication\\n    payload = {{\\n        'username': \\\"admin' OR '1'='1' --\\\",\\n        'password': 'anything'\\n    }}\\n    \\n    print(f'[*] Targeting: {{target_url}}')\\n    print(f'[*] Payload: {{payload}}')\\n    \\n    try:\\n        response = requests.post(target_url, data=payload)\\n        if 'Welcome' in response.text or response.status_code == 200:\\n            print('[+] SUCCESS! Authentication bypassed!')\\n            return True\\n        else:\\n            print('[-] Exploit failed')\\n            return False\\n    except Exception as e:\\n        print(f'[-] Error: {{e}}')\\n        return False\\n\\nif __name__ == '__main__':\\n    if len(sys.argv) < 2:\\n        print('Usage: python sqli_exploit.py <target_url>')\\n        sys.exit(1)\\n    exploit_sqli(sys.argv[1])",
    "expected_output": "[+] SUCCESS! Authentication bypassed!",
    "customization_notes": "Modify payload for different SQL dialects"
  }}
]

Generate AT LEAST 5 complete PoC scripts. Return ONLY the JSON array."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=32768,
            ),
        )
        
        result = _parse_ai_response(response.text)
        if isinstance(result, list) and len(result) > 0:
            logger.info(f"PoC scripts agent returned {len(result)} scripts")
            return result
        elif isinstance(result, dict) and result.get("poc_scripts"):
            return result.get("poc_scripts", [])
        else:
            logger.warning(f"PoC scripts agent returned unexpected format: {type(result)}")
            return []
    except Exception as e:
        logger.error(f"Agent poc_scripts failed: {e}")
        return []


async def _agent_attack_guides(
    genai_client,
    aggregated_data: Dict[str, Any],
    data_counts: Dict[str, int],
    user_requirements: str = "",
) -> List[Dict[str, Any]]:
    """Agent 3: Generate step-by-step beginner attack guides."""
    from google.genai import types
    
    # Extract exploit scenarios
    exploit_scenarios = []
    for scan in aggregated_data.get("security_scans", []):
        for es in scan.get("exploit_scenarios", []):
            exploit_scenarios.append({
                "title": es.get("title"),
                "description": es.get("description", "")[:200],
                "severity": es.get("severity"),
            })
    
    # Add user requirements section if provided
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
The tester has specifically requested:
{user_requirements}

Focus your attack guides on these specific areas/techniques.
"""
    
    prompt = f"""You are a cybersecurity instructor creating BEGINNER-FRIENDLY attack guides.

## EXPLOIT SCENARIOS
{json.dumps(exploit_scenarios[:7], indent=2)}
{user_req_section}

## YOUR TASK
Create step-by-step guides for complete beginners.

IMPORTANT: Return ONLY a valid JSON array. No markdown, no explanation.

[
  {{
    "attack_name": "SQL Injection Authentication Bypass",
    "difficulty_level": "Beginner",
    "estimated_time": "15-20 minutes",
    "prerequisites": ["Web browser", "Basic understanding of login forms"],
    "tools_needed": [
      {{"tool": "Web browser", "installation": "Already installed", "purpose": "To access the target website"}},
      {{"tool": "Burp Suite (optional)", "installation": "Download from portswigger.net", "purpose": "To intercept and modify requests"}}
    ],
    "step_by_step_guide": [
      {{"step_number": 1, "title": "Navigate to the login page", "explanation": "Open your browser and go to the target application's login page", "command_or_action": "http://target.com/login", "expected_output": "You see a login form", "troubleshooting": "Make sure the server is running"}},
      {{"step_number": 2, "title": "Test for SQL injection", "explanation": "Enter a single quote in the username field to test", "command_or_action": "Enter: admin'", "expected_output": "Error message or different behavior", "troubleshooting": "Try password field if username doesn't work"}},
      {{"step_number": 3, "title": "Craft the bypass payload", "explanation": "Use a payload that always evaluates to true", "command_or_action": "Username: admin' OR '1'='1' --", "expected_output": "The query becomes true", "troubleshooting": "Try different quote styles"}},
      {{"step_number": 4, "title": "Submit the form", "explanation": "Click the login button", "command_or_action": "Click Login", "expected_output": "You should be logged in as admin", "troubleshooting": "Try with any password"}},
      {{"step_number": 5, "title": "Verify access", "explanation": "Check if you have admin privileges", "command_or_action": "Navigate to admin panel", "expected_output": "Access to admin features", "troubleshooting": "Look for admin links"}}
    ],
    "success_indicators": ["Logged in without valid password", "Access to admin panel"],
    "what_you_can_do_after": "Extract database contents, modify data, access other accounts"
  }}
]

Generate AT LEAST 5 complete attack guides. Return ONLY the JSON array."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=32768,
            ),
        )
        result = _parse_ai_response(response.text)
        if isinstance(result, list) and len(result) > 0:
            logger.info(f"Attack guides agent returned {len(result)} guides")
            return result
        elif isinstance(result, dict) and result.get("beginner_attack_guide"):
            return result.get("beginner_attack_guide", [])
        else:
            logger.warning(f"Attack guides agent returned unexpected format: {type(result)}")
            return []
    except Exception as e:
        logger.error(f"Agent attack_guides failed: {e}")
        return []


async def _agent_prioritized_vulns(
    genai_client,
    aggregated_data: Dict[str, Any],
    data_counts: Dict[str, int],
    user_requirements: str = "",
) -> List[Dict[str, Any]]:
    """Agent 4: Generate prioritized vulnerability list with detailed exploitation steps."""
    from google.genai import types
    
    # Get findings grouped by severity
    critical_findings = []
    high_findings = []
    for scan in aggregated_data.get("security_scans", []):
        for f in scan.get("findings", []):
            finding_data = {
                "type": f.get("type"),
                "summary": f.get("summary", "")[:200],
                "file_path": f.get("file_path"),
            }
            if f.get("severity", "").lower() == "critical":
                critical_findings.append(finding_data)
            elif f.get("severity", "").lower() == "high":
                high_findings.append(finding_data)
    
    # Add user requirements section if provided
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
The client has specifically requested:
{user_requirements}

Consider these requirements when prioritizing vulnerabilities and detailing exploitation.
"""
    
    prompt = f"""You are creating a PRIORITIZED vulnerability list with DETAILED information.

## CRITICAL FINDINGS ({len(critical_findings)} total)
{json.dumps(critical_findings[:15], indent=2)}

## HIGH FINDINGS ({len(high_findings)} total)
{json.dumps(high_findings[:15], indent=2)}
{user_req_section}
## YOUR TASK
Create a ranked list of vulnerabilities with COMPLETE details for each.

IMPORTANT: Return ONLY a valid JSON array. No markdown wrapping.

[
  {{
    "rank": 1,
    "title": "SQL Injection in Authentication",
    "severity": "Critical",
    "cvss_estimate": "9.8",
    "exploitability": "Easy",
    "impact": "Complete database compromise. Attacker can bypass authentication, extract all user data, passwords, and sensitive information. Can modify or delete records.",
    "source": "SAST Scan",
    "affected_component": "/login.php line 15",
    "exploitation_steps": [
      "Step 1: Navigate to the login page at /login.php",
      "Step 2: Enter username: admin' OR '1'='1' --",
      "Step 3: Enter any password",
      "Step 4: Submit the form",
      "Step 5: Observe successful login as admin without valid credentials"
    ],
    "poc_available": "Yes",
    "remediation_priority": "Immediate",
    "remediation_steps": [
      "Use parameterized queries/prepared statements",
      "Implement input validation",
      "Apply least privilege database permissions"
    ],
    "references": ["CWE-89", "OWASP SQL Injection"]
  }},
  {{
    "rank": 2,
    "title": "OS Command Injection",
    "severity": "Critical",
    "cvss_estimate": "9.8",
    "exploitability": "Easy",
    "impact": "Remote code execution on the server. Attacker can execute arbitrary system commands, access files, install backdoors.",
    "source": "SAST Scan",
    "affected_component": "/exec.php line 8",
    "exploitation_steps": [
      "Step 1: Find the command execution feature",
      "Step 2: Enter: 127.0.0.1; whoami",
      "Step 3: Observe command output in response",
      "Step 4: Escalate: 127.0.0.1; cat /etc/passwd",
      "Step 5: Establish reverse shell if needed"
    ],
    "poc_available": "Yes",
    "remediation_priority": "Immediate",
    "remediation_steps": [
      "Avoid shell_exec, system, exec functions",
      "Use allowlists for permitted commands",
      "Sanitize all user input"
    ],
    "references": ["CWE-78", "OWASP Command Injection"]
  }}
]

Generate AT LEAST 10 prioritized vulnerabilities with COMPLETE details. Return ONLY the JSON array."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.6,
                max_output_tokens=32768,
            ),
        )
        result = _parse_ai_response(response.text)
        if isinstance(result, list) and len(result) > 0:
            logger.info(f"Prioritized vulns agent returned {len(result)} items")
            return result
        elif isinstance(result, dict) and result.get("prioritized_vulnerabilities"):
            return result.get("prioritized_vulnerabilities", [])
        else:
            logger.warning(f"Prioritized vulns agent returned unexpected format: {type(result)}")
            return []
    except Exception as e:
        logger.error(f"Agent prioritized_vulns failed: {e}")
        return []
    except Exception as e:
        logger.error(f"Agent prioritized_vulns failed: {e}")
        return []


async def _agent_cross_analysis(
    genai_client,
    aggregated_data: Dict[str, Any],
    data_counts: Dict[str, int],
) -> List[Dict[str, Any]]:
    """Agent 5: Generate cross-analysis findings that span multiple scan types."""
    from google.genai import types
    
    # Summarize data sources with actual counts
    sources_summary = {
        "security_scans": len(aggregated_data.get("security_scans", [])),
        "network_reports": len(aggregated_data.get("network_reports", [])),
        "ssl_scans": len(aggregated_data.get("ssl_scans", [])),
        "dns_scans": len(aggregated_data.get("dns_scans", [])),
        "traceroute_scans": len(aggregated_data.get("traceroute_scans", [])),
        "re_reports": len(aggregated_data.get("re_reports", [])),
        "fuzzing_sessions": len(aggregated_data.get("fuzzing_sessions", [])),
    }
    
    # Get key findings from ALL sources with more context
    key_findings = []
    
    # Security scan findings and exploits
    for scan in aggregated_data.get("security_scans", []):
        for f in scan.get("findings", [])[:15]:
            sev = f.get('severity', 'unknown').upper()
            key_findings.append(f"[SAST/{sev}] {f.get('type')}: {f.get('summary', '')[:150]} | File: {f.get('file_path', 'N/A')}")
        for es in scan.get("exploit_scenarios", []):
            key_findings.append(f"[EXPLOIT/{es.get('severity', 'unknown').upper()}] {es.get('title')}: {es.get('narrative', '')[:200]}")
        # Entry points for correlation
        for ep in scan.get("identified_entry_points", [])[:10]:
            auth = "NO_AUTH" if not ep.get('auth', True) else "AUTH"
            key_findings.append(f"[ENTRY_POINT/{auth}] {ep.get('method', 'GET')} {ep.get('route', '/')} - Risk: {ep.get('risk', 'unknown')}")
    
    # Network analysis findings
    for nr in aggregated_data.get("network_reports", []):
        findings_data = nr.get("findings_data", [])
        if isinstance(findings_data, list):
            for f in findings_data[:10]:
                if isinstance(f, dict):
                    key_findings.append(f"[NETWORK/{f.get('severity', 'INFO').upper()}] {f.get('type', 'finding')}: {f.get('description', '')[:150]}")
        # AI insights
        ai_report = nr.get("ai_report", {})
        if isinstance(ai_report, dict):
            for kf in ai_report.get("key_findings", [])[:5]:
                if isinstance(kf, dict):
                    key_findings.append(f"[PCAP_AI] {kf.get('title', 'Finding')}: {kf.get('description', '')[:150]}")
    
    # SSL/TLS findings for correlation
    for ssl in aggregated_data.get("ssl_scans", []):
        for sf in ssl.get("ssl_findings", [])[:5]:
            for v in sf.get("vulnerabilities", [])[:5]:
                if isinstance(v, dict):
                    key_findings.append(f"[SSL/CRITICAL] {v.get('name', 'SSL Vuln')}: {v.get('description', '')[:100]} | Host: {sf.get('host', 'unknown')}")
            for f in sf.get("findings", [])[:5]:
                if isinstance(f, dict):
                    key_findings.append(f"[SSL/{f.get('severity', 'INFO').upper()}] {f.get('title', 'Finding')}: {f.get('description', '')[:100]}")
            # Cert issues
            cert = sf.get("certificate", {})
            if cert.get("is_expired"):
                key_findings.append(f"[SSL/HIGH] Expired certificate on {sf.get('host', 'unknown')}:{sf.get('port', 443)}")
            if cert.get("is_self_signed"):
                key_findings.append(f"[SSL/MEDIUM] Self-signed certificate on {sf.get('host', 'unknown')}:{sf.get('port', 443)}")
    
    # DNS findings for infrastructure correlation
    for dns in aggregated_data.get("dns_scans", []):
        domain = dns.get("domain", "unknown")
        if dns.get("zone_transfer_possible"):
            key_findings.append(f"[DNS/CRITICAL] Zone transfer allowed on {domain} - exposes all DNS records")
        for tr in dns.get("takeover_risks", [])[:5]:
            if isinstance(tr, dict):
                key_findings.append(f"[DNS/HIGH] Subdomain takeover risk: {tr.get('subdomain', '')} -> {tr.get('cname_target', '')} ({tr.get('provider', 'unknown')})")
        for dc in dns.get("dangling_cnames", [])[:3]:
            if isinstance(dc, dict):
                key_findings.append(f"[DNS/MEDIUM] Dangling CNAME: {dc.get('subdomain', '')} -> {dc.get('cname', '')}")
        security = dns.get("security", {})
        if security and not security.get("has_spf"):
            key_findings.append(f"[DNS/HIGH] No SPF record for {domain} - email spoofing possible")
        if security and not security.get("has_dmarc"):
            key_findings.append(f"[DNS/MEDIUM] No DMARC record for {domain} - email not authenticated")
    
    # Traceroute for network path correlation
    for tr in aggregated_data.get("traceroute_scans", []):
        if not tr.get("completed"):
            key_findings.append(f"[TRACEROUTE/HIGH] Target {tr.get('target', 'unknown')} unreachable - possible filtering")
        for f in tr.get("findings", [])[:5]:
            if isinstance(f, dict):
                key_findings.append(f"[TRACEROUTE/{f.get('severity', 'INFO').upper()}] {f.get('title', 'Finding')}: {f.get('description', '')[:100]}")
    
    # RE findings for binary/app correlation
    for re in aggregated_data.get("re_reports", []):
        filename = re.get("filename", "unknown")
        for issue in re.get("security_issues", [])[:10]:
            if isinstance(issue, dict):
                key_findings.append(f"[RE/{issue.get('severity', 'INFO').upper()}] {issue.get('type', 'Issue')} in {filename}: {issue.get('description', '')[:100]}")
        for sd in re.get("sensitive_data_findings", [])[:5]:
            if isinstance(sd, dict):
                key_findings.append(f"[RE/HIGH] Sensitive data in {filename}: {sd.get('type', 'data')} found at {sd.get('location', 'unknown')}")
    
    # Fuzzing findings for runtime correlation
    for fs in aggregated_data.get("fuzzing_sessions", []):
        target = fs.get("target_url", "unknown")
        for f in fs.get("findings", [])[:10]:
            if isinstance(f, dict):
                key_findings.append(f"[FUZZING/{f.get('severity', 'INFO').upper()}] {f.get('type', 'Finding')} at {target}: {f.get('description', '')[:100]}")

    prompt = f"""You are an expert security analyst correlating findings across multiple security analysis domains.

## DATA SOURCES AVAILABLE
{json.dumps(sources_summary, indent=2)}

## ALL FINDINGS FROM ALL SCAN TYPES (with severity and context)
{chr(10).join(key_findings[:80])}

## YOUR TASK
Identify CROSS-ANALYSIS FINDINGS where vulnerabilities from DIFFERENT scan types COMBINE to create larger security risks.

**CORRELATION PATTERNS TO LOOK FOR:**
1. SAST + Network: Code vulnerability + exposed service = direct exploitation path
2. SSL + SAST: Weak crypto in code + SSL issues = cryptographic attack chain
3. DNS + Network: Subdomain takeover + open ports = infrastructure compromise
4. RE + SAST: Binary hardcoded creds + source code creds = credential reuse attack
5. Fuzzing + SAST: Runtime crash + buffer overflow in code = exploitable memory corruption
6. PCAP + SAST: Plaintext credentials in traffic + weak auth code = auth bypass chain
7. SSL + DNS: Expired cert + dangling CNAME = phishing/MITM attack vector

**IMPORTANT**: Each finding must reference AT LEAST 2 different scan types to qualify as cross-analysis.

Return a JSON array:
```json
[
    {{
        "title": "SQL Injection + Exposed Database Port = Full Compromise",
        "description": "The SAST scan identified SQL injection in login.php at line 45, while network analysis revealed MySQL port 3306 is exposed to the internet. Combined, an attacker can exploit the SQL injection to extract credentials, then directly connect to the exposed database for full data exfiltration. This vulnerability chain requires no authentication and provides complete database access.",
        "severity": "Critical",
        "sources": ["security_scan", "network_report"],
        "source_details": [
            {{"type": "security_scan", "finding": "SQL Injection in login.php:45", "reference": "SAST Finding #3"}},
            {{"type": "network_report", "finding": "MySQL 3306 exposed", "reference": "PCAP Analysis"}}
        ],
        "exploitability_score": 0.95,
        "exploit_narrative": "An attacker would first identify the login endpoint. Using sqlmap, they inject the username field with: admin' UNION SELECT password FROM users--. After extracting the database credentials, they connect directly to the exposed MySQL port using: mysql -h target.com -u admin -p. From there, they have full database access to exfiltrate all user data, modify records, or drop tables.",
        "exploit_guidance": "Step 1: Test for SQL injection: curl -d 'user=admin'\"' target/login\\nStep 2: Extract data: sqlmap -u 'target/login' --data='user=test' --dump\\nStep 3: Connect to exposed DB: mysql -h target -u root -p\\nStep 4: Exfiltrate: SELECT * FROM users;",
        "poc_available": true,
        "remediation": "1) Use parameterized queries in login.php\\n2) Firewall MySQL port 3306\\n3) Implement WAF rules for SQL injection\\n4) Add database connection encryption"
    }}
]
```

Generate AT LEAST {max(data_counts.get('min_cross_findings', 5), 5)} cross-analysis findings. Each must:
- Reference 2+ different scan types
- Have 150+ word description
- Include specific exploit_narrative with actual attack steps
- Include specific exploit_guidance with commands"""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=32768,
            ),
        )
        result = _parse_ai_response(response.text)
        return result if isinstance(result, list) else result.get("cross_analysis_findings", [])
    except Exception as e:
        logger.error(f"Agent cross_analysis failed: {e}")
        return []


async def _agent_attack_surface_diagram(
    genai_client,
    aggregated_data: Dict[str, Any],
) -> str:
    """Agent 6: Generate a professional Mermaid attack surface diagram with icons and styling."""
    from google.genai import types
    
    # Extract vulnerability types and components
    vuln_types = set()
    components = set()
    for scan in aggregated_data.get("security_scans", []):
        for f in scan.get("findings", []):
            vuln_types.add(f.get("type", "Unknown")[:30])
            if f.get("file_path"):
                path = f.get("file_path", "")
                if "/" in path:
                    component = path.split("/")[-1].replace(".php", "").replace(".py", "").replace(".js", "")
                    if len(component) > 2:
                        components.add(component[:20])
        for es in scan.get("exploit_scenarios", []):
            vuln_types.add(es.get("title", "")[:30])
    
    vuln_list = list(vuln_types)[:10]
    component_list = list(components)[:8]
    
    prompt = f"""Create a professional Mermaid attack surface diagram.

## VULNERABILITIES FOUND
{json.dumps(vuln_list, indent=2)}

## COMPONENTS
{json.dumps(component_list, indent=2)}

## OUTPUT REQUIREMENTS
Output ONLY valid Mermaid code. No explanations. Start immediately with flowchart TB.

Use this exact structure with icons and styling:

flowchart TB
    subgraph Attacker["🎭 ATTACKER"]
        ATK[External Threat]
    end
    
    subgraph Entry["📍 ENTRY POINTS"]
        WEB[Web Application]
        API[API Endpoints]
        FORM[Input Forms]
    end
    
    subgraph Vulns["⚠️ VULNERABILITIES"]
        SQLi[SQL Injection]
        XSS[Cross-Site Scripting]
        CMDi[Command Injection]
        SSRF[Server-Side Request Forgery]
        LFI[Local File Inclusion]
        CREDS[Hardcoded Credentials]
    end
    
    subgraph Impact["🎯 IMPACT"]
        DB[(Database Compromise)]
        RCE[Remote Code Execution]
        DATA[Data Exfiltration]
        PRIV[Privilege Escalation]
    end
    
    ATK --> WEB
    ATK --> API
    ATK --> FORM
    
    WEB --> SQLi
    WEB --> XSS
    API --> CMDi
    FORM --> SQLi
    FORM --> XSS
    
    SQLi --> DB
    SQLi --> DATA
    CMDi --> RCE
    XSS --> DATA
    SSRF --> DATA
    LFI --> RCE
    CREDS --> PRIV
    
    classDef critical fill:#dc2626,color:#fff
    classDef high fill:#ea580c,color:#fff
    classDef medium fill:#ca8a04,color:#000
    classDef attacker fill:#7c3aed,color:#fff
    classDef impact fill:#1e40af,color:#fff
    
    class ATK attacker
    class SQLi,CMDi,RCE critical
    class XSS,SSRF,LFI,CREDS high
    class DB,DATA,PRIV impact

Generate NOW. Output ONLY the Mermaid code starting with 'flowchart TB'."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.2,  # Very low temp for predictable syntax
                max_output_tokens=4096,
            ),
        )
        
        diagram = response.text.strip()
        
        # Clean up the response - extract just the mermaid code
        if "```mermaid" in diagram:
            start = diagram.find("```mermaid") + 10
            end = diagram.find("```", start)
            if end > start:
                diagram = diagram[start:end].strip()
        elif "```" in diagram:
            start = diagram.find("```") + 3
            end = diagram.find("```", start)
            if end > start:
                diagram = diagram[start:end].strip()
        
        # Ensure it starts correctly
        if not diagram.startswith("flowchart") and not diagram.startswith("graph"):
            diagram = "flowchart TB\n" + diagram
        
        logger.info(f"Attack surface diagram generated: {len(diagram)} chars")
        return diagram
    except Exception as e:
        logger.error(f"Agent attack_surface_diagram failed: {e}")
        # Return a professional fallback diagram
        return """flowchart TB
    subgraph Attacker["🎭 ATTACKER"]
        ATK[External Threat]
    end
    
    subgraph Entry["📍 ENTRY POINTS"]
        WEB[Web Application]
        API[API Endpoints]
    end
    
    subgraph Vulns["⚠️ VULNERABILITIES"]
        SQLi[SQL Injection]
        XSS[Cross-Site Scripting]
        CMDi[Command Injection]
    end
    
    subgraph Impact["🎯 IMPACT"]
        DB[(Database)]
        RCE[Code Execution]
    end
    
    ATK --> WEB
    ATK --> API
    WEB --> SQLi
    WEB --> XSS
    API --> CMDi
    SQLi --> DB
    CMDi --> RCE
    
    classDef critical fill:#dc2626,color:#fff
    classDef attacker fill:#7c3aed,color:#fff
    
    class ATK attacker
    class SQLi,CMDi critical"""


async def _agent_attack_chains(
    genai_client,
    aggregated_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Agent 7: Generate attack chain scenarios."""
    from google.genai import types
    
    # Get exploit scenarios
    exploit_scenarios = []
    for scan in aggregated_data.get("security_scans", []):
        for es in scan.get("exploit_scenarios", []):
            exploit_scenarios.append({
                "title": es.get("title"),
                "description": es.get("description")[:200],
            })
    
    prompt = f"""You are mapping attack chains that combine vulnerabilities for maximum impact.

## AVAILABLE EXPLOITS
{json.dumps(exploit_scenarios, indent=2)}

## YOUR TASK
Create ATTACK CHAINS showing how vulnerabilities can be combined.

Return a JSON array:
```json
[
    {{
        "chain_name": "Web Shell to Full System Compromise",
        "entry_point": "Command Injection in ping module",
        "steps": [
            {{"step": 1, "action": "Inject command via ping parameter", "vulnerability_used": "OS Command Injection", "outcome": "Code execution"}},
            {{"step": 2, "action": "Download reverse shell script", "vulnerability_used": "Outbound network access", "outcome": "Persistent access"}},
            {{"step": 3, "action": "Escalate privileges using sudo misconfiguration", "vulnerability_used": "Privilege Escalation", "outcome": "Root access"}}
        ],
        "final_impact": "Complete system compromise with root access",
        "likelihood": "High"
    }}
]
```

Generate AT LEAST 3 attack chains NOW."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=16384,
            ),
        )
        result = _parse_ai_response(response.text)
        return result if isinstance(result, list) else result.get("attack_chains", [])
    except Exception as e:
        logger.error(f"Agent attack_chains failed: {e}")
        return []


async def _agent_exploit_development(
    genai_client,
    aggregated_data: Dict[str, Any],
    data_counts: Dict[str, int],
) -> List[Dict[str, Any]]:
    """Agent 8: Generate exploit development opportunities."""
    from google.genai import types
    
    # Get exploit scenarios
    exploit_scenarios = []
    for scan in aggregated_data.get("security_scans", []):
        for es in scan.get("exploit_scenarios", []):
            exploit_scenarios.append({
                "title": es.get("title"),
                "description": es.get("description"),
                "severity": es.get("severity"),
                "poc_scripts": es.get("poc_scripts", {}),
            })
    
    prompt = f"""You are identifying EXPLOIT DEVELOPMENT OPPORTUNITIES for security researchers.

## EXPLOIT SCENARIOS
{json.dumps(exploit_scenarios, indent=2)}

## YOUR TASK
For each exploit scenario, provide detailed development guidance.

Return a JSON array:
```json
[
    {{
        "title": "Automated SQL Injection Tool Development",
        "description": "Develop a custom SQL injection exploitation tool tailored for this application's specific query patterns...",
        "vulnerability_chain": ["SQL Injection", "Weak Session Management"],
        "attack_vector": "Network",
        "complexity": "Low",
        "impact": "Full database access, credential theft, data exfiltration",
        "prerequisites": ["Python 3", "requests library", "Network access to target"],
        "poc_guidance": "Step 1: Identify injection points\\nStep 2: Determine database type\\nStep 3: Extract schema...",
        "full_poc_script": "#!/usr/bin/env python3\\nimport requests\\n# Full script here...",
        "testing_notes": "Test in isolated environment first",
        "detection_evasion": "Use time-based injection to avoid WAF detection"
    }}
]
```

Generate AT LEAST {max(data_counts.get('total_exploit_scenarios', 5), 5)} exploit development areas NOW."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=24576,
            ),
        )
        result = _parse_ai_response(response.text)
        return result if isinstance(result, list) else result.get("exploit_development_areas", [])
    except Exception as e:
        logger.error(f"Agent exploit_development failed: {e}")
        return []


async def _agent_source_code_findings(
    genai_client,
    aggregated_data: Dict[str, Any],
    relevant_source_code: List[Dict[str, Any]],
    data_counts: Dict[str, int],
) -> List[Dict[str, Any]]:
    """Agent 9: Analyze source code and generate detailed findings with exploitation and remediation."""
    from google.genai import types
    
    if not relevant_source_code:
        logger.info("No relevant source code to analyze")
        return []
    
    # Get findings context to correlate with source code
    findings_context = []
    for scan in aggregated_data.get("security_scans", []):
        for f in scan.get("findings", [])[:20]:
            findings_context.append({
                "type": f.get("type"),
                "severity": f.get("severity"),
                "file_path": f.get("file_path"),
                "summary": f.get("summary", "")[:200],
            })
    
    # Build source code snippets for analysis
    code_snippets = []
    for code in relevant_source_code[:30]:  # Limit to avoid token overflow
        code_snippets.append({
            "file_path": code.get("file_path", "unknown"),
            "language": code.get("language", ""),
            "lines": f"{code.get('start_line', '?')}-{code.get('end_line', '?')}",
            "matched_term": code.get("matched_term", ""),
            "code": code.get("code", "")[:2000],
        })
    
    prompt = f"""You are a security code auditor performing a DEEP DIVE analysis of source code.

## SCAN FINDINGS TO CORRELATE WITH
{json.dumps(findings_context[:20], indent=2)}

## SOURCE CODE SNIPPETS TO ANALYZE
{json.dumps(code_snippets, indent=2)}

## YOUR TASK
Analyze each source code snippet for security vulnerabilities. For each issue found:
1. Identify the vulnerability type
2. Explain exactly what makes it vulnerable
3. Show how it can be exploited
4. Provide the secure code fix

Return a JSON array:
```json
[
    {{
        "file_path": "/path/to/file.py",
        "issue_type": "SQL Injection",
        "severity": "Critical",
        "description": "The query is constructed by directly concatenating user input without sanitization. The 'username' parameter from the request is inserted directly into the SQL string, allowing an attacker to inject arbitrary SQL commands.",
        "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE name = {{username}}')",
        "line_numbers": "45-47",
        "exploitation_example": "An attacker can send username: admin' OR '1'='1' -- to bypass authentication or username: admin'; DROP TABLE users; -- to delete data",
        "related_scan_findings": ["SQL Injection in authentication module", "SAST Finding #3"],
        "secure_code_fix": "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
        "remediation": "1) Use parameterized queries with placeholders\\n2) Implement input validation\\n3) Apply least privilege to database user\\n4) Use an ORM like SQLAlchemy"
    }}
]
```

Analyze ALL provided code snippets. Generate findings for each vulnerability you identify.
Focus on: SQL injection, command injection, XSS, path traversal, hardcoded secrets, insecure crypto, auth bypass.

IMPORTANT: Each finding must have:
- Complete exploitation_example showing exactly how to exploit it
- Complete secure_code_fix showing the fixed code
- Detailed remediation steps"""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                temperature=0.6,
                max_output_tokens=32768,
            ),
        )
        result = _parse_ai_response(response.text)
        if isinstance(result, list):
            logger.info(f"Source code findings agent returned {len(result)} findings")
            return result
        elif isinstance(result, dict) and result.get("source_code_findings"):
            return result.get("source_code_findings", [])
        else:
            logger.warning(f"Source code findings agent returned unexpected format: {type(result)}")
            return []
    except Exception as e:
        logger.error(f"Agent source_code_findings failed: {e}")
        return []


def get_combined_analysis_report(db: Session, report_id: int) -> Optional[models.CombinedAnalysisReport]:
    """Get a combined analysis report by ID."""
    return db.query(models.CombinedAnalysisReport).filter(
        models.CombinedAnalysisReport.id == report_id
    ).first()


def list_combined_analysis_reports(
    db: Session,
    project_id: int,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[models.CombinedAnalysisReport], int]:
    """List combined analysis reports for a project."""
    query = db.query(models.CombinedAnalysisReport).filter(
        models.CombinedAnalysisReport.project_id == project_id
    ).order_by(models.CombinedAnalysisReport.created_at.desc())
    
    total = query.count()
    reports = query.offset(offset).limit(limit).all()
    
    return reports, total


def delete_combined_analysis_report(db: Session, report_id: int) -> bool:
    """Delete a combined analysis report."""
    report = db.query(models.CombinedAnalysisReport).filter(
        models.CombinedAnalysisReport.id == report_id
    ).first()
    
    if not report:
        return False
    
    db.delete(report)
    db.commit()
    return True
