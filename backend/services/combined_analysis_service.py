"""
Combined Analysis Service

Aggregates data from Security Scans, Reverse Engineering reports, and Network Analysis
to generate comprehensive cross-analysis reports using Gemini AI.

IMPROVEMENTS (v2):
- Smart context prioritization: Critical/high findings are never truncated
- Two-phase agent communication: Analysis agents inform generation agents
- Structured output validation: Pydantic validation of AI responses
- Enhanced source code search: Semantic pattern matching
"""

import json
import base64
import re
from typing import Dict, List, Optional, Any, Tuple, Set, TypeVar
from datetime import datetime
from dataclasses import dataclass, field
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from pydantic import BaseModel, Field, ValidationError

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
from backend.services.combined_analysis_reasoning import (
    CombinedAnalysisReasoningEngine,
    ReasoningDepth,
)
from backend.services.evidence_framework import EvidenceFramework
from backend.services.contextual_risk_scoring import ContextualRiskScorer
from backend.services.control_bypass_service import ControlBypassService
from backend.services.document_parser_service import DocumentParserService, ParsedDocument

logger = get_logger(__name__)


# ============================================================================
# IMPROVEMENT: Finding Corroboration Detection
# Detects when findings appear across multiple sources = HIGHER CONFIDENCE
# ============================================================================

@dataclass
class CorroboratedFinding:
    """A finding that appears across multiple scan sources."""
    fingerprint: str  # Normalized identifier for matching
    title: str
    finding_type: str
    severity: str
    sources: List[str] = field(default_factory=list)  # e.g., ["SAST", "DAST", "Fuzzing"]
    source_details: List[Dict[str, Any]] = field(default_factory=list)
    confidence_level: str = "Low"  # Low (1 source), Medium (2), High (3+)
    evidence_count: int = 1
    
    def add_source(self, source: str, details: Dict[str, Any]):
        """Add a corroborating source."""
        if source not in self.sources:
            self.sources.append(source)
            self.source_details.append(details)
            self.evidence_count = len(self.sources)
            # Update confidence based on source count
            if self.evidence_count >= 3:
                self.confidence_level = "High"
            elif self.evidence_count == 2:
                self.confidence_level = "Medium"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "sources": self.sources,
            "source_details": self.source_details,
            "confidence_level": self.confidence_level,
            "evidence_count": self.evidence_count,
            "corroborated": self.evidence_count > 1,
        }


def _generate_finding_fingerprint(finding: Dict[str, Any], source_type: str) -> str:
    """
    Generate a normalized fingerprint for finding deduplication/corroboration.
    Uses fuzzy matching on key attributes.
    """
    # Normalize finding type
    finding_type = str(finding.get("type", finding.get("name", finding.get("title", "")))).lower()
    finding_type = re.sub(r'[^a-z0-9]', '', finding_type)
    
    # Normalize location (file path, URL, endpoint)
    location = ""
    for key in ["file_path", "url", "endpoint", "path", "route", "affected_component", "host"]:
        if finding.get(key):
            location = str(finding[key]).lower()
            # Extract just filename or endpoint
            location = location.split("/")[-1].split("\\")[-1].split("?")[0]
            location = re.sub(r'[^a-z0-9]', '', location)
            break
    
    # Combine into fingerprint
    fingerprint = f"{finding_type}:{location}" if location else finding_type
    return fingerprint


def _detect_corroborated_findings(aggregated_data: Dict[str, Any]) -> List[CorroboratedFinding]:
    """
    Detect findings that appear across multiple scan sources.
    These have HIGHER CONFIDENCE and should be highlighted in the report.
    """
    corroboration_map: Dict[str, CorroboratedFinding] = {}
    
    # Process security scan (SAST) findings
    for scan in aggregated_data.get("security_scans", []):
        for finding in scan.get("findings", []):
            fp = _generate_finding_fingerprint(finding, "sast")
            if fp not in corroboration_map:
                corroboration_map[fp] = CorroboratedFinding(
                    fingerprint=fp,
                    title=finding.get("type", "Unknown Finding"),
                    finding_type=finding.get("type", "unknown"),
                    severity=finding.get("severity", "Medium"),
                )
            corroboration_map[fp].add_source("SAST", {
                "scan_type": "security_scan",
                "file_path": finding.get("file_path"),
                "summary": finding.get("summary", "")[:200],
            })
    
    # Process dynamic scan (DAST) findings
    for scan in aggregated_data.get("dynamic_scans", []):
        for alert in scan.get("alerts", []):
            fp = _generate_finding_fingerprint(alert, "dast")
            if fp not in corroboration_map:
                corroboration_map[fp] = CorroboratedFinding(
                    fingerprint=fp,
                    title=alert.get("name", "Unknown Alert"),
                    finding_type=alert.get("name", "unknown"),
                    severity=alert.get("risk", "Medium"),
                )
            corroboration_map[fp].add_source("DAST", {
                "scan_type": "dynamic_scan",
                "url": alert.get("url"),
                "description": alert.get("description", "")[:200],
            })
    
    # Process API fuzzing findings
    for session in aggregated_data.get("fuzzing_sessions", []):
        for finding in session.get("findings", []):
            if isinstance(finding, dict):
                fp = _generate_finding_fingerprint(finding, "fuzzing")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=finding.get("type", "Fuzzing Finding"),
                        finding_type=finding.get("type", "unknown"),
                        severity=finding.get("severity", "Medium"),
                    )
                corroboration_map[fp].add_source("API Fuzzing", {
                    "scan_type": "fuzzing_session",
                    "endpoint": finding.get("endpoint"),
                    "description": finding.get("description", "")[:200],
                })
    
    # Process agentic fuzzer findings
    for report in aggregated_data.get("agentic_fuzzer_reports", []):
        for finding in report.get("findings", []):
            if isinstance(finding, dict):
                fp = _generate_finding_fingerprint(finding, "agentic")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=finding.get("type", "Agentic Finding"),
                        finding_type=finding.get("type", "unknown"),
                        severity=finding.get("severity", "Medium"),
                    )
                corroboration_map[fp].add_source("Agentic Fuzzer", {
                    "scan_type": "agentic_fuzzer",
                    "endpoint": finding.get("endpoint"),
                    "description": finding.get("description", "")[:200],
                })
    
    # Process binary fuzzer findings (crashes indicate potential vulns)
    for session in aggregated_data.get("binary_fuzzer_sessions", []):
        for crash in session.get("crashes", []):
            if isinstance(crash, dict):
                crash_type = crash.get("crash_type", "memory_corruption")
                fp = f"binaryfuzz:{crash_type}"
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=f"Memory Corruption ({crash_type})",
                        finding_type="memory_corruption",
                        severity="Critical",
                    )
                corroboration_map[fp].add_source("Binary Fuzzer", {
                    "scan_type": "binary_fuzzer",
                    "crash_type": crash_type,
                    "binary": session.get("binary_path"),
                })

    # Process fuzzing campaign report findings (AI-analyzed crashes)
    for report in aggregated_data.get("fuzzing_campaign_reports", []):
        for crash in report.get("crashes", []):
            if isinstance(crash, dict):
                crash_type = crash.get("crash_type", "memory_corruption")
                exploitability = crash.get("exploitability", "unknown")
                fp = f"campaign:{crash_type}:{report.get('binary_name', 'unknown')}"
                if fp not in corroboration_map:
                    # Map exploitability to severity
                    if exploitability.lower() == "exploitable":
                        severity = "Critical"
                    elif exploitability.lower() == "probably_exploitable":
                        severity = "High"
                    else:
                        severity = "Medium"
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=f"Binary Vulnerability ({crash_type})",
                        finding_type="binary_vulnerability",
                        severity=severity,
                    )
                corroboration_map[fp].add_source("Agentic Binary Fuzzer", {
                    "scan_type": "fuzzing_campaign_report",
                    "crash_type": crash_type,
                    "exploitability": exploitability,
                    "binary": report.get("binary_name"),
                    "impact": crash.get("impact", ""),
                    "recommendation": crash.get("recommendation", ""),
                })

    # Process RE findings (binary analysis)
    for report in aggregated_data.get("re_reports", []):
        for issue in report.get("security_issues", []):
            if isinstance(issue, dict):
                fp = _generate_finding_fingerprint(issue, "re")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=issue.get("type", "RE Finding"),
                        finding_type=issue.get("type", "unknown"),
                        severity=issue.get("severity", "Medium"),
                    )
                corroboration_map[fp].add_source("Reverse Engineering", {
                    "scan_type": "re_report",
                    "filename": report.get("filename"),
                    "description": issue.get("description", "")[:200],
                })
    
    # Process network findings
    for report in aggregated_data.get("network_reports", []):
        for finding in report.get("findings_data", []) or []:
            if isinstance(finding, dict):
                fp = _generate_finding_fingerprint(finding, "network")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=finding.get("type", "Network Finding"),
                        finding_type=finding.get("type", "unknown"),
                        severity=finding.get("severity", "Medium"),
                    )
                corroboration_map[fp].add_source("Network Analysis", {
                    "scan_type": "network_report",
                    "description": finding.get("description", "")[:200],
                })
    
    # Process SSL findings
    for scan in aggregated_data.get("ssl_scans", []):
        for sf in scan.get("ssl_findings", []):
            for vuln in sf.get("vulnerabilities", []) or []:
                if isinstance(vuln, dict):
                    fp = f"ssl:{vuln.get('name', 'unknown').lower().replace(' ', '')}"
                    if fp not in corroboration_map:
                        corroboration_map[fp] = CorroboratedFinding(
                            fingerprint=fp,
                            title=vuln.get("name", "SSL Vulnerability"),
                            finding_type="ssl_vulnerability",
                            severity="Critical",
                        )
                    corroboration_map[fp].add_source("SSL/TLS Scan", {
                        "scan_type": "ssl_scan",
                        "host": sf.get("host"),
                        "description": vuln.get("description", "")[:200],
                    })
    
    # Process MITM analysis findings
    for report in aggregated_data.get("mitm_analysis_reports", []):
        for finding in report.get("findings", []):
            if isinstance(finding, dict):
                fp = _generate_finding_fingerprint(finding, "mitm")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=finding.get("title", finding.get("category", "MITM Finding")),
                        finding_type=finding.get("category", "unknown"),
                        severity=finding.get("severity", "Medium").capitalize(),
                    )
                corroboration_map[fp].add_source("MITM Traffic Analysis", {
                    "scan_type": "mitm_analysis_report",
                    "category": finding.get("category"),
                    "evidence": finding.get("evidence", "")[:200],
                    "recommendation": finding.get("recommendation", "")[:200],
                })

    # Process Nmap scan findings
    for scan in aggregated_data.get("nmap_scans", []):
        # Process vulnerabilities from AI analysis
        ai_analysis = scan.get("ai_analysis", {})
        if isinstance(ai_analysis, dict):
            for vuln in ai_analysis.get("vulnerabilities", []):
                if isinstance(vuln, dict):
                    fp = _generate_finding_fingerprint(vuln, "nmap")
                    if fp not in corroboration_map:
                        corroboration_map[fp] = CorroboratedFinding(
                            fingerprint=fp,
                            title=vuln.get("name", vuln.get("type", "Nmap Finding")),
                            finding_type=vuln.get("type", "network"),
                            severity=vuln.get("severity", "Medium"),
                        )
                    corroboration_map[fp].add_source("Nmap Scan", {
                        "scan_type": "nmap_scan",
                        "host": vuln.get("host"),
                        "port": vuln.get("port"),
                        "service": vuln.get("service"),
                        "description": vuln.get("description", "")[:200],
                    })

    # Process PCAP analysis findings
    for report in aggregated_data.get("pcap_reports", []):
        for finding in report.get("findings_data", []) or []:
            if isinstance(finding, dict):
                fp = _generate_finding_fingerprint(finding, "pcap")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=finding.get("type", finding.get("title", "PCAP Finding")),
                        finding_type=finding.get("type", "traffic_analysis"),
                        severity=finding.get("severity", "Medium"),
                    )
                corroboration_map[fp].add_source("PCAP Analysis", {
                    "scan_type": "pcap_report",
                    "protocol": finding.get("protocol"),
                    "description": finding.get("description", "")[:200],
                })

    # Process API Tester findings
    for report in aggregated_data.get("api_tester_reports", []):
        for finding in report.get("findings_data", []) or []:
            if isinstance(finding, dict):
                fp = _generate_finding_fingerprint(finding, "api_tester")
                if fp not in corroboration_map:
                    corroboration_map[fp] = CorroboratedFinding(
                        fingerprint=fp,
                        title=finding.get("title", finding.get("category", "API Security Finding")),
                        finding_type=finding.get("category", "api_security"),
                        severity=finding.get("severity", "Medium"),
                    )
                corroboration_map[fp].add_source("API Security Testing", {
                    "scan_type": "api_tester_report",
                    "endpoint": finding.get("endpoint"),
                    "category": finding.get("category"),
                    "description": finding.get("description", "")[:200],
                })

    # Return only corroborated findings (evidence_count > 1), sorted by confidence
    corroborated = [cf for cf in corroboration_map.values() if cf.evidence_count > 1]
    corroborated.sort(key=lambda x: (-x.evidence_count, x.severity.lower() != "critical"))
    
    logger.info(f"Detected {len(corroborated)} corroborated findings from {len(corroboration_map)} unique findings")
    return corroborated


# ============================================================================
# IMPROVEMENT: Token Budget Management
# Estimates token usage and truncates low-priority data first
# ============================================================================

def _estimate_tokens(text: str) -> int:
    """Rough token estimation (avg 4 chars per token for English)."""
    return len(text) // 4


def _estimate_data_tokens(data: Dict[str, Any]) -> int:
    """Estimate tokens for a data structure."""
    return _estimate_tokens(json.dumps(data, default=str))


@dataclass
class TokenBudget:
    """Manages token budget for AI context."""
    max_tokens: int = 90000  # Conservative limit for quality
    reserved_for_prompt: int = 5000
    reserved_for_output: int = 20000
    
    # Allocation percentages for data types
    critical_findings_pct: float = 0.25
    high_findings_pct: float = 0.15
    corroborated_findings_pct: float = 0.10
    source_code_pct: float = 0.15
    supporting_docs_pct: float = 0.30  # 30% - documents are core to combined analysis
    other_findings_pct: float = 0.05
    
    def available_for_data(self) -> int:
        return self.max_tokens - self.reserved_for_prompt - self.reserved_for_output
    
    def allocate(self, data_type: str) -> int:
        """Get token allocation for a data type."""
        available = self.available_for_data()
        allocations = {
            "critical": int(available * self.critical_findings_pct),
            "high": int(available * self.high_findings_pct),
            "corroborated": int(available * self.corroborated_findings_pct),
            "source_code": int(available * self.source_code_pct),
            "supporting_docs": int(available * self.supporting_docs_pct),
            "other": int(available * self.other_findings_pct),
        }
        return allocations.get(data_type, 5000)


def _truncate_to_token_budget(data: List[Dict[str, Any]], max_tokens: int) -> List[Dict[str, Any]]:
    """Truncate a list of findings to fit within token budget."""
    result = []
    current_tokens = 0

    for item in data:
        item_tokens = _estimate_data_tokens(item)
        if current_tokens + item_tokens > max_tokens:
            break
        result.append(item)
        current_tokens += item_tokens

    return result


# ============================================================================
# DYNAMIC CONTEXT BUDGET ALLOCATION
# Allocates context space based on what data sources are present
# ============================================================================

@dataclass
class ContextBudget:
    """
    Dynamic context budget allocation for combined analysis.

    Total agent context budget: ~100K chars (safe for most LLMs)
    Allocates based on:
    - Number and size of documents
    - Complexity of scan types present
    - Priority of data sources
    """
    # Total budget per agent (chars)
    TOTAL_AGENT_BUDGET: int = 100000

    # Base allocations (will be adjusted dynamically)
    documents_budget: int = 15000
    security_scans_budget: int = 20000
    network_budget: int = 10000
    binary_budget: int = 15000
    mitm_budget: int = 12000
    fuzzing_budget: int = 10000
    other_budget: int = 8000

    # Minimum allocations (never go below these)
    MIN_DOCS: int = 5000
    MIN_SCANS: int = 8000
    MIN_NETWORK: int = 3000
    MIN_BINARY: int = 5000
    MIN_MITM: int = 4000
    MIN_FUZZING: int = 3000

    @classmethod
    def calculate_budget(
        cls,
        num_documents: int,
        total_doc_chars: int,
        has_security_scans: bool,
        has_network: bool,
        has_binary: bool,
        has_mitm: bool,
        has_fuzzing: bool,
        num_findings: int,
    ) -> "ContextBudget":
        """
        Calculate optimal budget allocation based on what data is present.
        """
        budget = cls()

        # Count active data sources
        active_sources = sum([
            num_documents > 0,
            has_security_scans,
            has_network,
            has_binary,
            has_mitm,
            has_fuzzing,
        ])

        if active_sources == 0:
            return budget

        # Calculate document complexity factor (0.5 to 2.0)
        # More docs or larger docs = higher factor
        doc_complexity = 1.0
        if num_documents > 0:
            avg_doc_size = total_doc_chars / num_documents
            if avg_doc_size > 100000:  # Large docs
                doc_complexity = 1.5
            elif avg_doc_size > 50000:  # Medium docs
                doc_complexity = 1.2
            if num_documents > 3:  # Multiple docs
                doc_complexity *= 1.3

        # Calculate available budget for each source
        # Start with base allocations and adjust
        allocations = {
            "documents": budget.documents_budget if num_documents > 0 else 0,
            "security_scans": budget.security_scans_budget if has_security_scans else 0,
            "network": budget.network_budget if has_network else 0,
            "binary": budget.binary_budget if has_binary else 0,
            "mitm": budget.mitm_budget if has_mitm else 0,
            "fuzzing": budget.fuzzing_budget if has_fuzzing else 0,
        }

        # Redistribute unused budget
        used = sum(allocations.values())
        unused = cls.TOTAL_AGENT_BUDGET - used

        if unused > 0 and active_sources > 0:
            # Give extra to documents if they're large
            if num_documents > 0 and total_doc_chars > 100000:
                doc_bonus = min(unused * 0.4, 20000)  # Up to 20K extra for docs
                allocations["documents"] += int(doc_bonus)
                unused -= doc_bonus

            # Give extra to findings-heavy sources
            if has_security_scans and num_findings > 50:
                scan_bonus = min(unused * 0.3, 15000)
                allocations["security_scans"] += int(scan_bonus)
                unused -= scan_bonus

            # Distribute remaining evenly
            if unused > 0:
                per_source = unused / active_sources
                for key in allocations:
                    if allocations[key] > 0:
                        allocations[key] += int(per_source)

        # Apply document complexity factor
        if num_documents > 0:
            allocations["documents"] = int(allocations["documents"] * doc_complexity)

        # Ensure minimums
        if num_documents > 0:
            allocations["documents"] = max(allocations["documents"], cls.MIN_DOCS)
        if has_security_scans:
            allocations["security_scans"] = max(allocations["security_scans"], cls.MIN_SCANS)
        if has_network:
            allocations["network"] = max(allocations["network"], cls.MIN_NETWORK)
        if has_binary:
            allocations["binary"] = max(allocations["binary"], cls.MIN_BINARY)
        if has_mitm:
            allocations["mitm"] = max(allocations["mitm"], cls.MIN_MITM)
        if has_fuzzing:
            allocations["fuzzing"] = max(allocations["fuzzing"], cls.MIN_FUZZING)

        # Update budget object
        budget.documents_budget = allocations["documents"]
        budget.security_scans_budget = allocations["security_scans"]
        budget.network_budget = allocations["network"]
        budget.binary_budget = allocations["binary"]
        budget.mitm_budget = allocations["mitm"]
        budget.fuzzing_budget = allocations["fuzzing"]

        return budget

    def to_dict(self) -> Dict[str, int]:
        return {
            "documents": self.documents_budget,
            "security_scans": self.security_scans_budget,
            "network": self.network_budget,
            "binary": self.binary_budget,
            "mitm": self.mitm_budget,
            "fuzzing": self.fuzzing_budget,
            "total": sum([
                self.documents_budget,
                self.security_scans_budget,
                self.network_budget,
                self.binary_budget,
                self.mitm_budget,
                self.fuzzing_budget,
            ])
        }


def prepare_documents_for_context(
    parsed_documents: List,  # List[ParsedDocument]
    budget: int,
    prioritize_security: bool = True,
) -> Tuple[str, Dict[str, Any]]:
    """
    Prepare documents for agent context with smart allocation.

    For huge documents or many documents:
    1. Use smart summaries for oversized docs
    2. Prioritize security-relevant content
    3. Deduplicate similar content across docs
    4. Track what was included vs truncated

    Returns:
        Tuple of (context_string, stats_dict)
    """
    if not parsed_documents:
        return "", {"documents_included": 0, "truncated": False}

    total_doc_chars = sum(p.total_chars for p in parsed_documents)
    num_docs = len(parsed_documents)

    stats = {
        "documents_included": num_docs,
        "total_original_chars": total_doc_chars,
        "budget_chars": budget,
        "truncated": total_doc_chars > budget,
        "strategy": "full" if total_doc_chars <= budget else "smart_summary",
    }

    # Case 1: Everything fits
    if total_doc_chars <= budget:
        parts = []
        for doc in parsed_documents:
            content = doc.get_prioritized_content(max_chars=budget // num_docs)
            parts.append(f"### {doc.filename}\n{content}")
        return "\n\n---\n\n".join(parts), stats

    # Case 2: Need smart allocation
    # Calculate per-document budget based on importance
    doc_importance = []
    for doc in parsed_documents:
        importance = 0.5  # Base
        # OpenAPI specs are very valuable
        if doc.document_type.value in ["openapi", "json", "yaml"]:
            if doc.api_endpoints:
                importance = 0.9
        # Docs with many security excerpts are valuable
        if len(doc.security_excerpts) > 5:
            importance += 0.2
        # Large docs get slightly less budget per char
        if doc.total_chars > 200000:
            importance -= 0.1
        doc_importance.append((doc, max(0.3, min(1.0, importance))))

    # Normalize importance to allocate budget
    total_importance = sum(imp for _, imp in doc_importance)

    parts = []
    used = 0

    for doc, importance in doc_importance:
        # Calculate this doc's share
        doc_budget = int((importance / total_importance) * budget)
        doc_budget = max(2000, doc_budget)  # Minimum 2K per doc

        # For very large docs, use smart summary
        if doc.total_chars > doc_budget * 3:
            # Doc is much bigger than budget - use condensed summary
            content = doc.get_smart_summary(max_chars=doc_budget)
            stats["strategy"] = "smart_summary"
        else:
            # Doc can be reasonably represented
            content = doc.get_prioritized_content(max_chars=doc_budget)

        if used + len(content) <= budget:
            parts.append(f"### {doc.filename}\n{content}")
            used += len(content) + 50  # Account for separators
        else:
            # Emergency truncation
            remaining = budget - used - 100
            if remaining > 1000:
                parts.append(f"### {doc.filename} (truncated)\n{content[:remaining]}")
            break

    stats["chars_used"] = used
    stats["docs_fully_included"] = len(parts)

    return "\n\n---\n\n".join(parts), stats


# ============================================================================
# IMPROVEMENT 1: Smart Context Prioritization
# Ensures critical findings are NEVER truncated, intelligently manages token budget
# ============================================================================

@dataclass
class PrioritizedFindings:
    """Container for findings organized by priority level."""
    critical: List[Dict[str, Any]] = field(default_factory=list)
    high_with_poc: List[Dict[str, Any]] = field(default_factory=list)
    high: List[Dict[str, Any]] = field(default_factory=list)
    with_exploit_scenario: List[Dict[str, Any]] = field(default_factory=list)
    medium: List[Dict[str, Any]] = field(default_factory=list)
    low: List[Dict[str, Any]] = field(default_factory=list)
    info: List[Dict[str, Any]] = field(default_factory=list)
    
    def total_count(self) -> int:
        return (len(self.critical) + len(self.high_with_poc) + len(self.high) +
                len(self.with_exploit_scenario) + len(self.medium) + 
                len(self.low) + len(self.info))
    
    def get_prioritized_list(self, max_items: int = 100) -> List[Dict[str, Any]]:
        """Return findings in priority order up to max_items."""
        result = []
        for category in [self.critical, self.high_with_poc, self.high, 
                         self.with_exploit_scenario, self.medium, self.low, self.info]:
            for item in category:
                if len(result) >= max_items:
                    return result
                result.append(item)
        return result


def _prioritize_findings(aggregated_data: Dict[str, Any]) -> PrioritizedFindings:
    """
    Intelligently prioritize findings to ensure critical items are never lost.
    Returns PrioritizedFindings with categorized items.
    """
    prioritized = PrioritizedFindings()
    
    # Get all exploit scenarios for reference
    exploit_scenario_titles = set()
    for scan in aggregated_data.get("security_scans", []):
        for es in scan.get("exploit_scenarios", []):
            exploit_scenario_titles.add(es.get("title", "").lower())
    
    # Categorize security scan findings
    for scan in aggregated_data.get("security_scans", []):
        for finding in scan.get("findings", []):
            severity = finding.get("severity", "").lower()
            has_poc = bool(finding.get("details", {}).get("poc_scripts") if isinstance(finding.get("details"), dict) else False)
            finding_type = finding.get("type", "").lower()
            
            # Check if this finding has an associated exploit scenario
            has_exploit = any(
                finding_type in title or finding.get("summary", "").lower() in title
                for title in exploit_scenario_titles
            )
            
            if severity == "critical":
                prioritized.critical.append(finding)
            elif severity == "high" and has_poc:
                prioritized.high_with_poc.append(finding)
            elif severity == "high":
                prioritized.high.append(finding)
            elif has_exploit:
                prioritized.with_exploit_scenario.append(finding)
            elif severity == "medium":
                prioritized.medium.append(finding)
            elif severity == "low":
                prioritized.low.append(finding)
            else:
                prioritized.info.append(finding)
    
    # Add network findings to appropriate categories
    for nr in aggregated_data.get("network_reports", []):
        for finding in nr.get("findings_data", []) or []:
            if isinstance(finding, dict):
                severity = str(finding.get("severity", "info")).lower()
                if severity == "critical":
                    prioritized.critical.append(finding)
                elif severity == "high":
                    prioritized.high.append(finding)
                elif severity == "medium":
                    prioritized.medium.append(finding)
                else:
                    prioritized.low.append(finding)
    
    # Add SSL findings
    for ssl in aggregated_data.get("ssl_scans", []):
        for sf in ssl.get("ssl_findings", []):
            for vuln in sf.get("vulnerabilities", []) or []:
                if isinstance(vuln, dict):
                    prioritized.critical.append({
                        "type": "ssl_vulnerability",
                        "severity": "critical",
                        "host": sf.get("host"),
                        **vuln
                    })
    
    # Add DNS findings
    for dns in aggregated_data.get("dns_scans", []):
        if dns.get("zone_transfer_possible"):
            prioritized.critical.append({
                "type": "zone_transfer",
                "severity": "critical",
                "domain": dns.get("domain"),
                "summary": f"Zone transfer allowed on {dns.get('domain')}"
            })
        for risk in dns.get("takeover_risks", []) or []:
            if isinstance(risk, dict) and risk.get("is_vulnerable"):
                prioritized.high.append({
                    "type": "subdomain_takeover",
                    "severity": "high",
                    **risk
                })
    
    logger.info(f"Prioritized findings: {prioritized.total_count()} total "
                f"(Critical: {len(prioritized.critical)}, High+PoC: {len(prioritized.high_with_poc)}, "
                f"High: {len(prioritized.high)}, Medium: {len(prioritized.medium)})")
    
    return prioritized


def _estimate_token_count(text: str) -> int:
    """Rough estimate of token count (avg 4 chars per token)."""
    return len(text) // 4


def _build_prioritized_context(
    aggregated_data: Dict[str, Any],
    max_tokens: int = 80000,
) -> Tuple[str, Dict[str, int]]:
    """
    Build context string with smart prioritization.
    Critical/High findings get full detail, lower severity gets summarized.
    Returns (context_string, stats_dict).
    """
    prioritized = _prioritize_findings(aggregated_data)
    context_parts = []
    current_tokens = 0
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "truncated": 0}
    
    # ALWAYS include ALL critical findings with full detail
    for finding in prioritized.critical:
        finding_text = _format_finding_full(finding)
        tokens = _estimate_token_count(finding_text)
        context_parts.append(finding_text)
        current_tokens += tokens
        stats["critical"] += 1
    
    # Include high+poc findings with full detail
    for finding in prioritized.high_with_poc:
        finding_text = _format_finding_full(finding)
        tokens = _estimate_token_count(finding_text)
        if current_tokens + tokens < max_tokens * 0.6:
            context_parts.append(finding_text)
            current_tokens += tokens
            stats["high"] += 1
        else:
            stats["truncated"] += 1
    
    # Include high findings
    for finding in prioritized.high:
        finding_text = _format_finding_full(finding)
        tokens = _estimate_token_count(finding_text)
        if current_tokens + tokens < max_tokens * 0.75:
            context_parts.append(finding_text)
            current_tokens += tokens
            stats["high"] += 1
        else:
            # Summarize instead of full detail
            summary_text = _format_finding_summary(finding)
            summary_tokens = _estimate_token_count(summary_text)
            if current_tokens + summary_tokens < max_tokens * 0.85:
                context_parts.append(summary_text)
                current_tokens += summary_tokens
                stats["high"] += 1
            else:
                stats["truncated"] += 1
    
    # Include medium findings with summary only
    for finding in prioritized.medium[:30]:  # Cap at 30
        summary_text = _format_finding_summary(finding)
        tokens = _estimate_token_count(summary_text)
        if current_tokens + tokens < max_tokens * 0.9:
            context_parts.append(summary_text)
            current_tokens += tokens
            stats["medium"] += 1
        else:
            stats["truncated"] += 1
    
    # Include low findings as one-liners
    low_summary = []
    for finding in prioritized.low[:20]:
        low_summary.append(f"- [{finding.get('type', 'Unknown')}] {finding.get('summary', '')[:100]}")
        stats["low"] += 1
    
    if low_summary:
        context_parts.append("\n**Low Severity Summary:**\n" + "\n".join(low_summary))
    
    logger.info(f"Built prioritized context: {current_tokens} tokens, stats: {stats}")
    return "\n\n".join(context_parts), stats


def _format_finding_full(finding: Dict[str, Any]) -> str:
    """Format a finding with full details."""
    severity = finding.get("severity", "Unknown").upper()
    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "⚪")
    
    parts = [f"{severity_emoji} **[{severity}] {finding.get('type', 'Unknown')}**"]
    parts.append(f"Summary: {finding.get('summary', 'No summary')}")
    
    if finding.get("file_path"):
        parts.append(f"File: `{finding.get('file_path')}` (Line {finding.get('start_line', 'N/A')})")
    
    details = finding.get("details", {})
    if isinstance(details, dict):
        if details.get("vulnerable_code") or details.get("code_snippet"):
            code = details.get("vulnerable_code") or details.get("code_snippet")
            parts.append(f"```\n{code[:1500]}\n```")
        
        for key in ["impact", "remediation", "exploit_guidance"]:
            if details.get(key):
                parts.append(f"**{key.title()}:** {details[key][:500]}")
    
    return "\n".join(parts)


def _format_finding_summary(finding: Dict[str, Any]) -> str:
    """Format a finding with summary only."""
    severity = finding.get("severity", "Unknown").upper()
    return f"- [{severity}] {finding.get('type', 'Unknown')}: {finding.get('summary', '')[:200]} | File: {finding.get('file_path', 'N/A')}"


# ============================================================================
# IMPROVEMENT 2: Structured Output Validation
# Pydantic models for validating AI agent responses
# ============================================================================

class ValidatedPoCScript(BaseModel):
    """Validated PoC script from AI."""
    vulnerability_name: str = Field(..., min_length=3)
    language: str = Field(default="python")
    description: str = Field(default="")
    usage_instructions: Optional[str] = None
    script_code: str = Field(..., min_length=50)
    expected_output: Optional[str] = None
    customization_notes: Optional[str] = None


class ValidatedAttackStep(BaseModel):
    """Validated attack step."""
    step_number: int = Field(ge=1)
    title: str = Field(..., min_length=3)
    explanation: str = Field(..., min_length=10)
    command_or_action: Optional[str] = None
    expected_output: Optional[str] = None
    troubleshooting: Optional[str] = None


class ValidatedAttackGuide(BaseModel):
    """Validated beginner attack guide."""
    attack_name: str = Field(..., min_length=5)
    difficulty_level: str = Field(default="Intermediate")
    estimated_time: Optional[str] = None
    prerequisites: List[str] = Field(default_factory=list)
    tools_needed: List[Dict[str, Any]] = Field(default_factory=list)
    step_by_step_guide: List[ValidatedAttackStep] = Field(..., min_length=3)
    success_indicators: List[str] = Field(default_factory=list)
    what_you_can_do_after: Optional[str] = None


class ValidatedCrossFinding(BaseModel):
    """Validated cross-analysis finding."""
    title: str = Field(..., min_length=5)
    description: str = Field(..., min_length=50)
    severity: str = Field(default="Medium")
    sources: List[str] = Field(..., min_length=1)
    source_details: Optional[List[Dict[str, Any]]] = None
    exploitability_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    exploit_narrative: Optional[str] = None
    exploit_guidance: Optional[str] = None
    poc_available: Optional[bool] = None
    remediation: Optional[str] = None


class ValidatedPrioritizedVuln(BaseModel):
    """Validated prioritized vulnerability."""
    rank: int = Field(ge=1)
    title: str = Field(..., min_length=5)
    severity: str
    cvss_estimate: Optional[str] = None
    exploitability: Optional[str] = None
    impact: str = Field(..., min_length=20)
    source: Optional[str] = None
    affected_component: Optional[str] = None
    exploitation_steps: List[str] = Field(..., min_length=3)
    poc_available: Optional[str] = None
    remediation_priority: Optional[str] = None
    remediation_steps: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)


def _validate_and_fix_poc_scripts(raw_scripts: List[Any]) -> List[Dict[str, Any]]:
    """Validate PoC scripts and fix/filter invalid ones."""
    validated = []
    for script in raw_scripts:
        if not isinstance(script, dict):
            continue
        try:
            # Try to validate
            validated_script = ValidatedPoCScript(**script)
            validated.append(validated_script.model_dump())
        except ValidationError as e:
            # Try to fix common issues
            fixed = _fix_poc_script(script)
            if fixed:
                validated.append(fixed)
            else:
                logger.warning(f"Could not validate/fix PoC script: {e}")
    
    logger.info(f"Validated {len(validated)}/{len(raw_scripts)} PoC scripts")
    return validated


def _fix_poc_script(script: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Attempt to fix common issues in PoC script."""
    if not script.get("vulnerability_name"):
        script["vulnerability_name"] = script.get("title", script.get("name", "Unknown Exploit"))
    
    if not script.get("script_code") or len(script.get("script_code", "")) < 50:
        # Try to extract from other fields
        code = script.get("code", script.get("poc", script.get("exploit", "")))
        if code and len(code) >= 50:
            script["script_code"] = code
        else:
            return None
    
    return script


def _validate_and_fix_attack_guides(raw_guides: List[Any]) -> List[Dict[str, Any]]:
    """Validate attack guides and fix/filter invalid ones."""
    validated = []
    for guide in raw_guides:
        if not isinstance(guide, dict):
            continue
        try:
            # Fix common issues before validation
            guide = _preprocess_attack_guide(guide)
            validated_guide = ValidatedAttackGuide(**guide)
            validated.append(validated_guide.model_dump())
        except ValidationError as e:
            logger.warning(f"Could not validate attack guide '{guide.get('attack_name', 'Unknown')}': {e}")
            # Still include with minimal fixes
            if guide.get("attack_name") and guide.get("step_by_step_guide"):
                validated.append(guide)
    
    logger.info(f"Validated {len(validated)}/{len(raw_guides)} attack guides")
    return validated


def _preprocess_attack_guide(guide: Dict[str, Any]) -> Dict[str, Any]:
    """Preprocess attack guide to fix common issues."""
    # Ensure step_by_step_guide has proper structure
    steps = guide.get("step_by_step_guide", [])
    fixed_steps = []
    for i, step in enumerate(steps):
        if isinstance(step, dict):
            step["step_number"] = step.get("step_number", i + 1)
            step["title"] = step.get("title", f"Step {i + 1}")
            step["explanation"] = step.get("explanation", step.get("description", "Perform this step"))
            fixed_steps.append(step)
        elif isinstance(step, str):
            fixed_steps.append({
                "step_number": i + 1,
                "title": f"Step {i + 1}",
                "explanation": step
            })
    
    guide["step_by_step_guide"] = fixed_steps
    return guide


def _validate_and_fix_cross_findings(raw_findings: List[Any]) -> List[Dict[str, Any]]:
    """Validate cross-analysis findings."""
    validated = []
    for finding in raw_findings:
        if not isinstance(finding, dict):
            continue
        try:
            # Ensure sources is a list
            if not finding.get("sources"):
                finding["sources"] = ["security_scan"]
            elif isinstance(finding.get("sources"), str):
                finding["sources"] = [finding["sources"]]
            
            validated_finding = ValidatedCrossFinding(**finding)
            validated.append(validated_finding.model_dump())
        except ValidationError as e:
            logger.warning(f"Could not validate cross-finding: {e}")
            # Include anyway if it has basic structure
            if finding.get("title") and finding.get("description"):
                validated.append(finding)
    
    logger.info(f"Validated {len(validated)}/{len(raw_findings)} cross-analysis findings")
    return validated


def _validate_and_fix_prioritized_vulns(raw_vulns: List[Any]) -> List[Dict[str, Any]]:
    """Validate prioritized vulnerabilities."""
    validated = []
    for i, vuln in enumerate(raw_vulns):
        if not isinstance(vuln, dict):
            continue
        try:
            # Fix common issues
            vuln["rank"] = vuln.get("rank", i + 1)
            if not vuln.get("exploitation_steps"):
                vuln["exploitation_steps"] = ["Identify the vulnerability", "Craft the payload", "Execute the exploit"]
            
            validated_vuln = ValidatedPrioritizedVuln(**vuln)
            validated.append(validated_vuln.model_dump())
        except ValidationError as e:
            logger.warning(f"Could not validate prioritized vuln: {e}")
            if vuln.get("title") and vuln.get("severity"):
                validated.append(vuln)
    
    logger.info(f"Validated {len(validated)}/{len(raw_vulns)} prioritized vulnerabilities")
    return validated


# ============================================================================
# IMPROVEMENT 3: Two-Phase Agent Communication
# Analysis phase informs generation phase for better correlation
# ============================================================================

@dataclass
class Phase1Results:
    """Results from Phase 1 (Analysis) agents."""
    executive_summary: Dict[str, Any] = field(default_factory=dict)
    cross_findings: List[Dict[str, Any]] = field(default_factory=list)
    prioritized_vulns: List[Dict[str, Any]] = field(default_factory=list)
    key_attack_vectors: List[str] = field(default_factory=list)
    
    def get_top_vulnerabilities(self, n: int = 5) -> List[str]:
        """Get titles of top n vulnerabilities."""
        vulns = sorted(self.prioritized_vulns, key=lambda x: x.get("rank", 999))[:n]
        return [v.get("title", "Unknown") for v in vulns]
    
    def get_severity_summary(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in self.prioritized_vulns:
            sev = v.get("severity", "Medium")
            if sev in summary:
                summary[sev] += 1
        return summary


# ============================================================================
# IMPROVEMENT 4: Enhanced Source Code Search
# Semantic pattern matching for better vulnerability correlation
# ============================================================================

# Vulnerability-to-code patterns mapping for smarter search
VULN_CODE_PATTERNS = {
    "sql_injection": [
        r"execute\s*\(",
        r"cursor\.\w+\(",
        r"SELECT\s+.*FROM",
        r"INSERT\s+INTO",
        r"UPDATE\s+.*SET",
        r"DELETE\s+FROM",
        r"query\s*\(",
        r"raw_sql",
        r"rawQuery",
        r"\.query\(",
    ],
    "xss": [
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"document\.write\(",
        r"eval\(",
        r"dangerouslySetInnerHTML",
        r"v-html",
        r"\{\{.*\}\}",  # Template injection
        r"\.html\(",  # jQuery
    ],
    "command_injection": [
        r"exec\s*\(",
        r"system\s*\(",
        r"popen\s*\(",
        r"subprocess\.",
        r"shell\s*=\s*True",
        r"os\.system",
        r"child_process",
        r"spawn\s*\(",
    ],
    "path_traversal": [
        r"open\s*\(",
        r"read_file",
        r"file_get_contents",
        r"include\s*\(",
        r"require\s*\(",
        r"readFile",
        r"join\s*\(.*\.\.",
        r"path\.join",
    ],
    "hardcoded_credentials": [
        r"password\s*=\s*['\"]",
        r"secret\s*=\s*['\"]",
        r"api_key\s*=\s*['\"]",
        r"token\s*=\s*['\"]",
        r"AWS_SECRET",
        r"private_key\s*=",
        r"BEGIN\s+PRIVATE\s+KEY",
    ],
    "insecure_crypto": [
        r"MD5\s*\(",
        r"SHA1\s*\(",
        r"DES\s*\(",
        r"\.md5\(",
        r"\.sha1\(",
        r"ECB",  # Insecure block cipher mode
        r"PKCS1v15",  # Vulnerable padding
    ],
    "ssrf": [
        r"requests\.(get|post|put)\s*\(",
        r"urllib\.",
        r"http\.request",
        r"fetch\s*\(",
        r"axios\.",
        r"curl_exec",
    ],
    "deserialization": [
        r"pickle\.load",
        r"yaml\.load",
        r"unserialize\s*\(",
        r"JSON\.parse",
        r"ObjectInputStream",
        r"readObject\s*\(",
    ],
}


def _get_patterns_for_vulnerability(vuln_type: str) -> List[str]:
    """Get regex patterns for a vulnerability type."""
    vuln_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")
    
    # Direct match
    if vuln_lower in VULN_CODE_PATTERNS:
        return VULN_CODE_PATTERNS[vuln_lower]
    
    # Partial match
    for key, patterns in VULN_CODE_PATTERNS.items():
        if key in vuln_lower or vuln_lower in key:
            return patterns
    
    return []


def _enhanced_source_code_search(
    db: Session,
    project_id: int,
    indicators: Dict[str, Set[str]],
    aggregated_data: Dict[str, Any],
    max_chunks: int = 75,
) -> List[Dict[str, Any]]:
    """
    Enhanced source code search with semantic pattern matching.
    Searches based on vulnerability types found in scans.
    """
    relevant_code: List[Dict[str, Any]] = []
    seen_chunks: Set[int] = set()
    
    # Build search terms from indicators
    search_terms: List[str] = []
    
    # Add file paths
    for fp in list(indicators.get("file_paths", []))[:25]:
        search_terms.append(fp)
    
    # Add function names
    for fn in list(indicators.get("function_names", []))[:20]:
        search_terms.append(fn)
    
    # Add vulnerability-specific patterns
    vuln_patterns: Dict[str, List[str]] = {}
    for vuln_type in indicators.get("vulnerability_types", []):
        patterns = _get_patterns_for_vulnerability(vuln_type)
        if patterns:
            vuln_patterns[vuln_type] = patterns[:5]  # Top 5 patterns per vuln type
    
    logger.info(f"Enhanced search: {len(search_terms)} terms, {len(vuln_patterns)} vuln pattern sets")
    
    # First: Search by file paths and function names (existing logic)
    for term in search_terms[:30]:
        if len(relevant_code) >= max_chunks:
            break
        
        try:
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
                
                # Calculate relevance score
                relevance_score = _calculate_chunk_relevance(chunk, indicators)
                
                relevant_code.append({
                    "file_path": chunk.file_path,
                    "language": chunk.language,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "code": chunk.code[:4000],  # Increased limit
                    "matched_term": term,
                    "summary": chunk.summary,
                    "relevance_score": relevance_score,
                })
        except Exception as e:
            logger.warning(f"Error searching for term '{term}': {e}")
            continue
    
    # Second: Search by vulnerability patterns (NEW)
    for vuln_type, patterns in vuln_patterns.items():
        if len(relevant_code) >= max_chunks:
            break
        
        for pattern in patterns:
            if len(relevant_code) >= max_chunks:
                break
            
            try:
                # Use regex-like search
                chunks = db.query(models.CodeChunk).filter(
                    models.CodeChunk.project_id == project_id,
                    models.CodeChunk.code.op("~*")(pattern)  # PostgreSQL regex
                ).limit(3).all()
                
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
                        "code": chunk.code[:4000],
                        "matched_term": f"Pattern: {pattern} (for {vuln_type})",
                        "summary": chunk.summary,
                        "vulnerability_type": vuln_type,
                        "relevance_score": 0.9,  # High relevance for pattern matches
                    })
            except Exception as e:
                # Fall back to ILIKE if regex not supported
                try:
                    # Convert regex to simple search
                    simple_term = pattern.replace(r"\s*", " ").replace(r"\(", "(").replace(r"\.", ".")
                    simple_term = re.sub(r'[\\^$.*+?{}[\]|()]', '', simple_term)
                    if len(simple_term) > 3:
                        chunks = db.query(models.CodeChunk).filter(
                            models.CodeChunk.project_id == project_id,
                            models.CodeChunk.code.ilike(f"%{simple_term}%")
                        ).limit(2).all()
                        
                        for chunk in chunks:
                            if chunk.id not in seen_chunks:
                                seen_chunks.add(chunk.id)
                                relevant_code.append({
                                    "file_path": chunk.file_path,
                                    "language": chunk.language,
                                    "start_line": chunk.start_line,
                                    "end_line": chunk.end_line,
                                    "code": chunk.code[:4000],
                                    "matched_term": f"Pattern fallback: {simple_term}",
                                    "summary": chunk.summary,
                                    "vulnerability_type": vuln_type,
                                    "relevance_score": 0.7,
                                })
                except Exception:
                    pass
    
    # Sort by relevance score
    relevant_code.sort(key=lambda x: x.get("relevance_score", 0), reverse=True)
    
    logger.info(f"Enhanced search found {len(relevant_code)} relevant code chunks")
    return relevant_code[:max_chunks]


def _calculate_chunk_relevance(chunk, indicators: Dict[str, Set[str]]) -> float:
    """Calculate relevance score for a code chunk based on indicators."""
    score = 0.5  # Base score
    
    code_lower = chunk.code.lower() if chunk.code else ""
    file_path_lower = chunk.file_path.lower() if chunk.file_path else ""
    
    # Check for vulnerability-related keywords
    high_risk_keywords = ["password", "secret", "exec", "query", "eval", "system", "admin", "root"]
    for keyword in high_risk_keywords:
        if keyword in code_lower:
            score += 0.1
    
    # Check if file path matches indicators
    for fp in indicators.get("file_paths", []):
        if fp.lower() in file_path_lower:
            score += 0.2
            break
    
    # Check for function names
    for fn in indicators.get("function_names", []):
        if fn.lower() in code_lower:
            score += 0.15
    
    # Check for endpoints
    for ep in indicators.get("endpoints", []):
        if ep.lower() in code_lower:
            score += 0.1
    
    return min(score, 1.0)

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

    # Nmap Scans (port/service detection - both live scans and uploaded results)
    nmap_scans = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type == "nmap"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()

    for nmap in nmap_scans:
        report_data = nmap.report_data or {}
        raw_data = nmap.raw_data or {}

        # Extract scan summary
        hosts_count = len(raw_data.get("hosts", []))
        total_ports = 0
        open_ports = 0
        for host in raw_data.get("hosts", []):
            ports = host.get("ports", [])
            total_ports += len(ports)
            open_ports += sum(1 for p in ports if p.get("state") == "open")

        # Count findings from AI analysis
        ai_analysis = report_data.get("ai_analysis", {})
        findings_count = 0
        if isinstance(ai_analysis, dict):
            findings_count = len(ai_analysis.get("vulnerabilities", []))
            findings_count += len(ai_analysis.get("security_issues", []))

        response.nmap_scans.append(AvailableScanItem(
            scan_type="nmap_scan",
            scan_id=nmap.id,
            title=nmap.title or f"Nmap Scan {nmap.id}",
            created_at=nmap.created_at,
            summary=f"Hosts: {hosts_count}, Open Ports: {open_ports}/{total_ports}",
            risk_level=nmap.risk_level,
            findings_count=findings_count,
        ))

    # PCAP Analysis Reports (packet capture analysis)
    pcap_reports = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type == "pcap"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()

    for pcap in pcap_reports:
        findings_count = len(pcap.findings_data) if pcap.findings_data else 0
        raw_data = pcap.raw_data or {}

        # Extract PCAP summary
        packet_count = raw_data.get("packet_count", 0)
        protocols = raw_data.get("protocols", [])
        protocol_summary = ", ".join(protocols[:3]) if protocols else "N/A"
        if len(protocols) > 3:
            protocol_summary += f" (+{len(protocols) - 3})"

        response.pcap_reports.append(AvailableScanItem(
            scan_type="pcap_report",
            scan_id=pcap.id,
            title=pcap.title or f"PCAP Analysis {pcap.id}",
            created_at=pcap.created_at,
            summary=f"Packets: {packet_count}, Protocols: {protocol_summary}, Risk: {pcap.risk_level or 'N/A'}",
            risk_level=pcap.risk_level,
            findings_count=findings_count,
        ))

    # API Tester Reports (endpoint security testing)
    # Note: API Tester results are stored in NetworkAnalysisReport with analysis_type='api_tester'
    api_tester_reports = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.project_id == project_id,
        models.NetworkAnalysisReport.analysis_type == "api_tester"
    ).order_by(models.NetworkAnalysisReport.created_at.desc()).all()

    for api in api_tester_reports:
        findings_count = len(api.findings_data) if api.findings_data else 0
        raw_data = api.raw_data or {}

        # Extract API testing summary
        endpoints_tested = raw_data.get("endpoints_tested", 0)
        base_url = raw_data.get("base_url", "N/A")

        response.api_tester_reports.append(AvailableScanItem(
            scan_type="api_tester_report",
            scan_id=api.id,
            title=api.title or f"API Security Test {api.id}",
            created_at=api.created_at,
            summary=f"Target: {base_url[:40]}{'...' if len(base_url) > 40 else ''}, Endpoints: {endpoints_tested}",
            risk_level=api.risk_level,
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
    
    # ZAP DAST Scans (now called Dynamic Scans)
    zap_scans = db.query(models.ZAPScan).filter(
        models.ZAPScan.project_id == project_id
    ).order_by(models.ZAPScan.created_at.desc()).all()
    
    for zap in zap_scans:
        # Count total alerts
        findings_count = (
            (zap.alerts_high or 0) +
            (zap.alerts_medium or 0) +
            (zap.alerts_low or 0) +
            (zap.alerts_info or 0)
        )
        
        # Determine risk level
        if zap.alerts_high and zap.alerts_high > 0:
            risk_level = "High"
        elif zap.alerts_medium and zap.alerts_medium > 0:
            risk_level = "Medium"
        elif zap.alerts_low and zap.alerts_low > 0:
            risk_level = "Low"
        else:
            risk_level = "Clean"
        
        response.dynamic_scans.append(AvailableScanItem(
            scan_type="dynamic_scan",
            scan_id=zap.id,
            title=zap.title or f"Dynamic Scan: {zap.target_url[:50]}...",
            created_at=zap.created_at,
            summary=f"Target: {zap.target_url}, Type: {zap.scan_type}, URLs: {zap.urls_found or 0}",
            risk_level=risk_level,
            findings_count=findings_count,
        ))
    
    # Binary Fuzzer Sessions (AFL++, coverage-guided fuzzing)
    binary_sessions = db.query(models.BinaryFuzzerSession).filter(
        models.BinaryFuzzerSession.project_id == project_id
    ).order_by(models.BinaryFuzzerSession.created_at.desc()).all()
    
    for bs in binary_sessions:
        # Count total crashes by severity
        findings_count = (
            (bs.crashes_critical or 0) +
            (bs.crashes_high or 0) +
            (bs.crashes_medium or 0) +
            (bs.crashes_low or 0)
        )
        
        # Determine risk level from crash severities
        if bs.crashes_critical and bs.crashes_critical > 0:
            risk_level = "Critical"
        elif bs.crashes_high and bs.crashes_high > 0:
            risk_level = "High"
        elif bs.crashes_medium and bs.crashes_medium > 0:
            risk_level = "Medium"
        elif bs.crashes_low and bs.crashes_low > 0:
            risk_level = "Low"
        else:
            risk_level = "Clean"
        
        response.binary_fuzzer_sessions.append(AvailableScanItem(
            scan_type="binary_fuzzer_session",
            scan_id=bs.id,
            title=bs.name or f"Binary Fuzzer: {bs.binary_name or 'Unknown'}",
            created_at=bs.created_at,
            summary=f"Binary: {bs.binary_name or 'N/A'}, Crashes: {bs.unique_crashes or 0}, Coverage: {bs.coverage_percentage or 0:.1f}%",
            risk_level=risk_level,
            findings_count=findings_count,
        ))

    # Fuzzing Campaign Reports (AI-generated reports from Agentic Binary Fuzzer)
    campaign_reports = db.query(models.FuzzingCampaignReport).filter(
        models.FuzzingCampaignReport.project_id == project_id
    ).order_by(models.FuzzingCampaignReport.created_at.desc()).all()

    for cr in campaign_reports:
        # Count findings based on crashes
        findings_count = (cr.unique_crashes or 0) + (cr.exploitable_crashes or 0)

        # Determine risk level from report data
        risk_rating = cr.report_data.get("risk_rating", "Unknown") if cr.report_data else "Unknown"
        risk_level = risk_rating if risk_rating in ["Critical", "High", "Medium", "Low"] else "Unknown"

        response.fuzzing_campaign_reports.append(AvailableScanItem(
            scan_type="fuzzing_campaign_report",
            scan_id=cr.id,
            title=f"Campaign Report: {cr.binary_name}",
            created_at=cr.created_at,
            summary=f"Binary: {cr.binary_name}, Coverage: {cr.final_coverage or 0:.1f}%, Crashes: {cr.unique_crashes or 0} ({cr.exploitable_crashes or 0} exploitable)",
            risk_level=risk_level,
            findings_count=findings_count,
        ))

    # MITM Analysis Reports (traffic interception analysis)
    mitm_reports = db.query(models.MITMAnalysisReport).filter(
        models.MITMAnalysisReport.project_id == project_id
    ).order_by(models.MITMAnalysisReport.created_at.desc()).all()
    
    for mr in mitm_reports:
        findings_count = mr.findings_count or 0
        risk_level = mr.risk_level or "Unknown"
        
        # Build summary with 3-pass analysis stats
        summary_parts = [f"Traffic: {mr.traffic_analyzed or 0}"]
        if mr.analysis_passes:
            summary_parts.append(f"{mr.analysis_passes}-pass analysis")
        if mr.false_positives_removed:
            summary_parts.append(f"{mr.false_positives_removed} FPs removed")
        summary_parts.append(f"Risk: {risk_level}")
        
        response.mitm_analysis_reports.append(AvailableScanItem(
            scan_type="mitm_analysis_report",
            scan_id=mr.id,
            title=mr.title or f"MITM Analysis {mr.id}",
            created_at=mr.created_at,
            summary=", ".join(summary_parts),
            risk_level=risk_level,
            findings_count=findings_count,
        ))
    
    response.total_available = (
        len(response.security_scans) +
        len(response.network_reports) +
        len(response.ssl_scans) +
        len(response.dns_scans) +
        len(response.traceroute_scans) +
        len(response.nmap_scans) +
        len(response.pcap_reports) +
        len(response.api_tester_reports) +
        len(response.re_reports) +
        len(response.fuzzing_sessions) +
        len(response.agentic_fuzzer_reports) +
        len(response.dynamic_scans) +
        len(response.binary_fuzzer_sessions) +
        len(response.fuzzing_campaign_reports) +
        len(response.mitm_analysis_reports)
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


def _fetch_nmap_scan_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from an Nmap scan report (live or uploaded)."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == scan_id,
        models.NetworkAnalysisReport.analysis_type == "nmap"
    ).first()
    if not report:
        return {"error": f"Nmap scan {scan_id} not found"}

    report_data = report.report_data or {}
    raw_data = report.raw_data or {}
    ai_analysis = report_data.get("ai_analysis", {})

    # Extract host data
    hosts = raw_data.get("hosts", [])
    total_hosts = len(hosts)
    up_hosts = sum(1 for h in hosts if h.get("status", {}).get("state") == "up")

    # Aggregate port information
    all_ports = []
    services = []
    for host in hosts:
        host_ip = host.get("address") or host.get("ip", "")
        for port in host.get("ports", []):
            port_info = {
                "host": host_ip,
                "port": port.get("portid") or port.get("port"),
                "protocol": port.get("protocol", "tcp"),
                "state": port.get("state"),
                "service": port.get("service", {}).get("name") if isinstance(port.get("service"), dict) else port.get("service"),
                "version": port.get("service", {}).get("version") if isinstance(port.get("service"), dict) else None,
                "product": port.get("service", {}).get("product") if isinstance(port.get("service"), dict) else None,
            }
            all_ports.append(port_info)
            if port_info["service"]:
                services.append(port_info["service"])

    # Count open ports
    open_ports = [p for p in all_ports if p.get("state") == "open"]
    closed_ports = [p for p in all_ports if p.get("state") == "closed"]
    filtered_ports = [p for p in all_ports if p.get("state") == "filtered"]

    # Extract vulnerabilities from AI analysis
    findings = []
    if isinstance(ai_analysis, dict):
        for vuln in ai_analysis.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                findings.append({
                    "type": vuln.get("type", "vulnerability"),
                    "severity": vuln.get("severity", "medium"),
                    "title": vuln.get("name", vuln.get("title", "Vulnerability")),
                    "description": vuln.get("description", ""),
                    "host": vuln.get("host"),
                    "port": vuln.get("port"),
                    "service": vuln.get("service"),
                    "cve": vuln.get("cve"),
                })
        for issue in ai_analysis.get("security_issues", []):
            if isinstance(issue, dict):
                findings.append({
                    "type": "security_issue",
                    "severity": issue.get("severity", "medium"),
                    "title": issue.get("title", issue.get("issue", "Security Issue")),
                    "description": issue.get("description", issue.get("details", "")),
                })

    return {
        "report_id": scan_id,
        "title": report.title,
        "analysis_type": "nmap",
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "total_hosts": total_hosts,
        "up_hosts": up_hosts,
        "open_ports_count": len(open_ports),
        "closed_ports_count": len(closed_ports),
        "filtered_ports_count": len(filtered_ports),
        "open_ports": open_ports[:50],  # Limit for context
        "services": list(set(services)),
        "hosts": hosts[:20],  # Limit hosts for context
        "findings": findings,
        "findings_count": len(findings),
        "ai_analysis": ai_analysis,
    }


def _fetch_pcap_report_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a PCAP analysis report."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == scan_id,
        models.NetworkAnalysisReport.analysis_type == "pcap"
    ).first()
    if not report:
        return {"error": f"PCAP report {scan_id} not found"}

    report_data = report.report_data or {}
    raw_data = report.raw_data or {}
    findings_data = report.findings_data or []

    # Extract PCAP analysis summary
    packet_count = raw_data.get("packet_count", 0)
    protocols = raw_data.get("protocols", [])
    duration = raw_data.get("capture_duration", 0)
    file_size = raw_data.get("file_size", 0)

    # Extract conversation data
    conversations = raw_data.get("conversations", [])
    unique_ips = set()
    for conv in conversations:
        if conv.get("src_ip"):
            unique_ips.add(conv["src_ip"])
        if conv.get("dst_ip"):
            unique_ips.add(conv["dst_ip"])

    # Extract credential findings
    credentials = []
    suspicious_traffic = []
    for finding in findings_data:
        if isinstance(finding, dict):
            if finding.get("type") in ["credential", "credentials", "password", "cleartext_auth"]:
                credentials.append(finding)
            elif finding.get("severity") in ["high", "critical"]:
                suspicious_traffic.append(finding)

    return {
        "report_id": scan_id,
        "title": report.title,
        "analysis_type": "pcap",
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "filename": report.filename,
        "packet_count": packet_count,
        "protocols": protocols,
        "capture_duration": duration,
        "file_size": file_size,
        "unique_ips": list(unique_ips)[:50],
        "conversations_count": len(conversations),
        "findings_data": findings_data,
        "findings_count": len(findings_data),
        "credentials_found": len(credentials),
        "suspicious_traffic_count": len(suspicious_traffic),
        "ai_summary": report_data.get("ai_summary", ""),
    }


def _fetch_api_tester_report_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from an API security test report."""
    report = db.query(models.NetworkAnalysisReport).filter(
        models.NetworkAnalysisReport.id == scan_id,
        models.NetworkAnalysisReport.analysis_type == "api_tester"
    ).first()
    if not report:
        return {"error": f"API Tester report {scan_id} not found"}

    report_data = report.report_data or {}
    raw_data = report.raw_data or {}
    findings_data = report.findings_data or []

    # Extract API testing summary
    base_url = raw_data.get("base_url", "")
    endpoints_tested = raw_data.get("endpoints_tested", 0)
    total_requests = raw_data.get("total_requests", 0)
    duration = raw_data.get("duration_ms", 0)

    # Categorize findings by type
    auth_findings = []
    injection_findings = []
    config_findings = []
    other_findings = []

    for finding in findings_data:
        if isinstance(finding, dict):
            category = finding.get("category", "").lower()
            if "auth" in category or "authentication" in category or "authorization" in category:
                auth_findings.append(finding)
            elif "injection" in category or "xss" in category or "sqli" in category:
                injection_findings.append(finding)
            elif "cors" in category or "header" in category or "config" in category:
                config_findings.append(finding)
            else:
                other_findings.append(finding)

    # Severity breakdown
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings_data:
        if isinstance(finding, dict):
            sev = finding.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

    return {
        "report_id": scan_id,
        "title": report.title,
        "analysis_type": "api_tester",
        "created_at": str(report.created_at),
        "risk_level": report.risk_level,
        "base_url": base_url,
        "endpoints_tested": endpoints_tested,
        "total_requests": total_requests,
        "duration_ms": duration,
        "findings_data": findings_data,
        "findings_count": len(findings_data),
        "severity_counts": severity_counts,
        "auth_findings_count": len(auth_findings),
        "injection_findings_count": len(injection_findings),
        "config_findings_count": len(config_findings),
        "auth_findings": auth_findings[:10],  # Limit for context
        "injection_findings": injection_findings[:10],
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


def _fetch_dynamic_scan_data(db: Session, scan_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a Dynamic (DAST) scan."""
    zap_scan = db.query(models.ZAPScan).filter(
        models.ZAPScan.id == scan_id
    ).first()
    if not zap_scan:
        return {"error": f"Dynamic scan {scan_id} not found"}
    
    # Process alerts to extract findings
    alerts = zap_scan.alerts_data or []
    findings = []
    for alert in alerts:
        findings.append({
            "name": alert.get("name", alert.get("alert", "Unknown")),
            "risk": alert.get("risk", "info"),
            "confidence": alert.get("confidence", "Medium"),
            "url": alert.get("url", ""),
            "method": alert.get("method", "GET"),
            "parameter": alert.get("param", alert.get("parameter", "")),
            "description": alert.get("description", ""),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", ""),
            "cwe_id": alert.get("cweid", alert.get("cwe_id", "")),
            "wasc_id": alert.get("wascid", alert.get("wasc_id", "")),
            "evidence": alert.get("evidence", ""),
        })
    
    return {
        "scan_id": scan_id,
        "session_id": zap_scan.session_id,
        "title": zap_scan.title,
        "target_url": zap_scan.target_url,
        "scan_type": zap_scan.scan_type,
        "status": zap_scan.status,
        "started_at": str(zap_scan.started_at) if zap_scan.started_at else None,
        "completed_at": str(zap_scan.completed_at) if zap_scan.completed_at else None,
        "urls_found": zap_scan.urls_found,
        "alerts_high": zap_scan.alerts_high,
        "alerts_medium": zap_scan.alerts_medium,
        "alerts_low": zap_scan.alerts_low,
        "alerts_info": zap_scan.alerts_info,
        "findings": findings,
        "urls_discovered": zap_scan.urls_data or [],
        "stats": zap_scan.stats,
    }


def _fetch_mitm_analysis_report_data(db: Session, report_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a MITM Analysis Report."""
    report = db.query(models.MITMAnalysisReport).filter(
        models.MITMAnalysisReport.id == report_id
    ).first()
    if not report:
        return {"error": f"MITM analysis report {report_id} not found"}
    
    findings = report.findings or []
    
    return {
        "report_id": report_id,
        "proxy_id": report.proxy_id,
        "session_id": report.session_id,
        "title": report.title,
        "description": report.description,
        "created_at": str(report.created_at) if report.created_at else None,
        # Traffic stats
        "traffic_analyzed": report.traffic_analyzed,
        "rules_active": report.rules_active,
        # 3-pass analysis stats
        "analysis_passes": report.analysis_passes,
        "pass1_findings": report.pass1_findings,
        "pass2_ai_findings": report.pass2_ai_findings,
        "after_dedup": report.after_dedup,
        "false_positives_removed": report.false_positives_removed,
        # Risk assessment
        "findings_count": report.findings_count,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "summary": report.summary,
        # Detailed findings and analysis
        "findings": findings,
        "attack_paths": report.attack_paths,
        "recommendations": report.recommendations,
        "exploit_references": report.exploit_references,
        "cve_references": report.cve_references,
        "ai_exploitation_writeup": report.ai_exploitation_writeup,
    }


def _fetch_binary_fuzzer_session_data(db: Session, session_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a Binary Fuzzer (AFL++) session."""
    session = db.query(models.BinaryFuzzerSession).filter(
        models.BinaryFuzzerSession.id == session_id
    ).first()
    if not session:
        return {"error": f"Binary fuzzer session {session_id} not found"}
    
    # Process crashes to extract findings
    crashes = session.crashes or []
    findings = []
    for crash in crashes:
        severity = crash.get("severity", "medium").lower()
        findings.append({
            "type": crash.get("type", crash.get("crash_type", "Unknown crash")),
            "severity": severity,
            "signal": crash.get("signal", ""),
            "address": crash.get("address", crash.get("crash_address", "")),
            "function": crash.get("function", crash.get("crash_function", "")),
            "stack_trace": crash.get("stack_trace", crash.get("backtrace", [])),
            "input_file": crash.get("input_file", ""),
            "input_hash": crash.get("input_hash", ""),
            "exploitability": crash.get("exploitability", "Unknown"),
            "description": crash.get("description", ""),
        })
    
    # Process memory errors if available
    memory_errors = session.memory_errors or []
    for error in memory_errors:
        findings.append({
            "type": f"Memory Error: {error.get('type', 'Unknown')}",
            "severity": error.get("severity", "high"),
            "address": error.get("address", ""),
            "size": error.get("size", ""),
            "stack_trace": error.get("stack_trace", []),
            "description": error.get("description", ""),
        })
    
    return {
        "session_id": session_id,
        "uuid": session.session_id,
        "name": session.name,
        "binary_path": session.binary_path,
        "binary_name": session.binary_name,
        "architecture": session.architecture,
        "mode": session.mode,
        "status": session.status,
        "started_at": str(session.started_at) if session.started_at else None,
        "stopped_at": str(session.stopped_at) if session.stopped_at else None,
        # Statistics
        "total_executions": session.total_executions,
        "executions_per_second": session.executions_per_second,
        "total_crashes": session.total_crashes,
        "unique_crashes": session.unique_crashes,
        "hangs": session.hangs,
        "coverage_edges": session.coverage_edges,
        "coverage_percentage": session.coverage_percentage,
        "corpus_size": session.corpus_size,
        # Severity breakdown
        "crashes_critical": session.crashes_critical,
        "crashes_high": session.crashes_high,
        "crashes_medium": session.crashes_medium,
        "crashes_low": session.crashes_low,
        # Findings
        "findings": findings,
        "crashes": crashes,
        "memory_errors": memory_errors,
        "coverage_data": session.coverage_data,
        "ai_analysis": session.ai_analysis,
    }


def _fetch_fuzzing_campaign_report_data(db: Session, report_id: int) -> Dict[str, Any]:
    """Fetch detailed data from a Fuzzing Campaign Report (Agentic Binary Fuzzer)."""
    report = db.query(models.FuzzingCampaignReport).filter(
        models.FuzzingCampaignReport.id == report_id
    ).first()
    if not report:
        return {"error": f"Fuzzing campaign report {report_id} not found"}

    # Process crashes from the report
    crashes = report.crashes or []
    findings = []
    for crash in crashes:
        exploitability = crash.get("exploitability", "unknown").lower()
        # Map exploitability to severity
        if exploitability == "exploitable":
            severity = "critical"
        elif exploitability == "probably_exploitable":
            severity = "high"
        elif exploitability == "probably_not_exploitable":
            severity = "medium"
        else:
            severity = "low"

        findings.append({
            "type": crash.get("crash_type", "Unknown crash"),
            "severity": severity,
            "crash_id": crash.get("crash_id", ""),
            "exploitability": exploitability,
            "confidence": crash.get("confidence", 0),
            "impact": crash.get("impact", ""),
            "recommendation": crash.get("recommendation", ""),
        })

    # Extract key findings from report data
    key_findings = []
    if report.report_data and report.report_data.get("key_findings"):
        key_findings = report.report_data["key_findings"]

    return {
        "report_id": report_id,
        "campaign_id": report.campaign_id,
        "binary_name": report.binary_name,
        "binary_hash": report.binary_hash,
        "binary_type": report.binary_type,
        "architecture": report.architecture,
        "status": report.status,
        "started_at": str(report.started_at) if report.started_at else None,
        "completed_at": str(report.completed_at) if report.completed_at else None,
        "duration_seconds": report.duration_seconds,
        # Key metrics
        "total_executions": report.total_executions,
        "executions_per_second": report.executions_per_second,
        "final_coverage": report.final_coverage,
        "unique_crashes": report.unique_crashes,
        "exploitable_crashes": report.exploitable_crashes,
        "total_decisions": report.total_decisions,
        # AI Analysis
        "executive_summary": report.executive_summary,
        "findings_summary": report.findings_summary,
        "recommendations": report.recommendations,
        "risk_rating": report.report_data.get("risk_rating") if report.report_data else None,
        "key_findings": key_findings,
        "strategy_effectiveness": report.report_data.get("strategy_effectiveness") if report.report_data else None,
        # Findings
        "findings": findings,
        "crashes": crashes,
        "decisions": report.decisions,
        "coverage_data": report.coverage_data,
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
        "nmap_scans": [],
        "pcap_reports": [],
        "api_tester_reports": [],
        "re_reports": [],
        "fuzzing_sessions": [],
        "agentic_fuzzer_reports": [],
        "dynamic_scans": [],
        "binary_fuzzer_sessions": [],
        "fuzzing_campaign_reports": [],
        "mitm_analysis_reports": [],
    }

    counts = {
        "security_scan": 0,
        "network_report": 0,
        "ssl_scan": 0,
        "dns_scan": 0,
        "traceroute_scan": 0,
        "nmap_scan": 0,
        "pcap_report": 0,
        "api_tester_report": 0,
        "re_report": 0,
        "fuzzing_session": 0,
        "agentic_fuzzer_report": 0,
        "dynamic_scan": 0,
        "binary_fuzzer_session": 0,
        "fuzzing_campaign_report": 0,
        "mitm_analysis_report": 0,
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
        elif scan.scan_type == "nmap_scan":
            data = _fetch_nmap_scan_data(db, scan.scan_id)
            aggregated["nmap_scans"].append(data)
            counts["nmap_scan"] += 1
        elif scan.scan_type == "pcap_report":
            data = _fetch_pcap_report_data(db, scan.scan_id)
            aggregated["pcap_reports"].append(data)
            counts["pcap_report"] += 1
        elif scan.scan_type == "api_tester_report":
            data = _fetch_api_tester_report_data(db, scan.scan_id)
            aggregated["api_tester_reports"].append(data)
            counts["api_tester_report"] += 1
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
        elif scan.scan_type == "dynamic_scan":
            data = _fetch_dynamic_scan_data(db, scan.scan_id)
            aggregated["dynamic_scans"].append(data)
            counts["dynamic_scan"] += 1
        elif scan.scan_type == "binary_fuzzer_session":
            data = _fetch_binary_fuzzer_session_data(db, scan.scan_id)
            aggregated["binary_fuzzer_sessions"].append(data)
            counts["binary_fuzzer_session"] += 1
        elif scan.scan_type == "fuzzing_campaign_report":
            data = _fetch_fuzzing_campaign_report_data(db, scan.scan_id)
            aggregated["fuzzing_campaign_reports"].append(data)
            counts["fuzzing_campaign_report"] += 1
        elif scan.scan_type == "mitm_analysis_report":
            data = _fetch_mitm_analysis_report_data(db, scan.scan_id)
            aggregated["mitm_analysis_reports"].append(data)
            counts["mitm_analysis_report"] += 1
    
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
    
    # Add MITM traffic analysis data
    if aggregated_data.get("mitm_analysis_reports"):
        prompt += """
## MITM TRAFFIC ANALYSIS DATA
"""
        for i, mr in enumerate(aggregated_data["mitm_analysis_reports"], 1):
            prompt += f"""
### MITM Analysis {i}: {mr.get('title', 'Unknown')}
- Proxy ID: {mr.get('proxy_id', 'N/A')}
- Session ID: {mr.get('session_id', 'N/A')}
- Created: {mr.get('created_at', 'N/A')}
- Traffic Analyzed: {mr.get('traffic_analyzed', 0)} requests
- Rules Active: {mr.get('rules_active', 0)}
- Risk Level: {mr.get('risk_level', 'N/A')}
- Risk Score: {mr.get('risk_score', 0)}/100
- Findings Count: {mr.get('findings_count', 0)}

**3-Pass Analysis Stats:**
- Analysis Passes: {mr.get('analysis_passes', 'N/A')}
- Pass 1 Findings: {mr.get('pass1_findings', 0)}
- Pass 2 AI Findings: {mr.get('pass2_ai_findings', 0)}
- After Deduplication: {mr.get('after_dedup', 0)}
- False Positives Removed: {mr.get('false_positives_removed', 0)}
"""
            if mr.get("summary"):
                prompt += f"""
**Summary:** {mr.get('summary')}
"""
            if mr.get("findings"):
                findings = mr.get("findings", [])[:20]
                prompt += f"""
**🔴 MITM Findings ({len(findings)} shown, {mr.get('findings_count', 0)} total):**
{json.dumps(findings, indent=2)}
"""
            if mr.get("attack_paths"):
                prompt += f"""
**Attack Paths Identified:**
{json.dumps(mr.get('attack_paths', [])[:5], indent=2)}
"""
            if mr.get("recommendations"):
                recs = mr.get("recommendations", [])[:10]
                prompt += f"""
**Recommendations ({len(recs)}):**
{json.dumps(recs, indent=2)}
"""
            if mr.get("cve_references"):
                prompt += f"""
**CVE References:**
{json.dumps(mr.get('cve_references', [])[:10], indent=2)}
"""
            if mr.get("exploit_references"):
                prompt += f"""
**Exploit References:**
{json.dumps(mr.get('exploit_references', [])[:10], indent=2)}
"""
            if mr.get("ai_exploitation_writeup"):
                writeup = mr.get("ai_exploitation_writeup", "")[:3000]
                prompt += f"""
**AI Exploitation Writeup:**
{writeup}
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
    docs_metadata = {"uploaded_documents": [], "analysis_reports": []}
    if request.supporting_documents:
        for doc in request.supporting_documents:
            docs_metadata["uploaded_documents"].append({
                "filename": doc.filename,
                "content_type": doc.content_type,
                "description": doc.description,
            })
    if request.document_analysis_report_ids:
        docs_metadata["analysis_reports"] = list(request.document_analysis_report_ids)
    if docs_metadata["uploaded_documents"] or docs_metadata["analysis_reports"]:
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
        
        # Calculate dynamic context budget based on what data sources are present
        total_findings = sum(
            len(scan.get("findings", [])) for scan in aggregated_data.get("security_scans", [])
        )
        context_budget = ContextBudget.calculate_budget(
            num_documents=len(request.supporting_documents) if request.supporting_documents else 0,
            total_doc_chars=0,  # Will be updated after parsing
            has_security_scans=len(aggregated_data.get("security_scans", [])) > 0,
            has_network=len(aggregated_data.get("network_reports", [])) > 0,
            has_binary=(
                len(aggregated_data.get("binary_fuzzer_sessions", [])) > 0 or
                len(aggregated_data.get("re_reports", [])) > 0
            ),
            has_mitm=len(aggregated_data.get("mitm_analysis_reports", [])) > 0,
            has_fuzzing=(
                len(aggregated_data.get("fuzzing_sessions", [])) > 0 or
                len(aggregated_data.get("agentic_fuzzer_reports", [])) > 0
            ),
            num_findings=total_findings,
        )
        logger.info(f"Dynamic context budget allocation: {context_budget.to_dict()}")

        # Process supporting documents using offline document parser
        # Properly parses PDFs, Word docs, Excel, OpenAPI specs, etc.
        supporting_docs_text = None
        parsed_documents: List[ParsedDocument] = []
        docs_for_agents = ""  # Prioritized content for agents
        document_processing_stats = {}
        analysis_report_context = ""
        analysis_report_brief = ""

        if request.supporting_documents:
            try:
                doc_parser = DocumentParserService()
                docs_text_parts = []
                security_excerpts_all = []
                api_endpoints_all = []

                for doc in request.supporting_documents:
                    try:
                        # Parse document properly (handles PDF, Word, Excel, OpenAPI, etc.)
                        parsed = doc_parser.parse_document(
                            filename=doc.filename,
                            content_base64=doc.content_base64,
                            content_type=doc.content_type,
                            description=doc.description,
                        )
                        parsed_documents.append(parsed)

                        # Collect security excerpts (high-priority content)
                        security_excerpts_all.extend(parsed.security_excerpts)

                        # Collect API endpoints if OpenAPI spec
                        api_endpoints_all.extend(parsed.api_endpoints)

                        # Build document text with metadata
                        doc_description = f" - {doc.description}" if doc.description else ""
                        doc_meta = f"[Type: {parsed.document_type.value}, Pages: {parsed.total_pages or 'N/A'}, Chars: {parsed.total_chars}]"

                        # Use prioritized content (security-relevant first)
                        prioritized_content = parsed.get_prioritized_content(max_chars=100000)

                        docs_text_parts.append(
                            f"### Document: {doc.filename}{doc_description}\n{doc_meta}\n\n{prioritized_content}"
                        )

                        logger.info(
                            f"Parsed document: {doc.filename} "
                            f"(type={parsed.document_type.value}, "
                            f"chars={parsed.total_chars}, "
                            f"sections={len(parsed.sections)}, "
                            f"security_excerpts={len(parsed.security_excerpts)}, "
                            f"api_endpoints={len(parsed.api_endpoints)})"
                        )

                        if parsed.parse_errors:
                            logger.warning(f"Document parse warnings for {doc.filename}: {parsed.parse_errors}")

                    except Exception as e:
                        logger.warning(f"Could not parse document {doc.filename}: {e}")
                        # Fallback to raw decode
                        try:
                            content = base64.b64decode(doc.content_base64).decode("utf-8", errors="ignore")
                            docs_text_parts.append(f"### Document: {doc.filename}\n\n{content[:75000]}")
                        except Exception as e2:
                            logger.error(f"Failed to decode document {doc.filename}: {e2}")

                if docs_text_parts:
                    supporting_docs_text = "\n\n---\n\n".join(docs_text_parts)
                    logger.info(f"Total supporting documentation: {len(supporting_docs_text)} chars from {len(docs_text_parts)} documents")

                # Build prioritized content for agents (security excerpts + API endpoints first)
                agent_content_parts = []

                # 1. Security-relevant excerpts (highest priority)
                if security_excerpts_all:
                    agent_content_parts.append("## Security-Relevant Document Excerpts\n")
                    for excerpt in security_excerpts_all[:30]:  # Top 30 excerpts
                        agent_content_parts.append(f"- {excerpt[:500]}\n")

                # 2. API endpoints from OpenAPI specs
                if api_endpoints_all:
                    agent_content_parts.append("\n## API Endpoints from Documentation\n")
                    for ep in api_endpoints_all[:100]:  # Top 100 endpoints
                        security_info = f" [SECURED]" if ep.get("security") else ""
                        agent_content_parts.append(
                            f"- {ep.get('method', 'GET')} {ep.get('path', '/')}{security_info}: {ep.get('summary', '')}\n"
                        )

                # 3. High-importance sections from all documents
                all_high_sections = []
                for parsed in parsed_documents:
                    for section in parsed.sections:
                        if section.importance_score >= 0.6:
                            all_high_sections.append((section.importance_score, section, parsed.filename))

                all_high_sections.sort(key=lambda x: x[0], reverse=True)

                if all_high_sections:
                    agent_content_parts.append("\n## Important Document Sections\n")
                    for score, section, filename in all_high_sections[:20]:  # Top 20 sections
                        agent_content_parts.append(
                            f"\n### {section.title} (from {filename})\n{section.content[:1500]}\n"
                        )

                docs_for_agents = "".join(agent_content_parts)

                # Recalculate budget now that we know total document size
                total_doc_chars = sum(p.total_chars for p in parsed_documents)
                context_budget = ContextBudget.calculate_budget(
                    num_documents=len(parsed_documents),
                    total_doc_chars=total_doc_chars,
                    has_security_scans=len(aggregated_data.get("security_scans", [])) > 0,
                    has_network=len(aggregated_data.get("network_reports", [])) > 0,
                    has_binary=(
                        len(aggregated_data.get("binary_fuzzer_sessions", [])) > 0 or
                        len(aggregated_data.get("re_reports", [])) > 0
                    ),
                    has_mitm=len(aggregated_data.get("mitm_analysis_reports", [])) > 0,
                    has_fuzzing=(
                        len(aggregated_data.get("fuzzing_sessions", [])) > 0 or
                        len(aggregated_data.get("agentic_fuzzer_reports", [])) > 0
                    ),
                    num_findings=total_findings,
                )
                doc_budget = context_budget.documents_budget
                logger.info(f"Recalculated document budget: {doc_budget} chars (total doc content: {total_doc_chars} chars)")

                # If still under limit, add more general content
                remaining = doc_budget - len(docs_for_agents)
                if remaining > 5000 and supporting_docs_text:
                    docs_for_agents += f"\n\n## Additional Document Content\n\n{supporting_docs_text[:remaining]}"

                # For very large documents, use smart summaries
                if total_doc_chars > doc_budget * 2:
                    logger.info(f"Documents are large ({total_doc_chars} chars). Using smart summaries.")
                    # Use the smart document preparation
                    smart_docs, doc_stats = prepare_documents_for_context(
                        parsed_documents, doc_budget, prioritize_security=True
                    )
                    # Combine smart docs with already-extracted excerpts and endpoints
                    if len(smart_docs) > len(docs_for_agents):
                        docs_for_agents = smart_docs
                    document_processing_stats = doc_stats

                logger.info(
                    f"Prepared {len(docs_for_agents)} chars of prioritized document content for agents "
                    f"({len(security_excerpts_all)} security excerpts, {len(api_endpoints_all)} API endpoints, "
                    f"budget: {doc_budget} chars)"
                )

            except Exception as doc_error:
                logger.error(f"Document processing failed: {doc_error}")
                # Fallback to simple processing
                docs_text_parts = []
                for doc in request.supporting_documents:
                    try:
                        content = base64.b64decode(doc.content_base64).decode("utf-8", errors="ignore")
                        docs_text_parts.append(f"### Document: {doc.filename}\n\n{content[:75000]}")
                    except Exception:
                        pass
                if docs_text_parts:
                    supporting_docs_text = "\n\n---\n\n".join(docs_text_parts)
                    docs_for_agents = supporting_docs_text[:75000]

        # Attach existing document analysis reports (summaries only)
        if request.document_analysis_report_ids:
            reports = db.query(models.DocumentAnalysisReport).filter(
                models.DocumentAnalysisReport.project_id == request.project_id,
                models.DocumentAnalysisReport.id.in_(request.document_analysis_report_ids),
                models.DocumentAnalysisReport.status == "completed",
            ).all()

            report_blocks = []
            report_brief_parts = []
            for report in reports:
                report_block = [f"## Document Analysis Report {report.id}"]
                if report.combined_summary:
                    report_block.append("### Combined Summary\n" + report.combined_summary)
                    report_brief_parts.append(report.combined_summary)
                if report.combined_key_points:
                    points = "\n".join([f"- {p}" for p in report.combined_key_points[:20]])
                    report_block.append("### Key Points\n" + points)
                    report_brief_parts.extend(report.combined_key_points[:20])

                for doc in report.documents:
                    if doc.summary:
                        report_block.append(f"### {doc.original_filename}\n{doc.summary}")
                    if doc.key_points:
                        report_block.append("\n".join([f"- {p}" for p in doc.key_points[:10]]))

                report_blocks.append("\n\n".join(report_block))

            if report_blocks:
                analysis_report_context = "\n\n---\n\n".join(report_blocks)
                analysis_report_brief = "\n".join([f"- {p}" for p in report_brief_parts if p])[:15000]
                logger.info(
                    f"Attached {len(report_blocks)} document analysis report summaries "
                    f"({len(analysis_report_context)} chars)"
                )

        if analysis_report_context:
            if supporting_docs_text:
                supporting_docs_text += "\n\n---\n\n" + analysis_report_context
            else:
                supporting_docs_text = analysis_report_context

            if docs_for_agents:
                docs_for_agents += "\n\n## Document Analysis Report Summaries\n" + analysis_report_brief
            else:
                docs_for_agents = "## Document Analysis Report Summaries\n" + analysis_report_brief
        
        # Source Code Deep Dive - Extract indicators from findings and search codebase
        # Using ENHANCED source code search with semantic pattern matching
        logger.info("Performing ENHANCED source code deep dive analysis...")
        indicators = _extract_indicators_from_findings(aggregated_data)
        indicator_counts = {k: len(v) for k, v in indicators.items()}
        logger.info(f"Extracted indicators: {indicator_counts}")
        
        # Use enhanced search with vulnerability pattern matching
        relevant_source_code = _enhanced_source_code_search(
            db, request.project_id, indicators, aggregated_data, max_chunks=75
        )
        source_code_context = _build_source_code_context(relevant_source_code)
        logger.info(f"Enhanced search found {len(relevant_source_code)} code chunks with relevance scores")
        
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
        
        # =====================================================================
        # DETECT CORROBORATED FINDINGS - Multi-source = Higher Confidence
        # =====================================================================
        corroborated_findings = _detect_corroborated_findings(aggregated_data)
        logger.info(f"Detected {len(corroborated_findings)} corroborated findings (multi-source)")
        
        # Convert to dict format for agents
        corroborated_data = [cf.to_dict() for cf in corroborated_findings]

        # =====================================================================
        # DOCUMENT-FINDING CORRELATION - Link findings to relevant documentation
        # =====================================================================
        document_finding_summary = {}
        if parsed_documents and corroborated_data:
            try:
                doc_parser = DocumentParserService()

                # Enrich corroborated findings with document correlations
                corroborated_data = doc_parser.correlate_findings_with_documents(
                    corroborated_data, parsed_documents, max_correlations_per_finding=3
                )

                # Get summary of documentation coverage
                document_finding_summary = doc_parser.get_document_summary_for_findings(
                    corroborated_data, parsed_documents
                )

                findings_with_docs = document_finding_summary.get("findings_with_documentation", 0)
                coverage_pct = document_finding_summary.get("documentation_coverage_percent", 0)
                logger.info(
                    f"Document-finding correlation complete: "
                    f"{findings_with_docs}/{len(corroborated_data)} findings have documentation references "
                    f"({coverage_pct}% coverage)"
                )
            except Exception as doc_corr_error:
                logger.warning(f"Document correlation failed (non-fatal): {doc_corr_error}")
                document_finding_summary = {"error": str(doc_corr_error)}

        # Track agent status for transparency
        agent_status = {
            "executive_summary": {"status": "pending", "error": None},
            "poc_scripts": {"status": "pending", "error": None},
            "attack_guides": {"status": "pending", "error": None},
            "prioritized_vulns": {"status": "pending", "error": None},
            "cross_analysis": {"status": "pending", "error": None},
            "attack_diagram": {"status": "pending", "error": None},
            "attack_chains": {"status": "pending", "error": None},
            "exploit_development": {"status": "pending", "error": None},
            "source_code_findings": {"status": "pending", "error": None},
        }
        
        # Run all agents in parallel for speed
        logger.info("Launching 9 parallel AI agents...")
        
        # Pass user requirements and supporting docs to ALL agents
        user_reqs = request.user_requirements or ""
        # Use prioritized document content (security excerpts, API endpoints, high-importance sections)
        # docs_for_agents was already built above with smart prioritization - up to 50K chars
        # If not built (no docs), initialize empty
        if not docs_for_agents and supporting_docs_text:
            docs_for_agents = supporting_docs_text[:75000]  # Fallback to simple truncation (30% doc budget)
        logger.info(f"Document content for agents: {len(docs_for_agents)} chars")
        
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
            _agent_executive_summary(genai_client, aggregated_data, data_counts, user_reqs, docs_for_agents, corroborated_data),
            _agent_poc_scripts(genai_client, aggregated_data, data_counts, user_reqs, docs_for_agents),
            _agent_attack_guides(genai_client, aggregated_data, data_counts, user_reqs, docs_for_agents),
            _agent_prioritized_vulns(genai_client, aggregated_data, data_counts, user_reqs, docs_for_agents, corroborated_data),
            _agent_cross_analysis(genai_client, aggregated_data, data_counts, user_reqs, docs_for_agents, corroborated_data),
            _agent_attack_surface_diagram(genai_client, aggregated_data, user_reqs, docs_for_agents),
            _agent_attack_chains(genai_client, aggregated_data, user_reqs, docs_for_agents),
            _agent_exploit_development(genai_client, aggregated_data, data_counts, user_reqs, docs_for_agents),
            _agent_source_code_findings(genai_client, aggregated_data, relevant_source_code, data_counts, user_reqs, docs_for_agents),
            return_exceptions=True,  # Don't fail if one agent fails
        )
        
        # Log results and track agent status
        logger.info("Multi-agent results:")
        
        if isinstance(exec_summary_result, Exception):
            logger.error(f"Executive summary agent failed: {exec_summary_result}")
            agent_status["executive_summary"] = {"status": "failed", "error": str(exec_summary_result)}
            exec_summary_result = {}
        else:
            agent_status["executive_summary"] = {"status": "success", "items": len(exec_summary_result.get('executive_summary', ''))}
            logger.info(f"  - executive_summary: {len(exec_summary_result.get('executive_summary', ''))} chars")
        
        if isinstance(poc_scripts, Exception):
            logger.error(f"PoC scripts agent failed: {poc_scripts}")
            agent_status["poc_scripts"] = {"status": "failed", "error": str(poc_scripts)}
            poc_scripts = []
        else:
            agent_status["poc_scripts"] = {"status": "success", "items": len(poc_scripts) if isinstance(poc_scripts, list) else 0}
            logger.info(f"  - poc_scripts: {len(poc_scripts) if isinstance(poc_scripts, list) else 'ERROR'}")
        
        if isinstance(attack_guides, Exception):
            logger.error(f"Attack guides agent failed: {attack_guides}")
            agent_status["attack_guides"] = {"status": "failed", "error": str(attack_guides)}
            attack_guides = []
        else:
            agent_status["attack_guides"] = {"status": "success", "items": len(attack_guides) if isinstance(attack_guides, list) else 0}
            logger.info(f"  - attack_guides: {len(attack_guides) if isinstance(attack_guides, list) else 'ERROR'}")
        
        if isinstance(prioritized_vulns, Exception):
            logger.error(f"Prioritized vulns agent failed: {prioritized_vulns}")
            agent_status["prioritized_vulns"] = {"status": "failed", "error": str(prioritized_vulns)}
            prioritized_vulns = []
        else:
            agent_status["prioritized_vulns"] = {"status": "success", "items": len(prioritized_vulns) if isinstance(prioritized_vulns, list) else 0}
            logger.info(f"  - prioritized_vulns: {len(prioritized_vulns) if isinstance(prioritized_vulns, list) else 'ERROR'}")
        
        if isinstance(cross_findings, Exception):
            logger.error(f"Cross findings agent failed: {cross_findings}")
            agent_status["cross_analysis"] = {"status": "failed", "error": str(cross_findings)}
            cross_findings = []
        else:
            agent_status["cross_analysis"] = {"status": "success", "items": len(cross_findings) if isinstance(cross_findings, list) else 0}
            logger.info(f"  - cross_findings: {len(cross_findings) if isinstance(cross_findings, list) else 'ERROR'}")
        
        if isinstance(attack_diagram, Exception):
            logger.error(f"Attack diagram agent failed: {attack_diagram}")
            agent_status["attack_diagram"] = {"status": "failed", "error": str(attack_diagram)}
            attack_diagram = ""
        else:
            agent_status["attack_diagram"] = {"status": "success", "items": len(attack_diagram) if isinstance(attack_diagram, str) else 0}
            logger.info(f"  - attack_diagram: {len(attack_diagram) if isinstance(attack_diagram, str) else 'ERROR'}")
        
        if isinstance(attack_chains, Exception):
            logger.error(f"Attack chains agent failed: {attack_chains}")
            agent_status["attack_chains"] = {"status": "failed", "error": str(attack_chains)}
            attack_chains = []
        else:
            agent_status["attack_chains"] = {"status": "success", "items": len(attack_chains) if isinstance(attack_chains, list) else 0}
            logger.info(f"  - attack_chains: {len(attack_chains) if isinstance(attack_chains, list) else 'ERROR'}")
        
        if isinstance(exploit_dev_areas, Exception):
            logger.error(f"Exploit dev areas agent failed: {exploit_dev_areas}")
            agent_status["exploit_development"] = {"status": "failed", "error": str(exploit_dev_areas)}
            exploit_dev_areas = []
        else:
            agent_status["exploit_development"] = {"status": "success", "items": len(exploit_dev_areas) if isinstance(exploit_dev_areas, list) else 0}
            logger.info(f"  - exploit_dev_areas: {len(exploit_dev_areas) if isinstance(exploit_dev_areas, list) else 'ERROR'}")
        
        if isinstance(source_code_findings, Exception):
            logger.error(f"Source code findings agent failed: {source_code_findings}")
            agent_status["source_code_findings"] = {"status": "failed", "error": str(source_code_findings)}
            source_code_findings = []
        else:
            agent_status["source_code_findings"] = {"status": "success", "items": len(source_code_findings) if isinstance(source_code_findings, list) else 0}
            logger.info(f"  - source_code_findings: {len(source_code_findings) if isinstance(source_code_findings, list) else 'ERROR'}")
        
        # =====================================================================
        # SYNTHESIS AGENT - Review all outputs, remove contradictions, fill gaps
        # =====================================================================
        logger.info("Running Synthesis Agent to review and improve outputs...")
        
        # Build agent outputs dict for synthesis
        agent_outputs_for_synthesis = {
            "executive_summary": exec_summary_result.get("executive_summary", "") if isinstance(exec_summary_result, dict) else "",
            "poc_scripts": poc_scripts if isinstance(poc_scripts, list) else [],
            "attack_guides": attack_guides if isinstance(attack_guides, list) else [],
            "prioritized_vulnerabilities": prioritized_vulns if isinstance(prioritized_vulns, list) else [],
            "cross_analysis_findings": cross_findings if isinstance(cross_findings, list) else [],
            "attack_surface_diagram": attack_diagram if isinstance(attack_diagram, str) else "",
            "attack_chains": attack_chains if isinstance(attack_chains, list) else [],
            "exploit_development": exploit_dev_areas if isinstance(exploit_dev_areas, list) else [],
            "source_code_findings": source_code_findings if isinstance(source_code_findings, list) else [],
        }
        
        # Convert agent_status to simple string format for synthesis
        agent_status_simple = {k: v.get("status", "unknown") for k, v in agent_status.items()}
        
        synthesis_result = await _agent_synthesis(
            genai_client,
            agent_outputs=agent_outputs_for_synthesis,
            corroborated_findings=corroborated_data,
            agent_status=agent_status_simple,
            user_requirements=user_reqs,
        )
        
        if synthesis_result:
            logger.info(f"Synthesis agent produced: confidence_score={synthesis_result.get('overall_confidence_score', 'N/A')}, "
                       f"consistency_issues={len(synthesis_result.get('consistency_issues', []))}, "
                       f"coverage_gaps={len(synthesis_result.get('coverage_gaps', []))}")
        
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
        
        # Apply structured validation to all agent outputs
        # This ensures consistent, well-formed data and fixes common AI output issues
        logger.info("Validating and fixing agent outputs...")
        
        # Validate cross-analysis findings
        validated_cross = _validate_and_fix_cross_findings(
            cross_findings if isinstance(cross_findings, list) else []
        )
        db_report.cross_analysis_findings = validated_cross
        
        db_report.attack_surface_diagram = attack_diagram if isinstance(attack_diagram, str) else ""
        db_report.attack_chains = attack_chains if isinstance(attack_chains, list) else []
        
        # Validate attack guides
        validated_guides = _validate_and_fix_attack_guides(
            attack_guides if isinstance(attack_guides, list) else []
        )
        db_report.beginner_attack_guide = validated_guides
        
        # Validate PoC scripts
        validated_pocs = _validate_and_fix_poc_scripts(
            poc_scripts if isinstance(poc_scripts, list) else []
        )
        db_report.poc_scripts = validated_pocs
        
        db_report.exploit_development_areas = exploit_dev_areas if isinstance(exploit_dev_areas, list) else []
        
        # Validate prioritized vulnerabilities
        validated_vulns = _validate_and_fix_prioritized_vulns(
            prioritized_vulns if isinstance(prioritized_vulns, list) else []
        )
        db_report.prioritized_vulnerabilities = validated_vulns
        
        db_report.source_code_findings = source_code_findings if isinstance(source_code_findings, list) else []
        db_report.documentation_analysis = ""
        
        # Log validation results
        logger.info(f"Validation results: "
                    f"cross_findings={len(validated_cross)}, "
                    f"attack_guides={len(validated_guides)}, "
                    f"poc_scripts={len(validated_pocs)}, "
                    f"prioritized_vulns={len(validated_vulns)}")

        # =====================================================================
        # REASONING ENGINE - True AI reasoning for enhanced correlation
        # Dynamically discovers correlations, synthesizes exploit chains,
        # verifies PoC scripts, and applies security-first principles
        # =====================================================================
        reasoning_result = {}
        try:
            logger.info("Running AI Reasoning Engine for enhanced analysis...")

            # Initialize the reasoning engine
            reasoning_engine = CombinedAnalysisReasoningEngine(
                depth=ReasoningDepth.STANDARD
            )

            # Build target description from project info
            target_desc = request.project_info or "Security assessment target"

            # Run the full reasoning analysis with aggregated data
            reasoning_result = await reasoning_engine.run_full_analysis(
                aggregated_data=aggregated_data,
                target_description=target_desc,
            )

            stats = reasoning_result.get("statistics", {})
            logger.info(f"Reasoning engine completed: "
                       f"correlations={stats.get('correlations_discovered', 0)}, "
                       f"novel_correlations={stats.get('novel_correlations', 0)}, "
                       f"exploit_chains={stats.get('exploit_chains_synthesized', 0)}")

            # Enhance cross-analysis findings with AI-discovered correlations
            if reasoning_result.get("correlations"):
                for corr in reasoning_result["correlations"]:
                    # Build a descriptive title from source findings
                    corr_title = f"{corr.get('source_a', 'Source A')} + {corr.get('source_b', 'Source B')} Correlation"
                    validated_cross.append({
                        "title": corr_title,
                        "description": corr.get("reasoning", ""),
                        "finding_a": corr.get("finding_a_summary", ""),
                        "finding_b": corr.get("finding_b_summary", ""),
                        "correlation_type": corr.get("correlation_type", ""),
                        "attack_narrative": corr.get("exploitation_narrative", ""),
                        "ai_discovered": True,
                        "is_novel": corr.get("novel", False),
                        "confidence_score": corr.get("confidence", 0.8),
                    })
                db_report.cross_analysis_findings = validated_cross

            # Enhance attack chains with synthesized exploit chains
            if reasoning_result.get("exploit_chains"):
                enhanced_chains = attack_chains if isinstance(attack_chains, list) else []
                for chain in reasoning_result["exploit_chains"]:
                    enhanced_chains.append({
                        "title": chain.get("name", "AI-Synthesized Exploit Chain"),
                        "description": chain.get("summary", ""),
                        "entry_point": chain.get("entry_point", ""),
                        "final_impact": chain.get("final_impact", ""),
                        "prerequisites": chain.get("prerequisites", []),
                        "steps": chain.get("steps", []),
                        "total_steps": chain.get("total_steps", 0),
                        "estimated_complexity": chain.get("estimated_complexity", "Medium"),
                        "risk_score": chain.get("risk_score", 0.5),
                        "reasoning": chain.get("reasoning", ""),
                        "ai_synthesized": True,
                    })
                db_report.attack_chains = enhanced_chains

            # Add security reasoning insights to executive summary if available
            security_reasoning = reasoning_result.get("security_reasoning", {})
            if security_reasoning and db_report.executive_summary:
                novel_insights = reasoning_result.get("novel_insights", [])
                if novel_insights:
                    insight_summary = "\n\n## AI-Discovered Novel Insights\n\n"
                    for insight in novel_insights[:5]:  # Top 5 novel insights
                        insight_title = f"{insight.get('source_a', '')} + {insight.get('source_b', '')} Correlation"
                        insight_summary += f"- **{insight_title}**: {insight.get('reasoning', '')[:200]}...\n"
                    db_report.executive_summary += insight_summary

        except Exception as reasoning_error:
            logger.warning(f"Reasoning engine encountered an error (non-fatal): {reasoning_error}")
            reasoning_result = {"error": str(reasoning_error)}

        # =====================================================================
        # EVIDENCE FRAMEWORK - Generate evidence collection guidance
        # Helps pentesters prove findings and avoid false positives
        # =====================================================================
        evidence_guides = []
        try:
            logger.info("Generating evidence collection guides...")
            evidence_framework = EvidenceFramework()

            # Collect all findings for evidence guidance
            all_findings_for_evidence = []
            for scan in aggregated_data.get("security_scans", []):
                for finding in scan.get("findings", []):
                    all_findings_for_evidence.append(finding)
                for es in scan.get("exploit_scenarios", []):
                    all_findings_for_evidence.append({
                        "id": es.get("id", f"es_{hash(es.get('title', ''))%10000}"),
                        "title": es.get("title", "Unknown"),
                        "type": "exploit_scenario",
                        "severity": es.get("severity", "High"),
                        "description": es.get("narrative", ""),
                    })

            # Generate evidence guides for high/critical findings
            high_priority_findings = [
                f for f in all_findings_for_evidence
                if f.get("severity", "").lower() in ["critical", "high"]
            ]
            evidence_guides = evidence_framework.generate_evidence_guides_batch(
                high_priority_findings[:25]  # Top 25 high/critical findings
            )
            logger.info(f"Generated {len(evidence_guides)} evidence collection guides")

        except Exception as evidence_error:
            logger.warning(f"Evidence framework encountered an error (non-fatal): {evidence_error}")
            evidence_guides = []

        # =====================================================================
        # CONTEXTUAL RISK SCORING - Adjust risk based on real-world context
        # Considers auth requirements, network position, compensating controls
        # =====================================================================
        contextual_risk_scores = []
        try:
            logger.info("Calculating contextual risk scores...")
            risk_scorer = ContextualRiskScorer()

            # Build scan context for factor detection
            scan_context = {
                "waf_detected": any(
                    "waf" in str(f).lower() or "firewall" in str(f).lower()
                    for scan in aggregated_data.get("security_scans", [])
                    for f in scan.get("findings", [])
                ),
                "rate_limiting_detected": any(
                    "rate limit" in str(f).lower()
                    for scan in aggregated_data.get("security_scans", [])
                    for f in scan.get("findings", [])
                ),
            }

            # Calculate contextual risk for all findings
            all_findings_for_risk = []
            for scan in aggregated_data.get("security_scans", []):
                all_findings_for_risk.extend(scan.get("findings", []))

            contextual_risk_scores = risk_scorer.calculate_risk_scores_batch(
                all_findings_for_risk,
                scan_context=scan_context,
            )

            # Sort by contextual risk score
            contextual_risk_scores.sort(
                key=lambda x: x.get("contextual_risk_score", 0),
                reverse=True
            )

            logger.info(f"Calculated {len(contextual_risk_scores)} contextual risk scores")

            # Add contextual risk summary to executive summary
            if contextual_risk_scores and db_report.executive_summary:
                immediate_count = sum(
                    1 for s in contextual_risk_scores
                    if s.get("priority_level") == "immediate"
                )
                high_count = sum(
                    1 for s in contextual_risk_scores
                    if s.get("priority_level") == "high"
                )

                if immediate_count > 0 or high_count > 0:
                    risk_summary = "\n\n## Contextual Risk Priority\n\n"
                    if immediate_count > 0:
                        risk_summary += f"🔴 **{immediate_count} findings require immediate attention** (24-48 hours)\n"
                    if high_count > 0:
                        risk_summary += f"🟠 **{high_count} findings are high priority** (1-2 weeks)\n"

                    # Show top 3 immediate priority items
                    immediate_items = [
                        s for s in contextual_risk_scores
                        if s.get("priority_level") == "immediate"
                    ][:3]
                    if immediate_items:
                        risk_summary += "\n**Immediate Actions:**\n"
                        for item in immediate_items:
                            drivers = item.get("key_risk_drivers", [])
                            driver_text = drivers[0] if drivers else "High contextual risk"
                            risk_summary += f"- **{item.get('finding_title', 'Finding')}** ({item.get('contextual_risk_score', 0):.0f}/100): {driver_text}\n"

                    db_report.executive_summary += risk_summary

        except Exception as risk_error:
            logger.warning(f"Contextual risk scoring encountered an error (non-fatal): {risk_error}")
            contextual_risk_scores = []

        # =====================================================================
        # CONTROL BYPASS RECOMMENDATIONS - How to bypass compensating controls
        # Helps pentesters turn "protected" vulns into exploitable ones
        # =====================================================================
        control_bypass_recommendations = []
        try:
            logger.info("Generating control bypass recommendations...")
            bypass_service = ControlBypassService()

            # Collect detected controls from contextual risk scores
            detected_controls = []
            for score in contextual_risk_scores:
                factors = score.get("factors", {})
                controls = factors.get("compensating_controls", [])
                for control in controls:
                    # Avoid duplicates
                    control_name = control.get("name", "")
                    if control_name and not any(c.get("name") == control_name for c in detected_controls):
                        detected_controls.append({
                            "name": control_name,
                            "control_type": control_name.lower().replace(" ", "_"),
                            "effectiveness": control.get("effectiveness", 0.5),
                        })

            if detected_controls:
                # Get bypass recommendations for each detected control
                control_bypass_recommendations = bypass_service.get_bypass_recommendations(
                    detected_controls
                )
                logger.info(f"Generated bypass recommendations for {len(control_bypass_recommendations)} controls")

                # Add bypass summary to executive summary if significant controls detected
                if control_bypass_recommendations and db_report.executive_summary:
                    bypass_summary = "\n\n## Compensating Control Bypass Opportunities\n\n"
                    bypass_summary += f"Detected **{len(detected_controls)} compensating controls** protecting vulnerable endpoints:\n"
                    for rec in control_bypass_recommendations[:3]:
                        control_name = rec.get("control_name", "Control")
                        techniques_count = len(rec.get("bypass_techniques", []))
                        bypass_summary += f"- **{control_name}**: {techniques_count} bypass techniques available\n"
                    bypass_summary += "\nSee detailed bypass techniques in the Control Evasion section below.\n"
                    db_report.executive_summary += bypass_summary
            else:
                logger.info("No compensating controls detected - skipping bypass recommendations")

        except Exception as bypass_error:
            logger.warning(f"Control bypass service encountered an error (non-fatal): {bypass_error}")
            control_bypass_recommendations = []

        # Build parsed documents summary for storage
        parsed_docs_summary = []
        for parsed in parsed_documents:
            parsed_docs_summary.append({
                "filename": parsed.filename,
                "type": parsed.document_type.value,
                "total_chars": parsed.total_chars,
                "total_pages": parsed.total_pages,
                "sections_count": len(parsed.sections),
                "security_excerpts_count": len(parsed.security_excerpts),
                "api_endpoints_count": len(parsed.api_endpoints),
                "api_endpoints": parsed.api_endpoints[:50],  # Store top 50 endpoints
                "high_importance_sections": [
                    {"title": s.title, "keywords": s.keywords_found[:5]}
                    for s in parsed.sections if s.importance_score >= 0.7
                ][:20],
            })

        # Store agent status, corroborated findings, synthesis, reasoning, evidence, risk, bypass, and docs in raw response
        db_report.raw_ai_response = json.dumps({
            "multi_agent": True,
            "agent_status": agent_status,
            "corroborated_findings": corroborated_data,
            "corroborated_count": len(corroborated_data),
            "synthesis_result": synthesis_result if synthesis_result else {},
            "reasoning_engine_result": reasoning_result,
            "evidence_collection_guides": evidence_guides,
            "contextual_risk_scores": contextual_risk_scores,
            "control_bypass_recommendations": control_bypass_recommendations,
            "parsed_documents": parsed_docs_summary,
            "document_stats": {
                "total_documents": len(parsed_documents),
                "total_chars_processed": sum(p.total_chars for p in parsed_documents),
                "total_security_excerpts": sum(len(p.security_excerpts) for p in parsed_documents),
                "total_api_endpoints": sum(len(p.api_endpoints) for p in parsed_documents),
                "document_types": list(set(p.document_type.value for p in parsed_documents)),
                "chars_sent_to_agents": len(docs_for_agents) if docs_for_agents else 0,
                "budget_allocation": context_budget.to_dict() if context_budget else {},
                "processing_stats": document_processing_stats,
            } if parsed_documents else {},
            "document_finding_correlation": document_finding_summary,
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
    supporting_docs: str = "",
    corroborated_findings: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Agent 1: Generate executive summary and overall risk assessment with MARKDOWN formatting."""
    from google.genai import types
    
    corroborated_findings = corroborated_findings or []
    
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
    
    # Add supporting documentation context
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION CONTEXT
The following documentation was provided for context:
{supporting_docs[:15000]}

Reference this documentation when relevant to the findings.
"""
    
    # Add corroborated findings - these are HIGH CONFIDENCE findings
    corroboration_section = ""
    if corroborated_findings:
        high_confidence = [cf for cf in corroborated_findings if cf.get("confidence_level") == "High"]
        medium_confidence = [cf for cf in corroborated_findings if cf.get("confidence_level") == "Medium"]

        # Format findings with document context
        def format_finding_with_docs(finding):
            base = {k: v for k, v in finding.items() if k not in ["document_correlations"]}
            doc_refs = finding.get("document_correlations", [])
            if doc_refs:
                base["documentation_context"] = [
                    f"{d['document']}: {d['excerpt'][:200]}..."
                    for d in doc_refs[:2]
                ]
                base["has_documentation"] = True
            return base

        high_conf_formatted = [format_finding_with_docs(cf) for cf in high_confidence[:5]]
        med_conf_formatted = [format_finding_with_docs(cf) for cf in medium_confidence[:5]]

        # Count findings with documentation
        findings_with_docs = sum(1 for cf in corroborated_findings if cf.get("has_documentation"))

        corroboration_section = f"""
## ⚠️ HIGH-CONFIDENCE FINDINGS (Corroborated Across Multiple Sources)
These findings were detected by MULTIPLE independent scan types, making them HIGHLY LIKELY TO BE REAL:

**Documentation Coverage:** {findings_with_docs}/{len(corroborated_findings)} findings have related documentation

**High Confidence ({len(high_confidence)} findings - 3+ sources):**
{json.dumps(high_conf_formatted, indent=2) if high_conf_formatted else "None"}

**Medium Confidence ({len(medium_confidence)} findings - 2 sources):**
{json.dumps(med_conf_formatted, indent=2) if med_conf_formatted else "None"}

IMPORTANT:
- Corroborated findings should be given PRIORITY as they have the highest certainty of being exploitable.
- When a finding has "documentation_context", reference the relevant documentation in your analysis.
- Findings with documentation links show exactly where in the docs the vulnerable functionality is described.
"""
    
    prompt = f"""You are an elite security consultant writing an EXECUTIVE SUMMARY for a penetration test report.

## INPUT DATA SUMMARY
- Total Findings: {data_counts.get('total_findings', 0)}
- Critical Findings: {severity_counts['Critical']}
- High Findings: {severity_counts['High']}
- Medium Findings: {severity_counts['Medium']}
- Low Findings: {severity_counts['Low']}
- Exploit Scenarios Identified: {data_counts.get('total_exploit_scenarios', 0)}
- Corroborated Findings (multi-source): {len(corroborated_findings)}

Scans Analyzed:
{chr(10).join(findings_summary)}
{user_req_section}{docs_section}{corroboration_section}

## YOUR TASK
Generate a CONCISE executive summary. This is a HIGH-LEVEL OVERVIEW only.

IMPORTANT: 
- Do NOT include detailed exploit scenarios or step-by-step instructions
- Do NOT list every vulnerability in detail
- The detailed information is in OTHER SECTIONS of the report
- Focus on: Overall posture, key risks, business impact, and top recommendations
- HIGHLIGHT corroborated findings (detected by multiple sources) as HIGH CONFIDENCE issues
- Mention when findings are verified across multiple scan types (this increases confidence)

Return a JSON object (ONLY valid JSON, nothing else):
```json
{{
    "executive_summary": "## Security Assessment Overview\\n\\nOpening paragraph summarizing overall security posture...\\n\\n## High-Confidence Findings (Multi-Source Corroborated)\\n\\nThese issues were detected by multiple independent scans...\\n\\n## Key Risk Areas\\n\\n**1. Critical Authentication Issues:** Brief description...\\n\\n**2. Injection Vulnerabilities:** Brief description...\\n\\n**3. Sensitive Data Exposure:** Brief description...\\n\\n## Business Impact\\n\\nExplain the potential business impact in 2-3 paragraphs...\\n\\n## Priority Recommendations\\n\\n1. **Immediate Action Required:** Fix critical auth issues\\n2. **Short-term:** Address injection vulnerabilities\\n3. **Medium-term:** Implement security controls\\n\\n## Conclusion\\n\\nClosing paragraph with overall assessment...",
    "overall_risk_level": "Critical",
    "overall_risk_score": 95,
    "risk_justification": "This risk level is assigned because the application has {severity_counts['Critical']} critical and {severity_counts['High']} high severity vulnerabilities that can be exploited for unauthorized access. The combination of authentication weaknesses and injection flaws creates multiple attack paths.",
    "high_confidence_finding_count": {len([cf for cf in corroborated_findings if cf.get('confidence_level') == 'High'])}
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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    supporting_docs: str = "",
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
    
    # Add supporting documentation context
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION
{supporting_docs[:12000]}
Reference this documentation when creating PoC scripts (e.g., API specs, endpoint details).
"""
    
    prompt = f"""You are an expert penetration tester creating WORKING PROOF-OF-CONCEPT SCRIPTS.

## EXPLOIT SCENARIOS (with existing PoC hints)
{json.dumps(exploit_scenarios[:7], indent=2)}
{user_req_section}{docs_section}

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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    supporting_docs: str = "",
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
    
    # Add supporting documentation context
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION
{supporting_docs[:12000]}
Reference this documentation for accurate endpoint details and attack context.
"""
    
    prompt = f"""You are a cybersecurity instructor creating BEGINNER-FRIENDLY attack guides.

## EXPLOIT SCENARIOS
{json.dumps(exploit_scenarios[:7], indent=2)}
{user_req_section}{docs_section}

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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    supporting_docs: str = "",
    corroborated_findings: List[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Agent 4: Generate prioritized vulnerability list with detailed exploitation steps."""
    from google.genai import types
    
    corroborated_findings = corroborated_findings or []
    
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
    
    # Add supporting documentation context
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION
{supporting_docs[:12000]}
Reference this documentation for accurate context on affected systems.
"""
    
    # Add corroborated findings section - these should be prioritized higher
    corroboration_section = ""
    if corroborated_findings:
        # Format findings to highlight document correlations
        formatted_findings = []
        for cf in corroborated_findings[:10]:
            formatted = {k: v for k, v in cf.items() if k != "document_correlations"}
            doc_refs = cf.get("document_correlations", [])
            if doc_refs:
                formatted["related_documentation"] = [
                    {"document": d["document"], "matched_term": d["matched_term"], "context": d["excerpt"][:150] + "..."}
                    for d in doc_refs[:2]
                ]
            formatted_findings.append(formatted)

        findings_with_docs = sum(1 for cf in corroborated_findings if cf.get("has_documentation"))

        corroboration_section = f"""
## 🎯 CORROBORATED FINDINGS (HIGH CONFIDENCE - Multiple Sources)
These findings were detected by MULTIPLE scan types, making them MORE LIKELY TO BE REAL vulnerabilities.
Documentation coverage: {findings_with_docs}/{len(corroborated_findings)} findings have related documentation.

{json.dumps(formatted_findings, indent=2)}

IMPORTANT:
- Corroborated findings should be ranked HIGHER because they have been verified by multiple independent analysis methods.
- Mark them with "corroborated": true in your output.
- When a finding has "related_documentation", mention the documentation context in your exploitation analysis.
- Include "documented_in": ["filename1", "filename2"] for findings that have documentation references.
"""
    
    prompt = f"""You are creating a PRIORITIZED vulnerability list with DETAILED information.

## CRITICAL FINDINGS ({len(critical_findings)} total)
{json.dumps(critical_findings[:15], indent=2)}

## HIGH FINDINGS ({len(high_findings)} total)
{json.dumps(high_findings[:15], indent=2)}
{corroboration_section}{user_req_section}{docs_section}
## YOUR TASK
Create a ranked list of vulnerabilities with COMPLETE details for each.
- Rank corroborated findings HIGHER (they have higher confidence)
- For each corroborated finding, set "corroborated": true and list the "sources" array

IMPORTANT: Return ONLY a valid JSON array. No markdown wrapping.

[
  {{
    "rank": 1,
    "corroborated": true,
    "sources": ["SAST", "DAST"],
    "confidence_level": "High",
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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    user_requirements: str = "",
    supporting_docs: str = "",
    corroborated_findings: List[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Agent 5: Generate cross-analysis findings that span multiple scan types."""
    from google.genai import types
    
    corroborated_findings = corroborated_findings or []
    
    # Summarize data sources with actual counts
    sources_summary = {
        "security_scans": len(aggregated_data.get("security_scans", [])),
        "network_reports": len(aggregated_data.get("network_reports", [])),
        "ssl_scans": len(aggregated_data.get("ssl_scans", [])),
        "dns_scans": len(aggregated_data.get("dns_scans", [])),
        "traceroute_scans": len(aggregated_data.get("traceroute_scans", [])),
        "re_reports": len(aggregated_data.get("re_reports", [])),
        "fuzzing_sessions": len(aggregated_data.get("fuzzing_sessions", [])),
        "dynamic_scans": len(aggregated_data.get("dynamic_scans", [])),
        "binary_fuzzer_sessions": len(aggregated_data.get("binary_fuzzer_sessions", [])),
        "fuzzing_campaign_reports": len(aggregated_data.get("fuzzing_campaign_reports", [])),
        "agentic_fuzzer_reports": len(aggregated_data.get("agentic_fuzzer_reports", [])),
        "mitm_analysis_reports": len(aggregated_data.get("mitm_analysis_reports", [])),
    }
    
    # Get key findings from ALL sources with more context - INCREASED LIMITS
    key_findings = []
    
    # Security scan findings and exploits - increased from 15 to 30
    for scan in aggregated_data.get("security_scans", []):
        for f in scan.get("findings", [])[:30]:
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

    # Dynamic scan (DAST) findings for runtime vuln correlation
    for ds in aggregated_data.get("dynamic_scans", []):
        target = ds.get("target_url", "unknown")
        for alert in ds.get("alerts", [])[:15]:
            if isinstance(alert, dict):
                risk = alert.get("risk", "Info").upper()
                key_findings.append(f"[DAST/{risk}] {alert.get('name', 'Alert')}: {alert.get('description', '')[:120]} | URL: {alert.get('url', target)[:80]}")
    
    # Binary fuzzer (AFL++) findings for memory corruption correlation
    for bf in aggregated_data.get("binary_fuzzer_sessions", []):
        binary = bf.get("binary_path", "unknown")
        # Crashes indicate memory corruption vulnerabilities
        for crash in bf.get("crashes", [])[:10]:
            if isinstance(crash, dict):
                crash_type = crash.get("crash_type", "crash")
                key_findings.append(f"[BINARY_FUZZ/CRITICAL] {crash_type} in {binary}: {crash.get('description', 'Memory corruption')[:100]} | Input: {crash.get('input_file', 'N/A')[:50]}")
        # Memory errors from sanitizers
        for merr in bf.get("memory_errors", [])[:10]:
            if isinstance(merr, dict):
                key_findings.append(f"[BINARY_FUZZ/HIGH] {merr.get('error_type', 'Memory Error')} in {binary}: {merr.get('description', '')[:100]}")
        # AI analysis insights if available
        ai_analysis = bf.get("ai_analysis", {})
        if isinstance(ai_analysis, dict):
            for insight in ai_analysis.get("security_insights", [])[:5]:
                if isinstance(insight, str):
                    key_findings.append(f"[BINARY_AI] {insight[:150]}")

    # Fuzzing Campaign Reports (AI-generated from Agentic Binary Fuzzer)
    for fcr in aggregated_data.get("fuzzing_campaign_reports", []):
        binary = fcr.get("binary_name", "unknown")
        risk_rating = fcr.get("risk_rating", "Unknown")
        # Add executive summary as a key finding
        if fcr.get("executive_summary"):
            key_findings.append(f"[CAMPAIGN_REPORT/{risk_rating.upper()}] {binary}: {fcr['executive_summary'][:200]}")
        # Add key findings from the report
        for finding in fcr.get("key_findings", [])[:5]:
            if isinstance(finding, str):
                key_findings.append(f"[CAMPAIGN_FINDING] {binary}: {finding[:150]}")
        # Add exploitable crashes
        for crash in fcr.get("crashes", [])[:10]:
            if isinstance(crash, dict):
                exploitability = crash.get("exploitability", "unknown")
                if exploitability.lower() in ["exploitable", "probably_exploitable"]:
                    key_findings.append(f"[CAMPAIGN_CRASH/CRITICAL] {crash.get('crash_type', 'crash')} in {binary}: {crash.get('impact', '')[:100]} | Exploitability: {exploitability}")
        # Add strategy effectiveness insights
        strategy_effectiveness = fcr.get("strategy_effectiveness", {})
        if strategy_effectiveness:
            for strategy, stats in list(strategy_effectiveness.items())[:3]:
                if isinstance(stats, dict) and stats.get("effectiveness_rate") is not None:
                    key_findings.append(f"[CAMPAIGN_STRATEGY] {binary}: {strategy} was {stats['effectiveness_rate']*100:.0f}% effective ({stats.get('count', 0)} uses)")

    # Agentic fuzzer findings for intelligent fuzzing correlation
    for af in aggregated_data.get("agentic_fuzzer_reports", []):
        target = af.get("target_url", af.get("base_url", "unknown"))
        for finding in af.get("findings", [])[:15]:
            if isinstance(finding, dict):
                sev = finding.get("severity", "Info").upper()
                key_findings.append(f"[AGENTIC_FUZZ/{sev}] {finding.get('type', 'Finding')}: {finding.get('description', '')[:120]} | Endpoint: {finding.get('endpoint', target)[:60]}")
        # Vulnerabilities discovered
        for vuln in af.get("vulnerabilities_discovered", [])[:10]:
            if isinstance(vuln, dict):
                key_findings.append(f"[AGENTIC_FUZZ/HIGH] {vuln.get('type', 'Vuln')}: {vuln.get('details', '')[:120]}")
    
    # MITM traffic analysis findings for network interception correlation
    for mr in aggregated_data.get("mitm_analysis_reports", []):
        title = mr.get("title", "MITM Session")
        risk_level = mr.get("risk_level", "Unknown").upper()
        
        # Summary stats
        key_findings.append(f"[MITM/{risk_level}] {title}: {mr.get('findings_count', 0)} findings, Risk Score: {mr.get('risk_score', 0)}/100")
        
        # Individual findings from MITM analysis
        for finding in mr.get("findings", [])[:15]:
            if isinstance(finding, dict):
                sev = finding.get("severity", "Medium").upper()
                finding_type = finding.get("type", finding.get("finding_type", "Traffic Finding"))
                description = finding.get("description", finding.get("details", ""))[:150]
                endpoint = finding.get("endpoint", finding.get("url", "N/A"))[:60]
                key_findings.append(f"[MITM/{sev}] {finding_type}: {description} | Endpoint: {endpoint}")
        
        # Attack paths identified in MITM
        for path in mr.get("attack_paths", [])[:5]:
            if isinstance(path, dict):
                path_name = path.get("name", path.get("title", "Attack Path"))
                impact = path.get("impact", path.get("description", ""))[:100]
                key_findings.append(f"[MITM/ATTACK_PATH] {path_name}: {impact}")
        
        # Exploitation writeup highlights
        if mr.get("ai_exploitation_writeup"):
            writeup = mr.get("ai_exploitation_writeup", "")[:200]
            key_findings.append(f"[MITM_AI] Exploitation Analysis: {writeup}")
    
    # Add user requirements context if provided
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
The tester has specifically requested:
{user_requirements[:2000]}

Focus your cross-analysis on areas relevant to these requirements.
"""
    
    # Add supporting documentation context if provided
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION (Reference in your analysis)
{supporting_docs[:8000]}

Use this documentation to inform your cross-analysis correlations.
"""

    # Add corroborated findings section - these are PRE-VALIDATED HIGH CONFIDENCE
    corroboration_section = ""
    if corroborated_findings:
        high_conf = [f for f in corroborated_findings if f.get("confidence_level") == "High"]
        medium_conf = [f for f in corroborated_findings if f.get("confidence_level") == "Medium"]
        
        corroboration_section = f"""
## 🔴 CORROBORATED FINDINGS - HIGH CONFIDENCE (PRIORITIZE THESE)
These findings were detected by MULTIPLE independent scan sources, meaning they are HIGHLY LIKELY TO BE REAL vulnerabilities.
Multi-source detection = Higher confidence = Prioritize in your cross-analysis.

### HIGH CONFIDENCE (3+ sources) - DEFINITELY REAL:
"""
        for f in high_conf[:15]:
            # Include document references if available
            doc_refs = f.get('document_correlations', [])
            doc_info = ""
            if doc_refs:
                doc_names = [d.get('document', 'doc') for d in doc_refs[:2]]
                doc_info = f"\n  Documentation: {', '.join(doc_names)}"

            corroboration_section += f"""
- **{f.get('title', 'Finding')}** [{f.get('severity', 'Unknown')}]
  Sources: {', '.join(f.get('sources', []))}
  Evidence: {f.get('evidence_count', 1)} independent detections{doc_info}
"""

        if medium_conf:
            corroboration_section += f"""
### MEDIUM CONFIDENCE (2 sources) - VERY LIKELY REAL:
"""
            for f in medium_conf[:10]:
                doc_refs = f.get('document_correlations', [])
                doc_info = ""
                if doc_refs:
                    doc_names = [d.get('document', 'doc') for d in doc_refs[:2]]
                    doc_info = f" | Docs: {', '.join(doc_names)}"

                corroboration_section += f"""
- **{f.get('title', 'Finding')}** [{f.get('severity', 'Unknown')}]
  Sources: {', '.join(f.get('sources', []))}{doc_info}
"""

        # Count documented findings
        documented_count = sum(1 for f in corroborated_findings if f.get('has_documentation'))

        corroboration_section += f"""
**Documentation Coverage:** {documented_count}/{len(corroborated_findings)} corroborated findings have related documentation

**IMPORTANT**:
- PRIORITIZE building attack chains that include these corroborated findings.
- Mark any correlation that uses corroborated findings as "high_confidence": true in your output.
- When a finding has documentation references, include "documented_context": true in your output.
"""

    prompt = f"""You are an expert security analyst correlating findings across multiple security analysis domains.

## DATA SOURCES AVAILABLE
{json.dumps(sources_summary, indent=2)}
{user_req_section}{docs_section}{corroboration_section}
## ALL FINDINGS FROM ALL SCAN TYPES (with severity and context)
{chr(10).join(key_findings[:120])}

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
        "uses_corroborated_findings": true,
        "confidence_level": "High",
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
- Include specific exploit_guidance with commands
- Set "uses_corroborated_findings": true and "confidence_level": "High" if any findings used are from the corroborated list above"""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    user_requirements: str = "",
    supporting_docs: str = "",
) -> str:
    """Agent 6: Generate a professional Mermaid attack surface diagram with icons and styling.
    
    Now enhanced to extract attack surface from ALL scan types, not just security_scans.
    """
    from google.genai import types
    
    # Extract vulnerability types, components, and endpoints from ALL scan sources
    vuln_types = set()
    components = set()
    endpoints = set()
    network_services = set()
    
    # 1. Security scans (SAST)
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
    
    # 2. Dynamic scans (DAST/ZAP)
    for ds in aggregated_data.get("dynamic_scans", []):
        target = ds.get("target_url", "")
        if target:
            endpoints.add(target[:50])
        for alert in ds.get("alerts", [])[:20]:
            if isinstance(alert, dict):
                vuln_types.add(alert.get("name", "")[:30])
                if alert.get("url"):
                    endpoints.add(alert.get("url", "")[:50])
    
    # 3. API fuzzing results
    for fuzz in aggregated_data.get("fuzzing_results", []):
        endpoint = fuzz.get("endpoint", "")
        if endpoint:
            endpoints.add(endpoint[:50])
        for f in fuzz.get("findings", [])[:15]:
            if isinstance(f, dict):
                vuln_types.add(f.get("type", "")[:30])
    
    # 4. Network reports (PCAP, ports)
    for nr in aggregated_data.get("network_reports", []):
        for host in nr.get("hosts", [])[:10]:
            if isinstance(host, dict):
                for port in host.get("ports", [])[:5]:
                    if isinstance(port, dict):
                        svc = f"{port.get('port', '?')}/{port.get('service', 'unknown')}"
                        network_services.add(svc)
    
    # 5. Binary fuzzer sessions (AFL++)
    for bf in aggregated_data.get("binary_fuzzer_sessions", []):
        binary = bf.get("binary_path", "")
        if binary:
            components.add(binary.split("/")[-1][:20])
        for crash in bf.get("crashes", [])[:10]:
            if isinstance(crash, dict):
                vuln_types.add(crash.get("crash_type", "Memory Corruption")[:30])

    # 5b. Fuzzing Campaign Reports (AI-generated from Agentic Binary Fuzzer)
    for fcr in aggregated_data.get("fuzzing_campaign_reports", []):
        binary = fcr.get("binary_name", "")
        if binary:
            components.add(binary[:20])
        for crash in fcr.get("crashes", [])[:10]:
            if isinstance(crash, dict):
                vuln_types.add(crash.get("crash_type", "Memory Corruption")[:30])

    # 6. Agentic fuzzer reports
    for af in aggregated_data.get("agentic_fuzzer_reports", []):
        for endpoint in af.get("endpoints_tested", [])[:15]:
            if isinstance(endpoint, str):
                endpoints.add(endpoint[:50])
        for vuln in af.get("vulnerabilities_discovered", [])[:15]:
            if isinstance(vuln, dict):
                vuln_types.add(vuln.get("type", "")[:30])
    
    # 6b. MITM traffic analysis reports
    for mr in aggregated_data.get("mitm_analysis_reports", []):
        for finding in mr.get("findings", [])[:15]:
            if isinstance(finding, dict):
                finding_type = finding.get("type", finding.get("finding_type", ""))[:30]
                if finding_type:
                    vuln_types.add(f"MITM: {finding_type}")
                endpoint = finding.get("endpoint", finding.get("url", ""))[:50]
                if endpoint:
                    endpoints.add(endpoint)
        # Add attack paths as vulnerability types
        for path in mr.get("attack_paths", [])[:5]:
            if isinstance(path, dict):
                path_name = path.get("name", path.get("title", ""))[:30]
                if path_name:
                    vuln_types.add(f"MITM Attack: {path_name}")
    
    # 7. Reverse engineering reports  
    for re_report in aggregated_data.get("re_reports", [])[:5]:
        for func in re_report.get("dangerous_functions", [])[:10]:
            if isinstance(func, dict):
                vuln_types.add(f"RE: {func.get('name', 'Function')[:25]}")
        for secret in re_report.get("secrets_found", [])[:5]:
            vuln_types.add("Hardcoded Secret")
    
    # 8. SSL scan results
    for ssl in aggregated_data.get("ssl_results", [])[:5]:
        for issue in ssl.get("issues", [])[:10]:
            if isinstance(issue, dict):
                vuln_types.add(f"SSL: {issue.get('type', 'Issue')[:25]}")
    
    # 9. DNS reconnaissance
    for dns in aggregated_data.get("dns_results", [])[:5]:
        for record in dns.get("records", [])[:10]:
            if isinstance(record, dict) and record.get("value"):
                endpoints.add(record.get("value", "")[:50])
    
    vuln_list = list(vuln_types)[:15]  # Increased from 10
    component_list = list(components)[:12]  # Increased from 8
    endpoint_list = list(endpoints)[:10]
    service_list = list(network_services)[:8]
    
    prompt = f"""Create a professional Mermaid attack surface diagram.

## VULNERABILITIES FOUND (from SAST, DAST, fuzzing, RE analysis)
{json.dumps(vuln_list, indent=2)}

## COMPONENTS (binaries, files, modules)
{json.dumps(component_list, indent=2)}

## ENDPOINTS (API, web, discovered URLs)
{json.dumps(endpoint_list, indent=2)}

## NETWORK SERVICES (open ports/services)
{json.dumps(service_list, indent=2)}

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
                thinking_config=types.ThinkingConfig(thinking_level="medium"),  # Medium thinking for predictable syntax
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
    user_requirements: str = "",
    supporting_docs: str = "",
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
    
    # Build context sections
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
{user_requirements[:1500]}
Focus attack chains on scenarios relevant to these requirements.
"""
    
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION
{supporting_docs[:12000]}
Use this context to inform your attack chain analysis.
"""
    
    prompt = f"""You are mapping attack chains that combine vulnerabilities for maximum impact.

## AVAILABLE EXPLOITS
{json.dumps(exploit_scenarios, indent=2)}
{user_req_section}{docs_section}
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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    user_requirements: str = "",
    supporting_docs: str = "",
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
    
    # Build context sections
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
{user_requirements[:1500]}
Tailor exploit development guidance to these specific requirements.
"""
    
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION
{supporting_docs[:12000]}
Reference this documentation when developing exploits.
"""
    
    prompt = f"""You are identifying EXPLOIT DEVELOPMENT OPPORTUNITIES for security researchers.

## EXPLOIT SCENARIOS
{json.dumps(exploit_scenarios, indent=2)}
{user_req_section}{docs_section}
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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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
    user_requirements: str = "",
    supporting_docs: str = "",
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
    
    # Build context sections
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS
{user_requirements[:1500]}
Focus your code analysis on areas relevant to these requirements.
"""
    
    docs_section = ""
    if supporting_docs:
        docs_section = f"""
## SUPPORTING DOCUMENTATION
{supporting_docs[:12000]}
Reference this documentation when analyzing code and providing fixes.
"""
    
    prompt = f"""You are a security code auditor performing a DEEP DIVE analysis of source code.

## SCAN FINDINGS TO CORRELATE WITH
{json.dumps(findings_context[:20], indent=2)}

## SOURCE CODE SNIPPETS TO ANALYZE
{json.dumps(code_snippets, indent=2)}
{user_req_section}{docs_section}
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
                thinking_config=types.ThinkingConfig(thinking_level="high"),
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


async def _agent_synthesis(
    genai_client,
    agent_outputs: Dict[str, Any],
    corroborated_findings: List[Dict[str, Any]],
    agent_status: Dict[str, str],
    user_requirements: str = "",
) -> Dict[str, Any]:
    """Agent 10: Synthesis Agent - Reviews all agent outputs, validates consistency, and produces final quality report.
    
    This agent runs AFTER all other agents complete. It:
    1. Reviews outputs from all 9 agents
    2. Identifies contradictions or inconsistencies
    3. Highlights corroborated findings that agents may have missed correlating
    4. Produces quality assessment and confidence scores
    5. Fills gaps where agents failed or produced sparse output
    """
    from google.genai import types
    
    # Build summary of what each agent produced
    agent_summary = []
    
    # Executive summary
    exec_summary = agent_outputs.get("executive_summary", "")
    agent_summary.append(f"**Executive Summary**: {len(exec_summary)} chars - {'OK' if exec_summary else 'EMPTY'}")
    
    # POC scripts
    poc_scripts = agent_outputs.get("poc_scripts", [])
    agent_summary.append(f"**POC Scripts**: {len(poc_scripts)} scripts")
    poc_preview = [f"- {p.get('title', 'Untitled')}: {p.get('vulnerability_type', 'Unknown')}" for p in poc_scripts[:5]]
    
    # Attack guides
    attack_guides = agent_outputs.get("attack_guides", [])
    agent_summary.append(f"**Attack Guides**: {len(attack_guides)} guides")
    
    # Prioritized vulnerabilities
    prioritized_vulns = agent_outputs.get("prioritized_vulnerabilities", [])
    agent_summary.append(f"**Prioritized Vulns**: {len(prioritized_vulns)} items")
    vuln_preview = [f"- [{v.get('severity', '?')}] {v.get('title', 'Untitled')}" for v in prioritized_vulns[:8]]
    
    # Cross-analysis findings
    cross_findings = agent_outputs.get("cross_analysis_findings", [])
    agent_summary.append(f"**Cross-Analysis Findings**: {len(cross_findings)} correlations")
    
    # Attack surface diagram
    diagram = agent_outputs.get("attack_surface_diagram", "")
    agent_summary.append(f"**Attack Surface Diagram**: {len(diagram)} chars - {'OK' if 'flowchart' in diagram.lower() else 'POSSIBLY INVALID'}")
    
    # Attack chains
    attack_chains = agent_outputs.get("attack_chains", [])
    agent_summary.append(f"**Attack Chains**: {len(attack_chains)} chains")
    
    # Exploit development
    exploit_dev = agent_outputs.get("exploit_development", [])
    agent_summary.append(f"**Exploit Development**: {len(exploit_dev)} exploits")
    
    # Source code findings
    source_findings = agent_outputs.get("source_code_findings", [])
    agent_summary.append(f"**Source Code Findings**: {len(source_findings)} findings")
    
    # Build corroboration summary
    corroboration_summary = ""
    if corroborated_findings:
        high_conf = [f for f in corroborated_findings if f.get("confidence_level") == "High"]
        medium_conf = [f for f in corroborated_findings if f.get("confidence_level") == "Medium"]
        documented_count = sum(1 for f in corroborated_findings if f.get("has_documentation"))

        # Format findings with doc indicators
        def format_with_docs(finding):
            base = f"- {finding.get('title', 'Finding')} [{finding.get('severity')}] - Sources: {', '.join(finding.get('sources', []))}"
            if finding.get('has_documentation'):
                doc_names = [d.get('document', 'doc') for d in finding.get('document_correlations', [])[:2]]
                base += f" | DOCUMENTED in: {', '.join(doc_names)}"
            return base

        corroboration_summary = f"""
## CORROBORATED FINDINGS (Multi-Source = High Confidence)
These findings were detected by MULTIPLE independent scanners. They are HIGHLY LIKELY to be real.
**Documentation Coverage:** {documented_count}/{len(corroborated_findings)} findings have related documentation

HIGH CONFIDENCE ({len(high_conf)} findings from 3+ sources):
{chr(10).join([format_with_docs(f) for f in high_conf[:10]])}

MEDIUM CONFIDENCE ({len(medium_conf)} findings from 2 sources):
{chr(10).join([format_with_docs(f) for f in medium_conf[:8]])}

**IMPORTANT:** Findings marked with "DOCUMENTED" have been linked to uploaded documentation. Verify that these findings are appropriately referenced in the report outputs.
"""
    
    # Build agent status summary
    status_summary = "\n".join([f"- {agent}: {status}" for agent, status in agent_status.items()])
    
    # User requirements context
    user_req_section = ""
    if user_requirements:
        user_req_section = f"""
## USER REQUIREMENTS (verify these were addressed)
{user_requirements[:1500]}
"""
    
    prompt = f"""You are the SYNTHESIS AGENT - the final quality reviewer for a comprehensive security assessment.

## AGENT STATUS SUMMARY
{status_summary}

## AGENT OUTPUT SUMMARY
{chr(10).join(agent_summary)}

## SAMPLE OF PRIORITIZED VULNERABILITIES
{chr(10).join(vuln_preview)}

## SAMPLE OF POC SCRIPTS
{chr(10).join(poc_preview)}
{corroboration_summary}{user_req_section}
## YOUR SYNTHESIS TASK

Review all agent outputs and produce a quality assessment. You are looking for:

1. **CONSISTENCY CHECK**: Are there contradictions between agents? (e.g., one says Critical, another says Low)
2. **CORROBORATION GAPS**: Did agents properly highlight the corroborated (multi-source) findings?
3. **COVERAGE GAPS**: Are there obvious vulnerabilities that agents missed?
4. **QUALITY ISSUES**: Any agents that produced sparse/low-quality output?
5. **OVERALL CONFIDENCE**: How confident should the user be in this report?

Return a JSON object:
```json
{{
    "synthesis_summary": "2-3 paragraph executive summary of the report quality and key highlights",
    "overall_confidence_score": 0.85,
    "confidence_justification": "Why you gave this score",
    "consistency_issues": [
        {{
            "issue": "Description of contradiction",
            "agents_involved": ["agent1", "agent2"],
            "resolution_suggestion": "How to resolve it"
        }}
    ],
    "corroboration_highlights": [
        {{
            "finding": "Finding that should be highlighted",
            "confidence": "High",
            "why_important": "Why this is significant"
        }}
    ],
    "coverage_gaps": [
        {{
            "gap": "What was missed",
            "suggestion": "What should be added"
        }}
    ],
    "agent_quality_assessment": {{
        "executive_summary": {{"quality": "good/fair/poor", "notes": "..."}},
        "poc_scripts": {{"quality": "good/fair/poor", "notes": "..."}},
        "attack_guides": {{"quality": "good/fair/poor", "notes": "..."}},
        "prioritized_vulns": {{"quality": "good/fair/poor", "notes": "..."}},
        "cross_analysis": {{"quality": "good/fair/poor", "notes": "..."}},
        "attack_diagram": {{"quality": "good/fair/poor", "notes": "..."}},
        "attack_chains": {{"quality": "good/fair/poor", "notes": "..."}},
        "exploit_dev": {{"quality": "good/fair/poor", "notes": "..."}},
        "source_code": {{"quality": "good/fair/poor", "notes": "..."}}
    }},
    "user_requirements_addressed": true,
    "requirements_gaps": ["Any user requirements that weren't addressed"],
    "recommended_follow_ups": ["Suggested additional scans or manual testing"]
}}
```

Be critical but fair. This synthesis helps the user understand report quality and reliability."""

    try:
        response = genai_client.models.generate_content(
            model=settings.gemini_model_id,
            contents=[{"role": "user", "parts": [{"text": prompt}]}],
            config=types.GenerateContentConfig(
                thinking_config=types.ThinkingConfig(thinking_level="high"),  # High thinking for thorough analysis
                max_output_tokens=16384,
            ),
        )
        result = _parse_ai_response(response.text)
        if isinstance(result, dict):
            logger.info(f"Synthesis agent completed with confidence score: {result.get('overall_confidence_score', 'N/A')}")
            return result
        else:
            logger.warning(f"Synthesis agent returned unexpected format: {type(result)}")
            return {"synthesis_summary": "Synthesis agent produced unexpected output format", "overall_confidence_score": 0.5}
    except Exception as e:
        logger.error(f"Agent synthesis failed: {e}")
        return {"synthesis_summary": f"Synthesis agent failed: {str(e)}", "overall_confidence_score": 0.0}


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
