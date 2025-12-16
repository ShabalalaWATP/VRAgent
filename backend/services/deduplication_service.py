"""
Scanner Result Deduplication Service

Merges findings from multiple scanners (Semgrep, Bandit, ESLint, gosec, etc.)
that report the same vulnerability. Creates unified findings with provenance
tracking showing which scanners detected each issue.

Deduplication Strategy:
1. Fingerprint-based: file + line range + vulnerability category
2. CWE-based: Same CWE at same location = same issue
3. Fuzzy matching: Similar code snippets within N lines
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DeduplicatedFinding:
    """A deduplicated finding that may combine multiple scanner results."""
    # Primary finding (highest severity or most detailed)
    primary_finding: Any  # models.Finding
    # List of merged findings from other scanners
    merged_findings: List[Any] = field(default_factory=list)
    # Which scanners detected this issue
    scanners: Set[str] = field(default_factory=set)
    # Confidence boost from multiple detections
    confidence_boost: float = 0.0
    # Unified fingerprint
    fingerprint: str = ""


# Map scanner finding types to vulnerability categories
VULNERABILITY_CATEGORIES = {
    # Code Injection
    "eval": "code_injection",
    "exec": "code_injection",
    "code_injection": "code_injection",
    "b307": "code_injection",  # Bandit eval
    "b102": "code_injection",  # Bandit exec
    "detect-eval": "code_injection",  # ESLint
    
    # Command Injection
    "command": "command_injection",
    "shell": "command_injection",
    "subprocess": "command_injection",
    "b602": "command_injection",  # Bandit shell=True
    "b603": "command_injection",  # Bandit subprocess
    "b604": "command_injection",  # Bandit shell injection
    "b605": "command_injection",  # Bandit start process
    "b606": "command_injection",  # Bandit os.popen
    "b607": "command_injection",  # Bandit start process partial path
    "g204": "command_injection",  # gosec subprocess
    "detect-child-process": "command_injection",  # ESLint
    
    # SQL Injection
    "sql": "sql_injection",
    "sqli": "sql_injection",
    "b608": "sql_injection",  # Bandit SQL
    "g201": "sql_injection",  # gosec SQL
    "g202": "sql_injection",  # gosec SQL
    
    # XSS
    "xss": "xss",
    "cross-site": "xss",
    "b320": "xss",  # Bandit XSS
    "no-unsanitized": "xss",  # ESLint
    
    # Path Traversal
    "path": "path_traversal",
    "traversal": "path_traversal",
    "directory": "path_traversal",
    "b108": "path_traversal",  # Bandit hardcoded tmp
    "g304": "path_traversal",  # gosec file inclusion
    "g305": "path_traversal",  # gosec zip slip
    
    # Secrets
    "secret": "hardcoded_secret",
    "password": "hardcoded_secret",
    "credential": "hardcoded_secret",
    "api_key": "hardcoded_secret",
    "token": "hardcoded_secret",
    "b104": "hardcoded_secret",  # Bandit hardcoded bind
    "b105": "hardcoded_secret",  # Bandit hardcoded password
    "b106": "hardcoded_secret",  # Bandit hardcoded password func
    "b107": "hardcoded_secret",  # Bandit hardcoded password default
    "g101": "hardcoded_secret",  # gosec hardcoded credentials
    
    # Cryptography
    "crypto": "weak_crypto",
    "md5": "weak_crypto",
    "sha1": "weak_crypto",
    "random": "weak_crypto",
    "b303": "weak_crypto",  # Bandit MD5/SHA1
    "b311": "weak_crypto",  # Bandit random
    "b324": "weak_crypto",  # Bandit hashlib
    "g401": "weak_crypto",  # gosec MD5
    "g402": "weak_crypto",  # gosec TLS
    "g404": "weak_crypto",  # gosec weak random
    
    # Deserialization
    "deserialize": "insecure_deserialization",
    "pickle": "insecure_deserialization",
    "yaml": "insecure_deserialization",
    "b301": "insecure_deserialization",  # Bandit pickle
    "b506": "insecure_deserialization",  # Bandit yaml
    
    # XXE
    "xxe": "xxe",
    "xml": "xxe",
    "b313": "xxe",  # Bandit XML
    "b314": "xxe",  # Bandit XML
    "b318": "xxe",  # Bandit XML
    "b319": "xxe",  # Bandit XML
    "b320": "xxe",  # Bandit XML
    "g303": "xxe",  # gosec XML
    
    # SSRF
    "ssrf": "ssrf",
    "request": "ssrf",
    "b310": "ssrf",  # Bandit URL open
    
    # Authentication
    "auth": "authentication",
    "session": "authentication",
    "jwt": "authentication",
    
    # TLS/SSL
    "tls": "insecure_transport",
    "ssl": "insecure_transport",
    "verify": "insecure_transport",
    "b501": "insecure_transport",  # Bandit request verify=False
    "b502": "insecure_transport",  # Bandit SSL bad version
    "b503": "insecure_transport",  # Bandit SSL bad defaults
    "g402": "insecure_transport",  # gosec TLS
}

# CWE to category mapping for additional matching
CWE_CATEGORIES = {
    "CWE-78": "command_injection",
    "CWE-79": "xss",
    "CWE-89": "sql_injection",
    "CWE-90": "ldap_injection",
    "CWE-94": "code_injection",
    "CWE-95": "code_injection",
    "CWE-22": "path_traversal",
    "CWE-23": "path_traversal",
    "CWE-36": "path_traversal",
    "CWE-98": "path_traversal",
    "CWE-259": "hardcoded_secret",
    "CWE-798": "hardcoded_secret",
    "CWE-327": "weak_crypto",
    "CWE-328": "weak_crypto",
    "CWE-330": "weak_crypto",
    "CWE-338": "weak_crypto",
    "CWE-502": "insecure_deserialization",
    "CWE-611": "xxe",
    "CWE-918": "ssrf",
    "CWE-295": "insecure_transport",
    "CWE-319": "insecure_transport",
}


def _get_vulnerability_category(finding: Any) -> str:
    """
    Determine the vulnerability category for a finding.
    
    Uses rule IDs, CWEs, and summary text to categorize.
    """
    details = finding.details if hasattr(finding, 'details') and finding.details else {}
    summary = (finding.summary or "").lower()
    finding_type = (finding.type or "").lower()
    
    # Check for agentic AI findings first (type is "agentic-SQL Injection" etc)
    if finding_type.startswith("agentic-"):
        vuln_type = finding_type.replace("agentic-", "").lower().replace(" ", "_")
        # Map common agentic vulnerability types
        agentic_categories = {
            "sql_injection": "sql_injection",
            "command_injection": "command_injection",
            "cross-site_scripting": "xss",
            "xss": "xss",
            "path_traversal": "path_traversal",
            "ssrf": "ssrf",
            "server-side_request_forgery": "ssrf",
            "xxe": "xxe",
            "xml_external_entity": "xxe",
            "insecure_deserialization": "insecure_deserialization",
            "code_injection": "code_injection",
        }
        return agentic_categories.get(vuln_type, vuln_type)
    
    # Try rule ID first (most specific)
    rule_id = (
        details.get("rule_id") or 
        details.get("test_id") or 
        details.get("check_name") or
        ""
    ).lower()
    
    if rule_id:
        for pattern, category in VULNERABILITY_CATEGORIES.items():
            if pattern in rule_id:
                return category
    
    # Try CWE
    cwes = details.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    for cwe in cwes:
        cwe_str = str(cwe).upper()
        if not cwe_str.startswith("CWE-"):
            cwe_str = f"CWE-{cwe_str}"
        if cwe_str in CWE_CATEGORIES:
            return CWE_CATEGORIES[cwe_str]
    
    # Try summary keywords
    for pattern, category in VULNERABILITY_CATEGORIES.items():
        if pattern in summary:
            return category
    
    # Try finding type
    if finding_type in ("secret", "hardcoded_secret"):
        return "hardcoded_secret"
    if finding_type == "dependency_vuln":
        return "dependency_vulnerability"
    
    return "other"


def _create_fingerprint(
    file_path: str,
    start_line: int,
    end_line: Optional[int],
    category: str,
    code_hash: Optional[str] = None
) -> str:
    """
    Create a unique fingerprint for a finding.
    
    Fingerprint components:
    - Normalized file path
    - Line range (with some tolerance)
    - Vulnerability category
    - Optional code hash for exact matching
    """
    # Normalize file path
    normalized_path = file_path.replace("\\", "/").lower()
    
    # Use line range with tolerance (findings might be off by 1-2 lines)
    line_bucket = start_line // 5 * 5  # Group lines in buckets of 5
    
    # Create fingerprint
    fp_parts = [normalized_path, str(line_bucket), category]
    if code_hash:
        fp_parts.append(code_hash[:16])
    
    fp_string = "|".join(fp_parts)
    return hashlib.sha256(fp_string.encode()).hexdigest()[:32]


def _extract_code_hash(finding: Any) -> Optional[str]:
    """Extract a hash of the code snippet from a finding."""
    details = finding.details if hasattr(finding, 'details') and finding.details else {}
    code_snippet = details.get("code_snippet", "")
    
    if code_snippet:
        # Normalize whitespace
        normalized = re.sub(r'\s+', ' ', code_snippet.strip())
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    return None


def _get_scanner_name(finding: Any) -> str:
    """Get the scanner name from a finding type."""
    finding_type = (finding.type or "").lower()
    
    # Check for agentic AI scan first (type is "agentic-SQL Injection" etc)
    if finding_type.startswith("agentic-"):
        return "Agentic AI"
    
    scanner_map = {
        "semgrep": "Semgrep",
        "bandit": "Bandit",
        "gosec": "Gosec",
        "eslint": "ESLint",
        "eslint_security": "ESLint",
        "spotbugs": "SpotBugs",
        "clangtidy": "Clang-Tidy",
        "clang-tidy": "Clang-Tidy",
        "secret": "Secret Scanner",
        "code_pattern": "Pattern Scanner",
        "dependency_vuln": "Dependency Scanner",
    }
    
    return scanner_map.get(finding_type, finding_type.title())


def _calculate_severity_priority(severity: str) -> int:
    """Get numeric priority for severity comparison."""
    priorities = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    return priorities.get(severity.lower(), 0)


def _select_primary_finding(findings: List[Any]) -> Any:
    """
    Select the primary finding from a group of duplicates.
    
    Preference:
    1. Highest severity
    2. Most detailed (has CWE, code snippet, fix suggestion)
    3. From more trusted scanner (Semgrep > Bandit > ESLint > Pattern)
    """
    scanner_trust = {
        "Agentic AI": 6,  # Highest trust - LLM-powered with flow tracing
        "Semgrep": 5,
        "SpotBugs": 4,
        "Bandit": 4,
        "Gosec": 4,
        "Clang-Tidy": 4,
        "ESLint": 3,
        "Secret Scanner": 3,
        "Pattern Scanner": 1,
        "Dependency Scanner": 5,
    }
    
    def score_finding(f):
        details = f.details if hasattr(f, 'details') and f.details else {}
        
        # Severity score (0-4)
        severity_score = _calculate_severity_priority(f.severity or "medium")
        
        # Detail score (0-5)
        detail_score = 0
        if details.get("cwe"):
            detail_score += 1
        if details.get("code_snippet"):
            detail_score += 1
        if details.get("fix") or details.get("remediation_code"):
            detail_score += 1
        if details.get("owasp"):
            detail_score += 1
        if details.get("more_info") or details.get("references"):
            detail_score += 1
        
        # Scanner trust score (0-5)
        scanner = _get_scanner_name(f)
        trust_score = scanner_trust.get(scanner, 2)
        
        return (severity_score * 10 + detail_score * 2 + trust_score)
    
    return max(findings, key=score_finding)


def _merge_finding_details(primary: Any, merged: List[Any]) -> Dict:
    """
    Merge details from multiple findings into the primary finding.
    
    Combines:
    - CWEs from all scanners
    - OWASP mappings
    - Code snippets (keep best)
    - References/more_info
    - Scanner-specific info
    """
    primary_details = dict(primary.details) if primary.details else {}
    
    # Collect all CWEs
    all_cwes = set()
    if primary_details.get("cwe"):
        cwes = primary_details["cwe"]
        if isinstance(cwes, list):
            all_cwes.update(cwes)
        else:
            all_cwes.add(cwes)
    
    # Collect all OWASP
    all_owasp = set()
    if primary_details.get("owasp"):
        owasp = primary_details["owasp"]
        if isinstance(owasp, list):
            all_owasp.update(owasp)
        else:
            all_owasp.add(owasp)
    
    # Scanner detections
    scanner_detections = [{
        "scanner": _get_scanner_name(primary),
        "rule_id": primary_details.get("rule_id") or primary_details.get("test_id"),
        "message": primary.summary,
    }]
    
    # Merge from other findings
    for f in merged:
        f_details = f.details if f.details else {}
        
        # CWEs
        if f_details.get("cwe"):
            cwes = f_details["cwe"]
            if isinstance(cwes, list):
                all_cwes.update(cwes)
            else:
                all_cwes.add(cwes)
        
        # OWASP
        if f_details.get("owasp"):
            owasp = f_details["owasp"]
            if isinstance(owasp, list):
                all_owasp.update(owasp)
            else:
                all_owasp.add(owasp)
        
        # Scanner detection
        scanner_detections.append({
            "scanner": _get_scanner_name(f),
            "rule_id": f_details.get("rule_id") or f_details.get("test_id"),
            "message": f.summary,
        })
        
        # Keep best code snippet
        if f_details.get("code_snippet") and not primary_details.get("code_snippet"):
            primary_details["code_snippet"] = f_details["code_snippet"]
        elif f_details.get("code_snippet"):
            # Keep longer snippet
            if len(f_details["code_snippet"]) > len(primary_details.get("code_snippet", "")):
                primary_details["code_snippet"] = f_details["code_snippet"]
        
        # Merge fix suggestions
        if f_details.get("fix") and not primary_details.get("fix"):
            primary_details["fix"] = f_details["fix"]
    
    # Update merged details
    if all_cwes:
        primary_details["cwe"] = sorted(list(all_cwes))
    if all_owasp:
        primary_details["owasp"] = sorted(list(all_owasp))
    
    primary_details["scanner_detections"] = scanner_detections
    primary_details["detected_by_scanners"] = len(scanner_detections)
    
    return primary_details


def deduplicate_findings(findings: List[Any]) -> Tuple[List[Any], Dict[str, Any]]:
    """
    Deduplicate findings from multiple scanners.
    
    Returns:
        Tuple of (deduplicated_findings, deduplication_stats)
    
    Stats include:
        - original_count: Number of findings before dedup
        - deduplicated_count: Number after dedup
        - duplicates_removed: Number of duplicates merged
        - by_category: Counts per vulnerability category
        - multi_scanner_findings: Findings detected by multiple scanners
    """
    if not findings:
        return [], {"original_count": 0, "deduplicated_count": 0, "duplicates_removed": 0}
    
    logger.info(f"Deduplicating {len(findings)} findings")
    
    # Group findings by fingerprint
    fingerprint_groups: Dict[str, List[Any]] = defaultdict(list)
    
    for finding in findings:
        category = _get_vulnerability_category(finding)
        code_hash = _extract_code_hash(finding)
        
        fingerprint = _create_fingerprint(
            file_path=finding.file_path or "",
            start_line=finding.start_line or 0,
            end_line=finding.end_line,
            category=category,
            code_hash=code_hash
        )
        
        fingerprint_groups[fingerprint].append(finding)
    
    # Process each group
    deduplicated = []
    multi_scanner_count = 0
    category_counts: Dict[str, int] = defaultdict(int)
    
    for fingerprint, group in fingerprint_groups.items():
        if len(group) == 1:
            # No duplicates, keep as-is
            finding = group[0]
            category = _get_vulnerability_category(finding)
            category_counts[category] += 1
            
            # Add scanner info to details
            details = dict(finding.details) if finding.details else {}
            details["scanner_detections"] = [{
                "scanner": _get_scanner_name(finding),
                "rule_id": details.get("rule_id") or details.get("test_id"),
                "message": finding.summary,
            }]
            details["detected_by_scanners"] = 1
            finding.details = details
            
            deduplicated.append(finding)
        else:
            # Multiple scanners detected this - merge
            primary = _select_primary_finding(group)
            merged = [f for f in group if f != primary]
            
            # Merge details
            merged_details = _merge_finding_details(primary, merged)
            primary.details = merged_details
            
            # Boost severity if multiple scanners agree on high/critical
            high_severity_count = sum(
                1 for f in group 
                if f.severity and f.severity.lower() in ("high", "critical")
            )
            if high_severity_count >= 2 and primary.severity == "medium":
                primary.severity = "high"
                merged_details["severity_boosted"] = True
                merged_details["severity_boost_reason"] = f"Multiple scanners ({high_severity_count}) flagged as high/critical"
            
            category = _get_vulnerability_category(primary)
            category_counts[category] += 1
            multi_scanner_count += 1
            
            deduplicated.append(primary)
            
            logger.debug(
                f"Merged {len(group)} findings into one: {primary.summary[:50]}... "
                f"(scanners: {[_get_scanner_name(f) for f in group]})"
            )
    
    duplicates_removed = len(findings) - len(deduplicated)
    
    stats = {
        "original_count": len(findings),
        "deduplicated_count": len(deduplicated),
        "duplicates_removed": duplicates_removed,
        "reduction_percent": round(duplicates_removed / len(findings) * 100, 1) if findings else 0,
        "multi_scanner_findings": multi_scanner_count,
        "by_category": dict(category_counts),
    }
    
    logger.info(
        f"Deduplication complete: {len(findings)} -> {len(deduplicated)} findings "
        f"({duplicates_removed} duplicates removed, {multi_scanner_count} multi-scanner detections)"
    )
    
    return deduplicated, stats


def get_deduplication_summary(findings: List[Any]) -> Dict[str, Any]:
    """
    Get a summary of potential duplicates without modifying findings.
    
    Useful for reporting/analytics.
    """
    fingerprint_counts: Dict[str, int] = defaultdict(int)
    scanner_overlaps: Dict[Tuple[str, str], int] = defaultdict(int)
    
    for finding in findings:
        category = _get_vulnerability_category(finding)
        fingerprint = _create_fingerprint(
            file_path=finding.file_path or "",
            start_line=finding.start_line or 0,
            end_line=finding.end_line,
            category=category,
        )
        fingerprint_counts[fingerprint] += 1
    
    # Count potential duplicates
    potential_duplicates = sum(
        count - 1 for count in fingerprint_counts.values() if count > 1
    )
    
    return {
        "total_findings": len(findings),
        "unique_fingerprints": len(fingerprint_counts),
        "potential_duplicates": potential_duplicates,
        "duplicate_groups": sum(1 for count in fingerprint_counts.values() if count > 1),
    }


def correlate_cross_file_findings(findings: List[Any]) -> List[Dict[str, Any]]:
    """
    Correlate findings across different files to identify potential attack paths.
    
    This identifies when an entry point in one file connects to a sink in another,
    suggesting a potential vulnerability flow across the codebase.
    
    Returns:
        List of correlation groups with related findings
    """
    correlations = []
    
    # Index findings by category and file
    by_category: Dict[str, List[Any]] = defaultdict(list)
    entry_points: List[Any] = []
    sinks: List[Any] = []
    
    ENTRY_POINT_PATTERNS = {
        "request", "input", "param", "query", "body", "form",
        "get", "post", "route", "endpoint", "handler", "api"
    }
    
    SINK_PATTERNS = {
        "sql", "exec", "eval", "system", "popen", "shell",
        "write", "save", "store", "insert", "update", "delete",
        "render", "response", "output", "send"
    }
    
    for finding in findings:
        category = _get_vulnerability_category(finding)
        by_category[category].append(finding)
        
        summary_lower = (finding.summary or "").lower()
        file_lower = (finding.file_path or "").lower()
        
        # Identify entry points
        if any(p in summary_lower or p in file_lower for p in ENTRY_POINT_PATTERNS):
            entry_points.append(finding)
        
        # Identify sinks
        if any(p in summary_lower for p in SINK_PATTERNS):
            sinks.append(finding)
    
    # Look for cross-file correlations
    # Pattern 1: Entry point in one file, sink in another
    for entry in entry_points:
        entry_file = entry.file_path or ""
        for sink in sinks:
            sink_file = sink.file_path or ""
            
            # Skip same file (already correlated by other means)
            if entry_file == sink_file:
                continue
            
            # Look for module relationship (e.g., routes.py -> models.py)
            entry_module = entry_file.split("/")[-1].replace(".py", "").replace(".js", "")
            sink_module = sink_file.split("/")[-1].replace(".py", "").replace(".js", "")
            
            # Check if these could be connected (same directory, import relationship, etc.)
            entry_dir = "/".join(entry_file.split("/")[:-1])
            sink_dir = "/".join(sink_file.split("/")[:-1])
            
            if entry_dir == sink_dir or abs(len(entry_dir) - len(sink_dir)) <= 2:
                correlations.append({
                    "type": "cross_file_flow",
                    "entry_point": {
                        "file": entry_file,
                        "line": entry.start_line,
                        "summary": entry.summary,
                        "finding_id": entry.id if hasattr(entry, 'id') else None,
                    },
                    "sink": {
                        "file": sink_file,
                        "line": sink.start_line,
                        "summary": sink.summary,
                        "finding_id": sink.id if hasattr(sink, 'id') else None,
                    },
                    "risk": "high" if _get_vulnerability_category(sink) in 
                        ("sql_injection", "command_injection", "code_injection") else "medium",
                    "description": f"User input from {entry_module} may flow to {sink_module}",
                })
    
    # Pattern 2: Same vulnerability type across related files
    for category, cat_findings in by_category.items():
        if len(cat_findings) >= 2:
            # Group by directory
            by_dir: Dict[str, List[Any]] = defaultdict(list)
            for f in cat_findings:
                dir_path = "/".join((f.file_path or "").split("/")[:-1])
                by_dir[dir_path].append(f)
            
            for dir_path, dir_findings in by_dir.items():
                if len(dir_findings) >= 2:
                    correlations.append({
                        "type": "category_cluster",
                        "category": category,
                        "directory": dir_path,
                        "finding_count": len(dir_findings),
                        "finding_ids": [f.id for f in dir_findings if hasattr(f, 'id')],
                        "description": f"Multiple {category} issues in {dir_path} ({len(dir_findings)} findings)",
                        "risk": "high" if category in ("sql_injection", "command_injection") else "medium",
                    })
    
    logger.info(f"Found {len(correlations)} cross-file correlations")
    return correlations
