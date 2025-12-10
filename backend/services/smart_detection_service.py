"""
Smart Detection Service

Provides intelligent vulnerability detection, anomaly analysis, and 
automatic categorization of fuzzing results.
"""

import re
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities that can be detected."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    OPEN_REDIRECT = "open_redirect"
    IDOR = "idor"
    INFORMATION_DISCLOSURE = "information_disclosure"
    ERROR_BASED = "error_based"
    AUTH_BYPASS = "auth_bypass"
    BUSINESS_LOGIC = "business_logic"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectionSignature:
    """A signature for detecting vulnerabilities."""
    name: str
    vuln_type: VulnerabilityType
    severity: Severity
    patterns: List[str]  # Regex patterns
    description: str
    false_positive_indicators: List[str] = field(default_factory=list)
    context_required: bool = False  # Needs payload context
    min_confidence: float = 0.7


@dataclass
class SmartFinding:
    """A finding detected by the smart detection engine."""
    id: str
    vuln_type: VulnerabilityType
    severity: Severity
    confidence: float
    title: str
    description: str
    evidence: List[str]
    payload: str
    response_id: str
    indicators: List[str]
    recommendation: str
    false_positive_likelihood: str  # low, medium, high
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "payload": self.payload,
            "response_id": self.response_id,
            "indicators": self.indicators,
            "recommendation": self.recommendation,
            "false_positive_likelihood": self.false_positive_likelihood,
        }


@dataclass 
class AnomalyResult:
    """Result of anomaly detection."""
    response_id: str
    anomaly_type: str  # time, length, status, content
    score: float  # 0-1, higher = more anomalous
    baseline_value: Any
    actual_value: Any
    deviation: float
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "response_id": self.response_id,
            "anomaly_type": self.anomaly_type,
            "score": self.score,
            "baseline_value": self.baseline_value,
            "actual_value": self.actual_value,
            "deviation": self.deviation,
            "description": self.description,
        }


# =============================================================================
# Detection Signatures Database
# =============================================================================

SQL_INJECTION_SIGNATURES = [
    DetectionSignature(
        name="SQL Error - MySQL",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
        ],
        description="MySQL database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - PostgreSQL",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near",
        ],
        description="PostgreSQL database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - MSSQL",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"mssql_query\(\)",
        ],
        description="Microsoft SQL Server error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - Oracle",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_",
            r"quoted string not properly terminated",
            r"oracle\.jdbc\.driver",
        ],
        description="Oracle database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - SQLite",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLITE_ERROR",
        ],
        description="SQLite database error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Error - Generic",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.MEDIUM,
        patterns=[
            r"SQL syntax error",
            r"syntax error.*SQL",
            r"Syntax error in string in query expression",
            r"Incorrect syntax near",
            r"Unexpected end of command in statement",
            r"ODBC.*Driver.*Error",
        ],
        description="Generic SQL error message detected in response",
        false_positive_indicators=["documentation", "tutorial", "example"],
    ),
    DetectionSignature(
        name="SQL Injection - Boolean Based",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        patterns=[],  # Detected by differential analysis
        description="Response difference suggests boolean-based SQL injection",
        context_required=True,
    ),
]

XSS_SIGNATURES = [
    DetectionSignature(
        name="XSS - Reflected Script",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        patterns=[
            r"<script[^>]*>[^<]*</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"onfocus\s*=",
            r"onblur\s*=",
        ],
        description="Reflected XSS payload detected in response",
        context_required=True,  # Need to verify payload is reflected
    ),
    DetectionSignature(
        name="XSS - SVG Injection",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        patterns=[
            r"<svg[^>]*onload\s*=",
            r"<svg[^>]*onerror\s*=",
        ],
        description="SVG-based XSS vector detected in response",
        context_required=True,
    ),
    DetectionSignature(
        name="XSS - IMG Tag Injection",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        patterns=[
            r"<img[^>]*onerror\s*=",
            r"<img[^>]*onload\s*=",
            r'<img[^>]*src\s*=\s*["\']?javascript:',
        ],
        description="IMG tag-based XSS vector detected in response",
        context_required=True,
    ),
]

COMMAND_INJECTION_SIGNATURES = [
    DetectionSignature(
        name="Command Injection - Linux",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"root:.*:0:0:",  # /etc/passwd content
            r"uid=\d+.*gid=\d+",  # id command output
            r"Linux\s+\S+\s+\d+\.\d+",  # uname output
            r"/bin/(?:ba)?sh",
            r"drwx[-rwx]{9}",  # ls -la output
        ],
        description="Linux command execution output detected in response",
    ),
    DetectionSignature(
        name="Command Injection - Windows",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        patterns=[
            r"Volume Serial Number",
            r"Directory of [A-Z]:\\",
            r"Microsoft Windows \[Version",
            r"Windows IP Configuration",
            r"\[Font\]|\[Extensions\]",  # win.ini
        ],
        description="Windows command execution output detected in response",
    ),
]

PATH_TRAVERSAL_SIGNATURES = [
    DetectionSignature(
        name="Path Traversal - Linux Files",
        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        patterns=[
            r"root:.*:0:0:",  # /etc/passwd
            r"\[boot loader\]",  # boot.ini
            r"# /etc/hosts",
            r"localhost\s+127\.0\.0\.1",
        ],
        description="Sensitive Linux file content detected in response",
    ),
    DetectionSignature(
        name="Path Traversal - Windows Files",
        vuln_type=VulnerabilityType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        patterns=[
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"\[fonts\]",
            r"for 16-bit app support",
        ],
        description="Sensitive Windows file content detected in response",
    ),
]

SSTI_SIGNATURES = [
    DetectionSignature(
        name="SSTI - Template Evaluation",
        vuln_type=VulnerabilityType.SSTI,
        severity=Severity.CRITICAL,
        patterns=[
            r"49",  # 7*7 = 49
            r"7777777",  # 7*'7'
        ],
        description="Server-side template injection confirmed via math evaluation",
        context_required=True,  # Only valid if payload was {{7*7}}
    ),
    DetectionSignature(
        name="SSTI - Error Messages",
        vuln_type=VulnerabilityType.SSTI,
        severity=Severity.MEDIUM,
        patterns=[
            r"jinja2\.exceptions",
            r"mako\.exceptions",
            r"Twig_Error",
            r"freemarker\.core",
            r"velocity\.exception",
            r"TemplateError",
            r"TemplateSyntaxError",
        ],
        description="Template engine error message detected",
    ),
]

INFORMATION_DISCLOSURE_SIGNATURES = [
    DetectionSignature(
        name="Stack Trace Disclosure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.MEDIUM,
        patterns=[
            r"Traceback \(most recent call last\)",
            r"at \S+\.java:\d+",
            r"at \S+\.cs:\d+",
            r"File \"[^\"]+\", line \d+",
            r"#\d+ \S+\.php\(\d+\):",
            r"Stack trace:",
            r"Exception in thread",
        ],
        description="Application stack trace leaked in response",
    ),
    DetectionSignature(
        name="Debug Information",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.LOW,
        patterns=[
            r"DEBUG\s*[:=]\s*True",
            r"debug\s*mode\s*enabled",
            r"DJANGO_SETTINGS_MODULE",
            r"APP_ENV\s*[:=]\s*(?:dev|development)",
            r"phpinfo\(\)",
        ],
        description="Debug mode or configuration information detected",
    ),
    DetectionSignature(
        name="Sensitive Data Exposure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.HIGH,
        patterns=[
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"(?:secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
            r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----",
            r"(?:aws_)?(?:access_key|secret_key)\s*[:=]",
        ],
        description="Sensitive credentials or keys detected in response",
    ),
    DetectionSignature(
        name="Internal IP Disclosure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.LOW,
        patterns=[
            r"(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}",
        ],
        description="Internal IP address detected in response",
        false_positive_indicators=["documentation", "example", "10.0.0.1"],
    ),
    DetectionSignature(
        name="Version Disclosure",
        vuln_type=VulnerabilityType.INFORMATION_DISCLOSURE,
        severity=Severity.INFO,
        patterns=[
            r"(?:Apache|nginx|IIS|Tomcat)/[\d.]+",
            r"PHP/[\d.]+",
            r"X-Powered-By:\s*\S+",
            r"Server:\s*\S+",
        ],
        description="Server version information disclosed",
    ),
]

OPEN_REDIRECT_SIGNATURES = [
    DetectionSignature(
        name="Open Redirect",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        patterns=[
            r"(?:Location|Refresh):\s*https?://(?:evil\.com|attacker\.com|google\.com)",
        ],
        description="Open redirect detected via Location header",
        context_required=True,
    ),
]

XXE_SIGNATURES = [
    DetectionSignature(
        name="XXE - File Disclosure",
        vuln_type=VulnerabilityType.XXE,
        severity=Severity.CRITICAL,
        patterns=[
            r"root:.*:0:0:",  # /etc/passwd via XXE
        ],
        description="XXE vulnerability confirmed via file disclosure",
        context_required=True,
    ),
    DetectionSignature(
        name="XXE - Error Based",
        vuln_type=VulnerabilityType.XXE,
        severity=Severity.HIGH,
        patterns=[
            r"XMLParseError",
            r"SAXParseException",
            r"XML Parsing Error",
            r"Start tag expected",
            r"DTD.*not allowed",
        ],
        description="XML parsing error may indicate XXE testing vector",
    ),
]

LDAP_INJECTION_SIGNATURES = [
    DetectionSignature(
        name="LDAP Injection Error",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        severity=Severity.HIGH,
        patterns=[
            r"Invalid DN syntax",
            r"LdapErr:",
            r"LDAP.*error",
            r"javax\.naming\.directory",
            r"supplied argument is not a valid ldap",
        ],
        description="LDAP error message detected",
    ),
]

# Combine all signatures
ALL_SIGNATURES: List[DetectionSignature] = (
    SQL_INJECTION_SIGNATURES +
    XSS_SIGNATURES +
    COMMAND_INJECTION_SIGNATURES +
    PATH_TRAVERSAL_SIGNATURES +
    SSTI_SIGNATURES +
    INFORMATION_DISCLOSURE_SIGNATURES +
    OPEN_REDIRECT_SIGNATURES +
    XXE_SIGNATURES +
    LDAP_INJECTION_SIGNATURES
)


# =============================================================================
# Smart Detection Engine
# =============================================================================

class SmartDetectionEngine:
    """
    Intelligent detection engine for analyzing fuzzing responses.
    """
    
    def __init__(self):
        self.signatures = ALL_SIGNATURES
        self.compiled_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_patterns()
        
    def _compile_patterns(self):
        """Pre-compile all regex patterns for performance."""
        for sig in self.signatures:
            self.compiled_patterns[sig.name] = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in sig.patterns
            ]
    
    def detect_vulnerabilities(
        self,
        responses: List[Dict[str, Any]],
        baseline_response: Optional[Dict[str, Any]] = None,
    ) -> List[SmartFinding]:
        """
        Analyze responses for vulnerability indicators.
        
        Args:
            responses: List of fuzzing response dicts
            baseline_response: Optional baseline for comparison
            
        Returns:
            List of detected findings
        """
        findings: List[SmartFinding] = []
        finding_hashes: Set[str] = set()  # Deduplicate
        
        for response in responses:
            body = response.get("body", "")
            headers = response.get("headers", {})
            payload = response.get("payload", "")
            response_id = response.get("id", "unknown")
            
            # Combine body and headers for analysis
            full_response = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
            
            # Check each signature
            for sig in self.signatures:
                # Skip context-required signatures if payload doesn't match
                if sig.context_required and not self._payload_matches_context(payload, sig):
                    continue
                
                matches = self._check_signature(sig, full_response)
                if matches:
                    # Check for false positives
                    fp_likelihood = self._assess_false_positive(sig, full_response, payload)
                    
                    # Create finding hash for deduplication
                    finding_hash = hashlib.md5(
                        f"{sig.name}:{response_id}:{matches[0]}".encode()
                    ).hexdigest()
                    
                    if finding_hash not in finding_hashes:
                        finding_hashes.add(finding_hash)
                        
                        confidence = self._calculate_confidence(sig, matches, fp_likelihood)
                        
                        findings.append(SmartFinding(
                            id=finding_hash[:12],
                            vuln_type=sig.vuln_type,
                            severity=sig.severity,
                            confidence=confidence,
                            title=sig.name,
                            description=sig.description,
                            evidence=matches[:5],  # Limit evidence
                            payload=payload,
                            response_id=response_id,
                            indicators=[m[:100] for m in matches[:3]],
                            recommendation=self._get_recommendation(sig.vuln_type),
                            false_positive_likelihood=fp_likelihood,
                        ))
        
        # Sort by severity and confidence
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        findings.sort(key=lambda f: (severity_order[f.severity], -f.confidence))
        
        return findings
    
    def _check_signature(self, sig: DetectionSignature, content: str) -> List[str]:
        """Check if signature matches content."""
        matches = []
        for pattern in self.compiled_patterns.get(sig.name, []):
            for match in pattern.finditer(content):
                matches.append(match.group(0))
        return matches
    
    def _payload_matches_context(self, payload: str, sig: DetectionSignature) -> bool:
        """Check if payload is relevant for context-required signature."""
        payload_lower = payload.lower()
        
        if sig.vuln_type == VulnerabilityType.XSS:
            return any(x in payload_lower for x in ["<script", "onerror", "onload", "javascript:"])
        elif sig.vuln_type == VulnerabilityType.SSTI:
            return any(x in payload for x in ["{{", "${", "<%", "{%"])
        elif sig.vuln_type == VulnerabilityType.OPEN_REDIRECT:
            return any(x in payload_lower for x in ["http://", "https://", "//"])
        elif sig.vuln_type == VulnerabilityType.XXE:
            return any(x in payload for x in ["<!ENTITY", "<!DOCTYPE", "SYSTEM"])
        
        return True
    
    def _assess_false_positive(
        self,
        sig: DetectionSignature,
        content: str,
        payload: str
    ) -> str:
        """Assess likelihood of false positive."""
        content_lower = content.lower()
        
        # Check false positive indicators
        fp_matches = sum(
            1 for indicator in sig.false_positive_indicators
            if indicator.lower() in content_lower
        )
        
        if fp_matches >= 2:
            return "high"
        elif fp_matches == 1:
            return "medium"
        
        # Additional heuristics
        if sig.vuln_type == VulnerabilityType.XSS:
            # If payload isn't reflected, likely FP
            if payload and payload not in content:
                return "high"
        
        return "low"
    
    def _calculate_confidence(
        self,
        sig: DetectionSignature,
        matches: List[str],
        fp_likelihood: str
    ) -> float:
        """Calculate confidence score for finding."""
        base_confidence = sig.min_confidence
        
        # More matches = higher confidence
        match_bonus = min(len(matches) * 0.05, 0.2)
        
        # Reduce for false positive likelihood
        fp_penalty = {"low": 0, "medium": 0.15, "high": 0.3}.get(fp_likelihood, 0)
        
        confidence = base_confidence + match_bonus - fp_penalty
        return max(0.1, min(1.0, confidence))
    
    def _get_recommendation(self, vuln_type: VulnerabilityType) -> str:
        """Get remediation recommendation for vulnerability type."""
        recommendations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            VulnerabilityType.XSS: "Encode output based on context (HTML, JavaScript, URL). Use Content-Security-Policy headers.",
            VulnerabilityType.COMMAND_INJECTION: "Avoid system commands with user input. Use safe APIs and input validation.",
            VulnerabilityType.PATH_TRAVERSAL: "Validate and sanitize file paths. Use a whitelist of allowed files.",
            VulnerabilityType.SSRF: "Validate and whitelist URLs. Block internal IP ranges.",
            VulnerabilityType.XXE: "Disable external entity processing in XML parsers.",
            VulnerabilityType.SSTI: "Avoid passing user input to template engines. Use sandboxed templates.",
            VulnerabilityType.LDAP_INJECTION: "Escape special LDAP characters in user input.",
            VulnerabilityType.XPATH_INJECTION: "Use parameterized XPath queries.",
            VulnerabilityType.OPEN_REDIRECT: "Validate redirect URLs against a whitelist.",
            VulnerabilityType.IDOR: "Implement proper access controls and authorization checks.",
            VulnerabilityType.INFORMATION_DISCLOSURE: "Disable debug mode in production. Remove verbose error messages.",
            VulnerabilityType.ERROR_BASED: "Implement custom error handlers that don't leak information.",
            VulnerabilityType.AUTH_BYPASS: "Review authentication logic and implement proper session management.",
            VulnerabilityType.BUSINESS_LOGIC: "Review business logic for edge cases and implement proper validation.",
        }
        return recommendations.get(vuln_type, "Review the application logic and implement proper input validation.")
    
    def detect_anomalies(
        self,
        responses: List[Dict[str, Any]],
        baseline_responses: Optional[List[Dict[str, Any]]] = None,
    ) -> List[AnomalyResult]:
        """
        Detect anomalous responses using statistical analysis.
        
        Args:
            responses: List of fuzzing response dicts
            baseline_responses: Optional baseline responses for comparison
            
        Returns:
            List of anomaly results
        """
        anomalies: List[AnomalyResult] = []
        
        if len(responses) < 3:
            return anomalies
        
        # Calculate baselines
        response_times = [r.get("response_time", 0) for r in responses]
        response_lengths = [r.get("response_length", 0) for r in responses]
        status_codes = [r.get("status_code", 0) for r in responses]
        
        # Statistical baselines
        time_mean = statistics.mean(response_times) if response_times else 0
        time_stdev = statistics.stdev(response_times) if len(response_times) > 1 else 0
        
        length_mean = statistics.mean(response_lengths) if response_lengths else 0
        length_stdev = statistics.stdev(response_lengths) if len(response_lengths) > 1 else 0
        
        # Most common status code
        status_counts = defaultdict(int)
        for code in status_codes:
            status_counts[code] += 1
        baseline_status = max(status_counts.keys(), key=lambda k: status_counts[k]) if status_counts else 200
        
        # Content hash baseline
        content_hashes = defaultdict(int)
        for r in responses:
            body = r.get("body", "")
            content_hash = hashlib.md5(body.encode()).hexdigest()[:8]
            content_hashes[content_hash] += 1
        baseline_hash = max(content_hashes.keys(), key=lambda k: content_hashes[k]) if content_hashes else ""
        
        # Detect anomalies
        for response in responses:
            response_id = response.get("id", "unknown")
            
            # Time anomaly (z-score > 2)
            if time_stdev > 0:
                time_val = response.get("response_time", 0)
                z_score = abs(time_val - time_mean) / time_stdev
                if z_score > 2:
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="time",
                        score=min(z_score / 4, 1.0),
                        baseline_value=round(time_mean, 2),
                        actual_value=time_val,
                        deviation=round(z_score, 2),
                        description=f"Response time ({time_val}ms) is {z_score:.1f} standard deviations from mean ({time_mean:.0f}ms)",
                    ))
            
            # Length anomaly (z-score > 2)
            if length_stdev > 0:
                length_val = response.get("response_length", 0)
                z_score = abs(length_val - length_mean) / length_stdev
                if z_score > 2:
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="length",
                        score=min(z_score / 4, 1.0),
                        baseline_value=int(length_mean),
                        actual_value=length_val,
                        deviation=round(z_score, 2),
                        description=f"Response length ({length_val}) is {z_score:.1f} standard deviations from mean ({length_mean:.0f})",
                    ))
            
            # Status code anomaly
            status = response.get("status_code", 200)
            if status != baseline_status:
                # Calculate rarity
                status_ratio = status_counts.get(status, 0) / len(responses)
                if status_ratio < 0.1:  # Less than 10% of responses
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="status",
                        score=1 - status_ratio,
                        baseline_value=baseline_status,
                        actual_value=status,
                        deviation=0,
                        description=f"Uncommon status code {status} (only {status_ratio*100:.1f}% of responses)",
                    ))
            
            # Content anomaly
            body = response.get("body", "")
            content_hash = hashlib.md5(body.encode()).hexdigest()[:8]
            if content_hash != baseline_hash:
                hash_ratio = content_hashes.get(content_hash, 0) / len(responses)
                if hash_ratio < 0.1:  # Less than 10% of responses
                    anomalies.append(AnomalyResult(
                        response_id=response_id,
                        anomaly_type="content",
                        score=1 - hash_ratio,
                        baseline_value=baseline_hash,
                        actual_value=content_hash,
                        deviation=0,
                        description=f"Unique response content (only {hash_ratio*100:.1f}% of responses have similar content)",
                    ))
        
        # Sort by score
        anomalies.sort(key=lambda a: -a.score)
        
        return anomalies
    
    def differential_analysis(
        self,
        baseline_response: Dict[str, Any],
        test_responses: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Perform differential analysis comparing responses to a baseline.
        
        Useful for detecting:
        - Boolean-based SQL injection
        - Authentication bypass
        - Access control issues
        """
        results = []
        
        baseline_length = baseline_response.get("response_length", 0)
        baseline_status = baseline_response.get("status_code", 200)
        baseline_body = baseline_response.get("body", "")
        baseline_hash = hashlib.md5(baseline_body.encode()).hexdigest()
        
        for response in test_responses:
            diff_result = {
                "response_id": response.get("id"),
                "payload": response.get("payload"),
                "differences": [],
                "similarity_score": 0.0,
                "potentially_interesting": False,
            }
            
            # Status code difference
            status = response.get("status_code", 200)
            if status != baseline_status:
                diff_result["differences"].append({
                    "type": "status_code",
                    "baseline": baseline_status,
                    "current": status,
                })
            
            # Length difference
            length = response.get("response_length", 0)
            length_diff_pct = abs(length - baseline_length) / max(baseline_length, 1) * 100
            if length_diff_pct > 10:  # More than 10% difference
                diff_result["differences"].append({
                    "type": "length",
                    "baseline": baseline_length,
                    "current": length,
                    "difference_percent": round(length_diff_pct, 1),
                })
            
            # Content difference
            body = response.get("body", "")
            body_hash = hashlib.md5(body.encode()).hexdigest()
            if body_hash != baseline_hash:
                # Calculate similarity using set of words
                baseline_words = set(baseline_body.lower().split())
                current_words = set(body.lower().split())
                if baseline_words or current_words:
                    intersection = baseline_words & current_words
                    union = baseline_words | current_words
                    similarity = len(intersection) / len(union) if union else 1.0
                    diff_result["similarity_score"] = round(similarity, 3)
                    
                    if similarity < 0.9:  # Less than 90% similar
                        diff_result["differences"].append({
                            "type": "content",
                            "similarity": round(similarity, 3),
                        })
            else:
                diff_result["similarity_score"] = 1.0
            
            # Mark as interesting if significant differences
            if diff_result["differences"]:
                diff_result["potentially_interesting"] = True
            
            results.append(diff_result)
        
        # Sort by number of differences (more = more interesting)
        results.sort(key=lambda r: -len(r["differences"]))
        
        return results
    
    def categorize_responses(
        self,
        responses: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """
        Automatically categorize responses into groups.
        
        Returns categories like:
        - success: 2xx responses
        - redirect: 3xx responses  
        - client_error: 4xx responses
        - server_error: 5xx responses
        - interesting: Flagged as potentially vulnerable
        - timeout: Timed out requests
        - blocked: Potentially blocked by WAF
        """
        categories = defaultdict(list)
        
        for response in responses:
            response_id = response.get("id", "unknown")
            status = response.get("status_code", 0)
            flags = response.get("flags", [])
            error = response.get("error", "")
            body = response.get("body", "").lower()
            
            # Status-based categorization
            if 200 <= status < 300:
                categories["success"].append(response_id)
            elif 300 <= status < 400:
                categories["redirect"].append(response_id)
            elif 400 <= status < 500:
                categories["client_error"].append(response_id)
                if status == 401:
                    categories["auth_required"].append(response_id)
                elif status == 403:
                    categories["forbidden"].append(response_id)
                elif status == 429:
                    categories["rate_limited"].append(response_id)
            elif status >= 500:
                categories["server_error"].append(response_id)
            
            # Flag-based categorization
            if "interesting" in flags or response.get("interesting"):
                categories["interesting"].append(response_id)
            
            # Error-based categorization
            if "timeout" in error.lower():
                categories["timeout"].append(response_id)
            
            # WAF detection
            waf_indicators = [
                "blocked", "forbidden", "access denied",
                "security", "waf", "firewall", "cloudflare",
                "request rejected", "not acceptable",
            ]
            if any(ind in body for ind in waf_indicators):
                categories["blocked"].append(response_id)
        
        return dict(categories)


# =============================================================================
# Session Management Functions
# =============================================================================

def create_session_summary(
    session_data: Dict[str, Any],
    findings: List[SmartFinding],
    anomalies: List[AnomalyResult],
) -> Dict[str, Any]:
    """Create a summary for a fuzzing session."""
    
    # Count findings by severity
    severity_counts = defaultdict(int)
    vuln_type_counts = defaultdict(int)
    for finding in findings:
        severity_counts[finding.severity.value] += 1
        vuln_type_counts[finding.vuln_type.value] += 1
    
    # Calculate risk score
    severity_weights = {
        "critical": 40,
        "high": 25,
        "medium": 10,
        "low": 3,
        "info": 1,
    }
    risk_score = sum(
        severity_weights.get(sev, 0) * count
        for sev, count in severity_counts.items()
    )
    risk_score = min(100, risk_score)  # Cap at 100
    
    return {
        "total_requests": session_data.get("total_requests", 0),
        "success_count": session_data.get("success_count", 0),
        "error_count": session_data.get("error_count", 0),
        "interesting_count": session_data.get("interesting_count", 0),
        "findings_count": len(findings),
        "anomalies_count": len(anomalies),
        "severity_breakdown": dict(severity_counts),
        "vulnerability_types": dict(vuln_type_counts),
        "risk_score": risk_score,
        "risk_level": (
            "critical" if risk_score >= 70 else
            "high" if risk_score >= 40 else
            "medium" if risk_score >= 20 else
            "low" if risk_score >= 5 else
            "info"
        ),
    }


# Create singleton instance
detection_engine = SmartDetectionEngine()


# Convenience functions
def detect_vulnerabilities(
    responses: List[Dict[str, Any]],
    baseline_response: Optional[Dict[str, Any]] = None,
) -> List[SmartFinding]:
    """Detect vulnerabilities in responses."""
    return detection_engine.detect_vulnerabilities(responses, baseline_response)


def detect_anomalies(
    responses: List[Dict[str, Any]],
    baseline_responses: Optional[List[Dict[str, Any]]] = None,
) -> List[AnomalyResult]:
    """Detect anomalous responses."""
    return detection_engine.detect_anomalies(responses, baseline_responses)


def differential_analysis(
    baseline_response: Dict[str, Any],
    test_responses: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Perform differential analysis."""
    return detection_engine.differential_analysis(baseline_response, test_responses)


def categorize_responses(responses: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Categorize responses into groups."""
    return detection_engine.categorize_responses(responses)
