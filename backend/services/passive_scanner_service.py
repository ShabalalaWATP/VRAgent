"""
Passive Analysis Scanner Service

Extracts vulnerabilities and security issues from HTTP responses without active probing.
Analyzes headers, cookies, body content, and metadata for security weaknesses.
"""

import re
import hashlib
import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs
import base64
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class PassiveFindingSeverity(Enum):
    """Severity levels for passive findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PassiveFindingType(Enum):
    """Types of passive security findings."""
    # Header Issues
    MISSING_SECURITY_HEADER = "missing_security_header"
    WEAK_SECURITY_HEADER = "weak_security_header"
    DEPRECATED_HEADER = "deprecated_header"
    INFORMATION_DISCLOSURE_HEADER = "information_disclosure_header"
    
    # Cookie Issues
    INSECURE_COOKIE = "insecure_cookie"
    MISSING_COOKIE_FLAG = "missing_cookie_flag"
    SENSITIVE_COOKIE_EXPOSURE = "sensitive_cookie_exposure"
    SESSION_FIXATION_RISK = "session_fixation_risk"
    
    # Information Disclosure
    SERVER_VERSION_DISCLOSURE = "server_version_disclosure"
    TECHNOLOGY_DISCLOSURE = "technology_disclosure"
    DEBUG_INFORMATION = "debug_information"
    STACK_TRACE = "stack_trace"
    ERROR_MESSAGE_DISCLOSURE = "error_message_disclosure"
    PATH_DISCLOSURE = "path_disclosure"
    IP_DISCLOSURE = "ip_disclosure"
    EMAIL_DISCLOSURE = "email_disclosure"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    API_KEY_EXPOSURE = "api_key_exposure"
    PRIVATE_KEY_EXPOSURE = "private_key_exposure"
    DATABASE_ERROR = "database_error"
    SOURCE_CODE_DISCLOSURE = "source_code_disclosure"
    COMMENT_DISCLOSURE = "comment_disclosure"
    
    # Configuration Issues
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CSP_MISCONFIGURATION = "csp_misconfiguration"
    HSTS_MISCONFIGURATION = "hsts_misconfiguration"
    CACHE_CONTROL_ISSUE = "cache_control_issue"
    
    # SSL/TLS Issues
    MIXED_CONTENT = "mixed_content"
    INSECURE_REDIRECT = "insecure_redirect"
    
    # API Issues
    RATE_LIMIT_HEADER_LEAK = "rate_limit_header_leak"
    INTERNAL_API_EXPOSURE = "internal_api_exposure"
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    SWAGGER_EXPOSURE = "swagger_exposure"
    
    # Authentication Issues
    AUTH_TOKEN_IN_URL = "auth_token_in_url"
    WEAK_SESSION_ID = "weak_session_id"
    JWT_ISSUES = "jwt_issues"
    
    # Content Issues
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    PII_EXPOSURE = "pii_exposure"
    CREDIT_CARD_EXPOSURE = "credit_card_exposure"
    SSN_EXPOSURE = "ssn_exposure"


@dataclass
class PassiveFinding:
    """A passive security finding."""
    finding_type: PassiveFindingType
    severity: PassiveFindingSeverity
    title: str
    description: str
    evidence: str
    location: str  # header, cookie, body, url
    remediation: str
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[int] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityHeader:
    """Security header configuration."""
    name: str
    required: bool = False
    recommended_value: Optional[str] = None
    check_func: Optional[str] = None
    severity_if_missing: PassiveFindingSeverity = PassiveFindingSeverity.MEDIUM
    description: str = ""
    cwe_id: Optional[int] = None


class PassiveScanner:
    """
    Comprehensive passive security scanner.
    Extracts vulnerabilities from HTTP responses without sending additional requests.
    """
    
    # Security headers to check
    SECURITY_HEADERS: List[SecurityHeader] = [
        SecurityHeader(
            name="Strict-Transport-Security",
            required=True,
            severity_if_missing=PassiveFindingSeverity.HIGH,
            description="HSTS ensures browsers only use HTTPS",
            cwe_id=319
        ),
        SecurityHeader(
            name="Content-Security-Policy",
            required=True,
            severity_if_missing=PassiveFindingSeverity.MEDIUM,
            description="CSP prevents XSS and injection attacks",
            cwe_id=79
        ),
        SecurityHeader(
            name="X-Content-Type-Options",
            required=True,
            recommended_value="nosniff",
            severity_if_missing=PassiveFindingSeverity.MEDIUM,
            description="Prevents MIME-type sniffing",
            cwe_id=16
        ),
        SecurityHeader(
            name="X-Frame-Options",
            required=True,
            severity_if_missing=PassiveFindingSeverity.MEDIUM,
            description="Prevents clickjacking attacks",
            cwe_id=1021
        ),
        SecurityHeader(
            name="X-XSS-Protection",
            required=False,
            severity_if_missing=PassiveFindingSeverity.LOW,
            description="Legacy XSS protection (deprecated but still useful)",
            cwe_id=79
        ),
        SecurityHeader(
            name="Referrer-Policy",
            required=False,
            severity_if_missing=PassiveFindingSeverity.LOW,
            description="Controls referrer information leakage",
            cwe_id=200
        ),
        SecurityHeader(
            name="Permissions-Policy",
            required=False,
            severity_if_missing=PassiveFindingSeverity.LOW,
            description="Controls browser feature access",
            cwe_id=16
        ),
        SecurityHeader(
            name="Cross-Origin-Embedder-Policy",
            required=False,
            severity_if_missing=PassiveFindingSeverity.INFO,
            description="Cross-origin isolation",
            cwe_id=16
        ),
        SecurityHeader(
            name="Cross-Origin-Opener-Policy",
            required=False,
            severity_if_missing=PassiveFindingSeverity.INFO,
            description="Cross-origin isolation",
            cwe_id=16
        ),
        SecurityHeader(
            name="Cross-Origin-Resource-Policy",
            required=False,
            severity_if_missing=PassiveFindingSeverity.INFO,
            description="Cross-origin resource sharing control",
            cwe_id=16
        ),
    ]
    
    # Headers that leak information
    INFO_DISCLOSURE_HEADERS = [
        "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
        "X-Runtime", "X-Version", "X-Backend-Server", "X-Server-Name",
        "X-Node", "X-Instance-ID", "X-Debug", "X-Debug-Token",
        "X-CF-Instance-ID", "X-CF-Instance-Index", "X-Request-ID",
    ]
    
    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        "email": (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', PassiveFindingSeverity.LOW),
        "ipv4": (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', PassiveFindingSeverity.LOW),
        "ipv6": (r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', PassiveFindingSeverity.LOW),
        "credit_card": (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b', PassiveFindingSeverity.CRITICAL),
        "ssn": (r'\b\d{3}-\d{2}-\d{4}\b', PassiveFindingSeverity.CRITICAL),
        "aws_key": (r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', PassiveFindingSeverity.CRITICAL),
        "aws_secret": (r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', PassiveFindingSeverity.HIGH),
        "gcp_key": (r'AIza[0-9A-Za-z_-]{35}', PassiveFindingSeverity.CRITICAL),
        "azure_key": (r'[A-Za-z0-9+/]{86}==', PassiveFindingSeverity.HIGH),
        "github_token": (r'gh[pousr]_[A-Za-z0-9_]{36,}', PassiveFindingSeverity.CRITICAL),
        "jwt": (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', PassiveFindingSeverity.MEDIUM),
        "private_key": (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', PassiveFindingSeverity.CRITICAL),
        "password_field": (r'(?:password|passwd|pwd|secret|token|api_key|apikey|auth|credentials?)\s*[=:]\s*["\']?([^"\'\s<>]{4,})', PassiveFindingSeverity.HIGH),
        "connection_string": (r'(?:mongodb|mysql|postgres|redis|amqp|mssql):\/\/[^\s<>"\']+', PassiveFindingSeverity.CRITICAL),
        "bearer_token": (r'Bearer\s+[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*', PassiveFindingSeverity.HIGH),
        "basic_auth": (r'Basic\s+[A-Za-z0-9+/]+=*', PassiveFindingSeverity.HIGH),
        "slack_token": (r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}', PassiveFindingSeverity.CRITICAL),
        "stripe_key": (r'sk_(?:live|test)_[0-9a-zA-Z]{24,}', PassiveFindingSeverity.CRITICAL),
        "sendgrid_key": (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', PassiveFindingSeverity.CRITICAL),
        "twilio_key": (r'SK[a-f0-9]{32}', PassiveFindingSeverity.CRITICAL),
        "mailgun_key": (r'key-[0-9a-zA-Z]{32}', PassiveFindingSeverity.CRITICAL),
        "heroku_key": (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', PassiveFindingSeverity.HIGH),
    }
    
    # Debug/error patterns
    DEBUG_PATTERNS = {
        "stack_trace_python": (r'Traceback \(most recent call last\):', PassiveFindingSeverity.MEDIUM),
        "stack_trace_java": (r'(?:java\.lang\.\w+Exception|at [\w.$]+\([\w.]+:\d+\))', PassiveFindingSeverity.MEDIUM),
        "stack_trace_php": (r'(?:Fatal error|Parse error|Warning|Notice):\s+.*?(?:in|on line)\s+', PassiveFindingSeverity.MEDIUM),
        "stack_trace_dotnet": (r'System\.\w+Exception:', PassiveFindingSeverity.MEDIUM),
        "stack_trace_node": (r'at\s+(?:\w+\s+\()?(?:\/[^\s]+|\[[^\]]+\]):\d+:\d+\)?', PassiveFindingSeverity.MEDIUM),
        "stack_trace_ruby": (r'(?:\w+Error|Exception).*?:in\s+`\w+\'', PassiveFindingSeverity.MEDIUM),
        "sql_error": (r'(?:SQL syntax|mysql_fetch|ORA-\d{5}|PG::Error|sqlite3|SQLSTATE)', PassiveFindingSeverity.HIGH),
        "debug_mode": (r'(?:DEBUG\s*[=:]\s*[Tt]rue|debug_mode|DEVELOPMENT|staging)', PassiveFindingSeverity.MEDIUM),
        "verbose_error": (r'(?:Undefined (?:variable|index|offset)|Call to undefined|Cannot (?:read|access)|TypeError:|ReferenceError:)', PassiveFindingSeverity.LOW),
    }
    
    # Path disclosure patterns
    PATH_PATTERNS = {
        "unix_path": (r'(?:/(?:home|var|etc|usr|opt|tmp)/[\w/.-]+)', PassiveFindingSeverity.LOW),
        "windows_path": (r'(?:[A-Za-z]:\\(?:Users|Windows|Program Files|inetpub)\\[^\s<>"\']+)', PassiveFindingSeverity.LOW),
        "web_root": (r'(?:/var/www/|/srv/http/|C:\\inetpub\\wwwroot\\)', PassiveFindingSeverity.MEDIUM),
    }

    def __init__(self):
        """Initialize the passive scanner."""
        self._findings_cache: Dict[str, List[PassiveFinding]] = {}
        self._seen_hashes: Set[str] = set()
        self._stats = {
            "responses_scanned": 0,
            "findings_total": 0,
            "findings_by_severity": {s.value: 0 for s in PassiveFindingSeverity},
            "findings_by_type": {},
        }

    def scan_response(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        request_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> List[PassiveFinding]:
        """
        Perform comprehensive passive scan on an HTTP response.
        
        Args:
            url: The request URL
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            request_headers: Original request headers (for context)
            cookies: Cookies from Set-Cookie headers
            
        Returns:
            List of passive findings
        """
        findings: List[PassiveFinding] = []
        
        # Normalize headers to lowercase keys
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Run all passive checks
        findings.extend(self._check_security_headers(headers_lower, url))
        findings.extend(self._check_info_disclosure_headers(headers_lower, url))
        findings.extend(self._check_cookies(headers_lower, url))
        findings.extend(self._check_cors(headers_lower, request_headers, url))
        findings.extend(self._check_csp(headers_lower, url))
        findings.extend(self._check_hsts(headers_lower, url))
        findings.extend(self._check_cache_headers(headers_lower, url))
        findings.extend(self._check_body_disclosure(body, url))
        findings.extend(self._check_sensitive_data(body, url))
        findings.extend(self._check_debug_info(body, url))
        findings.extend(self._check_path_disclosure(body, url))
        findings.extend(self._check_url_issues(url))
        findings.extend(self._check_api_exposure(body, headers_lower, url))
        findings.extend(self._check_jwt_issues(body, headers_lower, url))
        findings.extend(self._check_html_comments(body, url))
        
        # Deduplicate findings
        unique_findings = self._deduplicate_findings(findings)
        
        # Update stats
        self._stats["responses_scanned"] += 1
        self._stats["findings_total"] += len(unique_findings)
        for finding in unique_findings:
            self._stats["findings_by_severity"][finding.severity.value] += 1
            finding_type = finding.finding_type.value
            self._stats["findings_by_type"][finding_type] = \
                self._stats["findings_by_type"].get(finding_type, 0) + 1
        
        return unique_findings

    def _check_security_headers(
        self, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check for missing or weak security headers."""
        findings = []
        
        for header in self.SECURITY_HEADERS:
            header_name_lower = header.name.lower()
            
            if header_name_lower not in headers:
                if header.required:
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.MISSING_SECURITY_HEADER,
                        severity=header.severity_if_missing,
                        title=f"Missing Security Header: {header.name}",
                        description=f"The {header.name} header is not set. {header.description}",
                        evidence=f"Header '{header.name}' not found in response",
                        location="header",
                        remediation=f"Add the {header.name} header to your server configuration",
                        cwe_id=header.cwe_id,
                        references=[
                            f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header.name}"
                        ],
                    ))
            elif header.recommended_value:
                actual_value = headers[header_name_lower]
                if actual_value.lower() != header.recommended_value.lower():
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.WEAK_SECURITY_HEADER,
                        severity=PassiveFindingSeverity.LOW,
                        title=f"Weak Security Header Value: {header.name}",
                        description=f"The {header.name} header has value '{actual_value}' "
                                   f"instead of recommended '{header.recommended_value}'",
                        evidence=f"{header.name}: {actual_value}",
                        location="header",
                        remediation=f"Set {header.name}: {header.recommended_value}",
                        cwe_id=header.cwe_id,
                    ))
        
        return findings

    def _check_info_disclosure_headers(
        self, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check for information disclosure in headers."""
        findings = []
        
        for header in self.INFO_DISCLOSURE_HEADERS:
            header_lower = header.lower()
            if header_lower in headers:
                value = headers[header_lower]
                
                # Check for version info
                version_match = re.search(r'[\d.]+', value)
                
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.INFORMATION_DISCLOSURE_HEADER,
                    severity=PassiveFindingSeverity.LOW if not version_match else PassiveFindingSeverity.MEDIUM,
                    title=f"Information Disclosure: {header}",
                    description=f"The {header} header reveals server information: {value}",
                    evidence=f"{header}: {value}",
                    location="header",
                    remediation=f"Remove or obfuscate the {header} header",
                    cwe_id=200,
                    metadata={"version_found": version_match.group() if version_match else None},
                ))
        
        return findings

    def _check_cookies(
        self, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check for cookie security issues."""
        findings = []
        
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return findings
        
        # Parse cookie(s) - might be multiple
        cookies = set_cookie.split(",") if "," in set_cookie else [set_cookie]
        
        for cookie_str in cookies:
            cookie_parts = cookie_str.strip().split(";")
            if not cookie_parts:
                continue
                
            cookie_name = cookie_parts[0].split("=")[0].strip()
            cookie_lower = cookie_str.lower()
            
            # Check Secure flag
            if "secure" not in cookie_lower:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.MISSING_COOKIE_FLAG,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title=f"Cookie Missing Secure Flag: {cookie_name}",
                    description=f"Cookie '{cookie_name}' does not have the Secure flag set, "
                               f"allowing transmission over unencrypted HTTP",
                    evidence=cookie_str[:200],
                    location="cookie",
                    remediation="Add the Secure flag to the cookie",
                    cwe_id=614,
                ))
            
            # Check HttpOnly flag for session cookies
            session_indicators = ["session", "sess", "sid", "auth", "token", "jwt", "login"]
            is_session_cookie = any(ind in cookie_name.lower() for ind in session_indicators)
            
            if is_session_cookie and "httponly" not in cookie_lower:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.MISSING_COOKIE_FLAG,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title=f"Session Cookie Missing HttpOnly Flag: {cookie_name}",
                    description=f"Session cookie '{cookie_name}' does not have the HttpOnly flag, "
                               f"making it accessible to JavaScript and vulnerable to XSS",
                    evidence=cookie_str[:200],
                    location="cookie",
                    remediation="Add the HttpOnly flag to session cookies",
                    cwe_id=1004,
                ))
            
            # Check SameSite attribute
            if "samesite" not in cookie_lower:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.MISSING_COOKIE_FLAG,
                    severity=PassiveFindingSeverity.LOW,
                    title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                    description=f"Cookie '{cookie_name}' does not have the SameSite attribute, "
                               f"potentially vulnerable to CSRF attacks",
                    evidence=cookie_str[:200],
                    location="cookie",
                    remediation="Add SameSite=Strict or SameSite=Lax to the cookie",
                    cwe_id=352,
                ))
            elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.INSECURE_COOKIE,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title=f"SameSite=None Without Secure: {cookie_name}",
                    description=f"Cookie '{cookie_name}' uses SameSite=None without Secure flag, "
                               f"which is rejected by modern browsers",
                    evidence=cookie_str[:200],
                    location="cookie",
                    remediation="Add Secure flag when using SameSite=None",
                    cwe_id=614,
                ))
            
            # Check for weak session IDs (short, predictable)
            if is_session_cookie:
                cookie_value = cookie_parts[0].split("=", 1)[1] if "=" in cookie_parts[0] else ""
                if len(cookie_value) < 16:
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.WEAK_SESSION_ID,
                        severity=PassiveFindingSeverity.HIGH,
                        title=f"Potentially Weak Session ID: {cookie_name}",
                        description=f"Session ID appears short ({len(cookie_value)} chars), "
                                   f"potentially weak entropy",
                        evidence=f"{cookie_name}={cookie_value[:20]}...",
                        location="cookie",
                        remediation="Use cryptographically secure session IDs with at least 128 bits of entropy",
                        cwe_id=330,
                    ))
        
        return findings

    def _check_cors(
        self, 
        headers: Dict[str, str],
        request_headers: Optional[Dict[str, str]],
        url: str
    ) -> List[PassiveFinding]:
        """Check for CORS misconfigurations."""
        findings = []
        
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        
        if not acao:
            return findings
        
        # Wildcard with credentials
        if acao == "*" and acac == "true":
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.CORS_MISCONFIGURATION,
                severity=PassiveFindingSeverity.HIGH,
                title="CORS Wildcard with Credentials",
                description="Access-Control-Allow-Origin is * with credentials enabled. "
                           "This is actually blocked by browsers but indicates misconfiguration.",
                evidence=f"Access-Control-Allow-Origin: {acao}, "
                        f"Access-Control-Allow-Credentials: {acac}",
                location="header",
                remediation="Don't use wildcard origin with credentials. Whitelist specific origins.",
                cwe_id=942,
            ))
        
        # Reflects origin with credentials (dangerous)
        if request_headers:
            request_origin = request_headers.get("Origin", "")
            if request_origin and acao == request_origin and acac == "true":
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CORS_MISCONFIGURATION,
                    severity=PassiveFindingSeverity.HIGH,
                    title="CORS Origin Reflection with Credentials",
                    description="The server reflects the Origin header in ACAO with credentials enabled, "
                               "potentially allowing any site to make authenticated requests",
                    evidence=f"Origin reflected: {request_origin}",
                    location="header",
                    remediation="Whitelist specific trusted origins instead of reflecting the Origin header",
                    cwe_id=942,
                ))
        
        # Null origin allowed
        if acao.lower() == "null" and acac == "true":
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.CORS_MISCONFIGURATION,
                severity=PassiveFindingSeverity.MEDIUM,
                title="CORS Null Origin Allowed",
                description="Access-Control-Allow-Origin allows 'null' origin which can be "
                           "exploited via sandboxed iframes",
                evidence=f"Access-Control-Allow-Origin: null",
                location="header",
                remediation="Don't allow null origin, use specific trusted origins",
                cwe_id=942,
            ))
        
        return findings

    def _check_csp(
        self, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check Content Security Policy for weaknesses."""
        findings = []
        
        csp = headers.get("content-security-policy", "")
        if not csp:
            return findings
        
        # Parse CSP directives
        directives = {}
        for directive in csp.split(";"):
            parts = directive.strip().split(None, 1)
            if parts:
                directives[parts[0]] = parts[1] if len(parts) > 1 else ""
        
        # Check for unsafe directives
        for directive, value in directives.items():
            if "'unsafe-inline'" in value:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CSP_MISCONFIGURATION,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title=f"CSP unsafe-inline in {directive}",
                    description=f"The {directive} directive allows 'unsafe-inline', "
                               f"which defeats XSS protection",
                    evidence=f"{directive}: {value[:100]}",
                    location="header",
                    remediation="Remove 'unsafe-inline' and use nonces or hashes instead",
                    cwe_id=79,
                ))
            
            if "'unsafe-eval'" in value:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CSP_MISCONFIGURATION,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title=f"CSP unsafe-eval in {directive}",
                    description=f"The {directive} directive allows 'unsafe-eval', "
                               f"enabling JavaScript eval() function",
                    evidence=f"{directive}: {value[:100]}",
                    location="header",
                    remediation="Remove 'unsafe-eval' and refactor code to avoid eval()",
                    cwe_id=79,
                ))
            
            # Check for wildcard domains
            if "*" in value and "data:" not in value and "blob:" not in value:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CSP_MISCONFIGURATION,
                    severity=PassiveFindingSeverity.LOW,
                    title=f"CSP Wildcard Source in {directive}",
                    description=f"The {directive} directive contains wildcard sources",
                    evidence=f"{directive}: {value[:100]}",
                    location="header",
                    remediation="Avoid wildcards, specify exact trusted domains",
                    cwe_id=79,
                ))
        
        # Check for missing important directives
        important_directives = ["default-src", "script-src", "object-src"]
        for directive in important_directives:
            if directive not in directives and "default-src" not in directives:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CSP_MISCONFIGURATION,
                    severity=PassiveFindingSeverity.LOW,
                    title=f"CSP Missing {directive}",
                    description=f"The CSP does not include {directive} and may rely on browser defaults",
                    evidence=csp[:200],
                    location="header",
                    remediation=f"Add {directive} to the CSP",
                    cwe_id=79,
                ))
        
        return findings

    def _check_hsts(
        self, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check HSTS header configuration."""
        findings = []
        
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            return findings
        
        # Parse HSTS
        max_age_match = re.search(r'max-age=(\d+)', hsts.lower())
        if max_age_match:
            max_age = int(max_age_match.group(1))
            
            # Check for low max-age (less than 6 months = 15768000 seconds)
            if max_age < 15768000:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.HSTS_MISCONFIGURATION,
                    severity=PassiveFindingSeverity.LOW,
                    title="HSTS max-age Too Short",
                    description=f"HSTS max-age is {max_age} seconds ({max_age // 86400} days), "
                               f"should be at least 6 months (15768000 seconds)",
                    evidence=hsts,
                    location="header",
                    remediation="Set max-age to at least 31536000 (1 year)",
                    cwe_id=319,
                ))
        
        # Check for includeSubDomains
        if "includesubdomains" not in hsts.lower():
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.HSTS_MISCONFIGURATION,
                severity=PassiveFindingSeverity.INFO,
                title="HSTS Missing includeSubDomains",
                description="HSTS does not include subdomains",
                evidence=hsts,
                location="header",
                remediation="Add includeSubDomains to protect all subdomains",
                cwe_id=319,
            ))
        
        return findings

    def _check_cache_headers(
        self, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check for sensitive caching issues."""
        findings = []
        
        cache_control = headers.get("cache-control", "").lower()
        pragma = headers.get("pragma", "").lower()
        
        # If there's no cache control on sensitive endpoints
        sensitive_paths = ["/api/", "/auth", "/login", "/user", "/account", "/admin", "/token"]
        is_sensitive = any(path in url.lower() for path in sensitive_paths)
        
        if is_sensitive:
            if not cache_control or ("no-store" not in cache_control and "private" not in cache_control):
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.CACHE_CONTROL_ISSUE,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title="Sensitive Endpoint May Be Cached",
                    description="This sensitive endpoint does not have proper cache-control headers, "
                               "responses may be cached by intermediaries",
                    evidence=f"Cache-Control: {cache_control or 'not set'}",
                    location="header",
                    remediation="Add 'Cache-Control: no-store, private' for sensitive endpoints",
                    cwe_id=525,
                ))
        
        return findings

    def _check_body_disclosure(
        self, body: str, url: str
    ) -> List[PassiveFinding]:
        """Check response body for general information disclosure."""
        findings = []
        
        # Check for source code disclosure
        code_patterns = [
            (r'<\?php', "PHP source code"),
            (r'<%@?\s*(?:page|include|taglib)', "JSP source code"),
            (r'<asp:', "ASP.NET source code"),
            (r'#!/(?:bin/)?(?:bash|sh|python|perl|ruby)', "Script source code"),
        ]
        
        for pattern, desc in code_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.SOURCE_CODE_DISCLOSURE,
                    severity=PassiveFindingSeverity.HIGH,
                    title=f"Possible Source Code Disclosure: {desc}",
                    description=f"Response appears to contain {desc}",
                    evidence=body[:500],
                    location="body",
                    remediation="Ensure server-side code is not exposed in responses",
                    cwe_id=540,
                ))
        
        return findings

    def _check_sensitive_data(
        self, body: str, url: str
    ) -> List[PassiveFinding]:
        """Check for sensitive data patterns in response body."""
        findings = []
        
        for pattern_name, (pattern, severity) in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                # Limit matches for evidence
                sample_matches = matches[:3]
                
                # Mask sensitive data in evidence
                masked = [self._mask_sensitive(m) if isinstance(m, str) else m for m in sample_matches]
                
                findings.append(PassiveFinding(
                    finding_type=self._get_finding_type_for_pattern(pattern_name),
                    severity=severity,
                    title=f"Sensitive Data Exposure: {pattern_name.replace('_', ' ').title()}",
                    description=f"Found {len(matches)} instance(s) of {pattern_name.replace('_', ' ')} in response",
                    evidence=f"Found: {masked}",
                    location="body",
                    remediation="Remove or redact sensitive data from responses",
                    cwe_id=200,
                    metadata={"match_count": len(matches), "pattern": pattern_name},
                ))
        
        return findings

    def _check_debug_info(
        self, body: str, url: str
    ) -> List[PassiveFinding]:
        """Check for debug and error information."""
        findings = []
        
        for pattern_name, (pattern, severity) in self.DEBUG_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                # Extract context around match
                match = re.search(pattern, body, re.IGNORECASE)
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 200)
                context = body[start:end]
                
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.DEBUG_INFORMATION if "debug" in pattern_name 
                                else PassiveFindingType.STACK_TRACE if "stack" in pattern_name
                                else PassiveFindingType.DATABASE_ERROR if "sql" in pattern_name
                                else PassiveFindingType.ERROR_MESSAGE_DISCLOSURE,
                    severity=severity,
                    title=f"Debug/Error Information: {pattern_name.replace('_', ' ').title()}",
                    description=f"Response contains {pattern_name.replace('_', ' ')}",
                    evidence=context,
                    location="body",
                    remediation="Disable debug mode and implement custom error handlers in production",
                    cwe_id=209,
                ))
        
        return findings

    def _check_path_disclosure(
        self, body: str, url: str
    ) -> List[PassiveFinding]:
        """Check for internal path disclosure."""
        findings = []
        
        for pattern_name, (pattern, severity) in self.PATH_PATTERNS.items():
            matches = re.findall(pattern, body)
            if matches:
                unique_paths = list(set(matches))[:5]
                
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.PATH_DISCLOSURE,
                    severity=severity,
                    title=f"Path Disclosure: {pattern_name.replace('_', ' ').title()}",
                    description=f"Response contains internal file system paths",
                    evidence=f"Paths found: {unique_paths}",
                    location="body",
                    remediation="Remove internal paths from error messages and responses",
                    cwe_id=200,
                ))
        
        return findings

    def _check_url_issues(self, url: str) -> List[PassiveFinding]:
        """Check for security issues in the URL itself."""
        findings = []
        
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # Check for auth tokens in URL
        sensitive_params = ["token", "api_key", "apikey", "key", "auth", "session", 
                          "password", "pwd", "secret", "jwt", "access_token", "bearer"]
        
        for param in sensitive_params:
            if param in query_params:
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.AUTH_TOKEN_IN_URL,
                    severity=PassiveFindingSeverity.MEDIUM,
                    title=f"Sensitive Parameter in URL: {param}",
                    description=f"The URL contains sensitive parameter '{param}' which may be logged "
                               f"in server logs, browser history, and referrer headers",
                    evidence=f"?{param}=***",
                    location="url",
                    remediation="Send sensitive parameters in request headers or POST body instead",
                    cwe_id=598,
                ))
        
        return findings

    def _check_api_exposure(
        self, body: str, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check for exposed API documentation or internal APIs."""
        findings = []
        
        # Check for Swagger/OpenAPI exposure
        swagger_indicators = [
            '"swagger":', '"openapi":', '/swagger-ui', '/api-docs', 
            '/swagger.json', '/openapi.json', '"paths":{', '"info":{'
        ]
        
        for indicator in swagger_indicators:
            if indicator.lower() in body.lower():
                findings.append(PassiveFinding(
                    finding_type=PassiveFindingType.SWAGGER_EXPOSURE,
                    severity=PassiveFindingSeverity.LOW,
                    title="API Documentation Exposed",
                    description="Response contains Swagger/OpenAPI documentation indicators. "
                               "This may expose internal API structure.",
                    evidence=indicator,
                    location="body",
                    remediation="Restrict access to API documentation in production",
                    cwe_id=200,
                ))
                break
        
        # Check for GraphQL introspection
        if '"__schema"' in body or '"__type"' in body:
            findings.append(PassiveFinding(
                finding_type=PassiveFindingType.GRAPHQL_INTROSPECTION,
                severity=PassiveFindingSeverity.LOW,
                title="GraphQL Introspection Enabled",
                description="GraphQL introspection appears to be enabled, exposing the full schema",
                evidence="Found __schema or __type in response",
                location="body",
                remediation="Disable GraphQL introspection in production",
                cwe_id=200,
            ))
        
        return findings

    def _check_jwt_issues(
        self, body: str, headers: Dict[str, str], url: str
    ) -> List[PassiveFinding]:
        """Check for JWT security issues."""
        findings = []
        
        # Find JWTs in response
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*'
        jwts = re.findall(jwt_pattern, body)
        
        # Also check authorization header if present
        auth_header = headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            jwts.append(auth_header[7:])
        
        for jwt in jwts:
            try:
                # Decode header (first part)
                parts = jwt.split(".")
                if len(parts) >= 2:
                    # Add padding if needed
                    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    
                    # Check for weak algorithms
                    alg = header.get("alg", "").upper()
                    
                    if alg == "NONE":
                        findings.append(PassiveFinding(
                            finding_type=PassiveFindingType.JWT_ISSUES,
                            severity=PassiveFindingSeverity.CRITICAL,
                            title="JWT Using 'none' Algorithm",
                            description="JWT uses 'none' algorithm which provides no signature verification",
                            evidence=f"alg: {alg}",
                            location="body",
                            remediation="Use RS256 or HS256 algorithm with strong secrets",
                            cwe_id=327,
                        ))
                    elif alg == "HS256":
                        findings.append(PassiveFinding(
                            finding_type=PassiveFindingType.JWT_ISSUES,
                            severity=PassiveFindingSeverity.INFO,
                            title="JWT Using Symmetric Algorithm",
                            description="JWT uses HS256 (symmetric). Ensure the secret is strong "
                                       "and not exposed.",
                            evidence=f"alg: {alg}",
                            location="body",
                            remediation="Consider using RS256 for better security, ensure strong secrets",
                            cwe_id=327,
                        ))
                    
                    # Decode payload and check for sensitive data
                    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    
                    # Check for sensitive fields in payload
                    sensitive_fields = ["password", "secret", "credit_card", "ssn"]
                    for field in sensitive_fields:
                        if field in str(payload).lower():
                            findings.append(PassiveFinding(
                                finding_type=PassiveFindingType.JWT_ISSUES,
                                severity=PassiveFindingSeverity.HIGH,
                                title="JWT Contains Sensitive Data",
                                description=f"JWT payload may contain sensitive field: {field}",
                                evidence="JWT payload contains sensitive fields",
                                location="body",
                                remediation="Don't store sensitive data in JWT payloads",
                                cwe_id=315,
                            ))
                            break
                    
            except Exception:
                pass  # Invalid JWT, skip
        
        return findings

    def _check_html_comments(
        self, body: str, url: str
    ) -> List[PassiveFinding]:
        """Check for sensitive information in HTML comments."""
        findings = []
        
        # Extract HTML comments
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        
        sensitive_comment_patterns = [
            (r'(?:password|secret|key|token|api)', "credentials"),
            (r'TODO|FIXME|HACK|BUG|XXX', "development notes"),
            (r'(?:admin|internal|debug|test)', "internal info"),
            (r'(?:version|v\d|build)', "version info"),
            (r'(?:localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', "internal addresses"),
        ]
        
        for comment in comments:
            for pattern, desc in sensitive_comment_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    findings.append(PassiveFinding(
                        finding_type=PassiveFindingType.COMMENT_DISCLOSURE,
                        severity=PassiveFindingSeverity.LOW,
                        title=f"HTML Comment Contains {desc.title()}",
                        description=f"HTML comment may contain sensitive {desc}",
                        evidence=f"<!--{comment[:200]}-->",
                        location="body",
                        remediation="Remove sensitive information from HTML comments before deployment",
                        cwe_id=615,
                    ))
                    break
        
        return findings

    def _get_finding_type_for_pattern(self, pattern_name: str) -> PassiveFindingType:
        """Map pattern name to finding type."""
        mapping = {
            "email": PassiveFindingType.EMAIL_DISCLOSURE,
            "ipv4": PassiveFindingType.IP_DISCLOSURE,
            "ipv6": PassiveFindingType.IP_DISCLOSURE,
            "credit_card": PassiveFindingType.CREDIT_CARD_EXPOSURE,
            "ssn": PassiveFindingType.SSN_EXPOSURE,
            "aws_key": PassiveFindingType.API_KEY_EXPOSURE,
            "aws_secret": PassiveFindingType.API_KEY_EXPOSURE,
            "gcp_key": PassiveFindingType.API_KEY_EXPOSURE,
            "azure_key": PassiveFindingType.API_KEY_EXPOSURE,
            "github_token": PassiveFindingType.API_KEY_EXPOSURE,
            "jwt": PassiveFindingType.CREDENTIAL_EXPOSURE,
            "private_key": PassiveFindingType.PRIVATE_KEY_EXPOSURE,
            "password_field": PassiveFindingType.CREDENTIAL_EXPOSURE,
            "connection_string": PassiveFindingType.CREDENTIAL_EXPOSURE,
            "bearer_token": PassiveFindingType.CREDENTIAL_EXPOSURE,
            "basic_auth": PassiveFindingType.CREDENTIAL_EXPOSURE,
            "slack_token": PassiveFindingType.API_KEY_EXPOSURE,
            "stripe_key": PassiveFindingType.API_KEY_EXPOSURE,
            "sendgrid_key": PassiveFindingType.API_KEY_EXPOSURE,
            "twilio_key": PassiveFindingType.API_KEY_EXPOSURE,
            "mailgun_key": PassiveFindingType.API_KEY_EXPOSURE,
            "heroku_key": PassiveFindingType.API_KEY_EXPOSURE,
        }
        return mapping.get(pattern_name, PassiveFindingType.SENSITIVE_DATA_EXPOSURE)

    def _mask_sensitive(self, value: str) -> str:
        """Mask sensitive data for evidence."""
        if len(value) <= 8:
            return "*" * len(value)
        return value[:4] + "*" * (len(value) - 8) + value[-4:]

    def _deduplicate_findings(
        self, findings: List[PassiveFinding]
    ) -> List[PassiveFinding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create a hash of the finding
            finding_hash = hashlib.md5(
                f"{finding.finding_type.value}:{finding.title}:{finding.evidence[:100]}".encode()
            ).hexdigest()
            
            if finding_hash not in seen:
                seen.add(finding_hash)
                unique.append(finding)
        
        return unique

    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self._stats.copy()

    def reset_stats(self):
        """Reset scanner statistics."""
        self._stats = {
            "responses_scanned": 0,
            "findings_total": 0,
            "findings_by_severity": {s.value: 0 for s in PassiveFindingSeverity},
            "findings_by_type": {},
        }


# Singleton instance for easy access
_passive_scanner: Optional[PassiveScanner] = None


def get_passive_scanner() -> PassiveScanner:
    """Get or create the passive scanner instance."""
    global _passive_scanner
    if _passive_scanner is None:
        _passive_scanner = PassiveScanner()
    return _passive_scanner
