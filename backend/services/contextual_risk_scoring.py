"""
Contextual Risk Scoring Service

Provides realistic risk assessment that goes beyond CVSS scores by considering:
- Authentication requirements (unauth vs auth vs admin)
- Network position (external vs internal vs localhost)
- Compensating controls (WAF, rate limiting, etc.)
- Exploitability factors (complexity, reliability)
- Data sensitivity of affected assets
- Business context

Returns adjusted risk scores with clear justification.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


class AuthenticationLevel(str, Enum):
    """Required authentication to exploit."""
    NONE = "none"                    # No authentication needed
    LOW_PRIV = "low_privilege"       # Regular user account
    HIGH_PRIV = "high_privilege"     # Admin or elevated account
    PHYSICAL = "physical"            # Physical access required


class NetworkPosition(str, Enum):
    """Network position required to exploit."""
    EXTERNAL = "external"            # Internet-accessible
    ADJACENT = "adjacent"            # Same network segment
    INTERNAL = "internal"            # Inside corporate network
    LOCAL = "local"                  # Localhost only


class ExploitComplexity(str, Enum):
    """How complex is the exploit to execute."""
    TRIVIAL = "trivial"              # Point and click
    LOW = "low"                      # Simple scripting
    MEDIUM = "medium"                # Requires skill
    HIGH = "high"                    # Requires expertise
    VERY_HIGH = "very_high"          # Requires research/development


class ExploitReliability(str, Enum):
    """How reliable is the exploit."""
    ALWAYS = "always"                # Works every time
    USUALLY = "usually"              # Works most of the time
    SOMETIMES = "sometimes"          # Works under certain conditions
    RARELY = "rarely"                # Requires specific circumstances
    THEORETICAL = "theoretical"      # Not proven to work


class DataSensitivity(str, Enum):
    """Sensitivity of data at risk."""
    PUBLIC = "public"                # Already public info
    INTERNAL = "internal"            # Internal but not sensitive
    CONFIDENTIAL = "confidential"    # Business confidential
    PII = "pii"                      # Personal identifiable info
    FINANCIAL = "financial"          # Financial/payment data
    CREDENTIALS = "credentials"      # Passwords, API keys
    REGULATED = "regulated"          # HIPAA, PCI-DSS, etc.


@dataclass
class CompensatingControl:
    """A security control that reduces risk."""
    name: str
    effectiveness: float  # 0.0 to 1.0
    description: str
    verified: bool = False


@dataclass
class ContextualRiskFactors:
    """All contextual factors affecting risk."""
    # Access requirements
    authentication_required: AuthenticationLevel = AuthenticationLevel.NONE
    network_position_required: NetworkPosition = NetworkPosition.EXTERNAL
    user_interaction_required: bool = False

    # Exploit characteristics
    exploit_complexity: ExploitComplexity = ExploitComplexity.LOW
    exploit_reliability: ExploitReliability = ExploitReliability.USUALLY
    exploit_publicly_available: bool = False
    actively_exploited_in_wild: bool = False

    # Impact factors
    data_sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    affects_availability: bool = False
    affects_integrity: bool = False
    affects_confidentiality: bool = True
    scope_limited: bool = True  # Only affects single component

    # Compensating controls
    compensating_controls: List[CompensatingControl] = field(default_factory=list)

    # Business context
    asset_criticality: str = "medium"  # low, medium, high, critical
    business_function: str = ""
    regulatory_scope: List[str] = field(default_factory=list)  # PCI, HIPAA, etc.


@dataclass
class ContextualRiskScore:
    """Risk score with full context and justification."""
    finding_id: str
    finding_title: str

    # Original scores
    original_severity: str
    original_cvss: Optional[float] = None

    # Contextual scores (0-100)
    contextual_risk_score: float = 0.0
    contextual_severity: str = "Medium"

    # Factor contributions
    base_score: float = 0.0
    auth_modifier: float = 0.0
    network_modifier: float = 0.0
    complexity_modifier: float = 0.0
    reliability_modifier: float = 0.0
    data_sensitivity_modifier: float = 0.0
    compensating_controls_modifier: float = 0.0
    threat_intel_modifier: float = 0.0

    # Factors used
    factors: Optional[ContextualRiskFactors] = None

    # Justification
    risk_justification: str = ""
    key_risk_drivers: List[str] = field(default_factory=list)
    risk_reducers: List[str] = field(default_factory=list)

    # Recommendations
    priority_level: str = "medium"  # immediate, high, medium, low, accepted
    recommended_timeline: str = ""
    additional_investigation_needed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_title": self.finding_title,
            "original_severity": self.original_severity,
            "original_cvss": self.original_cvss,
            "contextual_risk_score": round(self.contextual_risk_score, 1),
            "contextual_severity": self.contextual_severity,
            "score_breakdown": {
                "base_score": round(self.base_score, 1),
                "auth_modifier": round(self.auth_modifier, 1),
                "network_modifier": round(self.network_modifier, 1),
                "complexity_modifier": round(self.complexity_modifier, 1),
                "reliability_modifier": round(self.reliability_modifier, 1),
                "data_sensitivity_modifier": round(self.data_sensitivity_modifier, 1),
                "compensating_controls_modifier": round(self.compensating_controls_modifier, 1),
                "threat_intel_modifier": round(self.threat_intel_modifier, 1),
            },
            "factors": {
                "authentication_required": self.factors.authentication_required.value if self.factors else "unknown",
                "network_position_required": self.factors.network_position_required.value if self.factors else "unknown",
                "exploit_complexity": self.factors.exploit_complexity.value if self.factors else "unknown",
                "exploit_reliability": self.factors.exploit_reliability.value if self.factors else "unknown",
                "data_sensitivity": self.factors.data_sensitivity.value if self.factors else "unknown",
                "compensating_controls": [
                    {"name": c.name, "effectiveness": c.effectiveness}
                    for c in (self.factors.compensating_controls if self.factors else [])
                ],
                "actively_exploited": self.factors.actively_exploited_in_wild if self.factors else False,
            },
            "risk_justification": self.risk_justification,
            "key_risk_drivers": self.key_risk_drivers,
            "risk_reducers": self.risk_reducers,
            "priority_level": self.priority_level,
            "recommended_timeline": self.recommended_timeline,
            "additional_investigation_needed": self.additional_investigation_needed,
        }


# Mapping tables for score calculations
AUTH_SCORE_MODIFIERS = {
    AuthenticationLevel.NONE: 0,           # No reduction
    AuthenticationLevel.LOW_PRIV: -10,     # Requires user account
    AuthenticationLevel.HIGH_PRIV: -25,    # Requires admin
    AuthenticationLevel.PHYSICAL: -40,     # Requires physical access
}

NETWORK_SCORE_MODIFIERS = {
    NetworkPosition.EXTERNAL: 0,           # Internet accessible
    NetworkPosition.ADJACENT: -10,         # Requires network adjacency
    NetworkPosition.INTERNAL: -20,         # Requires internal access
    NetworkPosition.LOCAL: -35,            # Localhost only
}

COMPLEXITY_SCORE_MODIFIERS = {
    ExploitComplexity.TRIVIAL: +10,        # Script kiddie level
    ExploitComplexity.LOW: +5,             # Easy to exploit
    ExploitComplexity.MEDIUM: 0,           # Moderate skill
    ExploitComplexity.HIGH: -10,           # Expert required
    ExploitComplexity.VERY_HIGH: -20,      # Research required
}

RELIABILITY_SCORE_MODIFIERS = {
    ExploitReliability.ALWAYS: +10,        # 100% reliable
    ExploitReliability.USUALLY: +5,        # Usually works
    ExploitReliability.SOMETIMES: 0,       # Hit or miss
    ExploitReliability.RARELY: -10,        # Unreliable
    ExploitReliability.THEORETICAL: -20,   # Unproven
}

DATA_SENSITIVITY_MODIFIERS = {
    DataSensitivity.PUBLIC: -20,           # No real impact
    DataSensitivity.INTERNAL: -10,         # Minor impact
    DataSensitivity.CONFIDENTIAL: 0,       # Business impact
    DataSensitivity.PII: +10,              # Privacy impact
    DataSensitivity.FINANCIAL: +15,        # Financial impact
    DataSensitivity.CREDENTIALS: +20,      # Access impact
    DataSensitivity.REGULATED: +25,        # Compliance impact
}

SEVERITY_TO_BASE_SCORE = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "informational": 10,
    "info": 10,
}

SCORE_TO_SEVERITY = [
    (90, "Critical"),
    (70, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Informational"),
]

SCORE_TO_PRIORITY = [
    (85, "immediate", "Fix within 24-48 hours"),
    (70, "high", "Fix within 1-2 weeks"),
    (50, "medium", "Fix within 1 month"),
    (25, "low", "Fix within quarter"),
    (0, "accepted", "Accept risk or fix opportunistically"),
]


class ContextualRiskScorer:
    """
    Calculates contextual risk scores based on multiple factors.
    """

    def __init__(self):
        pass

    def calculate_risk_score(
        self,
        finding: Dict[str, Any],
        factors: Optional[ContextualRiskFactors] = None,
        scan_context: Optional[Dict[str, Any]] = None,
    ) -> ContextualRiskScore:
        """
        Calculate contextual risk score for a finding.
        """
        finding_id = finding.get("id", str(hash(str(finding)) % 10000))
        finding_title = finding.get("title", finding.get("name", "Unknown"))
        original_severity = finding.get("severity", "medium").lower()
        original_cvss = finding.get("cvss", finding.get("cvss_score"))

        # Auto-detect factors if not provided
        if factors is None:
            factors = self._auto_detect_factors(finding, scan_context)

        # Calculate base score from severity
        base_score = SEVERITY_TO_BASE_SCORE.get(original_severity, 50)

        # Apply modifiers
        auth_mod = AUTH_SCORE_MODIFIERS.get(factors.authentication_required, 0)
        network_mod = NETWORK_SCORE_MODIFIERS.get(factors.network_position_required, 0)
        complexity_mod = COMPLEXITY_SCORE_MODIFIERS.get(factors.exploit_complexity, 0)
        reliability_mod = RELIABILITY_SCORE_MODIFIERS.get(factors.exploit_reliability, 0)
        data_mod = DATA_SENSITIVITY_MODIFIERS.get(factors.data_sensitivity, 0)

        # User interaction penalty
        if factors.user_interaction_required:
            complexity_mod -= 10

        # Compensating controls reduction
        controls_mod = 0
        for control in factors.compensating_controls:
            # Each control reduces risk by its effectiveness percentage
            controls_mod -= control.effectiveness * 15  # Max -15 per control

        # Threat intelligence modifier
        threat_mod = 0
        if factors.actively_exploited_in_wild:
            threat_mod += 20
        if factors.exploit_publicly_available:
            threat_mod += 10

        # Calculate final score
        raw_score = (
            base_score
            + auth_mod
            + network_mod
            + complexity_mod
            + reliability_mod
            + data_mod
            + controls_mod
            + threat_mod
        )

        # Clamp to 0-100
        final_score = max(0, min(100, raw_score))

        # Determine contextual severity
        contextual_severity = "Medium"
        for threshold, severity in SCORE_TO_SEVERITY:
            if final_score >= threshold:
                contextual_severity = severity
                break

        # Determine priority and timeline
        priority_level = "medium"
        recommended_timeline = "Fix within 1 month"
        for threshold, priority, timeline in SCORE_TO_PRIORITY:
            if final_score >= threshold:
                priority_level = priority
                recommended_timeline = timeline
                break

        # Build justification
        justification, drivers, reducers = self._build_justification(
            finding, factors, base_score, final_score
        )

        # Identify additional investigation needs
        investigation_needed = self._identify_investigation_needs(finding, factors)

        return ContextualRiskScore(
            finding_id=finding_id,
            finding_title=finding_title,
            original_severity=original_severity.capitalize(),
            original_cvss=original_cvss,
            contextual_risk_score=final_score,
            contextual_severity=contextual_severity,
            base_score=base_score,
            auth_modifier=auth_mod,
            network_modifier=network_mod,
            complexity_modifier=complexity_mod,
            reliability_modifier=reliability_mod,
            data_sensitivity_modifier=data_mod,
            compensating_controls_modifier=controls_mod,
            threat_intel_modifier=threat_mod,
            factors=factors,
            risk_justification=justification,
            key_risk_drivers=drivers,
            risk_reducers=reducers,
            priority_level=priority_level,
            recommended_timeline=recommended_timeline,
            additional_investigation_needed=investigation_needed,
        )

    def calculate_risk_scores_batch(
        self,
        findings: List[Dict[str, Any]],
        scan_context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Calculate contextual risk scores for multiple findings.
        """
        scores = []
        for finding in findings:
            score = self.calculate_risk_score(finding, scan_context=scan_context)
            scores.append(score.to_dict())
        return scores

    def _auto_detect_factors(
        self,
        finding: Dict[str, Any],
        scan_context: Optional[Dict[str, Any]] = None,
    ) -> ContextualRiskFactors:
        """
        Automatically detect risk factors from finding data.
        Uses multiple detection strategies: keywords, CVSS vectors, vulnerability-specific defaults.
        """
        factors = ContextualRiskFactors()

        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        vuln_type = finding.get("type", "").lower()
        combined = f"{title} {desc} {vuln_type}"
        severity = finding.get("severity", "medium").lower()

        # Try to parse CVSS vector if available for more accurate detection
        cvss_vector = finding.get("cvss_vector", finding.get("vector", ""))
        cvss_parsed = self._parse_cvss_vector(cvss_vector) if cvss_vector else {}

        # Detect vulnerability type for type-specific defaults
        vuln_category = self._classify_vulnerability_type(combined)

        # === AUTHENTICATION REQUIREMENTS ===
        # Priority: CVSS > explicit keywords > vulnerability-type defaults
        if cvss_parsed.get("PR"):
            pr = cvss_parsed["PR"]
            if pr == "N":
                factors.authentication_required = AuthenticationLevel.NONE
            elif pr == "L":
                factors.authentication_required = AuthenticationLevel.LOW_PRIV
            elif pr == "H":
                factors.authentication_required = AuthenticationLevel.HIGH_PRIV
        elif any(x in combined for x in ["unauthenticated", "no authentication", "without auth", "pre-auth", "anonymous"]):
            factors.authentication_required = AuthenticationLevel.NONE
        elif any(x in combined for x in ["admin", "administrator", "privileged", "root", "superuser"]):
            factors.authentication_required = AuthenticationLevel.HIGH_PRIV
        elif any(x in combined for x in ["authenticated", "logged in", "user session", "requires login", "after auth"]):
            factors.authentication_required = AuthenticationLevel.LOW_PRIV
        else:
            # Vulnerability-type-specific defaults
            auth_defaults = {
                "auth_bypass": AuthenticationLevel.NONE,
                "sqli": AuthenticationLevel.NONE,  # Often in login forms
                "xss_reflected": AuthenticationLevel.NONE,
                "ssrf": AuthenticationLevel.LOW_PRIV,
                "idor": AuthenticationLevel.LOW_PRIV,
                "rce": AuthenticationLevel.LOW_PRIV,
                "xxe": AuthenticationLevel.LOW_PRIV,
            }
            factors.authentication_required = auth_defaults.get(vuln_category, AuthenticationLevel.LOW_PRIV)

        # === NETWORK POSITION ===
        if cvss_parsed.get("AV"):
            av = cvss_parsed["AV"]
            if av == "N":
                factors.network_position_required = NetworkPosition.EXTERNAL
            elif av == "A":
                factors.network_position_required = NetworkPosition.ADJACENT
            elif av == "L":
                factors.network_position_required = NetworkPosition.LOCAL
            elif av == "P":
                factors.network_position_required = NetworkPosition.LOCAL
                factors.authentication_required = AuthenticationLevel.PHYSICAL
        elif any(x in combined for x in ["localhost", "127.0.0.1", "local only", "loopback"]):
            factors.network_position_required = NetworkPosition.LOCAL
        elif any(x in combined for x in ["internal", "intranet", "vpn required", "private network", "corp network"]):
            factors.network_position_required = NetworkPosition.INTERNAL
        elif any(x in combined for x in ["adjacent", "same network", "lan", "local network", "same subnet"]):
            factors.network_position_required = NetworkPosition.ADJACENT
        else:
            factors.network_position_required = NetworkPosition.EXTERNAL

        # === EXPLOIT COMPLEXITY ===
        if cvss_parsed.get("AC"):
            ac = cvss_parsed["AC"]
            if ac == "L":
                factors.exploit_complexity = ExploitComplexity.LOW
            elif ac == "H":
                factors.exploit_complexity = ExploitComplexity.HIGH
        elif any(x in combined for x in ["trivial", "one-click", "script kiddie", "automated"]):
            factors.exploit_complexity = ExploitComplexity.TRIVIAL
        elif any(x in combined for x in ["simple", "easy", "straightforward"]):
            factors.exploit_complexity = ExploitComplexity.LOW
        elif any(x in combined for x in ["complex", "difficult", "requires expertise", "chained", "multi-step"]):
            factors.exploit_complexity = ExploitComplexity.HIGH
        elif any(x in combined for x in ["research required", "0-day", "novel", "custom exploit"]):
            factors.exploit_complexity = ExploitComplexity.VERY_HIGH
        else:
            # Vulnerability-type-specific complexity defaults
            complexity_defaults = {
                "xss_reflected": ExploitComplexity.TRIVIAL,
                "xss_stored": ExploitComplexity.LOW,
                "sqli": ExploitComplexity.LOW,
                "ssrf": ExploitComplexity.MEDIUM,
                "rce": ExploitComplexity.MEDIUM,
                "deserialization": ExploitComplexity.HIGH,
                "race_condition": ExploitComplexity.HIGH,
                "xxe": ExploitComplexity.MEDIUM,
                "idor": ExploitComplexity.TRIVIAL,
            }
            factors.exploit_complexity = complexity_defaults.get(vuln_category, ExploitComplexity.MEDIUM)

        # === EXPLOIT RELIABILITY ===
        if any(x in combined for x in ["reliable", "consistent", "deterministic", "100%"]):
            factors.exploit_reliability = ExploitReliability.ALWAYS
        elif any(x in combined for x in ["unreliable", "inconsistent", "flaky"]):
            factors.exploit_reliability = ExploitReliability.RARELY
        elif any(x in combined for x in ["theoretical", "potential", "possible", "may be", "could be"]):
            factors.exploit_reliability = ExploitReliability.THEORETICAL
        elif any(x in combined for x in ["race condition", "timing", "heap spray"]):
            factors.exploit_reliability = ExploitReliability.SOMETIMES
        else:
            # Vulnerability-type-specific reliability defaults
            reliability_defaults = {
                "sqli": ExploitReliability.ALWAYS,
                "xss_reflected": ExploitReliability.ALWAYS,
                "xss_stored": ExploitReliability.ALWAYS,
                "idor": ExploitReliability.ALWAYS,
                "ssrf": ExploitReliability.USUALLY,
                "rce": ExploitReliability.USUALLY,
                "race_condition": ExploitReliability.SOMETIMES,
                "deserialization": ExploitReliability.USUALLY,
                "buffer_overflow": ExploitReliability.SOMETIMES,
            }
            factors.exploit_reliability = reliability_defaults.get(vuln_category, ExploitReliability.USUALLY)

        # === USER INTERACTION ===
        if cvss_parsed.get("UI"):
            factors.user_interaction_required = cvss_parsed["UI"] == "R"
        elif any(x in combined for x in ["user interaction", "click", "social engineering", "phishing", "victim must", "requires victim"]):
            factors.user_interaction_required = True
        elif vuln_category in ["xss_reflected", "csrf", "open_redirect", "clickjacking"]:
            factors.user_interaction_required = True

        # === DATA SENSITIVITY ===
        if any(x in combined for x in ["password", "credential", "api key", "secret key", "access token", "jwt", "session"]):
            factors.data_sensitivity = DataSensitivity.CREDENTIALS
        elif any(x in combined for x in ["credit card", "payment", "financial", "bank", "billing", "transaction"]):
            factors.data_sensitivity = DataSensitivity.FINANCIAL
        elif any(x in combined for x in ["pii", "personal", "ssn", "social security", "health", "medical", "patient"]):
            factors.data_sensitivity = DataSensitivity.PII
        elif any(x in combined for x in ["pci", "hipaa", "gdpr", "regulated", "sox", "ferpa"]):
            factors.data_sensitivity = DataSensitivity.REGULATED
        elif any(x in combined for x in ["confidential", "sensitive", "private", "proprietary", "trade secret"]):
            factors.data_sensitivity = DataSensitivity.CONFIDENTIAL
        elif any(x in combined for x in ["public", "non-sensitive", "informational"]):
            factors.data_sensitivity = DataSensitivity.PUBLIC
        else:
            # Vulnerability-type-specific data sensitivity defaults
            data_defaults = {
                "sqli": DataSensitivity.CONFIDENTIAL,  # Database access = likely sensitive
                "auth_bypass": DataSensitivity.CREDENTIALS,
                "idor": DataSensitivity.PII,  # Often exposes user data
                "path_traversal": DataSensitivity.CONFIDENTIAL,
                "rce": DataSensitivity.CREDENTIALS,  # System access = can reach secrets
                "xxe": DataSensitivity.CONFIDENTIAL,
            }
            factors.data_sensitivity = data_defaults.get(vuln_category, DataSensitivity.INTERNAL)

        # === SCOPE (Impact beyond vulnerable component) ===
        if cvss_parsed.get("S"):
            factors.scope_limited = cvss_parsed["S"] == "U"  # Unchanged = limited
        elif any(x in combined for x in ["chain", "pivot", "lateral", "escalate", "full system", "other components"]):
            factors.scope_limited = False
        elif vuln_category in ["rce", "ssrf", "deserialization"]:
            factors.scope_limited = False  # These typically allow chaining

        # === IMPACT TYPES ===
        if cvss_parsed.get("C"):
            factors.affects_confidentiality = cvss_parsed["C"] != "N"
        if cvss_parsed.get("I"):
            factors.affects_integrity = cvss_parsed["I"] != "N"
        if cvss_parsed.get("A"):
            factors.affects_availability = cvss_parsed["A"] != "N"
        else:
            # Vulnerability-type defaults for impact
            if vuln_category in ["sqli", "path_traversal", "idor", "xxe", "ssrf"]:
                factors.affects_confidentiality = True
            if vuln_category in ["sqli", "rce", "deserialization", "xss_stored"]:
                factors.affects_integrity = True
            if vuln_category in ["rce", "dos", "resource_exhaustion"]:
                factors.affects_availability = True

        # === THREAT INTELLIGENCE ===
        # Check for CVE references
        cve_pattern = r'CVE-\d{4}-\d+'
        cves_found = re.findall(cve_pattern, combined.upper())
        if cves_found:
            factors.exploit_publicly_available = True  # CVE means public knowledge

        if any(x in combined for x in ["exploit available", "metasploit", "poc available", "exploit-db", "nuclei template"]):
            factors.exploit_publicly_available = True

        if any(x in combined for x in ["actively exploited", "in the wild", "known attacks", "cisa kev", "threat actor"]):
            factors.actively_exploited_in_wild = True

        # === COMPENSATING CONTROLS ===
        # Detect from finding description
        if any(x in combined for x in ["waf", "web application firewall", "modsecurity", "cloudflare"]):
            factors.compensating_controls.append(CompensatingControl(
                name="Web Application Firewall",
                effectiveness=0.4,  # Conservative estimate
                description="WAF detected in response - may block common payloads",
                verified=False,
            ))

        if any(x in combined for x in ["csp", "content-security-policy", "content security policy"]):
            if vuln_category in ["xss_reflected", "xss_stored"]:
                factors.compensating_controls.append(CompensatingControl(
                    name="Content Security Policy",
                    effectiveness=0.6,
                    description="CSP may mitigate XSS impact",
                    verified=False,
                ))

        if any(x in combined for x in ["rate limit", "throttl", "backoff"]):
            factors.compensating_controls.append(CompensatingControl(
                name="Rate Limiting",
                effectiveness=0.3,
                description="Rate limiting may slow automated attacks",
                verified=False,
            ))

        if any(x in combined for x in ["2fa", "mfa", "two-factor", "multi-factor"]):
            if vuln_category == "auth_bypass":
                factors.compensating_controls.append(CompensatingControl(
                    name="Multi-Factor Authentication",
                    effectiveness=0.7,
                    description="MFA provides additional authentication layer",
                    verified=False,
                ))

        if any(x in combined for x in ["captcha", "recaptcha", "hcaptcha"]):
            factors.compensating_controls.append(CompensatingControl(
                name="CAPTCHA",
                effectiveness=0.5,
                description="CAPTCHA may prevent automated exploitation",
                verified=False,
            ))

        if any(x in combined for x in ["input validation", "sanitiz", "escap", "parameteriz"]):
            factors.compensating_controls.append(CompensatingControl(
                name="Input Validation/Sanitization",
                effectiveness=0.3,
                description="Some input validation present (partial bypass may be possible)",
                verified=False,
            ))

        # Detect from scan context
        if scan_context:
            if scan_context.get("waf_detected") and not any(c.name == "Web Application Firewall" for c in factors.compensating_controls):
                factors.compensating_controls.append(CompensatingControl(
                    name="Web Application Firewall",
                    effectiveness=0.5,
                    description="WAF detected during scanning",
                    verified=True,
                ))
            if scan_context.get("rate_limiting_detected") and not any(c.name == "Rate Limiting" for c in factors.compensating_controls):
                factors.compensating_controls.append(CompensatingControl(
                    name="Rate Limiting",
                    effectiveness=0.3,
                    description="Rate limiting observed during scanning",
                    verified=True,
                ))
            if scan_context.get("csp_header_present") and not any(c.name == "Content Security Policy" for c in factors.compensating_controls):
                factors.compensating_controls.append(CompensatingControl(
                    name="Content Security Policy",
                    effectiveness=0.5,
                    description="CSP header present in responses",
                    verified=True,
                ))

        # === ASSET CRITICALITY from context ===
        if scan_context:
            factors.asset_criticality = scan_context.get("asset_criticality", "medium")
            factors.business_function = scan_context.get("business_function", "")
            factors.regulatory_scope = scan_context.get("regulatory_scope", [])

        return factors

    def _parse_cvss_vector(self, vector: str) -> Dict[str, str]:
        """
        Parse CVSS 3.x vector string into components.
        Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        components = {}
        if not vector:
            return components

        # Remove CVSS version prefix if present
        if vector.startswith("CVSS:"):
            parts = vector.split("/")[1:]  # Skip version part
        else:
            parts = vector.split("/")

        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                components[key] = value

        return components

    def _classify_vulnerability_type(self, combined: str) -> str:
        """
        Classify vulnerability into a category for default factor assignment.
        """
        if any(x in combined for x in ["sql injection", "sqli", "sql-injection"]):
            return "sqli"
        elif any(x in combined for x in ["stored xss", "persistent xss"]):
            return "xss_stored"
        elif any(x in combined for x in ["reflected xss", "xss", "cross-site scripting"]):
            return "xss_reflected"
        elif any(x in combined for x in ["ssrf", "server-side request"]):
            return "ssrf"
        elif any(x in combined for x in ["rce", "remote code", "command injection"]):
            return "rce"
        elif any(x in combined for x in ["idor", "insecure direct object"]):
            return "idor"
        elif any(x in combined for x in ["auth bypass", "authentication bypass"]):
            return "auth_bypass"
        elif any(x in combined for x in ["xxe", "xml external entity"]):
            return "xxe"
        elif any(x in combined for x in ["deserialization", "unserialize"]):
            return "deserialization"
        elif any(x in combined for x in ["race condition", "toctou"]):
            return "race_condition"
        elif any(x in combined for x in ["path traversal", "directory traversal", "lfi"]):
            return "path_traversal"
        elif any(x in combined for x in ["csrf", "cross-site request forgery"]):
            return "csrf"
        elif any(x in combined for x in ["open redirect"]):
            return "open_redirect"
        elif any(x in combined for x in ["buffer overflow", "stack overflow", "heap overflow"]):
            return "buffer_overflow"
        elif any(x in combined for x in ["dos", "denial of service", "resource exhaustion"]):
            return "dos"
        elif any(x in combined for x in ["clickjacking", "ui redressing"]):
            return "clickjacking"
        else:
            return "unknown"

    def _build_justification(
        self,
        finding: Dict[str, Any],
        factors: ContextualRiskFactors,
        base_score: float,
        final_score: float,
    ) -> Tuple[str, List[str], List[str]]:
        """
        Build human-readable justification for the risk score.
        """
        drivers = []
        reducers = []

        # Analyze what's driving risk up
        if factors.authentication_required == AuthenticationLevel.NONE:
            drivers.append("No authentication required - anyone can attempt exploitation")

        if factors.network_position_required == NetworkPosition.EXTERNAL:
            drivers.append("Internet-accessible - exposed to global attackers")

        if factors.exploit_complexity in [ExploitComplexity.TRIVIAL, ExploitComplexity.LOW]:
            drivers.append("Low exploit complexity - easy to execute")

        if factors.exploit_reliability in [ExploitReliability.ALWAYS, ExploitReliability.USUALLY]:
            drivers.append("Reliable exploit - high success rate expected")

        if factors.actively_exploited_in_wild:
            drivers.append("ACTIVELY EXPLOITED - known attacks in the wild")

        if factors.exploit_publicly_available:
            drivers.append("Public exploit available - low barrier to attack")

        if factors.data_sensitivity in [DataSensitivity.CREDENTIALS, DataSensitivity.FINANCIAL, DataSensitivity.REGULATED]:
            drivers.append(f"High-value target - {factors.data_sensitivity.value} data at risk")

        # Analyze what's reducing risk
        if factors.authentication_required == AuthenticationLevel.HIGH_PRIV:
            reducers.append("Requires privileged access - limits attacker pool")

        if factors.network_position_required in [NetworkPosition.INTERNAL, NetworkPosition.LOCAL]:
            reducers.append(f"Requires {factors.network_position_required.value} network access")

        if factors.exploit_complexity in [ExploitComplexity.HIGH, ExploitComplexity.VERY_HIGH]:
            reducers.append("High complexity - requires expert attacker")

        if factors.user_interaction_required:
            reducers.append("Requires user interaction - social engineering needed")

        for control in factors.compensating_controls:
            reducers.append(f"{control.name} ({int(control.effectiveness * 100)}% effective)")

        # Build justification text
        score_change = final_score - base_score
        direction = "increased" if score_change > 0 else "decreased" if score_change < 0 else "unchanged"

        justification = f"""**Contextual Risk Assessment**

Original severity {finding.get('severity', 'Medium')} (base score: {base_score}) was {direction} to contextual score of {final_score:.0f}.

"""

        if drivers:
            justification += "**Risk Drivers:**\n"
            for d in drivers:
                justification += f"- {d}\n"
            justification += "\n"

        if reducers:
            justification += "**Risk Reducers:**\n"
            for r in reducers:
                justification += f"- {r}\n"
            justification += "\n"

        if abs(score_change) >= 20:
            if score_change > 0:
                justification += f"⚠️ **Score increased significantly (+{score_change:.0f})** due to threat intelligence and exploitability factors.\n"
            else:
                justification += f"✓ **Score decreased significantly ({score_change:.0f})** due to compensating controls and access requirements.\n"

        return justification, drivers, reducers

    def _identify_investigation_needs(
        self,
        finding: Dict[str, Any],
        factors: ContextualRiskFactors,
    ) -> List[str]:
        """
        Identify what additional investigation is needed to improve risk accuracy.
        """
        needs = []

        title = finding.get("title", "").lower()
        desc = finding.get("description", "").lower()
        combined = f"{title} {desc}"

        # Authentication verification
        if factors.authentication_required == AuthenticationLevel.LOW_PRIV:
            needs.append("Verify authentication enforcement - attempt unauthenticated access to vulnerable endpoint")
        if factors.authentication_required == AuthenticationLevel.NONE:
            needs.append("Confirm no authentication is required - check for hidden auth mechanisms")

        # Compensating controls verification
        for control in factors.compensating_controls:
            if not control.verified:
                if control.name == "Web Application Firewall":
                    needs.append(f"Test WAF bypass - try encoding variations, HTTP parameter pollution, chunked transfer")
                elif control.name == "Content Security Policy":
                    needs.append(f"Analyze CSP policy for weaknesses - check for unsafe-inline, unsafe-eval, wildcard sources")
                elif control.name == "Rate Limiting":
                    needs.append(f"Test rate limit bypass - try distributed requests, header manipulation, session rotation")
                elif control.name == "Multi-Factor Authentication":
                    needs.append(f"Check MFA bypass vectors - session fixation, MFA fatigue, backup codes")
                else:
                    needs.append(f"Verify effectiveness of {control.name} - attempt bypass")

        # Network position verification
        if factors.network_position_required == NetworkPosition.INTERNAL:
            needs.append("Confirm internal-only access - check for CDN/proxy exposure, VPN tunnels, SSRF chains")
        if factors.network_position_required == NetworkPosition.LOCAL:
            needs.append("Verify localhost restriction - check for reverse proxy configs, DNS rebinding potential")

        # Reliability confirmation
        if factors.exploit_reliability == ExploitReliability.THEORETICAL:
            needs.append("Develop working PoC to confirm exploitability - theoretical vulns need proof")
        if factors.exploit_reliability == ExploitReliability.SOMETIMES:
            needs.append("Determine exploit success conditions - document timing/race requirements")

        # Data sensitivity assessment
        if factors.data_sensitivity == DataSensitivity.INTERNAL:
            needs.append("Assess actual data sensitivity - enumerate accessible data types and volume")

        # Scope and chaining
        if not factors.scope_limited:
            needs.append("Map attack chain potential - identify what other systems/data can be reached")
        else:
            needs.append("Check for privilege escalation paths - can this be chained for greater impact?")

        # Vulnerability-specific investigations
        vuln_category = self._classify_vulnerability_type(combined)

        if vuln_category == "sqli":
            needs.append("Determine SQL injection type (error-based, blind, time-based) and database type")
            if factors.data_sensitivity != DataSensitivity.CREDENTIALS:
                needs.append("Check if SQLi can access credential tables or escalate to OS command execution")
        elif vuln_category in ["xss_reflected", "xss_stored"]:
            needs.append("Test XSS in different contexts - attribute, script, HTML body, JavaScript string")
            needs.append("Check if XSS can steal session tokens or perform sensitive actions")
        elif vuln_category == "ssrf":
            needs.append("Enumerate internal services reachable via SSRF - cloud metadata, internal APIs")
            needs.append("Test SSRF protocol handlers - file://, gopher://, dict://")
        elif vuln_category == "rce":
            needs.append("Determine command execution context - user, privileges, network access")
            needs.append("Check for sandboxing or containerization limiting RCE impact")
        elif vuln_category == "idor":
            needs.append("Enumerate IDOR scope - how many objects are accessible? What data types?")
            needs.append("Check for horizontal and vertical privilege escalation via IDOR")
        elif vuln_category == "deserialization":
            needs.append("Identify deserialization library and available gadget chains")
            needs.append("Check if RCE is possible or limited to DoS/info disclosure")
        elif vuln_category == "xxe":
            needs.append("Test XXE for file read, SSRF, and potentially RCE via expect:// or PHP wrappers")
            needs.append("Check for out-of-band XXE if inline exfiltration is blocked")

        # Threat intelligence gaps
        if not factors.exploit_publicly_available:
            needs.append("Search exploit databases (Exploit-DB, Metasploit) for public exploits")
        if not factors.actively_exploited_in_wild:
            needs.append("Check CISA KEV and threat intel feeds for active exploitation")

        # Limit to most important items
        return needs[:8]  # Return top 8 most relevant investigation items

    def get_risk_summary_markdown(
        self,
        scores: List[ContextualRiskScore],
    ) -> str:
        """
        Generate markdown summary of all risk scores.
        """
        # Sort by contextual risk score descending
        sorted_scores = sorted(scores, key=lambda x: x.contextual_risk_score, reverse=True)

        md = """# Contextual Risk Assessment Summary

## Risk Distribution

"""
        # Count by severity
        severity_counts = {}
        for score in sorted_scores:
            sev = score.contextual_severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                md += f"- **{sev}:** {count} findings\n"

        md += "\n## Priority Actions\n\n"

        # Group by priority
        immediate = [s for s in sorted_scores if s.priority_level == "immediate"]
        high = [s for s in sorted_scores if s.priority_level == "high"]

        if immediate:
            md += "### 🔴 Immediate (24-48 hours)\n\n"
            for s in immediate:
                md += f"- [{s.contextual_risk_score:.0f}] **{s.finding_title}** - {s.key_risk_drivers[0] if s.key_risk_drivers else 'High risk'}\n"
            md += "\n"

        if high:
            md += "### 🟠 High Priority (1-2 weeks)\n\n"
            for s in high:
                md += f"- [{s.contextual_risk_score:.0f}] **{s.finding_title}** - {s.key_risk_drivers[0] if s.key_risk_drivers else 'Elevated risk'}\n"
            md += "\n"

        md += "## Detailed Scores\n\n"
        md += "| Finding | Original | Contextual | Change | Priority |\n"
        md += "|---------|----------|------------|--------|----------|\n"

        for score in sorted_scores[:20]:  # Top 20
            change = score.contextual_risk_score - score.base_score
            change_str = f"+{change:.0f}" if change > 0 else f"{change:.0f}"
            md += f"| {score.finding_title[:40]} | {score.original_severity} | {score.contextual_severity} ({score.contextual_risk_score:.0f}) | {change_str} | {score.priority_level} |\n"

        return md
