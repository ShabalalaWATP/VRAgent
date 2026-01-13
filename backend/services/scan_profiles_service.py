"""
Scan Profiles Service for Agentic Fuzzer.

Provides predefined and customizable scan configurations for different
security testing scenarios. Profiles control which techniques to use,
crawl depth, timing, and risk tolerance.

Features:
- Predefined profiles (Quick, Full, OWASP Top 10, API, Auth-focused, etc.)
- Custom profile creation and management
- Profile templates for common scenarios
- Risk-based technique selection
- Compliance-oriented profiles (PCI-DSS, HIPAA, etc.)
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import hashlib

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class ScanProfileType(Enum):
    """Type of scan profile."""
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    OWASP_TOP_10 = "owasp_top_10"
    OWASP_API_TOP_10 = "owasp_api_top_10"
    API_FOCUSED = "api_focused"
    AUTH_FOCUSED = "auth_focused"
    INJECTION_FOCUSED = "injection_focused"
    XSS_FOCUSED = "xss_focused"
    BUSINESS_LOGIC = "business_logic"
    COMPLIANCE_PCI = "compliance_pci"
    COMPLIANCE_HIPAA = "compliance_hipaa"
    PASSIVE_ONLY = "passive_only"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"
    CUSTOM = "custom"


class RiskLevel(Enum):
    """Risk level for scan aggressiveness."""
    MINIMAL = "minimal"      # Very safe, unlikely to cause issues
    LOW = "low"              # Safe for production with care
    MEDIUM = "medium"        # May cause minor disruptions
    HIGH = "high"            # Could cause service issues
    CRITICAL = "critical"    # Only for isolated test environments


class ScanSpeed(Enum):
    """Scan speed configuration."""
    SNEAKY = "sneaky"        # Very slow, evades detection
    POLITE = "polite"        # Respectful rate limiting
    NORMAL = "normal"        # Standard speed
    AGGRESSIVE = "aggressive" # Fast, may trigger WAF
    INSANE = "insane"        # Maximum speed


class TechniqueCategory(Enum):
    """Categories of attack techniques."""
    INJECTION = "injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    BUSINESS_LOGIC = "business_logic"
    FILE_OPERATIONS = "file_operations"
    SSRF = "ssrf"
    DESERIALIZATION = "deserialization"
    API_ABUSE = "api_abuse"
    INFORMATION_DISCLOSURE = "information_disclosure"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class TechniqueConfig:
    """Configuration for a specific attack technique."""
    name: str
    enabled: bool = True
    payload_count: int = 50
    timeout_seconds: float = 10.0
    risk_level: RiskLevel = RiskLevel.MEDIUM
    categories: List[TechniqueCategory] = field(default_factory=list)
    custom_payloads: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "payload_count": self.payload_count,
            "timeout_seconds": self.timeout_seconds,
            "risk_level": self.risk_level.value,
            "categories": [c.value for c in self.categories],
            "custom_payloads": self.custom_payloads,
        }


@dataclass
class CrawlConfig:
    """Configuration for crawling behavior."""
    enabled: bool = True
    max_depth: int = 3
    max_pages: int = 100
    max_parameters_per_page: int = 50
    follow_redirects: bool = True
    respect_robots_txt: bool = False
    include_subdomains: bool = False
    exclude_patterns: List[str] = field(default_factory=list)
    include_patterns: List[str] = field(default_factory=list)
    handle_javascript: bool = True
    extract_forms: bool = True
    extract_links: bool = True
    extract_api_endpoints: bool = True
    extract_comments: bool = True
    detect_authentication: bool = True
    follow_external_links: bool = False
    delay_between_requests_ms: int = 100
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimingConfig:
    """Timing and rate limiting configuration."""
    requests_per_second: float = 10.0
    delay_between_requests_ms: int = 100
    timeout_seconds: float = 30.0
    max_retries: int = 3
    backoff_multiplier: float = 2.0
    jitter_percent: float = 20.0
    concurrent_requests: int = 5
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuthConfig:
    """Authentication configuration for scans."""
    enabled: bool = False
    auth_type: str = "none"  # none, basic, bearer, cookie, form, oauth2
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"
    cookie_name: Optional[str] = None
    cookie_value: Optional[str] = None
    login_url: Optional[str] = None
    login_method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: Optional[str] = None
    logout_indicators: List[str] = field(default_factory=list)
    session_indicators: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        # Don't expose sensitive data in dict
        if self.password:
            result["password"] = "***"
        if self.token:
            result["token"] = "***"
        return result


@dataclass
class ScanScope:
    """Scope configuration for the scan."""
    target_urls: List[str] = field(default_factory=list)
    include_domains: List[str] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    include_paths: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    exclude_extensions: List[str] = field(default_factory=lambda: [
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".doc", ".docx",
    ])
    include_methods: List[str] = field(default_factory=lambda: [
        "GET", "POST", "PUT", "PATCH", "DELETE"
    ])
    max_url_length: int = 2048
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReportingConfig:
    """Configuration for scan reporting."""
    generate_report: bool = True
    report_format: str = "json"  # json, html, pdf, sarif
    include_evidence: bool = True
    include_requests: bool = True
    include_responses: bool = False  # Can be large
    max_evidence_length: int = 10000
    severity_threshold: str = "low"  # Only report findings >= this severity
    include_informational: bool = True
    include_poc: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanProfile:
    """Complete scan profile configuration."""
    id: str
    name: str
    description: str
    profile_type: ScanProfileType
    version: str = "1.0.0"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: str = "system"
    
    # Risk and speed settings
    risk_level: RiskLevel = RiskLevel.MEDIUM
    scan_speed: ScanSpeed = ScanSpeed.NORMAL
    
    # Feature flags
    passive_scan_enabled: bool = True
    active_scan_enabled: bool = True
    crawl_enabled: bool = True
    auto_discovery_enabled: bool = True
    chain_attacks_enabled: bool = True
    blind_detection_enabled: bool = True
    waf_evasion_enabled: bool = True
    
    # Technique configurations
    enabled_techniques: List[str] = field(default_factory=list)
    technique_configs: Dict[str, TechniqueConfig] = field(default_factory=dict)
    
    # Sub-configurations
    crawl_config: CrawlConfig = field(default_factory=CrawlConfig)
    timing_config: TimingConfig = field(default_factory=TimingConfig)
    auth_config: AuthConfig = field(default_factory=AuthConfig)
    scope_config: ScanScope = field(default_factory=ScanScope)
    reporting_config: ReportingConfig = field(default_factory=ReportingConfig)
    
    # Advanced options
    max_iterations: int = 50
    max_findings: int = 1000
    stop_on_critical: bool = False
    use_ai_analysis: bool = True
    parallel_execution: bool = False
    deduplication_enabled: bool = True
    
    # Custom metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "profile_type": self.profile_type.value,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "created_by": self.created_by,
            "risk_level": self.risk_level.value,
            "scan_speed": self.scan_speed.value,
            "passive_scan_enabled": self.passive_scan_enabled,
            "active_scan_enabled": self.active_scan_enabled,
            "crawl_enabled": self.crawl_enabled,
            "auto_discovery_enabled": self.auto_discovery_enabled,
            "chain_attacks_enabled": self.chain_attacks_enabled,
            "blind_detection_enabled": self.blind_detection_enabled,
            "waf_evasion_enabled": self.waf_evasion_enabled,
            "enabled_techniques": self.enabled_techniques,
            "technique_configs": {k: v.to_dict() for k, v in self.technique_configs.items()},
            "crawl_config": self.crawl_config.to_dict(),
            "timing_config": self.timing_config.to_dict(),
            "auth_config": self.auth_config.to_dict(),
            "scope_config": self.scope_config.to_dict(),
            "reporting_config": self.reporting_config.to_dict(),
            "max_iterations": self.max_iterations,
            "max_findings": self.max_findings,
            "stop_on_critical": self.stop_on_critical,
            "use_ai_analysis": self.use_ai_analysis,
            "parallel_execution": self.parallel_execution,
            "deduplication_enabled": self.deduplication_enabled,
            "tags": self.tags,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanProfile":
        """Create a ScanProfile from a dictionary."""
        # Parse enums
        profile_type = ScanProfileType(data.get("profile_type", "custom"))
        risk_level = RiskLevel(data.get("risk_level", "medium"))
        scan_speed = ScanSpeed(data.get("scan_speed", "normal"))
        
        # Parse sub-configs
        crawl_config = CrawlConfig(**data.get("crawl_config", {}))
        timing_config = TimingConfig(**data.get("timing_config", {}))
        auth_config = AuthConfig(**data.get("auth_config", {}))
        scope_config = ScanScope(**data.get("scope_config", {}))
        reporting_config = ReportingConfig(**data.get("reporting_config", {}))
        
        # Parse technique configs
        technique_configs = {}
        for name, config in data.get("technique_configs", {}).items():
            config["risk_level"] = RiskLevel(config.get("risk_level", "medium"))
            config["categories"] = [TechniqueCategory(c) for c in config.get("categories", [])]
            technique_configs[name] = TechniqueConfig(**config)
        
        return cls(
            id=data.get("id", hashlib.md5(data.get("name", "").encode()).hexdigest()[:12]),
            name=data.get("name", "Custom Profile"),
            description=data.get("description", ""),
            profile_type=profile_type,
            version=data.get("version", "1.0.0"),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            updated_at=data.get("updated_at", datetime.utcnow().isoformat()),
            created_by=data.get("created_by", "user"),
            risk_level=risk_level,
            scan_speed=scan_speed,
            passive_scan_enabled=data.get("passive_scan_enabled", True),
            active_scan_enabled=data.get("active_scan_enabled", True),
            crawl_enabled=data.get("crawl_enabled", True),
            auto_discovery_enabled=data.get("auto_discovery_enabled", True),
            chain_attacks_enabled=data.get("chain_attacks_enabled", True),
            blind_detection_enabled=data.get("blind_detection_enabled", True),
            waf_evasion_enabled=data.get("waf_evasion_enabled", True),
            enabled_techniques=data.get("enabled_techniques", []),
            technique_configs=technique_configs,
            crawl_config=crawl_config,
            timing_config=timing_config,
            auth_config=auth_config,
            scope_config=scope_config,
            reporting_config=reporting_config,
            max_iterations=data.get("max_iterations", 50),
            max_findings=data.get("max_findings", 1000),
            stop_on_critical=data.get("stop_on_critical", False),
            use_ai_analysis=data.get("use_ai_analysis", True),
            parallel_execution=data.get("parallel_execution", False),
            deduplication_enabled=data.get("deduplication_enabled", True),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


# =============================================================================
# PREDEFINED PROFILES
# =============================================================================

# All available techniques
ALL_TECHNIQUES = [
    "sql_injection", "xss", "command_injection", "path_traversal",
    "ssti", "xxe", "ssrf", "idor", "auth_bypass", "session_fixation",
    "csrf", "open_redirect", "crlf_injection", "ldap_injection",
    "xpath_injection", "nosql_injection", "graphql_injection",
    "websocket_hijacking", "jwt_attacks", "api_abuse",
    "mass_assignment", "rate_limit_bypass", "cors_misconfiguration",
    "security_misconfiguration", "sensitive_data_exposure",
    "broken_authentication", "broken_authorization",
    "business_logic_flaws", "file_upload", "deserialization",
    "http_smuggling", "race_condition", "cache_poisoning",
    "parameter_pollution", "prototype_pollution", "subdomain_takeover",
]

# OWASP Top 10 2021 techniques
OWASP_TOP_10_TECHNIQUES = [
    "sql_injection", "xss", "command_injection", "path_traversal",
    "xxe", "ssrf", "auth_bypass", "broken_authentication",
    "broken_authorization", "sensitive_data_exposure",
    "security_misconfiguration", "deserialization",
]

# OWASP API Top 10 2023 techniques
OWASP_API_TOP_10_TECHNIQUES = [
    "idor", "broken_authorization", "broken_authentication",
    "mass_assignment", "rate_limit_bypass", "api_abuse",
    "ssrf", "security_misconfiguration", "sensitive_data_exposure",
    "graphql_injection",
]

# Injection-focused techniques
INJECTION_TECHNIQUES = [
    "sql_injection", "command_injection", "ssti", "xxe",
    "ldap_injection", "xpath_injection", "nosql_injection",
    "graphql_injection", "crlf_injection",
]

# XSS-focused techniques
XSS_TECHNIQUES = [
    "xss", "dom_xss", "stored_xss", "reflected_xss",
    "ssti", "open_redirect", "crlf_injection",
]

# Auth-focused techniques
AUTH_TECHNIQUES = [
    "auth_bypass", "broken_authentication", "broken_authorization",
    "session_fixation", "jwt_attacks", "csrf", "idor",
    "rate_limit_bypass",
]


def create_quick_profile() -> ScanProfile:
    """Create a quick scan profile for fast security checks."""
    return ScanProfile(
        id="quick",
        name="Quick Scan",
        description="Fast security scan focusing on critical vulnerabilities. Ideal for CI/CD pipelines.",
        profile_type=ScanProfileType.QUICK,
        risk_level=RiskLevel.LOW,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=[
            "sql_injection", "xss", "command_injection",
            "path_traversal", "auth_bypass", "ssrf",
        ],
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=2,
            max_pages=50,
            delay_between_requests_ms=50,
        ),
        timing_config=TimingConfig(
            requests_per_second=20.0,
            delay_between_requests_ms=50,
            timeout_seconds=30.0,
            max_retries=3,
            concurrent_requests=10,
        ),
        max_iterations=50,
        chain_attacks_enabled=False,
        blind_detection_enabled=False,
        parallel_execution=True,
        tags=["quick", "ci-cd", "fast", "minimal"],
    )


def create_standard_profile() -> ScanProfile:
    """Create a standard comprehensive scan profile."""
    return ScanProfile(
        id="standard",
        name="Standard Scan",
        description="Balanced security scan with good coverage and reasonable speed.",
        profile_type=ScanProfileType.STANDARD,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=OWASP_TOP_10_TECHNIQUES + [
            "idor", "csrf", "open_redirect", "jwt_attacks",
            "cors_misconfiguration", "rate_limit_bypass",
        ],
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=100,
            delay_between_requests_ms=100,
        ),
        timing_config=TimingConfig(
            requests_per_second=10.0,
            delay_between_requests_ms=100,
            timeout_seconds=45.0,
            max_retries=3,
            concurrent_requests=5,
        ),
        max_iterations=150,
        tags=["standard", "balanced", "comprehensive", "medium"],
    )


def create_full_profile() -> ScanProfile:
    """Create a full comprehensive scan profile."""
    return ScanProfile(
        id="full",
        name="Full Scan",
        description="Comprehensive security scan testing all vulnerability categories. Use in test environments.",
        profile_type=ScanProfileType.FULL,
        risk_level=RiskLevel.HIGH,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=ALL_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=5,
            max_pages=500,
            delay_between_requests_ms=100,
            handle_javascript=True,
            extract_comments=True,
        ),
        timing_config=TimingConfig(
            requests_per_second=10.0,
            delay_between_requests_ms=100,
            timeout_seconds=60.0,
            max_retries=5,
            concurrent_requests=5,
        ),
        max_iterations=500,
        max_findings=5000,
        chain_attacks_enabled=True,
        blind_detection_enabled=True,
        waf_evasion_enabled=True,
        tags=["full", "comprehensive", "all-techniques", "high"],
    )


def create_owasp_top10_profile() -> ScanProfile:
    """Create an OWASP Top 10 focused scan profile."""
    return ScanProfile(
        id="owasp_top_10",
        name="OWASP Top 10",
        description="Scan focused on OWASP Top 10 2021 vulnerabilities.",
        profile_type=ScanProfileType.OWASP_TOP_10,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=OWASP_TOP_10_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=100,
        ),
        max_iterations=50,
        tags=["owasp", "top-10", "2021", "compliance"],
    )


def create_owasp_api_top10_profile() -> ScanProfile:
    """Create an OWASP API Top 10 focused scan profile."""
    return ScanProfile(
        id="owasp_api_top_10",
        name="OWASP API Top 10",
        description="Scan focused on OWASP API Security Top 10 2023 vulnerabilities.",
        profile_type=ScanProfileType.OWASP_API_TOP_10,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=OWASP_API_TOP_10_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=2,
            max_pages=50,
            extract_api_endpoints=True,
            extract_forms=False,  # APIs don't have forms
        ),
        max_iterations=50,
        tags=["owasp", "api", "top-10", "2023"],
    )


def create_api_focused_profile() -> ScanProfile:
    """Create an API-focused scan profile."""
    return ScanProfile(
        id="api_focused",
        name="API Security Scan",
        description="Comprehensive API security testing including REST, GraphQL, and WebSocket.",
        profile_type=ScanProfileType.API_FOCUSED,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=[
            "sql_injection", "nosql_injection", "graphql_injection",
            "idor", "broken_authorization", "broken_authentication",
            "mass_assignment", "rate_limit_bypass", "api_abuse",
            "ssrf", "jwt_attacks", "parameter_pollution",
        ],
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=2,
            max_pages=100,
            extract_api_endpoints=True,
            extract_forms=False,
        ),
        max_iterations=50,
        tags=["api", "rest", "graphql", "websocket"],
    )


def create_auth_focused_profile() -> ScanProfile:
    """Create an authentication-focused scan profile."""
    return ScanProfile(
        id="auth_focused",
        name="Authentication Security Scan",
        description="Focused testing of authentication and authorization mechanisms.",
        profile_type=ScanProfileType.AUTH_FOCUSED,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.POLITE,
        enabled_techniques=AUTH_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=2,
            max_pages=50,
            detect_authentication=True,
        ),
        max_iterations=40,
        tags=["authentication", "authorization", "session"],
    )


def create_injection_focused_profile() -> ScanProfile:
    """Create an injection-focused scan profile."""
    return ScanProfile(
        id="injection_focused",
        name="Injection Attack Scan",
        description="Comprehensive testing for all injection vulnerabilities.",
        profile_type=ScanProfileType.INJECTION_FOCUSED,
        risk_level=RiskLevel.HIGH,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=INJECTION_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=100,
        ),
        max_iterations=60,
        blind_detection_enabled=True,
        tags=["injection", "sqli", "command-injection"],
    )


def create_xss_focused_profile() -> ScanProfile:
    """Create an XSS-focused scan profile."""
    return ScanProfile(
        id="xss_focused",
        name="XSS Security Scan",
        description="Comprehensive testing for Cross-Site Scripting vulnerabilities.",
        profile_type=ScanProfileType.XSS_FOCUSED,
        risk_level=RiskLevel.LOW,
        scan_speed=ScanSpeed.NORMAL,
        enabled_techniques=XSS_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=100,
            handle_javascript=True,
        ),
        max_iterations=50,
        tags=["xss", "cross-site-scripting", "dom"],
    )


def create_passive_only_profile() -> ScanProfile:
    """Create a passive-only scan profile (no active attacks)."""
    return ScanProfile(
        id="passive_only",
        name="Passive Security Scan",
        description="Non-intrusive scan that only analyzes responses without sending attack payloads.",
        profile_type=ScanProfileType.PASSIVE_ONLY,
        risk_level=RiskLevel.MINIMAL,
        scan_speed=ScanSpeed.POLITE,
        enabled_techniques=[],  # No active techniques
        passive_scan_enabled=True,
        active_scan_enabled=False,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=200,
            respect_robots_txt=True,
        ),
        max_iterations=0,
        chain_attacks_enabled=False,
        blind_detection_enabled=False,
        tags=["passive", "safe", "non-intrusive", "production-safe"],
    )


def create_stealth_profile() -> ScanProfile:
    """Create a stealth scan profile that evades detection."""
    return ScanProfile(
        id="stealth",
        name="Stealth Scan",
        description="Low-and-slow scanning designed to evade WAF and IDS detection.",
        profile_type=ScanProfileType.STEALTH,
        risk_level=RiskLevel.LOW,
        scan_speed=ScanSpeed.SNEAKY,
        enabled_techniques=[
            "sql_injection", "xss", "path_traversal",
            "ssrf", "idor", "auth_bypass",
        ],
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=2,
            max_pages=50,
            delay_between_requests_ms=2000,  # 2 seconds between requests
            respect_robots_txt=True,
        ),
        timing_config=TimingConfig(
            requests_per_second=0.5,  # Very slow
            delay_between_requests_ms=2000,
            timeout_seconds=60.0,
            jitter_percent=50.0,  # High randomization
            concurrent_requests=1,
        ),
        max_iterations=30,
        waf_evasion_enabled=True,
        parallel_execution=False,
        tags=["stealth", "evasion", "low-and-slow"],
    )


def create_aggressive_profile() -> ScanProfile:
    """Create an aggressive scan profile for isolated test environments."""
    return ScanProfile(
        id="aggressive",
        name="Aggressive Scan",
        description="Maximum coverage and speed. Only use in isolated test environments! For exhaustive testing use 2000+ iterations.",
        profile_type=ScanProfileType.AGGRESSIVE,
        risk_level=RiskLevel.CRITICAL,
        scan_speed=ScanSpeed.INSANE,
        enabled_techniques=ALL_TECHNIQUES,
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=10,
            max_pages=2000,
            delay_between_requests_ms=10,
            include_subdomains=True,
        ),
        timing_config=TimingConfig(
            requests_per_second=100.0,
            delay_between_requests_ms=10,
            timeout_seconds=120.0,  # 2 min timeout for complex payloads
            max_retries=5,
            concurrent_requests=20,
        ),
        max_iterations=1500,
        max_findings=50000,
        chain_attacks_enabled=True,
        blind_detection_enabled=True,
        waf_evasion_enabled=True,
        parallel_execution=True,
        tags=["aggressive", "fast", "test-only", "warning", "maximum", "exhaustive"],
    )


def create_pci_compliance_profile() -> ScanProfile:
    """Create a PCI-DSS compliance focused scan profile."""
    return ScanProfile(
        id="compliance_pci",
        name="PCI-DSS Compliance Scan",
        description="Scan focused on PCI-DSS requirements for payment card security.",
        profile_type=ScanProfileType.COMPLIANCE_PCI,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.POLITE,
        enabled_techniques=[
            "sql_injection", "xss", "auth_bypass",
            "broken_authentication", "sensitive_data_exposure",
            "security_misconfiguration", "cors_misconfiguration",
        ],
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=100,
        ),
        reporting_config=ReportingConfig(
            generate_report=True,
            report_format="json",
            include_evidence=True,
            include_poc=True,
        ),
        max_iterations=50,
        tags=["compliance", "pci-dss", "payment"],
    )


def create_hipaa_compliance_profile() -> ScanProfile:
    """Create a HIPAA compliance focused scan profile."""
    return ScanProfile(
        id="compliance_hipaa",
        name="HIPAA Compliance Scan",
        description="Scan focused on HIPAA security requirements for healthcare data.",
        profile_type=ScanProfileType.COMPLIANCE_HIPAA,
        risk_level=RiskLevel.MEDIUM,
        scan_speed=ScanSpeed.POLITE,
        enabled_techniques=[
            "sql_injection", "auth_bypass", "broken_authentication",
            "broken_authorization", "sensitive_data_exposure",
            "security_misconfiguration", "idor",
        ],
        crawl_config=CrawlConfig(
            enabled=True,
            max_depth=3,
            max_pages=100,
        ),
        reporting_config=ReportingConfig(
            generate_report=True,
            report_format="json",
            include_evidence=True,
            include_poc=True,
        ),
        max_iterations=50,
        tags=["compliance", "hipaa", "healthcare"],
    )


# =============================================================================
# SCAN PROFILE MANAGER
# =============================================================================

class ScanProfileManager:
    """Manager for scan profiles."""
    
    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = Path(storage_path) if storage_path else None
        self._profiles: Dict[str, ScanProfile] = {}
        self._load_builtin_profiles()
        
        if self.storage_path:
            self._load_custom_profiles()
    
    def _load_builtin_profiles(self):
        """Load all built-in profiles."""
        builtin_profiles = [
            create_quick_profile(),
            create_standard_profile(),
            create_full_profile(),
            create_owasp_top10_profile(),
            create_owasp_api_top10_profile(),
            create_api_focused_profile(),
            create_auth_focused_profile(),
            create_injection_focused_profile(),
            create_xss_focused_profile(),
            create_passive_only_profile(),
            create_stealth_profile(),
            create_aggressive_profile(),
            create_pci_compliance_profile(),
            create_hipaa_compliance_profile(),
        ]
        
        for profile in builtin_profiles:
            self._profiles[profile.id] = profile
    
    def _load_custom_profiles(self):
        """Load custom profiles from storage."""
        if not self.storage_path or not self.storage_path.exists():
            return
        
        for file_path in self.storage_path.glob("*.json"):
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)
                    profile = ScanProfile.from_dict(data)
                    self._profiles[profile.id] = profile
            except Exception as e:
                logger.warning(f"Failed to load profile from {file_path}: {e}")
    
    def get_profile(self, profile_id: str) -> Optional[ScanProfile]:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)
    
    def get_profile_by_type(self, profile_type: ScanProfileType) -> Optional[ScanProfile]:
        """Get a profile by type."""
        for profile in self._profiles.values():
            if profile.profile_type == profile_type:
                return profile
        return None
    
    def list_profiles(self, tags: Optional[List[str]] = None) -> List[ScanProfile]:
        """List all profiles, optionally filtered by tags."""
        profiles = list(self._profiles.values())
        
        if tags:
            profiles = [
                p for p in profiles
                if any(tag in p.tags for tag in tags)
            ]
        
        return sorted(profiles, key=lambda p: p.name)
    
    def create_profile(self, profile: ScanProfile) -> ScanProfile:
        """Create a new custom profile."""
        profile.profile_type = ScanProfileType.CUSTOM
        profile.created_at = datetime.utcnow().isoformat()
        profile.updated_at = datetime.utcnow().isoformat()
        
        self._profiles[profile.id] = profile
        
        if self.storage_path:
            self._save_profile(profile)
        
        return profile
    
    def update_profile(self, profile_id: str, updates: Dict[str, Any]) -> Optional[ScanProfile]:
        """Update an existing profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None
        
        # Don't allow updating built-in profiles
        if profile.profile_type != ScanProfileType.CUSTOM:
            # Clone it as a custom profile
            new_id = f"custom_{profile_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            profile = ScanProfile.from_dict({**profile.to_dict(), "id": new_id})
            profile.profile_type = ScanProfileType.CUSTOM
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(profile, key):
                setattr(profile, key, value)
        
        profile.updated_at = datetime.utcnow().isoformat()
        self._profiles[profile.id] = profile
        
        if self.storage_path:
            self._save_profile(profile)
        
        return profile
    
    def delete_profile(self, profile_id: str) -> bool:
        """Delete a custom profile."""
        profile = self._profiles.get(profile_id)
        if not profile or profile.profile_type != ScanProfileType.CUSTOM:
            return False
        
        del self._profiles[profile_id]
        
        if self.storage_path:
            file_path = self.storage_path / f"{profile_id}.json"
            if file_path.exists():
                file_path.unlink()
        
        return True
    
    def clone_profile(self, profile_id: str, new_name: str) -> Optional[ScanProfile]:
        """Clone an existing profile with a new name."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None
        
        new_id = hashlib.md5(new_name.encode()).hexdigest()[:12]
        new_profile = ScanProfile.from_dict(profile.to_dict())
        new_profile.id = new_id
        new_profile.name = new_name
        new_profile.profile_type = ScanProfileType.CUSTOM
        new_profile.created_at = datetime.utcnow().isoformat()
        new_profile.updated_at = datetime.utcnow().isoformat()
        new_profile.created_by = "user"
        
        self._profiles[new_id] = new_profile
        
        if self.storage_path:
            self._save_profile(new_profile)
        
        return new_profile
    
    def _save_profile(self, profile: ScanProfile):
        """Save a profile to storage."""
        if not self.storage_path:
            return
        
        self.storage_path.mkdir(parents=True, exist_ok=True)
        file_path = self.storage_path / f"{profile.id}.json"
        
        with open(file_path, "w") as f:
            json.dump(profile.to_dict(), f, indent=2)
    
    def export_profile(self, profile_id: str) -> Optional[str]:
        """Export a profile as JSON string."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return None
        return json.dumps(profile.to_dict(), indent=2)
    
    def import_profile(self, json_str: str) -> ScanProfile:
        """Import a profile from JSON string."""
        data = json.loads(json_str)
        profile = ScanProfile.from_dict(data)
        profile.profile_type = ScanProfileType.CUSTOM
        profile.created_at = datetime.utcnow().isoformat()
        profile.updated_at = datetime.utcnow().isoformat()
        
        self._profiles[profile.id] = profile
        
        if self.storage_path:
            self._save_profile(profile)
        
        return profile
    
    def get_recommended_profile(
        self,
        target_type: str = "web",
        risk_tolerance: str = "medium",
        time_available: str = "normal",
    ) -> ScanProfile:
        """Get a recommended profile based on requirements."""
        # Map risk tolerance
        risk_map = {
            "minimal": [ScanProfileType.PASSIVE_ONLY],
            "low": [ScanProfileType.QUICK, ScanProfileType.STEALTH],
            "medium": [ScanProfileType.STANDARD, ScanProfileType.OWASP_TOP_10],
            "high": [ScanProfileType.FULL],
            "critical": [ScanProfileType.AGGRESSIVE],
        }
        
        # Map target type
        type_map = {
            "api": [ScanProfileType.API_FOCUSED, ScanProfileType.OWASP_API_TOP_10],
            "web": [ScanProfileType.STANDARD, ScanProfileType.OWASP_TOP_10],
            "auth": [ScanProfileType.AUTH_FOCUSED],
        }
        
        # Map time available
        time_map = {
            "quick": [ScanProfileType.QUICK],
            "normal": [ScanProfileType.STANDARD],
            "long": [ScanProfileType.FULL],
        }
        
        # Find best match
        risk_profiles = set(risk_map.get(risk_tolerance, [ScanProfileType.STANDARD]))
        type_profiles = set(type_map.get(target_type, [ScanProfileType.STANDARD]))
        time_profiles = set(time_map.get(time_available, [ScanProfileType.STANDARD]))
        
        # Find intersection
        candidates = risk_profiles & type_profiles
        if not candidates:
            candidates = risk_profiles | type_profiles
        
        # Prefer time-appropriate
        final = candidates & time_profiles
        if final:
            candidates = final
        
        # Return first match
        for profile_type in candidates:
            profile = self.get_profile_by_type(profile_type)
            if profile:
                return profile
        
        # Default to standard
        return self._profiles.get("standard", create_standard_profile())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        builtin_count = sum(
            1 for p in self._profiles.values()
            if p.profile_type != ScanProfileType.CUSTOM
        )
        custom_count = sum(
            1 for p in self._profiles.values()
            if p.profile_type == ScanProfileType.CUSTOM
        )
        
        return {
            "total_profiles": len(self._profiles),
            "builtin_profiles": builtin_count,
            "custom_profiles": custom_count,
            "profile_types": list(set(p.profile_type.value for p in self._profiles.values())),
            "available_techniques": len(ALL_TECHNIQUES),
        }


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_profile_manager: Optional[ScanProfileManager] = None


def get_profile_manager(storage_path: Optional[str] = None) -> ScanProfileManager:
    """Get the singleton profile manager instance."""
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = ScanProfileManager(storage_path)
    return _profile_manager


def reset_profile_manager():
    """Reset the profile manager singleton."""
    global _profile_manager
    _profile_manager = None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_profile(profile_id: str) -> Optional[ScanProfile]:
    """Get a scan profile by ID."""
    return get_profile_manager().get_profile(profile_id)


def list_profiles(tags: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """List all available profiles."""
    profiles = get_profile_manager().list_profiles(tags)
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "type": p.profile_type.value,
            "risk_level": p.risk_level.value,
            "tags": p.tags,
        }
        for p in profiles
    ]


def get_recommended_profile(
    target_type: str = "web",
    risk_tolerance: str = "medium",
    time_available: str = "normal",
) -> Dict[str, Any]:
    """Get a recommended profile based on requirements."""
    profile = get_profile_manager().get_recommended_profile(
        target_type, risk_tolerance, time_available
    )
    return profile.to_dict()


def create_custom_profile(
    name: str,
    description: str,
    enabled_techniques: List[str],
    **kwargs,
) -> Dict[str, Any]:
    """Create a custom scan profile."""
    profile_id = hashlib.md5(name.encode()).hexdigest()[:12]
    
    profile = ScanProfile(
        id=profile_id,
        name=name,
        description=description,
        profile_type=ScanProfileType.CUSTOM,
        enabled_techniques=enabled_techniques,
        **kwargs,
    )
    
    created = get_profile_manager().create_profile(profile)
    return created.to_dict()
