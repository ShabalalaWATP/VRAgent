"""
Finding Validator Service - Validates, deduplicates, and contextualizes security findings.

This service:
1. Groups similar findings (e.g., same header missing on multiple endpoints)
2. Adjusts severity based on target context (embedded device vs enterprise webapp)
3. Filters false positives based on context
4. Optionally verifies high-severity findings
"""
import re
import json
import httpx
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from urllib.parse import urlparse

from backend.core.logging import get_logger
from backend.core.config import settings

logger = get_logger(__name__)


class TargetContext(Enum):
    """Context classification for the scan target."""
    EMBEDDED_DEVICE = "embedded_device"      # Routers, IoT, cameras
    ENTERPRISE_WEB = "enterprise_web"        # Production web apps
    INTERNAL_API = "internal_api"            # Internal/private APIs
    DEVELOPMENT = "development"              # Dev/staging environments
    LEGACY_SYSTEM = "legacy_system"          # Old systems, limited updates
    UNKNOWN = "unknown"


@dataclass
class ContextHints:
    """Hints about the target context gathered from responses."""
    server_headers: List[str] = field(default_factory=list)
    detected_technologies: List[str] = field(default_factory=list)
    is_https: bool = False
    is_private_ip: bool = False
    response_patterns: List[str] = field(default_factory=list)
    port: int = 80
    
    
@dataclass
class ValidatedFinding:
    """A finding after validation and contextualization."""
    original_finding: Dict[str, Any]
    adjusted_severity: str
    original_severity: str
    group_id: str
    occurrence_count: int
    is_false_positive: bool
    false_positive_reason: Optional[str]
    context_notes: List[str]
    verification_status: str  # "verified", "unverified", "failed_verification"
    

class FindingValidatorService:
    """
    Validates and contextualizes security findings to reduce false positives
    and provide more accurate severity ratings.
    """
    
    # Patterns that indicate embedded devices
    EMBEDDED_DEVICE_PATTERNS = [
        r"lighttpd",
        r"mini_httpd",
        r"micro_httpd",
        r"boa",
        r"goahead",
        r"router",
        r"gateway",
        r"modem",
        r"vodafone",
        r"netgear",
        r"linksys",
        r"tp-link",
        r"asus.*rt-",
        r"dlink",
        r"zyxel",
        r"huawei.*hg",
        r"firmware",
        r"embedded",
        r"busybox",
    ]
    
    # Findings that are false positives for embedded devices
    EMBEDDED_FP_RULES = {
        "Missing HSTS": "Embedded devices typically use HTTP only on local networks",
        "Missing Content-Security-Policy": "CSP not applicable to simple router UIs",
        "Missing X-Content-Type-Options": "Low risk for router admin interfaces",
        "Cookie without Secure flag": "Expected when using HTTP (no HTTPS available)",
        "Strict-Transport-Security": "HSTS requires HTTPS which many routers lack",
    }
    
    # Severity adjustments by context
    SEVERITY_ADJUSTMENTS = {
        TargetContext.EMBEDDED_DEVICE: {
            "information_disclosure": -1,  # Reduce by 1 level
            "missing_security_header": -2,  # Reduce by 2 levels
            "cookie_security": -1,
        },
        TargetContext.INTERNAL_API: {
            "missing_security_header": -1,
            "information_disclosure": -1,
        },
        TargetContext.ENTERPRISE_WEB: {
            # No adjustments - full severity
        },
    }
    
    SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
    
    def __init__(self):
        self.context_hints = ContextHints()
        self.detected_context = TargetContext.UNKNOWN
        
    def detect_target_context(
        self, 
        target_url: str, 
        findings: List[Dict[str, Any]],
        response_samples: Optional[List[Dict[str, Any]]] = None
    ) -> TargetContext:
        """
        Analyze the target to determine its context/type.
        """
        parsed = urlparse(target_url)
        
        # Check if private IP
        ip_match = re.match(r'^(\d+)\.(\d+)\.(\d+)\.(\d+)$', parsed.hostname or "")
        if ip_match:
            octets = [int(o) for o in ip_match.groups()]
            if (octets[0] == 10 or 
                (octets[0] == 172 and 16 <= octets[1] <= 31) or
                (octets[0] == 192 and octets[1] == 168)):
                self.context_hints.is_private_ip = True
        
        # Check common router IPs
        common_router_ips = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "192.168.1.254"]
        if parsed.hostname in common_router_ips:
            logger.info(f"Detected common router IP: {parsed.hostname}")
            return TargetContext.EMBEDDED_DEVICE
        
        self.context_hints.is_https = parsed.scheme == "https"
        self.context_hints.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        
        # Analyze findings for server headers
        for finding in findings:
            finding_str = json.dumps(finding).lower()
            
            # Check for embedded device patterns
            for pattern in self.EMBEDDED_DEVICE_PATTERNS:
                if re.search(pattern, finding_str, re.IGNORECASE):
                    logger.info(f"Detected embedded device pattern: {pattern}")
                    return TargetContext.EMBEDDED_DEVICE
        
        # Analyze response samples if available
        if response_samples:
            for sample in response_samples:
                headers = sample.get("headers", {})
                server = headers.get("Server", "").lower()
                
                self.context_hints.server_headers.append(server)
                
                for pattern in self.EMBEDDED_DEVICE_PATTERNS:
                    if re.search(pattern, server, re.IGNORECASE):
                        return TargetContext.EMBEDDED_DEVICE
        
        # Default based on IP type
        if self.context_hints.is_private_ip:
            return TargetContext.INTERNAL_API
        
        return TargetContext.ENTERPRISE_WEB
    
    def group_similar_findings(
        self, 
        findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group similar findings together to reduce noise.
        E.g., "Missing X-Frame-Options" on 50 endpoints becomes 1 grouped finding.
        """
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        for finding in findings:
            # Create group key based on finding type and description
            finding_type = finding.get("type", finding.get("name", "unknown"))
            severity = finding.get("severity", "info")
            
            # Normalize the description to group similar findings
            description = finding.get("description", "")
            
            # Extract the core issue (remove URL-specific parts)
            core_issue = self._extract_core_issue(finding_type, description)
            
            group_key = f"{severity}:{core_issue}"
            groups[group_key].append(finding)
        
        return dict(groups)
    
    def _extract_core_issue(self, finding_type: str, description: str) -> str:
        """Extract the core issue from a finding, removing URL-specific parts."""
        # Common patterns to normalize
        core = finding_type.lower()
        
        # Remove URL/path references
        core = re.sub(r'https?://[^\s]+', '', core)
        core = re.sub(r'/[a-zA-Z0-9/_-]+', '', core)
        
        # Normalize common finding types
        if "x-frame-options" in core.lower() or "x-frame-options" in description.lower():
            return "missing_x_frame_options"
        if "content-security-policy" in core.lower() or "csp" in core.lower():
            return "missing_csp"
        if "x-content-type-options" in core.lower():
            return "missing_x_content_type_options"
        if "strict-transport-security" in core.lower() or "hsts" in core.lower():
            return "missing_hsts"
        if "server" in core.lower() and ("header" in core.lower() or "disclosure" in description.lower()):
            return "server_header_disclosure"
        if "x-powered-by" in core.lower():
            return "x_powered_by_disclosure"
        if "cookie" in core.lower():
            if "httponly" in core.lower() or "httponly" in description.lower():
                return "cookie_missing_httponly"
            if "secure" in core.lower() or "secure" in description.lower():
                return "cookie_missing_secure"
            if "samesite" in core.lower() or "samesite" in description.lower():
                return "cookie_missing_samesite"
            return "cookie_security_issue"
        if "information" in core.lower() and "disclosure" in core.lower():
            return "information_disclosure"
        
        return core.strip()[:50]  # Limit length
    
    def _get_finding_category(self, core_issue: str) -> str:
        """Categorize a finding for severity adjustment."""
        if "disclosure" in core_issue or "server" in core_issue or "powered" in core_issue:
            return "information_disclosure"
        if "missing" in core_issue or "header" in core_issue or "hsts" in core_issue or "csp" in core_issue:
            return "missing_security_header"
        if "cookie" in core_issue:
            return "cookie_security"
        return "other"
    
    def adjust_severity(
        self, 
        original_severity: str, 
        core_issue: str,
        context: TargetContext
    ) -> str:
        """Adjust severity based on target context."""
        adjustments = self.SEVERITY_ADJUSTMENTS.get(context, {})
        category = self._get_finding_category(core_issue)
        
        adjustment = adjustments.get(category, 0)
        
        if adjustment == 0:
            return original_severity
        
        try:
            current_idx = self.SEVERITY_LEVELS.index(original_severity.lower())
            new_idx = max(0, current_idx + adjustment)  # Can only decrease
            return self.SEVERITY_LEVELS[new_idx]
        except ValueError:
            return original_severity
    
    def check_false_positive(
        self, 
        core_issue: str, 
        context: TargetContext,
        finding: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a finding is a false positive based on context.
        Returns (is_false_positive, reason).
        """
        if context != TargetContext.EMBEDDED_DEVICE:
            return False, None
        
        # Check embedded device FP rules
        for pattern, reason in self.EMBEDDED_FP_RULES.items():
            if pattern.lower() in core_issue.lower():
                return True, reason
            
            # Also check the original finding description
            description = finding.get("description", "")
            if pattern.lower() in description.lower():
                return True, reason
        
        # HSTS is always a FP for HTTP-only targets
        if "hsts" in core_issue and not self.context_hints.is_https:
            return True, "HSTS requires HTTPS - target only supports HTTP"
        
        # Secure cookie flag is expected to be missing on HTTP
        if "cookie_missing_secure" in core_issue and not self.context_hints.is_https:
            return True, "Secure flag requires HTTPS - target only supports HTTP"
        
        return False, None
    
    def validate_findings(
        self,
        target_url: str,
        findings: List[Dict[str, Any]],
        response_samples: Optional[List[Dict[str, Any]]] = None,
        context_override: Optional[TargetContext] = None
    ) -> Dict[str, Any]:
        """
        Main validation method - processes all findings and returns validated results.
        """
        logger.info(f"Validating {len(findings)} findings for {target_url}")
        
        # Detect context
        if context_override:
            self.detected_context = context_override
        else:
            self.detected_context = self.detect_target_context(
                target_url, findings, response_samples
            )
        
        logger.info(f"Detected target context: {self.detected_context.value}")
        
        # Group similar findings
        grouped = self.group_similar_findings(findings)
        
        validated_findings: List[ValidatedFinding] = []
        removed_fps: List[Dict[str, Any]] = []
        severity_adjustments: List[Dict[str, Any]] = []
        
        for group_key, group_findings in grouped.items():
            original_severity, core_issue = group_key.split(":", 1)
            
            # Check for false positives
            is_fp, fp_reason = self.check_false_positive(
                core_issue, self.detected_context, group_findings[0]
            )
            
            if is_fp:
                removed_fps.append({
                    "core_issue": core_issue,
                    "count": len(group_findings),
                    "reason": fp_reason,
                    "original_severity": original_severity
                })
                continue
            
            # Adjust severity
            adjusted_severity = self.adjust_severity(
                original_severity, core_issue, self.detected_context
            )
            
            if adjusted_severity != original_severity.lower():
                severity_adjustments.append({
                    "core_issue": core_issue,
                    "original": original_severity,
                    "adjusted": adjusted_severity,
                    "reason": f"Adjusted for {self.detected_context.value} context"
                })
            
            # Create validated finding (representative of the group)
            context_notes = []
            if self.detected_context == TargetContext.EMBEDDED_DEVICE:
                context_notes.append("Target appears to be an embedded device (router/IoT)")
            if not self.context_hints.is_https:
                context_notes.append("Target does not support HTTPS")
            if self.context_hints.is_private_ip:
                context_notes.append("Target is on a private network")
            
            validated = ValidatedFinding(
                original_finding=group_findings[0],
                adjusted_severity=adjusted_severity,
                original_severity=original_severity,
                group_id=group_key,
                occurrence_count=len(group_findings),
                is_false_positive=False,
                false_positive_reason=None,
                context_notes=context_notes,
                verification_status="unverified"
            )
            validated_findings.append(validated)
        
        # Calculate new severity counts
        severity_counts = defaultdict(int)
        for vf in validated_findings:
            severity_counts[vf.adjusted_severity] += 1
        
        # Build result
        result = {
            "target_url": target_url,
            "detected_context": self.detected_context.value,
            "context_hints": {
                "is_https": self.context_hints.is_https,
                "is_private_ip": self.context_hints.is_private_ip,
                "server_headers": self.context_hints.server_headers[:5],
                "port": self.context_hints.port
            },
            "original_finding_count": len(findings),
            "validated_finding_count": len(validated_findings),
            "removed_false_positives": len(removed_fps),
            "false_positives": removed_fps,
            "severity_adjustments": severity_adjustments,
            "adjusted_severity_counts": {
                "critical": severity_counts.get("critical", 0),
                "high": severity_counts.get("high", 0),
                "medium": severity_counts.get("medium", 0),
                "low": severity_counts.get("low", 0),
                "info": severity_counts.get("info", 0),
            },
            "validated_findings": [
                {
                    "core_issue": vf.group_id.split(":", 1)[1],
                    "severity": vf.adjusted_severity,
                    "original_severity": vf.original_severity,
                    "occurrence_count": vf.occurrence_count,
                    "context_notes": vf.context_notes,
                    "sample_finding": {
                        "type": vf.original_finding.get("type", vf.original_finding.get("name")),
                        "description": vf.original_finding.get("description", "")[:200],
                        "url": vf.original_finding.get("url", "")
                    }
                }
                for vf in validated_findings
            ],
            "summary": self._generate_summary(
                validated_findings, removed_fps, self.detected_context
            )
        }
        
        logger.info(
            f"Validation complete: {len(findings)} → {len(validated_findings)} findings, "
            f"{len(removed_fps)} false positives removed"
        )
        
        return result
    
    def _generate_summary(
        self,
        findings: List[ValidatedFinding],
        removed_fps: List[Dict[str, Any]],
        context: TargetContext
    ) -> str:
        """Generate a human-readable summary of the validation results."""
        lines = []
        
        if context == TargetContext.EMBEDDED_DEVICE:
            lines.append("**Target Type:** Embedded Device (Router/IoT)")
            lines.append("")
            lines.append("Findings have been adjusted for embedded device context. "
                        "Many security headers that are critical for web applications "
                        "are not applicable or expected to be missing on embedded devices.")
        elif context == TargetContext.INTERNAL_API:
            lines.append("**Target Type:** Internal API/Service")
            lines.append("")
            lines.append("Findings have been adjusted for internal network context.")
        else:
            lines.append("**Target Type:** Enterprise Web Application")
            lines.append("")
            lines.append("Full severity ratings applied.")
        
        if removed_fps:
            lines.append("")
            lines.append(f"**False Positives Removed:** {len(removed_fps)}")
            for fp in removed_fps[:5]:  # Show first 5
                lines.append(f"  - {fp['core_issue']}: {fp['reason']}")
        
        # Group remaining findings by severity
        by_severity = defaultdict(list)
        for f in findings:
            by_severity[f.adjusted_severity].append(f)
        
        lines.append("")
        lines.append("**Validated Findings:**")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                count = len(by_severity[sev])
                total_occurrences = sum(f.occurrence_count for f in by_severity[sev])
                lines.append(f"  - {sev.upper()}: {count} unique issues ({total_occurrences} total occurrences)")
        
        return "\n".join(lines)


# Singleton instance
finding_validator = FindingValidatorService()
