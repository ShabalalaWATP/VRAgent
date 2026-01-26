"""
MITM MITRE ATT&CK Mapping

Maps MITM attack tools to MITRE ATT&CK techniques and provides:
- Technique IDs and descriptions
- Tactic classifications
- Attack narratives
- Risk scoring
- Remediation recommendations
"""

import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# MITRE ATT&CK Definitions
# ============================================================================

class MITRETactic(str, Enum):
    """MITRE ATT&CK Tactics."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique definition."""
    technique_id: str
    name: str
    description: str
    tactics: List[MITRETactic]
    url: str

    # Sub-techniques if any
    sub_techniques: List[str] = field(default_factory=list)

    # Detection and mitigation
    detection_methods: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['tactics'] = [t.value for t in self.tactics]
        return d


# ============================================================================
# Technique Registry
# ============================================================================

MITRE_TECHNIQUES: Dict[str, MITRETechnique] = {
    "T1557": MITRETechnique(
        technique_id="T1557",
        name="Adversary-in-the-Middle",
        description="Adversaries may attempt to position themselves between two or more "
                    "networked devices to support follow-on behaviors such as Network Sniffing "
                    "or Transmitted Data Manipulation.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS, MITRETactic.COLLECTION],
        url="https://attack.mitre.org/techniques/T1557/",
        sub_techniques=["T1557.001", "T1557.002", "T1557.003"],
        detection_methods=[
            "Monitor network traffic for anomalies",
            "Detect ARP spoofing via ARP cache monitoring",
            "Monitor DNS query responses for unexpected changes"
        ],
        mitigations=[
            "Network segmentation",
            "Encrypt network traffic (HTTPS, VPN)",
            "Implement HSTS",
            "Use certificate pinning"
        ]
    ),

    "T1557.001": MITRETechnique(
        technique_id="T1557.001",
        name="LLMNR/NBT-NS Poisoning and SMB Relay",
        description="Adversaries may spoof LLMNR, NBT-NS, and mDNS responses to redirect "
                    "network traffic to adversary-controlled systems.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1557/001/",
        detection_methods=[
            "Monitor for LLMNR/NBT-NS queries and responses",
            "Detect rogue LLMNR responders on network"
        ],
        mitigations=[
            "Disable LLMNR and NBT-NS",
            "Enable SMB signing",
            "Network segmentation"
        ]
    ),

    "T1557.002": MITRETechnique(
        technique_id="T1557.002",
        name="ARP Cache Poisoning",
        description="Adversaries may poison ARP caches to position themselves between "
                    "devices communicating with each other.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1557/002/",
        detection_methods=[
            "Monitor ARP cache for unexpected changes",
            "Implement dynamic ARP inspection",
            "Use ARP monitoring tools"
        ],
        mitigations=[
            "Use static ARP entries for critical systems",
            "Implement DAI (Dynamic ARP Inspection)",
            "Network segmentation",
            "Use encrypted protocols"
        ]
    ),

    "T1040": MITRETechnique(
        technique_id="T1040",
        name="Network Sniffing",
        description="Adversaries may sniff network traffic to capture information about "
                    "an environment, including authentication material.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS, MITRETactic.DISCOVERY],
        url="https://attack.mitre.org/techniques/T1040/",
        detection_methods=[
            "Monitor for promiscuous mode on network interfaces",
            "Monitor for unusual network capture processes"
        ],
        mitigations=[
            "Encrypt network traffic",
            "Use secure protocols (TLS)",
            "Segment networks"
        ]
    ),

    "T1539": MITRETechnique(
        technique_id="T1539",
        name="Steal Web Session Cookie",
        description="Adversaries may steal web application cookies to gain access to "
                    "authenticated web sessions.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1539/",
        detection_methods=[
            "Monitor for cookie exfiltration via XSS",
            "Detect unusual session activity"
        ],
        mitigations=[
            "Set HttpOnly flag on cookies",
            "Set Secure flag on cookies",
            "Implement SameSite cookie attribute",
            "Use CSP to prevent XSS"
        ]
    ),

    "T1056.001": MITRETechnique(
        technique_id="T1056.001",
        name="Keylogging",
        description="Adversaries may log user keystrokes to intercept credentials.",
        tactics=[MITRETactic.COLLECTION, MITRETactic.CREDENTIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1056/001/",
        detection_methods=[
            "Monitor for keyboard hook API calls",
            "Detect injected scripts capturing keystrokes"
        ],
        mitigations=[
            "Use content security policy",
            "Employ password managers with auto-fill",
            "Use two-factor authentication"
        ]
    ),

    "T1059.007": MITRETechnique(
        technique_id="T1059.007",
        name="JavaScript",
        description="Adversaries may abuse JavaScript for execution, such as injecting "
                    "malicious scripts into web pages.",
        tactics=[MITRETactic.EXECUTION],
        url="https://attack.mitre.org/techniques/T1059/007/",
        detection_methods=[
            "Monitor for injected scripts",
            "CSP violation reports"
        ],
        mitigations=[
            "Content Security Policy",
            "Input validation",
            "Output encoding"
        ]
    ),

    "T1528": MITRETechnique(
        technique_id="T1528",
        name="Steal Application Access Token",
        description="Adversaries can steal application access tokens as a means of "
                    "acquiring credentials to access remote systems.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1528/",
        detection_methods=[
            "Monitor for token theft attempts",
            "Audit token usage patterns"
        ],
        mitigations=[
            "Rotate tokens regularly",
            "Implement token binding",
            "Use short-lived tokens"
        ]
    ),

    "T1550.001": MITRETechnique(
        technique_id="T1550.001",
        name="Application Access Token",
        description="Adversaries may use stolen application access tokens to bypass "
                    "authentication and access services.",
        tactics=[MITRETactic.DEFENSE_EVASION, MITRETactic.LATERAL_MOVEMENT],
        url="https://attack.mitre.org/techniques/T1550/001/",
        detection_methods=[
            "Monitor token usage from unexpected locations",
            "Detect anomalous API access patterns"
        ],
        mitigations=[
            "Implement token expiration",
            "Use device binding",
            "Monitor for suspicious activity"
        ]
    ),

    "T1111": MITRETechnique(
        technique_id="T1111",
        name="Multi-Factor Authentication Interception",
        description="Adversaries may target MFA mechanisms to gain access to credentials.",
        tactics=[MITRETactic.CREDENTIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1111/",
        detection_methods=[
            "Monitor for phishing targeting MFA",
            "Detect MFA bypass attempts"
        ],
        mitigations=[
            "Use hardware-based MFA",
            "Implement phishing-resistant MFA",
            "User awareness training"
        ]
    ),

    "T1190": MITRETechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        description="Adversaries may attempt to exploit vulnerabilities in internet-facing "
                    "applications to gain access.",
        tactics=[MITRETactic.INITIAL_ACCESS],
        url="https://attack.mitre.org/techniques/T1190/",
        detection_methods=[
            "Monitor web application logs",
            "Deploy WAF rules",
            "Monitor for exploit indicators"
        ],
        mitigations=[
            "Patch vulnerabilities",
            "Web Application Firewall",
            "Input validation"
        ]
    ),
}


# ============================================================================
# Tool to Technique Mapping
# ============================================================================

TOOL_MITRE_MAPPING: Dict[str, List[str]] = {
    # SSL Stripping
    "sslstrip": ["T1557.002", "T1557"],
    "hsts_bypass": ["T1557.002", "T1557"],

    # Credential Harvesting
    "credential_sniffer": ["T1040", "T1557"],
    "form_hijacker": ["T1056.001", "T1557"],
    "keylogger_advanced": ["T1056.001"],

    # Session Hijacking
    "cookie_hijacker": ["T1539"],
    "jwt_manipulator": ["T1528", "T1550.001"],
    "oauth_interceptor": ["T1528"],

    # Content Injection
    "script_injector": ["T1059.007"],
    "phishing_injector": ["T1056.001", "T1539"],

    # Header Manipulation
    "csp_bypass": ["T1059.007"],
    "cors_manipulator": ["T1557"],
    "x_frame_bypass": ["T1059.007"],

    # Protocol Attacks
    "request_smuggling_clte": ["T1190"],
    "request_smuggling_tecl": ["T1190"],
    "request_smuggling_tete": ["T1190"],
    "cache_poisoning": ["T1190"],
    "cache_deception": ["T1190"],

    # Network Attacks
    "arp_spoofing": ["T1557.002"],
    "dns_spoofing": ["T1557.001", "T1557"],
    "dhcp_starvation": ["T1557"],
    "dhcp_rogue": ["T1557"],
    "icmp_redirect": ["T1557"],
    "llmnr_poison": ["T1557.001"],

    # WebSocket
    "websocket_hijacker": ["T1557"],
    "graphql_injector": ["T1190"],

    # API
    "api_param_tamper": ["T1190"],
    "mtls_downgrade": ["T1557"],
    "cert_pinning_bypass": ["T1557"],

    # Advanced
    "2fa_interceptor": ["T1111"],
    "sse_interceptor": ["T1557"],
}


# ============================================================================
# Narrative Generator
# ============================================================================

@dataclass
class AttackNarrative:
    """A narrative description of an attack with MITRE mapping."""
    title: str
    summary: str
    attack_timeline: List[Dict[str, Any]]
    techniques_used: List[Dict[str, Any]]
    risk_score: int  # 0-100
    business_impact: str
    remediation_steps: List[str]
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['generated_at'] = self.generated_at.isoformat()
        return d


class MITMNarrativeGenerator:
    """
    Generates attack narratives with MITRE ATT&CK mapping.

    Provides professional security assessment narratives
    with technique references and remediation guidance.
    """

    def __init__(self):
        self.techniques = MITRE_TECHNIQUES
        self.tool_mapping = TOOL_MITRE_MAPPING

    def generate_narrative(
        self,
        executed_tools: List[Dict[str, Any]],
        captured_data: Dict[str, Any],
        target_info: Dict[str, Any]
    ) -> AttackNarrative:
        """
        Generate a complete attack narrative.

        Args:
            executed_tools: List of executed tools with results
            captured_data: Captured credentials, tokens, etc.
            target_info: Information about the target
        """
        # Build timeline
        timeline = self._build_timeline(executed_tools)

        # Map techniques
        techniques_used = self._map_techniques(executed_tools)

        # Calculate risk score
        risk_score = self._calculate_risk_score(executed_tools, captured_data)

        # Generate summary
        summary = self._generate_summary(executed_tools, captured_data, target_info)

        # Assess business impact
        impact = self._assess_business_impact(captured_data, risk_score)

        # Generate remediation steps
        remediation = self._generate_remediation(techniques_used)

        # Build title
        title = self._generate_title(target_info, risk_score)

        return AttackNarrative(
            title=title,
            summary=summary,
            attack_timeline=timeline,
            techniques_used=techniques_used,
            risk_score=risk_score,
            business_impact=impact,
            remediation_steps=remediation
        )

    def _build_timeline(self, executed_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build attack timeline from executed tools."""
        timeline = []

        for i, tool in enumerate(executed_tools, 1):
            entry = {
                "step": i,
                "timestamp": tool.get("timestamp", datetime.utcnow().isoformat()),
                "action": tool.get("tool_name", tool.get("tool_id", "Unknown")),
                "description": tool.get("description", ""),
                "outcome": "success" if tool.get("success") else "failed",
                "findings_count": len(tool.get("findings", [])),
                "credentials_captured": len(tool.get("credentials_captured", []))
            }

            # Add MITRE technique references
            tool_id = tool.get("tool_id", "")
            if tool_id in self.tool_mapping:
                entry["mitre_techniques"] = self.tool_mapping[tool_id]

            timeline.append(entry)

        return timeline

    def _map_techniques(self, executed_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map executed tools to MITRE techniques."""
        technique_ids = set()

        for tool in executed_tools:
            tool_id = tool.get("tool_id", "")
            if tool_id in self.tool_mapping:
                technique_ids.update(self.tool_mapping[tool_id])

        techniques = []
        for tid in technique_ids:
            technique = self.techniques.get(tid)
            if technique:
                techniques.append({
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactics": [t.value for t in technique.tactics],
                    "url": technique.url,
                    "description": technique.description
                })

        return techniques

    def _calculate_risk_score(
        self,
        executed_tools: List[Dict[str, Any]],
        captured_data: Dict[str, Any]
    ) -> int:
        """Calculate risk score (0-100)."""
        score = 0

        # Base score from successful attacks
        successful = [t for t in executed_tools if t.get("success")]
        score += len(successful) * 5

        # Credential capture is high risk
        creds = len(captured_data.get("credentials", []))
        score += creds * 15

        # Token capture
        tokens = len(captured_data.get("tokens", []))
        score += tokens * 10

        # Session hijacking
        sessions = len(captured_data.get("sessions", []))
        score += sessions * 12

        # Injection successful
        if any(t.get("injection_successful") for t in executed_tools):
            score += 20

        # Network-level MITM
        network_tools = ["arp_spoofing", "dns_spoofing", "llmnr_poison"]
        if any(t.get("tool_id") in network_tools and t.get("success") for t in executed_tools):
            score += 25

        # Critical technique usage
        critical_techniques = ["T1557.002", "T1111", "T1056.001"]
        for tool in executed_tools:
            tool_id = tool.get("tool_id", "")
            techniques = self.tool_mapping.get(tool_id, [])
            if any(t in critical_techniques for t in techniques):
                score += 10

        return min(100, score)

    def _generate_summary(
        self,
        executed_tools: List[Dict[str, Any]],
        captured_data: Dict[str, Any],
        target_info: Dict[str, Any]
    ) -> str:
        """Generate narrative summary."""
        parts = []

        target = target_info.get("target_host", "the target")
        parts.append(f"A man-in-the-middle attack was conducted against {target}.")

        # Describe attack progression
        successful = len([t for t in executed_tools if t.get("success")])
        total = len(executed_tools)
        parts.append(f"{successful} of {total} attack techniques were successful.")

        # Describe captured data
        creds = len(captured_data.get("credentials", []))
        if creds > 0:
            parts.append(f"CRITICAL: {creds} credential(s) were captured during the attack.")

        tokens = len(captured_data.get("tokens", []))
        if tokens > 0:
            parts.append(f"HIGH: {tokens} authentication token(s) were intercepted.")

        sessions = len(captured_data.get("sessions", []))
        if sessions > 0:
            parts.append(f"HIGH: {sessions} active session(s) were hijacked.")

        # Describe key vulnerabilities
        if any(t.get("tool_id") == "sslstrip" and t.get("success") for t in executed_tools):
            parts.append("The target was vulnerable to SSL stripping due to missing HSTS.")

        if any(t.get("tool_id") == "csp_bypass" and t.get("success") for t in executed_tools):
            parts.append("Content Security Policy was bypassed, enabling script injection.")

        return " ".join(parts)

    def _assess_business_impact(
        self,
        captured_data: Dict[str, Any],
        risk_score: int
    ) -> str:
        """Assess business impact of the attack."""
        if risk_score >= 80:
            severity = "CRITICAL"
            impact = "Complete compromise of user accounts and potential data breach."
        elif risk_score >= 60:
            severity = "HIGH"
            impact = "Significant risk of account takeover and data exposure."
        elif risk_score >= 40:
            severity = "MEDIUM"
            impact = "Moderate security weaknesses that could be exploited."
        elif risk_score >= 20:
            severity = "LOW"
            impact = "Minor security issues with limited exploitation potential."
        else:
            severity = "INFORMATIONAL"
            impact = "Defense-in-depth improvements recommended."

        creds = len(captured_data.get("credentials", []))
        if creds > 0:
            impact += f" {creds} user credential(s) were compromised."

        return f"[{severity}] {impact}"

    def _generate_remediation(
        self,
        techniques_used: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate remediation steps based on techniques used."""
        remediation = set()

        for tech_info in techniques_used:
            tid = tech_info.get("technique_id")
            technique = self.techniques.get(tid)
            if technique:
                remediation.update(technique.mitigations)

        # Prioritize remediation steps
        priority_order = [
            "Implement HSTS",
            "Use certificate pinning",
            "Content Security Policy",
            "Set HttpOnly flag on cookies",
            "Set Secure flag on cookies",
            "Encrypt network traffic",
            "Network segmentation",
            "Disable LLMNR and NBT-NS",
            "Patch vulnerabilities",
            "Web Application Firewall",
            "Input validation",
            "Output encoding",
            "Use hardware-based MFA",
            "Rotate tokens regularly"
        ]

        ordered = []
        for step in priority_order:
            if step in remediation:
                ordered.append(step)
                remediation.discard(step)

        # Add remaining
        ordered.extend(sorted(remediation))

        return ordered

    def _generate_title(self, target_info: Dict[str, Any], risk_score: int) -> str:
        """Generate narrative title."""
        target = target_info.get("target_host", "Target Application")

        if risk_score >= 80:
            return f"CRITICAL: Man-in-the-Middle Attack Assessment - {target}"
        elif risk_score >= 60:
            return f"HIGH RISK: MITM Security Assessment - {target}"
        elif risk_score >= 40:
            return f"MODERATE: MITM Vulnerability Assessment - {target}"
        else:
            return f"MITM Security Assessment - {target}"

    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a MITRE technique."""
        technique = self.techniques.get(technique_id)
        if technique:
            return technique.to_dict()
        return None

    def get_tool_techniques(self, tool_id: str) -> List[Dict[str, Any]]:
        """Get MITRE techniques for a specific tool."""
        technique_ids = self.tool_mapping.get(tool_id, [])
        techniques = []

        for tid in technique_ids:
            technique = self.techniques.get(tid)
            if technique:
                techniques.append(technique.to_dict())

        return techniques

    def get_all_techniques_summary(self) -> List[Dict[str, str]]:
        """Get summary of all mapped techniques."""
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactics": ", ".join(tactic.value for tactic in t.tactics),
                "url": t.url
            }
            for t in self.techniques.values()
        ]

    def generate_exploitation_commands(
        self,
        tool_id: str,
        target_info: Dict[str, Any]
    ) -> List[str]:
        """Generate example exploitation commands for a tool."""
        target_host = target_info.get("target_host", "target.com")
        target_ip = target_info.get("target_ip", "192.168.1.100")
        interface = target_info.get("interface", "eth0")

        commands = {
            "arp_spoofing": [
                f"# ARP Spoofing with Bettercap",
                f"bettercap -iface {interface}",
                f"set arp.spoof.targets {target_ip}",
                f"set arp.spoof.fullduplex true",
                f"arp.spoof on"
            ],
            "dns_spoofing": [
                f"# DNS Spoofing with Bettercap",
                f"set dns.spoof.domains {target_host}",
                f"set dns.spoof.address 192.168.1.50",
                f"dns.spoof on"
            ],
            "llmnr_poison": [
                f"# LLMNR/NBT-NS Poisoning with Responder",
                f"responder -I {interface} -wrf"
            ],
            "sslstrip": [
                f"# SSL Strip Attack",
                f"# Configure iptables for traffic redirect",
                f"iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000",
                f"sslstrip -l 10000"
            ],
            "jwt_manipulator": [
                f"# JWT Algorithm Confusion",
                f'# Original token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig',
                f'# Modified: eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.',
                f'# Use jwt_tool for automated attacks',
                f'jwt_tool <token> -A',
            ],
        }

        return commands.get(tool_id, [f"# No specific commands for {tool_id}"])
