"""
Nmap Analysis Service for VRAgent.

Analyzes Nmap scan results for security issues including:
- Open ports and services
- Vulnerability detection from scripts
- OS fingerprinting
- Service version detection
- Security misconfigurations
"""

import json
import re
import shutil
import subprocess
import tempfile
import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from collections import defaultdict

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class NmapHost:
    """A host discovered by Nmap."""
    ip: str
    hostname: Optional[str] = None
    status: str = "up"
    os_guess: Optional[str] = None
    os_accuracy: Optional[int] = None
    ports: List[Dict[str, Any]] = field(default_factory=list)
    scripts: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NmapFinding:
    """A security finding from Nmap analysis."""
    category: str  # open_port, vulnerable_service, weak_config, cve, etc.
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    evidence: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NmapSummary:
    """Summary statistics from Nmap analysis."""
    total_hosts: int
    hosts_up: int
    hosts_down: int
    total_ports_scanned: int
    open_ports: int
    filtered_ports: int
    closed_ports: int
    services_detected: Dict[str, int] = field(default_factory=dict)
    os_distribution: Dict[str, int] = field(default_factory=dict)
    scan_type: Optional[str] = None
    scan_time: Optional[str] = None
    command: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NmapAnalysisResult:
    """Complete Nmap analysis result."""
    filename: str
    summary: NmapSummary
    hosts: List[NmapHost] = field(default_factory=list)
    findings: List[NmapFinding] = field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "summary": self.summary.to_dict(),
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in self.findings],
            "ai_analysis": self.ai_analysis,
        }


# High-risk ports that should be flagged
HIGH_RISK_PORTS = {
    21: ("FTP", "high", "FTP often transmits credentials in cleartext"),
    22: ("SSH", "info", "SSH - verify strong authentication is required"),
    23: ("Telnet", "critical", "Telnet transmits all data including credentials in cleartext"),
    25: ("SMTP", "medium", "SMTP may allow mail relay if misconfigured"),
    53: ("DNS", "medium", "DNS may be vulnerable to cache poisoning or zone transfers"),
    110: ("POP3", "high", "POP3 transmits credentials in cleartext"),
    111: ("RPC", "high", "RPC services can expose internal network information"),
    135: ("MSRPC", "high", "Windows RPC - often targeted for exploits"),
    137: ("NetBIOS-NS", "high", "NetBIOS can leak system information"),
    138: ("NetBIOS-DGM", "high", "NetBIOS datagram service"),
    139: ("NetBIOS-SSN", "high", "NetBIOS session service - SMB over NetBIOS"),
    143: ("IMAP", "high", "IMAP may transmit credentials in cleartext"),
    161: ("SNMP", "high", "SNMP often uses weak community strings"),
    389: ("LDAP", "medium", "LDAP may expose directory information"),
    443: ("HTTPS", "info", "HTTPS - verify TLS configuration"),
    445: ("SMB", "high", "SMB - common target for ransomware and exploits"),
    512: ("rexec", "critical", "Remote execution without encryption"),
    513: ("rlogin", "critical", "Remote login without encryption"),
    514: ("rsh", "critical", "Remote shell without encryption"),
    1433: ("MSSQL", "high", "Microsoft SQL Server - verify authentication"),
    1521: ("Oracle", "high", "Oracle database - verify authentication"),
    2049: ("NFS", "high", "NFS can expose file systems if misconfigured"),
    3306: ("MySQL", "high", "MySQL database - verify authentication"),
    3389: ("RDP", "high", "Remote Desktop - common brute force target"),
    5432: ("PostgreSQL", "medium", "PostgreSQL database"),
    5900: ("VNC", "high", "VNC often has weak authentication"),
    5985: ("WinRM", "high", "Windows Remote Management"),
    6379: ("Redis", "critical", "Redis often has no authentication by default"),
    8080: ("HTTP-Proxy", "medium", "HTTP proxy or alternative web server"),
    27017: ("MongoDB", "critical", "MongoDB often has no authentication by default"),
}


def parse_nmap_xml(file_path: Path) -> NmapAnalysisResult:
    """Parse Nmap XML output file."""
    logger.info(f"Parsing Nmap XML: {file_path}")
    
    tree = ET.parse(str(file_path))
    root = tree.getroot()
    
    # Extract scan metadata
    scan_info = root.find("scaninfo")
    scan_type = scan_info.get("type") if scan_info is not None else None
    
    run_stats = root.find("runstats")
    finished = run_stats.find("finished") if run_stats else None
    scan_time = finished.get("timestr") if finished is not None else None
    
    command = root.get("args", "")
    
    hosts: List[NmapHost] = []
    findings: List[NmapFinding] = []
    
    total_hosts = 0
    hosts_up = 0
    hosts_down = 0
    open_ports = 0
    filtered_ports = 0
    closed_ports = 0
    services: Dict[str, int] = defaultdict(int)
    os_dist: Dict[str, int] = defaultdict(int)
    
    for host_elem in root.findall("host"):
        total_hosts += 1
        
        # Get host status
        status_elem = host_elem.find("status")
        status = status_elem.get("state", "unknown") if status_elem is not None else "unknown"
        
        if status == "up":
            hosts_up += 1
        else:
            hosts_down += 1
            continue
        
        # Get IP address
        addr_elem = host_elem.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host_elem.find("address[@addrtype='ipv6']")
        ip = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"
        
        # Get hostname
        hostnames_elem = host_elem.find("hostnames")
        hostname = None
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name")
        
        # Get OS detection
        os_elem = host_elem.find("os")
        os_guess = None
        os_accuracy = None
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_guess = osmatch.get("name")
                os_accuracy = int(osmatch.get("accuracy", 0))
                os_dist[os_guess] = os_dist.get(os_guess, 0) + 1
        
        host_ports: List[Dict[str, Any]] = []
        host_scripts: List[Dict[str, Any]] = []
        
        # Parse ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                
                if state == "open":
                    open_ports += 1
                elif state == "filtered":
                    filtered_ports += 1
                elif state == "closed":
                    closed_ports += 1
                
                # Get service info
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                service_product = service_elem.get("product", "") if service_elem is not None else ""
                service_version = service_elem.get("version", "") if service_elem is not None else ""
                
                if state == "open":
                    services[service_name] = services.get(service_name, 0) + 1
                
                port_info = {
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": service_product,
                    "version": service_version,
                }
                
                # Parse port scripts
                port_scripts = []
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    port_scripts.append({"id": script_id, "output": script_output})
                    
                    # Check for vulnerabilities in script output
                    script_findings = _check_script_for_vulns(script_id, script_output, ip, port_num, service_name)
                    findings.extend(script_findings)
                
                port_info["scripts"] = port_scripts
                host_ports.append(port_info)
                
                # Check for high-risk ports
                if state == "open" and port_num in HIGH_RISK_PORTS:
                    risk_info = HIGH_RISK_PORTS[port_num]
                    findings.append(NmapFinding(
                        category="open_port",
                        severity=risk_info[1],
                        title=f"High-Risk Port Open: {port_num}/{protocol} ({risk_info[0]})",
                        description=risk_info[2],
                        host=ip,
                        port=port_num,
                        service=service_name,
                    ))
        
        # Parse host scripts
        hostscript_elem = host_elem.find("hostscript")
        if hostscript_elem is not None:
            for script_elem in hostscript_elem.findall("script"):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")
                host_scripts.append({"id": script_id, "output": script_output})
                
                script_findings = _check_script_for_vulns(script_id, script_output, ip, None, None)
                findings.extend(script_findings)
        
        hosts.append(NmapHost(
            ip=ip,
            hostname=hostname,
            status=status,
            os_guess=os_guess,
            os_accuracy=os_accuracy,
            ports=host_ports,
            scripts=host_scripts,
        ))
    
    summary = NmapSummary(
        total_hosts=total_hosts,
        hosts_up=hosts_up,
        hosts_down=hosts_down,
        total_ports_scanned=open_ports + filtered_ports + closed_ports,
        open_ports=open_ports,
        filtered_ports=filtered_ports,
        closed_ports=closed_ports,
        services_detected=dict(services),
        os_distribution=dict(os_dist),
        scan_type=scan_type,
        scan_time=scan_time,
        command=command,
    )
    
    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f.title, f.host, f.port)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    return NmapAnalysisResult(
        filename=file_path.name,
        summary=summary,
        hosts=hosts,
        findings=unique_findings,
    )


def parse_nmap_text(file_path: Path) -> NmapAnalysisResult:
    """Parse Nmap text/grepable output file."""
    logger.info(f"Parsing Nmap text output: {file_path}")
    
    content = file_path.read_text(encoding='utf-8', errors='ignore')
    
    hosts: List[NmapHost] = []
    findings: List[NmapFinding] = []
    services: Dict[str, int] = defaultdict(int)
    
    open_ports = 0
    hosts_up = 0
    
    # Parse grepable format
    if "Host:" in content and "Ports:" in content:
        for line in content.split('\n'):
            if line.startswith("Host:"):
                match = re.match(r'Host:\s+(\S+)\s+\((.*?)\).*Ports:\s+(.*)', line)
                if match:
                    ip = match.group(1)
                    hostname = match.group(2) if match.group(2) else None
                    ports_str = match.group(3)
                    
                    hosts_up += 1
                    host_ports = []
                    
                    for port_info in ports_str.split(','):
                        port_info = port_info.strip()
                        parts = port_info.split('/')
                        if len(parts) >= 5:
                            port_num = int(parts[0])
                            state = parts[1]
                            protocol = parts[2]
                            service = parts[4] if len(parts) > 4 else "unknown"
                            
                            if state == "open":
                                open_ports += 1
                                services[service] = services.get(service, 0) + 1
                                
                                if port_num in HIGH_RISK_PORTS:
                                    risk_info = HIGH_RISK_PORTS[port_num]
                                    findings.append(NmapFinding(
                                        category="open_port",
                                        severity=risk_info[1],
                                        title=f"High-Risk Port Open: {port_num}/{protocol} ({risk_info[0]})",
                                        description=risk_info[2],
                                        host=ip,
                                        port=port_num,
                                        service=service,
                                    ))
                            
                            host_ports.append({
                                "port": port_num,
                                "protocol": protocol,
                                "state": state,
                                "service": service,
                            })
                    
                    hosts.append(NmapHost(ip=ip, hostname=hostname, ports=host_ports))
    
    # Parse standard format
    else:
        current_host = None
        for line in content.split('\n'):
            # Host discovery
            host_match = re.match(r'Nmap scan report for\s+(?:(\S+)\s+\()?(\d+\.\d+\.\d+\.\d+)', line)
            if host_match:
                if current_host:
                    hosts.append(current_host)
                hostname = host_match.group(1)
                ip = host_match.group(2)
                current_host = NmapHost(ip=ip, hostname=hostname, ports=[])
                hosts_up += 1
                continue
            
            # Port info
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)', line)
            if port_match and current_host:
                port_num = int(port_match.group(1))
                protocol = port_match.group(2)
                state = port_match.group(3)
                service = port_match.group(4)
                
                if state == "open":
                    open_ports += 1
                    services[service] = services.get(service, 0) + 1
                    
                    if port_num in HIGH_RISK_PORTS:
                        risk_info = HIGH_RISK_PORTS[port_num]
                        findings.append(NmapFinding(
                            category="open_port",
                            severity=risk_info[1],
                            title=f"High-Risk Port Open: {port_num}/{protocol} ({risk_info[0]})",
                            description=risk_info[2],
                            host=current_host.ip,
                            port=port_num,
                            service=service,
                        ))
                
                current_host.ports.append({
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                })
        
        if current_host:
            hosts.append(current_host)
    
    summary = NmapSummary(
        total_hosts=hosts_up,
        hosts_up=hosts_up,
        hosts_down=0,
        total_ports_scanned=open_ports,
        open_ports=open_ports,
        filtered_ports=0,
        closed_ports=0,
        services_detected=dict(services),
        os_distribution={},
    )
    
    return NmapAnalysisResult(
        filename=file_path.name,
        summary=summary,
        hosts=hosts,
        findings=findings,
    )


def _check_script_for_vulns(script_id: str, output: str, host: str, port: Optional[int], service: Optional[str]) -> List[NmapFinding]:
    """Check Nmap script output for vulnerabilities."""
    findings = []
    output_lower = output.lower()
    
    # CVE detection
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    cves = re.findall(cve_pattern, output, re.IGNORECASE)
    if cves:
        findings.append(NmapFinding(
            category="cve",
            severity="high",
            title=f"CVE(s) Detected: {', '.join(cves[:5])}",
            description=f"Nmap script '{script_id}' detected known vulnerabilities.",
            host=host,
            port=port,
            service=service,
            evidence=output[:500],
            cve_ids=cves,
        ))
    
    # SMB vulnerabilities
    if "smb-vuln" in script_id:
        if "vulnerable" in output_lower or "state: vulnerable" in output_lower:
            findings.append(NmapFinding(
                category="vulnerable_service",
                severity="critical",
                title=f"SMB Vulnerability Detected ({script_id})",
                description="SMB service is vulnerable to known exploits.",
                host=host,
                port=port or 445,
                service="smb",
                evidence=output[:500],
            ))
    
    # SSL/TLS issues
    if "ssl-" in script_id or "tls-" in script_id:
        if "sslv2" in output_lower or "sslv3" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="Deprecated SSL/TLS Version Supported",
                description="Server supports deprecated SSLv2 or SSLv3 which are vulnerable.",
                host=host,
                port=port,
                service=service,
                evidence=output[:300],
            ))
        if "weak" in output_lower or "export" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="Weak SSL/TLS Ciphers Supported",
                description="Server supports weak or export-grade ciphers.",
                host=host,
                port=port,
                service=service,
            ))
    
    # Default/weak credentials
    if "brute" in script_id or "login" in script_id:
        if "valid credentials" in output_lower or "success" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="critical",
                title="Weak/Default Credentials Detected",
                description="Service may be using default or easily guessable credentials.",
                host=host,
                port=port,
                service=service,
            ))
    
    # Anonymous access
    if "anonymous" in output_lower and ("allowed" in output_lower or "enabled" in output_lower):
        findings.append(NmapFinding(
            category="weak_config",
            severity="high",
            title="Anonymous Access Allowed",
            description="Service allows anonymous/unauthenticated access.",
            host=host,
            port=port,
            service=service,
        ))
    
    return findings


def analyze_nmap(file_path: Path) -> NmapAnalysisResult:
    """
    Analyze an Nmap scan output file.
    
    Supports:
    - XML output (-oX)
    - Grepable output (-oG)
    - Normal text output (-oN)
    """
    content = file_path.read_bytes()[:1000]
    
    # Detect format
    if b"<?xml" in content or b"<nmaprun" in content:
        return parse_nmap_xml(file_path)
    else:
        return parse_nmap_text(file_path)


async def analyze_nmap_with_ai(analysis_result: NmapAnalysisResult) -> Dict[str, Any]:
    """
    Use Gemini to provide AI-powered structured analysis of Nmap scan results.
    """
    if not settings.gemini_api_key:
        return {"error": "AI analysis unavailable: GEMINI_API_KEY not configured"}
    
    try:
        import google.generativeai as genai
        
        genai.configure(api_key=settings.gemini_api_key)
        model = genai.GenerativeModel(settings.gemini_model_id)
        
        # Build summary for AI
        findings_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description} (host: {f.host}, port: {f.port})"
            for f in analysis_result.findings[:25]
        )
        
        hosts_text = "\n".join(
            f"- {h.ip} ({h.hostname or 'no hostname'}): {len([p for p in h.ports if p.get('state') == 'open'])} open ports, OS: {h.os_guess or 'unknown'}"
            for h in analysis_result.hosts[:20]
        )
        
        prompt = f"""You are an expert network security analyst and penetration tester. Analyze this Nmap scan data and produce a comprehensive, structured security assessment report.

## SCAN DATA

### Overview
- **Filename**: {analysis_result.filename}
- **Scan Command**: {analysis_result.summary.command or 'N/A'}
- **Scan Time**: {analysis_result.summary.scan_time or 'N/A'}
- **Scan Type**: {analysis_result.summary.scan_type or 'N/A'}

### Statistics
- **Total Hosts**: {analysis_result.summary.total_hosts}
- **Hosts Up**: {analysis_result.summary.hosts_up}
- **Hosts Down**: {analysis_result.summary.hosts_down}
- **Open Ports**: {analysis_result.summary.open_ports}
- **Filtered Ports**: {analysis_result.summary.filtered_ports}

### Services Detected
```json
{json.dumps(analysis_result.summary.services_detected, indent=2)}
```

### OS Distribution
```json
{json.dumps(analysis_result.summary.os_distribution, indent=2)}
```

### Hosts Summary
{hosts_text}

### Automated Security Findings ({len(analysis_result.findings)} issues)
{findings_text if findings_text else "No critical security issues detected by automated analysis."}

---

## REQUIRED OUTPUT FORMAT

You MUST respond with a valid JSON object matching this exact structure. Do not include any text before or after the JSON.

{{
  "risk_level": "Critical|High|Medium|Low",
  "risk_score": <0-100>,
  "executive_summary": "<2-3 paragraph executive summary for non-technical stakeholders. Explain the overall network security posture, main concerns, and business impact in plain language.>",
  "network_overview": {{
    "assessment": "<overall assessment of network exposure>",
    "attack_surface_rating": "Large|Medium|Small|Minimal",
    "internet_exposed_services": <count>,
    "internal_only_services": <count>
  }},
  "key_findings": [
    {{
      "title": "<finding title>",
      "severity": "Critical|High|Medium|Low|Info",
      "description": "<detailed technical description>",
      "affected_hosts": ["<ip1>", "<ip2>"],
      "affected_ports": [<port1>, <port2>],
      "evidence": "<specific evidence>",
      "recommendation": "<specific remediation action>"
    }}
  ],
  "vulnerable_services": [
    {{
      "service": "<service name>",
      "port": <port>,
      "hosts": ["<ip1>", "<ip2>"],
      "vulnerability": "<vulnerability description>",
      "severity": "Critical|High|Medium|Low",
      "cve_ids": ["CVE-XXXX-XXXX"],
      "exploit_available": true|false,
      "recommendation": "<fix>"
    }}
  ],
  "high_risk_hosts": [
    {{
      "ip": "<IP address>",
      "hostname": "<hostname if known>",
      "risk_level": "Critical|High|Medium|Low",
      "open_ports_count": <count>,
      "critical_services": ["<service1>", "<service2>"],
      "os": "<detected OS>",
      "concerns": "<why this host is high risk>",
      "priority_actions": ["<action1>", "<action2>"]
    }}
  ],
  "service_analysis": {{
    "web_servers": {{
      "count": <count>,
      "hosts": ["<ip:port>"],
      "concerns": "<concerns about web servers>"
    }},
    "databases": {{
      "count": <count>,
      "hosts": ["<ip:port>"],
      "concerns": "<concerns about exposed databases>"
    }},
    "remote_access": {{
      "count": <count>,
      "hosts": ["<ip:port>"],
      "concerns": "<concerns about RDP/SSH/VNC etc>"
    }},
    "file_sharing": {{
      "count": <count>,
      "hosts": ["<ip:port>"],
      "concerns": "<concerns about SMB/FTP/NFS>"
    }},
    "legacy_services": {{
      "count": <count>,
      "hosts": ["<ip:port>"],
      "concerns": "<concerns about Telnet/rsh/etc>"
    }}
  }},
  "attack_vectors": [
    {{
      "vector": "<attack vector name>",
      "severity": "Critical|High|Medium|Low",
      "entry_points": ["<ip:port>"],
      "description": "<how an attacker could exploit this>",
      "potential_impact": "<what could be compromised>",
      "likelihood": "High|Medium|Low"
    }}
  ],
  "compliance_concerns": [
    {{
      "standard": "PCI-DSS|HIPAA|SOC2|NIST|ISO27001|General",
      "concern": "<compliance concern>",
      "affected_hosts": ["<ip>"],
      "remediation": "<how to become compliant>"
    }}
  ],
  "recommendations": [
    {{
      "priority": "Immediate|High|Medium|Low",
      "category": "Firewall|Patching|Configuration|Monitoring|Decommission",
      "action": "<specific actionable recommendation>",
      "affected_hosts": ["<ip>"],
      "rationale": "<why this is important>",
      "effort": "Low|Medium|High"
    }}
  ],
  "network_segmentation_assessment": "<assessment of network segmentation based on discovered services and hosts>"
}}

IMPORTANT GUIDELINES:
1. Be thorough but avoid false positives
2. Prioritize findings by actual exploitability
3. Consider the context - internal vs external scan
4. Highlight any services that should never be exposed
5. Focus on actionable recommendations
6. Return ONLY valid JSON - no markdown, no explanations outside the JSON"""

        response = await model.generate_content_async(prompt)
        response_text = response.text.strip()
        
        # Clean up response
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        try:
            report = json.loads(response_text)
            return {"structured_report": report}
        except json.JSONDecodeError as je:
            logger.error(f"Failed to parse AI response as JSON: {je}")
            return {"raw_analysis": response_text, "parse_error": str(je)}
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": f"AI analysis failed: {str(e)}"}


# ============================================================================
# Nmap Execution Functions
# ============================================================================

# Available scan types with descriptions - ordered from least to most intensive
# Each scan type includes an estimated time range for a single host
# Timeouts are generous to handle slow/distant hosts
SCAN_TYPES = {
    "ping": {
        "name": "Ping Sweep",
        "description": "Host discovery only - no port scanning",
        "args": ["-sn", "-T4"],
        "timeout": 120,
        "requires_root": False,
        "estimated_time": "5-30 sec",
        "intensity": 1,
    },
    "quick": {
        "name": "Quick Scan",
        "description": "Top 100 ports, no service detection",
        "args": ["-T4", "-F", "--top-ports", "100"],
        "timeout": 300,
        "requires_root": False,
        "estimated_time": "30-60 sec",
        "intensity": 2,
    },
    "stealth": {
        "name": "Stealth SYN Scan",
        "description": "SYN scan - fast and less detectable",
        "args": ["-sS", "-T4", "--top-ports", "1000"],
        "timeout": 600,
        "requires_root": False,
        "estimated_time": "1-3 min",
        "intensity": 3,
    },
    "basic": {
        "name": "Basic Scan",
        "description": "Top 1000 ports with service detection",
        "args": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
        "timeout": 900,
        "requires_root": False,
        "estimated_time": "3-10 min",
        "intensity": 4,
    },
    "version": {
        "name": "Version Detection",
        "description": "Detailed service version identification",
        "args": ["-sV", "-T4", "--version-intensity", "5", "--top-ports", "1000"],
        "timeout": 900,
        "requires_root": False,
        "estimated_time": "3-10 min",
        "intensity": 5,
    },
    "script": {
        "name": "Script Scan",
        "description": "Default NSE scripts for common services",
        "args": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
        "timeout": 900,
        "requires_root": False,
        "estimated_time": "3-10 min",
        "intensity": 6,
    },
    "udp_quick": {
        "name": "UDP Quick Scan",
        "description": "Top 20 UDP ports (DNS, SNMP, etc)",
        "args": ["-sU", "-T4", "--top-ports", "20"],
        "timeout": 600,
        "requires_root": False,
        "estimated_time": "2-5 min",
        "intensity": 7,
    },
    "os_detect": {
        "name": "OS Detection",
        "description": "Operating system fingerprinting",
        "args": ["-O", "-sV", "-T4", "--top-ports", "1000"],
        "timeout": 900,
        "requires_root": False,
        "estimated_time": "3-10 min",
        "intensity": 8,
    },
    "vuln": {
        "name": "Vulnerability Scan",
        "description": "Run vulnerability detection scripts",
        "args": ["-sV", "-T4", "--script", "vuln", "--top-ports", "1000"],
        "timeout": 1800,
        "requires_root": False,
        "estimated_time": "10-30 min",
        "intensity": 9,
    },
    "aggressive": {
        "name": "Aggressive Scan",
        "description": "OS, version, scripts, traceroute combined",
        "args": ["-A", "-T4", "--top-ports", "1000"],
        "timeout": 1800,
        "requires_root": False,
        "estimated_time": "10-20 min",
        "intensity": 10,
    },
    "udp": {
        "name": "UDP Full Scan",
        "description": "Top 100 UDP ports - comprehensive",
        "args": ["-sU", "-sV", "-T4", "--top-ports", "100"],
        "timeout": 1800,
        "requires_root": False,
        "estimated_time": "10-30 min",
        "intensity": 11,
    },
    "comprehensive": {
        "name": "Comprehensive Scan",
        "description": "TCP + UDP + OS + scripts + traceroute",
        "args": ["-sS", "-sU", "-sV", "-sC", "-O", "-T4", "--top-ports", "1000"],
        "timeout": 2700,
        "requires_root": False,
        "estimated_time": "20-45 min",
        "intensity": 12,
    },
    "full_tcp": {
        "name": "Full TCP Scan",
        "description": "All 65535 TCP ports with service detection",
        "args": ["-sV", "-sC", "-T4", "-p-"],
        "timeout": 7200,
        "requires_root": False,
        "estimated_time": "30-120 min",
        "intensity": 13,
    },
    "full_all": {
        "name": "Full Scan (TCP+UDP)",
        "description": "All TCP ports + top 100 UDP - most thorough",
        "args": ["-sS", "-sU", "-sV", "-sC", "-O", "-T4", "-p-", "--top-udp-ports", "100"],
        "timeout": 14400,
        "requires_root": False,
        "estimated_time": "1-4 hours",
        "intensity": 14,
    },
}


def is_nmap_installed() -> bool:
    """Check if nmap is installed and available."""
    return shutil.which("nmap") is not None


def get_scan_types() -> List[Dict[str, Any]]:
    """Get list of available scan types with descriptions, ordered by intensity."""
    scan_list = [
        {
            "id": scan_id,
            "name": scan_info["name"],
            "description": scan_info["description"],
            "timeout": scan_info["timeout"],
            "requires_root": scan_info["requires_root"],
            "estimated_time": scan_info.get("estimated_time", "Unknown"),
            "intensity": scan_info.get("intensity", 0),
        }
        for scan_id, scan_info in SCAN_TYPES.items()
    ]
    # Sort by intensity (least to most intensive)
    return sorted(scan_list, key=lambda x: x["intensity"])


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate a scan target for safety.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    target = target.strip()
    
    if not target:
        return False, "Target cannot be empty"
    
    # Block dangerous targets
    blocked_patterns = [
        "127.0.0.1", "localhost", "0.0.0.0",
        "::1", "169.254.",  # Link-local
    ]
    
    for pattern in blocked_patterns:
        if pattern in target.lower():
            return False, f"Scanning {pattern} is not allowed for safety reasons"
    
    # Try to parse as IP address
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_loopback:
            return False, "Cannot scan loopback addresses"
        if ip.is_link_local:
            return False, "Cannot scan link-local addresses"
        if ip.is_multicast:
            return False, "Cannot scan multicast addresses"
        if ip.is_reserved:
            return False, "Cannot scan reserved addresses"
        return True, ""
    except ValueError:
        pass
    
    # Try CIDR notation
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 256:
            return False, f"Network too large: {network.num_addresses} addresses. Maximum is /24 (256 addresses)"
        if network.is_loopback:
            return False, "Cannot scan loopback networks"
        return True, ""
    except ValueError:
        pass
    
    # Hostname validation
    if len(target) > 255:
        return False, "Hostname too long (max 255 characters)"
    
    # Basic hostname pattern - allow domains like example.com, sub.example.com
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    if not re.match(hostname_pattern, target):
        return False, "Invalid hostname format. Use IP address, CIDR notation, or valid hostname"
    
    return True, ""


def run_nmap_scan(
    target: str,
    scan_type: str = "basic",
    ports: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> Tuple[Optional[Path], Optional[str], Optional[str]]:
    """
    Run an Nmap scan and return the path to the XML output.
    
    Args:
        target: IP address, CIDR range, or hostname to scan
        scan_type: Type of scan from SCAN_TYPES
        ports: Optional port specification (e.g., "22,80,443" or "1-1000")
        extra_args: Additional nmap arguments
        
    Returns:
        Tuple of (output_xml_path, command_used, error_message)
    """
    if not is_nmap_installed():
        return None, None, "Nmap is not installed on the server"
    
    # Validate target
    is_valid, error = validate_target(target)
    if not is_valid:
        return None, None, error
    
    # Get scan configuration
    scan_config = SCAN_TYPES.get(scan_type)
    if not scan_config:
        return None, None, f"Unknown scan type: {scan_type}. Available: {list(SCAN_TYPES.keys())}"
    
    # Build command
    cmd = ["nmap"]
    cmd.extend(scan_config["args"])
    
    # Add specific ports if provided (overrides scan type default)
    if ports:
        # Validate port specification
        if not re.match(r'^[\d,\-\s]+$', ports):
            return None, None, "Invalid port specification. Use format like '22,80,443' or '1-1000'"
        # Remove existing port args if any
        cmd = [arg for arg in cmd if arg not in ["-F", "--top-ports"] and not arg.isdigit()]
        cmd.extend(["-p", ports.replace(" ", "")])
    
    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args)
    
    # Output format - XML
    output_dir = Path(tempfile.mkdtemp(prefix="nmap_scan_"))
    output_file = output_dir / "scan_result.xml"
    cmd.extend(["-oX", str(output_file)])
    
    # Add target
    cmd.append(target)
    
    command_str = " ".join(cmd)
    logger.info(f"Running Nmap scan: {command_str}")
    
    try:
        timeout = scan_config["timeout"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        
        # Log output for debugging
        if result.stdout:
            logger.debug(f"Nmap stdout: {result.stdout[:500]}")
        if result.stderr:
            logger.warning(f"Nmap stderr: {result.stderr[:500]}")
        
        # Check for permission errors in stderr
        if result.returncode != 0 and "permission" in (result.stderr or "").lower():
            return None, command_str, "Permission denied. The server needs root privileges for this scan type."
        
        # Nmap often returns non-zero for partial results, check if output exists
        if not output_file.exists():
            error_msg = result.stderr or result.stdout or "Nmap did not produce output"
            return None, command_str, f"Scan failed: {error_msg}"
        
        # Check if file has content
        if output_file.stat().st_size == 0:
            return None, command_str, "Nmap produced empty output file"
        
        logger.info(f"Nmap scan completed successfully. Output: {output_file}")
        return output_file, command_str, None
        
    except subprocess.TimeoutExpired:
        return None, command_str, f"Scan timed out after {scan_config['timeout']} seconds. Try a quicker scan type."
    except PermissionError as e:
        logger.error(f"Permission error running nmap: {e}")
        return None, command_str, "Permission denied. The server needs root privileges for nmap scans."
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return None, command_str, f"Scan failed: {str(e)}"

