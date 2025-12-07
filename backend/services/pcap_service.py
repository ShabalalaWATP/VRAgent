"""
PCAP Analysis Service for VRAgent.

Analyzes Wireshark packet captures for security issues including:
- Cleartext credentials (HTTP Basic Auth, FTP, Telnet)
- Suspicious traffic patterns (port scans, beaconing)
- Unencrypted protocols
- DNS queries and HTTP hosts
- Network conversations and statistics

Also supports live packet capture using tshark (Wireshark CLI).
"""

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from collections import defaultdict

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Try to import scapy - it's optional
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw, ICMP, ARP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("scapy not installed. PCAP analysis will be unavailable. Install with: pip install scapy")


@dataclass
class PcapFinding:
    """A security finding from PCAP analysis."""
    category: str  # credential_exposure, cleartext_protocol, suspicious_traffic, etc.
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    packet_number: Optional[int] = None
    evidence: Optional[str] = None  # Relevant packet data (sanitized)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class PcapSummary:
    """Summary statistics from PCAP analysis."""
    total_packets: int
    duration_seconds: float
    protocols: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Dict[str, Any]] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    potential_issues: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PcapAnalysisResult:
    """Complete PCAP analysis result."""
    filename: str
    summary: PcapSummary
    findings: List[PcapFinding] = field(default_factory=list)
    conversations: List[Dict[str, Any]] = field(default_factory=list)
    ai_analysis: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "conversations": self.conversations,
            "ai_analysis": self.ai_analysis,
        }


# ============================================================================
# Tshark/Wireshark Live Capture Functions
# ============================================================================

# Available capture profiles with different filters and settings
CAPTURE_PROFILES = {
    "all": {
        "name": "All Traffic",
        "description": "Capture all network traffic",
        "filter": "",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 1,
    },
    "http": {
        "name": "HTTP/HTTPS Traffic",
        "description": "Capture web traffic on ports 80, 443, 8080",
        "filter": "port 80 or port 443 or port 8080",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 2,
    },
    "dns": {
        "name": "DNS Traffic",
        "description": "Capture DNS queries and responses",
        "filter": "port 53",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 2,
    },
    "auth": {
        "name": "Authentication Traffic",
        "description": "Capture FTP, Telnet, SSH, RDP, SMB traffic",
        "filter": "port 21 or port 22 or port 23 or port 3389 or port 445",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 3,
    },
    "email": {
        "name": "Email Traffic",
        "description": "Capture SMTP, POP3, IMAP traffic",
        "filter": "port 25 or port 110 or port 143 or port 465 or port 587 or port 993 or port 995",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 3,
    },
    "database": {
        "name": "Database Traffic",
        "description": "Capture MySQL, PostgreSQL, MSSQL, MongoDB traffic",
        "filter": "port 3306 or port 5432 or port 1433 or port 27017",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 3,
    },
    "suspicious": {
        "name": "Suspicious Ports",
        "description": "Capture traffic on commonly exploited ports",
        "filter": "port 4444 or port 5555 or port 6666 or port 1234 or port 31337 or port 8888",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 4,
    },
    "icmp": {
        "name": "ICMP Traffic",
        "description": "Capture ping and ICMP messages",
        "filter": "icmp",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 2,
    },
    "custom": {
        "name": "Custom Filter",
        "description": "Use a custom BPF capture filter",
        "filter": "",
        "timeout": 60,
        "estimated_time": "User defined",
        "intensity": 5,
    },
}


def is_tshark_installed() -> bool:
    """Check if tshark is installed and available."""
    return shutil.which("tshark") is not None


def get_capture_profiles() -> List[Dict[str, Any]]:
    """Get list of available capture profiles."""
    return [
        {
            "id": profile_id,
            "name": profile["name"],
            "description": profile["description"],
            "default_filter": profile["filter"],
            "timeout": profile["timeout"],
            "estimated_time": profile["estimated_time"],
            "intensity": profile["intensity"],
        }
        for profile_id, profile in CAPTURE_PROFILES.items()
    ]


def get_network_interfaces() -> List[Dict[str, str]]:
    """Get list of available network interfaces for capture."""
    if not is_tshark_installed():
        return []
    
    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            if line:
                # Parse format: "1. eth0" or "1. eth0 (Description)"
                parts = line.split(".", 1)
                if len(parts) == 2:
                    iface_info = parts[1].strip()
                    # Extract interface name
                    if " (" in iface_info:
                        name = iface_info.split(" (")[0].strip()
                        desc = iface_info.split(" (")[1].rstrip(")")
                    else:
                        name = iface_info
                        desc = iface_info
                    interfaces.append({"name": name, "description": desc})
        
        return interfaces
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        return []


def validate_capture_filter(filter_expr: str) -> Tuple[bool, str]:
    """
    Validate a BPF capture filter expression.
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not filter_expr:
        return True, ""
    
    if not is_tshark_installed():
        return False, "tshark is not installed"
    
    try:
        # Use tshark to validate the filter
        result = subprocess.run(
            ["tshark", "-f", filter_expr, "-c", "0", "-a", "duration:0"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        
        # Check for filter syntax errors
        if "Invalid capture filter" in result.stderr or "syntax error" in result.stderr.lower():
            return False, f"Invalid capture filter: {result.stderr.strip()}"
        
        return True, ""
    except subprocess.TimeoutExpired:
        return True, ""  # Timeout is OK, filter was likely valid
    except Exception as e:
        return False, str(e)


def run_packet_capture(
    interface: str = "any",
    duration: int = 30,
    packet_count: Optional[int] = None,
    capture_filter: Optional[str] = None,
    profile: str = "all",
) -> Tuple[Optional[Path], Optional[str], Optional[str]]:
    """
    Run a live packet capture using tshark.
    
    Args:
        interface: Network interface to capture on (default: "any")
        duration: Capture duration in seconds (default: 30)
        packet_count: Maximum packets to capture (optional)
        capture_filter: BPF filter expression (optional)
        profile: Capture profile ID (default: "all")
        
    Returns:
        Tuple of (output_pcap_path, command_used, error_message)
    """
    if not is_tshark_installed():
        return None, None, "tshark is not installed on the server"
    
    # Get profile settings
    profile_config = CAPTURE_PROFILES.get(profile, CAPTURE_PROFILES["all"])
    
    # Use profile filter if no custom filter provided
    if capture_filter is None:
        capture_filter = profile_config["filter"]
    
    # Validate filter
    if capture_filter:
        is_valid, error = validate_capture_filter(capture_filter)
        if not is_valid:
            return None, None, error
    
    # Limit duration for safety
    max_duration = 300  # 5 minutes max
    if duration > max_duration:
        duration = max_duration
    
    # Limit packet count
    max_packets = 100000
    if packet_count and packet_count > max_packets:
        packet_count = max_packets
    
    # Create output file
    output_dir = Path(tempfile.mkdtemp(prefix="tshark_capture_"))
    output_file = output_dir / "capture.pcap"
    
    # Build command
    cmd = ["tshark", "-i", interface, "-w", str(output_file)]
    
    # Add duration limit
    cmd.extend(["-a", f"duration:{duration}"])
    
    # Add packet count limit if specified
    if packet_count:
        cmd.extend(["-c", str(packet_count)])
    
    # Add capture filter
    if capture_filter:
        cmd.extend(["-f", capture_filter])
    
    command_str = " ".join(cmd)
    logger.info(f"Starting packet capture: {command_str}")
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 30,  # Add buffer for startup/shutdown
        )
        
        # Log output
        if result.stdout:
            logger.debug(f"tshark stdout: {result.stdout[:500]}")
        if result.stderr:
            # tshark outputs stats to stderr, not necessarily errors
            logger.debug(f"tshark stderr: {result.stderr[:500]}")
        
        # Check for permission errors
        if "permission" in (result.stderr or "").lower():
            return None, command_str, "Permission denied. The server needs root privileges for packet capture."
        
        # Check if file exists and has content
        if not output_file.exists():
            error_msg = result.stderr or result.stdout or "tshark did not produce output"
            return None, command_str, f"Capture failed: {error_msg}"
        
        if output_file.stat().st_size == 0:
            return None, command_str, "No packets captured. Check interface and filter settings."
        
        logger.info(f"Capture completed successfully: {output_file} ({output_file.stat().st_size} bytes)")
        return output_file, command_str, None
        
    except subprocess.TimeoutExpired:
        # This shouldn't happen since tshark has its own duration limit
        if output_file.exists() and output_file.stat().st_size > 0:
            return output_file, command_str, None
        return None, command_str, f"Capture timed out after {duration + 30} seconds"
    except PermissionError:
        return None, command_str, "Permission denied. The server needs root privileges for packet capture."
    except Exception as e:
        logger.error(f"Capture failed: {e}")
        return None, command_str, f"Capture failed: {str(e)}"


def is_pcap_analysis_available() -> bool:
    """Check if PCAP analysis dependencies are available."""
    return SCAPY_AVAILABLE


def analyze_pcap(file_path: Path, max_packets: int = 100000) -> PcapAnalysisResult:
    """
    Analyze a single PCAP file for security issues.
    
    Args:
        file_path: Path to .pcap or .pcapng file
        max_packets: Maximum packets to analyze (for large files)
        
    Returns:
        PcapAnalysisResult with findings and statistics
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy not installed. Run: pip install scapy")
    
    logger.info(f"Loading PCAP file: {file_path}")
    packets = rdpcap(str(file_path), count=max_packets)
    logger.info(f"Loaded {len(packets)} packets")
    
    findings: List[PcapFinding] = []
    protocols: Dict[str, int] = defaultdict(int)
    ip_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    dns_queries: List[str] = []
    http_hosts: List[str] = []
    
    # Track for pattern detection
    syn_packets: Dict[str, set] = defaultdict(set)  # src_ip -> set of dest ports
    
    for i, pkt in enumerate(packets):
        # Count protocols
        proto = _get_protocol(pkt)
        protocols[proto] += 1
        
        # Track IP statistics
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            pkt_len = len(pkt)
            ip_stats[src]["packets"] += 1
            ip_stats[src]["bytes"] += pkt_len
            ip_stats[dst]["packets"] += 1
            ip_stats[dst]["bytes"] += pkt_len
            
            # Track SYN packets for port scan detection
            if TCP in pkt and pkt[TCP].flags == 0x02:  # SYN only
                syn_packets[src].add(pkt[TCP].dport)
        
        # Check for security issues
        pkt_findings = _check_packet_security(pkt, i)
        findings.extend(pkt_findings)
        
        # Extract DNS queries
        if DNS in pkt:
            try:
                if pkt[DNS].qr == 0 and pkt[DNS].qd:  # Query
                    qname = pkt[DNS].qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='ignore')
                    qname = qname.rstrip('.')
                    if qname and qname not in dns_queries:
                        dns_queries.append(qname)
            except Exception:
                pass
        
        # Extract HTTP hosts
        if TCP in pkt and Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)
                if b"Host:" in payload or b"host:" in payload:
                    lines = payload.split(b"\r\n")
                    for line in lines:
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].strip().decode('utf-8', errors='ignore')
                            if host and host not in http_hosts:
                                http_hosts.append(host)
                            break
            except Exception:
                pass
    
    # Detect port scanning
    for src_ip, ports in syn_packets.items():
        if len(ports) > 20:  # More than 20 different ports = likely scan
            findings.append(PcapFinding(
                category="suspicious_traffic",
                severity="high",
                title="Potential Port Scan Detected",
                description=f"Host {src_ip} sent SYN packets to {len(ports)} different ports, indicating possible port scanning activity",
                source_ip=src_ip,
                protocol="TCP",
                evidence=f"Targeted ports include: {', '.join(str(p) for p in sorted(list(ports))[:20])}...",
            ))
    
    # Build top talkers list
    top_talkers = sorted(
        [{"ip": ip, "packets": stats["packets"], "bytes": stats["bytes"]} 
         for ip, stats in ip_stats.items()],
        key=lambda x: x["packets"],
        reverse=True
    )[:10]
    
    # Calculate duration
    duration = _get_capture_duration(packets)
    
    # Build summary
    summary = PcapSummary(
        total_packets=len(packets),
        duration_seconds=round(duration, 2),
        protocols=dict(protocols),
        top_talkers=top_talkers,
        dns_queries=dns_queries[:100],  # Limit to 100
        http_hosts=http_hosts[:100],
        potential_issues=len(findings),
    )
    
    # Extract conversations
    conversations = _extract_conversations(packets)
    
    # Deduplicate findings by title + source_ip + dest_ip
    seen_findings: set = set()
    unique_findings: List[PcapFinding] = []
    for f in findings:
        key = (f.title, f.source_ip, f.dest_ip, f.port)
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)
    
    logger.info(f"Analysis complete: {len(unique_findings)} findings, {len(conversations)} conversations")
    
    return PcapAnalysisResult(
        filename=file_path.name,
        summary=summary,
        findings=unique_findings,
        conversations=conversations,
    )


def _get_protocol(pkt) -> str:
    """Determine the highest-layer protocol."""
    if DNS in pkt:
        return "DNS"
    if TCP in pkt:
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        # Check common ports
        ports = {dport, sport}
        if 80 in ports:
            return "HTTP"
        if 443 in ports:
            return "HTTPS/TLS"
        if 21 in ports:
            return "FTP"
        if 22 in ports:
            return "SSH"
        if 23 in ports:
            return "Telnet"
        if 25 in ports:
            return "SMTP"
        if 110 in ports:
            return "POP3"
        if 143 in ports:
            return "IMAP"
        if 3389 in ports:
            return "RDP"
        if 3306 in ports:
            return "MySQL"
        if 5432 in ports:
            return "PostgreSQL"
        if 1433 in ports:
            return "MSSQL"
        if 6379 in ports:
            return "Redis"
        if 27017 in ports:
            return "MongoDB"
        return "TCP"
    if UDP in pkt:
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport
        ports = {dport, sport}
        if 53 in ports:
            return "DNS"
        if 67 in ports or 68 in ports:
            return "DHCP"
        if 123 in ports:
            return "NTP"
        if 161 in ports or 162 in ports:
            return "SNMP"
        if 500 in ports:
            return "IKE"
        if 1900 in ports:
            return "SSDP"
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    if ARP in pkt:
        return "ARP"
    if IP in pkt:
        return "IP"
    return "Other"


def _check_packet_security(pkt, packet_num: int) -> List[PcapFinding]:
    """Check a packet for security issues."""
    findings: List[PcapFinding] = []
    
    if IP not in pkt:
        return findings
    
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    
    # Check for cleartext credentials and sensitive data
    if Raw in pkt:
        try:
            payload = bytes(pkt[Raw].load)
            payload_lower = payload.lower()
            
            # HTTP Basic Auth
            if b"authorization: basic" in payload_lower:
                findings.append(PcapFinding(
                    category="credential_exposure",
                    severity="critical",
                    title="HTTP Basic Authentication in Cleartext",
                    description="Credentials transmitted via HTTP Basic Auth without TLS encryption. Base64-encoded credentials can be trivially decoded.",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=pkt[TCP].dport if TCP in pkt else None,
                    protocol="HTTP",
                    packet_number=packet_num,
                ))
            
            # HTTP form data with password
            if b"password=" in payload_lower or b"passwd=" in payload_lower or b"pwd=" in payload_lower:
                if TCP in pkt and pkt[TCP].dport == 80:
                    findings.append(PcapFinding(
                        category="credential_exposure",
                        severity="critical",
                        title="Password Submitted Over HTTP",
                        description="Password field detected in HTTP POST data. Credentials transmitted in cleartext.",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=80,
                        protocol="HTTP",
                        packet_number=packet_num,
                    ))
            
            # FTP credentials
            if TCP in pkt:
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport == 21 or sport == 21:
                    if payload_lower.startswith(b"user ") or payload_lower.startswith(b"pass "):
                        findings.append(PcapFinding(
                            category="credential_exposure",
                            severity="critical",
                            title="FTP Credentials in Cleartext",
                            description="FTP username or password transmitted without encryption. FTP is inherently insecure.",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            port=21,
                            protocol="FTP",
                            packet_number=packet_num,
                        ))
            
            # SMTP Auth
            if b"auth login" in payload_lower or b"auth plain" in payload_lower:
                if TCP in pkt and pkt[TCP].dport == 25:
                    findings.append(PcapFinding(
                        category="credential_exposure",
                        severity="critical",
                        title="SMTP Authentication in Cleartext",
                        description="Email credentials transmitted via unencrypted SMTP.",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=25,
                        protocol="SMTP",
                        packet_number=packet_num,
                    ))
            
            # Database connection strings
            db_patterns = [
                (b"mysql://", "MySQL"),
                (b"postgres://", "PostgreSQL"),
                (b"mongodb://", "MongoDB"),
                (b"redis://", "Redis"),
            ]
            for pattern, db_name in db_patterns:
                if pattern in payload_lower:
                    findings.append(PcapFinding(
                        category="credential_exposure",
                        severity="critical",
                        title=f"{db_name} Connection String Exposed",
                        description=f"{db_name} connection string (potentially containing credentials) transmitted in cleartext.",
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        port=pkt[TCP].dport if TCP in pkt else None,
                        protocol="TCP",
                        packet_number=packet_num,
                    ))
            
            # API keys and tokens
            token_patterns = [
                (b"api_key=", "API Key"),
                (b"apikey=", "API Key"),
                (b"api-key:", "API Key"),
                (b"x-api-key:", "API Key"),
                (b"authorization: bearer", "Bearer Token"),
                (b"access_token=", "Access Token"),
                (b"secret_key=", "Secret Key"),
            ]
            for pattern, token_type in token_patterns:
                if pattern in payload_lower:
                    if TCP in pkt and pkt[TCP].dport == 80:  # Only flag if HTTP (not HTTPS)
                        findings.append(PcapFinding(
                            category="credential_exposure",
                            severity="high",
                            title=f"{token_type} Transmitted Over HTTP",
                            description=f"{token_type} detected in unencrypted HTTP traffic.",
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            port=80,
                            protocol="HTTP",
                            packet_number=packet_num,
                        ))
                    break
            
            # Credit card patterns (basic check - 16 digits)
            if _contains_credit_card_pattern(payload):
                findings.append(PcapFinding(
                    category="sensitive_data",
                    severity="critical",
                    title="Potential Credit Card Number Detected",
                    description="Data resembling a credit card number was transmitted in cleartext.",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=pkt[TCP].dport if TCP in pkt else None,
                    protocol=_get_protocol(pkt),
                    packet_number=packet_num,
                ))
            
        except Exception as e:
            logger.debug(f"Error checking packet payload: {e}")
    
    # Check for insecure protocols
    if TCP in pkt:
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        
        # Telnet
        if dport == 23 or sport == 23:
            findings.append(PcapFinding(
                category="cleartext_protocol",
                severity="high",
                title="Telnet Session Detected",
                description="Telnet transmits all data (including credentials) in cleartext. Use SSH instead.",
                source_ip=src_ip,
                dest_ip=dst_ip,
                port=23,
                protocol="Telnet",
                packet_number=packet_num,
            ))
        
        # Unencrypted database connections
        insecure_db_ports = {
            3306: ("MySQL", "MySQL connection without TLS. Database traffic may contain sensitive queries and data."),
            5432: ("PostgreSQL", "PostgreSQL connection without SSL. Consider enabling SSL mode."),
            1433: ("MSSQL", "Microsoft SQL Server connection detected. Ensure encryption is enabled."),
            6379: ("Redis", "Redis connection detected. Redis traffic is unencrypted by default."),
            27017: ("MongoDB", "MongoDB connection detected. Ensure TLS is configured."),
        }
        
        for port, (db_name, desc) in insecure_db_ports.items():
            if dport == port or sport == port:
                findings.append(PcapFinding(
                    category="cleartext_protocol",
                    severity="medium",
                    title=f"Unencrypted {db_name} Connection",
                    description=desc,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    port=port,
                    protocol=db_name,
                    packet_number=packet_num,
                ))
    
    return findings


def _contains_credit_card_pattern(data: bytes) -> bool:
    """Check if data contains a potential credit card number."""
    import re
    try:
        text = data.decode('utf-8', errors='ignore')
        # Look for 16 consecutive digits or groups of 4 digits separated by spaces/dashes
        patterns = [
            r'\b\d{16}\b',
            r'\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b',
        ]
        for pattern in patterns:
            if re.search(pattern, text):
                return True
    except Exception:
        pass
    return False


def _get_capture_duration(packets) -> float:
    """Calculate capture duration in seconds."""
    if len(packets) < 2:
        return 0.0
    try:
        return float(packets[-1].time - packets[0].time)
    except Exception:
        return 0.0


def _extract_conversations(packets, max_convos: int = 50) -> List[Dict[str, Any]]:
    """Extract top TCP/UDP conversations."""
    convos: Dict[tuple, Dict[str, Any]] = {}
    
    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                proto = "TCP"
            else:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                proto = "UDP"
            
            # Normalize conversation key (sort to make bidirectional)
            endpoints = tuple(sorted([(src, sport), (dst, dport)]))
            key = (endpoints, proto)
            
            if key not in convos:
                convos[key] = {
                    "src": endpoints[0][0],
                    "sport": endpoints[0][1],
                    "dst": endpoints[1][0],
                    "dport": endpoints[1][1],
                    "protocol": proto,
                    "service": _guess_service(endpoints[0][1], endpoints[1][1]),
                    "packets": 0,
                    "bytes": 0,
                }
            convos[key]["packets"] += 1
            convos[key]["bytes"] += len(pkt)
    
    # Sort by packets and return top N
    sorted_convos = sorted(convos.values(), key=lambda x: x["packets"], reverse=True)
    return sorted_convos[:max_convos]


def _guess_service(port1: int, port2: int) -> str:
    """Guess the service based on port numbers."""
    services = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
        123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    for port in (port1, port2):
        if port in services:
            return services[port]
    # Assume lower port is the service
    min_port = min(port1, port2)
    if min_port < 1024:
        return f"Port-{min_port}"
    return "Unknown"


@dataclass
class AISecurityReport:
    """Structured AI security assessment report."""
    risk_level: str  # Critical, High, Medium, Low
    risk_score: int  # 0-100
    executive_summary: str
    key_findings: List[Dict[str, str]]  # List of {title, severity, description, recommendation}
    traffic_analysis: Dict[str, Any]  # {patterns, anomalies, protocols_of_concern}
    dns_analysis: Dict[str, Any]  # {suspicious_domains, potential_dga, tunneling_indicators}
    credential_exposure: Dict[str, Any]  # {exposed_credentials, affected_services, risk}
    indicators_of_compromise: List[Dict[str, str]]  # List of {type, value, context, threat_level}
    attack_indicators: Dict[str, Any]  # {reconnaissance, lateral_movement, exfiltration, c2}
    recommendations: List[Dict[str, str]]  # List of {priority, action, rationale}
    timeline_analysis: str  # Temporal patterns
    affected_assets: List[Dict[str, str]]  # List of {ip, role, risk, services}
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


async def analyze_pcap_with_ai(
    analysis_result: PcapAnalysisResult,
) -> Dict[str, Any]:
    """
    Use Gemini to provide AI-powered structured analysis of PCAP findings.
    
    Args:
        analysis_result: The parsed PCAP analysis
        
    Returns:
        Structured AI security report as dictionary
    """
    if not settings.gemini_api_key:
        return {"error": "AI analysis unavailable: GEMINI_API_KEY not configured"}
    
    try:
        from google import genai
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build concise summary for AI (avoid token limits)
        findings_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description} (src: {f.source_ip}, dst: {f.dest_ip}, port: {f.port})"
            for f in analysis_result.findings[:30]
        )
        
        dns_sample = analysis_result.summary.dns_queries[:100]
        http_sample = analysis_result.summary.http_hosts[:50]
        
        prompt = f"""You are an expert network forensics analyst writing a professional security incident report. Your task is to analyze this packet capture and write a comprehensive, detailed report in clear, professional English that explains EXACTLY what is happening in the network traffic.

## PACKET CAPTURE DATA FOR ANALYSIS

### Capture Overview
- **File**: {analysis_result.filename}
- **Total Packets Captured**: {analysis_result.summary.total_packets:,}
- **Capture Duration**: {analysis_result.summary.duration_seconds:.1f} seconds
- **Packets Per Second**: {analysis_result.summary.total_packets / max(analysis_result.summary.duration_seconds, 1):.1f}
- **Automated Security Findings**: {len(analysis_result.findings)}

### Protocol Breakdown
{json.dumps(analysis_result.summary.protocols, indent=2)}

### Top Network Hosts (by traffic volume)
{json.dumps(analysis_result.summary.top_talkers[:15], indent=2)}

### DNS Queries Made ({len(analysis_result.summary.dns_queries)} total unique domains)
{json.dumps(dns_sample, indent=2)}

### HTTP/Web Hosts Contacted ({len(analysis_result.summary.http_hosts)} unique hosts)
{json.dumps(http_sample, indent=2)}

### Security Scanner Findings
{findings_text if findings_text else "No critical security issues detected by automated scanners."}

### Network Conversations (communication pairs)
{json.dumps(analysis_result.conversations[:20], indent=2)}
```json
{json.dumps(analysis_result.conversations[:15], indent=2)}
```

---

## YOUR TASK

Write a comprehensive incident response report that answers these questions in DETAILED, PROFESSIONAL ENGLISH:

1. **What type of network activity is captured?** (Normal browsing, server communications, potential attack, malware traffic, etc.)
2. **Who is communicating with whom?** (Identify all hosts, their apparent roles, and relationships)
3. **What exactly happened during this capture?** (Step-by-step narrative of events)
4. **Are there any security concerns?** (Explain each concern in plain language)
5. **What should be done next?** (Specific, actionable recommendations)

---

## REQUIRED OUTPUT FORMAT

You MUST respond with a valid JSON object. Write all text fields as if you're writing a professional security report - use complete sentences, clear explanations, and proper English. Avoid jargon without explanation.

{{
  "risk_level": "Critical|High|Medium|Low",
  "risk_score": <0-100>,
  
  "executive_summary": "<WRITE 3-4 DETAILED PARAGRAPHS explaining what this packet capture shows. Start with an overview of what was captured, then describe the main activities observed, highlight any security concerns, and conclude with your assessment. Write this as if briefing a security manager who needs to understand what happened.>",
  
  "what_happened": {{
    "narrative": "<WRITE A DETAILED STORY (4-6 paragraphs) of exactly what happened in this network capture, in chronological order. Describe the sequence of events as if you're telling a story: 'The capture begins with host X establishing a connection to server Y. This appears to be a normal HTTPS handshake... Then we observe DNS queries for domains A, B, and C... Meanwhile, another host Z is generating significant traffic to...' Make this readable and engaging.>",
    "timeline": [
      {{
        "timestamp_range": "<start - end time>",
        "description": "<What happened during this period in clear English>",
        "hosts_involved": ["<ip1>", "<ip2>"],
        "significance": "<Why this matters from a security perspective>"
      }}
    ],
    "communication_flow": "<Describe the overall flow of communications. Who initiated connections to whom? What was the pattern? Were there any unusual communication patterns like a workstation making hundreds of outbound connections, or traffic flowing in unexpected directions?>"
  }},
  
  "key_findings": [
    {{
      "title": "<Clear, descriptive title>",
      "severity": "Critical|High|Medium|Low|Info",
      "what_we_found": "<WRITE 2-3 PARAGRAPHS explaining this finding in detail. What exactly was observed? Use specific examples from the packet data. Explain why this is significant. Write as if explaining to someone who needs to understand the full context.>",
      "technical_evidence": "<List the specific technical evidence: packet numbers, IP addresses, ports, protocol details, payload snippets, timestamps>",
      "potential_impact": "<Explain in plain English what could happen if this is malicious or not addressed>",
      "recommended_action": "<Specific steps to investigate further or remediate this finding>"
    }}
  ],
  
  "traffic_analysis": {{
    "narrative_summary": "<WRITE 2-3 PARAGRAPHS describing the traffic patterns observed. What types of traffic dominated the capture? Was the traffic pattern consistent or did it change over time? Were there any anomalies in volume, timing, or protocol distribution?>",
    "overall_assessment": "<One paragraph assessment: Is this traffic normal for a typical network? What stands out?>",
    "protocol_breakdown_explained": "<Explain what each major protocol's presence means. For example: 'The high volume of DNS traffic (45%) suggests either active browsing or potentially DNS-based tunneling. The HTTPS traffic (35%) to well-known services like google.com and microsoft.com appears normal...'  >",
    "suspicious_patterns": [
      {{
        "pattern_name": "<Name of the pattern>",
        "description": "<DETAILED explanation of what this pattern is and why it's suspicious>",
        "evidence": "<Specific packets/IPs/ports that demonstrate this pattern>",
        "severity": "Critical|High|Medium|Low"
      }}
    ],
    "data_flow_analysis": "<Analyze the direction and volume of data. Is more data leaving the network than entering? Are there any large transfers to unexpected destinations? Explain what this means.>",
    "encryption_assessment": "<What percentage of traffic is encrypted vs cleartext? Is sensitive data being transmitted without encryption? Explain the implications.>"
  }},
  
  "hosts_analysis": [
    {{
      "ip_address": "<IP>",
      "likely_role": "<Client workstation|Server|Router/Gateway|External service|Unknown>",
      "hostname": "<hostname if identified from DNS>",
      "behavior_summary": "<WRITE 2-3 SENTENCES describing what this host was doing. 'This host appears to be a user workstation that was actively browsing the internet, making connections to social media sites and streaming services...' or 'This server was receiving connections from multiple internal hosts, suggesting it may be a file or application server...'>",
      "services_identified": ["<service1>", "<service2>"],
      "connections_made": <number>,
      "data_transferred": "<volume>",
      "risk_assessment": "<Is this host's behavior concerning? Explain why or why not>",
      "concerns": ["<Specific concern 1>", "<Specific concern 2>"]
    }}
  ],
  
  "dns_analysis": {{
    "narrative_summary": "<WRITE 2-3 PARAGRAPHS about the DNS activity. What domains were being looked up? Do they appear legitimate? Any signs of DNS tunneling, DGA domains, or suspicious lookups?>",
    "overall_assessment": "<One paragraph: Is the DNS activity normal? What stands out?>",
    "suspicious_domains": [
      {{
        "domain": "<domain name>",
        "why_suspicious": "<DETAILED explanation of why this domain is concerning - is it a known bad domain? Does it look algorithmically generated? Is it an unusual TLD? Explain your reasoning.>",
        "threat_category": "<malware|phishing|c2|dga|tunneling|typosquatting|unknown>",
        "recommended_action": "<What to do about this domain - block it? Investigate hosts that queried it?>"
      }}
    ],
    "legitimate_activity": "<List the clearly legitimate DNS activity observed (google.com, microsoft.com, etc.) to establish baseline of normal behavior>",
    "dga_analysis": "<Explain if there are any signs of Domain Generation Algorithm (DGA) domains - randomly generated domain names often used by malware>",
    "tunneling_analysis": "<Explain if there are any signs of DNS tunneling - unusually long DNS queries, high query volumes, or encoded data in DNS fields>"
  }},
  
  "credential_exposure": {{
    "severity": "Critical|High|Medium|Low|None",
    "narrative_summary": "<WRITE 1-2 PARAGRAPHS explaining any credential exposure found. If credentials were transmitted in cleartext, explain exactly what was exposed, how it was exposed, and the implications. If no credentials were exposed, explain what protocols were checked and confirm they were secure.>",
    "exposed_credentials": [
      {{
        "credential_type": "<HTTP Basic Auth|FTP password|Database credentials|API Key|Session token|etc>",
        "exposure_method": "<How was this credential exposed - cleartext HTTP, unencrypted protocol, etc>",
        "affected_service": "<What service or application was this for>",
        "source_host": "<IP of the host that sent the credential>",
        "destination": "<Where the credential was sent>",
        "risk_explanation": "<Explain in plain English what an attacker could do with this credential>",
        "immediate_action_required": "<Specific steps to take RIGHT NOW - change password, revoke token, etc>"
      }}
    ],
    "secure_practices_observed": "<Note any good practices observed - use of HTTPS, encrypted protocols, etc>"
  }},
  
  "indicators_of_compromise": [
    {{
      "ioc_type": "IP Address|Domain|URL|File Hash|Behavioral Pattern",
      "ioc_value": "<the actual IOC>",
      "context_explanation": "<EXPLAIN in detail where and how this IOC was observed in the traffic. What makes it an indicator of compromise?>",
      "threat_association": "<Is this IOC associated with known threats? What type of threat?>",
      "threat_level": "Critical|High|Medium|Low",
      "recommended_response": "<What should be done - block at firewall, investigate host, alert SOC, etc>"
    }}
  ],
  
  "attack_indicators": {{
    "overall_assessment": "<WRITE 1-2 PARAGRAPHS: Is there evidence of an active attack or compromise? Summarize your analysis of attack indicators.>",
    "reconnaissance": {{
      "detected": true|false,
      "explanation": "<If detected, EXPLAIN what reconnaissance activity was observed - port scanning, network mapping, service enumeration, etc. If not detected, briefly state why you don't believe recon was occurring.>",
      "evidence": "<Specific evidence - source IPs, scan patterns, ports probed>",
      "attacker_interest": "<What appears to be the attacker's goal - mapping the network, finding vulnerable services, identifying targets?>"
    }},
    "lateral_movement": {{
      "detected": true|false,
      "explanation": "<If detected, EXPLAIN the lateral movement - how is the attacker moving between systems? What protocols are being used? If not detected, explain why.>",
      "evidence": "<Specific evidence>",
      "affected_systems": ["<system1>", "<system2>"],
      "movement_pattern": "<Describe the movement pattern if detected>"
    }},
    "data_exfiltration": {{
      "detected": true|false,
      "explanation": "<If detected, EXPLAIN the exfiltration - what data appears to be leaving? How is it being extracted? To where? If not detected, explain why.>",
      "evidence": "<Specific evidence>",
      "estimated_data_volume": "<If detected, estimate how much data may have been exfiltrated>",
      "exfiltration_method": "<The technique being used - HTTPS to external server, DNS tunneling, etc>"
    }},
    "command_and_control": {{
      "detected": true|false,
      "explanation": "<If detected, EXPLAIN the C2 activity - what patterns indicate C2? Beaconing intervals? Known C2 infrastructure? If not detected, explain why.>",
      "evidence": "<Specific evidence>",
      "c2_infrastructure": ["<suspected C2 endpoints>"],
      "communication_pattern": "<Describe the C2 communication pattern if detected>"
    }}
  }},
  
  "recommendations": [
    {{
      "priority": "Immediate|High|Medium|Low",
      "title": "<Clear action title>",
      "detailed_action": "<WRITE 2-3 SENTENCES with specific, actionable steps. Don't say 'improve security' - say exactly what to do: 'Configure firewall rule X to block traffic to IP Y. Then investigate host Z for potential compromise by checking logs from timestamp A to B.'>",
      "rationale": "<Explain WHY this recommendation is important based on what was found in the capture>",
      "expected_outcome": "<What will this action achieve?>",
      "effort_level": "Low|Medium|High",
      "responsible_team": "Network Operations|Security Operations|IT Support|Management"
    }}
  ],
  
  "conclusion": "<WRITE 2-3 PARAGRAPHS summarizing your analysis. Restate the main findings, overall risk assessment, and most important next steps. End with a clear statement about the security posture revealed by this capture.>"
}}

---

## CRITICAL WRITING GUIDELINES

1. **WRITE IN COMPLETE, PROFESSIONAL ENGLISH**: Every description should be written as if you're preparing a formal incident report. Use full sentences, proper grammar, and clear explanations.

2. **EXPLAIN TECHNICAL CONCEPTS**: When you mention technical terms (DNS tunneling, C2, DGA, etc.), briefly explain what they mean and why they matter.

3. **BE SPECIFIC WITH EVIDENCE**: Always cite specific evidence from the packet data - IP addresses, port numbers, timestamps, packet counts. Don't make vague claims.

4. **TELL THE STORY**: The "what_happened" section should read like a narrative - what happened first, then what, then what. Help the reader understand the sequence of events.

5. **AVOID FALSE POSITIVES**: Don't flag normal traffic as suspicious. If the capture shows routine web browsing and email, say so. Only raise alerts for genuinely concerning activity.

6. **BE ACTIONABLE**: Every finding should lead to a clear action. Don't just say "this is suspicious" - say what to do about it.

7. **CONSIDER CONTEXT**: Internal traffic behaves differently than external. Development environments differ from production. Consider what might be normal for this network.

8. **PROVIDE BALANCED ASSESSMENT**: Note both concerning AND normal/healthy behaviors. This helps establish credibility and context.

9. **QUANTIFY WHEN POSSIBLE**: Use numbers - "23 hosts", "847 DNS queries", "15MB of outbound traffic" rather than "many", "lots", or "significant".

10. **WRITE FOR THE AUDIENCE**: The executive summary is for managers. Technical details are for analysts. Make sure each section is appropriate for its audience.

Return ONLY valid JSON - no markdown code blocks, no explanations outside the JSON structure."""

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
        response_text = response.text.strip()
        
        # Clean up response - remove markdown code blocks if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()
        
        # Parse JSON response
        try:
            report = json.loads(response_text)
            return {"structured_report": report}
        except json.JSONDecodeError as je:
            logger.error(f"Failed to parse AI response as JSON: {je}")
            # Return the raw text as fallback
            return {
                "raw_analysis": response_text,
                "parse_error": f"Failed to parse structured report: {str(je)}"
            }
        
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return {"error": f"AI analysis failed: {str(e)}"}
