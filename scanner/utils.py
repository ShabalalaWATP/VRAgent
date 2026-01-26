"""
Scanner Sidecar Utilities
Helper functions for parsing scan outputs and validation.
"""

import re
import ipaddress
from typing import Tuple, Optional, List
import xml.etree.ElementTree as ET


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate scan target (IP, CIDR, hostname).
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Strip whitespace
    target = target.strip()
    
    if not target:
        return False, "Target cannot be empty"
    
    # Block dangerous patterns
    dangerous_patterns = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
    for pattern in dangerous_patterns:
        if pattern in target:
            return False, f"Invalid character in target: {pattern}"
    
    # Try parsing as IP address
    try:
        ipaddress.ip_address(target)
        return True, ""
    except ValueError:
        pass
    
    # Try parsing as CIDR range
    try:
        network = ipaddress.ip_network(target, strict=False)
        # Limit scan range size
        if network.num_addresses > 65536:  # /16 max
            return False, "Network range too large. Maximum /16 (65536 hosts)"
        return True, ""
    except ValueError:
        pass
    
    # Hostname validation
    if len(target) > 255:
        return False, "Hostname too long (max 255 characters)"
    
    # Basic hostname pattern
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    if not re.match(hostname_pattern, target):
        return False, "Invalid hostname format"
    
    return True, ""


def validate_ports(ports: Optional[str]) -> Tuple[bool, str]:
    """Validate port specification and ensure ranges/values are sane."""
    if not ports:
        return True, ""

    entries = [entry.strip() for entry in ports.split(",") if entry.strip()]
    if not entries:
        return False, "Port specification cannot be empty"

    seen_ranges = []
    for entry in entries:
        if "-" in entry:
            parts = entry.split("-", 1)
            if len(parts) != 2:
                return False, f"Invalid port range: {entry}"
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                return False, f"Non-numeric port range: {entry}"
            if start <= 0 or end <= 0 or start > 65535 or end > 65535:
                return False, "Ports must be between 1 and 65535"
            if start > end:
                return False, f"Port range start must be <= end in '{entry}'"
            seen_ranges.append((start, end))
        else:
            try:
                port = int(entry)
            except ValueError:
                return False, f"Non-numeric port: {entry}"
            if port <= 0 or port > 65535:
                return False, "Ports must be between 1 and 65535"
            seen_ranges.append((port, port))

    # Check for overlapping ranges that could indicate misuse
    seen_ranges.sort()
    last_end = -1
    for start, end in seen_ranges:
        if start <= last_end:
            return False, f"Overlapping or duplicated ports detected around {start}-{end}"
        last_end = end
    return True, ""


def parse_nmap_xml(xml_content: str) -> dict:
    """Parse Nmap XML output into structured data."""
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        return {"error": f"Failed to parse XML: {e}"}
    
    result = {
        "hosts": [],
        "scan_info": {},
        "stats": {
            "total_hosts": 0,
            "up_hosts": 0,
            "total_ports": 0,
            "open_ports": 0,
        }
    }
    
    # Parse scan info
    scaninfo = root.find(".//scaninfo")
    if scaninfo is not None:
        result["scan_info"] = {
            "type": scaninfo.get("type", ""),
            "protocol": scaninfo.get("protocol", ""),
            "services": scaninfo.get("services", ""),
        }
    
    # Parse hosts
    for host in root.findall(".//host"):
        host_data = {
            "ip": "",
            "hostname": "",
            "state": "unknown",
            "os": "",
            "ports": [],
        }
        
        # Get IP address
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        if address is not None:
            host_data["ip"] = address.get("addr", "")
        
        # Get hostname
        hostname = host.find(".//hostname")
        if hostname is not None:
            host_data["hostname"] = hostname.get("name", "")
        
        # Get host state
        status = host.find("status")
        if status is not None:
            host_data["state"] = status.get("state", "unknown")
        
        # Get OS detection
        osmatch = host.find(".//osmatch")
        if osmatch is not None:
            host_data["os"] = osmatch.get("name", "")
        
        # Get ports
        for port in host.findall(".//port"):
            port_data = {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": "unknown",
                "service": "",
                "version": "",
                "product": "",
                "scripts": [],
            }
            
            state = port.find("state")
            if state is not None:
                port_data["state"] = state.get("state", "unknown")
            
            service = port.find("service")
            if service is not None:
                port_data["service"] = service.get("name", "")
                port_data["product"] = service.get("product", "")
                port_data["version"] = service.get("version", "")
            
            # Get script output
            for script in port.findall(".//script"):
                port_data["scripts"].append({
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                })
            
            if port_data["state"] == "open":
                result["stats"]["open_ports"] += 1
            
            result["stats"]["total_ports"] += 1
            host_data["ports"].append(port_data)
        
        result["stats"]["total_hosts"] += 1
        if host_data["state"] == "up":
            result["stats"]["up_hosts"] += 1
        
        result["hosts"].append(host_data)
    
    return result


def parse_nuclei_jsonl(jsonl_content: str) -> List[dict]:
    """Parse Nuclei JSONL output into structured findings."""
    import json
    
    findings = []
    for line in jsonl_content.strip().split('\n'):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
            findings.append({
                "template_id": finding.get("template-id", ""),
                "template_name": finding.get("info", {}).get("name", ""),
                "severity": finding.get("info", {}).get("severity", "unknown"),
                "host": finding.get("host", ""),
                "matched_at": finding.get("matched-at", ""),
                "type": finding.get("type", ""),
                "ip": finding.get("ip", ""),
                "port": finding.get("port", ""),
                "protocol": finding.get("protocol", ""),
                "description": finding.get("info", {}).get("description", ""),
                "reference": finding.get("info", {}).get("reference", []),
                "cve_id": finding.get("info", {}).get("classification", {}).get("cve-id", []),
                "cvss_score": finding.get("info", {}).get("classification", {}).get("cvss-score", 0),
                "extracted_results": finding.get("extracted-results", []),
                "matcher_name": finding.get("matcher-name", ""),
                "curl_command": finding.get("curl-command", ""),
            })
        except json.JSONDecodeError:
            continue
    
    return findings


# Service classification for AI routing
WEB_SERVICES = {
    80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443,
    # Common web app ports
    4443, 8081, 8082, 8090, 8181, 8888, 9090, 9091,
}

NETWORK_CVE_SERVICES = {
    # SSH
    22,
    # SMB/CIFS
    139, 445,
    # RDP
    3389,
    # Databases
    3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200,
    # FTP
    21,
    # SMTP
    25, 465, 587,
    # LDAP
    389, 636,
    # Kerberos
    88,
    # SNMP
    161, 162,
    # VNC
    5900, 5901,
    # Telnet
    23,
    # NFS
    111, 2049,
}


def classify_service(port: int, service_name: str = "") -> str:
    """
    Classify a service for routing to appropriate scanner.
    
    Returns:
        "web" - Route to ZAP
        "network" - Route to Nuclei CVE templates
        "both" - Route to both
        "skip" - Low priority, skip detailed scanning
    """
    service_lower = service_name.lower()
    
    # Explicit web service names
    if any(web in service_lower for web in ['http', 'https', 'web', 'nginx', 'apache', 'tomcat', 'iis']):
        return "web"
    
    # Check port numbers
    if port in WEB_SERVICES:
        return "web"
    
    if port in NETWORK_CVE_SERVICES:
        return "network"
    
    # High ports with unknown service - likely web
    if port > 1024 and service_name in ['', 'unknown', 'tcpwrapped']:
        return "web"  # Probe as web first
    
    return "network"


def get_nuclei_tags_for_service(port: int, service_name: str = "") -> List[str]:
    """Get appropriate Nuclei template tags for a service."""
    service_lower = service_name.lower()
    tags = ["cve", "network"]
    
    if port == 22 or "ssh" in service_lower:
        tags.extend(["ssh", "openssh"])
    elif port in [139, 445] or "smb" in service_lower or "microsoft-ds" in service_lower:
        tags.extend(["smb", "samba", "eternalblue", "ms17-010"])
    elif port == 3389 or "rdp" in service_lower or "ms-wbt-server" in service_lower:
        tags.extend(["rdp", "bluekeep"])
    elif port == 3306 or "mysql" in service_lower:
        tags.extend(["mysql", "mariadb"])
    elif port == 5432 or "postgres" in service_lower:
        tags.extend(["postgres", "postgresql"])
    elif port == 1433 or "mssql" in service_lower:
        tags.extend(["mssql", "sqlserver"])
    elif port == 21 or "ftp" in service_lower:
        tags.extend(["ftp", "vsftpd", "proftpd"])
    elif port == 6379 or "redis" in service_lower:
        tags.extend(["redis"])
    elif port == 27017 or "mongo" in service_lower:
        tags.extend(["mongodb"])
    elif port in [161, 162] or "snmp" in service_lower:
        tags.extend(["snmp"])
    elif port in [5900, 5901] or "vnc" in service_lower:
        tags.extend(["vnc"])
    elif port == 23 or "telnet" in service_lower:
        tags.extend(["telnet"])
    elif port in [389, 636] or "ldap" in service_lower:
        tags.extend(["ldap"])
    
    return tags
