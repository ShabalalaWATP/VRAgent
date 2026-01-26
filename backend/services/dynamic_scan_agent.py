"""
Dynamic Scan AI Agent

AI-powered agent that orchestrates an intelligent pentesting workflow:

1. **Reconnaissance Phase**: Nmap discovers hosts and open ports
2. **Analysis Phase**: AI analyzes services and decides which tools to use
3. **Vulnerability Scanning**: 
   - OpenVAS for network service vulnerabilities
   - OWASP ZAP for web application vulnerabilities
   - Nuclei for CVE detection
4. **Exploit Research**: Searches Exploit-DB for available exploits
5. **AI Analysis**: Generates attack narratives and exploitation guidance

The agent makes intelligent decisions about:
- Which targets to scan with which tools
- How deep to scan based on risk indicators
- Which exploits are most likely to succeed
- Attack paths and lateral movement opportunities
"""

import json
import logging
from typing import Dict, Any, List, Optional
from dataclasses import asdict
from enum import Enum

logger = logging.getLogger(__name__)


# Try importing Gemini
try:
    from google import genai
    from google.genai import types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    logger.warning("Google Generative AI not available")


class ScanTool(str, Enum):
    """Available scanning tools."""
    NMAP = "nmap"
    OPENVAS = "openvas"
    ZAP = "zap"
    NUCLEI = "nuclei"


# =============================================================================
# COMPREHENSIVE TOOL OPTIONS FOR AI-LED SCANNING
# =============================================================================

# Nmap Scan Types - AI can select the most appropriate
NMAP_SCAN_TYPES = {
    "ping": {
        "description": "Host discovery only - no port scanning. Fastest option.",
        "use_case": "Quick check if hosts are alive, large network ranges",
        "time": "5-30 seconds",
        "stealth": "high",
    },
    "quick": {
        "description": "Top 100 ports, no service detection",
        "use_case": "Fast overview of common services",
        "time": "30-60 seconds",
        "stealth": "medium",
    },
    "basic": {
        "description": "Top 1000 ports with service detection",
        "use_case": "Good balance of speed and coverage",
        "time": "3-10 minutes",
        "stealth": "medium",
    },
    "service": {
        "description": "Service/version detection on top 1000 ports",
        "use_case": "Recommended default - identifies service versions for CVE matching",
        "time": "5-15 minutes",
        "stealth": "medium",
    },
    "version": {
        "description": "Intense version detection with higher accuracy",
        "use_case": "When exact version info is critical for exploit matching",
        "time": "10-20 minutes",
        "stealth": "low",
    },
    "stealth": {
        "description": "SYN scan - half-open connections, less logging",
        "use_case": "When trying to avoid IDS/IPS detection",
        "time": "3-10 minutes",
        "stealth": "high",
    },
    "script": {
        "description": "Default NSE scripts for vulnerability detection",
        "use_case": "Active vulnerability detection for common services",
        "time": "10-30 minutes",
        "stealth": "low",
    },
    "vuln": {
        "description": "Run vulnerability detection scripts specifically",
        "use_case": "Direct vulnerability scanning when speed isn't critical",
        "time": "15-45 minutes",
        "stealth": "very_low",
    },
    "aggressive": {
        "description": "OS detection + version + scripts + traceroute",
        "use_case": "Maximum info gathering, doesn't care about stealth",
        "time": "15-30 minutes",
        "stealth": "very_low",
    },
    "os_detect": {
        "description": "Operating system fingerprinting",
        "use_case": "When OS identification is important for exploit selection",
        "time": "5-15 minutes",
        "stealth": "medium",
    },
    "udp_quick": {
        "description": "Top 20 UDP ports (DNS, SNMP, TFTP, etc)",
        "use_case": "Quick check for common UDP services",
        "time": "2-5 minutes",
        "stealth": "medium",
    },
    "udp": {
        "description": "Top 100 UDP ports - comprehensive",
        "use_case": "Full UDP service discovery",
        "time": "10-30 minutes",
        "stealth": "medium",
    },
    "comprehensive": {
        "description": "TCP + UDP + OS + scripts + traceroute",
        "use_case": "Maximum coverage, internal network assessments",
        "time": "30-60 minutes",
        "stealth": "very_low",
    },
    "full_tcp": {
        "description": "All 65535 TCP ports with service detection",
        "use_case": "When you need to find services on non-standard ports",
        "time": "30-120 minutes",
        "stealth": "very_low",
    },
}

# Nmap NSE Script Categories - AI can select which to run
NMAP_NSE_SCRIPTS = {
    "vuln": {
        "description": "Vulnerability detection scripts",
        "scripts": ["vuln", "vulners"],
        "use_case": "Direct CVE/vulnerability scanning",
    },
    "auth": {
        "description": "Authentication bypass and credential checks",
        "scripts": ["auth"],
        "use_case": "Check for default/weak credentials, auth bypass",
    },
    "brute": {
        "description": "Brute force credential attacks",
        "scripts": ["brute"],
        "use_case": "Test for weak passwords on services (SSH, FTP, etc)",
    },
    "discovery": {
        "description": "Service and host discovery scripts",
        "scripts": ["discovery"],
        "use_case": "Enumerate users, shares, databases, etc",
    },
    "exploit": {
        "description": "Active exploitation scripts",
        "scripts": ["exploit"],
        "use_case": "Attempt to exploit known vulnerabilities",
    },
    "smb": {
        "description": "SMB/Windows file sharing enumeration",
        "scripts": ["smb-enum-shares", "smb-enum-users", "smb-os-discovery", "smb-vuln-*"],
        "use_case": "Windows network enumeration, EternalBlue check",
    },
    "http": {
        "description": "Web server enumeration",
        "scripts": ["http-enum", "http-headers", "http-methods", "http-vuln-*", "http-title"],
        "use_case": "Web application reconnaissance",
    },
    "ssl": {
        "description": "SSL/TLS analysis",
        "scripts": ["ssl-cert", "ssl-enum-ciphers", "ssl-heartbleed", "ssl-poodle"],
        "use_case": "Check for weak SSL/TLS configurations",
    },
    "dns": {
        "description": "DNS enumeration",
        "scripts": ["dns-zone-transfer", "dns-brute", "dns-srv-enum"],
        "use_case": "DNS reconnaissance and zone transfer checks",
    },
    "ftp": {
        "description": "FTP analysis",
        "scripts": ["ftp-anon", "ftp-bounce", "ftp-brute", "ftp-vsftpd-backdoor"],
        "use_case": "FTP enumeration and vulnerability checks",
    },
    "ssh": {
        "description": "SSH analysis",
        "scripts": ["ssh-auth-methods", "ssh-brute", "ssh2-enum-algos"],
        "use_case": "SSH configuration and security analysis",
    },
    "database": {
        "description": "Database enumeration",
        "scripts": ["mysql-*", "pgsql-brute", "mongodb-*", "redis-*", "ms-sql-*"],
        "use_case": "Database discovery and security assessment",
    },
    "safe": {
        "description": "Non-intrusive scripts only",
        "scripts": ["safe"],
        "use_case": "When minimal impact is required",
    },
}

# Advanced Nmap Options - AI can request these for specific scenarios
NMAP_ADVANCED_OPTIONS = {
    "version_intensity": {
        "description": "Service version detection intensity (0-9)",
        "values": ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        "default": "7",
        "use_case": "Higher = more probes, slower but more accurate version detection",
    },
    "max_retries": {
        "description": "Maximum number of port scan probe retransmissions",
        "values": ["1", "2", "3", "5", "10"],
        "default": "3",
        "use_case": "Lower for fast scans, higher for unreliable networks",
    },
    "host_timeout": {
        "description": "Maximum time to spend on a single host",
        "values": ["5m", "15m", "30m", "60m"],
        "default": "30m",
        "use_case": "Limit time per host for large network scans",
    },
    "scan_delay": {
        "description": "Minimum delay between probes",
        "values": ["0", "100ms", "500ms", "1s", "5s"],
        "default": "0",
        "use_case": "Rate limiting to avoid detection/overload",
    },
    "min_rate": {
        "description": "Minimum packets per second",
        "values": ["10", "50", "100", "500", "1000"],
        "default": "100",
        "use_case": "Ensure minimum scan speed",
    },
    "max_rate": {
        "description": "Maximum packets per second",
        "values": ["100", "500", "1000", "5000", "10000"],
        "default": "1000",
        "use_case": "Limit scan speed for stealth/network preservation",
    },
    "fragmentation": {
        "description": "Fragment packets for firewall evasion",
        "values": ["-f", "-ff", "--mtu 8", "--mtu 16", "--mtu 24"],
        "default": None,
        "use_case": "Bypass simple packet filters",
    },
    "source_port": {
        "description": "Spoof source port",
        "values": ["53", "80", "443", "88"],
        "default": None,
        "use_case": "Bypass firewalls that allow specific source ports (DNS/HTTP)",
    },
    "decoy": {
        "description": "Use decoy IP addresses",
        "values": ["RND:5", "RND:10", "ME"],
        "default": None,
        "use_case": "Hide real scanner among decoys (IDS evasion)",
    },
    "spoof_mac": {
        "description": "Spoof MAC address",
        "values": ["0", "Apple", "Dell", "Cisco", "random"],
        "default": None,
        "use_case": "MAC address spoofing for LAN scans",
    },
    "ipv6": {
        "description": "Enable IPv6 scanning",
        "flag": "-6",
        "use_case": "Scan IPv6 targets",
    },
    "reason": {
        "description": "Display reason for port state",
        "flag": "--reason",
        "use_case": "Debugging/understanding why ports are filtered",
    },
    "traceroute": {
        "description": "Trace hop path to each host",
        "flag": "--traceroute",
        "use_case": "Network topology mapping",
    },
    "osscan_guess": {
        "description": "Guess OS more aggressively",
        "flag": "--osscan-guess",
        "use_case": "When OS detection fails with normal settings",
    },
}

# ZAP Scan Policies - AI can select attack intensity
ZAP_SCAN_POLICIES = {
    "light": {
        "description": "Quick passive + light active scan",
        "attack_strength": "LOW",
        "alert_threshold": "MEDIUM",
        "use_case": "Fast overview, production systems",
        "time": "5-15 minutes",
    },
    "standard": {
        "description": "Balanced active scanning",
        "attack_strength": "MEDIUM",
        "alert_threshold": "MEDIUM",
        "use_case": "Standard web app assessment",
        "time": "15-45 minutes",
    },
    "thorough": {
        "description": "Comprehensive active scanning",
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
        "use_case": "Full security assessment, test environments",
        "time": "45-120 minutes",
    },
    "maximum": {
        "description": "Maximum attack intensity",
        "attack_strength": "INSANE",
        "alert_threshold": "LOW",
        "use_case": "Test/lab environments only - very aggressive",
        "time": "2-4 hours",
    },
    "api_focused": {
        "description": "Optimized for REST/GraphQL APIs",
        "attack_strength": "MEDIUM",
        "alert_threshold": "LOW",
        "use_case": "API security testing",
        "time": "20-60 minutes",
    },
    "sqli_focused": {
        "description": "Focus on SQL injection testing",
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
        "use_case": "When SQL injection is primary concern",
        "time": "30-90 minutes",
    },
    "xss_focused": {
        "description": "Focus on XSS testing",
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
        "use_case": "When XSS is primary concern",
        "time": "30-90 minutes",
    },
    "auth_bypass": {
        "description": "Focus on authentication/authorization bypass",
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
        "use_case": "When auth mechanisms need testing",
        "time": "30-60 minutes",
    },
    "ssrf_focused": {
        "description": "Focus on SSRF vulnerabilities",
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
        "use_case": "Cloud/microservice environments",
        "time": "20-45 minutes",
    },
}

# ZAP Attack Vectors - Specific scanner categories AI can enable/disable
ZAP_ATTACK_VECTORS = {
    "injection": {
        "description": "SQL, NoSQL, LDAP, OS command injection",
        "scanner_ids": [40018, 40019, 40020, 40021, 40022, 90019],
        "risk": "critical",
        "use_case": "Databases, user input handling",
    },
    "xss": {
        "description": "Reflected, stored, DOM-based XSS",
        "scanner_ids": [40012, 40014, 40016, 40017],
        "risk": "high",
        "use_case": "User-generated content, forms",
    },
    "path_traversal": {
        "description": "Directory traversal, LFI, RFI",
        "scanner_ids": [6, 7, 43],
        "risk": "high",
        "use_case": "File operations, includes",
    },
    "ssrf": {
        "description": "Server-side request forgery",
        "scanner_ids": [40046],
        "risk": "critical",
        "use_case": "URL parameters, webhooks",
    },
    "xxe": {
        "description": "XML external entity injection",
        "scanner_ids": [90023],
        "risk": "critical",
        "use_case": "XML parsers, SOAP services",
    },
    "ssti": {
        "description": "Server-side template injection",
        "scanner_ids": [90035],
        "risk": "critical",
        "use_case": "Template engines (Jinja, Twig, etc)",
    },
    "csrf": {
        "description": "Cross-site request forgery",
        "scanner_ids": [20012],
        "risk": "medium",
        "use_case": "State-changing operations",
    },
    "authentication": {
        "description": "Weak auth, session fixation, brute force",
        "scanner_ids": [10011, 10023, 10054, 10057],
        "risk": "high",
        "use_case": "Login forms, session handling",
    },
    "information_disclosure": {
        "description": "Error messages, stack traces, debug info",
        "scanner_ids": [10023, 10035, 10036, 10037],
        "risk": "medium",
        "use_case": "Error handling, verbose responses",
    },
    "header_security": {
        "description": "Missing security headers",
        "scanner_ids": [10015, 10016, 10017, 10020, 10021],
        "risk": "low",
        "use_case": "All web applications",
    },
    "cors": {
        "description": "CORS misconfigurations",
        "scanner_ids": [40040],
        "risk": "medium",
        "use_case": "APIs with cross-origin access",
    },
    "caching": {
        "description": "Cache poisoning, sensitive data caching",
        "scanner_ids": [10050, 10051],
        "risk": "medium",
        "use_case": "CDN, caching proxies",
    },
}

# ZAP Advanced Features - AI can request these
ZAP_ADVANCED_FEATURES = {
    "openapi_import": {
        "description": "Import OpenAPI/Swagger spec for targeted API testing",
        "use_case": "When target has /swagger.json or /openapi.yaml",
        "requirement": "URL to OpenAPI specification",
    },
    "graphql_import": {
        "description": "Import GraphQL schema via introspection for targeted testing",
        "use_case": "When target has GraphQL endpoint",
        "requirement": "GraphQL endpoint URL",
    },
    "forced_browsing": {
        "description": "Directory/file brute forcing with wordlists",
        "use_case": "Find hidden paths, admin panels, backup files",
        "wordlists": ["directory-list-2.3-small.txt", "directory-list-2.3-medium.txt", "dirbuster-big.txt"],
    },
    "ajax_spider": {
        "description": "Crawl JavaScript-heavy SPAs with headless browser",
        "use_case": "React, Angular, Vue apps",
        "browsers": ["firefox-headless", "chrome-headless"],
    },
    "websocket_testing": {
        "description": "Intercept and test WebSocket communications",
        "use_case": "Real-time apps, chat applications",
    },
    "authenticated_scanning": {
        "description": "Scan with user credentials for deeper coverage",
        "use_case": "Behind-login areas, user-specific features",
        "auth_methods": ["form", "http_basic", "json", "oauth", "script"],
    },
    "context_separation": {
        "description": "Separate contexts for different app sections",
        "use_case": "Multi-tenant apps, role-based testing",
    },
}

# Agentic action schema (compact)
AGENT_ACTIONS = {
    "run_nmap": {
        "parameters": ["scan_type", "ports", "nse_scripts", "timing_template", "run_udp", "advanced_options"],
        "use_case": "Network discovery and service fingerprinting",
    },
    "classify_services": {
        "parameters": [],
        "use_case": "Classify discovered services into web vs network targets",
    },
    "run_openvas": {
        "parameters": ["scan_config", "port_list", "nvt_families", "qod_threshold", "alive_test", "max_hosts",
                      "authenticated_scan", "credential_type", "schedule", "alert"],
        "use_case": "Deep network vulnerability scanning",
    },
    "run_zap": {
        "parameters": ["scan_policy", "spider_mode", "attack_vectors", "advanced_features", "forced_browse", "wordlist"],
        "use_case": "Web application scanning (spider + active scan)",
    },
    "run_nuclei": {
        "parameters": ["templates", "severity"],
        "use_case": "CVE/signature scanning",
    },
    "run_directory_enum": {
        "parameters": ["engine", "wordlist", "extensions", "threads"],
        "use_case": "Discover hidden directories and files",
    },
    "run_forced_browse": {
        "parameters": ["wordlist", "scan_policy"],
        "use_case": "Wordlist-based path discovery",
    },
    "run_wapiti": {
        "parameters": ["level"],
        "use_case": "Additional web vulnerability scanning",
    },
    "run_sqlmap": {
        "parameters": ["level", "risk", "method", "data", "threads"],
        "use_case": "SQL injection testing on discovered inputs",
    },
    "run_oob": {
        "parameters": ["callback_domain", "callback_port", "callback_protocol", "wait_seconds", "max_targets"],
        "use_case": "Blind/OOB vulnerability detection",
    },
    "run_validation": {
        "parameters": ["max_findings"],
        "use_case": "Validate high/critical findings",
    },
    "map_exploits": {
        "parameters": [],
        "use_case": "Exploit database lookup",
    },
    "ai_analysis": {
        "parameters": [],
        "use_case": "Generate attack narrative and recommendations",
    },
    "stop": {
        "parameters": ["reason"],
        "use_case": "End the agentic loop",
    },
}

# ZAP Spider Options - AI can customize crawling
ZAP_SPIDER_OPTIONS = {
    "quick": {
        "max_depth": 3,
        "max_children": 10,
        "ajax_spider": False,
        "use_case": "Fast crawl of simple sites",
    },
    "standard": {
        "max_depth": 5,
        "max_children": 0,  # unlimited
        "ajax_spider": True,
        "ajax_duration": 30,
        "use_case": "Standard crawling",
    },
    "deep": {
        "max_depth": 10,
        "max_children": 0,
        "ajax_spider": True,
        "ajax_duration": 60,
        "use_case": "Deep crawling of complex apps",
    },
    "spa_focused": {
        "max_depth": 5,
        "max_children": 0,
        "ajax_spider": True,
        "ajax_duration": 120,
        "browser": "firefox-headless",
        "use_case": "Single Page Applications with heavy JavaScript",
    },
}

# OpenVAS Scan Configurations - AI can select thoroughness
OPENVAS_SCAN_CONFIGS = {
    "host_discovery": {
        "config_id": "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
        "description": "Quick host discovery only",
        "use_case": "Finding live hosts before full scan",
        "time": "1-5 minutes",
    },
    "system_discovery": {
        "config_id": "bbca7412-a950-11e3-9109-406186ea4fc5",
        "description": "OS and service detection",
        "use_case": "Understanding the attack surface",
        "time": "5-15 minutes",
    },
    "discovery": {
        "config_id": "8715c877-47a0-438d-98a3-27c7a6ab2196",
        "description": "Comprehensive discovery scan",
        "use_case": "Full network reconnaissance",
        "time": "10-30 minutes",
    },
    "full_and_fast": {
        "config_id": "daba56c8-73ec-11df-a475-002264764cea",
        "description": "Complete vulnerability scan with speed optimization",
        "use_case": "Standard vulnerability assessment",
        "time": "30-90 minutes",
    },
    "full_and_deep": {
        "config_id": "708f25c4-7489-11df-8094-002264764cea",
        "description": "Deep vulnerability analysis",
        "use_case": "Thorough security assessment",
        "time": "1-3 hours",
    },
    "full_and_very_deep": {
        "config_id": "74db13d6-7489-11df-8094-002264764cea",
        "description": "Maximum depth vulnerability scan",
        "use_case": "Comprehensive pentest, test environments",
        "time": "2-6 hours",
    },
}

# OpenVAS Port Lists - AI can select port coverage
OPENVAS_PORT_LISTS = {
    "top_tcp_100": {
        "port_list_id": "730ef368-57e2-11e1-a90f-406186ea4fc5",
        "description": "Top 100 TCP ports",
        "use_case": "Quick scan of common services",
    },
    "top_tcp_1000": {
        "port_list_id": "ab33f6b0-57f8-11e1-96f5-406186ea4fc5",
        "description": "Top 1000 TCP + top 100 UDP",
        "use_case": "Standard coverage",
    },
    "all_tcp": {
        "port_list_id": "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
        "description": "All 65535 TCP ports",
        "use_case": "Complete TCP coverage",
    },
    "all_tcp_udp": {
        "port_list_id": "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
        "description": "All TCP + top 100 UDP",
        "use_case": "Maximum coverage",
    },
}

# OpenVAS NVT Families - AI can select which vulnerability test categories to enable
OPENVAS_NVT_FAMILIES = {
    "web_servers": {
        "name": "Web Servers",
        "description": "Vulnerabilities in Apache, Nginx, IIS, and other web servers",
        "use_case": "Web hosting, application servers",
        "example_nvts": ["Apache vulnerabilities", "Nginx misconfigs", "IIS exploits"],
    },
    "databases": {
        "name": "Databases",
        "description": "MySQL, PostgreSQL, MongoDB, MSSQL, Oracle vulnerabilities",
        "use_case": "Database servers, data stores",
        "example_nvts": ["SQL injection vectors", "Auth bypass", "Privilege escalation"],
    },
    "windows": {
        "name": "Windows",
        "description": "Windows OS and Active Directory vulnerabilities",
        "use_case": "Windows servers, domain controllers",
        "example_nvts": ["SMB exploits", "RDP vulnerabilities", "Windows updates"],
    },
    "linux": {
        "name": "Linux",
        "description": "Linux kernel and distribution-specific vulnerabilities",
        "use_case": "Linux servers, containers",
        "example_nvts": ["Kernel exploits", "SSH issues", "Package vulnerabilities"],
    },
    "general": {
        "name": "General",
        "description": "Generic vulnerability checks applicable to any system",
        "use_case": "Universal scanning",
        "example_nvts": ["SSL/TLS issues", "DNS vulnerabilities", "Information leaks"],
    },
    "credentials": {
        "name": "Credentials",
        "description": "Default credentials, weak passwords, credential exposure",
        "use_case": "Authentication testing",
        "example_nvts": ["Default passwords", "Brute force", "Credential stuffing"],
    },
    "denial_of_service": {
        "name": "Denial of Service",
        "description": "DoS vulnerability detection (non-destructive checks)",
        "use_case": "Availability testing - CAUTION: may impact service",
        "example_nvts": ["Resource exhaustion", "Crash vectors", "Amplification"],
    },
    "brute_force": {
        "name": "Brute force attacks",
        "description": "Password guessing and brute force attack vectors",
        "use_case": "Authentication strength testing",
        "example_nvts": ["SSH brute force", "FTP brute force", "HTTP auth"],
    },
    "malware": {
        "name": "Malware",
        "description": "Malware detection and backdoor identification",
        "use_case": "Compromise detection",
        "example_nvts": ["Web shells", "Rootkits", "Backdoors"],
    },
    "port_scanners": {
        "name": "Port scanners",
        "description": "Port and service discovery tests",
        "use_case": "Network reconnaissance",
        "example_nvts": ["TCP scan", "UDP scan", "Service detection"],
    },
    "service_detection": {
        "name": "Service detection",
        "description": "Identify running services and versions",
        "use_case": "Asset inventory, version detection",
        "example_nvts": ["Banner grabbing", "Fingerprinting", "Version detection"],
    },
    "firewalls": {
        "name": "Firewalls",
        "description": "Firewall and network device vulnerabilities",
        "use_case": "Network security devices",
        "example_nvts": ["Firewall bypasses", "ACL issues", "Config weaknesses"],
    },
    "smtp": {
        "name": "SMTP problems",
        "description": "Mail server vulnerabilities and misconfigurations",
        "use_case": "Email servers",
        "example_nvts": ["Open relay", "Spoofing", "Auth issues"],
    },
    "snmp": {
        "name": "SNMP",
        "description": "SNMP vulnerabilities and information disclosure",
        "use_case": "Network management",
        "example_nvts": ["Community strings", "SNMP v1/v2c", "Information leak"],
    },
    "ftp": {
        "name": "FTP",
        "description": "FTP server vulnerabilities",
        "use_case": "File transfer servers",
        "example_nvts": ["Anonymous FTP", "Bounce attacks", "Auth bypass"],
    },
    "ssl_tls": {
        "name": "SSL and TLS",
        "description": "Certificate and encryption vulnerabilities",
        "use_case": "Encrypted services",
        "example_nvts": ["Weak ciphers", "Expired certs", "Protocol issues"],
    },
    "scada": {
        "name": "IT-Grundschutz",
        "description": "Industrial control and SCADA system vulnerabilities",
        "use_case": "OT/ICS environments - USE WITH CAUTION",
        "example_nvts": ["Modbus", "DNP3", "ICS-specific exploits"],
    },
    "compliance": {
        "name": "Compliance",
        "description": "Compliance and policy checking",
        "use_case": "Regulatory compliance (PCI, HIPAA, etc)",
        "example_nvts": ["Policy violations", "Configuration checks", "Standards"],
    },
}

# OpenVAS Advanced Features - AI can configure scan behavior
OPENVAS_ADVANCED_FEATURES = {
    "qod_threshold": {
        "description": "Quality of Detection threshold (0-100) - filter results by confidence",
        "default": 70,
        "options": {
            "low": 30,       # Include uncertain results
            "standard": 70,  # Default - balanced confidence
            "high": 90,      # Only high-confidence findings
            "maximum": 98,   # Verified vulnerabilities only
        },
        "use_case": "Filter noise vs thoroughness tradeoff",
    },
    "alive_tests": {
        "description": "Method to determine if hosts are alive before scanning",
        "options": {
            "icmp_tcp_ack_ping": "ICMP & TCP-ACK ping",
            "tcp_syn_ping": "TCP-SYN ping only",
            "icmp_ping": "ICMP Echo Request only",
            "arp_ping": "ARP ping (same subnet only)",
            "consider_alive": "Consider all hosts alive (skip discovery)",
        },
        "use_case": "Customize host discovery for different network conditions",
    },
    "max_hosts": {
        "description": "Maximum number of hosts to scan simultaneously",
        "default": 20,
        "options": {
            "conservative": 5,    # Careful scanning
            "standard": 20,       # Default
            "aggressive": 50,     # Fast but resource heavy
        },
        "use_case": "Balance scan speed vs network impact",
    },
    "max_checks": {
        "description": "Maximum number of NVTs to run simultaneously per host",
        "default": 4,
        "options": {
            "conservative": 2,
            "standard": 4,
            "aggressive": 10,
        },
        "use_case": "Balance thoroughness vs target impact",
    },
    "network_timeout": {
        "description": "Network connection timeout in seconds",
        "default": 30,
        "options": {
            "fast": 10,           # Quick timeout for responsive networks
            "standard": 30,       # Default
            "slow": 60,           # For high-latency networks
            "very_slow": 120,     # VPN, satellite, etc
        },
        "use_case": "Adjust for network conditions",
    },
    "result_severity_filter": {
        "description": "Minimum severity level to include in results",
        "options": {
            "all": 0.0,           # All findings including logs
            "low_and_above": 0.1, # Exclude pure informational
            "medium_and_above": 4.0,  # Medium+ only
            "high_and_above": 7.0,    # High/Critical only
            "critical_only": 9.0,     # Critical only
        },
        "use_case": "Focus on most important findings",
    },
}

# OpenVAS Credential Types for Authenticated Scanning
OPENVAS_CREDENTIAL_TYPES = {
    "ssh_password": {
        "description": "SSH login with username/password",
        "fields": ["username", "password"],
        "use_case": "Linux/Unix authenticated scanning",
        "port": 22,
    },
    "ssh_key": {
        "description": "SSH login with private key",
        "fields": ["username", "private_key", "passphrase"],
        "use_case": "Key-based Linux authentication",
        "port": 22,
    },
    "smb": {
        "description": "Windows SMB/CIFS credentials",
        "fields": ["username", "password", "domain"],
        "use_case": "Windows authenticated scanning",
        "port": 445,
    },
    "snmp_v1_v2c": {
        "description": "SNMP v1/v2c community string",
        "fields": ["community"],
        "use_case": "Network device SNMP access",
    },
    "snmp_v3": {
        "description": "SNMP v3 with authentication and privacy",
        "fields": ["username", "auth_password", "auth_algorithm", "privacy_password", "privacy_algorithm"],
        "use_case": "Secure SNMP access",
    },
    "esxi": {
        "description": "VMware ESXi credentials",
        "fields": ["username", "password"],
        "use_case": "VMware infrastructure scanning",
    },
    "database": {
        "description": "Database credentials (MySQL, PostgreSQL, MSSQL, Oracle)",
        "fields": ["username", "password", "database_type"],
        "use_case": "Authenticated database scanning",
    },
}

# Built-in Wordlists for Directory Discovery
WORDLISTS = {
    "quick": {
        "description": "Fast directory discovery (~500 entries)",
        "files": ["directories_comprehensive.txt"],
        "use_case": "Quick check for common dirs/files",
        "time": "1-5 minutes",
    },
    "standard": {
        "description": "Standard directory list for comprehensive coverage",
        "files": ["directories_comprehensive.txt"],
        "use_case": "Normal directory bruteforcing",
        "time": "5-15 minutes",
    },
    "aggressive": {
        "description": "Aggressive discovery pack (dirs + API + sensitive + backups + CMS)",
        "files": [
            "directories_comprehensive.txt",
            "api_endpoints.txt",
            "graphql_comprehensive.txt",
            "sensitive_files.txt",
            "backup_config_files.txt",
            "cms_paths.txt",
        ],
        "use_case": "Maximum path discovery for lab targets",
        "time": "20-60 minutes",
    },
    "api": {
        "description": "API endpoint discovery wordlist",
        "files": ["api_endpoints.txt", "graphql_comprehensive.txt"],
        "use_case": "REST/GraphQL API endpoint enumeration",
        "time": "5-20 minutes",
    },
    "backup": {
        "description": "Backup and config file discovery",
        "files": ["backup_config_files.txt"],
        "use_case": "Find backup files, config dumps, credentials",
        "time": "5-15 minutes",
    },
    "sensitive": {
        "description": "Sensitive file discovery",
        "files": ["sensitive_files.txt"],
        "use_case": "Find sensitive/leaked files, keys, credentials",
        "time": "5-15 minutes",
    },
    "cms": {
        "description": "CMS-specific paths (WordPress, Drupal, Joomla, etc)",
        "files": ["cms_paths.txt"],
        "use_case": "CMS enumeration and admin panel discovery",
        "time": "10-30 minutes",
    },
    "sqli": {
        "description": "SQL injection test payloads",
        "files": ["sqli_comprehensive.txt"],
        "use_case": "SQL injection testing payloads",
        "time": "varies",
    },
    "xss": {
        "description": "XSS test payloads",
        "files": ["xss_comprehensive.txt"],
        "use_case": "Cross-site scripting testing",
        "time": "varies",
    },
    "ssrf": {
        "description": "SSRF test payloads",
        "files": ["ssrf_comprehensive.txt"],
        "use_case": "Server-side request forgery testing",
        "time": "varies",
    },
    "ssti": {
        "description": "Server-side template injection payloads",
        "files": ["ssti_comprehensive.txt"],
        "use_case": "Template injection testing",
        "time": "varies",
    },
    "xxe": {
        "description": "XML external entity payloads",
        "files": ["xxe_comprehensive.txt"],
        "use_case": "XXE injection testing",
        "time": "varies",
    },
    "credentials": {
        "description": "Common username and password lists",
        "files": ["usernames_common.txt", "passwords_top10k.txt"],
        "use_case": "Credential stuffing, brute force",
        "time": "varies",
    },
}

# Nuclei Template Categories - AI can select which to run
NUCLEI_TEMPLATES = {
    "cves": {
        "description": "Known CVE vulnerabilities",
        "templates": ["-t", "cves/"],
        "use_case": "Check for known CVEs based on detected versions",
    },
    "exposures": {
        "description": "Sensitive data exposure checks",
        "templates": ["-t", "exposures/"],
        "use_case": "Find exposed configs, credentials, tokens",
    },
    "misconfigurations": {
        "description": "Security misconfiguration detection",
        "templates": ["-t", "misconfiguration/"],
        "use_case": "Default creds, open admin panels, etc",
    },
    "vulnerabilities": {
        "description": "General vulnerability checks",
        "templates": ["-t", "vulnerabilities/"],
        "use_case": "Broad vulnerability scanning",
    },
    "takeovers": {
        "description": "Subdomain takeover detection",
        "templates": ["-t", "takeovers/"],
        "use_case": "Check for subdomain hijacking opportunities",
    },
    "network": {
        "description": "Network service vulnerabilities",
        "templates": ["-t", "network/"],
        "use_case": "Network protocol vulnerabilities",
    },
    "default_logins": {
        "description": "Default credential checks",
        "templates": ["-t", "default-logins/"],
        "use_case": "Find services with default passwords",
    },
    "technologies": {
        "description": "Technology detection",
        "templates": ["-t", "technologies/"],
        "use_case": "Identify frameworks, CMS, tech stack",
    },
    "all_critical": {
        "description": "All critical severity templates",
        "templates": ["-s", "critical"],
        "use_case": "Focus on critical vulnerabilities only",
    },
    "all_high": {
        "description": "High and critical severity",
        "templates": ["-s", "critical,high"],
        "use_case": "High-impact vulnerabilities",
    },
}


class ScanPhase(str, Enum):
    """Scanning phases."""
    RECON = "reconnaissance"
    ANALYSIS = "analysis"
    VULN_SCAN = "vulnerability_scanning"
    EXPLOIT_RESEARCH = "exploit_research"
    AI_ANALYSIS = "ai_analysis"
    COMPLETE = "complete"


class AgentDecision:
    """Represents an AI agent decision."""
    def __init__(
        self,
        action: str,
        tools: List[ScanTool],
        targets: List[Dict[str, Any]],
        reasoning: str,
        priority: int = 5,
    ):
        self.action = action
        self.tools = tools
        self.targets = targets
        self.reasoning = reasoning
        self.priority = priority
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "tools": [t.value for t in self.tools],
            "targets": self.targets,
            "reasoning": self.reasoning,
            "priority": self.priority,
        }


class DynamicScanAgent:
    """
    AI agent for orchestrating dynamic security scans
    and generating actionable attack narratives.
    
    The agent follows this workflow:
    1. Nmap discovers open ports and services
    2. Agent analyzes results and decides next steps
    3. For web services → ZAP scans
    4. For network services → OpenVAS scans  
    5. Nuclei runs CVE-specific checks
    6. Exploit-DB search for available exploits
    7. AI generates attack narrative and commands
    """
    
    # Service classification for routing
    WEB_SERVICES = {
        80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9443,
        4443, 8081, 8082, 8090, 8181, 9090, 9091, 3001, 4000,
    }
    
    WEB_SERVICE_NAMES = {
        "http", "https", "http-proxy", "http-alt", "ssl/http", 
        "nginx", "apache", "tomcat", "iis", "lighttpd", "express",
    }
    
    OPENVAS_PRIORITY_SERVICES = {
        # SSH - many CVEs, brute force
        22: ("ssh", "high"),
        # SMB - EternalBlue, etc.
        139: ("smb", "critical"),
        445: ("smb", "critical"),
        # RDP - BlueKeep, etc.
        3389: ("rdp", "critical"),
        # Databases - auth bypass, injection
        3306: ("mysql", "high"),
        5432: ("postgresql", "high"),
        1433: ("mssql", "high"),
        1521: ("oracle", "high"),
        27017: ("mongodb", "high"),
        6379: ("redis", "high"),
        # FTP - anonymous access, CVEs
        21: ("ftp", "medium"),
        # SMTP - relay, spoofing
        25: ("smtp", "medium"),
        465: ("smtp", "medium"),
        587: ("smtp", "medium"),
        # LDAP - info disclosure
        389: ("ldap", "high"),
        636: ("ldap", "high"),
        # SNMP - info disclosure
        161: ("snmp", "medium"),
        # VNC - auth bypass
        5900: ("vnc", "high"),
        5901: ("vnc", "high"),
        # Telnet - cleartext
        23: ("telnet", "high"),
    }
    
    def __init__(self):
        settings_obj = None
        try:
            from backend.core.config import settings as settings_obj
            self.model_id = settings_obj.gemini_model_id
        except Exception:
            self.model_id = "gemini-3-flash-preview"
        self.client = None
        
        if GEMINI_AVAILABLE:
            try:
                if settings_obj and settings_obj.gemini_api_key:
                    self.client = genai.Client(api_key=settings_obj.gemini_api_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini client: {e}")

    def _require_client(self) -> None:
        """Ensure Gemini client is configured."""
        if not self.client:
            raise RuntimeError("Gemini client not configured; set GEMINI_API_KEY")

    @staticmethod
    def _parse_json_response(text: str) -> Dict[str, Any]:
        """Parse a JSON response, stripping code fences if needed."""
        cleaned = (text or "").strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            if "\n" in cleaned:
                cleaned = cleaned.split("\n", 1)[1]
            cleaned = cleaned.strip()
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()
        return json.loads(cleaned)

    def _validate_action_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize agent action payloads."""
        if not isinstance(payload, dict):
            raise ValueError("Action payload must be a JSON object")
        action = payload.get("action")
        if not isinstance(action, str) or not action.strip():
            raise ValueError("Action must be a non-empty string")
        action = action.strip()
        if action not in AGENT_ACTIONS:
            raise ValueError(f"Unknown action '{action}'")
        params = payload.get("parameters", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise ValueError("Parameters must be a JSON object")
        reason = payload.get("reason")
        if isinstance(reason, str):
            reason = [reason]
        if not isinstance(reason, list) or not reason:
            raise ValueError("Reason must be a non-empty list of strings")
        reason = [item for item in reason if isinstance(item, str) and item.strip()]
        if not reason:
            raise ValueError("Reason must include at least one non-empty string")
        expected_signal = payload.get("expected_signal")
        if not isinstance(expected_signal, str) or not expected_signal.strip():
            if action == "stop":
                expected_signal = "stop"
            else:
                raise ValueError("expected_signal must be a non-empty string")
        plan_update = payload.get("plan_update", [])
        if plan_update is None:
            plan_update = []
        if not isinstance(plan_update, list):
            raise ValueError("plan_update must be a list of strings")
        plan_update = [item for item in plan_update if isinstance(item, str) and item.strip()]
        stop_reason = payload.get("stop_reason")
        if action == "stop" and stop_reason is not None and not isinstance(stop_reason, str):
            raise ValueError("stop_reason must be a string when provided")
        if action != "stop":
            payload.pop("stop_reason", None)
        payload["action"] = action
        payload["parameters"] = params
        payload["reason"] = reason
        payload["expected_signal"] = expected_signal.strip()
        payload["plan_update"] = plan_update
        return payload

    def _validate_analysis_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate AI analysis payload schema."""
        if not isinstance(payload, dict):
            raise ValueError("Analysis payload must be a JSON object")
        required_str = ["executive_summary", "attack_narrative", "risk_summary"]
        for key in required_str:
            if key not in payload or not isinstance(payload.get(key), str):
                raise ValueError(f"Missing or invalid '{key}'")
        list_fields = ["exploit_chains", "recommendations", "priority_targets"]
        for key in list_fields:
            if key not in payload or not isinstance(payload.get(key), list):
                raise ValueError(f"Missing or invalid '{key}'")
        commands = payload.get("commands")
        if not isinstance(commands, dict):
            raise ValueError("Missing or invalid 'commands'")
        return payload
    
    @staticmethod
    def get_available_tools() -> Dict[str, Any]:
        """
        Returns a comprehensive catalog of all available scanning tools and options.
        This can be used by the frontend to display available options or for documentation.
        
        Returns:
            Dict with all tool categories and their options
        """
        return {
            "nmap": {
                "description": "Network reconnaissance and port scanning",
                "scan_types": NMAP_SCAN_TYPES,
                "nse_script_categories": NMAP_NSE_SCRIPTS,
                "timing_templates": {
                    "T0": "Paranoid - IDS evasion, very slow",
                    "T1": "Sneaky - IDS evasion",
                    "T2": "Polite - Less bandwidth, slower",
                    "T3": "Normal - Default speed",
                    "T4": "Aggressive - Fast, assumes reliable network",
                    "T5": "Insane - Very fast, may miss ports",
                },
            },
            "zap": {
                "description": "OWASP ZAP web application security scanner",
                "scan_policies": ZAP_SCAN_POLICIES,
                "spider_options": ZAP_SPIDER_OPTIONS,
                "features": [
                    "Spider - Traditional web crawling",
                    "AJAX Spider - JavaScript-heavy SPA crawling",
                    "Active Scan - Vulnerability testing",
                    "Passive Scan - Non-intrusive analysis",
                    "Forced Browse - Directory enumeration",
                    "Authentication - Form, HTTP Basic, JSON, Script-based",
                ],
            },
            "openvas": {
                "description": "OpenVAS/GVM comprehensive vulnerability scanner",
                "scan_configs": OPENVAS_SCAN_CONFIGS,
                "port_lists": OPENVAS_PORT_LISTS,
            },
            "nuclei": {
                "description": "Fast CVE and vulnerability detection",
                "template_categories": NUCLEI_TEMPLATES,
            },
            "wordlists": {
                "description": "Directory and file discovery wordlists",
                "options": WORDLISTS,
            },
        }
    
    async def plan_scan_strategy(
        self,
        target: str,
        user_context: Optional[str] = None,
        aggressive_scan: bool = True,
    ) -> Dict[str, Any]:
        """
        AI-led scan planning. Analyzes the target and decides the optimal scan strategy.
        
        This is called BEFORE any scanning begins. The AI decides:
        - Whether to run Nmap reconnaissance (not needed for direct URLs)
        - What type of Nmap scan to perform (ping, service, comprehensive, stealth)
        - Which ports to focus on
        - Whether to enable specific scan types (OpenVAS, ZAP, Nuclei)
        - Overall scan strategy based on target type
        
        Args:
            target: IP, CIDR, hostname, or URL to scan
            user_context: Optional context from user (e.g., "this is a production server", "test environment", "looking for web vulns")
            aggressive_scan: Prefer maximum/aggressive intensity when True, thorough when False
            
        Returns:
            Dict with complete scan strategy
        """
        import re
        from urllib.parse import urlparse
        
        # Basic target analysis (deterministic)
        is_url = target.startswith('http://') or target.startswith('https://')
        is_cidr = '/' in target and not is_url
        is_private_ip = False
        is_localhost = False
        safe_lab_hint = False
        
        if not is_url:
            # Check for private IP ranges
            private_patterns = [
                r'^10\.',
                r'^192\.168\.',
                r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
                r'^127\.',
                r'^localhost$',
            ]
            for pattern in private_patterns:
                if re.match(pattern, target.lower()):
                    is_private_ip = True
                    if '127.' in target or 'localhost' in target.lower():
                        is_localhost = True
                    break

        context_blob = f"{target} {user_context or ''}".lower()
        lab_keywords = [
            "juice shop", "juiceshop", "owasp juice", "dvwa", "webgoat",
            "hackthebox", "htb", "vulnhub", "metasploitable", "ctf",
            "lab", "training", "staging", "test environment", "test env",
            "sandbox", "localhost",
        ]
        if any(keyword in context_blob for keyword in lab_keywords) or is_localhost:
            safe_lab_hint = True
        
        default_zap_policy = "maximum" if aggressive_scan else "thorough"
        default_openvas_config = "full_and_very_deep" if aggressive_scan else "full_and_deep"
        default_openvas_port_list = "all_tcp_udp" if aggressive_scan else "top_tcp_1000"
        default_openvas_qod_threshold = "low" if aggressive_scan else "standard"
        default_openvas_max_hosts = "aggressive" if aggressive_scan else "standard"
        default_nmap_timing = "T4" if aggressive_scan else "T3"
        default_run_nmap_udp = aggressive_scan
        default_zap_advanced_features = ["ajax_spider"]
        default_wordlist = None
        default_nuclei_templates = ["cves", "vulnerabilities"]
        if aggressive_scan:
            default_zap_advanced_features = [
                "ajax_spider",
                "openapi_import",
                "graphql_import",
                "forced_browsing",
            ]
            default_wordlist = "aggressive"
            default_nuclei_templates = ["cves", "vulnerabilities", "exposures", "misconfigurations"]

        # Default strategy (fallback if AI is not available) - DEFAULT TO AGGRESSIVE SCANNING
        default_strategy = {
            "target_analysis": {
                "target": target,
                "type": "url" if is_url else ("cidr" if is_cidr else "host"),
                "is_private": is_private_ip,
                "is_localhost": is_localhost,
                "safe_lab_hint": safe_lab_hint,
            },
            "scan_plan": {
                "run_nmap": not is_url,
                "nmap_scan_type": "service",
                "nmap_ports": None,  # Default ports
                "nmap_additional_scans": [],
                "nmap_timing": default_nmap_timing,
                "run_nmap_udp": default_run_nmap_udp,
                "run_openvas": not is_url and not is_localhost,
                "openvas_config": default_openvas_config,
                "openvas_port_list": default_openvas_port_list,
                "openvas_qod_threshold": default_openvas_qod_threshold,
                "openvas_max_hosts": default_openvas_max_hosts,
                "run_zap": True,
                "zap_scan_policy": default_zap_policy,
                "zap_spider_mode": "deep",
                "zap_attack_vectors": [],  # Empty = all scanners enabled
                "zap_advanced_features": default_zap_advanced_features,
                "zap_forced_browse": aggressive_scan,
                "zap_wordlist": default_wordlist,
                "run_nuclei": not is_url,
                "nuclei_templates": default_nuclei_templates,
                "run_exploit_mapping": True,
            },
            "ai_reasoning": (
                "Using aggressive default scan strategy - AI analysis unavailable. "
                "Defaulting to maximum-intensity scanning with full ZAP scanner coverage."
                if aggressive_scan else
                "Using thorough default scan strategy - AI analysis unavailable. "
                "Defaulting to comprehensive scanning with full ZAP scanner coverage."
            ),
            "risk_assessment": "medium",
            "estimated_duration_minutes": 30 if is_url else 60,
            "recommendations": [],
        }
        
        # If it's a URL, return optimized strategy immediately
        if is_url:
            parsed = urlparse(target)
            default_strategy["scan_plan"]["run_nmap"] = False
            default_strategy["scan_plan"]["run_openvas"] = False
            default_strategy["scan_plan"]["run_nuclei"] = aggressive_scan
            if aggressive_scan:
                default_strategy["scan_plan"]["nuclei_templates"] = default_nuclei_templates
            # Keep aggressive or thorough ZAP scanning for URLs
            intensity_label = "MAXIMUM" if aggressive_scan else "THOROUGH"
            default_strategy["ai_reasoning"] = (
                f"Direct URL target detected ({parsed.netloc}). Skipping network reconnaissance - "
                f"proceeding directly to {intensity_label} web application scanning with ZAP."
            )
            default_strategy["estimated_duration_minutes"] = 30
            default_strategy["recommendations"] = [
                f"ZAP {default_zap_policy} active scan will deeply crawl and test the web application",
                "Consider running authenticated scan for deeper coverage",
                "Nuclei signature scan will check for known CVEs and exposures" if aggressive_scan else "Enable Nuclei for CVE/misconfig coverage when needed",
                "All ZAP scanners enabled unless restricted by attack vector selection",
            ]
            return default_strategy
        
        # Use AI for intelligent planning if available
        if not self.client:
            return default_strategy
        
        try:
            context_section = ""
            if user_context:
                context_section = f"\n## User Context\n{user_context}\n"
            
            # Build comprehensive tool catalog for AI
            nmap_types_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']} | Time: {v['time']} | Stealth: {v['stealth']}"
                for k, v in NMAP_SCAN_TYPES.items()
            ])
            
            nse_scripts_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']}"
                for k, v in NMAP_NSE_SCRIPTS.items()
            ])
            
            nmap_advanced_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Default: {v.get('default', 'N/A')} | Use case: {v['use_case']}"
                for k, v in NMAP_ADVANCED_OPTIONS.items()
            ])
            
            zap_policies_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']} | Time: {v['time']}"
                for k, v in ZAP_SCAN_POLICIES.items()
            ])
            
            zap_spider_desc = "\n".join([
                f"   - \"{k}\": depth={v['max_depth']}, ajax={v.get('ajax_spider', False)} | Use case: {v['use_case']}"
                for k, v in ZAP_SPIDER_OPTIONS.items()
            ])
            
            zap_attacks_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Risk: {v['risk']} | Use case: {v['use_case']}"
                for k, v in ZAP_ATTACK_VECTORS.items()
            ])
            
            zap_advanced_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']}"
                for k, v in ZAP_ADVANCED_FEATURES.items()
            ])
            
            openvas_configs_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']} | Time: {v['time']}"
                for k, v in OPENVAS_SCAN_CONFIGS.items()
            ])
            
            openvas_ports_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']}"
                for k, v in OPENVAS_PORT_LISTS.items()
            ])
            
            openvas_nvt_families_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']}"
                for k, v in OPENVAS_NVT_FAMILIES.items()
            ])
            
            openvas_advanced_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Options: {list(v.get('options', {}).keys())}"
                for k, v in OPENVAS_ADVANCED_FEATURES.items()
            ])
            
            openvas_credentials_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']} | Fields: {v['fields']}"
                for k, v in OPENVAS_CREDENTIAL_TYPES.items()
            ])
            
            nuclei_templates_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']}"
                for k, v in NUCLEI_TEMPLATES.items()
            ])
            
            wordlists_desc = "\n".join([
                f"   - \"{k}\": {v['description']} | Use case: {v['use_case']} | Time: {v['time']}"
                for k, v in WORDLISTS.items()
            ])
            
            prompt = f"""You are an elite penetration tester and security researcher planning a comprehensive security assessment.

## Target
{target}
{context_section}
## Target Intelligence
- Type: {"CIDR range (multiple hosts possible)" if is_cidr else "single host/IP"}
- Network: {"Private/internal network" if is_private_ip else "Public/external network"}
- Localhost: {is_localhost}
- Safe lab hint: {safe_lab_hint}

## Operator Preferences
- Aggressive scan: {aggressive_scan} (true = maximum intensity, false = thorough)

You have access to a comprehensive arsenal of security scanning tools. Your job is to CREATE AN INTELLIGENT, TARGETED SCAN STRATEGY based on:
1. The target type and likely attack surface
2. What vulnerabilities are most likely based on context
3. Optimal tool combinations that complement each other
4. Time efficiency vs thoroughness tradeoffs

=== NMAP RECONNAISSANCE OPTIONS ===
{nmap_types_desc}

=== NMAP NSE SCRIPT CATEGORIES ===
(Run specific vulnerability checks based on discovered services)
{nse_scripts_desc}

=== NMAP ADVANCED OPTIONS ===
(Fine-tune Nmap behavior for specific scenarios - firewall evasion, stealth, speed)
{nmap_advanced_desc}

**Timing Templates (nmap_timing):** T0-T5
- T0: Paranoid (IDS evasion, very slow)
- T1: Sneaky (IDS evasion)
- T2: Polite (less bandwidth)
- T3: Normal (default)
- T4: Aggressive (fast, reliable network)
- T5: Insane (very fast, may miss)

**Firewall Evasion Tips:**
- Use fragmentation (-f) for simple packet filters
- Spoof source port to 53/80/443 to bypass lazy firewalls
- Use decoys (RND:5) to hide among fake IPs
- Lower timing (T2) reduces detection

=== ZAP WEB SCANNING POLICIES ===
(Select intensity based on target sensitivity)
{zap_policies_desc}

=== ZAP SPIDER/CRAWLER OPTIONS ===
{zap_spider_desc}

=== ZAP ATTACK VECTOR CATEGORIES ===
(Use only if you need to RESTRICT scanners; leave zap_attack_vectors empty for full coverage)
{zap_attacks_desc}

=== ZAP ADVANCED FEATURES ===
(Request these if the target warrants them)
{zap_advanced_desc}

=== OPENVAS VULNERABILITY SCAN CONFIGS ===
(Network-level vulnerability scanning)
{openvas_configs_desc}

=== OPENVAS PORT COVERAGE ===
{openvas_ports_desc}

=== OPENVAS NVT FAMILIES (VULNERABILITY TEST CATEGORIES) ===
(Select specific test categories to focus scanning - OpenVAS has 50,000+ tests)
{openvas_nvt_families_desc}

=== OPENVAS ADVANCED OPTIONS ===
(Fine-tune scan behavior for different scenarios)
{openvas_advanced_desc}

=== OPENVAS AUTHENTICATED SCANNING (CREDENTIAL TYPES) ===
(Request authenticated scanning when credentials are available - dramatically increases detection)
{openvas_credentials_desc}

**Authenticated Scanning Benefits:**
- Detects vulnerabilities invisible to unauthenticated scans
- Identifies missing patches accurately
- Checks local security configurations
- Reduces false positives significantly
- Enables compliance checking

**When to Request Authenticated Scanning:**
- Internal/private network targets with known credentials
- Compliance audits requiring deep inspection
- Comprehensive vulnerability assessments
- Targets where unauthenticated results are insufficient

=== OPENVAS SCHEDULING OPTIONS ===
(For recurring/scheduled scans - optional)
- "immediate": Run scan immediately (default)
- "daily": Schedule recurring daily scan
- "weekly": Schedule recurring weekly scan
- "monthly": Schedule recurring monthly scan

=== OPENVAS ALERTING ===
(Request alerts for scan completion - optional)
- "email": Send email on scan completion
- "syslog": Send to syslog for SIEM integration
- "webhook": Send HTTP notification

=== NUCLEI CVE TEMPLATES ===
(Fast, signature-based vulnerability detection)
{nuclei_templates_desc}

=== WORDLISTS FOR DISCOVERY ===
(Directory enumeration, file discovery)
{wordlists_desc}

## INTELLIGENCE GUIDELINES

**DEFAULT TO AGGRESSIVE SCANNING (MAXIMUM BASELINE):**
If aggressive_scan is true (operator preference):
- Use "maximum" ZAP policy
- Use "full_and_very_deep" OpenVAS config
- Use "deep" spider mode with ajax_spider enabled
- Enable openapi_import and graphql_import attempts for deeper API coverage
- Enable forced_browsing with an aggressive wordlist
- Leave zap_attack_vectors empty for full scanner coverage (only set it when you want to narrow scope)
- Run UDP scanning for comprehensive coverage when network targets are present
If aggressive_scan is false, fall back to the thorough baseline.

**For TEST ENVIRONMENTS, CTF, LAB, OR VULNERABLE APPS (ONLY WHEN CLEARLY INDICATED):**
(Juice Shop, DVWA, WebGoat, HackTheBox, internal test, localhost, staging, etc.)
- If aggressive_scan is true or safe_lab_hint is true (and production is NOT indicated), choose "maximum" ZAP policy
- Prefer "full_and_very_deep" OpenVAS when safe and time permits
- Enable broader attack vectors: injection, xss, path_traversal, ssrf, xxe, ssti, csrf, authentication
- Enable forced_browse with an aggressive wordlist when safe
- Run UDP scanning
- Use aggressive Nmap timing (T4) only if safe and authorized
Let the AI decide based on explicit context and risk tolerance.

**For WEB APPLICATIONS:**
- If URL contains /api, /graphql, /v1, /swagger → Use api_focused policy, consider graphql_import
- If target is SPA (React/Angular/Vue) → Use spa_focused spider with ajax_spider enabled
- If login page detected → Consider auth_bypass attacks, authenticated scanning
- If file upload exists → Focus on path_traversal, xxe attacks
- Cloud-hosted apps → Enable ssrf_focused attacks
- If aggressive_scan is true → Run Nuclei with exposures/misconfigurations for fast CVE/misconfig coverage
- Default: Use "maximum" if aggressive_scan is true, otherwise "thorough"

**For NETWORK SERVICES:**
- SMB (445) → CRITICAL - Run smb NSE scripts, check for EternalBlue
- RDP (3389) → CRITICAL - Run OpenVAS full_and_deep, check BlueKeep
- SSH (22) → Check auth methods, weak algorithms
- Database ports → Run database NSE scripts, check default creds

**For INTERNAL/PRIVATE NETWORKS:**
- Use "maximum" ZAP policy if aggressive_scan is true, otherwise "thorough"
- Enable UDP scanning for SNMP, DNS
- Use "full_and_very_deep" OpenVAS if aggressive_scan is true, otherwise "full_and_deep"
- Use openvas_max_hosts: "aggressive" only when aggressive_scan is true

**FOR PRODUCTION/EXTERNAL (ONLY WHEN EXPLICITLY STATED):**
- Use stealth Nmap scans
- Use "standard" ZAP policy when aggressive_scan is false and production is explicitly indicated
- Avoid aggressive timing
- Use openvas_qod_threshold: "high" to reduce false positives

**OPENVAS NVT FAMILY SELECTION:**
- Windows server → Enable "windows", "credentials", "smb" families
- Linux server → Enable "linux", "ssh", "general" families  
- Web server → Enable "web_servers", "ssl_tls", "general" families
- Database → Enable "databases", "credentials" families
- Network devices → Enable "firewalls", "snmp", "general" families
- IoT/SCADA → Enable "scada" family WITH CAUTION
- Mixed environment → Use "general", "service_detection", "port_scanners"

**OPENVAS QoD (Quality of Detection) GUIDANCE:**
- qod_threshold "low" (30) → See all findings including uncertain ones (noisy but thorough)
- qod_threshold "standard" (70) → Balanced - DEFAULT for most scans
- qod_threshold "high" (90) → Production systems, reduce false positives
- qod_threshold "maximum" (98) → Only verified vulnerabilities, very few results

**OPENVAS ALIVE TEST SELECTION:**
- Internal network with ICMP allowed → "icmp_tcp_ack_ping" (default)
- Firewall blocks ICMP → "tcp_syn_ping"
- Same subnet scanning → "arp_ping" (fastest)
- Stealth required → "tcp_syn_ping"
- Full coverage needed → "consider_alive" (scans all targets)

**OPENVAS AUTHENTICATED SCANNING GUIDANCE:**
- If SSH credentials available → Use "ssh_password" or "ssh_key" for Linux/Unix deep inspection
- If Windows domain credentials → Use "smb" credential for registry/file system checks
- If SNMP enabled on network devices → Use "snmp_v1_v2c" or "snmp_v3" for device interrogation
- If VMware environment → Use "esxi" credentials for hypervisor vulnerability checks
- If database access provided → Use "database" credentials for database-level scanning
- ALWAYS prefer authenticated scanning when credentials are available - it catches 3-5x more vulnerabilities

**OPENVAS SCHEDULING GUIDANCE:**
- One-time security assessment → "immediate" (default)
- Continuous monitoring → "weekly" for external, "daily" for critical internal
- Compliance maintenance → "monthly" with "high" qod_threshold
- Production windows → Schedule scans during maintenance windows

## YOUR RESPONSE
Provide a surgical, intelligent scan plan that maximizes vulnerability discovery while being appropriate for the target type.

Respond with JSON:
{{
  "target_analysis": {{
    "type": "cidr|host|internal|external|web_app|api",
    "likely_purpose": "What this target probably is (web app, API server, file server, etc)",
    "technology_guess": ["Possible technologies based on target"],
    "attack_surface": ["web", "network", "database", "authentication", "file_operations", "etc"],
    "risk_indicators": ["Specific risk factors observed"],
    "priority_vulns": ["Most likely vulnerability classes to find"]
  }},
  "scan_plan": {{
    "run_nmap": true,
    "nmap_scan_type": "service",
    "nmap_ports": null,
    "nmap_nse_scripts": ["vuln", "default"],
    "nmap_timing": "T4",
    "nmap_advanced": {{
      "version_intensity": null,
      "max_retries": null,
      "host_timeout": null,
      "scan_delay": null,
      "min_rate": null,
      "max_rate": null,
      "fragmentation": null,
      "source_port": null,
      "decoy": null,
      "reason": false,
      "traceroute": false,
      "osscan_guess": false
    }},
    "run_nmap_udp": true,
    "run_openvas": true,
    "openvas_config": "full_and_very_deep",
    "openvas_port_list": "all_tcp_udp",
    "openvas_nvt_families": ["general", "web_servers", "databases"],
    "openvas_qod_threshold": "low",
    "openvas_alive_test": "icmp_tcp_ack_ping",
    "openvas_max_hosts": "aggressive",
    "openvas_authenticated_scan": false,
    "openvas_credential_type": null,
    "openvas_schedule": "immediate",
    "openvas_alert": null,
    "run_zap": true,
    "zap_scan_policy": "maximum",
    "zap_spider_mode": "deep",
    "zap_attack_vectors": [],
    "zap_advanced_features": ["ajax_spider", "openapi_import", "graphql_import", "forced_browsing"],
    "zap_forced_browse": true,
    "zap_wordlist": "aggressive",
    "run_nuclei": true,
    "nuclei_templates": ["cves", "vulnerabilities", "exposures", "misconfigurations"],
    "run_directory_enum": false,
    "directory_wordlist": null,
    "run_exploit_mapping": true
  }},
  "authenticated_scan_recommendation": {{
    "recommended": false,
    "credential_types_needed": [],
    "reason": "Why authenticated scanning would benefit this target",
    "expected_benefit": "What additional vulnerabilities authenticated scanning would find"
  }},
  "scan_phases": [
    {{"phase": 1, "tool": "nmap", "purpose": "Initial port discovery and service detection"}},
    {{"phase": 2, "tool": "openvas", "purpose": "Deep network vulnerability scan", "condition": "if network services found"}},
    {{"phase": 3, "tool": "zap", "purpose": "Web application security testing", "condition": "if HTTP services found"}},
    {{"phase": 4, "tool": "nuclei", "purpose": "Fast CVE and signature detection"}}
  ],
  "ai_reasoning": "Detailed explanation of why these tools and configurations were selected - respect aggressive_scan preference (maximum vs thorough) unless production system",
  "risk_assessment": "low|medium|high|critical",
  "estimated_duration_minutes": 45,
  "recommendations": ["Strategic recommendations", "Alternative approaches if time permits"]
}}"""

            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="medium"),
                    max_output_tokens=2000,
                    response_mime_type="application/json",
                ),
            )
            
            result = self._parse_json_response(response.text)
            
            # Ensure required fields exist
            if "scan_plan" not in result:
                result["scan_plan"] = default_strategy["scan_plan"]
            if "target_analysis" not in result:
                result["target_analysis"] = default_strategy["target_analysis"]
            
            return result
            
        except Exception as e:
            logger.warning(f"AI scan planning failed: {e}")
            default_strategy["ai_reasoning"] = f"AI planning unavailable ({str(e)[:50]}). Using intelligent defaults."
            return default_strategy
    
    async def decide_followup_nmap(
        self,
        initial_results: List[Dict[str, Any]],
        initial_scan_type: str,
        target: str,
    ) -> Dict[str, Any]:
        """
        After initial Nmap scan, AI decides if additional scans are needed.
        
        Args:
            initial_results: Results from the first Nmap scan
            initial_scan_type: Type of scan that was run
            target: Original target
            
        Returns:
            Dict with followup scan recommendations
        """
        # Quick analysis without AI
        open_ports = []
        services_found = set()
        
        for host in initial_results:
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    open_ports.append(port.get("port"))
                    services_found.add(port.get("service", "unknown"))
        
        followup = {
            "run_additional_scan": False,
            "scan_type": None,
            "ports": None,
            "reasoning": "",
        }
        
        # Heuristic decisions
        # 1. If we found SMB/RDP, consider comprehensive scan
        critical_services = {"smb", "microsoft-ds", "rdp", "ms-wbt-server"}
        if services_found & critical_services:
            if initial_scan_type not in ["comprehensive"]:
                followup["run_additional_scan"] = True
                followup["scan_type"] = "comprehensive"
                followup["ports"] = "139,445,3389"
                followup["reasoning"] = "Critical services (SMB/RDP) detected. Running comprehensive scan for vuln scripts."
                return followup
        
        # 2. If very few ports found on a /24, might want broader scan
        if len(open_ports) < 5 and initial_scan_type in ["ping", "basic"]:
            followup["run_additional_scan"] = True
            followup["scan_type"] = "service"
            followup["reasoning"] = "Few open ports found. Running service detection for better coverage."
            return followup
        
        # 3. Use AI for complex decisions
        if self.client and len(initial_results) > 0:
            try:
                services_summary = []
                for host in initial_results[:5]:
                    ip = host.get("ip", "")
                    for port in host.get("ports", [])[:10]:
                        if port.get("state") == "open":
                            services_summary.append(
                                f"{ip}:{port['port']} - {port.get('service', '?')} {port.get('product', '')} {port.get('version', '')}"
                            )
                
                # Build NSE options for the prompt
                nse_options = "\n".join([
                    f"   - \"{k}\": {v['description']}"
                    for k, v in NMAP_NSE_SCRIPTS.items()
                ])
                
                prompt = f"""After an initial Nmap "{initial_scan_type}" scan on {target}, we found:

{chr(10).join(services_summary[:20]) or "No open ports found"}

=== AVAILABLE NSE SCRIPT CATEGORIES ===
{nse_options}

=== AVAILABLE SCAN TYPES ===
- "comprehensive": Full scan with default scripts
- "vuln": Vulnerability-focused scan
- "udp": UDP port discovery
- "udp_quick": Quick top 20 UDP ports
- "stealth": SYN-only scan for evasion
- "aggressive": Maximum detection (OS, scripts, traceroute)

Based on the discovered services, decide if additional scanning would be valuable.

Consider:
- For SMB (445): Run "smb" scripts to check EternalBlue, shares, users
- For HTTP (80/443/8080): Consider running "http" scripts for web vuln checks
- For SSL services: Run "ssl" scripts to check Heartbleed, weak ciphers
- For SSH (22): Run "ssh" scripts for auth method enumeration
- For databases: Run "database" scripts for auth checks
- If no UDP was scanned yet: Consider UDP for DNS (53), SNMP (161), TFTP (69)

Respond with JSON:
{{
  "run_additional_scan": false,
  "scan_type": "comprehensive|vuln|udp|udp_quick|stealth|aggressive|null",
  "nse_scripts": ["script categories to run, e.g., smb, http, ssl"],
  "ports": "specific ports or null for default",
  "reasoning": "Brief explanation of why this followup is needed or not needed"
}}"""

                response = self.client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        thinking_config=types.ThinkingConfig(thinking_level="medium"),
                        max_output_tokens=500,
                        response_mime_type="application/json",
                    ),
                )
                
                return self._parse_json_response(response.text)
                
            except Exception as e:
                logger.warning(f"AI followup decision failed: {e}")
        
        followup["reasoning"] = "Initial scan appears sufficient for the target."
        return followup
    
    async def analyze_recon_results(
        self,
        hosts: List[Dict[str, Any]],
        target: str,
    ) -> Dict[str, Any]:
        """
        Analyze Nmap reconnaissance results and decide which tools to use.
        
        This is the CORE AGENTIC DECISION POINT that determines:
        - Which hosts to scan with OpenVAS (network vulns)
        - Which hosts to scan with ZAP (web vulns)
        - Which specific Nuclei templates to run
        - Priority ordering of targets
        
        Args:
            hosts: List of discovered hosts with open ports
            target: Original target specification
            
        Returns:
            Dict with decisions for each scanning phase
        """
        # Classify services
        web_targets = []
        openvas_targets = []
        nuclei_targets = []
        
        for host in hosts:
            ip = host.get("ip", "")
            os_info = host.get("os", "")
            ports = host.get("ports", [])
            
            host_web_ports = []
            host_network_services = []
            
            for port_info in ports:
                if port_info.get("state") != "open":
                    continue
                
                port = port_info.get("port", 0)
                service = port_info.get("service", "").lower()
                product = port_info.get("product", "")
                version = port_info.get("version", "")
                
                # Check if it's a web service
                is_web = (
                    port in self.WEB_SERVICES or
                    any(ws in service for ws in self.WEB_SERVICE_NAMES)
                )
                
                if is_web:
                    protocol = "https" if port in [443, 8443, 9443] or "ssl" in service else "http"
                    host_web_ports.append({
                        "port": port,
                        "url": f"{protocol}://{ip}:{port}",
                        "service": service,
                        "product": product,
                        "version": version,
                    })
                
                # Check if it's an OpenVAS priority service
                if port in self.OPENVAS_PRIORITY_SERVICES:
                    service_name, priority = self.OPENVAS_PRIORITY_SERVICES[port]
                    host_network_services.append({
                        "port": port,
                        "service": service_name,
                        "priority": priority,
                        "product": product,
                        "version": version,
                    })
                elif not is_web:
                    # Unknown service - still scan with OpenVAS
                    host_network_services.append({
                        "port": port,
                        "service": service or "unknown",
                        "priority": "medium",
                        "product": product,
                        "version": version,
                    })
            
            # Build target entries
            if host_web_ports:
                web_targets.append({
                    "ip": ip,
                    "ports": host_web_ports,
                    "os": os_info,
                })
            
            if host_network_services:
                # Determine overall priority for this host
                priorities = [s["priority"] for s in host_network_services]
                if "critical" in priorities:
                    host_priority = "critical"
                elif "high" in priorities:
                    host_priority = "high"
                else:
                    host_priority = "medium"
                
                openvas_targets.append({
                    "ip": ip,
                    "services": host_network_services,
                    "priority": host_priority,
                    "os": os_info,
                })
            
            # All hosts get Nuclei CVE scanning
            nuclei_targets.append({
                "ip": ip,
                "ports": [p["port"] for p in ports if p.get("state") == "open"],
            })
        
        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        openvas_targets.sort(key=lambda x: priority_order.get(x["priority"], 2))
        
        # Use AI to refine decisions if available
        if self.client:
            ai_decisions = await self._get_ai_routing_decisions(
                hosts, web_targets, openvas_targets
            )
        else:
            ai_decisions = None
        
        return {
            "web_targets": web_targets,
            "openvas_targets": openvas_targets,
            "nuclei_targets": nuclei_targets,
            "ai_decisions": ai_decisions,
            "summary": {
                "total_hosts": len(hosts),
                "web_scan_hosts": len(web_targets),
                "openvas_scan_hosts": len(openvas_targets),
                "critical_priority": sum(1 for t in openvas_targets if t["priority"] == "critical"),
                "high_priority": sum(1 for t in openvas_targets if t["priority"] == "high"),
            },
            "recommendations": self._generate_routing_recommendations(
                web_targets, openvas_targets
            ),
        }
    
    async def _get_ai_routing_decisions(
        self,
        hosts: List[Dict[str, Any]],
        web_targets: List[Dict[str, Any]],
        openvas_targets: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Use AI to make intelligent routing decisions."""
        try:
            # Build concise summary for AI
            services_summary = []
            for host in hosts[:10]:  # Limit for token size
                ip = host.get("ip", "")
                for port in host.get("ports", [])[:10]:
                    if port.get("state") == "open":
                        services_summary.append(
                            f"{ip}:{port['port']} - {port.get('service', 'unknown')} "
                            f"({port.get('product', '')} {port.get('version', '')})"
                        )
            
            prompt = f"""You are an expert penetration tester deciding how to scan a target.

## Discovered Services
{chr(10).join(services_summary[:30])}

## Current Routing
- Web targets (for ZAP): {len(web_targets)} hosts
- Network targets (for OpenVAS): {len(openvas_targets)} hosts

Based on the discovered services, provide strategic scanning recommendations.

Respond with JSON:
{{
  "high_value_targets": [
    {{
      "host": "IP",
      "port": 445,
      "reason": "SMB service - check for EternalBlue, PrintNightmare",
      "recommended_tools": ["openvas", "nuclei"],
      "specific_checks": ["ms17-010", "CVE-2021-34527"]
    }}
  ],
  "skip_recommendations": [
    {{
      "host": "IP",
      "reason": "Appears to be a printer, low value target"
    }}
  ],
  "attack_surface_analysis": "Brief analysis of the overall attack surface",
  "recommended_scan_order": ["openvas_critical", "zap_web", "nuclei_cve"],
  "estimated_risk_level": "high/medium/low"
}}"""

            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="high"),
                    max_output_tokens=2000,
                    response_mime_type="application/json",
                ),
            )
            
            return self._parse_json_response(response.text)
            
        except Exception as e:
            logger.warning(f"AI routing decision failed: {e}")
            return None
    
    def _generate_routing_recommendations(
        self,
        web_targets: List[Dict[str, Any]],
        openvas_targets: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate human-readable recommendations."""
        recommendations = []
        
        # Critical services
        critical_hosts = [t for t in openvas_targets if t["priority"] == "critical"]
        if critical_hosts:
            services = set()
            for h in critical_hosts:
                for s in h["services"]:
                    services.add(s["service"])
            recommendations.append(
                f"🔴 CRITICAL: {len(critical_hosts)} hosts have high-risk services "
                f"({', '.join(services)}). OpenVAS scan strongly recommended."
            )
        
        # SMB specifically
        smb_hosts = [
            t for t in openvas_targets 
            if any(s["service"] == "smb" for s in t["services"])
        ]
        if smb_hosts:
            recommendations.append(
                f"⚠️ {len(smb_hosts)} hosts have SMB exposed. "
                "Check for EternalBlue (MS17-010), PrintNightmare, SMB signing."
            )
        
        # Web targets
        if web_targets:
            total_urls = sum(len(t["ports"]) for t in web_targets)
            recommendations.append(
                f"🌐 {total_urls} web endpoints found across {len(web_targets)} hosts. "
                "ZAP spider and active scan recommended."
            )
        
        # Database services
        db_hosts = [
            t for t in openvas_targets
            if any(s["service"] in ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis"]
                   for s in t["services"])
        ]
        if db_hosts:
            recommendations.append(
                f"🗄️ {len(db_hosts)} hosts have database services. "
                "Check for default credentials, auth bypass, and SQL injection."
            )
        
        return recommendations

    async def next_action(
        self,
        state: Dict[str, Any],
        max_retries: int = 2,
    ) -> Dict[str, Any]:
        """
        Decide the next agentic action based on current scan state.

        Args:
            state: Dict with current scan state, history, tool availability, and constraints
            max_retries: Number of attempts to recover from invalid JSON
        """
        self._require_client()

        action_list = sorted(AGENT_ACTIONS.keys())
        action_schema = {
            name: {
                "parameters": AGENT_ACTIONS[name]["parameters"],
                "use_case": AGENT_ACTIONS[name]["use_case"],
            }
            for name in action_list
        }

        prompt = f"""You are an autonomous security scanning agent orchestrating a multi-tool assessment.

RULES:
- Output ONLY valid JSON matching the schema below.
- Choose exactly one action per step.
- Respect tool availability and constraints in the provided state.
- Do not repeat actions with identical parameters already attempted.
- Prefer high-signal actions that increase coverage or validate high-risk findings.
- Use short, concrete reasoning (1-3 bullets).

SCHEMA:
{{
  "action": "<one of {', '.join(action_list)}>",
  "parameters": {{ ... }},
  "reason": ["short bullet", "short bullet"],
  "expected_signal": "what new evidence this action should produce",
  "plan_update": ["optional plan step", "optional plan step"],
  "stop_reason": "only when action is stop"
}}

AVAILABLE ACTIONS:
{json.dumps(action_schema, indent=2)}

CURRENT STATE:
{json.dumps(state, indent=2)}
"""

        last_error = None
        for attempt in range(max_retries + 1):
            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="medium"),
                    max_output_tokens=1200,
                    response_mime_type="application/json",
                ),
            )
            try:
                result = self._parse_json_response(response.text)
                result = self._validate_action_payload(result)
                return result
            except Exception as e:
                last_error = e
                prompt = f"""Return ONLY valid JSON that matches the schema.
Previous response (invalid JSON):
{response.text}
Error: {e}
Schema reminder:
{{
  "action": "<one of {', '.join(action_list)}>",
  "parameters": {{ ... }},
  "reason": ["short bullet"],
  "expected_signal": "string",
  "plan_update": ["optional"],
  "stop_reason": "only when action is stop"
}}
"""

        raise RuntimeError(f"Failed to obtain valid agent action: {last_error}")
    
    async def analyze_scan_results(self, scan_result) -> Dict[str, Any]:
        """
        Analyze complete scan results and generate attack narrative.
        
        Args:
            scan_result: DynamicScanResult dataclass
            
        Returns:
            Dict with executive_summary, attack_narrative, exploit_chains, recommendations, commands
        """
        self._require_client()
        
        try:
            # Prepare findings summary
            findings_summary = self._prepare_findings_summary(scan_result)
            
            # Build the prompt
            prompt = self._build_analysis_prompt(scan_result, findings_summary)
            
            last_error = None
            for attempt in range(2):
                response = self.client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        thinking_config=types.ThinkingConfig(thinking_level="high"),
                        max_output_tokens=8000,
                        response_mime_type="application/json",
                    ),
                )
                try:
                    result = self._parse_json_response(response.text)
                    result = self._validate_analysis_payload(result)
                    return {
                        "executive_summary": result.get("executive_summary", ""),
                        "attack_narrative": result.get("attack_narrative", ""),
                        "risk_summary": result.get("risk_summary", ""),
                        "exploit_chains": result.get("exploit_chains", []),
                        "recommendations": result.get("recommendations", []),
                        "commands": result.get("commands", {}),
                        "priority_targets": result.get("priority_targets", []),
                    }
                except Exception as e:
                    last_error = e
                    prompt = f"""Return ONLY valid JSON with keys:
executive_summary, attack_narrative, risk_summary, exploit_chains, recommendations, commands, priority_targets.
Previous response:
{response.text}
Error: {e}
"""
            raise RuntimeError(f"AI analysis JSON invalid: {last_error}")
            
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            raise
    
    def _prepare_findings_summary(self, scan_result) -> Dict[str, Any]:
        """Prepare a summary of findings for the AI prompt."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        source_counts = {"nmap": 0, "zap": 0, "nuclei": 0}
        exploitable_count = 0
        cve_list = []
        
        for finding in scan_result.findings:
            sev = finding.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            
            if finding.source in source_counts:
                source_counts[finding.source] += 1
            
            if finding.exploit_available:
                exploitable_count += 1
            
            if finding.cve_id:
                cve_list.append(finding.cve_id)
        
        return {
            "total_findings": len(scan_result.findings),
            "severity_breakdown": severity_counts,
            "source_breakdown": source_counts,
            "exploitable_findings": exploitable_count,
            "unique_cves": list(set(cve_list)),
            "hosts_scanned": len(scan_result.hosts),
            "web_targets": len(scan_result.web_targets),
            "network_targets": len(scan_result.network_targets),
        }
    
    def _build_analysis_prompt(self, scan_result, summary: Dict[str, Any]) -> str:
        """Build the AI analysis prompt."""
        
        # Get top findings (limit for token size)
        critical_high = [
            f for f in scan_result.findings 
            if f.severity.lower() in ["critical", "high"]
        ][:20]
        
        # Get medium findings too for context when no critical/high
        medium = [
            f for f in scan_result.findings 
            if f.severity.lower() == "medium"
        ][:15]
        
        exploitable = [
            f for f in scan_result.findings 
            if f.exploit_available
        ][:10]
        
        # Format findings for prompt - include medium if no critical/high
        findings_text = ""
        findings_to_show = critical_high if critical_high else medium
        if not findings_to_show:
            findings_to_show = scan_result.findings[:15]  # Show whatever we have
        
        for f in findings_to_show[:15]:
            findings_text += f"""
- **{f.severity.upper()}**: {f.title}
  - Host: {f.host}:{f.port or 'N/A'}
  - URL: {f.url or 'N/A'}
  - Source: {f.source}
  - CVE: {f.cve_id or 'N/A'}
  - Exploit Available: {f.exploit_available}
  - Description: {(f.description or '')[:200]}
"""
        
        # Format hosts
        hosts_text = ""
        for h in scan_result.hosts[:10]:
            open_ports = [p for p in h.ports if p.get("state") == "open"]
            ports_str = ", ".join([f"{p['port']}/{p.get('service', '?')}" for p in open_ports[:10]])
            hosts_text += f"- {h.ip} ({h.os or 'Unknown OS'}): {ports_str}\n"
        
        # Check if this is a no-findings scenario
        no_findings = summary['total_findings'] == 0
        
        prompt = f"""You are an expert penetration tester writing a professional security assessment report.
Generate a comprehensive attack narrative and exploitation guidance based on the scan results.

## Scan Summary

**Target:** {scan_result.target}
**Hosts Discovered:** {summary['hosts_scanned']}
**Web Targets:** {summary['web_targets']}
**Total Findings:** {summary['total_findings']}

**Severity Breakdown:**
- Critical: {summary['severity_breakdown']['critical']}
- High: {summary['severity_breakdown']['high']}
- Medium: {summary['severity_breakdown']['medium']}
- Low: {summary['severity_breakdown']['low']}

**Findings by Source:**
- Nmap (recon): {summary['source_breakdown'].get('nmap', 0)}
- ZAP (web vulns): {summary['source_breakdown'].get('zap', 0)}
- Nuclei (CVEs): {summary['source_breakdown'].get('nuclei', 0)}

**Exploitable Findings (with known CVEs):** {summary['exploitable_findings']}
**CVEs Found:** {', '.join(summary['unique_cves'][:10]) or 'None - scan found vulnerability patterns, not CVE-specific issues'}

## Discovered Hosts

{hosts_text or 'Web application target - no network reconnaissance performed.'}

## Findings

{findings_text or 'No findings detected by automated scanning.'}

## IMPORTANT INSTRUCTIONS

{'**NO FINDINGS SCENARIO**: The scan completed but found no vulnerabilities. Generate a report explaining this result, what was tested, and recommendations for deeper manual testing.' if no_findings else ''}

{'**NO CVE SCENARIO**: Even though no specific CVEs were found, the scan detected vulnerability PATTERNS (XSS vectors, injection points, misconfigurations, etc.). These are REAL security issues that can be exploited. Write the narrative focusing on these vulnerability types and how an attacker would exploit them.' if not summary['unique_cves'] and summary['total_findings'] > 0 else ''}

{'**CVE SCENARIO**: CVEs were found. Incorporate these specific CVEs into the attack narrative, describe known exploits, and prioritize based on exploitability.' if summary['unique_cves'] else ''}

## Your Task

Generate a JSON response with the following structure:

{{
  "executive_summary": "A 2-3 paragraph executive summary suitable for management. Summarize the overall security posture, key risks identified, and high-level recommendations. Use professional language. If no findings, explain what was tested and why no issues were found (or recommend manual testing).",
  
  "attack_narrative": "A detailed 3-5 paragraph attack narrative written from an offensive security perspective. Describe how an attacker would approach this target, what reconnaissance reveals, which vulnerabilities would be prioritized, and the potential attack path from initial access to impact. Be specific about the findings even if they're not CVE-related - XSS, CORS, header issues, etc. are all exploitable. If no findings, describe what attack surfaces were tested and why they appear secure.",
  
  "risk_summary": "One paragraph summary: Overall risk level (Critical/High/Medium/Low), number of issues by severity, key concerns, and immediate actions needed.",
  
  "exploit_chains": [
    {{
      "name": "Chain name describing the attack path",
      "description": "How this attack chain works step by step",
      "steps": ["Step 1: Initial reconnaissance", "Step 2: Exploit X", "Step 3: Achieve Y"],
      "impact": "What access/data/damage this achieves",
      "likelihood": "high/medium/low",
      "findings_used": ["Relevant finding titles or CVEs"]
    }}
  ],
  
  "priority_targets": [
    {{
      "host": "IP/hostname",
      "port": 80,
      "reason": "Why this is high priority - be specific",
      "attack_vector": "How to attack it"
    }}
  ],
  
  "commands": {{
    "curl": ["Manual verification and exploitation commands"],
    "sqlmap": ["SQL injection testing commands if relevant"],
    "xsstrike": ["XSS testing commands if XSS found"],
    "nuclei": ["Follow-up nuclei scans for deeper testing"],
    "nmap": ["Additional reconnaissance commands"],
    "metasploit": ["Metasploit modules if CVEs found"],
    "other": ["Any other useful commands"]
  }},
  
  "recommendations": [
    "Prioritized, actionable recommendation 1 - be specific about what to fix",
    "Prioritized, actionable recommendation 2",
    "Prioritized, actionable recommendation 3"
  ]
}}

CRITICAL RULES:
1. ALWAYS generate meaningful content even if no CVEs are found - web vulnerability patterns ARE exploitable
2. If no findings at all, explain what was tested and recommend manual testing approaches
3. Be specific about the actual vulnerabilities found, don't be generic
4. Include realistic, copy-paste ready commands for the specific findings
5. The executive_summary should be professional and suitable for non-technical readers
6. The attack_narrative should be technical and detailed for security professionals

Return ONLY valid JSON, no markdown formatting."""

        return prompt
    
    def _generate_fallback_analysis(self, scan_result) -> Dict[str, Any]:
        """Generate basic analysis without AI."""
        
        # Count findings
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in scan_result.findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        total_findings = len(scan_result.findings)
        
        # Handle no findings scenario
        if total_findings == 0:
            return {
                "executive_summary": f"The security scan of {scan_result.target} completed successfully with no vulnerabilities detected by automated scanning tools. While this is a positive result, it does not guarantee the absence of security issues. Manual penetration testing and code review are recommended to identify vulnerabilities that automated tools may miss.",
                "attack_narrative": f"Initial reconnaissance of {scan_result.target} was performed using automated security scanning tools. The scan completed successfully but did not identify any significant vulnerabilities. This could indicate a well-secured application, or it may suggest that deeper manual testing is required to uncover issues that automated tools cannot detect. Recommended next steps include manual testing of authentication flows, business logic vulnerabilities, and authorization controls.",
                "risk_summary": "LOW RISK - No vulnerabilities detected by automated scanning. Manual testing recommended for comprehensive assessment.",
                "exploit_chains": [],
                "recommendations": [
                    "Conduct manual penetration testing to identify business logic flaws",
                    "Perform authenticated scanning if credentials are available",
                    "Review application source code for security issues",
                    "Test for authorization and access control vulnerabilities manually"
                ],
                "commands": {},
                "priority_targets": [],
            }
        
        # Build narrative parts
        narrative_parts = []
        executive_parts = []
        
        if scan_result.hosts:
            narrative_parts.append(
                f"Reconnaissance discovered {len(scan_result.hosts)} live hosts on target {scan_result.target}."
            )
            executive_parts.append(
                f"The security assessment of {scan_result.target} identified {len(scan_result.hosts)} hosts with {total_findings} security findings."
            )
        else:
            narrative_parts.append(
                f"Web application scan of {scan_result.target} identified {total_findings} security findings."
            )
            executive_parts.append(
                f"The security assessment of {scan_result.target} identified {total_findings} potential security issues requiring attention."
            )
        
        if severity_counts["critical"] > 0:
            narrative_parts.append(
                f"**CRITICAL RISK**: {severity_counts['critical']} critical vulnerabilities detected requiring immediate attention."
            )
            executive_parts.append(
                f"URGENT: {severity_counts['critical']} critical-severity vulnerabilities were identified that pose immediate risk and require emergency remediation."
            )
        
        if severity_counts["high"] > 0:
            narrative_parts.append(
                f"{severity_counts['high']} high-severity issues identified that could enable unauthorized access."
            )
            executive_parts.append(
                f"{severity_counts['high']} high-severity issues should be addressed within the next 7 days."
            )
        
        if severity_counts["medium"] > 0:
            narrative_parts.append(
                f"{severity_counts['medium']} medium-severity findings detected including potential misconfigurations and security weaknesses."
            )
            executive_parts.append(
                f"{severity_counts['medium']} medium-severity findings should be reviewed and addressed in the near term."
            )
        
        exploitable = [f for f in scan_result.findings if f.exploit_available]
        if exploitable:
            narrative_parts.append(
                f"**{len(exploitable)} findings have known public exploits available**, making them high-priority targets for attackers."
            )
            executive_parts.append(
                f"Of particular concern, {len(exploitable)} vulnerabilities have publicly available exploits."
            )
        
        # Generate basic commands
        commands = {}
        
        # Add nmap follow-up
        if scan_result.hosts:
            first_host = scan_result.hosts[0].ip
            commands["nmap"] = [
                f"nmap -sV -sC -p- {first_host} -oA detailed_scan",
                f"nmap --script vuln {first_host}",
            ]
        
        # Add metasploit for known CVEs
        msf_commands = []
        for f in scan_result.findings:
            if f.cve_id and f.exploit_available and f.exploit_info:
                msf_module = f.exploit_info.get("msf_module")
                if msf_module:
                    msf_commands.append(f"use {msf_module}\nset RHOSTS {f.host}\nrun")
        
        if msf_commands:
            commands["metasploit"] = msf_commands[:5]
        
        # Build exploit chains from critical findings
        exploit_chains = []
        for f in scan_result.findings:
            if f.severity.lower() == "critical" and f.exploit_available:
                exploit_chains.append({
                    "name": f"Exploit {f.title}",
                    "description": f.description[:200] if f.description else "Critical vulnerability",
                    "steps": [
                        "Verify vulnerability exists",
                        "Prepare exploit payload",
                        "Execute exploit against target",
                        "Establish persistence if successful",
                    ],
                    "impact": "Potential system compromise",
                    "likelihood": "high",
                    "findings_used": [f.cve_id or f.title],
                })
        
        # Build recommendations
        recommendations = []
        if severity_counts["critical"] > 0:
            recommendations.append("URGENT: Immediately patch or mitigate critical vulnerabilities - these pose immediate risk of compromise")
        if severity_counts["high"] > 0:
            recommendations.append("Address high-severity findings within 7 days to prevent potential unauthorized access")
        if severity_counts["medium"] > 0:
            recommendations.append("Review and remediate medium-severity issues within 30 days")
        recommendations.append("Conduct follow-up manual penetration testing on identified attack surfaces")
        recommendations.append("Review network segmentation and access controls to limit potential lateral movement")
        recommendations.append("Implement regular vulnerability scanning as part of ongoing security operations")
        
        return {
            "executive_summary": " ".join(executive_parts) if executive_parts else f"Security scan of {scan_result.target} completed. Review findings below.",
            "attack_narrative": " ".join(narrative_parts) if narrative_parts else f"Security scan of {scan_result.target} completed with {total_findings} findings identified.",
            "risk_summary": f"{'CRITICAL' if severity_counts['critical'] > 0 else 'HIGH' if severity_counts['high'] > 0 else 'MEDIUM' if severity_counts['medium'] > 0 else 'LOW'} RISK - Scan identified {total_findings} total findings: {severity_counts['critical']} critical, {severity_counts['high']} high, {severity_counts['medium']} medium, {severity_counts['low']} low severity issues.",
            "exploit_chains": exploit_chains[:5],
            "recommendations": recommendations,
            "commands": commands,
            "priority_targets": [
                {
                    "host": f.host,
                    "port": f.port,
                    "reason": f.title,
                    "attack_vector": f.source,
                }
                for f in scan_result.findings
                if f.severity.lower() in ["critical", "high"]
            ][:5],
        }
    
    async def suggest_next_steps(
        self,
        scan_result,
        current_phase: str,
    ) -> Dict[str, Any]:
        """
        AI suggests what to do next based on current scan state.
        Used for interactive/step-by-step scanning.
        """
        if not self.client:
            return {"suggestion": "Continue with automated scanning", "commands": []}
        
        try:
            # Brief summary for quick suggestions
            open_ports = []
            for h in scan_result.hosts:
                for p in h.ports:
                    if p.get("state") == "open":
                        open_ports.append(f"{h.ip}:{p['port']} ({p.get('service', 'unknown')})")
            
            prompt = f"""You are a penetration testing assistant. Based on the current scan state, suggest the next action.

Current Phase: {current_phase}
Target: {scan_result.target}
Hosts Found: {len(scan_result.hosts)}
Open Services: {', '.join(open_ports[:20])}
Findings So Far: {len(scan_result.findings)}

Respond with JSON:
{{
  "suggestion": "Brief description of recommended next step",
  "reason": "Why this is the best next step",
  "commands": ["Specific commands to run"],
  "skip_phases": ["Phases that can be skipped based on results"]
}}"""

            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="high"),
                    max_output_tokens=1000,
                    response_mime_type="application/json",
                ),
            )
            
            return json.loads(response.text)
            
        except Exception as e:
            logger.error(f"AI suggestion failed: {e}")
            return {
                "suggestion": "Continue with the next phase",
                "commands": [],
            }
    
    async def explain_finding(self, finding) -> str:
        """Generate a detailed explanation of a specific finding."""
        if not self.client:
            return finding.description or "No detailed explanation available."
        
        try:
            prompt = f"""Explain this security vulnerability finding in detail for a penetration tester:

**Vulnerability:** {finding.title}
**Severity:** {finding.severity}
**Host:** {finding.host}:{finding.port or 'N/A'}
**CVE:** {finding.cve_id or 'N/A'}
**Source Scanner:** {finding.source}
**Evidence:** {finding.evidence or 'N/A'}

Provide:
1. What this vulnerability is and how it works
2. Why it's dangerous (potential impact)
3. How to exploit it (ethical pentesting context)
4. How to verify/confirm it manually
5. Remediation steps

Keep the response concise but informative (2-3 paragraphs)."""

            response = self.client.models.generate_content(
                model=self.model_id,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="high"),
                    max_output_tokens=1500,
                ),
            )
            
            return response.text
            
        except Exception as e:
            logger.error(f"Finding explanation failed: {e}")
            return finding.description or "Explanation unavailable."
