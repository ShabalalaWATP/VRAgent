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
from defusedxml import ElementTree as ET  # Use defusedxml to prevent XXE attacks
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


# High-risk ports that should be flagged (expanded list)
HIGH_RISK_PORTS = {
    # Remote Access - Critical
    21: ("FTP", "high", "FTP often transmits credentials in cleartext"),
    22: ("SSH", "info", "SSH - verify strong authentication is required"),
    23: ("Telnet", "critical", "Telnet transmits all data including credentials in cleartext"),
    512: ("rexec", "critical", "Remote execution without encryption"),
    513: ("rlogin", "critical", "Remote login without encryption"),
    514: ("rsh", "critical", "Remote shell without encryption"),
    3389: ("RDP", "high", "Remote Desktop - common brute force target"),
    5900: ("VNC", "high", "VNC often has weak authentication"),
    5901: ("VNC-1", "high", "VNC display :1 - often weak authentication"),
    5902: ("VNC-2", "high", "VNC display :2 - often weak authentication"),
    5985: ("WinRM-HTTP", "high", "Windows Remote Management over HTTP"),
    5986: ("WinRM-HTTPS", "medium", "Windows Remote Management over HTTPS"),
    
    # Mail Services
    25: ("SMTP", "medium", "SMTP may allow mail relay if misconfigured"),
    110: ("POP3", "high", "POP3 transmits credentials in cleartext"),
    143: ("IMAP", "high", "IMAP may transmit credentials in cleartext"),
    465: ("SMTPS", "info", "SMTP over SSL - verify configuration"),
    587: ("Submission", "medium", "Mail submission - verify authentication"),
    993: ("IMAPS", "info", "IMAP over SSL"),
    995: ("POP3S", "info", "POP3 over SSL"),
    
    # DNS/Directory
    53: ("DNS", "medium", "DNS may be vulnerable to cache poisoning or zone transfers"),
    389: ("LDAP", "medium", "LDAP may expose directory information"),
    636: ("LDAPS", "medium", "LDAP over SSL - still may expose directory info"),
    
    # Windows/NetBIOS/SMB
    135: ("MSRPC", "high", "Windows RPC - often targeted for exploits"),
    137: ("NetBIOS-NS", "high", "NetBIOS can leak system information"),
    138: ("NetBIOS-DGM", "high", "NetBIOS datagram service"),
    139: ("NetBIOS-SSN", "high", "NetBIOS session service - SMB over NetBIOS"),
    445: ("SMB", "high", "SMB - common target for ransomware and exploits (EternalBlue, WannaCry)"),
    
    # SNMP
    161: ("SNMP", "high", "SNMP often uses weak community strings (public/private)"),
    162: ("SNMP-Trap", "medium", "SNMP trap receiver - may leak information"),
    
    # Databases - Critical exposure
    1433: ("MSSQL", "high", "Microsoft SQL Server - verify authentication"),
    1434: ("MSSQL-Browser", "high", "MSSQL Browser service - can enumerate instances"),
    1521: ("Oracle", "high", "Oracle database - verify authentication"),
    1830: ("Oracle-XDB", "high", "Oracle XML DB - often misconfigured"),
    3306: ("MySQL", "high", "MySQL database - verify authentication"),
    5432: ("PostgreSQL", "medium", "PostgreSQL database"),
    6379: ("Redis", "critical", "Redis often has no authentication by default"),
    9042: ("Cassandra", "high", "Cassandra database - verify authentication"),
    9200: ("Elasticsearch", "critical", "Elasticsearch often has no authentication"),
    9300: ("Elasticsearch-Transport", "critical", "Elasticsearch transport - internal"),
    11211: ("Memcached", "critical", "Memcached - often no authentication, DDoS amplification"),
    27017: ("MongoDB", "critical", "MongoDB often has no authentication by default"),
    27018: ("MongoDB-Shard", "critical", "MongoDB shard server"),
    28017: ("MongoDB-Web", "critical", "MongoDB web interface - often exposed"),
    5984: ("CouchDB", "high", "CouchDB - verify authentication"),
    
    # RPC/NFS
    111: ("RPC", "high", "RPC services can expose internal network information"),
    2049: ("NFS", "high", "NFS can expose file systems if misconfigured"),
    
    # Web/Proxy
    80: ("HTTP", "info", "HTTP - check for sensitive data exposure"),
    443: ("HTTPS", "info", "HTTPS - verify TLS configuration"),
    8080: ("HTTP-Proxy", "medium", "HTTP proxy or alternative web server"),
    8443: ("HTTPS-Alt", "info", "Alternative HTTPS port"),
    8000: ("HTTP-Alt", "medium", "Alternative HTTP - often development servers"),
    8888: ("HTTP-Alt", "medium", "Alternative HTTP - often Jupyter/dev servers"),
    3000: ("Node/Dev", "medium", "Common Node.js/development server port"),
    
    # Container/Orchestration - Critical if exposed
    2375: ("Docker-API", "critical", "Docker API unencrypted - full container control"),
    2376: ("Docker-TLS", "high", "Docker API with TLS - verify certificates"),
    2377: ("Docker-Swarm", "critical", "Docker Swarm manager - cluster control"),
    4243: ("Docker-Alt", "critical", "Alternative Docker API port"),
    6443: ("K8s-API", "critical", "Kubernetes API server - cluster control"),
    10250: ("Kubelet", "critical", "Kubernetes Kubelet API - node control"),
    10255: ("Kubelet-RO", "high", "Kubernetes Kubelet read-only"),
    
    # Message Queues
    5672: ("AMQP", "high", "RabbitMQ/AMQP - verify authentication"),
    15672: ("RabbitMQ-Mgmt", "high", "RabbitMQ management interface"),
    61616: ("ActiveMQ", "high", "Apache ActiveMQ - verify authentication"),
    9092: ("Kafka", "high", "Apache Kafka broker"),
    
    # Build/CI/CD
    8081: ("Nexus/Artifactory", "medium", "Repository manager - may expose artifacts"),
    8082: ("Nexus-Docker", "medium", "Nexus Docker registry"),
    50000: ("Jenkins-Agent", "high", "Jenkins agent port - may allow code execution"),
    
    # Other Services
    79: ("Finger", "high", "Finger protocol - user enumeration"),
    69: ("TFTP", "high", "TFTP - no authentication, file exposure"),
    514: ("Syslog", "medium", "Syslog - may leak sensitive logs"),
    1099: ("Java-RMI", "critical", "Java RMI - often vulnerable to deserialization"),
    1100: ("Java-RMI-Alt", "critical", "Java RMI alternate port"),
    8009: ("AJP", "critical", "Apache JServ Protocol - Ghostcat vulnerability"),
    9001: ("Supervisor", "high", "Supervisord - process control"),
    9090: ("Prometheus", "medium", "Prometheus metrics - information disclosure"),
    9100: ("JetDirect", "medium", "HP JetDirect printer - often misconfigured"),
    11211: ("Memcached", "critical", "Memcached - DDoS amplification vector"),
    
    # VoIP/Media
    5060: ("SIP", "medium", "SIP signaling - VoIP"),
    5061: ("SIP-TLS", "info", "SIP over TLS"),
    554: ("RTSP", "medium", "RTSP streaming - verify authentication"),
}


# Known vulnerable service versions (product -> version pattern -> CVE/description)
VULNERABLE_VERSIONS = {
    "openssh": [
        (r"OpenSSH[_ ]([0-6]\.|7\.[0-3])", "high", "OpenSSH < 7.4 - Multiple vulnerabilities including user enumeration (CVE-2016-6210)"),
        (r"OpenSSH[_ ]7\.[4-6]", "medium", "OpenSSH 7.4-7.6 - Check for CVE-2017-15906 (readonly bypass)"),
        (r"OpenSSH[_ ]8\.[0-4]", "medium", "OpenSSH 8.0-8.4 - CVE-2021-28041 double-free vulnerability"),
        (r"OpenSSH[_ ]9\.0", "low", "OpenSSH 9.0 - CVE-2023-38408 PKCS#11 vulnerability in ssh-agent"),
        (r"OpenSSH[_ ]9\.[0-6]", "medium", "OpenSSH 9.x - CVE-2024-6387 RegreSSHion race condition RCE (check specific version)"),
    ],
    "apache": [
        (r"Apache[/ ]2\.4\.([0-9]|[1-3][0-9]|4[0-9])(?![0-9])", "high", "Apache < 2.4.50 - Multiple vulnerabilities including path traversal (CVE-2021-41773, CVE-2021-42013)"),
        (r"Apache[/ ]2\.4\.(50|51|52)", "medium", "Apache 2.4.50-2.4.52 - CVE-2022-22719, CVE-2022-22720, CVE-2022-22721"),
        (r"Apache[/ ]2\.4\.5[3-4]", "medium", "Apache 2.4.53-2.4.54 - CVE-2022-31813 mod_proxy X-Forwarded-For bypass"),
        (r"Apache[/ ]2\.2\.", "high", "Apache 2.2.x - End of life, multiple known vulnerabilities"),
    ],
    "nginx": [
        (r"nginx/1\.([0-9]|1[0-7])\.", "medium", "nginx < 1.18 - Multiple vulnerabilities"),
        (r"nginx/1\.18\.[0-1]", "low", "nginx 1.18.x - CVE-2021-23017 DNS resolver vulnerability"),
        (r"nginx/1\.(19|20|21)\.", "low", "nginx 1.19-1.21 - Check for HTTP/2 vulnerabilities"),
        (r"nginx/0\.", "high", "nginx 0.x - Very old, multiple vulnerabilities"),
    ],
    "mysql": [
        (r"MySQL[/ ]5\.[0-5]\.", "high", "MySQL 5.0-5.5 - End of life, multiple vulnerabilities"),
        (r"MySQL[/ ]5\.6\.", "medium", "MySQL 5.6 - Consider upgrading, EOL"),
        (r"MySQL[/ ]5\.7\.([0-2][0-9]|3[0-5])", "medium", "MySQL 5.7 < 5.7.36 - Multiple CVEs including privilege escalation"),
        (r"MySQL[/ ]8\.0\.([0-2][0-9])", "medium", "MySQL 8.0 < 8.0.30 - Multiple security fixes in later versions"),
        (r"MariaDB[/ ]5\.", "high", "MariaDB 5.x - Very old, multiple vulnerabilities"),
        (r"MariaDB[/ ]10\.[0-3]\.", "medium", "MariaDB 10.0-10.3 - End of life"),
    ],
    "microsoft-ds": [
        (r"Windows Server 200[38]", "critical", "Windows Server 2003/2008 - End of life, EternalBlue vulnerable"),
        (r"Windows XP", "critical", "Windows XP - End of life, critical vulnerabilities"),
        (r"Windows 7", "high", "Windows 7 - End of life since Jan 2020"),
        (r"Windows Server 2012", "high", "Windows Server 2012 - End of life Oct 2023"),
        (r"Windows 8\.1", "high", "Windows 8.1 - End of life Jan 2023"),
    ],
    "proftpd": [
        (r"ProFTPD[/ ]1\.[23]\.", "critical", "ProFTPD < 1.3.6 - Multiple critical vulnerabilities including backdoor"),
        (r"ProFTPD[/ ]1\.3\.[0-5]", "high", "ProFTPD < 1.3.6 - CVE-2019-12815 mod_copy vulnerability"),
    ],
    "vsftpd": [
        (r"vsftpd[/ ]2\.3\.4", "critical", "vsftpd 2.3.4 - Backdoor vulnerability (CVE-2011-2523)"),
        (r"vsftpd[/ ]2\.[0-3]", "medium", "vsftpd 2.x - Consider upgrading to 3.x"),
    ],
    "exim": [
        (r"Exim[/ ]4\.([0-8][0-9]|9[0-1])", "critical", "Exim < 4.92 - Multiple RCE vulnerabilities (CVE-2019-15846)"),
        (r"Exim[/ ]4\.9[2-4]", "high", "Exim 4.92-4.94 - CVE-2020-28007 to CVE-2020-28026 (21Nails)"),
    ],
    "postfix": [
        (r"Postfix[/ ]2\.", "medium", "Postfix 2.x - Consider upgrading"),
        (r"Postfix[/ ]3\.[0-4]\.", "low", "Postfix 3.0-3.4 - Check for security updates"),
    ],
    "iis": [
        (r"IIS[/ ]([5-7])\.", "high", "IIS 5-7 - Multiple known vulnerabilities"),
        (r"IIS[/ ]8\.[05]", "medium", "IIS 8.x - Check for HTTP/2 vulnerabilities"),
        (r"IIS[/ ]10\.0", "low", "IIS 10 - Ensure latest patches applied"),
    ],
    "tomcat": [
        (r"Tomcat[/ ]([5-7])\.", "high", "Tomcat 5-7 - End of life, multiple vulnerabilities"),
        (r"Tomcat[/ ]8\.[0-4]\.", "medium", "Tomcat 8.0-8.4 - Consider upgrading"),
        (r"Tomcat[/ ]9\.0\.([0-4][0-9]|5[0-9]|6[0-5])", "medium", "Tomcat 9.0 < 9.0.65 - CVE-2022-42252 request smuggling"),
        (r"Tomcat[/ ]10\.0\.([0-1][0-9]|2[0-3])", "medium", "Tomcat 10.0 < 10.0.23 - CVE-2022-42252"),
    ],
    "php": [
        (r"PHP[/ ]5\.", "high", "PHP 5.x - End of life, multiple vulnerabilities"),
        (r"PHP[/ ]7\.[0-3]\.", "medium", "PHP 7.0-7.3 - End of life"),
        (r"PHP[/ ]7\.4\.([0-2][0-9])", "low", "PHP 7.4 < 7.4.30 - Multiple security fixes in later versions"),
        (r"PHP[/ ]8\.0\.([0-1][0-9]|2[0-2])", "low", "PHP 8.0 < 8.0.23 - Multiple security fixes"),
        (r"PHP[/ ]8\.1\.([0-9]|1[0-1])", "low", "PHP 8.1 < 8.1.12 - Multiple security fixes"),
    ],
    "openssl": [
        (r"OpenSSL[/ ]0\.", "critical", "OpenSSL 0.x - Heartbleed and many other vulnerabilities"),
        (r"OpenSSL[/ ]1\.0\.[01]", "high", "OpenSSL 1.0.0-1.0.1 - Multiple vulnerabilities including Heartbleed (CVE-2014-0160)"),
        (r"OpenSSL[/ ]1\.0\.2[a-t]", "medium", "OpenSSL 1.0.2 < 1.0.2u - Multiple CVEs, EOL Dec 2019"),
        (r"OpenSSL[/ ]1\.1\.0", "medium", "OpenSSL 1.1.0 - EOL, upgrade to 1.1.1 or 3.x"),
        (r"OpenSSL[/ ]1\.1\.1[a-n]", "low", "OpenSSL 1.1.1 < 1.1.1o - Check for recent CVEs"),
        (r"OpenSSL[/ ]3\.0\.[0-6]", "medium", "OpenSSL 3.0 < 3.0.7 - CVE-2022-3602, CVE-2022-3786 buffer overflows"),
    ],
    "redis": [
        (r"Redis[/ ]([0-5])\.", "high", "Redis < 6 - Consider upgrading, check for auth"),
        (r"Redis[/ ]6\.[0-1]\.", "medium", "Redis 6.0-6.1 - CVE-2021-32625 to CVE-2021-32761"),
        (r"Redis[/ ]7\.0\.[0-4]", "medium", "Redis 7.0 < 7.0.5 - CVE-2022-35951 integer overflow"),
    ],
    "elasticsearch": [
        (r"Elasticsearch[/ ]([0-6])\.", "high", "Elasticsearch < 7 - Multiple vulnerabilities, check authentication"),
        (r"Elasticsearch[/ ]7\.([0-9]|1[0-5])\.", "medium", "Elasticsearch 7 < 7.16 - Log4j vulnerability (CVE-2021-44228)"),
        (r"Elasticsearch[/ ]8\.[0-5]\.", "low", "Elasticsearch 8 < 8.6 - Check for security updates"),
    ],
    "jenkins": [
        (r"Jenkins[/ ]([01]\.|2\.[0-9]{1,2}(?![0-9]))", "high", "Jenkins < 2.100 - Multiple vulnerabilities"),
        (r"Jenkins[/ ]2\.(1[0-9]{2}|2[0-9]{2}|3[0-2][0-9])", "medium", "Jenkins < 2.330 - Multiple CVEs"),
        (r"Jenkins[/ ]2\.(3[3-5][0-9]|36[0-5])", "low", "Jenkins < 2.366 - Check for security updates"),
    ],
    "mongodb": [
        (r"MongoDB[/ ]([0-3])\.", "high", "MongoDB < 4 - Multiple vulnerabilities, consider upgrading"),
        (r"MongoDB[/ ]4\.[0-2]\.", "medium", "MongoDB 4.0-4.2 - CVE-2020-7928 to CVE-2020-7929"),
        (r"MongoDB[/ ]4\.[4-6]\.", "low", "MongoDB 4.4-4.6 - Check for authentication, security updates"),
    ],
    "postgresql": [
        (r"PostgreSQL[/ ]([0-9]|1[0-1])\.", "high", "PostgreSQL < 12 - Multiple EOL versions with known CVEs"),
        (r"PostgreSQL[/ ]12\.([0-9]|1[0-2])", "medium", "PostgreSQL 12 < 12.13 - Multiple security fixes"),
        (r"PostgreSQL[/ ]13\.([0-8])", "low", "PostgreSQL 13 < 13.9 - Multiple security fixes"),
        (r"PostgreSQL[/ ]14\.([0-5])", "low", "PostgreSQL 14 < 14.6 - Multiple security fixes"),
    ],
    "rabbitmq": [
        (r"RabbitMQ[/ ]3\.([0-7])\.", "high", "RabbitMQ < 3.8 - Multiple vulnerabilities"),
        (r"RabbitMQ[/ ]3\.(8|9)\.[0-9]", "medium", "RabbitMQ 3.8-3.9 - CVE-2021-32718, CVE-2021-32719"),
    ],
    "docker": [
        (r"Docker[/ ]1[0-8]\.", "high", "Docker < 19 - Multiple container escape vulnerabilities"),
        (r"Docker[/ ]19\.(0[0-3])", "medium", "Docker 19 < 19.03.9 - CVE-2019-14271 to CVE-2020-15257"),
        (r"Docker[/ ]20\.10\.([0-9]|1[0-7])", "low", "Docker 20.10 < 20.10.18 - Security updates available"),
    ],
    "kubernetes": [
        (r"Kubernetes[/ ]1\.(1[0-9]|20)\.", "high", "Kubernetes 1.10-1.20 - Multiple CVEs, EOL"),
        (r"Kubernetes[/ ]1\.(21|22)\.", "medium", "Kubernetes 1.21-1.22 - CVE-2022-3162, CVE-2022-3172"),
    ],
    "grafana": [
        (r"Grafana[/ ]([0-7])\.", "high", "Grafana < 8 - Multiple vulnerabilities including auth bypass"),
        (r"Grafana[/ ]8\.([0-2])\.", "high", "Grafana 8.0-8.2 - CVE-2021-39226 snapshot auth bypass"),
        (r"Grafana[/ ]8\.[3-5]\.", "medium", "Grafana 8.3-8.5 - Multiple security fixes in later versions"),
    ],
    "gitlab": [
        (r"GitLab[/ ]1[0-3]\.", "high", "GitLab < 14 - Multiple critical CVEs"),
        (r"GitLab[/ ]14\.[0-9]\.", "medium", "GitLab 14.x - CVE-2021-22205 RCE, CVE-2022-0342"),
        (r"GitLab[/ ]15\.[0-3]\.", "low", "GitLab 15.0-15.3 - Check for latest security patches"),
    ],
    "confluence": [
        (r"Confluence[/ ]([0-6])\.", "critical", "Confluence < 7 - Multiple critical RCE vulnerabilities"),
        (r"Confluence[/ ]7\.[0-3]\.", "high", "Confluence 7.0-7.3 - CVE-2021-26084 OGNL injection"),
        (r"Confluence[/ ]7\.(4|5|6|7|8|9|1[0-7])", "medium", "Confluence 7.4-7.17 - CVE-2022-26134 RCE"),
    ],
    "jira": [
        (r"JIRA[/ ]([0-7])\.", "high", "Jira < 8 - Multiple vulnerabilities including SSRF"),
        (r"JIRA[/ ]8\.[0-9]\.", "medium", "Jira 8.x - CVE-2019-8449 to CVE-2019-8451"),
    ],
    "spring": [
        (r"Spring[/ ]([0-4])\.", "critical", "Spring < 5 - Multiple vulnerabilities"),
        (r"Spring[/ ]5\.([0-2])\.", "high", "Spring 5.0-5.2 - CVE-2022-22965 Spring4Shell RCE"),
        (r"Spring[/ ]5\.3\.([0-9]|1[0-7])", "medium", "Spring 5.3 < 5.3.18 - Spring4Shell and other CVEs"),
    ],
    "log4j": [
        (r"log4j[/ ]2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)", "critical", "Log4j 2.0-2.14 - CVE-2021-44228 Log4Shell RCE"),
        (r"log4j[/ ]2\.15", "high", "Log4j 2.15 - CVE-2021-45046 incomplete fix"),
        (r"log4j[/ ]2\.16", "medium", "Log4j 2.16 - CVE-2021-45105 DoS vulnerability"),
    ],
    "varnish": [
        (r"Varnish[/ ]([0-5])\.", "medium", "Varnish < 6 - Multiple security fixes in later versions"),
        (r"Varnish[/ ]6\.[0-3]\.", "low", "Varnish 6.0-6.3 - CVE-2021-36740 request smuggling"),
    ],
    "haproxy": [
        (r"HAProxy[/ ]1\.([0-7])\.", "high", "HAProxy < 1.8 - Multiple vulnerabilities"),
        (r"HAProxy[/ ]1\.8\.([0-9]|1[0-9]|2[0-5])", "medium", "HAProxy 1.8 < 1.8.26 - HTTP/2 vulnerabilities"),
        (r"HAProxy[/ ]2\.0\.([0-9]|1[0-9])", "low", "HAProxy 2.0 < 2.0.20 - Multiple security fixes"),
    ],
    "samba": [
        (r"Samba[/ ]([0-3])\.", "critical", "Samba < 4 - Multiple critical vulnerabilities"),
        (r"Samba[/ ]4\.[0-9]\.", "high", "Samba 4.0-4.9 - CVE-2017-7494 SambaCry RCE"),
        (r"Samba[/ ]4\.1[0-4]\.", "medium", "Samba 4.10-4.14 - CVE-2020-1472 Zerologon"),
    ],
    "bind": [
        (r"BIND[/ ]9\.([0-9]|10)\.", "high", "BIND 9.0-9.10 - Multiple critical vulnerabilities"),
        (r"BIND[/ ]9\.1[1-5]\.", "medium", "BIND 9.11-9.15 - CVE-2020-8616, CVE-2020-8617"),
        (r"BIND[/ ]9\.16\.([0-9]|1[0-9]|2[0-9])", "low", "BIND 9.16 < 9.16.30 - Check for security updates"),
    ],
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
                
                # Check service version/banner for known vulnerabilities
                if state == "open" and (service_product or service_version):
                    banner_findings = _check_banner_for_vulns(
                        service_product, service_version, ip, port_num, service_name
                    )
                    findings.extend(banner_findings)
                
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


def _check_banner_for_vulns(product: str, version: str, host: str, port: int, service: str) -> List[NmapFinding]:
    """Check service banner/version for known vulnerabilities."""
    findings = []
    
    if not product and not version:
        return findings
    
    banner = f"{product or ''} {version or ''}".strip().lower()
    
    # Check against known vulnerable versions
    for service_name, patterns in VULNERABLE_VERSIONS.items():
        if service_name.lower() in banner or service_name.lower() in (service or '').lower():
            for pattern, severity, description in patterns:
                if re.search(pattern, banner, re.IGNORECASE) or re.search(pattern, f"{product} {version}", re.IGNORECASE):
                    findings.append(NmapFinding(
                        category="vulnerable_version",
                        severity=severity,
                        title=f"Vulnerable Software Version: {product or service} {version or ''}".strip(),
                        description=description,
                        host=host,
                        port=port,
                        service=service,
                        evidence=f"Detected: {product} {version}",
                    ))
                    break  # Only report first match per service
    
    return findings


def _check_script_for_vulns(script_id: str, output: str, host: str, port: Optional[int], service: Optional[str]) -> List[NmapFinding]:
    """Check Nmap NSE script output for vulnerabilities - comprehensive detection."""
    findings = []
    output_lower = output.lower()
    script_id_lower = script_id.lower()
    
    # =========================================================================
    # CVE Detection
    # =========================================================================
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
    
    # =========================================================================
    # SMB Vulnerabilities (EternalBlue, SMBGhost, etc.)
    # =========================================================================
    if "smb-vuln" in script_id_lower or "smb2-vuln" in script_id_lower:
        if "vulnerable" in output_lower or "state: vulnerable" in output_lower:
            # Try to identify specific vulnerability
            vuln_name = script_id.replace("smb-vuln-", "").replace("smb2-vuln-", "").upper()
            findings.append(NmapFinding(
                category="vulnerable_service",
                severity="critical",
                title=f"SMB Vulnerability: {vuln_name}",
                description=f"SMB service is vulnerable to {vuln_name}. This may allow remote code execution.",
                host=host,
                port=port or 445,
                service="smb",
                evidence=output[:500],
            ))
    
    # SMB Signing
    if "smb-security-mode" in script_id_lower or "smb2-security-mode" in script_id_lower:
        if "message_signing: disabled" in output_lower or "signing_required: false" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="medium",
                title="SMB Signing Not Required",
                description="SMB signing is not required, making the connection vulnerable to relay attacks.",
                host=host,
                port=port or 445,
                service="smb",
                evidence=output[:300],
            ))
    
    # SMB Enumeration
    if "smb-enum" in script_id_lower:
        if "shares" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="medium",
                title="SMB Shares Enumerable",
                description="SMB shares can be enumerated, potentially exposing sensitive data.",
                host=host,
                port=port or 445,
                service="smb",
                evidence=output[:400],
            ))
        if "users" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="medium",
                title="SMB Users Enumerable",
                description="User accounts can be enumerated via SMB.",
                host=host,
                port=port or 445,
                service="smb",
                evidence=output[:400],
            ))
    
    # =========================================================================
    # SSL/TLS Issues
    # =========================================================================
    if "ssl-" in script_id_lower or "tls-" in script_id_lower:
        # Deprecated protocols
        if "sslv2" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="critical",
                title="SSLv2 Enabled - Critically Vulnerable",
                description="Server supports SSLv2 which has critical vulnerabilities and is completely broken.",
                host=host,
                port=port,
                service=service,
                evidence=output[:300],
            ))
        if "sslv3" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="SSLv3 Enabled - POODLE Vulnerable",
                description="Server supports SSLv3 which is vulnerable to POODLE attack (CVE-2014-3566).",
                host=host,
                port=port,
                service=service,
                evidence=output[:300],
                cve_ids=["CVE-2014-3566"],
            ))
        if "tlsv1.0" in output_lower and "only" not in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="medium",
                title="TLS 1.0 Enabled - Deprecated",
                description="Server supports TLS 1.0 which is deprecated and has known weaknesses.",
                host=host,
                port=port,
                service=service,
            ))
        
        # Weak ciphers
        if any(w in output_lower for w in ["export", "des-cbc", "rc4", "rc2", "null", "anon"]):
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="Weak SSL/TLS Ciphers Supported",
                description="Server supports weak, export-grade, or null ciphers.",
                host=host,
                port=port,
                service=service,
                evidence=output[:400],
            ))
        
        # Heartbleed
        if "heartbleed" in script_id_lower:
            if "vulnerable" in output_lower:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="critical",
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    description="Server is vulnerable to Heartbleed, allowing memory disclosure.",
                    host=host,
                    port=port,
                    service=service,
                    cve_ids=["CVE-2014-0160"],
                ))
        
        # POODLE
        if "ssl-poodle" in script_id_lower:
            if "vulnerable" in output_lower:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="high",
                    title="POODLE Vulnerability",
                    description="Server is vulnerable to POODLE attack on SSL/TLS.",
                    host=host,
                    port=port,
                    service=service,
                    cve_ids=["CVE-2014-3566"],
                ))
        
        # Certificate issues
        if "ssl-cert" in script_id_lower:
            if "expired" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="high",
                    title="SSL Certificate Expired",
                    description="The SSL/TLS certificate has expired.",
                    host=host,
                    port=port,
                    service=service,
                ))
            if "self-signed" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="medium",
                    title="Self-Signed SSL Certificate",
                    description="The SSL/TLS certificate is self-signed and not trusted.",
                    host=host,
                    port=port,
                    service=service,
                ))
    
    # =========================================================================
    # HTTP Vulnerabilities
    # =========================================================================
    if "http-" in script_id_lower:
        # HTTP Methods
        if "http-methods" in script_id_lower:
            dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
            for method in dangerous_methods:
                if method.lower() in output_lower:
                    findings.append(NmapFinding(
                        category="weak_config",
                        severity="medium" if method == "TRACE" else "high",
                        title=f"Dangerous HTTP Method Enabled: {method}",
                        description=f"HTTP {method} method is enabled, which may allow unauthorized actions.",
                        host=host,
                        port=port,
                        service=service,
                    ))
        
        # Shellshock
        if "http-shellshock" in script_id_lower:
            if "vulnerable" in output_lower:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="critical",
                    title="Shellshock Vulnerability (CVE-2014-6271)",
                    description="Web server is vulnerable to Shellshock, allowing remote code execution.",
                    host=host,
                    port=port,
                    service=service,
                    cve_ids=["CVE-2014-6271", "CVE-2014-7169"],
                ))
        
        # SQL Injection
        if "http-sql-injection" in script_id_lower:
            if output.strip() and "error" not in output_lower[:50]:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="critical",
                    title="Potential SQL Injection Detected",
                    description="Web application may be vulnerable to SQL injection.",
                    host=host,
                    port=port,
                    service=service,
                    evidence=output[:400],
                ))
        
        # XSS
        if "http-stored-xss" in script_id_lower or "http-dombased-xss" in script_id_lower:
            if output.strip() and "error" not in output_lower[:50]:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="high",
                    title="Potential XSS Vulnerability",
                    description="Web application may be vulnerable to Cross-Site Scripting.",
                    host=host,
                    port=port,
                    service=service,
                    evidence=output[:300],
                ))
        
        # Directory listing
        if "http-ls" in script_id_lower or "directory listing" in output_lower:
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="medium",
                title="Directory Listing Enabled",
                description="Web server allows directory listing, potentially exposing files.",
                host=host,
                port=port,
                service=service,
            ))
        
        # Robots.txt
        if "http-robots" in script_id_lower and output.strip():
            if any(s in output_lower for s in ["admin", "backup", "config", "secret", "private", "internal"]):
                findings.append(NmapFinding(
                    category="information_disclosure",
                    severity="low",
                    title="Sensitive Paths in robots.txt",
                    description="robots.txt reveals potentially sensitive paths.",
                    host=host,
                    port=port,
                    service=service,
                    evidence=output[:400],
                ))
        
        # Default pages/files
        if "http-enum" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="medium",
                title="Interesting HTTP Paths Found",
                description="HTTP enumeration found potentially interesting files/directories.",
                host=host,
                port=port,
                service=service,
                evidence=output[:500],
            ))
        
        # PHPInfo
        if "http-phpself-xss" in script_id_lower or "phpinfo" in output_lower:
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="medium",
                title="PHPInfo Exposed",
                description="phpinfo() is accessible, exposing system configuration.",
                host=host,
                port=port,
                service=service,
            ))
        
        # WebDAV
        if "http-webdav" in script_id_lower:
            if "webdav" in output_lower and "enabled" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="high",
                    title="WebDAV Enabled",
                    description="WebDAV is enabled, which may allow file upload/manipulation.",
                    host=host,
                    port=port,
                    service=service,
                ))
    
    # =========================================================================
    # FTP Issues
    # =========================================================================
    if "ftp-" in script_id_lower:
        # Anonymous FTP
        if "ftp-anon" in script_id_lower:
            if "anonymous" in output_lower and "allowed" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="high",
                    title="Anonymous FTP Access Allowed",
                    description="FTP server allows anonymous login, potentially exposing files.",
                    host=host,
                    port=port or 21,
                    service="ftp",
                    evidence=output[:300],
                ))
        
        # FTP Bounce
        if "ftp-bounce" in script_id_lower:
            if "vulnerable" in output_lower or "allows" in output_lower:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="high",
                    title="FTP Bounce Attack Possible",
                    description="FTP server may be vulnerable to bounce attacks.",
                    host=host,
                    port=port or 21,
                    service="ftp",
                ))
        
        # vsftpd backdoor
        if "ftp-vsftpd-backdoor" in script_id_lower:
            if "vulnerable" in output_lower or "backdoor" in output_lower:
                findings.append(NmapFinding(
                    category="vulnerable_service",
                    severity="critical",
                    title="vsftpd 2.3.4 Backdoor",
                    description="FTP server has the vsftpd 2.3.4 backdoor (CVE-2011-2523).",
                    host=host,
                    port=port or 21,
                    service="ftp",
                    cve_ids=["CVE-2011-2523"],
                ))
    
    # =========================================================================
    # SSH Issues
    # =========================================================================
    if "ssh-" in script_id_lower:
        # Weak algorithms
        if "ssh2-enum-algos" in script_id_lower:
            weak_algos = ["arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc", "diffie-hellman-group1"]
            for algo in weak_algos:
                if algo in output_lower:
                    findings.append(NmapFinding(
                        category="weak_config",
                        severity="medium",
                        title="Weak SSH Algorithm Supported",
                        description=f"SSH server supports weak algorithm: {algo}",
                        host=host,
                        port=port or 22,
                        service="ssh",
                    ))
                    break
        
        # SSH auth methods
        if "ssh-auth-methods" in script_id_lower:
            if "password" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="low",
                    title="SSH Password Authentication Enabled",
                    description="SSH allows password authentication (consider key-only).",
                    host=host,
                    port=port or 22,
                    service="ssh",
                ))
    
    # =========================================================================
    # DNS Issues
    # =========================================================================
    if "dns-" in script_id_lower:
        # Zone transfer
        if "dns-zone-transfer" in script_id_lower:
            if output.strip() and "failed" not in output_lower:
                findings.append(NmapFinding(
                    category="information_disclosure",
                    severity="high",
                    title="DNS Zone Transfer Allowed",
                    description="DNS server allows zone transfers, exposing all DNS records.",
                    host=host,
                    port=port or 53,
                    service="dns",
                    evidence=output[:500],
                ))
        
        # DNS recursion
        if "dns-recursion" in script_id_lower:
            if "recursion" in output_lower and "enabled" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="medium",
                    title="DNS Recursion Enabled",
                    description="DNS server allows recursive queries (potential amplification).",
                    host=host,
                    port=port or 53,
                    service="dns",
                ))
    
    # =========================================================================
    # SNMP Issues
    # =========================================================================
    if "snmp-" in script_id_lower:
        if "snmp-brute" in script_id_lower or "public" in output_lower or "private" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="SNMP Default/Weak Community String",
                description="SNMP uses default or easily guessable community strings.",
                host=host,
                port=port or 161,
                service="snmp",
                evidence=output[:200],
            ))
    
    # =========================================================================
    # Database Issues
    # =========================================================================
    # MySQL
    if "mysql-" in script_id_lower:
        if "mysql-empty-password" in script_id_lower:
            if "root" in output_lower or "empty" in output_lower:
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="critical",
                    title="MySQL Empty Root Password",
                    description="MySQL server has accounts with no password.",
                    host=host,
                    port=port or 3306,
                    service="mysql",
                ))
        if "mysql-brute" in script_id_lower and "valid" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="critical",
                title="MySQL Weak Credentials",
                description="MySQL server has accounts with weak passwords.",
                host=host,
                port=port or 3306,
                service="mysql",
            ))
    
    # PostgreSQL
    if "pgsql-brute" in script_id_lower and "valid" in output_lower:
        findings.append(NmapFinding(
            category="weak_config",
            severity="critical",
            title="PostgreSQL Weak Credentials",
            description="PostgreSQL server has accounts with weak passwords.",
            host=host,
            port=port or 5432,
            service="postgresql",
        ))
    
    # MongoDB
    if "mongodb-" in script_id_lower:
        if "mongodb-brute" in script_id_lower and "valid" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="critical",
                title="MongoDB Weak Credentials",
                description="MongoDB has accounts with weak passwords.",
                host=host,
                port=port or 27017,
                service="mongodb",
            ))
        if "mongodb-info" in script_id_lower or "mongodb-databases" in script_id_lower:
            if output.strip():
                findings.append(NmapFinding(
                    category="information_disclosure",
                    severity="high",
                    title="MongoDB Information Disclosure",
                    description="MongoDB server exposes database/server information.",
                    host=host,
                    port=port or 27017,
                    service="mongodb",
                    evidence=output[:400],
                ))
    
    # Redis
    if "redis-" in script_id_lower:
        if "redis-info" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="weak_config",
                severity="critical",
                title="Redis No Authentication",
                description="Redis server accessible without authentication.",
                host=host,
                port=port or 6379,
                service="redis",
                evidence=output[:300],
            ))
    
    # =========================================================================
    # RPC/NFS Issues
    # =========================================================================
    if "rpcinfo" in script_id_lower or "nfs-" in script_id_lower:
        if "nfs-showmount" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="high",
                title="NFS Exports Visible",
                description="NFS exports are enumerable, may expose file systems.",
                host=host,
                port=port or 2049,
                service="nfs",
                evidence=output[:400],
            ))
        if "nfs-ls" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="high",
                title="NFS Share Contents Accessible",
                description="NFS share contents are accessible, data may be exposed.",
                host=host,
                port=port or 2049,
                service="nfs",
            ))
    
    # =========================================================================
    # Java/RMI Issues
    # =========================================================================
    if "rmi-" in script_id_lower:
        if "rmi-vuln-classloader" in script_id_lower and "vulnerable" in output_lower:
            findings.append(NmapFinding(
                category="vulnerable_service",
                severity="critical",
                title="Java RMI Remote Code Execution",
                description="Java RMI is vulnerable to remote code execution.",
                host=host,
                port=port or 1099,
                service="rmi",
            ))
    
    # =========================================================================
    # LDAP Issues
    # =========================================================================
    if "ldap-" in script_id_lower:
        if "ldap-rootdse" in script_id_lower and output.strip():
            findings.append(NmapFinding(
                category="information_disclosure",
                severity="medium",
                title="LDAP Root DSE Accessible",
                description="LDAP root DSE is accessible, exposing directory information.",
                host=host,
                port=port or 389,
                service="ldap",
            ))
        if "ldap-brute" in script_id_lower and "valid" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="LDAP Weak Credentials",
                description="LDAP has accounts with weak passwords.",
                host=host,
                port=port or 389,
                service="ldap",
            ))
    
    # =========================================================================
    # VNC Issues
    # =========================================================================
    if "vnc-" in script_id_lower:
        if "vnc-brute" in script_id_lower and "valid" in output_lower:
            findings.append(NmapFinding(
                category="weak_config",
                severity="critical",
                title="VNC Weak Password",
                description="VNC server has a weak or no password.",
                host=host,
                port=port or 5900,
                service="vnc",
            ))
        if "realvnc-auth-bypass" in script_id_lower and "vulnerable" in output_lower:
            findings.append(NmapFinding(
                category="vulnerable_service",
                severity="critical",
                title="RealVNC Authentication Bypass",
                description="RealVNC is vulnerable to authentication bypass.",
                host=host,
                port=port or 5900,
                service="vnc",
            ))
    
    # =========================================================================
    # Generic Patterns
    # =========================================================================
    # Anonymous access (generic)
    if "anonymous" in output_lower and ("allowed" in output_lower or "enabled" in output_lower or "access" in output_lower):
        # Avoid duplicate if already caught by specific checks
        if not any(f.title.startswith("Anonymous") for f in findings):
            findings.append(NmapFinding(
                category="weak_config",
                severity="high",
                title="Anonymous Access Allowed",
                description="Service allows anonymous/unauthenticated access.",
                host=host,
                port=port,
                service=service,
            ))
    
    # Default credentials (generic)
    if any(cred in output_lower for cred in ["default", "credentials found", "valid credentials", "login successful"]):
        if "brute" in script_id_lower or "login" in script_id_lower:
            if not any(f.title.startswith("Weak") or f.title.startswith("MySQL") or f.title.startswith("PostgreSQL") for f in findings):
                findings.append(NmapFinding(
                    category="weak_config",
                    severity="critical",
                    title="Default/Weak Credentials Detected",
                    description="Service may be using default or easily guessable credentials.",
                    host=host,
                    port=port,
                    service=service,
                ))
    
    # Vulnerability scripts (generic)
    if "vuln" in script_id_lower and "vulnerable" in output_lower:
        if not any("ulnerable" in f.title for f in findings):
            findings.append(NmapFinding(
                category="vulnerable_service",
                severity="high",
                title=f"Vulnerability Detected: {script_id}",
                description=f"Service is vulnerable according to {script_id}.",
                host=host,
                port=port,
                service=service,
                evidence=output[:500],
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
        from google import genai
        
        client = genai.Client(api_key=settings.gemini_api_key)
        
        # Build detailed host info for AI (increased limits for better analysis)
        findings_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.description} (host: {f.host}, port: {f.port})"
            for f in analysis_result.findings[:50]  # Increased from 25 to 50
        )
        
        # More detailed host info including services
        def format_host_services(h):
            open_ports = [p for p in h.ports if p.get('state') == 'open'][:10]
            services_str = ', '.join([f"{p.get('port')}/{p.get('service', 'unknown')}" for p in open_ports])
            return f"- {h.ip} ({h.hostname or 'no hostname'}): {len([p for p in h.ports if p.get('state') == 'open'])} open ports, OS: {h.os_guess or 'unknown'}, Services: {services_str}"
        
        hosts_text = "\n".join(
            format_host_services(h)
            for h in analysis_result.hosts[:40]  # Increased from 20 to 40
        )
        
        # Build detailed port/service info
        all_open_ports = []
        for h in analysis_result.hosts[:40]:
            for p in h.ports:
                if p.get('state') == 'open':
                    all_open_ports.append({
                        "host": h.ip,
                        "port": p.get('port'),
                        "service": p.get('service', 'unknown'),
                        "product": p.get('product', ''),
                        "version": p.get('version', ''),
                    })
        
        ports_detail = "\n".join(
            f"- {p['host']}:{p['port']} - {p['service']} {p['product']} {p['version']}".strip()
            for p in all_open_ports[:100]  # Top 100 open ports with details
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

### Open Ports Detail (Top 100)
{ports_detail if ports_detail else "No open ports detected."}

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

        response = await client.aio.models.generate_content(
            model=settings.gemini_model_id,
            contents=prompt
        )
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
# Network ranges multiply time significantly - /24 can take 10-50x longer
SCAN_TYPES = {
    "ping": {
        "name": "Ping Sweep",
        "description": "Host discovery only - no port scanning. Fast for finding live hosts.",
        "args": ["-sn", "-T5", "--min-hostgroup", "64", "--max-retries", "1"],
        "timeout": 600,  # 10 minutes for network ranges
        "requires_root": False,
        "estimated_time": "5-30 sec (single) / 2-10 min (network)",
        "intensity": 1,
    },
    "quick": {
        "name": "Quick Scan",
        "description": "Top 100 ports, no service detection",
        "args": ["-T5", "-F", "--top-ports", "100", "--min-hostgroup", "32"],
        "timeout": 900,  # 15 minutes
        "requires_root": False,
        "estimated_time": "30-60 sec (single) / 5-15 min (network)",
        "intensity": 2,
    },
    "stealth": {
        "name": "Stealth SYN Scan",
        "description": "SYN scan - fast and less detectable",
        "args": ["-sS", "-T4", "--top-ports", "1000"],
        "timeout": 900,
        "requires_root": False,
        "estimated_time": "1-3 min",
        "intensity": 3,
    },
    "basic": {
        "name": "Basic Scan",
        "description": "Top 1000 ports with service detection",
        "args": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
        "timeout": 1800,  # 30 minutes
        "requires_root": False,
        "estimated_time": "3-10 min (single) / 15-45 min (network)",
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

# Available NSE script categories that can be added to scans
# Users can select one or more of these to run additional scripts
NSE_SCRIPT_CATEGORIES = {
    "vuln": {
        "name": "Vulnerability Scripts",
        "description": "Checks for known vulnerabilities (CVEs, misconfigurations)",
        "examples": ["smb-vuln-ms17-010", "http-vuln-cve2017-5638", "ssl-heartbleed"],
        "warning": "May trigger IDS/IPS alerts",
        "timeout_multiplier": 2.0,
    },
    "safe": {
        "name": "Safe Scripts",
        "description": "Non-intrusive scripts that won't crash services",
        "examples": ["http-headers", "ssh-hostkey", "ssl-cert"],
        "warning": None,
        "timeout_multiplier": 1.2,
    },
    "discovery": {
        "name": "Discovery Scripts",
        "description": "Enumerate services and gather info (banners, versions)",
        "examples": ["http-enum", "smb-enum-shares", "dns-brute"],
        "warning": "Can generate significant traffic",
        "timeout_multiplier": 1.5,
    },
    "auth": {
        "name": "Authentication Scripts",
        "description": "Check for auth issues, default creds, anonymous access",
        "examples": ["ftp-anon", "http-auth", "mysql-empty-password"],
        "warning": None,
        "timeout_multiplier": 1.3,
    },
    "brute": {
        "name": "Brute Force Scripts",
        "description": "Password brute forcing (use with caution)",
        "examples": ["ssh-brute", "ftp-brute", "http-brute"],
        "warning": "May lock out accounts, use responsibly",
        "timeout_multiplier": 3.0,
    },
    "exploit": {
        "name": "Exploit Scripts",
        "description": "Attempt to exploit vulnerabilities (pentesting only)",
        "examples": ["smb-vuln-ms08-067", "http-shellshock"],
        "warning": "DANGEROUS - Only use in authorized pentests",
        "timeout_multiplier": 2.0,
    },
    "intrusive": {
        "name": "Intrusive Scripts",
        "description": "May crash services or affect system stability",
        "examples": ["http-slowloris", "dns-update"],
        "warning": "May cause service disruption",
        "timeout_multiplier": 2.0,
    },
    "malware": {
        "name": "Malware Detection Scripts",
        "description": "Detect malware infections and backdoors",
        "examples": ["http-malware-host", "smb-double-pulsar-backdoor"],
        "warning": None,
        "timeout_multiplier": 1.5,
    },
    "default": {
        "name": "Default Scripts",
        "description": "Standard scripts included with -sC flag",
        "examples": ["ssh-hostkey", "http-title", "ssl-cert"],
        "warning": None,
        "timeout_multiplier": 1.0,
    },
    "broadcast": {
        "name": "Broadcast Scripts",
        "description": "Send broadcast packets to discover hosts/services",
        "examples": ["broadcast-dhcp-discover", "broadcast-netbios-master-browser"],
        "warning": "Generates broadcast traffic on the network",
        "timeout_multiplier": 1.2,
    },
}

# Individual NSE scripts that can be run for specific checks
NSE_INDIVIDUAL_SCRIPTS = {
    # SSL/TLS vulnerabilities
    "ssl-heartbleed": {
        "name": "Heartbleed (CVE-2014-0160)",
        "description": "Check for OpenSSL Heartbleed vulnerability",
        "category": "vuln",
    },
    "ssl-poodle": {
        "name": "POODLE (CVE-2014-3566)",
        "description": "Check for SSLv3 POODLE vulnerability",
        "category": "vuln",
    },
    "ssl-dh-params": {
        "name": "Weak DH Parameters",
        "description": "Check for weak Diffie-Hellman parameters",
        "category": "vuln",
    },
    "ssl-ccs-injection": {
        "name": "CCS Injection (CVE-2014-0224)",
        "description": "Check for OpenSSL CCS injection vulnerability",
        "category": "vuln",
    },
    "ssl-cert": {
        "name": "SSL Certificate",
        "description": "Retrieve and analyze SSL certificates",
        "category": "safe",
    },
    "ssl-enum-ciphers": {
        "name": "SSL Ciphers",
        "description": "Enumerate SSL/TLS cipher suites",
        "category": "safe",
    },
    # SMB vulnerabilities
    "smb-vuln-ms17-010": {
        "name": "EternalBlue (MS17-010)",
        "description": "Check for MS17-010 SMB vulnerability (WannaCry)",
        "category": "vuln",
    },
    "smb-vuln-ms08-067": {
        "name": "MS08-067",
        "description": "Check for MS08-067 SMB vulnerability (Conficker)",
        "category": "vuln",
    },
    "smb-vuln-cve-2017-7494": {
        "name": "SambaCry (CVE-2017-7494)",
        "description": "Check for Samba remote code execution",
        "category": "vuln",
    },
    "smb-double-pulsar-backdoor": {
        "name": "DoublePulsar Backdoor",
        "description": "Check for NSA DoublePulsar backdoor",
        "category": "malware",
    },
    "smb-enum-shares": {
        "name": "SMB Shares",
        "description": "Enumerate SMB shares",
        "category": "discovery",
    },
    # HTTP vulnerabilities
    "http-shellshock": {
        "name": "Shellshock (CVE-2014-6271)",
        "description": "Check for Shellshock vulnerability",
        "category": "vuln",
    },
    "http-vuln-cve2017-5638": {
        "name": "Apache Struts RCE (CVE-2017-5638)",
        "description": "Check for Apache Struts vulnerability",
        "category": "vuln",
    },
    "http-vuln-cve2021-41773": {
        "name": "Apache Path Traversal (CVE-2021-41773)",
        "description": "Check for Apache 2.4.49/2.4.50 path traversal",
        "category": "vuln",
    },
    "http-sql-injection": {
        "name": "SQL Injection",
        "description": "Basic SQL injection tests",
        "category": "vuln",
    },
    "http-xssed": {
        "name": "XSS Detection",
        "description": "Check for XSS vulnerabilities via xssed.com",
        "category": "vuln",
    },
    "http-enum": {
        "name": "HTTP Enumeration",
        "description": "Enumerate web directories and files",
        "category": "discovery",
    },
    "http-headers": {
        "name": "HTTP Headers",
        "description": "Retrieve HTTP response headers",
        "category": "safe",
    },
    "http-methods": {
        "name": "HTTP Methods",
        "description": "Check for dangerous HTTP methods (PUT, DELETE)",
        "category": "safe",
    },
    # Authentication
    "ftp-anon": {
        "name": "FTP Anonymous Login",
        "description": "Check for anonymous FTP access",
        "category": "auth",
    },
    "mysql-empty-password": {
        "name": "MySQL Empty Password",
        "description": "Check for MySQL accounts with no password",
        "category": "auth",
    },
    "mongodb-databases": {
        "name": "MongoDB Databases",
        "description": "List MongoDB databases (if unauthenticated)",
        "category": "auth",
    },
    "redis-info": {
        "name": "Redis Info",
        "description": "Get Redis server info (often unauthenticated)",
        "category": "auth",
    },
    # Service-specific
    "dns-zone-transfer": {
        "name": "DNS Zone Transfer",
        "description": "Attempt DNS zone transfer",
        "category": "discovery",
    },
    "snmp-info": {
        "name": "SNMP Info",
        "description": "Get SNMP system info",
        "category": "discovery",
    },
    "ntp-monlist": {
        "name": "NTP Monlist",
        "description": "Get NTP monlist for amplification check",
        "category": "vuln",
    },
    "memcached-info": {
        "name": "Memcached Info",
        "description": "Get Memcached server statistics",
        "category": "discovery",
    },
    # Log4j
    "http-vuln-cve2021-44228": {
        "name": "Log4Shell (CVE-2021-44228)",
        "description": "Check for Log4j remote code execution",
        "category": "vuln",
    },
}


def get_nse_script_categories() -> List[Dict[str, Any]]:
    """Get available NSE script categories."""
    return [
        {
            "id": cat_id,
            "name": cat_info["name"],
            "description": cat_info["description"],
            "examples": cat_info["examples"],
            "warning": cat_info["warning"],
        }
        for cat_id, cat_info in NSE_SCRIPT_CATEGORIES.items()
    ]


def get_nse_individual_scripts() -> List[Dict[str, Any]]:
    """Get available individual NSE scripts."""
    return [
        {
            "id": script_id,
            "name": script_info["name"],
            "description": script_info["description"],
            "category": script_info["category"],
        }
        for script_id, script_info in NSE_INDIVIDUAL_SCRIPTS.items()
    ]


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
    scripts: Optional[List[str]] = None,
    script_categories: Optional[List[str]] = None,
) -> Tuple[Optional[Path], Optional[str], Optional[str]]:
    """
    Run an Nmap scan and return the path to the XML output.
    
    Args:
        target: IP address, CIDR range, or hostname to scan
        scan_type: Type of scan from SCAN_TYPES
        ports: Optional port specification (e.g., "22,80,443" or "1-1000")
        extra_args: Additional nmap arguments
        scripts: List of individual NSE script names to run
        script_categories: List of NSE script categories to run (e.g., ["vuln", "safe"])
        
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
    
    # Calculate timeout multiplier for scripts
    timeout_multiplier = 1.0
    
    # Add script categories if provided
    if script_categories:
        # Validate categories
        valid_categories = []
        for cat in script_categories:
            if cat in NSE_SCRIPT_CATEGORIES:
                valid_categories.append(cat)
                # Apply timeout multiplier
                timeout_multiplier = max(timeout_multiplier, NSE_SCRIPT_CATEGORIES[cat]["timeout_multiplier"])
            else:
                logger.warning(f"Unknown script category: {cat}, skipping")
        
        if valid_categories:
            # Check if --script already in cmd and merge
            existing_script_idx = None
            for i, arg in enumerate(cmd):
                if arg == "--script" and i + 1 < len(cmd):
                    existing_script_idx = i + 1
                    break
            
            if existing_script_idx is not None:
                # Merge with existing script argument
                existing_scripts = cmd[existing_script_idx]
                new_scripts = ",".join(valid_categories)
                cmd[existing_script_idx] = f"{existing_scripts},{new_scripts}"
            else:
                cmd.extend(["--script", ",".join(valid_categories)])
    
    # Add individual scripts if provided
    if scripts:
        # Validate individual scripts
        valid_scripts = []
        for script in scripts:
            if script in NSE_INDIVIDUAL_SCRIPTS:
                valid_scripts.append(script)
            else:
                # Allow arbitrary script names (user may know scripts not in our list)
                if re.match(r'^[a-zA-Z0-9\-_]+$', script):
                    valid_scripts.append(script)
                    logger.info(f"Using custom script: {script}")
                else:
                    logger.warning(f"Invalid script name: {script}, skipping")
        
        if valid_scripts:
            # Check if --script already in cmd and merge
            existing_script_idx = None
            for i, arg in enumerate(cmd):
                if arg == "--script" and i + 1 < len(cmd):
                    existing_script_idx = i + 1
                    break
            
            if existing_script_idx is not None:
                # Merge with existing script argument
                existing_scripts = cmd[existing_script_idx]
                new_scripts = ",".join(valid_scripts)
                cmd[existing_script_idx] = f"{existing_scripts},{new_scripts}"
            else:
                cmd.extend(["--script", ",".join(valid_scripts)])
            
            # Add timeout multiplier for vuln scripts
            if any(s in NSE_INDIVIDUAL_SCRIPTS and NSE_INDIVIDUAL_SCRIPTS.get(s, {}).get("category") == "vuln" for s in valid_scripts):
                timeout_multiplier = max(timeout_multiplier, 1.5)
    
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
    
    # Calculate dynamic timeout based on target size and scripts
    base_timeout = scan_config["timeout"]
    timeout = base_timeout
    
    # Check if target is a CIDR range and increase timeout accordingly
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
            num_hosts = network.num_addresses
            # For /24 (256 hosts), multiply by 2
            # For /16 (65536 hosts), cap at a reasonable max
            if num_hosts > 1:
                multiplier = min(num_hosts / 128, 10)  # Max 10x base timeout
                timeout = int(base_timeout * max(1, multiplier))
                logger.info(f"Network range {target} has {num_hosts} hosts, timeout adjusted to {timeout}s (base: {base_timeout}s)")
        except ValueError:
            pass  # Not a valid CIDR, use base timeout
    
    # Apply script timeout multiplier
    if timeout_multiplier > 1.0:
        timeout = int(timeout * timeout_multiplier)
        logger.info(f"Scripts enabled, timeout multiplied by {timeout_multiplier}x = {timeout}s")
    
    logger.info(f"Running Nmap scan: {command_str} (timeout: {timeout}s)")
    
    try:
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
        return None, command_str, f"Scan timed out after {timeout} seconds. For network ranges, consider using 'ping' sweep first to find live hosts, then scan specific IPs."
    except PermissionError as e:
        logger.error(f"Permission error running nmap: {e}")
        return None, command_str, "Permission denied. The server needs root privileges for nmap scans."
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        return None, command_str, f"Scan failed: {str(e)}"

