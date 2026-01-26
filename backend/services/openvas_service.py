"""
OpenVAS/GVM Service

Integration with Greenbone Vulnerability Management (OpenVAS) for
comprehensive network vulnerability scanning.

OpenVAS provides:
- Full CVE vulnerability detection
- Network service vulnerability assessment
- Authenticated scanning capabilities
- Extensive plugin/NVT database (50,000+ tests)
"""

import asyncio
import logging
import ssl
from defusedxml import ElementTree as ET  # Use defusedxml to prevent XXE attacks
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from xml.sax.saxutils import escape as xml_escape

import httpx

from backend.core.config import settings

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    """OpenVAS scan status values."""
    REQUESTED = "Requested"
    QUEUED = "Queued"
    RUNNING = "Running"
    STOP_REQUESTED = "Stop Requested"
    STOPPED = "Stopped"
    DONE = "Done"
    INTERRUPTED = "Interrupted"


class SeverityLevel(str, Enum):
    """CVSS-based severity levels."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    LOG = "log"            # 0.0 / informational


@dataclass
class OpenVASVulnerability:
    """Represents a vulnerability found by OpenVAS."""
    nvt_oid: str
    name: str
    severity: float
    severity_level: SeverityLevel
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    host: str = ""
    port: str = ""
    protocol: str = ""
    description: str = ""
    solution: str = ""
    impact: str = ""
    affected: str = ""
    insight: str = ""
    detection: str = ""
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    bid_ids: List[str] = field(default_factory=list)
    xref: List[str] = field(default_factory=list)
    qod: int = 0  # Quality of Detection (0-100)
    qod_type: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "nvt_oid": self.nvt_oid,
            "name": self.name,
            "severity": self.severity,
            "severity_level": self.severity_level.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "description": self.description,
            "solution": self.solution,
            "impact": self.impact,
            "affected": self.affected,
            "insight": self.insight,
            "detection": self.detection,
            "references": self.references,
            "cve_ids": self.cve_ids,
            "bid_ids": self.bid_ids,
            "xref": self.xref,
            "qod": self.qod,
            "qod_type": self.qod_type,
        }


@dataclass
class OpenVASScanResult:
    """Complete scan result from OpenVAS."""
    task_id: str
    target_id: str
    report_id: str
    status: ScanStatus
    progress: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    host_count: int = 0
    vulnerabilities: List[OpenVASVulnerability] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "task_id": self.task_id,
            "target_id": self.target_id,
            "report_id": self.report_id,
            "status": self.status.value,
            "progress": self.progress,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "host_count": self.host_count,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "severity_counts": self.severity_counts,
        }


class OpenVASService:
    """
    Service for interacting with OpenVAS/GVM via the GMP protocol.
    
    Uses the Greenbone Management Protocol (GMP) over HTTP/HTTPS.
    """
    
    # Predefined scan configs in OpenVAS
    SCAN_CONFIGS = {
        "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
        "full_and_deep": "708f25c4-7489-11df-8094-002264764cea",
        "full_and_very_deep": "74db13d6-7489-11df-8094-002264764cea",
        "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
        "host_discovery": "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
        "system_discovery": "bbca7412-a950-11e3-9109-406186ea4fc5",
    }
    
    # Predefined port lists
    PORT_LISTS = {
        "all_tcp": "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
        "all_tcp_and_nmap_top_100_udp": "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
        "all_tcp_and_nmap_top_1000_udp": "730ef368-57e2-11e1-a90f-406186ea4fc5",
        "nmap_top_2000_tcp_top_100_udp": "ab33f6b0-57f8-11e1-96f5-406186ea4fc5",
        "openvas_default": "c7e03b6c-3f2e-11e1-9e72-406186ea4fc5",
    }
    
    # Credential types for authenticated scanning
    CREDENTIAL_TYPES = {
        "ssh_username_password": "up",       # SSH with username/password
        "ssh_username_key": "usk",           # SSH with private key
        "smb": "smb",                        # Windows SMB/CIFS
        "snmp_v1_v2c": "snmp",               # SNMP v1/v2c community string
        "snmp_v3": "snmpv3",                 # SNMP v3 with auth/priv
        "esxi": "esxi",                      # VMware ESXi
        "database": "database",              # Database credentials
    }
    
    # Alert notification methods
    ALERT_METHODS = {
        "email": "Email",
        "http_get": "HTTP Get",
        "scp": "SCP",
        "send": "Send",
        "smb": "SMB",
        "snmp": "SNMP",
        "sourcefire_connector": "Sourcefire Connector",
        "start_task": "Start Task",
        "syslog": "Syslog",
        "verinice_connector": "verinice Connector",
    }
    
    # Alert conditions
    ALERT_CONDITIONS = {
        "always": "Always",
        "severity_at_least": "Severity at least",
        "severity_changed": "Severity changed",
        "filter_count_changed": "Filter count changed",
        "filter_count_at_least": "Filter count at least",
    }
    
    # Alert events
    ALERT_EVENTS = {
        "task_run_status_changed": "Task run status changed",
        "updated_secinfo_arrived": "Updated SecInfo arrived",
        "new_secinfo_arrived": "New SecInfo arrived",
        "ticket_received": "Ticket received",
        "assigned_ticket_changed": "Assigned ticket changed",
        "owned_ticket_changed": "Owned ticket changed",
    }
    
    # Alive test methods for host discovery
    ALIVE_TESTS = {
        "scan_config_default": "Scan Config Default",
        "icmp_ping": "ICMP Ping",
        "tcp_ack_service_ping": "TCP-ACK Service Ping",
        "tcp_syn_service_ping": "TCP-SYN Service Ping",
        "arp_ping": "ARP Ping",
        "icmp_and_tcp_ack_service_ping": "ICMP & TCP-ACK Service Ping",
        "icmp_and_arp_ping": "ICMP & ARP Ping",
        "tcp_ack_service_and_arp_ping": "TCP-ACK Service & ARP Ping",
        "icmp_tcp_ack_and_arp_ping": "ICMP, TCP-ACK Service & ARP Ping",
        "consider_alive": "Consider Alive",
    }
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.base_url = base_url or getattr(settings, 'OPENVAS_URL', 'https://localhost:9392')
        self.username = username or getattr(settings, 'OPENVAS_USER', 'admin')
        self.password = password or getattr(settings, 'OPENVAS_PASSWORD', 'admin')
        self._session_token: Optional[str] = None
        self._client: Optional[httpx.AsyncClient] = None
        
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            # OpenVAS may use self-signed certs; set verify_ssl=False in config if needed
            # Default to True for security; configure via self.verify_ssl if available
            verify = getattr(self, 'verify_ssl', True)
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                verify=verify,
                timeout=60.0,
            )
        return self._client
    
    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def _gmp_command(self, command: str) -> ET.Element:
        """
        Send a GMP command and return the XML response.
        
        Args:
            command: GMP XML command string
            
        Returns:
            Parsed XML Element of the response
        """
        client = await self._get_client()
        
        # Build the request
        headers = {"Content-Type": "application/xml"}
        if self._session_token:
            headers["Cookie"] = f"token={self._session_token}"
        
        try:
            response = await client.post(
                "/gmp",
                content=command,
                headers=headers,
            )
            response.raise_for_status()
            
            # Parse XML response
            root = ET.fromstring(response.text)
            
            # Check for GMP errors
            status = root.get("status", "")
            if not status.startswith("2"):
                status_text = root.get("status_text", "Unknown error")
                raise Exception(f"GMP Error {status}: {status_text}")
            
            return root
            
        except httpx.HTTPError as e:
            logger.error(f"HTTP error communicating with OpenVAS: {e}")
            raise
        except ET.ParseError as e:
            logger.error(f"Failed to parse OpenVAS response: {e}")
            raise
    
    async def authenticate(self) -> bool:
        """
        Authenticate with OpenVAS/GVM.
        
        Returns:
            True if authentication successful
        """
        command = f"""
        <authenticate>
            <credentials>
                <username>{xml_escape(self.username)}</username>
                <password>{xml_escape(self.password)}</password>
            </credentials>
        </authenticate>
        """
        
        try:
            response = await self._gmp_command(command)
            # Extract session token from response
            self._session_token = response.get("token") or response.findtext(".//token")
            logger.info("Successfully authenticated with OpenVAS")
            return True
        except Exception as e:
            logger.error(f"Failed to authenticate with OpenVAS: {e}")
            return False
    
    async def get_version(self) -> Dict[str, str]:
        """Get OpenVAS/GVM version information."""
        command = "<get_version/>"
        response = await self._gmp_command(command)
        
        return {
            "gmp_version": response.findtext(".//version", ""),
            "backend_operation": response.get("status_text", ""),
        }
    
    async def check_connection(self) -> Dict[str, Any]:
        """
        Check if OpenVAS is available and responsive.
        
        Returns:
            Status information dictionary
        """
        try:
            if not self._session_token:
                authenticated = await self.authenticate()
                if not authenticated:
                    return {
                        "status": "error",
                        "message": "Authentication failed",
                        "connected": False,
                    }
            
            version = await self.get_version()
            
            return {
                "status": "connected",
                "message": "OpenVAS is available",
                "connected": True,
                "version": version,
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "connected": False,
            }
    
    async def create_target(
        self,
        name: str,
        hosts: str,
        port_list_id: Optional[str] = None,
        comment: str = "",
        ssh_credential_id: Optional[str] = None,
        smb_credential_id: Optional[str] = None,
        snmp_credential_id: Optional[str] = None,
        esxi_credential_id: Optional[str] = None,
        ssh_credential_port: int = 22,
        alive_test: Optional[str] = None,
        exclude_hosts: Optional[str] = None,
        reverse_lookup_only: bool = False,
        reverse_lookup_unify: bool = False,
    ) -> str:
        """
        Create a scan target in OpenVAS with optional credentials for authenticated scanning.
        
        Args:
            name: Target name
            hosts: Comma-separated list of hosts/IPs/ranges
            port_list_id: ID of port list to use (default: OpenVAS default)
            comment: Optional comment
            ssh_credential_id: SSH credential ID for authenticated Linux/Unix scanning
            smb_credential_id: SMB credential ID for authenticated Windows scanning
            snmp_credential_id: SNMP credential ID for network device scanning
            esxi_credential_id: ESXi credential ID for VMware scanning
            ssh_credential_port: SSH port (default: 22)
            alive_test: Alive test method (from ALIVE_TESTS)
            exclude_hosts: Hosts to exclude from scanning
            reverse_lookup_only: Only scan if reverse DNS lookup succeeds
            reverse_lookup_unify: Unify hosts with same IP from reverse lookup
            
        Returns:
            Target ID
        """
        if not self._session_token:
            await self.authenticate()
        
        port_list = port_list_id or self.PORT_LISTS["openvas_default"]
        
        # Build target XML with optional elements
        target_elements = [
            f"<name>{xml_escape(name)}</name>",
            f"<hosts>{xml_escape(hosts)}</hosts>",
            f'<port_list id="{port_list}"/>',
            f"<comment>{xml_escape(comment)}</comment>",
        ]
        
        # Add credential references for authenticated scanning
        if ssh_credential_id:
            target_elements.append(f'<ssh_credential id="{ssh_credential_id}"><port>{ssh_credential_port}</port></ssh_credential>')
        
        if smb_credential_id:
            target_elements.append(f'<smb_credential id="{smb_credential_id}"/>')
        
        if snmp_credential_id:
            target_elements.append(f'<snmp_credential id="{snmp_credential_id}"/>')
        
        if esxi_credential_id:
            target_elements.append(f'<esxi_credential id="{esxi_credential_id}"/>')
        
        # Add alive test if specified
        if alive_test:
            alive_test_value = self.ALIVE_TESTS.get(alive_test, alive_test)
            target_elements.append(f"<alive_tests>{xml_escape(alive_test_value)}</alive_tests>")
        
        # Add host exclusions
        if exclude_hosts:
            target_elements.append(f"<exclude_hosts>{xml_escape(exclude_hosts)}</exclude_hosts>")
        
        # Add reverse lookup options
        if reverse_lookup_only:
            target_elements.append("<reverse_lookup_only>1</reverse_lookup_only>")
        if reverse_lookup_unify:
            target_elements.append("<reverse_lookup_unify>1</reverse_lookup_unify>")
        
        command = f"""
        <create_target>
            {''.join(target_elements)}
        </create_target>
        """
        
        response = await self._gmp_command(command)
        target_id = response.get("id")
        
        if not target_id:
            raise Exception("Failed to create target - no ID returned")
        
        logger.info(f"Created OpenVAS target: {target_id}")
        return target_id
    
    async def create_task(
        self,
        name: str,
        target_id: str,
        scan_config_id: Optional[str] = None,
        scanner_id: Optional[str] = None,
        schedule_id: Optional[str] = None,
        alert_ids: Optional[List[str]] = None,
        max_hosts: Optional[int] = None,
        max_checks: Optional[int] = None,
        comment: str = "",
    ) -> str:
        """
        Create a scan task in OpenVAS with optional scheduling and alerts.
        
        Args:
            name: Task name
            target_id: ID of target to scan
            scan_config_id: ID of scan configuration (default: Full and Fast)
            scanner_id: ID of scanner to use (default: OpenVAS default)
            schedule_id: ID of schedule for automated scanning
            alert_ids: List of alert IDs to trigger on completion
            max_hosts: Maximum simultaneous hosts to scan
            max_checks: Maximum simultaneous checks per host
            comment: Optional comment
            
        Returns:
            Task ID
        """
        if not self._session_token:
            await self.authenticate()
        
        config_id = scan_config_id or self.SCAN_CONFIGS["full_and_fast"]
        
        # Get default scanner if not specified
        if not scanner_id:
            scanner_id = await self._get_default_scanner()
        
        # Build task XML with optional elements
        task_elements = [
            f"<name>{xml_escape(name)}</name>",
            f'<target id="{target_id}"/>',
            f'<config id="{config_id}"/>',
            f'<scanner id="{scanner_id}"/>',
            f"<comment>{xml_escape(comment)}</comment>",
        ]
        
        # Add schedule reference
        if schedule_id:
            task_elements.append(f'<schedule id="{schedule_id}"/>')
        
        # Add alert references
        if alert_ids:
            for alert_id in alert_ids:
                task_elements.append(f'<alert id="{alert_id}"/>')
        
        # Add scan preferences
        preferences = []
        if max_hosts is not None:
            preferences.append(f"""
                <preference>
                    <scanner_name>max_hosts</scanner_name>
                    <value>{max_hosts}</value>
                </preference>
            """)
        if max_checks is not None:
            preferences.append(f"""
                <preference>
                    <scanner_name>max_checks</scanner_name>
                    <value>{max_checks}</value>
                </preference>
            """)
        
        if preferences:
            task_elements.append(f"<preferences>{''.join(preferences)}</preferences>")
        
        command = f"""
        <create_task>
            {''.join(task_elements)}
        </create_task>
        """
        
        response = await self._gmp_command(command)
        task_id = response.get("id")
        
        if not task_id:
            raise Exception("Failed to create task - no ID returned")
        
        logger.info(f"Created OpenVAS task: {task_id}")
        return task_id
    
    async def _get_default_scanner(self) -> str:
        """Get the default OpenVAS scanner ID."""
        command = "<get_scanners/>"
        response = await self._gmp_command(command)
        
        for scanner in response.findall(".//scanner"):
            name = scanner.findtext("name", "")
            if "OpenVAS" in name or "Default" in name.lower():
                return scanner.get("id", "")
        
        # Return first scanner if no default found
        first_scanner = response.find(".//scanner")
        if first_scanner is not None:
            return first_scanner.get("id", "")
        
        raise Exception("No scanner found in OpenVAS")
    
    async def start_task(self, task_id: str) -> str:
        """
        Start a scan task.
        
        Args:
            task_id: ID of task to start
            
        Returns:
            Report ID for the scan
        """
        if not self._session_token:
            await self.authenticate()
        
        command = f'<start_task task_id="{task_id}"/>'
        response = await self._gmp_command(command)
        
        report_id = response.findtext(".//report_id", "")
        logger.info(f"Started OpenVAS task {task_id}, report: {report_id}")
        return report_id
    
    async def stop_task(self, task_id: str) -> bool:
        """Stop a running scan task."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<stop_task task_id="{task_id}"/>'
        await self._gmp_command(command)
        logger.info(f"Stopped OpenVAS task {task_id}")
        return True
    
    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get the status of a scan task.
        
        Returns:
            Dictionary with status, progress, and other details
        """
        if not self._session_token:
            await self.authenticate()
        
        command = f'<get_tasks task_id="{task_id}"/>'
        response = await self._gmp_command(command)
        
        task = response.find(".//task")
        if task is None:
            raise Exception(f"Task {task_id} not found")
        
        status = task.findtext("status", "Unknown")
        progress = int(task.findtext("progress", "0") or 0)
        
        last_report = task.find(".//last_report/report")
        report_id = last_report.get("id") if last_report is not None else None
        
        return {
            "task_id": task_id,
            "status": status,
            "progress": progress,
            "report_id": report_id,
            "name": task.findtext("name", ""),
        }
    
    async def get_report(
        self,
        report_id: str,
        min_qod: int = 70,
        include_details: bool = True,
    ) -> OpenVASScanResult:
        """
        Get the full report with vulnerabilities.
        
        Args:
            report_id: ID of the report to fetch
            min_qod: Minimum Quality of Detection (0-100)
            include_details: Include full vulnerability details
            
        Returns:
            OpenVASScanResult with all findings
        """
        if not self._session_token:
            await self.authenticate()
        
        # Build filter for minimum QoD
        filter_str = f"min_qod={min_qod}"
        
        command = f"""
        <get_reports 
            report_id="{report_id}"
            filter="{filter_str}"
            details="{1 if include_details else 0}"
            ignore_pagination="1"
        />
        """
        
        response = await self._gmp_command(command)
        report = response.find(".//report")
        
        if report is None:
            raise Exception(f"Report {report_id} not found")
        
        # Parse vulnerabilities
        vulnerabilities = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "log": 0}
        
        for result in report.findall(".//result"):
            vuln = self._parse_vulnerability(result)
            vulnerabilities.append(vuln)
            severity_counts[vuln.severity_level.value] += 1
        
        # Get task info
        task = report.find(".//task")
        task_id = task.get("id") if task is not None else ""
        
        target = report.find(".//task/target")
        target_id = target.get("id") if target is not None else ""
        
        # Parse timestamps
        start_time = None
        end_time = None
        
        creation_time = report.findtext(".//creation_time")
        if creation_time:
            try:
                start_time = datetime.fromisoformat(creation_time.replace("Z", "+00:00"))
            except ValueError:
                pass
        
        modification_time = report.findtext(".//modification_time")
        if modification_time:
            try:
                end_time = datetime.fromisoformat(modification_time.replace("Z", "+00:00"))
            except ValueError:
                pass
        
        # Get host count
        hosts = report.find(".//hosts")
        host_count = int(hosts.findtext("count", "0")) if hosts is not None else 0
        
        return OpenVASScanResult(
            task_id=task_id,
            target_id=target_id,
            report_id=report_id,
            status=ScanStatus.DONE,
            progress=100,
            start_time=start_time,
            end_time=end_time,
            host_count=host_count,
            vulnerabilities=vulnerabilities,
            severity_counts=severity_counts,
        )
    
    def _parse_vulnerability(self, result: ET.Element) -> OpenVASVulnerability:
        """Parse a vulnerability result from OpenVAS XML."""
        nvt = result.find("nvt")
        nvt_oid = nvt.get("oid", "") if nvt is not None else ""
        
        # Get severity
        severity_str = result.findtext("severity", "0")
        try:
            severity = float(severity_str)
        except ValueError:
            severity = 0.0
        
        # Classify severity
        if severity >= 9.0:
            severity_level = SeverityLevel.CRITICAL
        elif severity >= 7.0:
            severity_level = SeverityLevel.HIGH
        elif severity >= 4.0:
            severity_level = SeverityLevel.MEDIUM
        elif severity > 0:
            severity_level = SeverityLevel.LOW
        else:
            severity_level = SeverityLevel.LOG
        
        # Get host/port info
        host_elem = result.find("host")
        host = host_elem.text if host_elem is not None and host_elem.text else ""
        
        port_str = result.findtext("port", "")
        port_parts = port_str.split("/") if port_str else ["", ""]
        port = port_parts[0] if port_parts else ""
        protocol = port_parts[1] if len(port_parts) > 1 else ""
        
        # Get CVE references
        cve_ids = []
        bid_ids = []
        xrefs = []
        
        refs = nvt.find("refs") if nvt is not None else None
        if refs is not None:
            for ref in refs.findall("ref"):
                ref_type = ref.get("type", "")
                ref_id = ref.get("id", "")
                if ref_type == "cve":
                    cve_ids.append(ref_id)
                elif ref_type == "bid":
                    bid_ids.append(ref_id)
                else:
                    xrefs.append(f"{ref_type}:{ref_id}")
        
        # Get QoD
        qod = result.find("qod")
        qod_value = int(qod.findtext("value", "0")) if qod is not None else 0
        qod_type = qod.findtext("type", "") if qod is not None else ""
        
        return OpenVASVulnerability(
            nvt_oid=nvt_oid,
            name=nvt.findtext("name", "") if nvt is not None else "",
            severity=severity,
            severity_level=severity_level,
            cvss_score=severity,  # OpenVAS severity is CVSS
            cvss_vector=nvt.findtext("cvss_base_vector", "") if nvt is not None else "",
            host=host,
            port=port,
            protocol=protocol,
            description=result.findtext("description", ""),
            solution=nvt.findtext("solution", "") if nvt is not None else "",
            impact=nvt.findtext("impact", "") if nvt is not None else "",
            affected=nvt.findtext("affected", "") if nvt is not None else "",
            insight=nvt.findtext("insight", "") if nvt is not None else "",
            detection=nvt.findtext("detection", "") if nvt is not None else "",
            references=[],
            cve_ids=cve_ids,
            bid_ids=bid_ids,
            xref=xrefs,
            qod=qod_value,
            qod_type=qod_type,
        )
    
    async def run_scan(
        self,
        target: str,
        scan_name: Optional[str] = None,
        scan_type: str = "full_and_fast",
        port_list: str = "openvas_default",
        scan_config_id: Optional[str] = None,
        port_list_id: Optional[str] = None,
        wait_for_completion: bool = False,
        poll_interval: int = 30,
        timeout: int = 3600,
        # Advanced options - credentials for authenticated scanning
        ssh_credential_id: Optional[str] = None,
        smb_credential_id: Optional[str] = None,
        snmp_credential_id: Optional[str] = None,
        esxi_credential_id: Optional[str] = None,
        # Advanced options - target configuration
        alive_test: Optional[str] = None,
        exclude_hosts: Optional[str] = None,
        # Advanced options - task configuration
        schedule_id: Optional[str] = None,
        alert_ids: Optional[List[str]] = None,
        max_hosts: Optional[int] = None,
        max_checks: Optional[int] = None,
    ) -> OpenVASScanResult:
        """
        High-level method to run a complete OpenVAS scan.
        
        Args:
            target: IP address, hostname, or CIDR range to scan
            scan_name: Optional name for the scan
            scan_type: Scan configuration type (see SCAN_CONFIGS)
            port_list: Port list to use (see PORT_LISTS)
            scan_config_id: Optional explicit scan config ID (overrides scan_type)
            port_list_id: Optional explicit port list ID (overrides port_list)
            wait_for_completion: Wait for scan to complete
            poll_interval: Seconds between status checks
            timeout: Maximum wait time in seconds
            ssh_credential_id: SSH credential for authenticated Linux scanning
            smb_credential_id: SMB credential for authenticated Windows scanning
            snmp_credential_id: SNMP credential for network device scanning
            esxi_credential_id: ESXi credential for VMware scanning
            alive_test: Host alive detection method
            exclude_hosts: Hosts to exclude from scanning
            schedule_id: Schedule ID for recurring scans
            alert_ids: Alert IDs for notifications
            max_hosts: Maximum simultaneous hosts to scan
            max_checks: Maximum simultaneous checks per host
            
        Returns:
            OpenVASScanResult with findings (or status if not waiting)
        """
        # Authenticate if needed
        if not self._session_token:
            await self.authenticate()
        
        # Generate name if not provided
        if not scan_name:
            scan_name = f"VRAgent_Scan_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Create target with all options
        target_id = await self.create_target(
            name=f"Target_{scan_name}",
            hosts=target,
            port_list_id=port_list_id or self.PORT_LISTS.get(port_list, self.PORT_LISTS["openvas_default"]),
            ssh_credential_id=ssh_credential_id,
            smb_credential_id=smb_credential_id,
            snmp_credential_id=snmp_credential_id,
            esxi_credential_id=esxi_credential_id,
            alive_test=alive_test,
            exclude_hosts=exclude_hosts,
        )
        
        # Create task with all options
        task_id = await self.create_task(
            name=scan_name,
            target_id=target_id,
            scan_config_id=scan_config_id or self.SCAN_CONFIGS.get(scan_type, self.SCAN_CONFIGS["full_and_fast"]),
            schedule_id=schedule_id,
            alert_ids=alert_ids,
            max_hosts=max_hosts,
            max_checks=max_checks,
        )
        
        # Start task
        report_id = await self.start_task(task_id)
        
        if not wait_for_completion:
            # Return immediately with task info
            return OpenVASScanResult(
                task_id=task_id,
                target_id=target_id,
                report_id=report_id,
                status=ScanStatus.RUNNING,
                progress=0,
            )
        
        # Wait for completion
        start_time = datetime.now()
        while True:
            status = await self.get_task_status(task_id)
            
            if status["status"] == ScanStatus.DONE.value:
                break
            
            if status["status"] in [ScanStatus.STOPPED.value, ScanStatus.INTERRUPTED.value]:
                logger.warning(f"Scan {task_id} was stopped/interrupted")
                break
            
            # Check timeout
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > timeout:
                logger.warning(f"Scan {task_id} timed out after {timeout}s")
                await self.stop_task(task_id)
                break
            
            logger.info(f"OpenVAS scan progress: {status['progress']}%")
            await asyncio.sleep(poll_interval)
        
        # Get full report
        if report_id:
            return await self.get_report(report_id)
        else:
            return OpenVASScanResult(
                task_id=task_id,
                target_id=target_id,
                report_id="",
                status=ScanStatus.STOPPED,
                progress=0,
            )
    
    async def delete_task(self, task_id: str) -> bool:
        """Delete a scan task."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<delete_task task_id="{task_id}" ultimate="1"/>'
        await self._gmp_command(command)
        logger.info(f"Deleted OpenVAS task {task_id}")
        return True
    
    async def delete_target(self, target_id: str) -> bool:
        """Delete a scan target."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<delete_target target_id="{target_id}" ultimate="1"/>'
        await self._gmp_command(command)
        logger.info(f"Deleted OpenVAS target {target_id}")
        return True
    
    async def get_nvt_families(self) -> List[Dict[str, Any]]:
        """Get available NVT (vulnerability test) families."""
        if not self._session_token:
            await self.authenticate()
        
        command = "<get_nvt_families/>"
        response = await self._gmp_command(command)
        
        families = []
        for family in response.findall(".//family"):
            families.append({
                "name": family.findtext("name", ""),
                "max_nvt_count": int(family.findtext("max_nvt_count", "0")),
            })
        
        return families
    
    async def get_scan_configs(self) -> List[Dict[str, Any]]:
        """Get all available scan configurations."""
        if not self._session_token:
            await self.authenticate()
        
        command = "<get_configs/>"
        response = await self._gmp_command(command)
        
        configs = []
        for config in response.findall(".//config"):
            configs.append({
                "id": config.get("id", ""),
                "name": config.findtext("name", ""),
                "comment": config.findtext("comment", ""),
                "family_count": int(config.findtext("family_count/growing", "0")),
                "nvt_count": int(config.findtext("nvt_count/growing", "0")),
                "type": config.findtext("type", ""),
            })
        
        return configs
    
    async def clone_config(self, config_id: str, name: str) -> str:
        """
        Clone an existing scan configuration to create a custom one.
        
        Args:
            config_id: ID of configuration to clone
            name: Name for the new configuration
            
        Returns:
            New configuration ID
        """
        if not self._session_token:
            await self.authenticate()
        
        command = f'<create_config><copy>{config_id}</copy><name>{xml_escape(name)}</name></create_config>'
        response = await self._gmp_command(command)
        new_config_id = response.get("id")
        
        if not new_config_id:
            raise Exception("Failed to clone config - no ID returned")
        
        logger.info(f"Cloned OpenVAS config {config_id} -> {new_config_id} ({name})")
        return new_config_id
    
    async def modify_config_family_selection(
        self,
        config_id: str,
        family_name: str,
        selected: bool = True,
        grow: bool = True,
    ) -> bool:
        """
        Modify NVT family selection in a scan configuration.
        
        Args:
            config_id: ID of configuration to modify
            family_name: Name of the NVT family (e.g., "Web Servers", "Databases")
            selected: Whether to enable this family
            grow: Whether to automatically include new NVTs added to this family
            
        Returns:
            True if successful
        """
        if not self._session_token:
            await self.authenticate()
        
        selected_val = "1" if selected else "0"
        grow_val = "1" if grow else "0"
        
        command = f"""
        <modify_config config_id="{config_id}">
            <family_selection>
                <growing>{grow_val}</growing>
                <family>
                    <name>{xml_escape(family_name)}</name>
                    <all>{selected_val}</all>
                    <growing>{grow_val}</growing>
                </family>
            </family_selection>
        </modify_config>
        """
        
        await self._gmp_command(command)
        logger.info(f"Modified config {config_id}: family '{family_name}' = {selected}")
        return True
    
    async def modify_config_nvt_selection(
        self,
        config_id: str,
        nvt_oids: List[str],
        family_name: str,
    ) -> bool:
        """
        Select specific NVTs by OID in a scan configuration.
        
        Args:
            config_id: ID of configuration to modify
            nvt_oids: List of NVT OIDs to enable
            family_name: Family these NVTs belong to
            
        Returns:
            True if successful
        """
        if not self._session_token:
            await self.authenticate()
        
        nvt_elements = "\n".join([f'<nvt oid="{oid}"/>' for oid in nvt_oids])
        
        command = f"""
        <modify_config config_id="{config_id}">
            <nvt_selection>
                <family>{xml_escape(family_name)}</family>
                {nvt_elements}
            </nvt_selection>
        </modify_config>
        """
        
        await self._gmp_command(command)
        logger.info(f"Modified config {config_id}: enabled {len(nvt_oids)} NVTs in '{family_name}'")
        return True
    
    async def modify_config_preference(
        self,
        config_id: str,
        nvt_oid: str,
        preference_name: str,
        value: str,
    ) -> bool:
        """
        Modify a specific NVT preference in a scan configuration.
        
        Args:
            config_id: ID of configuration to modify
            nvt_oid: OID of the NVT (use empty string for scanner preferences)
            preference_name: Name of the preference
            value: New value for the preference
            
        Returns:
            True if successful
        """
        if not self._session_token:
            await self.authenticate()
        
        command = f"""
        <modify_config config_id="{config_id}">
            <preference>
                <nvt oid="{nvt_oid}"/>
                <name>{xml_escape(preference_name)}</name>
                <value>{xml_escape(value)}</value>
            </preference>
        </modify_config>
        """
        
        await self._gmp_command(command)
        logger.info(f"Modified config {config_id}: preference '{preference_name}' = '{value}'")
        return True
    
    async def delete_config(self, config_id: str) -> bool:
        """Delete a scan configuration."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<delete_config config_id="{config_id}" ultimate="1"/>'
        await self._gmp_command(command)
        logger.info(f"Deleted OpenVAS config {config_id}")
        return True
    
    async def get_nvts_by_family(self, family_name: str) -> List[Dict[str, Any]]:
        """
        Get all NVTs in a specific family.
        
        Args:
            family_name: Name of the NVT family
            
        Returns:
            List of NVTs with OID, name, and summary
        """
        if not self._session_token:
            await self.authenticate()
        
        command = f'<get_nvts family="{xml_escape(family_name)}" details="1"/>'
        response = await self._gmp_command(command)
        
        nvts = []
        for nvt in response.findall(".//nvt"):
            nvts.append({
                "oid": nvt.get("oid", ""),
                "name": nvt.findtext("name", ""),
                "family": nvt.findtext("family", ""),
                "cvss_base": nvt.findtext("cvss_base", ""),
                "summary": nvt.findtext("summary", "")[:200] if nvt.findtext("summary") else "",
                "solution_type": nvt.findtext("solution_type", ""),
                "qod_type": nvt.findtext("qod/type", ""),
            })
        
        return nvts
    
    async def create_custom_config_for_families(
        self,
        name: str,
        families: List[str],
        base_config: str = "full_and_fast",
    ) -> str:
        """
        Create a custom scan config with only specific NVT families enabled.
        
        This is a convenience method that:
        1. Clones a base configuration
        2. Disables all families
        3. Enables only the specified families
        
        Args:
            name: Name for the new configuration
            families: List of NVT family names to enable
            base_config: Base configuration to clone (default: full_and_fast)
            
        Returns:
            New configuration ID
        """
        # Get base config ID
        base_config_id = self.SCAN_CONFIGS.get(base_config, self.SCAN_CONFIGS["full_and_fast"])
        
        # Clone the base config
        new_config_id = await self.clone_config(base_config_id, name)
        
        # Get all available families
        all_families = await self.get_nvt_families()
        
        # Disable all families first, then enable only the requested ones
        for family in all_families:
            family_name = family["name"]
            should_enable = family_name in families
            try:
                await self.modify_config_family_selection(
                    new_config_id,
                    family_name,
                    selected=should_enable,
                    grow=should_enable,
                )
            except Exception as e:
                logger.warning(f"Failed to modify family '{family_name}': {e}")
        
        logger.info(f"Created custom config '{name}' with families: {families}")
        return new_config_id

    # ==================== CREDENTIAL MANAGEMENT ====================
    
    async def create_credential(
        self,
        name: str,
        credential_type: str,
        login: Optional[str] = None,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        key_phrase: Optional[str] = None,
        community: Optional[str] = None,
        auth_algorithm: Optional[str] = None,  # md5, sha1
        privacy_algorithm: Optional[str] = None,  # aes, des
        privacy_password: Optional[str] = None,
        comment: str = "",
    ) -> str:
        """
        Create a credential for authenticated scanning.
        
        Args:
            name: Credential name
            credential_type: Type from CREDENTIAL_TYPES (up, usk, smb, snmp, etc.)
            login: Username/login
            password: Password (for password-based auth)
            private_key: SSH private key content (for key-based auth)
            key_phrase: Passphrase for private key
            community: SNMP community string
            auth_algorithm: SNMP v3 auth algorithm (md5/sha1)
            privacy_algorithm: SNMP v3 privacy algorithm (aes/des)
            privacy_password: SNMP v3 privacy password
            comment: Optional comment
            
        Returns:
            Credential ID
        """
        if not self._session_token:
            await self.authenticate()
        
        # Validate credential type
        if credential_type not in self.CREDENTIAL_TYPES.values():
            # Try mapping from key
            credential_type = self.CREDENTIAL_TYPES.get(credential_type, credential_type)
        
        # Build credential XML based on type
        cred_elements = [
            f"<name>{xml_escape(name)}</name>",
            f"<type>{xml_escape(credential_type)}</type>",
            f"<comment>{xml_escape(comment)}</comment>",
        ]
        
        if login:
            cred_elements.append(f"<login>{xml_escape(login)}</login>")
        
        if password:
            cred_elements.append(f"<password>{xml_escape(password)}</password>")
        
        if private_key:
            key_section = f"<key><private>{xml_escape(private_key)}</private>"
            if key_phrase:
                key_section += f"<phrase>{xml_escape(key_phrase)}</phrase>"
            key_section += "</key>"
            cred_elements.append(key_section)
        
        if community:
            cred_elements.append(f"<community>{xml_escape(community)}</community>")
        
        if auth_algorithm:
            cred_elements.append(f"<auth_algorithm>{xml_escape(auth_algorithm)}</auth_algorithm>")
        
        if privacy_algorithm and privacy_password:
            cred_elements.append(f"""
                <privacy>
                    <algorithm>{xml_escape(privacy_algorithm)}</algorithm>
                    <password>{xml_escape(privacy_password)}</password>
                </privacy>
            """)
        
        command = f"""
        <create_credential>
            {''.join(cred_elements)}
        </create_credential>
        """
        
        response = await self._gmp_command(command)
        credential_id = response.get("id")
        
        if not credential_id:
            raise Exception("Failed to create credential - no ID returned")
        
        logger.info(f"Created OpenVAS credential: {credential_id} ({name})")
        return credential_id
    
    async def get_credentials(self) -> List[Dict[str, Any]]:
        """Get all credentials."""
        if not self._session_token:
            await self.authenticate()
        
        command = "<get_credentials/>"
        response = await self._gmp_command(command)
        
        credentials = []
        for cred in response.findall(".//credential"):
            credentials.append({
                "id": cred.get("id", ""),
                "name": cred.findtext("name", ""),
                "type": cred.findtext("type", ""),
                "login": cred.findtext("login", ""),
                "comment": cred.findtext("comment", ""),
                "creation_time": cred.findtext("creation_time", ""),
            })
        
        return credentials
    
    async def delete_credential(self, credential_id: str) -> bool:
        """Delete a credential."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<delete_credential credential_id="{credential_id}" ultimate="1"/>'
        await self._gmp_command(command)
        logger.info(f"Deleted OpenVAS credential {credential_id}")
        return True
    
    # ==================== ALERT MANAGEMENT ====================
    
    async def create_alert(
        self,
        name: str,
        condition: str = "always",
        event: str = "task_run_status_changed",
        method: str = "email",
        method_data: Optional[Dict[str, str]] = None,
        condition_data: Optional[Dict[str, str]] = None,
        event_data: Optional[Dict[str, str]] = None,
        comment: str = "",
    ) -> str:
        """
        Create an alert for scan notifications.
        
        Args:
            name: Alert name
            condition: Alert condition (always, severity_at_least, etc.)
            event: Alert event (task_run_status_changed, etc.)
            method: Notification method (email, http_get, syslog, etc.)
            method_data: Method-specific data (e.g., {"to_address": "admin@example.com"})
            condition_data: Condition-specific data (e.g., {"severity": "7.0"})
            event_data: Event-specific data (e.g., {"status": "Done"})
            comment: Optional comment
            
        Returns:
            Alert ID
        """
        if not self._session_token:
            await self.authenticate()
        
        # Build method data elements
        method_data_xml = ""
        if method_data:
            for key, value in method_data.items():
                method_data_xml += f"<data><name>{xml_escape(key)}</name><value>{xml_escape(value)}</value></data>"
        
        # Build condition data elements
        condition_data_xml = ""
        if condition_data:
            for key, value in condition_data.items():
                condition_data_xml += f"<data><name>{xml_escape(key)}</name><value>{xml_escape(value)}</value></data>"
        
        # Build event data elements
        event_data_xml = ""
        if event_data:
            for key, value in event_data.items():
                event_data_xml += f"<data><name>{xml_escape(key)}</name><value>{xml_escape(value)}</value></data>"
        
        command = f"""
        <create_alert>
            <name>{xml_escape(name)}</name>
            <comment>{xml_escape(comment)}</comment>
            <condition>{xml_escape(condition)}{condition_data_xml}</condition>
            <event>{xml_escape(event)}{event_data_xml}</event>
            <method>{xml_escape(method)}{method_data_xml}</method>
        </create_alert>
        """
        
        response = await self._gmp_command(command)
        alert_id = response.get("id")
        
        if not alert_id:
            raise Exception("Failed to create alert - no ID returned")
        
        logger.info(f"Created OpenVAS alert: {alert_id} ({name})")
        return alert_id
    
    async def get_alerts(self) -> List[Dict[str, Any]]:
        """Get all alerts."""
        if not self._session_token:
            await self.authenticate()
        
        command = "<get_alerts/>"
        response = await self._gmp_command(command)
        
        alerts = []
        for alert in response.findall(".//alert"):
            alerts.append({
                "id": alert.get("id", ""),
                "name": alert.findtext("name", ""),
                "condition": alert.findtext("condition", ""),
                "event": alert.findtext("event", ""),
                "method": alert.findtext("method", ""),
                "comment": alert.findtext("comment", ""),
            })
        
        return alerts
    
    async def delete_alert(self, alert_id: str) -> bool:
        """Delete an alert."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<delete_alert alert_id="{alert_id}" ultimate="1"/>'
        await self._gmp_command(command)
        logger.info(f"Deleted OpenVAS alert {alert_id}")
        return True
    
    # ==================== SCHEDULE MANAGEMENT ====================
    
    async def create_schedule(
        self,
        name: str,
        icalendar: Optional[str] = None,
        first_time: Optional[str] = None,
        duration: Optional[int] = None,
        period: Optional[int] = None,
        period_unit: str = "day",
        timezone: str = "UTC",
        comment: str = "",
    ) -> str:
        """
        Create a schedule for automated scanning.
        
        Args:
            name: Schedule name
            icalendar: Full iCalendar string (if provided, overrides other timing params)
            first_time: First run time (ISO 8601 format)
            duration: Duration in seconds (0 = until completion)
            period: Repeat period value
            period_unit: Period unit (hour, day, week, month)
            timezone: Timezone for scheduling
            comment: Optional comment
            
        Returns:
            Schedule ID
        """
        if not self._session_token:
            await self.authenticate()
        
        schedule_elements = [
            f"<name>{xml_escape(name)}</name>",
            f"<comment>{xml_escape(comment)}</comment>",
            f"<timezone>{xml_escape(timezone)}</timezone>",
        ]
        
        if icalendar:
            # Use full iCalendar specification
            schedule_elements.append(f"<icalendar>{xml_escape(icalendar)}</icalendar>")
        else:
            # Build simple schedule
            if first_time:
                schedule_elements.append(f"<first_time>{xml_escape(first_time)}</first_time>")
            
            if duration is not None:
                schedule_elements.append(f"<duration>{duration}</duration>")
            
            if period is not None:
                schedule_elements.append(f"<period>{period}</period>")
                unit_map = {"hour": "hour", "day": "day", "week": "week", "month": "month"}
                schedule_elements.append(f"<period_unit>{unit_map.get(period_unit, 'day')}</period_unit>")
        
        command = f"""
        <create_schedule>
            {''.join(schedule_elements)}
        </create_schedule>
        """
        
        response = await self._gmp_command(command)
        schedule_id = response.get("id")
        
        if not schedule_id:
            raise Exception("Failed to create schedule - no ID returned")
        
        logger.info(f"Created OpenVAS schedule: {schedule_id} ({name})")
        return schedule_id
    
    async def get_schedules(self) -> List[Dict[str, Any]]:
        """Get all schedules."""
        if not self._session_token:
            await self.authenticate()
        
        command = "<get_schedules/>"
        response = await self._gmp_command(command)
        
        schedules = []
        for schedule in response.findall(".//schedule"):
            schedules.append({
                "id": schedule.get("id", ""),
                "name": schedule.findtext("name", ""),
                "timezone": schedule.findtext("timezone", ""),
                "icalendar": schedule.findtext("icalendar", ""),
                "comment": schedule.findtext("comment", ""),
                "next_time": schedule.findtext("next_time", ""),
            })
        
        return schedules
    
    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        if not self._session_token:
            await self.authenticate()
        
        command = f'<delete_schedule schedule_id="{schedule_id}" ultimate="1"/>'
        await self._gmp_command(command)
        logger.info(f"Deleted OpenVAS schedule {schedule_id}")
        return True


# Singleton instance
_openvas_service: Optional[OpenVASService] = None


def get_openvas_service() -> OpenVASService:
    """Get or create the OpenVAS service singleton."""
    global _openvas_service
    if _openvas_service is None:
        _openvas_service = OpenVASService()
    return _openvas_service
