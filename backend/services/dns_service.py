"""
DNS Reconnaissance Service

Provides DNS enumeration capabilities including:
- DNS record lookups (A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, SRV)
- Subdomain enumeration via wordlist
- Zone transfer attempts (AXFR)
- Reverse DNS lookups
- WHOIS integration
- DNS security analysis (DNSSEC, SPF, DMARC, DKIM)
"""

import asyncio
import socket
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ipaddress

logger = logging.getLogger("vragent.backend.services.dns_service")

# Common DNS record types to query
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "exchange",
    "remote", "blog", "webdisk", "admin", "portal", "vpn", "secure", "server",
    "api", "app", "apps", "dev", "development", "staging", "stage", "test",
    "testing", "demo", "beta", "alpha", "prod", "production", "m", "mobile",
    "shop", "store", "cdn", "static", "assets", "media", "images", "img",
    "video", "download", "downloads", "help", "support", "docs", "wiki",
    "forum", "forums", "community", "chat", "irc", "news", "status", "stats",
    "analytics", "track", "tracking", "click", "ads", "ad", "adserver",
    "search", "old", "new", "web", "web1", "web2", "web3", "server1", "server2",
    "db", "database", "mysql", "postgres", "sql", "oracle", "mongo", "redis",
    "cache", "memcache", "elastic", "elasticsearch", "kibana", "grafana",
    "jenkins", "gitlab", "github", "git", "svn", "repo", "repository",
    "backup", "backups", "bak", "archive", "archives", "old", "legacy",
    "internal", "intranet", "extranet", "private", "corp", "corporate",
    "office", "hq", "headquarters", "us", "uk", "eu", "asia", "cn", "jp",
    "auth", "sso", "login", "signin", "accounts", "account", "my", "profile",
    "user", "users", "member", "members", "client", "clients", "customer",
    "crm", "erp", "hr", "payroll", "finance", "billing", "payment", "pay",
    "gateway", "gw", "proxy", "lb", "loadbalancer", "haproxy", "nginx",
    "apache", "iis", "tomcat", "jboss", "websphere", "weblogic",
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "docker", "swarm",
    "monitor", "monitoring", "nagios", "zabbix", "prometheus", "alertmanager",
    "log", "logs", "logging", "syslog", "splunk", "graylog", "elk",
    "ci", "cd", "build", "deploy", "release", "releases", "version",
    "autodiscover", "autoconfig", "cpanel", "whm", "plesk", "webmin",
    "phpmyadmin", "pma", "adminer", "roundcube", "webmail", "squirrelmail",
    "owa", "outlook", "office365", "o365", "sharepoint", "onedrive",
]

# Extended subdomain list for thorough scans
EXTENDED_SUBDOMAINS = COMMON_SUBDOMAINS + [
    "www1", "www2", "www3", "mail1", "mail2", "mail3", "mx3", "ns5", "ns6",
    "vpn1", "vpn2", "ssl", "secure1", "secure2", "web01", "web02", "app01",
    "app02", "api1", "api2", "api-dev", "api-staging", "api-prod",
    "dev1", "dev2", "dev3", "qa", "qa1", "qa2", "uat", "preprod", "pre-prod",
    "sandbox", "lab", "labs", "poc", "pilot", "canary", "green", "blue",
    "primary", "secondary", "master", "slave", "node1", "node2", "node3",
    "worker1", "worker2", "agent", "agents", "broker", "queue", "mq", "amqp",
    "rabbitmq", "kafka", "activemq", "zeromq", "nats", "redis1", "redis2",
    "postgres1", "postgres2", "mysql1", "mysql2", "mongodb", "cassandra",
    "couchdb", "couchbase", "dynamodb", "neo4j", "influxdb", "timescaledb",
    "s3", "storage", "blob", "files", "file", "upload", "uploads", "data",
    "spark", "hadoop", "hive", "presto", "airflow", "luigi", "mlflow",
    "jupyter", "notebook", "notebooks", "rstudio", "dash", "streamlit",
    "reports", "report", "dashboard", "dashboards", "bi", "tableau", "looker",
    "sentry", "bugsnag", "rollbar", "newrelic", "datadog", "appdynamics",
    "pagerduty", "opsgenie", "victorops", "slack", "teams", "zoom", "meet",
    "confluence", "jira", "trello", "asana", "monday", "notion", "airtable",
    "calendar", "drive", "box", "dropbox", "egnyte", "nextcloud", "owncloud",
    "vault", "secrets", "keycloak", "okta", "auth0", "ping", "ldap", "ad",
    "radius", "tacacs", "kerberos", "saml", "oauth", "oidc", "jwt",
    "waf", "firewall", "ids", "ips", "siem", "soar", "edr", "xdr",
    "antivirus", "av", "scan", "scanner", "pentest", "security", "infosec",
    "soc", "noc", "ops", "devops", "sre", "platform", "infra", "infrastructure",
]


@dataclass
class DNSRecord:
    """A single DNS record."""
    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # For MX records
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    subdomain: str
    full_domain: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    status: str = "found"  # found, timeout, nxdomain
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAnalysis:
    """DNS security analysis results."""
    has_spf: bool = False
    spf_record: Optional[str] = None
    spf_issues: List[str] = field(default_factory=list)
    
    has_dmarc: bool = False
    dmarc_record: Optional[str] = None
    dmarc_issues: List[str] = field(default_factory=list)
    
    has_dkim: bool = False
    dkim_selectors_found: List[str] = field(default_factory=list)
    
    has_dnssec: bool = False
    dnssec_details: Optional[str] = None
    
    has_caa: bool = False
    caa_records: List[str] = field(default_factory=list)
    
    mail_security_score: int = 0  # 0-100
    overall_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSReconResult:
    """Complete DNS reconnaissance result."""
    domain: str
    scan_timestamp: str
    scan_duration_seconds: float
    
    # Basic records
    records: List[DNSRecord] = field(default_factory=list)
    
    # Nameservers
    nameservers: List[str] = field(default_factory=list)
    
    # Mail servers with priority
    mail_servers: List[Dict[str, Any]] = field(default_factory=list)
    
    # Subdomains found
    subdomains: List[SubdomainResult] = field(default_factory=list)
    
    # Zone transfer results
    zone_transfer_possible: bool = False
    zone_transfer_data: List[str] = field(default_factory=list)
    
    # Security analysis
    security: Optional[SecurityAnalysis] = None
    
    # Reverse DNS for found IPs
    reverse_dns: Dict[str, str] = field(default_factory=dict)
    
    # Summary stats
    total_records: int = 0
    total_subdomains: int = 0
    unique_ips: List[str] = field(default_factory=list)
    
    # AI analysis
    ai_analysis: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "domain": self.domain,
            "scan_timestamp": self.scan_timestamp,
            "scan_duration_seconds": self.scan_duration_seconds,
            "records": [r.to_dict() for r in self.records],
            "nameservers": self.nameservers,
            "mail_servers": self.mail_servers,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "zone_transfer_possible": self.zone_transfer_possible,
            "zone_transfer_data": self.zone_transfer_data,
            "security": self.security.to_dict() if self.security else None,
            "reverse_dns": self.reverse_dns,
            "total_records": self.total_records,
            "total_subdomains": self.total_subdomains,
            "unique_ips": self.unique_ips,
            "ai_analysis": self.ai_analysis,
        }
        return result


# DNS scan types/profiles
DNS_SCAN_TYPES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Basic DNS records only (A, AAAA, MX, NS, TXT)",
        "record_types": ["A", "AAAA", "MX", "NS", "TXT"],
        "subdomain_count": 0,
        "check_security": False,
        "zone_transfer": False,
        "timeout": 60,
        "estimated_time": "5-15 sec",
    },
    "standard": {
        "name": "Standard Scan",
        "description": "All record types + top 50 subdomains + security check",
        "record_types": DNS_RECORD_TYPES,
        "subdomain_count": 50,
        "check_security": True,
        "zone_transfer": True,
        "timeout": 180,
        "estimated_time": "30-90 sec",
    },
    "thorough": {
        "name": "Thorough Scan",
        "description": "All records + 150 subdomains + full security analysis",
        "record_types": DNS_RECORD_TYPES,
        "subdomain_count": 150,
        "check_security": True,
        "zone_transfer": True,
        "timeout": 300,
        "estimated_time": "2-5 min",
    },
    "subdomain_focus": {
        "name": "Subdomain Enumeration",
        "description": "Focused on finding subdomains (300+ checked)",
        "record_types": ["A", "AAAA", "CNAME"],
        "subdomain_count": 300,
        "check_security": False,
        "zone_transfer": True,
        "timeout": 600,
        "estimated_time": "3-10 min",
    },
    "security_focus": {
        "name": "Security Analysis",
        "description": "Focus on email security (SPF, DMARC, DKIM) and DNSSEC",
        "record_types": DNS_RECORD_TYPES,
        "subdomain_count": 20,
        "check_security": True,
        "zone_transfer": True,
        "timeout": 180,
        "estimated_time": "30-60 sec",
    },
}


def get_scan_types() -> List[Dict[str, Any]]:
    """Get available DNS scan types."""
    return [
        {"id": k, **v}
        for k, v in DNS_SCAN_TYPES.items()
    ]


def validate_domain(domain: str) -> Tuple[bool, str]:
    """Validate domain name format."""
    if not domain:
        return False, "Domain cannot be empty"
    
    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)
    # Remove trailing slash and path
    domain = domain.split('/')[0]
    # Remove port if present
    domain = domain.split(':')[0]
    
    # Basic domain validation
    if len(domain) > 255:
        return False, "Domain name too long"
    
    # Check for valid domain pattern
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, domain):
        # Also allow single-level domains for internal use
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$', domain):
            return False, "Invalid domain format"
    
    return True, domain


def _resolve_dns(domain: str, record_type: str, timeout: float = 5.0) -> List[DNSRecord]:
    """Resolve DNS records using dnspython or socket."""
    records = []
    
    try:
        import dns.resolver
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        try:
            answers = resolver.resolve(domain, record_type)
            
            for rdata in answers:
                value = str(rdata)
                priority = None
                
                if record_type == "MX":
                    priority = rdata.preference
                    value = str(rdata.exchange).rstrip('.')
                elif record_type == "NS":
                    value = str(rdata.target).rstrip('.')
                elif record_type == "SOA":
                    value = f"Primary: {rdata.mname}, Admin: {rdata.rname}, Serial: {rdata.serial}"
                elif record_type == "SRV":
                    value = f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    priority = rdata.priority
                
                records.append(DNSRecord(
                    record_type=record_type,
                    name=domain,
                    value=value,
                    ttl=answers.ttl,
                    priority=priority,
                ))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            pass
        except Exception as e:
            logger.debug(f"DNS resolution error for {domain} {record_type}: {e}")
            
    except ImportError:
        # Fallback to socket for basic A record resolution
        if record_type == "A":
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                for ip in ips:
                    records.append(DNSRecord(
                        record_type="A",
                        name=domain,
                        value=ip,
                    ))
            except socket.gaierror:
                pass
    
    return records


def _check_subdomain(domain: str, subdomain: str, timeout: float = 3.0) -> Optional[SubdomainResult]:
    """Check if a subdomain exists."""
    full_domain = f"{subdomain}.{domain}"
    
    try:
        import dns.resolver
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        try:
            # Try A record first
            answers = resolver.resolve(full_domain, "A")
            ips = [str(rdata) for rdata in answers]
            
            # Check for CNAME
            cname = None
            try:
                cname_answers = resolver.resolve(full_domain, "CNAME")
                cname = str(list(cname_answers)[0].target).rstrip('.')
            except:
                pass
            
            return SubdomainResult(
                subdomain=subdomain,
                full_domain=full_domain,
                ip_addresses=ips,
                cname=cname,
                status="found",
            )
            
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoAnswer:
            # Domain exists but no A record - might have other records
            return SubdomainResult(
                subdomain=subdomain,
                full_domain=full_domain,
                ip_addresses=[],
                status="found",
            )
        except dns.resolver.Timeout:
            return None
        except Exception:
            return None
            
    except ImportError:
        # Fallback to socket
        try:
            ips = socket.gethostbyname_ex(full_domain)[2]
            return SubdomainResult(
                subdomain=subdomain,
                full_domain=full_domain,
                ip_addresses=ips,
                status="found",
            )
        except socket.gaierror:
            return None


def _attempt_zone_transfer(domain: str, nameserver: str, timeout: float = 10.0) -> Tuple[bool, List[str]]:
    """Attempt DNS zone transfer (AXFR)."""
    try:
        import dns.query
        import dns.zone
        import dns.resolver
        
        # First resolve the nameserver IP
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        
        try:
            ns_ips = resolver.resolve(nameserver, "A")
            ns_ip = str(list(ns_ips)[0])
        except:
            return False, []
        
        # Attempt zone transfer
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} {rdataset.rdtype.name} {rdata}")
            return True, records
        except Exception as e:
            logger.debug(f"Zone transfer failed for {domain} via {nameserver}: {e}")
            return False, []
            
    except ImportError:
        return False, []


def _analyze_security(domain: str, records: List[DNSRecord]) -> SecurityAnalysis:
    """Analyze DNS security configuration."""
    security = SecurityAnalysis()
    
    txt_records = [r for r in records if r.record_type == "TXT"]
    
    # Check SPF
    for r in txt_records:
        if "v=spf1" in r.value.lower():
            security.has_spf = True
            security.spf_record = r.value
            
            # Analyze SPF record
            if "+all" in r.value:
                security.spf_issues.append("SPF uses +all which allows any server to send mail")
            if "~all" in r.value:
                security.spf_issues.append("SPF uses ~all (softfail) - consider -all for stricter policy")
            if r.value.count("include:") > 10:
                security.spf_issues.append("SPF has many includes - may exceed DNS lookup limit (10)")
            break
    
    if not security.has_spf:
        security.overall_issues.append("No SPF record found - email spoofing possible")
        security.recommendations.append("Add SPF record to prevent email spoofing")
    
    # Check DMARC
    dmarc_records = _resolve_dns(f"_dmarc.{domain}", "TXT")
    for r in dmarc_records:
        if "v=dmarc1" in r.value.lower():
            security.has_dmarc = True
            security.dmarc_record = r.value
            
            # Analyze DMARC
            if "p=none" in r.value.lower():
                security.dmarc_issues.append("DMARC policy is 'none' - no enforcement")
            if "rua=" not in r.value.lower():
                security.dmarc_issues.append("No aggregate report address (rua) specified")
            break
    
    if not security.has_dmarc:
        security.overall_issues.append("No DMARC record found - email authentication not enforced")
        security.recommendations.append("Add DMARC record for email authentication")
    
    # Check common DKIM selectors
    common_dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim"]
    for selector in common_dkim_selectors:
        dkim_records = _resolve_dns(f"{selector}._domainkey.{domain}", "TXT")
        for r in dkim_records:
            if "v=dkim1" in r.value.lower() or "k=rsa" in r.value.lower():
                security.has_dkim = True
                security.dkim_selectors_found.append(selector)
                break
    
    if not security.has_dkim:
        security.overall_issues.append("No DKIM records found for common selectors")
        security.recommendations.append("Implement DKIM for email authentication")
    
    # Check CAA records
    caa_records = [r for r in records if r.record_type == "CAA"]
    if caa_records:
        security.has_caa = True
        security.caa_records = [r.value for r in caa_records]
    else:
        # Try explicit CAA query
        caa_explicit = _resolve_dns(domain, "CAA")
        if caa_explicit:
            security.has_caa = True
            security.caa_records = [r.value for r in caa_explicit]
    
    if not security.has_caa:
        security.overall_issues.append("No CAA records - any CA can issue certificates")
        security.recommendations.append("Add CAA records to restrict certificate issuance")
    
    # Check DNSSEC
    try:
        import dns.resolver
        import dns.dnssec
        
        resolver = dns.resolver.Resolver()
        try:
            response = resolver.resolve(domain, "DNSKEY")
            if response:
                security.has_dnssec = True
                security.dnssec_details = f"DNSKEY records found: {len(list(response))}"
        except:
            pass
    except ImportError:
        pass
    
    if not security.has_dnssec:
        security.recommendations.append("Consider implementing DNSSEC for DNS integrity")
    
    # Calculate mail security score
    score = 0
    if security.has_spf:
        score += 30
        if not security.spf_issues:
            score += 10
    if security.has_dmarc:
        score += 30
        if "p=reject" in (security.dmarc_record or "").lower():
            score += 10
        elif "p=quarantine" in (security.dmarc_record or "").lower():
            score += 5
    if security.has_dkim:
        score += 20
    
    security.mail_security_score = min(score, 100)
    
    return security


def _reverse_dns_lookup(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


async def run_dns_recon(
    domain: str,
    scan_type: str = "standard",
    custom_subdomains: Optional[List[str]] = None,
    progress_callback: Optional[callable] = None,
) -> DNSReconResult:
    """
    Run DNS reconnaissance on a domain.
    
    Args:
        domain: Target domain to scan
        scan_type: Type of scan (quick, standard, thorough, subdomain_focus, security_focus)
        custom_subdomains: Optional list of custom subdomains to check
        progress_callback: Optional callback function(phase, progress, message) for progress updates
        
    Returns:
        DNSReconResult with all findings
    """
    start_time = datetime.now()
    
    def report_progress(phase: str, progress: int, message: str):
        """Report progress if callback is provided."""
        if progress_callback:
            try:
                progress_callback(phase, progress, message)
            except Exception as e:
                logger.debug(f"Progress callback failed: {e}")
    
    # Validate domain
    is_valid, cleaned_domain = validate_domain(domain)
    if not is_valid:
        raise ValueError(cleaned_domain)  # cleaned_domain contains error message
    domain = cleaned_domain
    
    # Get scan configuration
    scan_config = DNS_SCAN_TYPES.get(scan_type, DNS_SCAN_TYPES["standard"])
    
    logger.info(f"Starting DNS recon for {domain} with scan type: {scan_type}")
    
    result = DNSReconResult(
        domain=domain,
        scan_timestamp=start_time.isoformat(),
        scan_duration_seconds=0,
    )
    
    # Collect all records
    all_records: List[DNSRecord] = []
    
    report_progress("records", 0, "Querying DNS records...")
    
    # Query each record type
    record_types = scan_config["record_types"]
    for i, record_type in enumerate(record_types):
        report_progress("records", int((i / len(record_types)) * 100), f"Querying {record_type} records...")
        records = _resolve_dns(domain, record_type)
        all_records.extend(records)
        
        # Extract nameservers and mail servers
        if record_type == "NS":
            result.nameservers = [r.value for r in records]
        elif record_type == "MX":
            result.mail_servers = [
                {"server": r.value, "priority": r.priority}
                for r in sorted(records, key=lambda x: x.priority or 0)
            ]
    
    report_progress("records", 100, f"Found {len(all_records)} DNS records")
    result.records = all_records
    result.total_records = len(all_records)
    
    # Subdomain enumeration
    subdomain_count = scan_config["subdomain_count"]
    if subdomain_count > 0 or custom_subdomains:
        subdomains_to_check = []
        
        if custom_subdomains:
            subdomains_to_check.extend(custom_subdomains)
        
        if subdomain_count > 0:
            if subdomain_count <= len(COMMON_SUBDOMAINS):
                subdomains_to_check.extend(COMMON_SUBDOMAINS[:subdomain_count])
            else:
                subdomains_to_check.extend(EXTENDED_SUBDOMAINS[:subdomain_count])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_subdomains = []
        for s in subdomains_to_check:
            if s.lower() not in seen:
                seen.add(s.lower())
                unique_subdomains.append(s)
        
        logger.info(f"Checking {len(unique_subdomains)} subdomains for {domain}")
        report_progress("subdomains", 0, f"Checking {len(unique_subdomains)} subdomains...")
        
        # Use thread pool for parallel subdomain checking with progress tracking
        found_subdomains = []
        total_to_check = len(unique_subdomains)
        checked_count = 0
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            loop = asyncio.get_event_loop()
            
            # Process in batches for progress reporting
            batch_size = 20
            for batch_start in range(0, len(unique_subdomains), batch_size):
                batch_end = min(batch_start + batch_size, len(unique_subdomains))
                batch = unique_subdomains[batch_start:batch_end]
                
                futures = [
                    loop.run_in_executor(executor, _check_subdomain, domain, sub)
                    for sub in batch
                ]
                
                batch_results = await asyncio.gather(*futures)
                
                for sub_result in batch_results:
                    if sub_result:
                        found_subdomains.append(sub_result)
                
                checked_count += len(batch)
                progress_pct = int((checked_count / total_to_check) * 100)
                report_progress("subdomains", progress_pct, f"Checked {checked_count}/{total_to_check} subdomains, found {len(found_subdomains)}")
        
        result.subdomains = found_subdomains
        result.total_subdomains = len(found_subdomains)
        report_progress("subdomains", 100, f"Found {len(found_subdomains)} subdomains")
        logger.info(f"Found {len(found_subdomains)} subdomains for {domain}")
    
    # Zone transfer attempt
    if scan_config["zone_transfer"] and result.nameservers:
        report_progress("zone_transfer", 0, "Testing zone transfer...")
        logger.info(f"Attempting zone transfer for {domain}")
        for i, ns in enumerate(result.nameservers[:3]):  # Try first 3 nameservers
            report_progress("zone_transfer", int((i / min(3, len(result.nameservers))) * 100), f"Testing {ns}...")
            success, zone_data = _attempt_zone_transfer(domain, ns)
            if success:
                result.zone_transfer_possible = True
                result.zone_transfer_data = zone_data[:500]  # Limit output
                logger.warning(f"Zone transfer successful for {domain} via {ns}!")
                break
        report_progress("zone_transfer", 100, "Zone transfer check complete")
    
    # Security analysis
    if scan_config["check_security"]:
        report_progress("security", 0, "Analyzing DNS security...")
        logger.info(f"Analyzing DNS security for {domain}")
        result.security = _analyze_security(domain, all_records)
        report_progress("security", 100, f"Security analysis complete - Score: {result.security.mail_security_score}/100")
    
    # Collect unique IPs
    all_ips = set()
    for record in all_records:
        if record.record_type in ["A", "AAAA"]:
            all_ips.add(record.value)
    for sub in result.subdomains:
        all_ips.update(sub.ip_addresses)
    
    result.unique_ips = sorted(list(all_ips))
    
    # Reverse DNS for found IPs (limit to 20)
    report_progress("reverse_dns", 0, "Performing reverse DNS lookups...")
    reverse_dns = {}
    ip_list = list(all_ips)[:20]
    for i, ip in enumerate(ip_list):
        hostname = _reverse_dns_lookup(ip)
        if hostname:
            reverse_dns[ip] = hostname
        if i % 5 == 0:
            report_progress("reverse_dns", int((i / len(ip_list)) * 100), f"Reverse DNS: {i}/{len(ip_list)}")
    result.reverse_dns = reverse_dns
    
    # Calculate duration
    end_time = datetime.now()
    result.scan_duration_seconds = (end_time - start_time).total_seconds()
    
    report_progress("complete", 100, f"Scan complete: {result.total_records} records, {result.total_subdomains} subdomains")
    logger.info(f"DNS recon complete for {domain}: {result.total_records} records, {result.total_subdomains} subdomains in {result.scan_duration_seconds:.1f}s")
    
    return result


def is_dns_available() -> bool:
    """Check if DNS resolution is working."""
    try:
        socket.gethostbyname("google.com")
        return True
    except:
        return False


def get_dns_status() -> Dict[str, Any]:
    """Get DNS service status."""
    has_dnspython = False
    try:
        import dns.resolver
        has_dnspython = True
    except ImportError:
        pass
    
    return {
        "available": is_dns_available(),
        "dnspython_installed": has_dnspython,
        "message": "DNS reconnaissance ready" if is_dns_available() else "DNS resolution not working",
        "features": {
            "basic_records": True,
            "subdomain_enum": True,
            "zone_transfer": has_dnspython,
            "security_analysis": has_dnspython,
            "dnssec_check": has_dnspython,
            "whois_lookup": is_whois_available(),
        }
    }


# ============================================================================
# WHOIS Functions
# ============================================================================

def is_whois_available() -> bool:
    """Check if whois command is available."""
    import shutil
    return shutil.which("whois") is not None


@dataclass
class WhoisDomainResult:
    """WHOIS lookup result for a domain."""
    domain: str
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_email: Optional[str] = None
    admin_email: Optional[str] = None
    tech_email: Optional[str] = None
    dnssec: Optional[str] = None
    raw_text: str = ""
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WhoisIPResult:
    """WHOIS lookup result for an IP address."""
    ip_address: str
    network_name: Optional[str] = None
    network_range: Optional[str] = None
    cidr: Optional[str] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    registrar: Optional[str] = None  # RIR (ARIN, RIPE, APNIC, etc.)
    registration_date: Optional[str] = None
    updated_date: Optional[str] = None
    abuse_contact: Optional[str] = None
    tech_contact: Optional[str] = None
    description: List[str] = field(default_factory=list)
    raw_text: str = ""
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_whois_domain(domain: str) -> WhoisDomainResult:
    """Run WHOIS lookup for a domain."""
    import subprocess
    
    result = WhoisDomainResult(domain=domain)
    
    if not is_whois_available():
        result.error = "WHOIS command not available"
        return result
    
    try:
        # Run whois command
        proc = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = proc.stdout
        result.raw_text = output
        
        if not output or "No match for" in output or "NOT FOUND" in output.upper():
            result.error = "Domain not found in WHOIS database"
            return result
        
        # Parse the output
        lines = output.split("\n")
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Registrar
            if line_lower.startswith("registrar:"):
                result.registrar = line.split(":", 1)[1].strip()
            elif line_lower.startswith("registrar url:"):
                result.registrar_url = line.split(":", 1)[1].strip()
            
            # Dates - be specific to avoid matching descriptions
            elif line_lower.startswith("creation date:") or line_lower.startswith("created:") or line_lower.startswith("registered:"):
                result.creation_date = line.split(":", 1)[1].strip()
            elif line_lower.startswith("registry expiry date:") or line_lower.startswith("expiration date:") or line_lower.startswith("registrar registration expiration date:"):
                result.expiration_date = line.split(":", 1)[1].strip()
            elif line_lower.startswith("updated date:") or line_lower.startswith("last updated:"):
                result.updated_date = line.split(":", 1)[1].strip()
            
            # Name servers
            elif line_lower.startswith("name server:") or line_lower.startswith("nserver:"):
                ns = line.split(":", 1)[1].strip()
                if ns and ns not in result.name_servers:
                    result.name_servers.append(ns)
            
            # Status
            elif line_lower.startswith("domain status:") or line_lower.startswith("status:"):
                status = line.split(":", 1)[1].strip()
                if status and status not in result.status:
                    result.status.append(status)
            
            # Registrant info (be careful with privacy)
            elif line_lower.startswith("registrant name:"):
                result.registrant_name = line.split(":", 1)[1].strip()
            elif line_lower.startswith("registrant organization:") or line_lower.startswith("registrant org:"):
                result.registrant_organization = line.split(":", 1)[1].strip()
            elif line_lower.startswith("registrant country:"):
                result.registrant_country = line.split(":", 1)[1].strip()
            elif line_lower.startswith("registrant email:"):
                email = line.split(":", 1)[1].strip()
                if "@" in email:  # Only store if it looks like an email
                    result.registrant_email = email
            
            # Admin email
            elif line_lower.startswith("admin email:"):
                email = line.split(":", 1)[1].strip()
                if "@" in email:
                    result.admin_email = email
            
            # Tech email
            elif line_lower.startswith("tech email:"):
                email = line.split(":", 1)[1].strip()
                if "@" in email:
                    result.tech_email = email
            
            # DNSSEC
            elif "dnssec:" in line_lower:
                result.dnssec = line.split(":", 1)[1].strip()
        
        logger.info(f"WHOIS lookup complete for domain {domain}")
        return result
        
    except subprocess.TimeoutExpired:
        result.error = "WHOIS lookup timed out"
        return result
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        result.error = str(e)
        return result


def run_whois_ip(ip_address: str) -> WhoisIPResult:
    """Run WHOIS lookup for an IP address."""
    import subprocess
    
    result = WhoisIPResult(ip_address=ip_address)
    
    if not is_whois_available():
        result.error = "WHOIS command not available"
        return result
    
    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        result.error = "Invalid IP address format"
        return result
    
    try:
        # Run whois command
        proc = subprocess.run(
            ["whois", ip_address],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = proc.stdout
        result.raw_text = output
        
        if not output:
            result.error = "No WHOIS data returned"
            return result
        
        # Parse the output
        lines = output.split("\n")
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Skip comments and empty lines
            if line.startswith("%") or line.startswith("#") or not line.strip():
                continue
            
            # Network name
            if line_lower.startswith("netname:") or line_lower.startswith("network name:"):
                result.network_name = line.split(":", 1)[1].strip()
            
            # Network range / CIDR
            elif line_lower.startswith("inetnum:") or line_lower.startswith("netrange:"):
                result.network_range = line.split(":", 1)[1].strip()
            elif line_lower.startswith("cidr:"):
                result.cidr = line.split(":", 1)[1].strip()
            
            # ASN
            elif line_lower.startswith("origin:") or line_lower.startswith("originas:"):
                result.asn = line.split(":", 1)[1].strip()
            elif line_lower.startswith("as-name:") or line_lower.startswith("asname:"):
                result.asn_name = line.split(":", 1)[1].strip()
            
            # Organization
            elif line_lower.startswith("org-name:") or line_lower.startswith("orgname:"):
                result.organization = line.split(":", 1)[1].strip()
            elif line_lower.startswith("organization:") and not result.organization:
                result.organization = line.split(":", 1)[1].strip()
            
            # Country
            elif line_lower.startswith("country:"):
                if not result.country:  # Take first occurrence
                    result.country = line.split(":", 1)[1].strip()
            
            # Registrar (RIR)
            elif line_lower.startswith("source:"):
                source = line.split(":", 1)[1].strip()
                if source.upper() in ["ARIN", "RIPE", "APNIC", "LACNIC", "AFRINIC"]:
                    result.registrar = source.upper()
            
            # Dates
            elif line_lower.startswith("regdate:") or line_lower.startswith("created:"):
                result.registration_date = line.split(":", 1)[1].strip()
            elif line_lower.startswith("updated:") or line_lower.startswith("last-modified:"):
                result.updated_date = line.split(":", 1)[1].strip()
            
            # Abuse contact
            elif "abuse" in line_lower and "@" in line:
                email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
                if email_match and not result.abuse_contact:
                    result.abuse_contact = email_match.group()
            
            # Tech contact
            elif line_lower.startswith("techc-email:") or line_lower.startswith("tech-c:"):
                if "@" in line:
                    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
                    if email_match:
                        result.tech_contact = email_match.group()
            
            # Description
            elif line_lower.startswith("descr:") or line_lower.startswith("comment:"):
                desc = line.split(":", 1)[1].strip()
                if desc and len(result.description) < 5:  # Limit to 5 description lines
                    result.description.append(desc)
        
        # Try to find organization from OrgId reference if not found
        if not result.organization:
            for line in lines:
                if line.lower().startswith("org:"):
                    result.organization = line.split(":", 1)[1].strip()
                    break
        
        logger.info(f"WHOIS lookup complete for IP {ip_address}")
        return result
        
    except subprocess.TimeoutExpired:
        result.error = "WHOIS lookup timed out"
        return result
    except Exception as e:
        logger.error(f"WHOIS lookup failed for {ip_address}: {e}")
        result.error = str(e)
        return result
