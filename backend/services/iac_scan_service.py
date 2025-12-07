"""
Infrastructure as Code (IaC) Scanning Service

Scans infrastructure configuration files for security misconfigurations:
1. Terraform (.tf, .tfvars)
2. CloudFormation (JSON/YAML templates)
3. Kubernetes manifests (YAML)
4. Helm charts
5. ARM templates (Azure)
6. Pulumi

Uses:
- Checkov - Multi-framework IaC scanner
- tfsec - Terraform-specific scanner
- Built-in pattern matching for common issues
"""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class IaCFinding:
    """Security finding in Infrastructure as Code."""
    rule_id: str
    severity: str
    file_path: str
    line_number: int
    resource_type: str  # e.g., "aws_s3_bucket", "kubernetes_pod"
    resource_name: str
    message: str
    remediation: str = ""
    framework: str = ""  # terraform, cloudformation, kubernetes, etc.
    check_type: str = ""  # e.g., "CKV_AWS_1", "CKV_K8S_1"
    guideline: str = ""  # Link to documentation


@dataclass
class IaCScanResult:
    """Complete result of IaC scanning."""
    files_scanned: int = 0
    findings: List[IaCFinding] = field(default_factory=list)
    frameworks_detected: Set[str] = field(default_factory=set)
    resources_analyzed: int = 0
    passed_checks: int = 0
    failed_checks: int = 0


def is_checkov_available() -> bool:
    """Check if Checkov is installed."""
    return shutil.which("checkov") is not None


def is_tfsec_available() -> bool:
    """Check if tfsec is installed."""
    return shutil.which("tfsec") is not None


# Built-in IaC security rules for pattern matching
IAC_RULES = {
    "terraform": [
        {
            "id": "TF001",
            "pattern": r'acl\s*=\s*["\']public-read',
            "severity": "high",
            "message": "S3 bucket has public read ACL",
            "remediation": "Set acl = 'private' or use bucket policies",
            "resource_pattern": r"aws_s3_bucket",
        },
        {
            "id": "TF002",
            "pattern": r'encrypted\s*=\s*false',
            "severity": "high",
            "message": "Resource encryption is disabled",
            "remediation": "Enable encryption: encrypted = true",
            "resource_pattern": None,
        },
        {
            "id": "TF003",
            "pattern": r'publicly_accessible\s*=\s*true',
            "severity": "critical",
            "message": "Database is publicly accessible",
            "remediation": "Set publicly_accessible = false",
            "resource_pattern": r"aws_db_instance|aws_rds",
        },
        {
            "id": "TF004",
            "pattern": r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0',
            "severity": "high",
            "message": "Security group allows traffic from any IP (0.0.0.0/0)",
            "remediation": "Restrict CIDR blocks to specific IP ranges",
            "resource_pattern": r"aws_security_group",
        },
        {
            "id": "TF005",
            "pattern": r'protocol\s*=\s*["\'](-1|all)',
            "severity": "medium",
            "message": "Security group rule allows all protocols",
            "remediation": "Specify explicit protocols (tcp, udp)",
            "resource_pattern": r"aws_security_group",
        },
        {
            "id": "TF006",
            "pattern": r'versioning\s*\{[^}]*enabled\s*=\s*false',
            "severity": "medium",
            "message": "S3 bucket versioning is disabled",
            "remediation": "Enable versioning for data protection",
            "resource_pattern": r"aws_s3_bucket",
        },
        {
            "id": "TF007",
            "pattern": r'logging\s*\{[^}]*target_bucket\s*=\s*""',
            "severity": "medium",
            "message": "Access logging is not configured",
            "remediation": "Configure access logging for audit trails",
            "resource_pattern": None,
        },
        {
            "id": "TF008",
            "pattern": r'kms_key_id\s*=\s*""',
            "severity": "medium",
            "message": "KMS key not specified for encryption",
            "remediation": "Specify a KMS key for encryption at rest",
            "resource_pattern": None,
        },
        {
            "id": "TF009",
            "pattern": r'deletion_protection\s*=\s*false',
            "severity": "medium",
            "message": "Deletion protection is disabled",
            "remediation": "Enable deletion_protection = true for production resources",
            "resource_pattern": None,
        },
        {
            "id": "TF010",
            "pattern": r'password\s*=\s*["\'][^"\']+["\']',
            "severity": "critical",
            "message": "Hardcoded password in Terraform configuration",
            "remediation": "Use variables, Vault, or AWS Secrets Manager",
            "resource_pattern": None,
        },
    ],
    "kubernetes": [
        {
            "id": "K8S001",
            "pattern": r'privileged:\s*true',
            "severity": "critical",
            "message": "Container running in privileged mode",
            "remediation": "Set privileged: false unless absolutely necessary",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S002",
            "pattern": r'runAsUser:\s*0',
            "severity": "high",
            "message": "Container running as root user",
            "remediation": "Set runAsUser to non-zero UID",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S003",
            "pattern": r'allowPrivilegeEscalation:\s*true',
            "severity": "high",
            "message": "Container allows privilege escalation",
            "remediation": "Set allowPrivilegeEscalation: false",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S004",
            "pattern": r'readOnlyRootFilesystem:\s*false',
            "severity": "medium",
            "message": "Container root filesystem is writable",
            "remediation": "Set readOnlyRootFilesystem: true",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S005",
            "pattern": r'hostNetwork:\s*true',
            "severity": "high",
            "message": "Pod uses host network namespace",
            "remediation": "Avoid hostNetwork: true unless necessary",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S006",
            "pattern": r'hostPID:\s*true',
            "severity": "high",
            "message": "Pod uses host PID namespace",
            "remediation": "Avoid hostPID: true",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S007",
            "pattern": r'hostIPC:\s*true',
            "severity": "high",
            "message": "Pod uses host IPC namespace",
            "remediation": "Avoid hostIPC: true",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S008",
            "pattern": r'capabilities:\s*\n\s*add:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)',
            "severity": "high",
            "message": "Container has dangerous capabilities",
            "remediation": "Drop all capabilities and add only required ones",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S009",
            "pattern": r'image:\s*[^:]+\s*$|image:\s*[^:]+:latest',
            "severity": "medium",
            "message": "Container image uses 'latest' tag or no tag",
            "remediation": "Use specific image tags for reproducibility",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S010",
            "pattern": r'imagePullPolicy:\s*(?:Always|Never)\s*$',
            "severity": "low",
            "message": "Image pull policy may cause issues",
            "remediation": "Use imagePullPolicy: IfNotPresent with pinned tags",
            "resource_pattern": r"Pod|Deployment|StatefulSet|DaemonSet",
        },
        {
            "id": "K8S011",
            "pattern": r'type:\s*NodePort',
            "severity": "medium",
            "message": "Service exposes NodePort (accessible on all nodes)",
            "remediation": "Use ClusterIP or LoadBalancer with proper network policies",
            "resource_pattern": r"Service",
        },
        {
            "id": "K8S012",
            "pattern": r'automountServiceAccountToken:\s*true',
            "severity": "medium",
            "message": "Service account token auto-mounted",
            "remediation": "Set automountServiceAccountToken: false if not needed",
            "resource_pattern": r"Pod|ServiceAccount",
        },
    ],
    "cloudformation": [
        {
            "id": "CFN001",
            "pattern": r'"PubliclyAccessible"\s*:\s*true',
            "severity": "critical",
            "message": "RDS instance is publicly accessible",
            "remediation": "Set PubliclyAccessible to false",
            "resource_pattern": r"AWS::RDS::DBInstance",
        },
        {
            "id": "CFN002",
            "pattern": r'"CidrIp"\s*:\s*"0\.0\.0\.0/0"',
            "severity": "high",
            "message": "Security group allows traffic from any IP",
            "remediation": "Restrict CidrIp to specific ranges",
            "resource_pattern": r"AWS::EC2::SecurityGroup",
        },
        {
            "id": "CFN003",
            "pattern": r'"Encrypted"\s*:\s*false',
            "severity": "high",
            "message": "Encryption is disabled",
            "remediation": "Set Encrypted to true",
            "resource_pattern": None,
        },
        {
            "id": "CFN004",
            "pattern": r'"AccessControl"\s*:\s*"PublicRead',
            "severity": "high",
            "message": "S3 bucket has public read access",
            "remediation": "Use Private access control",
            "resource_pattern": r"AWS::S3::Bucket",
        },
        {
            "id": "CFN005",
            "pattern": r'"VersioningConfiguration"[^}]*"Status"\s*:\s*"Suspended"',
            "severity": "medium",
            "message": "S3 bucket versioning is suspended",
            "remediation": "Enable versioning for data protection",
            "resource_pattern": r"AWS::S3::Bucket",
        },
    ],
    "arm": [
        {
            "id": "ARM001",
            "pattern": r'"publicNetworkAccess"\s*:\s*"Enabled"',
            "severity": "high",
            "message": "Public network access is enabled",
            "remediation": "Disable public network access",
            "resource_pattern": None,
        },
        {
            "id": "ARM002",
            "pattern": r'"httpsOnly"\s*:\s*false',
            "severity": "high",
            "message": "HTTPS-only is disabled",
            "remediation": "Set httpsOnly to true",
            "resource_pattern": None,
        },
        {
            "id": "ARM003",
            "pattern": r'"enabledForDiskEncryption"\s*:\s*false',
            "severity": "high",
            "message": "Disk encryption is disabled",
            "remediation": "Enable disk encryption",
            "resource_pattern": None,
        },
    ],
}


def detect_iac_framework(file_path: Path) -> Optional[str]:
    """Detect the IaC framework based on file extension and content."""
    suffix = file_path.suffix.lower()
    name = file_path.name.lower()
    
    # Check by extension
    if suffix in (".tf", ".tfvars"):
        return "terraform"
    
    if suffix in (".yaml", ".yml"):
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Kubernetes detection
            if any(kind in content for kind in [
                "kind: Pod", "kind: Deployment", "kind: Service",
                "kind: ConfigMap", "kind: Secret", "kind: StatefulSet",
                "kind: DaemonSet", "kind: Ingress", "kind: NetworkPolicy",
                "apiVersion: v1", "apiVersion: apps/v1"
            ]):
                return "kubernetes"
            
            # CloudFormation detection
            if "AWSTemplateFormatVersion" in content or "AWS::" in content:
                return "cloudformation"
            
            # Helm chart detection
            if name == "values.yaml" or "{{" in content and "}}" in content:
                return "helm"
            
            # Docker Compose (handled by docker_scan_service)
            if "services:" in content and ("image:" in content or "build:" in content):
                return "docker_compose"
            
        except Exception:
            pass
    
    if suffix == ".json":
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # CloudFormation JSON
            if "AWSTemplateFormatVersion" in content or '"AWS::' in content:
                return "cloudformation"
            
            # ARM template
            if '"$schema"' in content and "azure" in content.lower():
                return "arm"
            
        except Exception:
            pass
    
    return None


def scan_file_with_patterns(
    file_path: Path,
    framework: str
) -> List[IaCFinding]:
    """Scan a single file using built-in pattern rules."""
    findings: List[IaCFinding] = []
    rules = IAC_RULES.get(framework, [])
    
    if not rules:
        return findings
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.splitlines()
        
        for rule in rules:
            pattern = rule.get("pattern")
            if not pattern:
                continue
            
            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Extract resource info if possible
                resource_type = "unknown"
                resource_name = "unknown"
                
                # Try to find resource context
                resource_pattern = rule.get("resource_pattern")
                if resource_pattern and framework == "terraform":
                    # Look backwards for resource declaration
                    before_match = content[:match.start()]
                    resource_match = re.search(
                        rf'resource\s+"({resource_pattern})"\s+"(\w+)"',
                        before_match[-500:],  # Search last 500 chars
                        re.IGNORECASE
                    )
                    if resource_match:
                        resource_type = resource_match.group(1)
                        resource_name = resource_match.group(2)
                
                findings.append(IaCFinding(
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    file_path=str(file_path),
                    line_number=line_num,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    message=rule["message"],
                    remediation=rule.get("remediation", ""),
                    framework=framework,
                    check_type=rule["id"],
                ))
        
    except Exception as e:
        logger.debug(f"Error scanning {file_path}: {e}")
    
    return findings


def run_checkov(source_root: Path, timeout: int = 300) -> List[IaCFinding]:
    """Run Checkov scanner on the source directory."""
    if not is_checkov_available():
        logger.debug("Checkov not available")
        return []
    
    findings: List[IaCFinding] = []
    
    try:
        cmd = [
            "checkov",
            "-d", str(source_root),
            "-o", "json",
            "--quiet",
            "--compact",
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(source_root)
        )
        
        # Checkov exits with non-zero if it finds issues
        if result.stdout:
            try:
                # Checkov may output multiple JSON objects
                data = json.loads(result.stdout)
                
                if isinstance(data, list):
                    for item in data:
                        findings.extend(_parse_checkov_results(item, source_root))
                else:
                    findings.extend(_parse_checkov_results(data, source_root))
                    
            except json.JSONDecodeError:
                # Try to parse line by line for JSONL format
                for line in result.stdout.splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.extend(_parse_checkov_results(data, source_root))
                        except json.JSONDecodeError:
                            continue
        
        logger.info(f"Checkov found {len(findings)} issues")
        
    except subprocess.TimeoutExpired:
        logger.warning("Checkov scan timed out")
    except Exception as e:
        logger.error(f"Checkov scan failed: {e}")
    
    return findings


def _parse_checkov_results(data: Dict, source_root: Path) -> List[IaCFinding]:
    """Parse Checkov JSON output into findings."""
    findings = []
    
    # Handle results structure
    results = data.get("results", {})
    failed_checks = results.get("failed_checks", [])
    
    for check in failed_checks:
        try:
            # Get file path relative to source root
            file_path = check.get("file_path", "")
            if file_path.startswith("/"):
                file_path = file_path[1:]  # Remove leading slash
            
            # Map Checkov severity
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info",
            }
            severity = severity_map.get(
                check.get("severity", "MEDIUM"),
                "medium"
            )
            
            findings.append(IaCFinding(
                rule_id=check.get("check_id", ""),
                severity=severity,
                file_path=file_path,
                line_number=check.get("file_line_range", [0])[0],
                resource_type=check.get("resource", ""),
                resource_name=check.get("resource_address", ""),
                message=check.get("check_name", ""),
                remediation=check.get("guideline", ""),
                framework=check.get("check_type", "").lower(),
                check_type=check.get("check_id", ""),
                guideline=check.get("guideline", ""),
            ))
        except Exception as e:
            logger.debug(f"Error parsing Checkov result: {e}")
    
    return findings


def run_tfsec(source_root: Path, timeout: int = 300) -> List[IaCFinding]:
    """Run tfsec scanner on Terraform files."""
    if not is_tfsec_available():
        logger.debug("tfsec not available")
        return []
    
    findings: List[IaCFinding] = []
    
    try:
        cmd = [
            "tfsec",
            str(source_root),
            "--format", "json",
            "--no-color",
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.stdout:
            data = json.loads(result.stdout)
            
            for issue in data.get("results", []):
                # Map tfsec severity
                severity_map = {
                    "CRITICAL": "critical",
                    "HIGH": "high",
                    "MEDIUM": "medium",
                    "LOW": "low",
                }
                severity = severity_map.get(
                    issue.get("severity", "MEDIUM"),
                    "medium"
                )
                
                findings.append(IaCFinding(
                    rule_id=issue.get("rule_id", ""),
                    severity=severity,
                    file_path=issue.get("location", {}).get("filename", ""),
                    line_number=issue.get("location", {}).get("start_line", 0),
                    resource_type=issue.get("resource", ""),
                    resource_name="",
                    message=issue.get("description", ""),
                    remediation=issue.get("resolution", ""),
                    framework="terraform",
                    check_type=issue.get("rule_id", ""),
                    guideline=issue.get("links", [""])[0] if issue.get("links") else "",
                ))
        
        logger.info(f"tfsec found {len(findings)} issues")
        
    except subprocess.TimeoutExpired:
        logger.warning("tfsec scan timed out")
    except Exception as e:
        logger.debug(f"tfsec scan failed: {e}")
    
    return findings


def find_iac_files(source_root: Path) -> Dict[str, List[Path]]:
    """Find all IaC files grouped by framework."""
    iac_files: Dict[str, List[Path]] = {
        "terraform": [],
        "kubernetes": [],
        "cloudformation": [],
        "arm": [],
        "helm": [],
    }
    
    # Skip directories
    skip_dirs = {
        "node_modules", ".git", "vendor", "__pycache__",
        ".terraform", ".terragrunt-cache", "venv", ".venv"
    }
    
    # Find files
    for ext in ["*.tf", "*.tfvars", "*.yaml", "*.yml", "*.json"]:
        for path in source_root.rglob(ext):
            if any(skip in path.parts for skip in skip_dirs):
                continue
            
            framework = detect_iac_framework(path)
            if framework and framework in iac_files:
                iac_files[framework].append(path)
    
    return iac_files


def scan_iac(
    source_root: Path,
    use_checkov: bool = True,
    use_tfsec: bool = True,
    timeout: int = 300
) -> IaCScanResult:
    """
    Scan Infrastructure as Code files for security issues.
    
    Args:
        source_root: Root directory to scan
        use_checkov: Whether to use Checkov if available
        use_tfsec: Whether to use tfsec for Terraform
        timeout: Timeout for external tools
        
    Returns:
        IaCScanResult with all findings
    """
    result = IaCScanResult()
    
    # Find IaC files
    iac_files = find_iac_files(source_root)
    
    for framework, files in iac_files.items():
        if files:
            result.frameworks_detected.add(framework)
            result.files_scanned += len(files)
            logger.info(f"Found {len(files)} {framework} files")
    
    if result.files_scanned == 0:
        logger.info("No IaC files found")
        return result
    
    # Run external scanners first (more comprehensive)
    external_findings: List[IaCFinding] = []
    
    if use_checkov and is_checkov_available():
        logger.info("Running Checkov scanner")
        checkov_findings = run_checkov(source_root, timeout)
        external_findings.extend(checkov_findings)
    
    if use_tfsec and is_tfsec_available() and iac_files.get("terraform"):
        logger.info("Running tfsec scanner")
        tfsec_findings = run_tfsec(source_root, timeout)
        external_findings.extend(tfsec_findings)
    
    # Run built-in pattern scanning for files not covered by external tools
    if not external_findings:
        logger.info("Running built-in IaC pattern scanner")
        for framework, files in iac_files.items():
            for file_path in files:
                try:
                    rel_path = file_path.relative_to(source_root)
                    pattern_findings = scan_file_with_patterns(file_path, framework)
                    
                    # Update file paths to be relative
                    for finding in pattern_findings:
                        finding.file_path = str(rel_path)
                    
                    result.findings.extend(pattern_findings)
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")
    else:
        result.findings = external_findings
    
    # Deduplicate findings (external tools may overlap)
    seen = set()
    unique_findings = []
    for finding in result.findings:
        key = (finding.file_path, finding.line_number, finding.rule_id)
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    result.findings = unique_findings
    
    # Calculate stats
    result.failed_checks = len(result.findings)
    
    logger.info(
        f"IaC scan complete: {result.files_scanned} files, "
        f"{len(result.findings)} findings across {len(result.frameworks_detected)} frameworks"
    )
    
    return result


def convert_to_findings(
    iac_result: IaCScanResult,
    source_root: Path
) -> List[Dict[str, Any]]:
    """Convert IaC scan results to standard Finding format."""
    findings = []
    
    for iac_finding in iac_result.findings:
        findings.append({
            "type": "iac",
            "severity": iac_finding.severity,
            "file_path": iac_finding.file_path,
            "start_line": iac_finding.line_number,
            "end_line": iac_finding.line_number,
            "summary": f"[{iac_finding.rule_id}] {iac_finding.message}",
            "details": {
                "rule_id": iac_finding.rule_id,
                "check_type": iac_finding.check_type,
                "framework": iac_finding.framework,
                "resource_type": iac_finding.resource_type,
                "resource_name": iac_finding.resource_name,
                "remediation": iac_finding.remediation,
                "guideline": iac_finding.guideline,
            },
        })
    
    return findings
