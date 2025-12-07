"""
Docker Image Scanning Service

Scans Docker images and Dockerfiles for security vulnerabilities using:
1. Trivy - Container image vulnerability scanner
2. Dockerfile linting - Best practice checks

Features:
- Image vulnerability scanning (CVEs in base images and packages)
- Dockerfile security linting (misconfigurations, hardcoded secrets)
- Layer analysis (identifying which layer introduced vulnerabilities)
- Base image recommendations
"""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DockerVulnerability:
    """Vulnerability found in a Docker image."""
    vulnerability_id: str  # CVE-ID or other identifier
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: str
    description: str = ""
    layer: Optional[str] = None  # Which layer introduced this
    cvss_score: Optional[float] = None
    references: List[str] = field(default_factory=list)


@dataclass
class DockerfileFinding:
    """Security issue found in a Dockerfile."""
    rule_id: str
    severity: str
    line_number: int
    message: str
    remediation: str = ""
    category: str = ""  # e.g., "secrets", "privileges", "configuration"


@dataclass
class DockerScanResult:
    """Complete result of Docker scanning."""
    dockerfiles_scanned: int = 0
    images_scanned: int = 0
    dockerfile_findings: List[DockerfileFinding] = field(default_factory=list)
    image_vulnerabilities: List[DockerVulnerability] = field(default_factory=list)
    base_images_found: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def is_trivy_available() -> bool:
    """Check if Trivy is installed and available."""
    return shutil.which("trivy") is not None


def is_docker_available() -> bool:
    """Check if Docker CLI is available."""
    return shutil.which("docker") is not None


# Dockerfile security rules
DOCKERFILE_RULES = [
    # Privilege escalation risks
    {
        "id": "DS001",
        "pattern": r"^\s*USER\s+root\s*$",
        "severity": "medium",
        "message": "Container runs as root user",
        "remediation": "Use a non-root user: USER nonroot",
        "category": "privileges",
    },
    {
        "id": "DS002",
        "pattern": r"--privileged",
        "severity": "high",
        "message": "Privileged mode grants excessive permissions",
        "remediation": "Avoid --privileged flag, use specific capabilities instead",
        "category": "privileges",
    },
    # Secrets and credentials
    {
        "id": "DS003",
        "pattern": r"(?:password|passwd|pwd|secret|api[_-]?key|token|credential)s?\s*[=:]\s*['\"]?[a-zA-Z0-9+/=]{8,}",
        "severity": "critical",
        "message": "Potential hardcoded secret or credential",
        "remediation": "Use Docker secrets, environment variables, or secret managers",
        "category": "secrets",
    },
    {
        "id": "DS004",
        "pattern": r"^\s*ARG\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)",
        "severity": "high",
        "message": "Sensitive data passed as build argument (visible in image history)",
        "remediation": "Use Docker secrets or multi-stage builds to avoid exposing secrets",
        "category": "secrets",
    },
    {
        "id": "DS005",
        "pattern": r"^\s*ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=",
        "severity": "high",
        "message": "Sensitive data in environment variable",
        "remediation": "Use Docker secrets or runtime environment variables",
        "category": "secrets",
    },
    # Package management
    {
        "id": "DS006",
        "pattern": r"apt-get\s+(?:install|update)(?:(?!apt-get clean).)*$",
        "severity": "low",
        "message": "apt-get without cleanup increases image size",
        "remediation": "Add 'rm -rf /var/lib/apt/lists/*' after apt-get install",
        "category": "configuration",
    },
    {
        "id": "DS007",
        "pattern": r"pip\s+install(?:(?!--no-cache-dir).)*$",
        "severity": "low",
        "message": "pip install without --no-cache-dir increases image size",
        "remediation": "Use 'pip install --no-cache-dir' to reduce image size",
        "category": "configuration",
    },
    {
        "id": "DS008",
        "pattern": r"^\s*ADD\s+https?://",
        "severity": "medium",
        "message": "ADD with URL is unpredictable and can introduce vulnerabilities",
        "remediation": "Use COPY with curl/wget for better control and verification",
        "category": "configuration",
    },
    # Version pinning
    {
        "id": "DS009",
        "pattern": r"^\s*FROM\s+\w+(?::\s*latest)?\s*$",
        "severity": "medium",
        "message": "Base image uses 'latest' tag or no tag (unpredictable builds)",
        "remediation": "Pin base image to specific version: FROM image:1.2.3",
        "category": "configuration",
    },
    {
        "id": "DS010",
        "pattern": r"pip\s+install\s+(?!.*==)(?!.*>=)(?!.*~=)\w+",
        "severity": "low",
        "message": "pip install without version pinning",
        "remediation": "Pin package versions for reproducible builds",
        "category": "configuration",
    },
    # Network and exposure
    {
        "id": "DS011",
        "pattern": r"^\s*EXPOSE\s+22\s*$",
        "severity": "medium",
        "message": "SSH port exposed - containers should not run SSH",
        "remediation": "Use 'docker exec' for container access instead of SSH",
        "category": "network",
    },
    # Healthcheck
    {
        "id": "DS012",
        "pattern": None,  # Special: absence check
        "check_type": "missing_healthcheck",
        "severity": "low",
        "message": "No HEALTHCHECK instruction",
        "remediation": "Add HEALTHCHECK to enable container health monitoring",
        "category": "configuration",
    },
    # COPY vs ADD
    {
        "id": "DS013",
        "pattern": r"^\s*ADD\s+[^h]",  # ADD not starting with http
        "severity": "low",
        "message": "Using ADD for local files (COPY is preferred)",
        "remediation": "Use COPY for local files, ADD only for tar extraction or URLs",
        "category": "configuration",
    },
    # Shell form vs exec form
    {
        "id": "DS014",
        "pattern": r"^\s*(?:CMD|ENTRYPOINT)\s+(?!\[)",
        "severity": "low",
        "message": "CMD/ENTRYPOINT uses shell form instead of exec form",
        "remediation": "Use exec form: CMD [\"executable\", \"arg1\"]",
        "category": "configuration",
    },
    # Curl/wget piping
    {
        "id": "DS015",
        "pattern": r"curl.*\|\s*(?:bash|sh)|wget.*\|\s*(?:bash|sh)",
        "severity": "high",
        "message": "Piping curl/wget output to shell is dangerous",
        "remediation": "Download script first, verify checksum, then execute",
        "category": "security",
    },
]


def scan_dockerfile(dockerfile_path: Path) -> List[DockerfileFinding]:
    """
    Scan a Dockerfile for security issues using pattern matching.
    """
    findings: List[DockerfileFinding] = []
    
    try:
        content = dockerfile_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.splitlines()
        
        has_healthcheck = False
        has_user = False
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            
            # Track presence of certain instructions
            if stripped.upper().startswith("HEALTHCHECK"):
                has_healthcheck = True
            if stripped.upper().startswith("USER") and "root" not in stripped.lower():
                has_user = True
            
            # Check each rule
            for rule in DOCKERFILE_RULES:
                if rule.get("check_type"):
                    continue  # Handle special checks later
                
                pattern = rule.get("pattern")
                if pattern and re.search(pattern, line, re.IGNORECASE):
                    findings.append(DockerfileFinding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        line_number=line_num,
                        message=rule["message"],
                        remediation=rule["remediation"],
                        category=rule.get("category", ""),
                    ))
        
        # Special checks for missing instructions
        if not has_healthcheck:
            for rule in DOCKERFILE_RULES:
                if rule.get("check_type") == "missing_healthcheck":
                    findings.append(DockerfileFinding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        line_number=0,
                        message=rule["message"],
                        remediation=rule["remediation"],
                        category=rule.get("category", ""),
                    ))
        
        # Add recommendation if no non-root user
        if not has_user:
            findings.append(DockerfileFinding(
                rule_id="DS001",
                severity="medium",
                line_number=0,
                message="No non-root USER instruction found",
                remediation="Add 'USER nonroot' or similar to run as non-root",
                category="privileges",
            ))
        
        return findings
        
    except Exception as e:
        logger.error(f"Error scanning Dockerfile {dockerfile_path}: {e}")
        return []


def extract_base_images(dockerfile_path: Path) -> List[str]:
    """Extract base images from a Dockerfile."""
    images = []
    try:
        content = dockerfile_path.read_text(encoding='utf-8', errors='ignore')
        # Match FROM instructions
        from_pattern = r'^\s*FROM\s+([^\s]+)'
        for match in re.finditer(from_pattern, content, re.MULTILINE | re.IGNORECASE):
            image = match.group(1)
            # Skip build stage aliases
            if not image.startswith("$") and image not in images:
                images.append(image)
    except Exception as e:
        logger.debug(f"Error extracting base images: {e}")
    return images


def scan_image_with_trivy(image_name: str, timeout: int = 300) -> List[DockerVulnerability]:
    """
    Scan a Docker image using Trivy.
    """
    if not is_trivy_available():
        logger.warning("Trivy not available, skipping image scan")
        return []
    
    vulnerabilities: List[DockerVulnerability] = []
    
    try:
        # Run Trivy with JSON output
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
            "--quiet",
            image_name
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0 and "No such image" in result.stderr:
            logger.debug(f"Image {image_name} not found locally, skipping")
            return []
        
        if result.stdout:
            data = json.loads(result.stdout)
            
            # Parse Trivy JSON output
            for result_item in data.get("Results", []):
                target = result_item.get("Target", "")
                
                for vuln in result_item.get("Vulnerabilities", []):
                    vulnerabilities.append(DockerVulnerability(
                        vulnerability_id=vuln.get("VulnerabilityID", ""),
                        package_name=vuln.get("PkgName", ""),
                        installed_version=vuln.get("InstalledVersion", ""),
                        fixed_version=vuln.get("FixedVersion"),
                        severity=vuln.get("Severity", "UNKNOWN").lower(),
                        title=vuln.get("Title", ""),
                        description=vuln.get("Description", "")[:500],
                        layer=target,
                        cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                        references=vuln.get("References", [])[:5],
                    ))
        
        logger.info(f"Trivy found {len(vulnerabilities)} vulnerabilities in {image_name}")
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Trivy scan timed out for {image_name}")
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse Trivy output: {e}")
    except Exception as e:
        logger.error(f"Error scanning image {image_name}: {e}")
    
    return vulnerabilities


def scan_image_with_grype(image_name: str, timeout: int = 300) -> List[DockerVulnerability]:
    """
    Alternative: Scan a Docker image using Grype (Anchore).
    """
    if not shutil.which("grype"):
        return []
    
    vulnerabilities: List[DockerVulnerability] = []
    
    try:
        cmd = [
            "grype", image_name,
            "-o", "json",
            "--quiet"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.stdout:
            data = json.loads(result.stdout)
            
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                vulnerabilities.append(DockerVulnerability(
                    vulnerability_id=vuln.get("id", ""),
                    package_name=artifact.get("name", ""),
                    installed_version=artifact.get("version", ""),
                    fixed_version=vuln.get("fix", {}).get("versions", [None])[0] if vuln.get("fix") else None,
                    severity=vuln.get("severity", "unknown").lower(),
                    title=vuln.get("description", "")[:200],
                    description=vuln.get("description", "")[:500],
                    cvss_score=None,  # Grype format differs
                    references=vuln.get("urls", [])[:5],
                ))
        
    except Exception as e:
        logger.debug(f"Grype scan failed: {e}")
    
    return vulnerabilities


def find_dockerfiles(source_root: Path) -> List[Path]:
    """Find all Dockerfiles in the source tree."""
    dockerfiles = []
    
    # Common Dockerfile names
    dockerfile_patterns = [
        "Dockerfile",
        "Dockerfile.*",
        "*.Dockerfile",
        "dockerfile",
        "Containerfile",
    ]
    
    for pattern in dockerfile_patterns:
        for path in source_root.rglob(pattern):
            if path.is_file() and not any(skip in str(path) for skip in [
                "node_modules", ".git", "vendor", "__pycache__"
            ]):
                dockerfiles.append(path)
    
    return dockerfiles


def find_docker_compose_files(source_root: Path) -> List[Path]:
    """Find Docker Compose files."""
    compose_files = []
    patterns = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
    
    for pattern in patterns:
        for path in source_root.rglob(pattern):
            if path.is_file():
                compose_files.append(path)
    
    return compose_files


def extract_images_from_compose(compose_path: Path) -> List[str]:
    """Extract image names from docker-compose files."""
    images = []
    try:
        import yaml
        content = compose_path.read_text(encoding='utf-8')
        data = yaml.safe_load(content)
        
        services = data.get("services", {})
        for service_name, service_config in services.items():
            if isinstance(service_config, dict):
                image = service_config.get("image")
                if image and image not in images:
                    images.append(image)
    except Exception as e:
        logger.debug(f"Error parsing compose file {compose_path}: {e}")
    
    return images


def scan_docker_resources(
    source_root: Path,
    scan_images: bool = True,
    image_timeout: int = 300
) -> DockerScanResult:
    """
    Scan all Docker resources in a project.
    
    Args:
        source_root: Root directory to scan
        scan_images: Whether to scan referenced images (requires Docker/Trivy)
        image_timeout: Timeout for image scanning in seconds
        
    Returns:
        DockerScanResult with all findings
    """
    result = DockerScanResult()
    
    # Find and scan Dockerfiles
    dockerfiles = find_dockerfiles(source_root)
    logger.info(f"Found {len(dockerfiles)} Dockerfiles")
    
    for dockerfile in dockerfiles:
        result.dockerfiles_scanned += 1
        findings = scan_dockerfile(dockerfile)
        
        # Add file path to findings
        rel_path = str(dockerfile.relative_to(source_root))
        for finding in findings:
            finding.message = f"[{rel_path}] {finding.message}"
        
        result.dockerfile_findings.extend(findings)
        
        # Extract base images
        base_images = extract_base_images(dockerfile)
        result.base_images_found.extend(base_images)
    
    # Find images from docker-compose
    compose_files = find_docker_compose_files(source_root)
    for compose_file in compose_files:
        images = extract_images_from_compose(compose_file)
        for img in images:
            if img not in result.base_images_found:
                result.base_images_found.append(img)
    
    # Deduplicate base images
    result.base_images_found = list(set(result.base_images_found))
    
    # Scan images if requested and tools available
    if scan_images and result.base_images_found:
        if is_trivy_available():
            logger.info(f"Scanning {len(result.base_images_found)} Docker images with Trivy")
            for image in result.base_images_found[:5]:  # Limit to 5 images
                vulns = scan_image_with_trivy(image, timeout=image_timeout)
                result.image_vulnerabilities.extend(vulns)
                result.images_scanned += 1
        elif shutil.which("grype"):
            logger.info(f"Scanning Docker images with Grype")
            for image in result.base_images_found[:5]:
                vulns = scan_image_with_grype(image, timeout=image_timeout)
                result.image_vulnerabilities.extend(vulns)
                result.images_scanned += 1
        else:
            logger.warning("No image scanner available (Trivy or Grype)")
    
    # Generate recommendations
    if result.dockerfile_findings:
        critical_count = sum(1 for f in result.dockerfile_findings if f.severity == "critical")
        high_count = sum(1 for f in result.dockerfile_findings if f.severity == "high")
        
        if critical_count > 0:
            result.recommendations.append(
                f"Found {critical_count} critical Dockerfile issues - address immediately"
            )
        if high_count > 0:
            result.recommendations.append(
                f"Found {high_count} high-severity Dockerfile issues"
            )
    
    # Check for outdated base images
    for image in result.base_images_found:
        if ":latest" in image or ":" not in image:
            result.recommendations.append(
                f"Pin version for base image: {image}"
            )
    
    logger.info(
        f"Docker scan complete: {result.dockerfiles_scanned} Dockerfiles, "
        f"{len(result.dockerfile_findings)} findings, "
        f"{len(result.image_vulnerabilities)} image vulnerabilities"
    )
    
    return result


def convert_to_findings(
    docker_result: DockerScanResult,
    source_root: Path
) -> List[Dict[str, Any]]:
    """
    Convert Docker scan results to standard Finding format.
    """
    findings = []
    
    # Convert Dockerfile findings
    for df_finding in docker_result.dockerfile_findings:
        # Extract file path from message if present
        file_path = ""
        message = df_finding.message
        if message.startswith("["):
            end_bracket = message.find("]")
            if end_bracket > 0:
                file_path = message[1:end_bracket]
                message = message[end_bracket + 2:]
        
        findings.append({
            "type": "dockerfile",
            "severity": df_finding.severity,
            "file_path": file_path,
            "start_line": df_finding.line_number,
            "end_line": df_finding.line_number,
            "summary": f"[{df_finding.rule_id}] {message}",
            "details": {
                "rule_id": df_finding.rule_id,
                "category": df_finding.category,
                "remediation": df_finding.remediation,
            },
        })
    
    # Convert image vulnerabilities
    for img_vuln in docker_result.image_vulnerabilities:
        findings.append({
            "type": "docker_image",
            "severity": img_vuln.severity,
            "file_path": None,
            "start_line": None,
            "end_line": None,
            "summary": f"[{img_vuln.vulnerability_id}] {img_vuln.package_name}@{img_vuln.installed_version}: {img_vuln.title}",
            "details": {
                "vulnerability_id": img_vuln.vulnerability_id,
                "package_name": img_vuln.package_name,
                "installed_version": img_vuln.installed_version,
                "fixed_version": img_vuln.fixed_version,
                "description": img_vuln.description,
                "cvss_score": img_vuln.cvss_score,
                "layer": img_vuln.layer,
                "references": img_vuln.references,
            },
        })
    
    return findings
