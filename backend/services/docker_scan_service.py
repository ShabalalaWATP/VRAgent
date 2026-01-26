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
import math
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.core.config import settings
from backend.core.logging import get_logger


# =============================================================================
# BASE IMAGE INTELLIGENCE DATABASE
# Known EOL, compromised, or problematic base images
# =============================================================================

BASE_IMAGE_INTELLIGENCE = {
    # End-of-Life images - no longer receiving security updates
    "eol": {
        "python:2": {"eol_date": "2020-01-01", "message": "Python 2 reached EOL January 2020. No security patches.", "severity": "critical"},
        "python:2.7": {"eol_date": "2020-01-01", "message": "Python 2.7 reached EOL January 2020. No security patches.", "severity": "critical"},
        "node:8": {"eol_date": "2019-12-31", "message": "Node.js 8 reached EOL December 2019.", "severity": "critical"},
        "node:10": {"eol_date": "2021-04-30", "message": "Node.js 10 reached EOL April 2021.", "severity": "high"},
        "node:12": {"eol_date": "2022-04-30", "message": "Node.js 12 reached EOL April 2022.", "severity": "high"},
        "node:14": {"eol_date": "2023-04-30", "message": "Node.js 14 reached EOL April 2023.", "severity": "high"},
        "node:16": {"eol_date": "2024-04-30", "message": "Node.js 16 reached EOL April 2024.", "severity": "medium"},
        "ubuntu:14.04": {"eol_date": "2019-04-25", "message": "Ubuntu 14.04 (Trusty) reached EOL April 2019.", "severity": "critical"},
        "ubuntu:16.04": {"eol_date": "2021-04-30", "message": "Ubuntu 16.04 (Xenial) reached standard EOL April 2021.", "severity": "high"},
        "ubuntu:18.04": {"eol_date": "2023-05-31", "message": "Ubuntu 18.04 (Bionic) standard support ended May 2023.", "severity": "medium"},
        "debian:jessie": {"eol_date": "2020-06-30", "message": "Debian 8 (Jessie) reached EOL June 2020.", "severity": "critical"},
        "debian:stretch": {"eol_date": "2022-06-30", "message": "Debian 9 (Stretch) reached EOL June 2022.", "severity": "high"},
        "debian:buster": {"eol_date": "2024-06-30", "message": "Debian 10 (Buster) LTS ends June 2024.", "severity": "medium"},
        "centos:6": {"eol_date": "2020-11-30", "message": "CentOS 6 reached EOL November 2020.", "severity": "critical"},
        "centos:7": {"eol_date": "2024-06-30", "message": "CentOS 7 maintenance updates ended June 2024.", "severity": "high"},
        "centos:8": {"eol_date": "2021-12-31", "message": "CentOS 8 reached EOL December 2021 (shifted to Stream).", "severity": "high"},
        "alpine:3.12": {"eol_date": "2022-05-01", "message": "Alpine 3.12 reached EOL May 2022.", "severity": "medium"},
        "alpine:3.13": {"eol_date": "2022-11-01", "message": "Alpine 3.13 reached EOL November 2022.", "severity": "medium"},
        "alpine:3.14": {"eol_date": "2023-05-01", "message": "Alpine 3.14 reached EOL May 2023.", "severity": "medium"},
        "alpine:3.15": {"eol_date": "2023-11-01", "message": "Alpine 3.15 reached EOL November 2023.", "severity": "medium"},
        "ruby:2.5": {"eol_date": "2021-03-31", "message": "Ruby 2.5 reached EOL March 2021.", "severity": "high"},
        "ruby:2.6": {"eol_date": "2022-03-31", "message": "Ruby 2.6 reached EOL March 2022.", "severity": "high"},
        "ruby:2.7": {"eol_date": "2023-03-31", "message": "Ruby 2.7 reached EOL March 2023.", "severity": "medium"},
        "php:7.2": {"eol_date": "2020-11-30", "message": "PHP 7.2 reached EOL November 2020.", "severity": "critical"},
        "php:7.3": {"eol_date": "2021-12-06", "message": "PHP 7.3 reached EOL December 2021.", "severity": "high"},
        "php:7.4": {"eol_date": "2022-11-28", "message": "PHP 7.4 reached EOL November 2022.", "severity": "high"},
        "php:8.0": {"eol_date": "2023-11-26", "message": "PHP 8.0 reached EOL November 2023.", "severity": "medium"},
        "golang:1.15": {"eol_date": "2021-08-16", "message": "Go 1.15 no longer supported.", "severity": "medium"},
        "golang:1.16": {"eol_date": "2022-03-15", "message": "Go 1.16 no longer supported.", "severity": "medium"},
        "golang:1.17": {"eol_date": "2022-08-02", "message": "Go 1.17 no longer supported.", "severity": "medium"},
        "golang:1.18": {"eol_date": "2023-02-01", "message": "Go 1.18 no longer supported.", "severity": "medium"},
        "golang:1.19": {"eol_date": "2023-08-08", "message": "Go 1.19 no longer supported.", "severity": "low"},
        "java:8": {"eol_date": "2022-03-01", "message": "OpenJDK 8 public updates ended (Oracle). Use Eclipse Temurin.", "severity": "medium"},
        "openjdk:8": {"eol_date": "2022-03-01", "message": "OpenJDK 8 public updates ended. Use Eclipse Temurin.", "severity": "medium"},
    },

    # Known compromised or backdoored images (supply chain attacks)
    "compromised": {
        # Example entries - these are illustrative
        "malicious/cryptominer": {"message": "Known cryptominer image.", "severity": "critical", "attack_vector": "Runs cryptocurrency miner consuming resources"},
    },

    # Images with known critical unpatched vulnerabilities
    "vulnerable": {
        "log4j-vulnerable": {"cve": "CVE-2021-44228", "message": "Contains Log4Shell vulnerability", "severity": "critical"},
    },

    # Discouraged images (not EOL but problematic)
    "discouraged": {
        "latest": {"message": "Using 'latest' tag is unpredictable and a supply chain risk.", "severity": "medium"},
        "ubuntu:latest": {"message": "Unpinned Ubuntu version. Pin to specific version for reproducibility.", "severity": "medium"},
        "python:latest": {"message": "Unpinned Python version. Pin to specific version.", "severity": "medium"},
        "node:latest": {"message": "Unpinned Node.js version. Pin to specific version.", "severity": "medium"},
        "nginx:latest": {"message": "Unpinned nginx version. Pin to specific version.", "severity": "low"},
        "redis:latest": {"message": "Unpinned Redis version. Pin to specific version.", "severity": "low"},
        "postgres:latest": {"message": "Unpinned PostgreSQL version. Pin to specific version.", "severity": "low"},
        "mysql:latest": {"message": "Unpinned MySQL version. Pin to specific version.", "severity": "low"},
        "mongo:latest": {"message": "Unpinned MongoDB version. Pin to specific version.", "severity": "low"},
    },

    # Typosquatting candidates (common typos of popular images)
    "typosquatting": {
        "ngix": {"real": "nginx", "message": "Possible typosquat of 'nginx'", "severity": "critical"},
        "ngnix": {"real": "nginx", "message": "Possible typosquat of 'nginx'", "severity": "critical"},
        "nginix": {"real": "nginx", "message": "Possible typosquat of 'nginx'", "severity": "critical"},
        "ubunut": {"real": "ubuntu", "message": "Possible typosquat of 'ubuntu'", "severity": "critical"},
        "ubunto": {"real": "ubuntu", "message": "Possible typosquat of 'ubuntu'", "severity": "critical"},
        "pytohn": {"real": "python", "message": "Possible typosquat of 'python'", "severity": "critical"},
        "pyhton": {"real": "python", "message": "Possible typosquat of 'python'", "severity": "critical"},
        "nodjs": {"real": "node", "message": "Possible typosquat of 'node'", "severity": "critical"},
        "nodejs": {"real": "node", "message": "This should be 'node' not 'nodejs' on Docker Hub", "severity": "medium"},
        "alphine": {"real": "alpine", "message": "Possible typosquat of 'alpine'", "severity": "critical"},
        "apline": {"real": "alpine", "message": "Possible typosquat of 'alpine'", "severity": "critical"},
        "deiban": {"real": "debian", "message": "Possible typosquat of 'debian'", "severity": "critical"},
        "debain": {"real": "debian", "message": "Possible typosquat of 'debian'", "severity": "critical"},
        "readis": {"real": "redis", "message": "Possible typosquat of 'redis'", "severity": "critical"},
        "redsi": {"real": "redis", "message": "Possible typosquat of 'redis'", "severity": "critical"},
        "postgre": {"real": "postgres", "message": "Possible typosquat of 'postgres'", "severity": "critical"},
        "postgers": {"real": "postgres", "message": "Possible typosquat of 'postgres'", "severity": "critical"},
        "mongod": {"real": "mongo", "message": "Possible typosquat of 'mongo'", "severity": "critical"},
        "mynql": {"real": "mysql", "message": "Possible typosquat of 'mysql'", "severity": "critical"},
        "msyql": {"real": "mysql", "message": "Possible typosquat of 'mysql'", "severity": "critical"},
    },

    # Trusted registries (images not from these may be suspect)
    "trusted_registries": [
        "docker.io",
        "gcr.io",
        "ghcr.io",
        "quay.io",
        "mcr.microsoft.com",
        "registry.k8s.io",
        "public.ecr.aws",
        "registry.access.redhat.com",
    ],
}


@dataclass
class BaseImageFinding:
    """Finding from base image intelligence check."""
    image: str
    category: str  # eol, compromised, vulnerable, discouraged, typosquatting, untrusted
    severity: str
    message: str
    attack_vector: str = ""
    recommendation: str = ""


def check_base_image_intelligence(image_name: str) -> List[BaseImageFinding]:
    """
    Check a base image against the intelligence database.
    Returns findings for EOL, compromised, vulnerable, discouraged, or typosquatting images.
    """
    findings: List[BaseImageFinding] = []

    # Normalize image name
    image_lower = image_name.lower().strip()

    # Remove registry prefix for matching
    image_without_registry = image_lower
    for registry in BASE_IMAGE_INTELLIGENCE["trusted_registries"]:
        if image_lower.startswith(f"{registry}/"):
            image_without_registry = image_lower[len(registry) + 1:]
            break

    # Extract image name and tag
    if ":" in image_without_registry:
        image_base, tag = image_without_registry.rsplit(":", 1)
    else:
        image_base = image_without_registry
        tag = "latest"

    # Check for typosquatting first (most critical)
    base_name = image_base.split("/")[-1]  # Get just the image name without org
    if base_name in BASE_IMAGE_INTELLIGENCE["typosquatting"]:
        info = BASE_IMAGE_INTELLIGENCE["typosquatting"][base_name]
        findings.append(BaseImageFinding(
            image=image_name,
            category="typosquatting",
            severity=info["severity"],
            message=info["message"],
            attack_vector="Typosquatted images may contain malware, backdoors, or cryptominers",
            recommendation=f"Did you mean '{info['real']}'? Verify this is the correct image.",
        ))

    # Check for EOL images
    for eol_pattern, info in BASE_IMAGE_INTELLIGENCE["eol"].items():
        # Match patterns like "python:2" against "python:2.7.18"
        if image_without_registry.startswith(eol_pattern) or image_without_registry == eol_pattern:
            findings.append(BaseImageFinding(
                image=image_name,
                category="eol",
                severity=info["severity"],
                message=info["message"],
                attack_vector="EOL software receives no security patches. Known vulnerabilities remain unpatched.",
                recommendation=f"Upgrade to a supported version. EOL date: {info['eol_date']}",
            ))
            break

    # Check for compromised images
    for comp_pattern, info in BASE_IMAGE_INTELLIGENCE["compromised"].items():
        if comp_pattern in image_without_registry:
            findings.append(BaseImageFinding(
                image=image_name,
                category="compromised",
                severity=info["severity"],
                message=info["message"],
                attack_vector=info.get("attack_vector", "Known malicious image"),
                recommendation="Do NOT use this image. It is known to be malicious.",
            ))

    # Check for discouraged patterns
    if tag == "latest" or image_without_registry.endswith(":latest"):
        findings.append(BaseImageFinding(
            image=image_name,
            category="discouraged",
            severity="medium",
            message="Using 'latest' tag is unpredictable and a supply chain risk.",
            attack_vector="Attacker could push malicious 'latest' tag, affecting your next build",
            recommendation="Pin to a specific version tag or SHA256 digest",
        ))

    for disc_pattern, info in BASE_IMAGE_INTELLIGENCE["discouraged"].items():
        if image_without_registry == disc_pattern:
            findings.append(BaseImageFinding(
                image=image_name,
                category="discouraged",
                severity=info["severity"],
                message=info["message"],
                attack_vector="Unpinned versions can change unexpectedly, introducing vulnerabilities",
                recommendation="Pin to a specific version tag or SHA256 digest",
            ))
            break

    # Check for untrusted registry
    has_registry = "/" in image_name and ("." in image_name.split("/")[0] or ":" in image_name.split("/")[0])
    if has_registry:
        registry = image_name.split("/")[0]
        if registry not in BASE_IMAGE_INTELLIGENCE["trusted_registries"]:
            findings.append(BaseImageFinding(
                image=image_name,
                category="untrusted",
                severity="medium",
                message=f"Image from unverified registry: {registry}",
                attack_vector="Untrusted registries may host malicious or compromised images",
                recommendation="Use images from trusted registries (Docker Hub, GCR, GHCR, Quay, ECR)",
            ))

    return findings


# =============================================================================
# LAYER EXTRACTION & DEEP SCAN
# Extract image layers and scan for recoverable secrets in "deleted" files
# =============================================================================

# Sensitive file patterns to look for in extracted layers
LAYER_SENSITIVE_PATTERNS = [
    # SSH & Keys
    {"pattern": r"id_rsa$|id_ed25519$|id_ecdsa$|id_dsa$", "type": "ssh_private_key", "severity": "critical"},
    {"pattern": r"\.pem$|\.key$|\.p12$|\.pfx$|\.jks$", "type": "private_key", "severity": "critical"},
    {"pattern": r"known_hosts$|authorized_keys$", "type": "ssh_config", "severity": "high"},

    # Cloud credentials
    {"pattern": r"\.aws/credentials$|\.aws/config$", "type": "aws_credentials", "severity": "critical"},
    {"pattern": r"credentials\.json$|service[-_]?account\.json$", "type": "gcp_credentials", "severity": "critical"},
    {"pattern": r"\.azure/|azure\.json$", "type": "azure_credentials", "severity": "critical"},
    {"pattern": r"\.kube/config$|kubeconfig", "type": "kubernetes_config", "severity": "critical"},

    # Application secrets
    {"pattern": r"\.env$|\.env\.\w+$", "type": "env_file", "severity": "critical"},
    {"pattern": r"secrets?\.ya?ml$|secrets?\.json$", "type": "secrets_file", "severity": "critical"},
    {"pattern": r"\.htpasswd$|\.htaccess$", "type": "htaccess", "severity": "high"},
    {"pattern": r"\.netrc$|\.git-credentials$", "type": "git_credentials", "severity": "high"},
    {"pattern": r"\.npmrc$|\.pypirc$", "type": "package_manager_creds", "severity": "high"},
    {"pattern": r"\.docker/config\.json$", "type": "docker_config", "severity": "high"},

    # Database
    {"pattern": r"\.pgpass$|\.my\.cnf$|\.mongodb", "type": "database_credentials", "severity": "high"},
    {"pattern": r"\.sqlite$|\.db$|\.sql$", "type": "database_file", "severity": "medium"},

    # History files (may contain secrets in commands)
    {"pattern": r"\.bash_history$|\.zsh_history$|\.sh_history$", "type": "shell_history", "severity": "high"},
    {"pattern": r"\.python_history$|\.node_repl_history$", "type": "repl_history", "severity": "medium"},
    {"pattern": r"\.mysql_history$|\.psql_history$", "type": "db_history", "severity": "high"},

    # Config files that may contain secrets
    {"pattern": r"wp-config\.php$", "type": "wordpress_config", "severity": "high"},
    {"pattern": r"settings\.py$|local_settings\.py$", "type": "django_settings", "severity": "medium"},
    {"pattern": r"application\.ya?ml$|application\.properties$", "type": "spring_config", "severity": "medium"},
    {"pattern": r"config\.php$|database\.php$", "type": "php_config", "severity": "medium"},

    # Backup files
    {"pattern": r"\.bak$|\.backup$|\.old$|\.orig$", "type": "backup_file", "severity": "medium"},
    {"pattern": r"\.swp$|\.swo$|~$", "type": "editor_backup", "severity": "low"},
]


@dataclass
class LayerSecretFinding:
    """A secret or sensitive file found in an image layer."""
    layer_id: str
    layer_index: int
    file_path: str
    file_type: str
    severity: str
    size_bytes: int
    is_deleted: bool  # True if file was deleted in a later layer but still recoverable
    content_preview: Optional[str] = None  # First N chars if readable
    entropy: Optional[float] = None  # Shannon entropy if applicable
    attack_vector: str = ""


def _extract_layer_id(layer_tar_path: str) -> str:
    """Extract a stable layer identifier from a docker save layer path."""
    normalized = layer_tar_path.replace("\\", "/")
    parts = normalized.split("/")

    # OCI layout: blobs/sha256/<hash>
    if "blobs" in parts:
        try:
            idx = parts.index("blobs")
            if idx + 2 < len(parts):
                digest = parts[idx + 2]
                if digest.startswith("sha256:"):
                    digest = digest.split(":", 1)[1]
                if digest:
                    return digest[:12]
        except ValueError:
            pass

    base = os.path.basename(normalized)
    if base == "layer.tar" and len(parts) >= 2:
        return parts[-2][:12]
    if base:
        return base[:12]
    return normalized[:12]


def extract_and_scan_layers(
    image_name: str,
    max_layers: int = 20,
    scan_content: bool = True,
    max_file_size: int = 1024 * 1024,  # 1MB max for content scanning
) -> Tuple[List[LayerSecretFinding], Dict[str, Any]]:
    """
    Extract Docker image layers and scan for secrets/sensitive files.

    This is a DEEP SCAN that finds secrets even if they were "deleted" in later layers.
    Docker layers are additive - a file deleted in layer N still exists in layer N-1.

    Args:
        image_name: Docker image name to scan
        max_layers: Maximum number of most recent layers to scan (<= 0 or None for all)
        scan_content: Whether to scan file contents for secrets
        max_file_size: Maximum file size to scan contents

    Returns:
        Tuple of (findings, metadata)
    """
    findings: List[LayerSecretFinding] = []
    metadata = {
        "layers_scanned": 0,
        "layers_total": 0,
        "layers_start_index": 0,
        "layers_end_index": 0,
        "layers_truncated": False,
        "files_scanned": 0,
        "total_size_scanned": 0,
        "deleted_secrets_found": 0,
        "deleted_files_total": 0,
        "deleted_files_truncated": False,
        "deleted_files": [],
    }

    # Check if docker is available
    if not shutil.which("docker"):
        logger.warning("Docker not available for layer extraction")
        return findings, {"error": "Docker not available"}

    temp_dir = None
    try:
        # Create temp directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="docker_layer_scan_")
        tar_path = os.path.join(temp_dir, "image.tar")
        extract_dir = os.path.join(temp_dir, "layers")
        os.makedirs(extract_dir)

        logger.info(f"Extracting layers from {image_name}")

        # Export image to tar
        result = subprocess.run(
            ["docker", "save", "-o", tar_path, image_name],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            logger.error(f"Failed to save image: {result.stderr}")
            return findings, {"error": f"Failed to export image: {result.stderr}"}

        # Track file existence across layers (overlay semantics)
        current_files: Set[str] = set()
        deleted_files: List[Dict[str, Any]] = []
        deleted_files_total = 0
        deleted_files_limit = 500
        deleted_files_truncated = False

        def record_deleted(path: str, reason: str, removed_count: int = 1) -> None:
            nonlocal deleted_files_total, deleted_files_truncated
            deleted_files_total += max(removed_count, 0)
            if len(deleted_files) >= deleted_files_limit:
                deleted_files_truncated = True
                return
            entry = {"path": path, "reason": reason}
            if removed_count > 1:
                entry["removed_count"] = removed_count
            deleted_files.append(entry)

        def normalize_layer_path(path: str) -> str:
            path = path.replace("\\", "/")
            if path.startswith("./"):
                path = path[2:]
            return path.lstrip("/")

        def apply_whiteout(path: str) -> None:
            nonlocal current_files
            name = os.path.basename(path)
            dir_path = os.path.dirname(path)

            if name == ".wh..wh..opq":
                # Opaque directory: hides all lower-layer entries in this dir
                if dir_path:
                    prefix = f"{dir_path}/"
                    to_remove = {p for p in current_files if p.startswith(prefix)}
                    current_files = {p for p in current_files if p not in to_remove}
                    record_deleted(dir_path, "opaque_dir", removed_count=len(to_remove))
                else:
                    removed_count = len(current_files)
                    current_files.clear()
                    record_deleted("/", "opaque_dir", removed_count=removed_count)
                return

            if not name.startswith(".wh."):
                return

            target_name = name[len(".wh."):]
            if not target_name:
                return

            target_path = f"{dir_path}/{target_name}" if dir_path else target_name
            to_remove = {
                p for p in current_files
                if p == target_path or p.startswith(f"{target_path}/")
            }
            removed_count = len(to_remove)
            current_files = {p for p in current_files if p not in to_remove}
            record_deleted(target_path, "whiteout", removed_count=removed_count or 1)

        # Extract and scan the tar
        with tarfile.open(tar_path, 'r') as tar:
            # Find manifest to get layer order
            manifest = None
            for member in tar.getmembers():
                if member.name == "manifest.json":
                    f = tar.extractfile(member)
                    if f:
                        manifest = json.loads(f.read().decode('utf-8'))
                        break

            if not manifest or not manifest[0].get("Layers"):
                logger.warning("Could not find layer manifest")
                return findings, {"error": "Could not parse image manifest"}

            all_layers = manifest[0]["Layers"]
            metadata["layers_total"] = len(all_layers)

            use_all_layers = not max_layers or max_layers <= 0
            if use_all_layers or len(all_layers) <= max_layers:
                layers = all_layers
                metadata["layers_truncated"] = False
                metadata["layers_start_index"] = 0
            else:
                layers = all_layers[-max_layers:]
                metadata["layers_truncated"] = True
                metadata["layers_start_index"] = len(all_layers) - max_layers

            metadata["layers_scanned"] = len(layers)
            metadata["layers_end_index"] = metadata["layers_start_index"] + len(layers) - 1

            # Scan each layer
            for layer_idx, layer_tar_path in enumerate(layers):
                global_layer_index = metadata["layers_start_index"] + layer_idx

                # Extract layer tar
                try:
                    layer_member = tar.getmember(layer_tar_path)
                    layer_tar_data = tar.extractfile(layer_member)
                    if not layer_tar_data:
                        continue

                    # Save layer tar temporarily
                    layer_tar_file = os.path.join(temp_dir, f"layer_{layer_idx}.tar")
                    with open(layer_tar_file, 'wb') as f:
                        f.write(layer_tar_data.read())

                    # Scan the layer tar
                    with tarfile.open(layer_tar_file, 'r') as layer_tar:
                        whiteouts: List[str] = []
                        file_members: List[Tuple[tarfile.TarInfo, str]] = []

                        for member in layer_tar.getmembers():
                            if not member.isfile():
                                continue

                            file_path = normalize_layer_path(member.name)
                            if not file_path:
                                continue

                            # Collect whiteouts first to apply before additions
                            if os.path.basename(file_path).startswith(".wh."):
                                whiteouts.append(file_path)
                                continue

                            file_members.append((member, file_path))

                        for whiteout in whiteouts:
                            apply_whiteout(whiteout)

                        for member, file_path in file_members:
                            current_files.add(file_path)
                            metadata["files_scanned"] += 1

                            # Check against sensitive patterns
                            for pattern_info in LAYER_SENSITIVE_PATTERNS:
                                if re.search(pattern_info["pattern"], file_path, re.IGNORECASE):
                                    # Found sensitive file
                                    content_preview = None
                                    entropy = None

                                    # Extract and scan content if enabled
                                    if scan_content and member.size <= max_file_size:
                                        try:
                                            f = layer_tar.extractfile(member)
                                            if f:
                                                content = f.read()
                                                metadata["total_size_scanned"] += len(content)

                                                # Try to decode as text
                                                try:
                                                    text_content = content.decode('utf-8', errors='ignore')
                                                    content_preview = text_content[:200]
                                                    entropy = calculate_shannon_entropy(text_content[:1000])
                                                except:
                                                    pass
                                        except Exception as e:
                                            logger.debug(f"Could not read file content: {e}")

                                    findings.append(LayerSecretFinding(
                                        layer_id=_extract_layer_id(layer_tar_path),
                                        layer_index=global_layer_index,
                                        file_path=file_path,
                                        file_type=pattern_info["type"],
                                        severity=pattern_info["severity"],
                                        size_bytes=member.size,
                                        is_deleted=False,  # Will be updated later
                                        content_preview=content_preview,
                                        entropy=entropy,
                                        attack_vector=f"Extractable from layer {global_layer_index} with 'docker save' + tar",
                                    ))
                                    break

                except Exception as e:
                    logger.debug(f"Error scanning layer {layer_idx}: {e}")
                    continue

        # Identify "deleted" files based on overlay semantics and whiteouts
        for finding in findings:
            if finding.file_path not in current_files:
                finding.is_deleted = True
                finding.attack_vector = (
                    f"DELETED but recoverable! File removed in later layer but still in layer {finding.layer_index}"
                )
                metadata["deleted_secrets_found"] += 1

        metadata["deleted_files"] = deleted_files
        metadata["deleted_files_total"] = deleted_files_total
        metadata["deleted_files_truncated"] = deleted_files_truncated

        logger.info(f"Layer scan complete: {len(findings)} sensitive files found, {metadata['deleted_secrets_found']} deleted but recoverable")

    except subprocess.TimeoutExpired:
        logger.error("Docker save timed out")
        return findings, {"error": "Image export timed out"}
    except Exception as e:
        logger.error(f"Layer extraction failed: {e}")
        return findings, {"error": str(e)}
    finally:
        # Cleanup
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp dir: {e}")

    return findings, metadata


# =============================================================================
# ACCURACY IMPROVEMENTS: Semantic Parsing, Entropy Detection, Multi-Stage Aware
# =============================================================================

def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. High entropy = likely secret/random data."""
    if not data:
        return 0.0
    entropy = 0.0
    for char_count in [data.count(c) for c in set(data)]:
        if char_count:
            freq = float(char_count) / len(data)
            entropy -= freq * math.log2(freq)
    return entropy


def is_high_entropy_secret(value: str, threshold: float = 4.5) -> bool:
    """
    Detect if a string is likely a secret based on entropy analysis.
    Typical thresholds:
    - Random hex (API keys): ~4.0 entropy
    - Base64 encoded: ~5.0-6.0 entropy
    - Normal English text: ~2.5-3.5 entropy
    - UUIDs: ~3.5-4.0 entropy
    """
    if len(value) < 8:
        return False

    # Clean up the value (remove quotes, whitespace)
    cleaned = value.strip().strip('"\'')

    # Skip common non-secret patterns
    non_secret_patterns = [
        r'^https?://',  # URLs
        r'^/[\w/.-]+$',  # File paths
        r'^\d+\.\d+\.\d+',  # Version numbers
        r'^[\w.-]+@[\w.-]+',  # Emails
        r'^\$\{?\w+\}?$',  # Variable references like ${VAR}
        r'^true$|^false$|^null$|^none$',  # Boolean/null values
        r'^\d+$',  # Plain numbers
    ]
    for pattern in non_secret_patterns:
        if re.match(pattern, cleaned, re.IGNORECASE):
            return False

    entropy = calculate_shannon_entropy(cleaned)

    # Lower threshold for longer strings (more likely to be secrets)
    if len(cleaned) > 32:
        threshold = 4.0
    if len(cleaned) > 64:
        threshold = 3.8

    return entropy >= threshold


@dataclass
class DockerfileInstruction:
    """Parsed Dockerfile instruction with full context."""
    instruction: str  # FROM, RUN, COPY, etc.
    arguments: str    # Everything after the instruction
    line_start: int   # Starting line number
    line_end: int     # Ending line number (for multi-line)
    raw_lines: List[str]  # Original lines
    stage_name: Optional[str] = None  # Build stage name (for multi-stage)
    stage_index: int = 0  # 0-indexed stage number
    is_final_stage: bool = True  # Is this in the final stage?


def parse_dockerfile_semantic(content: str) -> Tuple[List[DockerfileInstruction], List[str]]:
    """
    Parse Dockerfile into semantic instruction blocks.
    Handles:
    - Multi-line instructions (with backslash continuation)
    - Multi-stage builds (FROM ... AS name)
    - Comments and empty lines

    Returns:
        Tuple of (instructions, stage_names) where stage_names[-1] is the final stage
    """
    instructions: List[DockerfileInstruction] = []
    stage_names: List[str] = []
    current_stage_index = -1
    current_stage_name: Optional[str] = None

    lines = content.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            i += 1
            continue

        # Collect multi-line instruction
        raw_lines = [line]
        line_start = i + 1  # 1-indexed
        full_line = stripped

        while full_line.endswith('\\') and i + 1 < len(lines):
            i += 1
            next_line = lines[i]
            raw_lines.append(next_line)
            full_line = full_line[:-1] + ' ' + next_line.strip()

        line_end = i + 1

        # Parse instruction and arguments
        match = re.match(r'^(\w+)\s*(.*)', full_line, re.DOTALL)
        if match:
            instruction = match.group(1).upper()
            arguments = match.group(2).strip()

            # Handle FROM instruction (new stage)
            if instruction == 'FROM':
                current_stage_index += 1
                # Check for AS alias
                as_match = re.search(r'\s+[Aa][Ss]\s+(\w+)', arguments)
                if as_match:
                    current_stage_name = as_match.group(1)
                else:
                    current_stage_name = None
                stage_names.append(current_stage_name or f"stage_{current_stage_index}")

            instructions.append(DockerfileInstruction(
                instruction=instruction,
                arguments=arguments,
                line_start=line_start,
                line_end=line_end,
                raw_lines=raw_lines,
                stage_name=current_stage_name,
                stage_index=current_stage_index,
            ))

        i += 1

    # Mark all instructions in final stage
    final_stage_index = current_stage_index
    for inst in instructions:
        inst.is_final_stage = (inst.stage_index == final_stage_index)

    return instructions, stage_names


@dataclass
class EntropyFinding:
    """A potential secret found via entropy analysis."""
    line_number: int
    value: str
    entropy: float
    context: str  # ENV, ARG, RUN, etc.
    var_name: Optional[str] = None


def detect_high_entropy_secrets(instructions: List[DockerfileInstruction]) -> List[EntropyFinding]:
    """
    Scan parsed instructions for high-entropy strings (likely secrets).
    More accurate than regex patterns alone.
    """
    findings: List[EntropyFinding] = []

    for inst in instructions:
        # Check ENV instructions
        if inst.instruction == 'ENV':
            # Parse ENV KEY=value or ENV KEY value
            env_matches = re.findall(r'(\w+)[=\s]+([^\s]+)', inst.arguments)
            for var_name, value in env_matches:
                if is_high_entropy_secret(value):
                    findings.append(EntropyFinding(
                        line_number=inst.line_start,
                        value=value[:50] + '...' if len(value) > 50 else value,
                        entropy=calculate_shannon_entropy(value.strip().strip('"\'') ),
                        context='ENV',
                        var_name=var_name,
                    ))

        # Check ARG instructions
        elif inst.instruction == 'ARG':
            arg_match = re.match(r'(\w+)(?:=(.+))?', inst.arguments)
            if arg_match and arg_match.group(2):
                var_name = arg_match.group(1)
                value = arg_match.group(2)
                if is_high_entropy_secret(value):
                    findings.append(EntropyFinding(
                        line_number=inst.line_start,
                        value=value[:50] + '...' if len(value) > 50 else value,
                        entropy=calculate_shannon_entropy(value.strip().strip('"\'') ),
                        context='ARG',
                        var_name=var_name,
                    ))

        # Check RUN instructions for inline secrets
        elif inst.instruction == 'RUN':
            # Look for patterns like: echo "secret" > file, curl -u user:pass, etc.
            secret_patterns = [
                r'["\']([A-Za-z0-9+/=]{20,})["\']',  # Base64-like in quotes
                r'(?:password|token|key|secret|credential)s?\s*[=:]\s*["\']?([^\s"\']+)',
            ]
            for pattern in secret_patterns:
                for match in re.finditer(pattern, inst.arguments, re.IGNORECASE):
                    value = match.group(1)
                    if is_high_entropy_secret(value):
                        findings.append(EntropyFinding(
                            line_number=inst.line_start,
                            value=value[:50] + '...' if len(value) > 50 else value,
                            entropy=calculate_shannon_entropy(value.strip().strip('"\'') ),
                            context='RUN',
                        ))

    return findings

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
    attack_vector: str = ""  # Offensive context: how an attacker could exploit this


@dataclass
class ComposeFinding:
    """Security issue found in docker-compose configuration."""
    rule_id: str
    severity: str
    service_name: str
    message: str
    remediation: str = ""
    category: str = ""
    attack_vector: str = ""  # How an attacker could exploit this
    file_path: str = ""


@dataclass
class BuildContextFinding:
    """Sensitive file that would be included in Docker build context."""
    file_path: str
    severity: str
    category: str
    message: str
    attack_vector: str = ""


@dataclass
class DockerScanResult:
    """Complete result of Docker scanning."""
    dockerfiles_scanned: int = 0
    images_scanned: int = 0
    compose_files_scanned: int = 0
    dockerfile_findings: List[DockerfileFinding] = field(default_factory=list)
    compose_findings: List[ComposeFinding] = field(default_factory=list)
    build_context_findings: List[BuildContextFinding] = field(default_factory=list)
    image_vulnerabilities: List[DockerVulnerability] = field(default_factory=list)
    base_images_found: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    ai_analysis: Optional[str] = None  # AI-powered security analysis
    # AI False Positive Adjudication results
    adjudication_enabled: bool = False
    adjudication_summary: Optional[str] = None
    rejected_as_false_positive: List[Dict[str, Any]] = field(default_factory=list)
    adjudication_stats: Dict[str, int] = field(default_factory=dict)  # {confirmed: X, rejected: Y}
    # Base Image Intelligence findings
    base_image_findings: List[BaseImageFinding] = field(default_factory=list)
    # Layer extraction deep scan findings
    layer_secrets: List[LayerSecretFinding] = field(default_factory=list)
    layer_scan_metadata: Dict[str, Any] = field(default_factory=dict)
    deleted_secrets_found: int = 0  # Count of secrets in "deleted" but recoverable files


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
        "attack_vector": "MITM attack could inject malicious code during download",
    },
    # =========================================================================
    # OFFENSIVE SECURITY RULES (DS016-DS030)
    # Focus: Container escape, privilege escalation, lateral movement vectors
    # =========================================================================

    # Container Escape Vectors
    {
        "id": "DS016",
        "pattern": r"--cap-add\s*=?\s*(?:ALL|SYS_ADMIN|SYS_PTRACE|SYS_RAWIO|DAC_READ_SEARCH)",
        "severity": "critical",
        "message": "Dangerous capability added - enables container escape",
        "remediation": "Remove dangerous capabilities. SYS_ADMIN allows mount namespace escape, SYS_PTRACE allows process injection",
        "category": "container_escape",
        "attack_vector": "SYS_ADMIN: Mount cgroup + release_agent escape. SYS_PTRACE: Inject into host processes via /proc",
    },
    {
        "id": "DS017",
        "pattern": r"-v\s+/:/|--volume\s+/:/|:/host(?:fs)?(?::|/)",
        "severity": "critical",
        "message": "Host root filesystem mounted - trivial container escape",
        "remediation": "Never mount host root. Use specific paths with :ro if needed",
        "category": "container_escape",
        "attack_vector": "Write to /host/etc/cron.d or /host/root/.ssh/authorized_keys for instant host compromise",
    },
    {
        "id": "DS018",
        "pattern": r"-v\s+/var/run/docker\.sock|--volume.*docker\.sock|docker\.sock:/",
        "severity": "critical",
        "message": "Docker socket mounted - full host compromise possible",
        "remediation": "Never mount Docker socket. Use Docker-in-Docker or rootless Docker if needed",
        "category": "container_escape",
        "attack_vector": "docker run -v /:/host --privileged from container = instant root on host",
    },
    {
        "id": "DS019",
        "pattern": r"--pid\s*=\s*host|pid:\s*host",
        "severity": "critical",
        "message": "Host PID namespace shared - can see/interact with host processes",
        "remediation": "Remove --pid=host unless absolutely necessary for monitoring",
        "category": "container_escape",
        "attack_vector": "Can inject into host processes, read /proc/1/environ for secrets, kill host processes",
    },
    {
        "id": "DS020",
        "pattern": r"--net\s*=\s*host|--network\s*=\s*host|network_mode:\s*host",
        "severity": "high",
        "message": "Host network namespace - can sniff host traffic and bind to host ports",
        "remediation": "Use bridge networking with explicit port mapping",
        "category": "network_exposure",
        "attack_vector": "Sniff host network traffic, ARP spoof, access services bound to localhost",
    },
    {
        "id": "DS021",
        "pattern": r"--userns\s*=\s*host",
        "severity": "high",
        "message": "Host user namespace - root in container = root on host",
        "remediation": "Use user namespace remapping (userns-remap) for isolation",
        "category": "privilege_escalation",
        "attack_vector": "Container root can modify host files owned by root if volumes mounted",
    },

    # Privilege Escalation Vectors
    {
        "id": "DS022",
        "pattern": r"chmod\s+[0-7]*[4-7][0-7]*\s+|chmod\s+\+s\s+|chmod\s+u\+s",
        "severity": "high",
        "message": "SUID/SGID bit being set - privilege escalation vector",
        "remediation": "Avoid SUID binaries. Run --no-new-privileges to prevent exploitation",
        "category": "privilege_escalation",
        "attack_vector": "SUID binary exploitation for root shell inside container",
    },
    {
        "id": "DS023",
        "pattern": r"^\s*RUN\s+.*(?:sudo|doas)\s+",
        "severity": "medium",
        "message": "sudo/doas installed or used - unnecessary in containers",
        "remediation": "Use USER directive to switch users. Remove sudo from final image",
        "category": "privilege_escalation",
        "attack_vector": "sudo misconfig or CVE could allow priv esc. Unnecessary attack surface",
    },
    {
        "id": "DS024",
        "pattern": r"apk\s+add.*--no-cache.*(?:sudo|shadow|su-exec)|apt.*install.*(?:sudo|passwd)",
        "severity": "medium",
        "message": "Privilege escalation tools being installed",
        "remediation": "Use multi-stage builds and don't include priv esc tools in final image",
        "category": "privilege_escalation",
        "attack_vector": "Tools like sudo, su, passwd enable privilege escalation if container compromised",
    },

    # Secrets & Credential Exposure
    {
        "id": "DS025",
        "pattern": r"(?:COPY|ADD)\s+(?:\.env|\.aws|\.ssh|\.gnupg|\.docker|\.kube|\.config|id_rsa|id_ed25519|\.pem|\.key|credentials|\.netrc|\.git-credentials)",
        "severity": "critical",
        "message": "Sensitive file copied into image - exposed in layer history",
        "remediation": "Use Docker secrets, mount at runtime, or use multi-stage builds to exclude",
        "category": "secrets",
        "attack_vector": "Extract image layers with 'docker save' + tar to recover secrets even if 'deleted'",
    },
    {
        "id": "DS026",
        "pattern": r"(?:echo|printf).*(?:>|>>)\s*(?:/etc/passwd|/etc/shadow|/root/\.ssh|\.aws/credentials)",
        "severity": "critical",
        "message": "Writing credentials to sensitive system files",
        "remediation": "Never hardcode credentials in Dockerfile. Use secrets management",
        "category": "secrets",
        "attack_vector": "Credentials visible in image history, recoverable from any layer",
    },
    {
        "id": "DS027",
        "pattern": r"--build-arg\s+(?:\w*(?:PASS|SECRET|KEY|TOKEN|CRED|AUTH|API_KEY|AWS_|GITHUB_|PRIVATE)\w*)\s*=",
        "severity": "high",
        "message": "Sensitive data passed as build argument - visible in image history",
        "remediation": "Use Docker BuildKit secrets: RUN --mount=type=secret,id=mysecret",
        "category": "secrets",
        "attack_vector": "'docker history --no-trunc' exposes all build args including secrets",
    },

    # Persistence & Backdoor Vectors
    {
        "id": "DS028",
        "pattern": r"(?:nc|ncat|netcat|socat)\s+.*-[el]|python.*-c.*socket|perl.*socket|ruby.*socket",
        "severity": "high",
        "message": "Potential reverse shell or backdoor setup",
        "remediation": "Remove network tools like netcat from production images. Use distroless",
        "category": "backdoor",
        "attack_vector": "Pre-configured reverse shell for persistent access after deployment",
    },
    {
        "id": "DS029",
        "pattern": r"cron|at\s+|systemctl\s+enable|update-rc\.d|chkconfig",
        "severity": "medium",
        "message": "Scheduling/init system used - unusual for containers",
        "remediation": "Use container orchestration for scheduling. Avoid init systems in containers",
        "category": "persistence",
        "attack_vector": "Cron/init persistence survives container restarts if volume mounted",
    },
    {
        "id": "DS030",
        "pattern": r"useradd.*-o\s+-u\s*0|usermod.*-u\s*0|echo.*:0:0:.*>>\s*/etc/passwd",
        "severity": "critical",
        "message": "Creating additional root user (UID 0) - backdoor technique",
        "remediation": "Audit all user creation. Never create users with UID 0",
        "category": "backdoor",
        "attack_vector": "Hidden root account for persistent privileged access",
    },

    # Supply Chain Attack Vectors
    {
        "id": "DS031",
        "pattern": r"^\s*FROM\s+(?!(?:docker\.io|gcr\.io|ghcr\.io|quay\.io|mcr\.microsoft\.com|registry\.k8s\.io|public\.ecr\.aws)/)[a-z0-9]+(?:/[a-z0-9._-]+)?(?::[a-z0-9._-]+)?(?:\s|$)",
        "severity": "medium",
        "message": "Base image from unverified registry - supply chain risk",
        "remediation": "Use images from trusted registries. Verify image signatures with cosign",
        "category": "supply_chain",
        "attack_vector": "Typosquatted or malicious base image with backdoors/cryptominers",
    },
    {
        "id": "DS032",
        "pattern": r"pip\s+install\s+--index-url\s+(?!https://pypi\.org)|npm\s+.*--registry\s+(?!https://registry\.npmjs\.org)",
        "severity": "high",
        "message": "Custom package registry - verify it's trusted",
        "remediation": "Only use official registries or verified internal mirrors",
        "category": "supply_chain",
        "attack_vector": "Malicious package from attacker-controlled registry (dependency confusion)",
    },
    {
        "id": "DS033",
        "pattern": r"git\s+clone\s+(?!https://github\.com|https://gitlab\.com).*(?:&&|\||;)\s*(?:cd|pushd).*(?:&&|\||;).*(?:make|pip|npm|cargo|go)\s+(?:install|build)",
        "severity": "medium",
        "message": "Building from untrusted git source",
        "remediation": "Pin to specific commit hash. Verify repository authenticity",
        "category": "supply_chain",
        "attack_vector": "Malicious code injected into cloned repo between Dockerfile creation and build",
    },
]


# ============================================================================
# Docker Compose Security Rules (Offensive Focus)
# ============================================================================

COMPOSE_SECURITY_RULES = [
    # Critical: Container Escape
    {
        "id": "DC001",
        "check_field": "privileged",
        "check_value": True,
        "severity": "critical",
        "message": "Container runs in privileged mode - trivial escape to host",
        "remediation": "Remove 'privileged: true'. Use specific capabilities if needed",
        "category": "container_escape",
        "attack_vector": "mount -t cgroup + release_agent, or direct /dev access for host compromise",
    },
    {
        "id": "DC002",
        "check_field": "volumes",
        "check_pattern": r"/var/run/docker\.sock|docker\.sock",
        "severity": "critical",
        "message": "Docker socket mounted - full cluster/host compromise",
        "remediation": "Never mount Docker socket. Use TCP with TLS if remote access needed",
        "category": "container_escape",
        "attack_vector": "Spawn privileged container from inside, mount host root, game over",
    },
    {
        "id": "DC003",
        "check_field": "volumes",
        "check_pattern": r"^/\s*:|:/\s*$|:/host",
        "severity": "critical",
        "message": "Host root filesystem mounted",
        "remediation": "Mount only specific directories with minimal permissions",
        "category": "container_escape",
        "attack_vector": "Write SSH keys, cron jobs, or replace binaries on host",
    },
    {
        "id": "DC004",
        "check_field": "pid",
        "check_value": "host",
        "severity": "critical",
        "message": "Host PID namespace - process injection possible",
        "remediation": "Remove 'pid: host' unless monitoring tool",
        "category": "container_escape",
        "attack_vector": "nsenter --target 1 --mount --uts --ipc --net --pid for host shell",
    },
    {
        "id": "DC005",
        "check_field": "cap_add",
        "check_pattern": r"SYS_ADMIN|SYS_PTRACE|ALL",
        "severity": "critical",
        "message": "Dangerous capability enables container escape",
        "remediation": "Remove dangerous caps. Use cap_drop: [ALL] and add only needed",
        "category": "container_escape",
        "attack_vector": "SYS_ADMIN: cgroup escape. SYS_PTRACE: process injection. ALL: everything",
    },

    # High: Network Exposure
    {
        "id": "DC006",
        "check_field": "network_mode",
        "check_value": "host",
        "severity": "high",
        "message": "Host network mode - container can sniff host traffic",
        "remediation": "Use bridge networking with specific port mappings",
        "category": "network_exposure",
        "attack_vector": "ARP spoofing, sniff credentials, access localhost-only services",
    },
    {
        "id": "DC007",
        "check_field": "ports",
        "check_pattern": r"^0\.0\.0\.0:|^\d+:",
        "severity": "medium",
        "message": "Port exposed on all interfaces (0.0.0.0)",
        "remediation": "Bind to specific IP: '127.0.0.1:8080:8080' for local only",
        "category": "network_exposure",
        "attack_vector": "Service accessible from any network, not just intended interface",
    },
    {
        "id": "DC008",
        "check_field": "ports",
        "check_pattern": r":22(?:/|$)|:23(?:/|$)|:3389(?:/|$)|:5900(?:/|$)",
        "severity": "high",
        "message": "Remote access port exposed (SSH/Telnet/RDP/VNC)",
        "remediation": "Use docker exec for container access. Remove remote access services",
        "category": "network_exposure",
        "attack_vector": "Brute force, credential stuffing, or exploit remote access service",
    },

    # High: Secrets Exposure
    {
        "id": "DC009",
        "check_field": "environment",
        "check_pattern": r"(?:PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY|AWS_|PRIVATE).*=.+",
        "severity": "high",
        "message": "Secrets in environment variables - visible in 'docker inspect'",
        "remediation": "Use Docker secrets or external secret manager (Vault, AWS Secrets Manager)",
        "category": "secrets",
        "attack_vector": "'docker inspect' or /proc/1/environ exposes all env vars to any container user",
    },
    {
        "id": "DC010",
        "check_field": "env_file",
        "check_pattern": r"\.env|secrets|credentials|\.key",
        "severity": "medium",
        "message": "Sensitive env file referenced - ensure not committed to repo",
        "remediation": "Add to .gitignore. Use Docker secrets for sensitive values",
        "category": "secrets",
        "attack_vector": "Env file in repo history exposes all secrets to anyone with repo access",
    },

    # Medium: Privilege Escalation
    {
        "id": "DC011",
        "check_field": "user",
        "check_value": "root",
        "severity": "medium",
        "message": "Container explicitly runs as root",
        "remediation": "Run as non-root user: 'user: 1000:1000' or 'user: nobody'",
        "category": "privilege_escalation",
        "attack_vector": "Root in container can modify mounted volumes, exploit kernel vulns more easily",
    },
    {
        "id": "DC012",
        "check_field": "security_opt",
        "check_pattern": r"seccomp\s*:\s*unconfined|apparmor\s*:\s*unconfined",
        "severity": "high",
        "message": "Security profiles disabled - kernel attack surface exposed",
        "remediation": "Use default seccomp/AppArmor or custom restrictive profiles",
        "category": "privilege_escalation",
        "attack_vector": "Kernel exploits more likely to succeed without seccomp syscall filtering",
    },
    {
        "id": "DC013",
        "check_field": "userns_mode",
        "check_value": "host",
        "severity": "high",
        "message": "Host user namespace - UID 0 in container = UID 0 on host",
        "remediation": "Use user namespace remapping for better isolation",
        "category": "privilege_escalation",
        "attack_vector": "Container root can write to host files if volumes mounted",
    },

    # Medium: Persistence & Reliability
    {
        "id": "DC014",
        "check_field": "restart",
        "check_value": "always",
        "check_also_missing": "healthcheck",
        "severity": "medium",
        "message": "restart: always without healthcheck - can restart broken/backdoored container",
        "remediation": "Add healthcheck or use 'restart: unless-stopped'",
        "category": "persistence",
        "attack_vector": "Backdoored container auto-restarts, maintaining persistence",
    },
    {
        "id": "DC015",
        "check_field": "volumes",
        "check_pattern": r"/etc/cron|/var/spool/cron|/etc/systemd|/etc/init\.d",
        "severity": "high",
        "message": "Host scheduling directories mounted - persistence vector",
        "remediation": "Never mount host cron/systemd directories",
        "category": "persistence",
        "attack_vector": "Write cron job or systemd unit for persistent host-level backdoor",
    },

    # Lateral Movement
    {
        "id": "DC016",
        "check_field": "volumes",
        "check_pattern": r"/root/\.ssh|/home/\w+/\.ssh|\.ssh",
        "severity": "high",
        "message": "SSH directory mounted - credential theft risk",
        "remediation": "Don't mount SSH directories. Use Docker secrets for keys if needed",
        "category": "lateral_movement",
        "attack_vector": "Steal SSH keys for lateral movement to other hosts",
    },
    {
        "id": "DC017",
        "check_field": "volumes",
        "check_pattern": r"/root/\.kube|\.kube/config|/etc/kubernetes",
        "severity": "critical",
        "message": "Kubernetes credentials mounted - cluster compromise risk",
        "remediation": "Use service accounts with minimal RBAC, not admin kubeconfig",
        "category": "lateral_movement",
        "attack_vector": "Kubeconfig access = full cluster control, lateral movement to all pods",
    },
    {
        "id": "DC018",
        "check_field": "volumes",
        "check_pattern": r"/root/\.aws|\.aws/credentials|\.aws/config",
        "severity": "critical",
        "message": "AWS credentials mounted - cloud account compromise",
        "remediation": "Use IAM roles for containers (ECS task roles, EKS IRSA)",
        "category": "lateral_movement",
        "attack_vector": "AWS creds = access to all cloud resources the role permits",
    },
]


def scan_dockerfile(dockerfile_path: Path, final_stage_only: bool = True) -> List[DockerfileFinding]:
    """
    Scan a Dockerfile for security issues using SEMANTIC PARSING.

    Improvements over line-by-line regex:
    - Multi-line instruction support (backslash continuations)
    - Multi-stage build awareness (only flag final stage for runtime issues)
    - Entropy-based secret detection
    - Full instruction context for pattern matching

    Args:
        dockerfile_path: Path to the Dockerfile
        final_stage_only: If True, only flag runtime issues in final stage (default: True)
    """
    findings: List[DockerfileFinding] = []

    try:
        content = dockerfile_path.read_text(encoding='utf-8', errors='ignore')

        # Parse into semantic instruction blocks
        instructions, stage_names = parse_dockerfile_semantic(content)
        is_multistage = len(stage_names) > 1

        has_healthcheck = False
        has_non_root_user_in_final = False

        for inst in instructions:
            # Track presence of certain instructions (only in final stage)
            if inst.instruction == "HEALTHCHECK":
                has_healthcheck = True
            if inst.instruction == "USER" and "root" not in inst.arguments.lower():
                if inst.is_final_stage:
                    has_non_root_user_in_final = True

            # Determine if this finding should only apply to final stage
            # Runtime concerns (privileges, network) only matter in final stage
            # Build-time concerns (secrets in ARG, supply chain) matter in all stages

            # Check each rule against the FULL instruction (including continuations)
            full_instruction_text = inst.arguments

            for rule in DOCKERFILE_RULES:
                if rule.get("check_type"):
                    continue  # Handle special checks later

                pattern = rule.get("pattern")
                if not pattern:
                    continue

                # Check if pattern matches the full instruction
                if re.search(pattern, full_instruction_text, re.IGNORECASE):
                    # Multi-stage awareness: Skip runtime-only issues in non-final stages
                    category = rule.get("category", "")
                    is_runtime_issue = category in [
                        "privileges", "network", "configuration", "container_escape",
                        "privilege_escalation", "network_exposure"
                    ]

                    if is_multistage and is_runtime_issue and not inst.is_final_stage and final_stage_only:
                        # Skip: This is a runtime concern in a build-only stage
                        continue

                    # Create finding with stage context
                    message = rule["message"]
                    if is_multistage and not inst.is_final_stage:
                        message = f"[Build stage: {inst.stage_name or inst.stage_index}] {message}"

                    findings.append(DockerfileFinding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        line_number=inst.line_start,
                        message=message,
                        remediation=rule["remediation"],
                        category=category,
                        attack_vector=rule.get("attack_vector", ""),
                    ))

        # Entropy-based secret detection (catches things regex misses)
        entropy_secrets = detect_high_entropy_secrets(instructions)
        for secret in entropy_secrets:
            # Check if we already have a finding for this line
            already_found = any(f.line_number == secret.line_number and f.category == "secrets" for f in findings)
            if not already_found:
                var_info = f" ({secret.var_name})" if secret.var_name else ""
                findings.append(DockerfileFinding(
                    rule_id="DS100",  # Entropy-based detection
                    severity="high",
                    line_number=secret.line_number,
                    message=f"High-entropy string detected in {secret.context}{var_info} - likely hardcoded secret (entropy: {secret.entropy:.2f})",
                    remediation="Use Docker secrets, BuildKit secret mounts, or environment variables at runtime",
                    category="secrets",
                    attack_vector=f"Secrets visible in image history, extractable with 'docker save' or 'docker history --no-trunc'",
                ))

        # Special checks for missing instructions (only matters for final stage)
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
                        attack_vector="Container health unknown, may serve stale/compromised content",
                    ))

        # Add recommendation if no non-root user in final stage
        if not has_non_root_user_in_final:
            findings.append(DockerfileFinding(
                rule_id="DS001",
                severity="medium",
                line_number=0,
                message="No non-root USER instruction in final stage",
                remediation="Add 'USER nonroot' or similar to run as non-root",
                category="privileges",
                attack_vector="Root in container increases impact of any RCE - can modify all files, mount devices",
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


def scan_compose_file(compose_path: Path) -> List[ComposeFinding]:
    """
    Scan a docker-compose file for security misconfigurations.
    Focus: Container escape, privilege escalation, lateral movement vectors.
    """
    findings: List[ComposeFinding] = []

    try:
        import yaml
        content = compose_path.read_text(encoding='utf-8')
        data = yaml.safe_load(content)

        if not data or not isinstance(data, dict):
            return findings

        services = data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            for rule in COMPOSE_SECURITY_RULES:
                check_field = rule.get("check_field")
                check_value = rule.get("check_value")
                check_pattern = rule.get("check_pattern")

                field_value = service_config.get(check_field)

                if field_value is None:
                    continue

                matched = False

                # Check for exact value match
                if check_value is not None:
                    if field_value == check_value:
                        matched = True
                    # Also check for string "true" for privileged
                    elif check_value is True and str(field_value).lower() == "true":
                        matched = True

                # Check for pattern match in field value
                if check_pattern is not None:
                    if isinstance(field_value, list):
                        # Check each item in list (volumes, ports, cap_add, etc.)
                        for item in field_value:
                            if isinstance(item, str) and re.search(check_pattern, item, re.IGNORECASE):
                                matched = True
                                break
                            elif isinstance(item, dict):
                                # Handle dict format like environment: {KEY: value}
                                for k, v in item.items():
                                    check_str = f"{k}={v}" if v else k
                                    if re.search(check_pattern, check_str, re.IGNORECASE):
                                        matched = True
                                        break
                    elif isinstance(field_value, dict):
                        # Handle dict format
                        for k, v in field_value.items():
                            check_str = f"{k}={v}" if v else k
                            if re.search(check_pattern, check_str, re.IGNORECASE):
                                matched = True
                                break
                    elif isinstance(field_value, str):
                        if re.search(check_pattern, field_value, re.IGNORECASE):
                            matched = True

                # Special check: restart=always without healthcheck
                if rule.get("check_also_missing"):
                    missing_field = rule["check_also_missing"]
                    if matched and service_config.get(missing_field) is not None:
                        matched = False  # Has healthcheck, so not a finding

                if matched:
                    findings.append(ComposeFinding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        service_name=service_name,
                        message=f"[{service_name}] {rule['message']}",
                        remediation=rule["remediation"],
                        category=rule.get("category", ""),
                        attack_vector=rule.get("attack_vector", ""),
                        file_path=str(compose_path),
                    ))

    except Exception as e:
        logger.error(f"Error scanning compose file {compose_path}: {e}")

    return findings


# Sensitive files that should never be in Docker build context
BUILD_CONTEXT_SENSITIVE_PATTERNS = [
    # Credentials & Keys
    {
        "pattern": r"^\.env$|^\.env\.|\.env\.local$|\.env\.production$",
        "severity": "critical",
        "category": "secrets",
        "message": "Environment file with secrets would be included in build context",
        "attack_vector": "Secrets visible in image layers, extractable with 'docker save'",
    },
    {
        "pattern": r"id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem$|\.key$|\.p12$|\.pfx$",
        "severity": "critical",
        "category": "secrets",
        "message": "Private key file would be included in build context",
        "attack_vector": "Private keys enable lateral movement, impersonation, decryption of traffic",
    },
    {
        "pattern": r"\.aws/credentials|\.aws/config|credentials\.json|service.account\.json",
        "severity": "critical",
        "category": "secrets",
        "message": "Cloud credentials file would be included in build context",
        "attack_vector": "Cloud credentials = full access to cloud account resources",
    },
    {
        "pattern": r"\.kube/config|kubeconfig",
        "severity": "critical",
        "category": "secrets",
        "message": "Kubernetes config would be included in build context",
        "attack_vector": "Kubeconfig provides cluster access, lateral movement to all pods",
    },
    {
        "pattern": r"\.docker/config\.json",
        "severity": "high",
        "category": "secrets",
        "message": "Docker config (may contain registry credentials) in build context",
        "attack_vector": "Registry credentials enable supply chain attacks via image replacement",
    },
    {
        "pattern": r"\.git-credentials|\.netrc|\.npmrc|\.pypirc",
        "severity": "high",
        "category": "secrets",
        "message": "Package manager/Git credentials in build context",
        "attack_vector": "Credentials enable supply chain attacks via malicious package publishing",
    },
    # Database & Application Secrets
    {
        "pattern": r"\.pgpass|\.my\.cnf|\.mongodb|redis\.conf",
        "severity": "high",
        "category": "secrets",
        "message": "Database credentials file in build context",
        "attack_vector": "Database credentials = access to sensitive data, potential pivot point",
    },
    {
        "pattern": r"secrets?\.ya?ml$|secrets?\.json$|vault\.ya?ml$",
        "severity": "critical",
        "category": "secrets",
        "message": "Secrets file would be included in build context",
        "attack_vector": "Centralized secrets file = keys to the kingdom",
    },
    # Version Control & History
    {
        "pattern": r"^\.git$|^\.git/",
        "severity": "high",
        "category": "information_disclosure",
        "message": ".git directory would be included - exposes full repo history",
        "attack_vector": "Git history may contain deleted secrets, internal comments, dev info",
    },
    {
        "pattern": r"^\.svn$|^\.hg$|^\.bzr$",
        "severity": "medium",
        "category": "information_disclosure",
        "message": "Version control directory in build context",
        "attack_vector": "VCS history may contain sensitive information",
    },
    # Backup & Temporary Files
    {
        "pattern": r"\.bak$|\.backup$|\.old$|\.orig$|~$|\.swp$|\.swo$",
        "severity": "medium",
        "category": "information_disclosure",
        "message": "Backup/temporary files in build context",
        "attack_vector": "Backup files may contain old configs, credentials, or sensitive data",
    },
    {
        "pattern": r"\.sql$|\.dump$|\.sqlite$|\.db$",
        "severity": "high",
        "category": "information_disclosure",
        "message": "Database dump/file in build context",
        "attack_vector": "Database dumps contain sensitive data, credentials, PII",
    },
    # Development & Debug
    {
        "pattern": r"\.vscode/|\.idea/|\.vs/",
        "severity": "low",
        "category": "information_disclosure",
        "message": "IDE configuration in build context",
        "attack_vector": "IDE configs may reveal internal paths, debug settings, developer info",
    },
    {
        "pattern": r"Thumbs\.db$|\.DS_Store$|desktop\.ini$",
        "severity": "low",
        "category": "information_disclosure",
        "message": "OS metadata files in build context",
        "attack_vector": "Metadata can reveal file system structure and user information",
    },
]


def scan_build_context(source_root: Path, dockerfile_path: Path) -> List[BuildContextFinding]:
    """
    Analyze what files would be included in Docker build context.
    Checks .dockerignore and warns about sensitive files.

    From offensive perspective: What secrets could be extracted from the image?
    """
    findings: List[BuildContextFinding] = []

    # Determine the build context directory (usually where Dockerfile is)
    build_context_dir = dockerfile_path.parent

    # Parse .dockerignore if it exists
    dockerignore_path = build_context_dir / ".dockerignore"
    ignored_patterns: List[str] = []

    if dockerignore_path.exists():
        try:
            content = dockerignore_path.read_text(encoding='utf-8')
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ignored_patterns.append(line)
        except Exception:
            pass

    def is_ignored(file_path: str) -> bool:
        """Check if a file path matches any .dockerignore pattern."""
        import fnmatch
        for pattern in ignored_patterns:
            # Handle negation patterns
            if pattern.startswith("!"):
                continue  # Simplified: not handling negation fully
            # Handle directory patterns
            if pattern.endswith("/"):
                if fnmatch.fnmatch(file_path, pattern[:-1]) or fnmatch.fnmatch(file_path, pattern[:-1] + "/*"):
                    return True
            if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(file_path, "*/" + pattern):
                return True
            # Check if any part of the path matches
            parts = file_path.split("/")
            for part in parts:
                if fnmatch.fnmatch(part, pattern):
                    return True
        return False

    # Walk the build context directory
    try:
        for path in build_context_dir.rglob("*"):
            if path.is_file():
                try:
                    rel_path = str(path.relative_to(build_context_dir)).replace("\\", "/")
                except ValueError:
                    continue

                # Check if ignored
                if is_ignored(rel_path):
                    continue

                # Check against sensitive patterns
                for pattern_info in BUILD_CONTEXT_SENSITIVE_PATTERNS:
                    if re.search(pattern_info["pattern"], rel_path, re.IGNORECASE):
                        findings.append(BuildContextFinding(
                            file_path=rel_path,
                            severity=pattern_info["severity"],
                            category=pattern_info["category"],
                            message=pattern_info["message"],
                            attack_vector=pattern_info["attack_vector"],
                        ))
                        break  # One finding per file

    except Exception as e:
        logger.error(f"Error scanning build context: {e}")

    # Check for missing .dockerignore
    if not dockerignore_path.exists():
        findings.append(BuildContextFinding(
            file_path=".dockerignore",
            severity="medium",
            category="configuration",
            message="No .dockerignore file - all files sent to Docker daemon",
            attack_vector="Entire directory tree included, may contain secrets, .git history, etc.",
        ))
    else:
        # Check for common patterns that SHOULD be in .dockerignore
        recommended_ignores = [".git", ".env", "*.pem", "*.key", ".aws", ".ssh"]
        missing_ignores = []
        for pattern in recommended_ignores:
            if pattern not in ignored_patterns and f"{pattern}/" not in ignored_patterns:
                missing_ignores.append(pattern)

        if missing_ignores:
            findings.append(BuildContextFinding(
                file_path=".dockerignore",
                severity="medium",
                category="configuration",
                message=f".dockerignore missing recommended patterns: {', '.join(missing_ignores)}",
                attack_vector="Sensitive files may be inadvertently included in image layers",
            ))

    return findings


async def generate_ai_docker_analysis(
    dockerfile_content: str,
    compose_content: Optional[str] = None,
    findings: Optional[List[Dict]] = None,
) -> str:
    """
    Generate AI-powered security analysis of Docker configurations.
    Focus: Offensive security perspective - what would an attacker look for?
    """
    try:
        from backend.services.ai_service import generate_with_ai
    except ImportError:
        logger.warning("AI service not available for Docker analysis")
        return ""

    # Build the analysis prompt
    prompt = """You are an offensive security expert analyzing Docker configurations for security weaknesses.
Analyze the following Docker configuration from an ATTACKER'S perspective.

Focus on:
1. **Container Escape Vectors**: Can an attacker break out of the container to the host?
   - Privileged mode, dangerous capabilities (SYS_ADMIN, SYS_PTRACE)
   - Mounted sensitive paths (/var/run/docker.sock, host root /)
   - Namespace sharing (pid, network, user)

2. **Privilege Escalation**: Can an attacker gain higher privileges?
   - Running as root, SUID binaries, sudo/su installed
   - Writable sensitive directories
   - Missing security profiles (seccomp, AppArmor)

3. **Secrets & Credential Exposure**: What secrets could an attacker extract?
   - Hardcoded credentials in ENV, ARG, or copied files
   - Secrets in environment variables (visible via /proc/1/environ)
   - Keys, tokens, or passwords in image layers

4. **Lateral Movement Potential**: Can compromising this container lead to other systems?
   - Mounted cloud credentials (AWS, GCP, Azure)
   - Kubernetes configs or service account tokens
   - SSH keys or internal network access

5. **Persistence Mechanisms**: How could an attacker maintain access?
   - Mounted cron directories
   - Auto-restart policies
   - Writable host paths

6. **Supply Chain Risks**: Could the image itself be compromised?
   - Untrusted base images
   - Unpinned package versions
   - Curl-pipe-bash installation patterns

Provide a **security assessment** with:
- Overall risk rating (Critical/High/Medium/Low)
- Top 3 attack vectors an attacker would exploit first
- Specific exploitation steps for critical findings
- Recommended remediations prioritized by impact

"""

    prompt += f"\n## Dockerfile Content:\n```dockerfile\n{dockerfile_content}\n```\n"

    if compose_content:
        prompt += f"\n## Docker Compose Content:\n```yaml\n{compose_content}\n```\n"

    if findings:
        prompt += "\n## Automated Findings:\n"
        for f in findings[:20]:  # Limit to top 20
            prompt += f"- [{f.get('severity', 'unknown').upper()}] {f.get('message', '')}\n"
            if f.get('attack_vector'):
                prompt += f"  Attack vector: {f.get('attack_vector')}\n"

    prompt += "\n\nProvide your offensive security analysis:"

    try:
        analysis = await generate_with_ai(
            prompt=prompt,
            system_prompt="You are an expert penetration tester and container security specialist. Provide actionable offensive security insights.",
            max_tokens=2000,
        )
        return analysis
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        return ""


@dataclass
class AdjudicatedFinding:
    """A finding that has been reviewed by the AI false positive adjudicator."""
    original_finding: Dict[str, Any]
    is_false_positive: bool
    confidence: str  # "high", "medium", "low"
    reasoning: str
    adjusted_severity: Optional[str] = None  # If severity should be changed


async def ai_false_positive_adjudicator(
    findings: List[Dict[str, Any]],
    dockerfile_content: str,
    compose_content: Optional[str] = None,
    skepticism_level: str = "high",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """
    AI-powered false positive adjudicator that reviews findings with HEAVY SKEPTICISM.

    Philosophy: Assume findings are FALSE POSITIVES unless there is clear, concrete
    evidence that they represent a real, exploitable security issue.

    Args:
        findings: List of findings to adjudicate
        dockerfile_content: The Dockerfile being analyzed
        compose_content: Optional compose file content
        skepticism_level: "high" (default), "medium", or "low"

    Returns:
        Tuple of (confirmed_findings, rejected_findings, adjudication_summary)
    """
    if not findings:
        return [], [], "No findings to adjudicate."

    try:
        from backend.services.ai_service import generate_with_ai
    except ImportError:
        logger.warning("AI service not available for false positive adjudication")
        return findings, [], "AI adjudication unavailable - returning all findings."

    # Build the adjudication prompt with heavy skepticism
    skepticism_instructions = {
        "high": """You are a SKEPTICAL security reviewer. Your job is to REJECT false positives aggressively.

CORE PRINCIPLE: A finding is a FALSE POSITIVE unless you can prove otherwise.

Reasons to mark as FALSE POSITIVE:
- The pattern matched but the context makes it benign (e.g., "password" in a comment, example, or docs)
- The "secret" is a placeholder, example value, or obviously fake (e.g., "changeme", "xxx", "example123")
- Multi-stage build: The issue is in a builder stage that doesn't affect the final image
- The value is a well-known public constant, not a secret (e.g., public API endpoints, version strings)
- The configuration is intentional and documented (e.g., development/test environments)
- The entropy-detected "secret" is actually a hash, checksum, or non-sensitive ID
- The pattern matched a variable reference ($VAR) not an actual value

Reasons to CONFIRM as real issue (must be CLEAR and CONCRETE):
- Actual hardcoded credential with high entropy that isn't a placeholder
- Privileged mode or dangerous capabilities in final/production stage
- Docker socket mount with no clear legitimate use case
- Secrets that would actually be extractable and usable by an attacker

When in doubt: FALSE POSITIVE. We prefer missing a minor issue over flooding with noise.""",

        "medium": """You are a security reviewer balancing accuracy with thoroughness.
Mark as false positive if the context clearly makes it benign, but confirm real issues.""",

        "low": """You are a thorough security reviewer. Only mark obvious false positives.""",
    }

    base_prompt = f"""{skepticism_instructions.get(skepticism_level, skepticism_instructions["high"])}

## Dockerfile Content:
```dockerfile
{dockerfile_content}
```
"""

    if compose_content:
        base_prompt += f"""
## Docker Compose Content:
```yaml
{compose_content}
```
"""

    base_prompt += """
## Findings to Adjudicate:
For each finding, determine: FALSE_POSITIVE or CONFIRMED

"""
    response_format = """

## Your Response:
For each finding, respond in this exact format:

FINDING_1: [FALSE_POSITIVE|CONFIRMED] | Confidence: [high|medium|low] | Reason: [brief explanation]
FINDING_2: [FALSE_POSITIVE|CONFIRMED] | Confidence: [high|medium|low] | Reason: [brief explanation]
... and so on

Then provide a brief SUMMARY of your adjudication.
"""

    confirmed_findings: List[Dict[str, Any]] = []
    rejected_findings: List[Dict[str, Any]] = []
    batch_summaries: List[str] = []
    failed_batches = 0

    batch_size = 15
    total_batches = max(1, math.ceil(len(findings) / batch_size))

    for batch_index, start in enumerate(range(0, len(findings), batch_size), start=1):
        chunk = findings[start:start + batch_size]

        prompt = base_prompt
        for i, finding in enumerate(chunk):
            prompt += f"""
### Finding {i+1}:
- Rule: {finding.get('rule_id', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}
- Message: {finding.get('message', 'N/A')}
- Line: {finding.get('line_number', 'N/A')}
- Category: {finding.get('category', 'N/A')}
"""
        prompt += response_format

        try:
            response = await generate_with_ai(
                prompt=prompt,
                system_prompt="You are a skeptical security auditor focused on eliminating false positives. Be concise.",
                max_tokens=1500,
            )
        except Exception as e:
            failed_batches += 1
            logger.error(f"AI adjudication failed for batch {batch_index}: {e}")
            confirmed_findings.extend(chunk)
            continue

        # Parse the AI response
        chunk_confirmed: List[Dict[str, Any]] = []
        chunk_rejected: List[Dict[str, Any]] = []

        lines = (response or "").strip().split('\n')
        finding_index = 0

        for line in lines:
            line = line.strip()
            if line.startswith('FINDING_'):
                if finding_index < len(chunk):
                    finding = chunk[finding_index].copy()

                    # Parse the verdict
                    if 'FALSE_POSITIVE' in line.upper():
                        reason_match = re.search(r'Reason:\s*(.+)', line, re.IGNORECASE)
                        reason = reason_match.group(1) if reason_match else "Marked as false positive by AI adjudicator"
                        finding['_adjudication'] = {
                            'verdict': 'false_positive',
                            'reason': reason,
                        }
                        chunk_rejected.append(finding)
                    elif 'CONFIRMED' in line.upper():
                        reason_match = re.search(r'Reason:\s*(.+)', line, re.IGNORECASE)
                        reason = reason_match.group(1) if reason_match else "Confirmed as real issue by AI adjudicator"
                        finding['_adjudication'] = {
                            'verdict': 'confirmed',
                            'reason': reason,
                        }
                        chunk_confirmed.append(finding)
                    else:
                        # Default to confirmed if unclear
                        chunk_confirmed.append(finding)

                    finding_index += 1

        # Handle any findings not in the response (keep them)
        for i in range(finding_index, len(chunk)):
            chunk_confirmed.append(chunk[i])

        summary_match = re.search(r'(?:SUMMARY|Summary)[:\s]+(.+)', response or "", re.IGNORECASE | re.DOTALL)
        if summary_match:
            batch_summaries.append(summary_match.group(1).strip()[:500])

        confirmed_findings.extend(chunk_confirmed)
        rejected_findings.extend(chunk_rejected)

    if total_batches == 1 and batch_summaries:
        summary = batch_summaries[0]
    else:
        summary = (
            f"Adjudicated {len(findings)} findings in {total_batches} batch(es): "
            f"{len(confirmed_findings)} confirmed, {len(rejected_findings)} rejected as false positives."
        )
        if failed_batches:
            summary += f" {failed_batches} batch(es) failed; those findings were kept."

    logger.info(f"AI adjudication: {len(confirmed_findings)} confirmed, {len(rejected_findings)} false positives from {len(findings)} total")

    return confirmed_findings, rejected_findings, summary


def scan_docker_resources(
    source_root: Path,
    scan_images: bool = True,
    image_timeout: int = 300,
    scan_build_context_files: bool = True,
) -> DockerScanResult:
    """
    Scan all Docker resources in a project.

    Args:
        source_root: Root directory to scan
        scan_images: Whether to scan referenced images (requires Docker/Trivy)
        image_timeout: Timeout for image scanning in seconds
        scan_build_context_files: Whether to scan for sensitive files in build context

    Returns:
        DockerScanResult with all findings including offensive security insights
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

        # Scan build context for sensitive files
        if scan_build_context_files:
            try:
                build_context_findings = scan_build_context(source_root, dockerfile)
                result.build_context_findings.extend(build_context_findings)
            except Exception as e:
                logger.debug(f"Build context scan failed for {dockerfile}: {e}")

    # Find and scan docker-compose files
    compose_files = find_docker_compose_files(source_root)
    logger.info(f"Found {len(compose_files)} docker-compose files")

    for compose_file in compose_files:
        result.compose_files_scanned += 1

        # Extract images
        images = extract_images_from_compose(compose_file)
        for img in images:
            if img not in result.base_images_found:
                result.base_images_found.append(img)

        # Security scan the compose file
        compose_findings = scan_compose_file(compose_file)
        result.compose_findings.extend(compose_findings)

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

    # Generate offensive-focused recommendations
    _generate_offensive_recommendations(result)

    logger.info(
        f"Docker scan complete: {result.dockerfiles_scanned} Dockerfiles, "
        f"{result.compose_files_scanned} compose files, "
        f"{len(result.dockerfile_findings)} Dockerfile findings, "
        f"{len(result.compose_findings)} compose findings, "
        f"{len(result.build_context_findings)} build context findings, "
        f"{len(result.image_vulnerabilities)} image vulnerabilities"
    )

    return result


def _generate_offensive_recommendations(result: DockerScanResult) -> None:
    """Generate offensive security-focused recommendations based on findings."""

    # Categorize findings by attack type
    container_escape_count = 0
    priv_esc_count = 0
    secrets_count = 0
    lateral_movement_count = 0

    all_findings = (
        [(f.category, f.severity) for f in result.dockerfile_findings] +
        [(f.category, f.severity) for f in result.compose_findings] +
        [(f.category, f.severity) for f in result.build_context_findings]
    )

    for category, severity in all_findings:
        if category in ["container_escape"]:
            container_escape_count += 1
        elif category in ["privilege_escalation", "privileges"]:
            priv_esc_count += 1
        elif category in ["secrets"]:
            secrets_count += 1
        elif category in ["lateral_movement"]:
            lateral_movement_count += 1

    # Critical: Container escape vectors
    if container_escape_count > 0:
        result.recommendations.append(
            f"🚨 CRITICAL: {container_escape_count} container escape vector(s) found! "
            "Attacker can break out to host system. Immediate remediation required."
        )

    # High: Lateral movement potential
    if lateral_movement_count > 0:
        result.recommendations.append(
            f"⚠️ HIGH: {lateral_movement_count} lateral movement vector(s) found! "
            "Compromised container can pivot to other systems (cloud, k8s, SSH)."
        )

    # Secrets exposure
    if secrets_count > 0:
        result.recommendations.append(
            f"🔑 {secrets_count} secret exposure issue(s) found! "
            "Credentials may be extractable from image layers or environment."
        )

    # Privilege escalation
    if priv_esc_count > 0:
        result.recommendations.append(
            f"⬆️ {priv_esc_count} privilege escalation vector(s) found! "
            "Attacker could gain elevated privileges within container."
        )

    # Check for outdated base images
    for image in result.base_images_found:
        if ":latest" in image or ":" not in image:
            result.recommendations.append(
                f"📦 Unpinned base image '{image}' - supply chain risk. "
                "Pin to specific digest or version tag."
            )

    # Overall severity assessment
    critical_count = sum(1 for f in result.dockerfile_findings if f.severity == "critical")
    critical_count += sum(1 for f in result.compose_findings if f.severity == "critical")
    critical_count += sum(1 for f in result.build_context_findings if f.severity == "critical")

    if critical_count > 0:
        result.recommendations.insert(0,
            f"🔴 OVERALL RISK: CRITICAL - {critical_count} critical finding(s). "
            "This configuration is highly exploitable by attackers."
        )
    elif container_escape_count > 0 or lateral_movement_count > 0:
        result.recommendations.insert(0,
            "🟠 OVERALL RISK: HIGH - Container escape or lateral movement possible."
        )
    elif secrets_count > 0 or priv_esc_count > 0:
        result.recommendations.insert(0,
            "🟡 OVERALL RISK: MEDIUM - Secrets exposure or privilege escalation risks."
        )


def convert_to_findings(
    docker_result: DockerScanResult,
    source_root: Path
) -> List[Dict[str, Any]]:
    """
    Convert Docker scan results to standard Finding format.
    Includes offensive security context (attack vectors).
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
                "attack_vector": df_finding.attack_vector,
            },
        })

    # Convert Docker Compose findings
    for compose_finding in docker_result.compose_findings:
        # Extract service name from message if present
        service_name = compose_finding.service_name
        message = compose_finding.message
        if message.startswith("["):
            end_bracket = message.find("]")
            if end_bracket > 0:
                message = message[end_bracket + 2:]

        findings.append({
            "type": "docker_compose",
            "severity": compose_finding.severity,
            "file_path": compose_finding.file_path,
            "start_line": None,
            "end_line": None,
            "summary": f"[{compose_finding.rule_id}] [{service_name}] {message}",
            "details": {
                "rule_id": compose_finding.rule_id,
                "service_name": service_name,
                "category": compose_finding.category,
                "remediation": compose_finding.remediation,
                "attack_vector": compose_finding.attack_vector,
            },
        })

    # Convert Build Context findings
    for bc_finding in docker_result.build_context_findings:
        findings.append({
            "type": "build_context",
            "severity": bc_finding.severity,
            "file_path": bc_finding.file_path,
            "start_line": None,
            "end_line": None,
            "summary": f"[BUILD_CTX] {bc_finding.message}",
            "details": {
                "category": bc_finding.category,
                "attack_vector": bc_finding.attack_vector,
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


# =============================================================================
# DOCKER IMAGE CVE INTEGRATION
# Extracts packages from Docker images and enriches with CVE/NVD/EPSS/KEV data
# =============================================================================

# Package ecosystem mapping for OSV
PACKAGE_MANAGER_TO_ECOSYSTEM = {
    # Debian/Ubuntu
    "dpkg": "Debian",
    "deb": "Debian",
    "debian": "Debian",
    "ubuntu": "Debian",
    # Alpine
    "apk": "Alpine",
    "alpine": "Alpine",
    # RHEL/CentOS/Rocky/Alma
    "rpm": "Rocky Linux",
    "centos": "Rocky Linux",
    "rhel": "Rocky Linux",
    "fedora": "Rocky Linux",
    "rocky": "Rocky Linux",
    "almalinux": "Rocky Linux",
    # Language ecosystems
    "pip": "PyPI",
    "python": "PyPI",
    "pypi": "PyPI",
    "npm": "npm",
    "node": "npm",
    "nodejs": "npm",
    "gem": "RubyGems",
    "ruby": "RubyGems",
    "bundler": "RubyGems",
    "cargo": "crates.io",
    "rust": "crates.io",
    "go": "Go",
    "golang": "Go",
    "gomod": "Go",
    "composer": "Packagist",
    "php": "Packagist",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "maven": "Maven",
    "gradle": "Maven",
    "java": "Maven",
    "jar": "Maven",
}


@dataclass
class DockerPackage:
    """A package installed in a Docker image."""
    name: str
    version: str
    ecosystem: str  # OSV ecosystem name (Debian, Alpine, PyPI, npm, etc.)
    pkg_type: str  # Original package type from Trivy (os, library, etc.)
    layer: Optional[str] = None  # Which layer introduced this package
    locations: List[str] = field(default_factory=list)  # File paths where package was found


@dataclass
class DockerCVEResult:
    """Result of CVE scanning for a Docker image."""
    image_name: str
    packages_scanned: int
    packages_with_vulns: int
    vulnerabilities: List[Dict[str, Any]]
    # Severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    # Special indicators
    kev_count: int = 0  # Count of CVEs in CISA KEV catalog
    high_epss_count: int = 0  # Count of CVEs with EPSS > 0.5
    # Metadata
    scan_duration_seconds: float = 0.0
    trivy_available: bool = False
    enrichment_applied: bool = False
    error: Optional[str] = None


def _normalize_ecosystem(pkg_type: str, target: str = "") -> str:
    """
    Normalize package type to OSV ecosystem name.

    Args:
        pkg_type: Package type from Trivy (os, library, npm, pip, etc.)
        target: Target string from Trivy (may contain OS info)

    Returns:
        OSV ecosystem name
    """
    pkg_type_lower = pkg_type.lower()
    target_lower = target.lower()

    # Check pkg_type first
    if pkg_type_lower in PACKAGE_MANAGER_TO_ECOSYSTEM:
        return PACKAGE_MANAGER_TO_ECOSYSTEM[pkg_type_lower]

    # Check target for OS hints
    if "alpine" in target_lower:
        return "Alpine"
    if "debian" in target_lower or "ubuntu" in target_lower:
        return "Debian"
    if "centos" in target_lower or "rhel" in target_lower or "rocky" in target_lower:
        return "Rocky Linux"

    # Common language package types
    if pkg_type_lower == "python-pkg":
        return "PyPI"
    if pkg_type_lower == "node-pkg":
        return "npm"
    if pkg_type_lower == "gemspec":
        return "RubyGems"
    if pkg_type_lower == "gobinary" or pkg_type_lower == "gomod":
        return "Go"
    if pkg_type_lower == "rust-binary" or pkg_type_lower == "cargo":
        return "crates.io"
    if pkg_type_lower == "jar" or pkg_type_lower == "pom":
        return "Maven"
    if pkg_type_lower == "composer":
        return "Packagist"
    if pkg_type_lower == "dotnet-deps" or pkg_type_lower == "nuget":
        return "NuGet"

    # Default to OS package based on target
    if pkg_type_lower == "os":
        if "alpine" in target_lower:
            return "Alpine"
        elif "debian" in target_lower or "ubuntu" in target_lower:
            return "Debian"
        else:
            return "Debian"  # Default fallback

    # Unknown - return as-is
    return pkg_type


async def extract_packages_from_image(
    image_name: str,
    timeout: int = 300
) -> Tuple[List[DockerPackage], Dict[str, Any]]:
    """
    Extract installed packages from a Docker image using Trivy.

    Uses Trivy with --list-all-pkgs to get a complete package inventory.
    Falls back to basic layer extraction if Trivy is not available.

    Args:
        image_name: Docker image name (e.g., "python:3.9-slim")
        timeout: Timeout in seconds for Trivy execution

    Returns:
        Tuple of (list of DockerPackage, metadata dict)
    """
    metadata = {
        "trivy_available": is_trivy_available(),
        "extraction_method": "trivy" if is_trivy_available() else "none",
        "os_detected": None,
        "packages_by_type": {},
    }

    if not is_trivy_available():
        logger.warning("Trivy not available for package extraction")
        return [], metadata

    packages: List[DockerPackage] = []

    try:
        # Run Trivy with --list-all-pkgs to get ALL packages (not just vulnerable ones)
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--list-all-pkgs",  # This is key - shows all packages
            "--quiet",
            image_name
        ]

        logger.info(f"Extracting packages from {image_name} using Trivy")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            if "No such image" in result.stderr:
                logger.warning(f"Image {image_name} not found locally")
                metadata["error"] = f"Image not found: {image_name}"
                return [], metadata
            else:
                logger.warning(f"Trivy command failed: {result.stderr[:500]}")
                metadata["error"] = result.stderr[:500]
                return [], metadata

        if not result.stdout:
            logger.warning("Trivy returned empty output")
            return [], metadata

        data = json.loads(result.stdout)

        # Extract OS information
        if data.get("Metadata"):
            os_info = data["Metadata"].get("OS", {})
            metadata["os_detected"] = f"{os_info.get('Family', 'unknown')} {os_info.get('Name', '')}"

        # Parse packages from Results
        pkg_type_counts: Dict[str, int] = {}
        seen_packages: Set[str] = set()  # Dedupe by name+version+ecosystem

        for result_item in data.get("Results", []):
            target = result_item.get("Target", "")
            pkg_class = result_item.get("Class", "")
            pkg_type = result_item.get("Type", "os")

            # Get packages from this result
            for pkg in result_item.get("Packages", []):
                pkg_name = pkg.get("Name", "")
                pkg_version = pkg.get("Version", "")

                if not pkg_name or not pkg_version:
                    continue

                # Normalize ecosystem
                ecosystem = _normalize_ecosystem(pkg_type, target)

                # Dedupe
                dedup_key = f"{pkg_name}:{pkg_version}:{ecosystem}"
                if dedup_key in seen_packages:
                    continue
                seen_packages.add(dedup_key)

                # Get file locations if available
                locations = pkg.get("Locations", [])
                if isinstance(locations, list):
                    locations = [loc.get("Path", "") if isinstance(loc, dict) else str(loc) for loc in locations]
                else:
                    locations = []

                packages.append(DockerPackage(
                    name=pkg_name,
                    version=pkg_version,
                    ecosystem=ecosystem,
                    pkg_type=pkg_type,
                    layer=pkg.get("Layer", {}).get("DiffID") if pkg.get("Layer") else None,
                    locations=locations,
                ))

                # Track counts by type
                pkg_type_counts[ecosystem] = pkg_type_counts.get(ecosystem, 0) + 1

        metadata["packages_by_type"] = pkg_type_counts
        logger.info(f"Extracted {len(packages)} packages from {image_name}: {pkg_type_counts}")

    except subprocess.TimeoutExpired:
        logger.warning(f"Trivy package extraction timed out for {image_name}")
        metadata["error"] = "Timeout during package extraction"
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse Trivy output: {e}")
        metadata["error"] = f"JSON parse error: {e}"
    except Exception as e:
        logger.error(f"Error extracting packages from {image_name}: {e}")
        metadata["error"] = str(e)

    return packages, metadata


async def scan_image_packages_for_cves(
    image_name: str,
    include_nvd_enrichment: bool = True,
    include_kev: bool = True,
    include_epss: bool = True,
    timeout: int = 300,
) -> DockerCVEResult:
    """
    Scan Docker image packages for known CVEs using the existing CVE infrastructure.

    This function:
    1. Extracts packages from the Docker image using Trivy
    2. Converts packages to Dependency models for cve_service
    3. Looks up CVEs via OSV API (with local database fallback)
    4. Enriches with NVD data (CVSS v3/v4 vectors, CWEs)
    5. Adds EPSS exploit probability scores
    6. Checks CISA KEV status

    Args:
        image_name: Docker image name to scan
        include_nvd_enrichment: Whether to enrich with NVD data
        include_kev: Whether to check CISA KEV status
        include_epss: Whether to include EPSS scores
        timeout: Timeout for package extraction

    Returns:
        DockerCVEResult with all vulnerabilities and enrichment data
    """
    import time
    start_time = time.time()

    result = DockerCVEResult(
        image_name=image_name,
        packages_scanned=0,
        packages_with_vulns=0,
        vulnerabilities=[],
        trivy_available=is_trivy_available(),
    )

    try:
        # 1. Extract packages from image
        packages, pkg_metadata = await extract_packages_from_image(image_name, timeout=timeout)

        if pkg_metadata.get("error"):
            result.error = pkg_metadata["error"]
            return result

        if not packages:
            logger.info(f"No packages found in {image_name}")
            result.scan_duration_seconds = time.time() - start_time
            return result

        result.packages_scanned = len(packages)
        logger.info(f"Looking up CVEs for {len(packages)} packages from {image_name}")

        # 2. Convert to Dependency models for cve_service
        from backend import models
        from backend.services import cve_service

        deps = [
            models.Dependency(
                id=idx,
                project_id=0,  # No project context for Docker scan
                name=pkg.name,
                version=pkg.version,
                ecosystem=pkg.ecosystem,
            )
            for idx, pkg in enumerate(packages)
        ]

        # 3. Lookup CVEs using existing service (OSV API + local DB fallback)
        vulns = await cve_service.lookup_dependencies(deps)

        if not vulns:
            logger.info(f"No CVEs found for packages in {image_name}")
            result.scan_duration_seconds = time.time() - start_time
            return result

        logger.info(f"Found {len(vulns)} CVEs for packages in {image_name}")

        # 4. Convert vulnerabilities to dict format for enrichment
        vuln_dicts = []
        pkg_lookup = {idx: pkg for idx, pkg in enumerate(packages)}

        for vuln in vulns:
            pkg = pkg_lookup.get(vuln.dependency_id)
            vuln_dict = {
                "external_id": vuln.external_id,
                "title": vuln.title,
                "description": vuln.description,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "source": vuln.source,
                # Package context
                "package_name": pkg.name if pkg else None,
                "package_version": pkg.version if pkg else None,
                "package_ecosystem": pkg.ecosystem if pkg else None,
                "package_type": pkg.pkg_type if pkg else None,
            }
            vuln_dicts.append(vuln_dict)

        # 5. Enrich with NVD/EPSS/KEV if requested
        if include_nvd_enrichment or include_kev or include_epss:
            from backend.services import nvd_service

            # Use the full enrichment function
            if include_nvd_enrichment and include_kev and include_epss:
                vuln_dicts = await nvd_service.enrich_all_parallel(vuln_dicts)
                result.enrichment_applied = True
            elif include_nvd_enrichment:
                vuln_dicts = await nvd_service.enrich_vulnerabilities_with_nvd(
                    vuln_dicts,
                    include_kev=include_kev
                )
                result.enrichment_applied = True

        # 6. Calculate statistics
        packages_with_vulns = set()
        for vuln in vuln_dicts:
            severity = (vuln.get("severity") or "").lower()

            if severity == "critical":
                result.critical_count += 1
            elif severity == "high":
                result.high_count += 1
            elif severity == "medium":
                result.medium_count += 1
            elif severity == "low":
                result.low_count += 1

            # Track KEV hits
            if vuln.get("in_kev"):
                result.kev_count += 1

            # Track high EPSS scores (> 50% exploitation probability)
            epss_score = vuln.get("epss_score")
            if epss_score and epss_score > 0.5:
                result.high_epss_count += 1

            # Track packages with vulns
            pkg_key = f"{vuln.get('package_name')}:{vuln.get('package_version')}"
            packages_with_vulns.add(pkg_key)

        result.packages_with_vulns = len(packages_with_vulns)
        result.vulnerabilities = vuln_dicts

        logger.info(
            f"CVE scan complete for {image_name}: "
            f"{len(vuln_dicts)} CVEs ({result.critical_count} critical, {result.high_count} high), "
            f"{result.kev_count} in KEV, {result.high_epss_count} with high EPSS"
        )

    except Exception as e:
        logger.error(f"Error scanning {image_name} for CVEs: {e}")
        result.error = str(e)

    result.scan_duration_seconds = time.time() - start_time
    return result
