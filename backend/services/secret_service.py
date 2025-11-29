"""
Secret Detection Service

Scans source code for hardcoded secrets, API keys, tokens, and credentials.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SecretFinding:
    """Represents a detected secret in source code."""
    secret_type: str
    file_path: str
    line_number: int
    line_content: str
    severity: str
    description: str
    masked_value: str


# Secret patterns with their types, severities, and descriptions
SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    # AWS
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', 'critical', 'AWS Access Key ID found - can provide full AWS account access'),
    (r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'AWS Secret Access Key', 'critical', 'AWS Secret Access Key found'),
    
    # Azure
    (r'(?i)azure[_\-]?storage[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9+/=]{88})["\']?', 'Azure Storage Key', 'critical', 'Azure Storage Account Key found'),
    (r'(?i)azure[_\-]?(?:client|tenant|subscription)[_\-]?(?:id|secret)[\s]*[=:]\s*["\']?([a-f0-9-]{36})["\']?', 'Azure Credential', 'high', 'Azure credential identifier found'),
    
    # Google Cloud
    (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key', 'high', 'Google API Key found'),
    (r'(?i)google[_\-]?(?:api[_\-]?key|cloud[_\-]?key)[\s]*[=:]\s*["\']?([A-Za-z0-9_-]{39})["\']?', 'Google Cloud Key', 'high', 'Google Cloud API Key found'),
    
    # GitHub
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', 'critical', 'GitHub PAT found - can access repositories'),
    (r'gho_[0-9a-zA-Z]{36}', 'GitHub OAuth Token', 'critical', 'GitHub OAuth Token found'),
    (r'ghu_[0-9a-zA-Z]{36}', 'GitHub User Token', 'critical', 'GitHub User-to-Server Token found'),
    (r'ghs_[0-9a-zA-Z]{36}', 'GitHub Server Token', 'critical', 'GitHub Server-to-Server Token found'),
    (r'github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}', 'GitHub Fine-grained PAT', 'critical', 'GitHub Fine-grained Personal Access Token found'),
    
    # GitLab
    (r'glpat-[0-9a-zA-Z_-]{20}', 'GitLab Personal Access Token', 'critical', 'GitLab PAT found'),
    
    # Slack
    (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token', 'high', 'Slack API Token found'),
    (r'https://hooks\.slack\.com/services/[A-Za-z0-9+/]+', 'Slack Webhook URL', 'medium', 'Slack Webhook URL found'),
    
    # Discord
    (r'(?i)discord[_\-]?(?:token|webhook)[\s]*[=:]\s*["\']?([A-Za-z0-9._-]{50,})["\']?', 'Discord Token', 'high', 'Discord Token or Webhook found'),
    
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Live Secret Key', 'critical', 'Stripe Live Secret Key found - can process payments'),
    (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Test Secret Key', 'medium', 'Stripe Test Secret Key found'),
    (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Live Publishable Key', 'low', 'Stripe Live Publishable Key found'),
    (r'rk_live_[0-9a-zA-Z]{24}', 'Stripe Live Restricted Key', 'high', 'Stripe Live Restricted Key found'),
    
    # Twilio
    (r'SK[0-9a-fA-F]{32}', 'Twilio API Key', 'high', 'Twilio API Key found'),
    (r'(?i)twilio[_\-]?(?:account[_\-]?sid|auth[_\-]?token)[\s]*[=:]\s*["\']?([A-Za-z0-9]{32,34})["\']?', 'Twilio Credential', 'high', 'Twilio credential found'),
    
    # SendGrid
    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 'SendGrid API Key', 'high', 'SendGrid API Key found'),
    
    # Mailgun
    (r'key-[0-9a-zA-Z]{32}', 'Mailgun API Key', 'high', 'Mailgun API Key found'),
    
    # Generic patterns
    (r'(?i)(?:api[_\-]?key|apikey|access[_\-]?key)[\s]*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?', 'Generic API Key', 'medium', 'Potential API key found'),
    (r'(?i)(?:secret|password|passwd|pwd)[\s]*[=:]\s*["\']([^"\']{8,})["\']', 'Hardcoded Password', 'high', 'Hardcoded password or secret found'),
    (r'(?i)(?:bearer|token)[\s]+([A-Za-z0-9_-]{20,})', 'Bearer Token', 'high', 'Bearer token found'),
    
    # Private Keys
    (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', 'Private Key', 'critical', 'Private key found - immediate rotation required'),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'PGP Private Key', 'critical', 'PGP Private Key found'),
    
    # Database Connection Strings
    (r'(?i)(?:mongodb|mysql|postgres|postgresql|mssql|redis)://[^\s"\']+:[^\s"\']+@[^\s"\']+', 'Database Connection String', 'critical', 'Database connection string with credentials found'),
    (r'(?i)(?:jdbc|odbc):[^\s"\']+password=[^\s"\'&]+', 'JDBC/ODBC Connection', 'critical', 'Database connection with embedded password found'),
    
    # JWT Secrets
    (r'(?i)jwt[_\-]?secret[\s]*[=:]\s*["\']?([A-Za-z0-9_-]{20,})["\']?', 'JWT Secret', 'critical', 'JWT signing secret found'),
    
    # NPM Tokens
    (r'npm_[A-Za-z0-9]{36}', 'NPM Token', 'high', 'NPM authentication token found'),
    
    # PyPI Tokens
    (r'pypi-AgE[A-Za-z0-9_-]{50,}', 'PyPI Token', 'high', 'PyPI authentication token found'),
    
    # Heroku
    (r'(?i)heroku[_\-]?api[_\-]?key[\s]*[=:]\s*["\']?([a-f0-9-]{36})["\']?', 'Heroku API Key', 'high', 'Heroku API Key found'),
    
    # DigitalOcean
    (r'dop_v1_[a-f0-9]{64}', 'DigitalOcean PAT', 'high', 'DigitalOcean Personal Access Token found'),
    (r'doo_v1_[a-f0-9]{64}', 'DigitalOcean OAuth Token', 'high', 'DigitalOcean OAuth Token found'),
]

# Files and patterns to ignore
IGNORE_PATTERNS = [
    r'\.git/',
    r'node_modules/',
    r'__pycache__/',
    r'\.env\.example',
    r'\.env\.sample',
    r'\.env\.template',
    r'test.*\.py$',
    r'.*_test\.py$',
    r'.*\.test\.[jt]sx?$',
    r'.*\.spec\.[jt]sx?$',
]

# Common false positive patterns
FALSE_POSITIVE_PATTERNS = [
    r'example',
    r'sample',
    r'placeholder',
    r'your[_\-]?key',
    r'xxx+',
    r'\*{3,}',
    r'<[^>]+>',
    r'\${[^}]+}',
    r'\{\{[^}]+\}\}',
]


def should_ignore_file(file_path: str) -> bool:
    """Check if file should be ignored based on path patterns."""
    for pattern in IGNORE_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False


def is_false_positive(value: str) -> bool:
    """Check if the detected value is likely a false positive."""
    value_lower = value.lower()
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, value_lower):
            return True
    return False


def mask_secret(value: str) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= 8:
        return '*' * len(value)
    return value[:4] + '*' * (len(value) - 8) + value[-4:]


def scan_content(content: str, file_path: str) -> List[SecretFinding]:
    """
    Scan content for secrets and return findings.
    
    Args:
        content: The source code content to scan
        file_path: Path to the file (for reporting)
        
    Returns:
        List of SecretFinding objects
    """
    if should_ignore_file(file_path):
        return []
    
    findings: List[SecretFinding] = []
    lines = content.split('\n')
    
    for line_num, line in enumerate(lines, start=1):
        # Skip comment lines
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
            # Still scan, but with lower priority - comments can leak secrets too
            pass
        
        for pattern, secret_type, severity, description in SECRET_PATTERNS:
            matches = re.finditer(pattern, line)
            for match in matches:
                matched_value = match.group(0)
                
                # Check for false positives
                if is_false_positive(matched_value):
                    continue
                
                # Check if it's in a clearly test/example context
                if 'test' in file_path.lower() or 'example' in line.lower():
                    # Downgrade severity for test files
                    severity = 'low' if severity in ['critical', 'high'] else severity
                
                finding = SecretFinding(
                    secret_type=secret_type,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line.strip()[:100],  # Truncate long lines
                    severity=severity,
                    description=description,
                    masked_value=mask_secret(matched_value),
                )
                findings.append(finding)
                
    return findings


def scan_file(file_path: str) -> List[SecretFinding]:
    """
    Scan a file for secrets.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of SecretFinding objects
    """
    if should_ignore_file(file_path):
        return []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return scan_content(content, file_path)
    except Exception as e:
        logger.warning(f"Could not scan file {file_path}: {e}")
        return []


def scan_directory(directory: str) -> List[SecretFinding]:
    """
    Recursively scan a directory for secrets.
    
    Args:
        directory: Path to the directory to scan
        
    Returns:
        List of all SecretFinding objects found
    """
    import os
    
    all_findings: List[SecretFinding] = []
    
    for root, dirs, files in os.walk(directory):
        # Skip ignored directories
        dirs[:] = [d for d in dirs if not should_ignore_file(os.path.join(root, d))]
        
        for file in files:
            file_path = os.path.join(root, file)
            # Only scan text-like files
            if file.endswith(('.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', 
                            '.rb', '.php', '.rs', '.kt', '.kts', '.cs', '.cpp', '.c', '.h', '.hpp',
                            '.yml', '.yaml', '.json', '.xml', '.env', '.config',
                            '.properties', '.ini', '.conf', '.sh', '.bash', '.zsh',
                            '.sql', '.md', '.txt', '.html', '.css', '.scss',
                            '.toml', '.lock', '.gradle')):
                findings = scan_file(file_path)
                all_findings.extend(findings)
    
    logger.info(f"Secret scan complete: found {len(all_findings)} potential secrets in {directory}")
    return all_findings


def get_severity_priority(severity: str) -> int:
    """Get numeric priority for sorting by severity."""
    priorities = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    return priorities.get(severity.lower(), 4)


def summarize_findings(findings: List[SecretFinding]) -> dict:
    """
    Generate a summary of secret findings.
    
    Args:
        findings: List of SecretFinding objects
        
    Returns:
        Dictionary with summary statistics
    """
    if not findings:
        return {
            'total_count': 0,
            'by_severity': {},
            'by_type': {},
            'files_affected': 0,
        }
    
    by_severity: dict = {}
    by_type: dict = {}
    files = set()
    
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_type[finding.secret_type] = by_type.get(finding.secret_type, 0) + 1
        files.add(finding.file_path)
    
    return {
        'total_count': len(findings),
        'by_severity': by_severity,
        'by_type': by_type,
        'files_affected': len(files),
    }
