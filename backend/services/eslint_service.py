"""
ESLint Security Service

Runs ESLint with security-focused plugins to detect JavaScript/TypeScript vulnerabilities.
"""

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ESLintFinding:
    """Represents an ESLint security finding."""
    rule_id: str
    severity: str
    message: str
    file_path: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    category: str = "security"


# ESLint security rules mapping to severity
SECURITY_RULES = {
    # eslint-plugin-security rules
    'security/detect-buffer-noassert': 'medium',
    'security/detect-child-process': 'high',
    'security/detect-disable-mustache-escape': 'high',
    'security/detect-eval-with-expression': 'critical',
    'security/detect-new-buffer': 'medium',
    'security/detect-no-csrf-before-method-override': 'high',
    'security/detect-non-literal-fs-filename': 'medium',
    'security/detect-non-literal-regexp': 'medium',
    'security/detect-non-literal-require': 'high',
    'security/detect-object-injection': 'high',
    'security/detect-possible-timing-attacks': 'medium',
    'security/detect-pseudoRandomBytes': 'medium',
    'security/detect-unsafe-regex': 'medium',
    
    # eslint-plugin-no-unsanitized rules
    'no-unsanitized/method': 'high',
    'no-unsanitized/property': 'high',
    
    # eslint-plugin-xss rules
    'xss/no-location-href-assign': 'high',
    'xss/no-mixed-html': 'medium',
    
    # Built-in ESLint rules with security implications
    'no-eval': 'critical',
    'no-implied-eval': 'critical',
    'no-new-func': 'high',
    'no-script-url': 'high',
}

# Default ESLint config for security scanning
DEFAULT_ESLINT_CONFIG = {
    "env": {
        "browser": True,
        "node": True,
        "es2021": True
    },
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module",
        "ecmaFeatures": {
            "jsx": True
        }
    },
    "plugins": ["security"],
    "extends": ["plugin:security/recommended"],
    "rules": {
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error",
        "no-script-url": "error",
        "security/detect-buffer-noassert": "error",
        "security/detect-child-process": "warn",
        "security/detect-disable-mustache-escape": "error",
        "security/detect-eval-with-expression": "error",
        "security/detect-new-buffer": "warn",
        "security/detect-no-csrf-before-method-override": "error",
        "security/detect-non-literal-fs-filename": "warn",
        "security/detect-non-literal-regexp": "warn",
        "security/detect-non-literal-require": "warn",
        "security/detect-object-injection": "warn",
        "security/detect-possible-timing-attacks": "warn",
        "security/detect-pseudoRandomBytes": "warn",
        "security/detect-unsafe-regex": "warn"
    }
}


def check_eslint_available() -> bool:
    """Check if ESLint is available in the system."""
    try:
        result = subprocess.run(
            ['npx', 'eslint', '--version'],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_node_available() -> bool:
    """Check if Node.js is available in the system."""
    try:
        result = subprocess.run(
            ['node', '--version'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_js_files(directory: str) -> List[str]:
    """Get all JavaScript/TypeScript files in a directory."""
    js_extensions = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
    js_files = []
    
    for root, dirs, files in os.walk(directory):
        # Skip node_modules and other ignored directories
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist', 'build', 'coverage']]
        
        for file in files:
            if any(file.endswith(ext) for ext in js_extensions):
                js_files.append(os.path.join(root, file))
    
    return js_files


def map_eslint_severity(eslint_severity: int) -> str:
    """Map ESLint severity (1=warn, 2=error) to our severity levels."""
    return 'high' if eslint_severity == 2 else 'medium'


def get_rule_severity(rule_id: str, eslint_severity: int) -> str:
    """Get severity for a rule, using our mapping or falling back to ESLint's."""
    if rule_id in SECURITY_RULES:
        return SECURITY_RULES[rule_id]
    return map_eslint_severity(eslint_severity)


def create_temp_eslint_config(directory: str) -> str:
    """Create a temporary ESLint config file for security scanning."""
    config_path = os.path.join(directory, '.eslintrc.security.json')
    with open(config_path, 'w') as f:
        json.dump(DEFAULT_ESLINT_CONFIG, f, indent=2)
    return config_path


def parse_eslint_output(output: str, base_dir: str) -> List[ESLintFinding]:
    """Parse ESLint JSON output into findings."""
    findings = []
    
    try:
        results = json.loads(output)
        
        for file_result in results:
            file_path = file_result.get('filePath', '')
            # Make path relative to base directory
            if file_path.startswith(base_dir):
                file_path = file_path[len(base_dir):].lstrip(os.sep)
            
            for message in file_result.get('messages', []):
                rule_id = message.get('ruleId', 'unknown')
                
                # Skip non-security rules if not in our list
                if not any(rule_id.startswith(prefix) for prefix in ['security/', 'no-unsanitized/', 'xss/', 'no-eval', 'no-implied-eval', 'no-new-func', 'no-script-url']):
                    continue
                
                severity = get_rule_severity(rule_id, message.get('severity', 1))
                
                finding = ESLintFinding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message.get('message', ''),
                    file_path=file_path,
                    line=message.get('line', 0),
                    column=message.get('column', 0),
                    end_line=message.get('endLine'),
                    end_column=message.get('endColumn'),
                )
                findings.append(finding)
                
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse ESLint output: {e}")
    
    return findings


def run_eslint_security_scan(
    directory: str,
    timeout: int = 300,
    install_plugins: bool = True,
) -> List[ESLintFinding]:
    """
    Run ESLint with security plugins on a directory.
    
    Args:
        directory: Directory to scan
        timeout: Timeout in seconds
        install_plugins: Whether to install security plugins if needed
        
    Returns:
        List of ESLintFinding objects
    """
    if not check_node_available():
        logger.warning("Node.js not available, skipping ESLint security scan")
        return []
    
    # Get JS/TS files
    js_files = get_js_files(directory)
    if not js_files:
        logger.info("No JavaScript/TypeScript files found to scan")
        return []
    
    logger.info(f"Running ESLint security scan on {len(js_files)} files")
    
    # Check if this is a Node project
    package_json = os.path.join(directory, 'package.json')
    has_package_json = os.path.exists(package_json)
    
    try:
        # Install security plugin if needed and requested
        if install_plugins and has_package_json:
            try:
                # Try to install eslint-plugin-security locally
                subprocess.run(
                    ['npm', 'install', '--save-dev', 'eslint', 'eslint-plugin-security'],
                    cwd=directory,
                    capture_output=True,
                    timeout=120,
                )
            except Exception as e:
                logger.warning(f"Could not install ESLint plugins: {e}")
        
        # Create temporary config
        config_path = create_temp_eslint_config(directory)
        
        try:
            # Run ESLint
            cmd = [
                'npx', 'eslint',
                '--config', config_path,
                '--format', 'json',
                '--no-error-on-unmatched-pattern',
            ]
            cmd.extend(js_files[:100])  # Limit files to avoid command line length issues
            
            result = subprocess.run(
                cmd,
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            
            # ESLint returns non-zero for lint errors, which is expected
            findings = parse_eslint_output(result.stdout, directory)
            
            logger.info(f"ESLint security scan found {len(findings)} issues")
            return findings
            
        finally:
            # Cleanup temp config
            if os.path.exists(config_path):
                os.remove(config_path)
                
    except subprocess.TimeoutExpired:
        logger.warning(f"ESLint scan timed out after {timeout} seconds")
        return []
    except Exception as e:
        logger.error(f"ESLint security scan failed: {e}")
        return []


def scan_single_file(file_path: str) -> List[ESLintFinding]:
    """
    Run ESLint security scan on a single file.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        List of ESLintFinding objects
    """
    if not os.path.exists(file_path):
        return []
    
    directory = os.path.dirname(file_path)
    
    if not check_node_available():
        return []
    
    # Create temporary config
    config_path = create_temp_eslint_config(directory)
    
    try:
        cmd = [
            'npx', 'eslint',
            '--config', config_path,
            '--format', 'json',
            '--no-error-on-unmatched-pattern',
            file_path,
        ]
        
        result = subprocess.run(
            cmd,
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
        )
        
        return parse_eslint_output(result.stdout, directory)
        
    except Exception as e:
        logger.warning(f"ESLint scan failed for {file_path}: {e}")
        return []
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)


def summarize_findings(findings: List[ESLintFinding]) -> Dict[str, Any]:
    """Generate a summary of ESLint findings."""
    if not findings:
        return {
            'total_count': 0,
            'by_severity': {},
            'by_rule': {},
            'files_affected': 0,
        }
    
    by_severity: Dict[str, int] = {}
    by_rule: Dict[str, int] = {}
    files = set()
    
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        files.add(finding.file_path)
    
    return {
        'total_count': len(findings),
        'by_severity': by_severity,
        'by_rule': by_rule,
        'files_affected': len(files),
    }
