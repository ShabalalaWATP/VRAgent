"""
PHP Security Scanner Service

Uses PHP_CodeSniffer with security-audit rules for PHP security scanning.
Detects:
- SQL injection
- XSS (Cross-Site Scripting)
- Command injection
- Path traversal
- Code injection
- File inclusion vulnerabilities
- Insecure cryptographic usage
- Header injection
"""
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)

# Severity mapping
SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
}


def is_progpilot_available() -> bool:
    """Check if phpcs with security audit is installed and available."""
    try:
        result = subprocess.run(
            ["phpcs", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug(f"phpcs not available: {e}")
        return False


def run_security_audit(project_path: Path, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run PHP_CodeSniffer security scan on PHP files.
    
    Args:
        project_path: Path to the project directory
        timeout: Maximum time in seconds for the scan
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    
    if not is_progpilot_available():
        logger.warning("phpcs not available, skipping PHP security scan")
        return findings
    
    # Check if there are PHP files
    php_files = list(project_path.rglob("*.php")) + list(project_path.rglob("*.phtml"))
    if not php_files:
        logger.debug("No PHP files found, skipping PHP security scan")
        return findings
    
    logger.info(f"Running phpcs security audit on {len(php_files)} PHP files in {project_path}")
    
    try:
        # Run phpcs with security-audit standard
        cmd = [
            "phpcs",
            "--standard=Security",
            "--report=json",
            "--extensions=php,phtml,inc",
            str(project_path)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(project_path)
        )
        
        # phpcs returns non-zero if it finds issues, but still outputs JSON
        output = result.stdout or result.stderr
        
        if output:
            try:
                # Try to parse JSON from output
                data = json.loads(output)
                
                for file_path, file_data in data.get("files", {}).items():
                    for msg in file_data.get("messages", []):
                        rel_path = file_path
                        try:
                            rel_path = str(Path(file_path).relative_to(project_path))
                        except ValueError:
                            pass
                        
                        severity = "medium"
                        msg_type = msg.get("type", "").upper()
                        if msg_type == "ERROR":
                            severity = "high"
                        elif msg_type == "WARNING":
                            severity = "medium"
                        
                        # Extract rule name for categorization
                        source = msg.get("source", "Security.Unknown")
                        rule_name = source.split(".")[-1].lower() if source else "security"
                        
                        findings.append({
                            "type": f"php-{rule_name}",
                            "severity": severity,
                            "file_path": rel_path,
                            "line_number": msg.get("line", 1),
                            "summary": msg.get("message", "PHP security issue")[:500],
                            "details": {
                                "tool": "phpcs-security-audit",
                                "rule": source,
                                "column": msg.get("column"),
                                "fixable": msg.get("fixable", False),
                            }
                        })
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse phpcs output as JSON: {e}")
                # Try line-by-line parsing as fallback
                findings.extend(_parse_phpcs_text_output(result.stdout, project_path))
        
        logger.info(f"PHP security scan found {len(findings)} issues")
        
    except subprocess.TimeoutExpired:
        logger.warning(f"phpcs timed out after {timeout}s")
    except Exception as e:
        logger.error(f"phpcs scan failed: {e}")
    
    return findings


def _parse_phpcs_text_output(output: str, project_path: Path) -> List[Dict[str, Any]]:
    """Parse phpcs text output when JSON parsing fails."""
    findings = []
    if not output:
        return findings
    
    import re
    # Match pattern like: FILE: /path/to/file.php
    # LINE X | ERROR/WARNING | Message
    current_file = None
    
    for line in output.split('\n'):
        file_match = re.match(r'^FILE:\s*(.+)$', line.strip())
        if file_match:
            current_file = file_match.group(1)
            continue
        
        # Match: " 10 | ERROR | Security issue message"
        issue_match = re.match(r'^\s*(\d+)\s*\|\s*(ERROR|WARNING)\s*\|\s*(.+)$', line.strip())
        if issue_match and current_file:
            line_num = int(issue_match.group(1))
            severity = "high" if issue_match.group(2) == "ERROR" else "medium"
            message = issue_match.group(3)
            
            rel_path = current_file
            try:
                rel_path = str(Path(current_file).relative_to(project_path))
            except ValueError:
                pass
            
            findings.append({
                "type": "php-security",
                "severity": severity,
                "file_path": rel_path,
                "line_number": line_num,
                "summary": message[:500],
                "details": {
                    "tool": "phpcs-security-audit",
                }
            })
    
    return findings

