"""
Bandit Security Scanner Service

Provides Python security analysis using Bandit - a tool designed to find common
security issues in Python code.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BanditFinding:
    """Represents a security finding from Bandit."""
    test_id: str
    test_name: str
    severity: str
    confidence: str
    file_path: str
    line_number: int
    line_range: List[int]
    message: str
    code: str
    cwe: Optional[str] = None
    more_info: Optional[str] = None


def is_bandit_available() -> bool:
    """Check if Bandit is installed and available."""
    try:
        result = subprocess.run(
            ["bandit", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_bandit_version() -> Optional[str]:
    """Get the installed Bandit version."""
    try:
        result = subprocess.run(
            ["bandit", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def map_bandit_severity(severity: str) -> str:
    """Map Bandit severity to our severity levels."""
    mapping = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    return mapping.get(severity.upper(), "medium")


def run_bandit_scan(
    source_path: Path,
    timeout: int = 300,
    recursive: bool = True
) -> List[BanditFinding]:
    """
    Run Bandit security scan on Python code.
    
    Args:
        source_path: Path to the source code directory
        timeout: Maximum execution time in seconds
        recursive: Whether to scan recursively
        
    Returns:
        List of BanditFinding objects
    """
    if not is_bandit_available():
        logger.warning("Bandit is not installed. Skipping Python security scan.")
        return []
    
    findings: List[BanditFinding] = []
    
    # Check if there are Python files to scan
    py_files = list(source_path.rglob("*.py")) if recursive else list(source_path.glob("*.py"))
    if not py_files:
        logger.info("No Python files found to scan with Bandit")
        return []
    
    logger.info(f"Running Bandit scan on {len(py_files)} Python files")
    
    try:
        cmd = [
            "bandit",
            "-f", "json",       # JSON output
            "-r" if recursive else "",  # Recursive
            "-ll",              # Only medium and higher severity
            "-ii",              # Only medium and higher confidence (reduces false positives)
            "--exclude", ".venv,venv,env,node_modules,__pycache__,dist,build,.git",  # Skip common non-source dirs
            str(source_path)
        ]
        # Remove empty strings from command
        cmd = [c for c in cmd if c]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(source_path)
        )
        
        # Bandit returns non-zero if it finds issues
        if result.stdout:
            try:
                output = json.loads(result.stdout)
                results = output.get("results", [])
                
                for item in results:
                    # Make path relative
                    file_path = item.get("filename", "")
                    try:
                        file_path = str(Path(file_path).relative_to(source_path))
                    except ValueError:
                        pass
                    
                    finding = BanditFinding(
                        test_id=item.get("test_id", ""),
                        test_name=item.get("test_name", ""),
                        severity=map_bandit_severity(item.get("issue_severity", "MEDIUM")),
                        confidence=item.get("issue_confidence", "MEDIUM"),
                        file_path=file_path,
                        line_number=item.get("line_number", 0),
                        line_range=item.get("line_range", []),
                        message=item.get("issue_text", ""),
                        code=item.get("code", "")[:500],  # Limit code length
                        cwe=item.get("issue_cwe", {}).get("id") if item.get("issue_cwe") else None,
                        more_info=item.get("more_info", ""),
                    )
                    findings.append(finding)
                
                logger.info(f"Bandit scan found {len(findings)} Python security issues")
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Bandit output: {e}")
        
        if result.stderr and "error" in result.stderr.lower():
            logger.warning(f"Bandit stderr: {result.stderr[:300]}")
            
    except subprocess.TimeoutExpired:
        logger.warning(f"Bandit scan timed out after {timeout} seconds")
    except Exception as e:
        logger.error(f"Bandit scan failed: {e}")
    
    return findings


def summarize_findings(findings: List[BanditFinding]) -> dict:
    """Generate a summary of Bandit findings."""
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_test": {},
            "cwe_ids": [],
        }
    
    by_severity = {}
    by_test = {}
    cwe_ids = set()
    
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_test[finding.test_id] = by_test.get(finding.test_id, 0) + 1
        if finding.cwe:
            cwe_ids.add(finding.cwe)
    
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_test": dict(sorted(by_test.items(), key=lambda x: -x[1])[:10]),
        "cwe_ids": sorted(list(cwe_ids)),
    }


def run_security_audit(source_root: Path) -> List[BanditFinding]:
    """
    Run a comprehensive security audit with Bandit.
    
    This is the main entry point for scan_service.py.
    
    Args:
        source_root: Root directory of the source code
        
    Returns:
        List of BanditFinding objects with security-relevant issues
    """
    return run_bandit_scan(source_root)
