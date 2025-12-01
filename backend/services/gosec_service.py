"""
Gosec Security Scanner Service

Provides Go security analysis using gosec - Golang Security Checker.
Inspects source code for security problems by scanning the Go AST.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class GosecFinding:
    """Represents a security finding from Gosec."""
    rule_id: str
    severity: str
    confidence: str
    file_path: str
    line: int
    column: int
    message: str
    code: str
    cwe: Optional[str] = None
    details: Optional[str] = None


def is_gosec_available() -> bool:
    """Check if Gosec is installed and available."""
    try:
        result = subprocess.run(
            ["gosec", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_gosec_version() -> Optional[str]:
    """Get the installed Gosec version."""
    try:
        result = subprocess.run(
            ["gosec", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def map_gosec_severity(severity: str) -> str:
    """Map Gosec severity to our severity levels."""
    mapping = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    return mapping.get(severity.upper(), "medium")


def run_gosec_scan(
    source_path: Path,
    timeout: int = 300
) -> List[GosecFinding]:
    """
    Run Gosec security scan on Go code.
    
    Args:
        source_path: Path to the source code directory
        timeout: Maximum execution time in seconds
        
    Returns:
        List of GosecFinding objects
    """
    if not is_gosec_available():
        logger.info("Gosec is not installed. Skipping Go security scan.")
        return []
    
    findings: List[GosecFinding] = []
    
    # Check if there are Go files to scan
    go_files = list(source_path.rglob("*.go"))
    if not go_files:
        logger.info("No Go files found to scan with Gosec")
        return []
    
    logger.info(f"Running Gosec scan on {len(go_files)} Go files")
    
    try:
        cmd = [
            "gosec",
            "-fmt=json",
            "-quiet",
            "-exclude-dir=vendor",
            "-exclude-dir=.git",
            "./..."
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(source_path)
        )
        
        # Gosec outputs JSON to stdout
        if result.stdout:
            try:
                output = json.loads(result.stdout)
                issues = output.get("Issues", [])
                
                for item in issues:
                    # Make path relative
                    file_path = item.get("file", "")
                    try:
                        file_path = str(Path(file_path).relative_to(source_path))
                    except ValueError:
                        pass
                    
                    finding = GosecFinding(
                        rule_id=item.get("rule_id", ""),
                        severity=map_gosec_severity(item.get("severity", "MEDIUM")),
                        confidence=item.get("confidence", "MEDIUM"),
                        file_path=file_path,
                        line=int(item.get("line", 0)),
                        column=int(item.get("column", 0)),
                        message=item.get("details", ""),
                        code=item.get("code", "")[:500],
                        cwe=item.get("cwe", {}).get("id") if item.get("cwe") else None,
                        details=item.get("details", ""),
                    )
                    findings.append(finding)
                
                logger.info(f"Gosec scan found {len(findings)} Go security issues")
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Gosec output: {e}")
        
        if result.stderr and "error" in result.stderr.lower():
            logger.debug(f"Gosec stderr: {result.stderr[:300]}")
            
    except subprocess.TimeoutExpired:
        logger.warning(f"Gosec scan timed out after {timeout} seconds")
    except Exception as e:
        logger.error(f"Gosec scan failed: {e}")
    
    return findings


def summarize_findings(findings: List[GosecFinding]) -> dict:
    """Generate a summary of Gosec findings."""
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_rule": {},
            "cwe_ids": [],
        }
    
    by_severity = {}
    by_rule = {}
    cwe_ids = set()
    
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        if finding.cwe:
            cwe_ids.add(finding.cwe)
    
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:10]),
        "cwe_ids": sorted(list(cwe_ids)),
    }


def run_security_audit(source_root: Path) -> List[GosecFinding]:
    """
    Run a comprehensive security audit with gosec.
    
    This is the main entry point for scan_service.py.
    
    Args:
        source_root: Root directory of the source code
        
    Returns:
        List of GosecFinding objects with security-relevant issues
    """
    return run_gosec_scan(source_root)
