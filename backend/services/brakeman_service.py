"""
Brakeman Security Scanner Service

Brakeman is a static analysis security scanner for Ruby on Rails applications.
It detects:
- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Mass assignment
- Remote code execution
- File access vulnerabilities
- Session manipulation
- Unsafe redirects
- And many more Rails-specific vulnerabilities
"""
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)

# Confidence level mapping
CONFIDENCE_MAP = {
    "High": "high",
    "Medium": "medium", 
    "Weak": "low",
}

# Warning type to severity mapping
WARNING_SEVERITY_MAP = {
    # Critical vulnerabilities
    "SQL Injection": "critical",
    "Command Injection": "critical",
    "Remote Code Execution": "critical",
    "Dangerous Eval": "critical",
    "File Access": "high",
    "Deserialization": "critical",
    
    # High severity
    "Cross-Site Scripting": "high",
    "Cross Site Scripting": "high",
    "Mass Assignment": "high",
    "Authentication": "high",
    "Session Setting": "high",
    "Session Manipulation": "high",
    
    # Medium severity
    "Redirect": "medium",
    "Unscoped Find": "medium",
    "Dynamic Render Path": "medium",
    "Denial of Service": "medium",
    "Header Injection": "medium",
    
    # Low severity
    "Attribute Restriction": "low",
    "Format Validation": "low",
    "Default Routes": "low",
}


def is_brakeman_available() -> bool:
    """Check if brakeman is installed and available."""
    try:
        result = subprocess.run(
            ["brakeman", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug(f"brakeman not available: {e}")
        return False


def is_rails_project(project_path: Path) -> bool:
    """Check if the directory is a Ruby on Rails project."""
    rails_indicators = [
        project_path / "Gemfile",
        project_path / "config" / "application.rb",
        project_path / "config" / "routes.rb",
        project_path / "app" / "controllers",
    ]
    return any(indicator.exists() for indicator in rails_indicators)


def run_security_audit(project_path: Path, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run Brakeman security scan on Ruby/Rails code.
    
    Args:
        project_path: Path to the project directory
        timeout: Maximum time in seconds for the scan
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    
    if not is_brakeman_available():
        logger.warning("brakeman not available, skipping Ruby security scan")
        return findings
    
    # Check if there are Ruby files
    ruby_files = list(project_path.rglob("*.rb")) + list(project_path.rglob("*.erb"))
    if not ruby_files:
        logger.debug("No Ruby files found, skipping brakeman scan")
        return findings
    
    # Brakeman works best on Rails projects, but can scan plain Ruby too
    is_rails = is_rails_project(project_path)
    
    logger.info(f"Running brakeman on {len(ruby_files)} Ruby files in {project_path} (Rails: {is_rails})")
    
    try:
        # Build command
        cmd = [
            "brakeman",
            "--format", "json",
            "--quiet",  # Suppress progress output
            "--no-pager",
            "--no-exit-on-warn",  # Don't exit with error on warnings
            "--no-exit-on-error",  # Don't exit with error on errors
        ]
        
        # For non-Rails projects, use --force
        if not is_rails:
            cmd.append("--force")
        
        cmd.append(str(project_path))
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(project_path)
        )
        
        # Parse JSON output
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                warnings = data.get("warnings", [])
                
                for warning in warnings:
                    finding = _convert_brakeman_warning(warning, project_path)
                    if finding:
                        findings.append(finding)
                
                # Also include errors as findings
                for error in data.get("errors", []):
                    findings.append({
                        "type": "brakeman-error",
                        "severity": "info",
                        "file_path": error.get("file", "unknown"),
                        "line_number": 1,
                        "summary": f"Brakeman error: {error.get('error', 'Unknown error')}",
                        "details": {"tool": "brakeman", "error": error}
                    })
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse brakeman JSON output: {e}")
        
        logger.info(f"brakeman found {len(findings)} Ruby security issues")
        
    except subprocess.TimeoutExpired:
        logger.warning(f"brakeman timed out after {timeout}s")
    except Exception as e:
        logger.error(f"brakeman scan failed: {e}")
    
    return findings


def _convert_brakeman_warning(warning: Dict[str, Any], project_path: Path) -> Optional[Dict[str, Any]]:
    """Convert a brakeman warning to our standard finding format."""
    try:
        file_path = warning.get("file", "unknown")
        
        # Make path relative to project
        try:
            file_path = str(Path(file_path).relative_to(project_path))
        except ValueError:
            pass
        
        # Get warning type and map to severity
        warning_type = warning.get("warning_type", "Unknown")
        severity = WARNING_SEVERITY_MAP.get(warning_type, "medium")
        
        # Adjust severity based on confidence
        confidence = warning.get("confidence", "Medium")
        if confidence == "Weak" and severity in ("critical", "high"):
            severity = "medium"
        
        # Build description
        message = warning.get("message", "Security vulnerability detected")
        
        # Include code snippet if available
        code = warning.get("code")
        if code:
            message = f"{message} | Code: {code[:100]}"
        
        return {
            "type": f"brakeman-{warning_type.lower().replace(' ', '-')}",
            "severity": severity,
            "file_path": file_path,
            "line_number": warning.get("line", 1),
            "summary": message[:500],
            "details": {
                "tool": "brakeman",
                "warning_type": warning_type,
                "confidence": confidence,
                "fingerprint": warning.get("fingerprint"),
                "link": warning.get("link"),
                "code": code,
                "render_path": warning.get("render_path"),
                "location": warning.get("location"),
                "user_input": warning.get("user_input"),
                "cwe_id": warning.get("cwe_id", []),
            }
        }
    except Exception as e:
        logger.warning(f"Failed to convert brakeman warning: {e}")
        return None
