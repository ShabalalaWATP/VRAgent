"""
Semgrep Security Scanning Service

Provides deep static analysis using Semgrep's semantic code analysis engine.
Supports 30+ languages with 2000+ security rules.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SemgrepFinding:
    """Represents a security finding from Semgrep."""
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    column_start: int
    column_end: int
    message: str
    severity: str
    category: str
    code_snippet: str
    cwe: Optional[List[str]] = None
    owasp: Optional[List[str]] = None
    fix: Optional[str] = None


def is_semgrep_available() -> bool:
    """Check if Semgrep CLI is installed and available."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def get_semgrep_version() -> Optional[str]:
    """Get the installed Semgrep version."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def run_semgrep_scan(
    source_path: Path,
    config: str = "auto",
    severity: Optional[List[str]] = None,
    timeout: int = 300
) -> List[SemgrepFinding]:
    """
    Run Semgrep security scan on a codebase.
    
    Args:
        source_path: Path to the source code directory
        config: Semgrep configuration. Options:
            - "auto": Auto-detect and use relevant rulesets
            - "p/security-audit": Comprehensive security rules
            - "p/owasp-top-ten": OWASP Top 10 vulnerabilities
            - "p/cwe-top-25": CWE Top 25 vulnerabilities
            - "p/python": Python-specific rules
            - "p/javascript": JavaScript-specific rules
            - "p/java": Java-specific rules
            - "p/go": Go-specific rules
            - "p/ruby": Ruby-specific rules
            - "p/rust": Rust-specific rules
            - "p/php": PHP-specific rules
            - "p/kotlin": Kotlin-specific rules
            - Path to custom rules file
        severity: Filter by severity levels (e.g., ["ERROR", "WARNING"])
        timeout: Maximum execution time in seconds
        
    Returns:
        List of SemgrepFinding objects
    """
    if not is_semgrep_available():
        logger.warning("Semgrep is not installed. Skipping Semgrep scan.")
        return []
    
    findings: List[SemgrepFinding] = []
    
    try:
        # Build command
        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--config", config,
            "--no-git-ignore",  # Scan all files
            "--metrics", "off",  # Disable telemetry
            "--exclude", "*_test.py",  # Skip test files (reduce FPs)
            "--exclude", "*_test.go",
            "--exclude", "*.test.js",
            "--exclude", "*.test.ts",
            "--exclude", "*.spec.js",
            "--exclude", "*.spec.ts",
            "--exclude", "test_*.py",
            "--exclude", "tests/*",
            "--exclude", "__tests__/*",
            "--exclude", "**/test/**",
            "--exclude", "**/tests/**",
            "--exclude", "**/mock/**",
            "--exclude", "**/mocks/**",
            "--exclude", "**/fixtures/**",
        ]
        
        # Add severity filter if specified
        if severity:
            for sev in severity:
                cmd.extend(["--severity", sev])
        
        # Add source path
        cmd.append(str(source_path))
        
        logger.info(f"Running Semgrep scan on {source_path} with config: {config}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(source_path)
        )
        
        # Parse JSON output
        if result.stdout:
            try:
                output = json.loads(result.stdout)
                results = output.get("results", [])
                
                for item in results:
                    # Extract metadata
                    extra = item.get("extra", {})
                    metadata = extra.get("metadata", {})
                    
                    # Map Semgrep severity to our severity levels
                    semgrep_severity = extra.get("severity", "INFO")
                    severity_map = {
                        "ERROR": "critical",
                        "WARNING": "high",
                        "INFO": "medium",
                    }
                    
                    finding = SemgrepFinding(
                        rule_id=item.get("check_id", "unknown"),
                        file_path=item.get("path", ""),
                        line_start=item.get("start", {}).get("line", 0),
                        line_end=item.get("end", {}).get("line", 0),
                        column_start=item.get("start", {}).get("col", 0),
                        column_end=item.get("end", {}).get("col", 0),
                        message=extra.get("message", ""),
                        severity=severity_map.get(semgrep_severity, "medium"),
                        category=metadata.get("category", "security"),
                        code_snippet=extra.get("lines", ""),
                        cwe=metadata.get("cwe", []),
                        owasp=metadata.get("owasp", []),
                        fix=extra.get("fix", None),
                    )
                    findings.append(finding)
                
                logger.info(f"Semgrep scan found {len(findings)} issues")
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Semgrep output: {e}")
        
        # Log any errors
        if result.stderr:
            # Filter out noise
            for line in result.stderr.splitlines():
                if "error" in line.lower() and "metric" not in line.lower():
                    logger.warning(f"Semgrep: {line}")
                    
    except subprocess.TimeoutExpired:
        logger.warning(f"Semgrep scan timed out after {timeout} seconds")
    except subprocess.SubprocessError as e:
        logger.warning(f"Semgrep scan failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error running Semgrep: {e}")
    
    return findings


def run_security_audit(source_path: Path) -> List[SemgrepFinding]:
    """
    Run a comprehensive security audit using multiple Semgrep rulesets.
    
    This combines several security-focused rulesets for thorough coverage.
    """
    all_findings: List[SemgrepFinding] = []
    seen_keys = set()
    
    # Run with multiple security configs for comprehensive coverage
    configs = [
        # Core security rulesets
        "p/security-audit",      # Comprehensive security rules
        "p/owasp-top-ten",       # OWASP Top 10 vulnerabilities
        "p/cwe-top-25",          # CWE Top 25 most dangerous weaknesses
        "p/secrets",             # Hardcoded secrets detection
        
        # Language-specific security rulesets
        "p/python",              # Python security rules
        "p/javascript",          # JavaScript security rules
        "p/typescript",          # TypeScript security rules
        "p/java",                # Java security rules
        "p/go",                  # Go security rules
        "p/c",                   # C security rules
        "p/php",                 # PHP security rules
        "p/ruby",                # Ruby security rules
        "p/rust",                # Rust security rules
        
        # Framework-specific rulesets
        "p/django",              # Django security
        "p/flask",               # Flask security
        "p/react",               # React security
        "p/nodejs",              # Node.js security
        "p/express",             # Express.js security
        "p/spring",              # Spring Boot security
        
        # Additional security rulesets
        "p/sql-injection",       # SQL injection patterns
        "p/xss",                 # Cross-site scripting
        "p/command-injection",   # Command injection
        "p/insecure-transport",  # Insecure transport (HTTP, no TLS)
        "p/jwt",                 # JWT security issues
        "p/crypto",              # Cryptography issues
        "p/deserialization",     # Insecure deserialization
    ]
    
    for config in configs:
        try:
            findings = run_semgrep_scan(source_path, config=config, timeout=120)
            
            for finding in findings:
                # Deduplicate by file/line/rule
                key = (finding.file_path, finding.line_start, finding.rule_id)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_findings.append(finding)
        except Exception as e:
            # Some rulesets may not exist or fail - continue with others
            logger.debug(f"Semgrep config {config} failed or not found: {e}")
            continue
    
    logger.info(f"Semgrep security audit found {len(all_findings)} total issues across {len(configs)} rulesets")
    return all_findings


def get_severity_priority(severity: str) -> int:
    """Get numeric priority for sorting by severity."""
    priorities = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    return priorities.get(severity.lower(), 4)


def summarize_findings(findings: List[SemgrepFinding]) -> dict:
    """
    Generate a summary of Semgrep findings.
    
    Args:
        findings: List of SemgrepFinding objects
        
    Returns:
        Dictionary with summary statistics
    """
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_category": {},
            "by_rule": {},
            "cwe_coverage": [],
            "owasp_coverage": [],
        }
    
    by_severity = {}
    by_category = {}
    by_rule = {}
    cwe_set = set()
    owasp_set = set()
    
    for finding in findings:
        # Count by severity
        sev = finding.severity
        by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # Count by category
        cat = finding.category
        by_category[cat] = by_category.get(cat, 0) + 1
        
        # Count by rule
        rule = finding.rule_id
        by_rule[rule] = by_rule.get(rule, 0) + 1
        
        # Collect CWE/OWASP
        if finding.cwe:
            cwe_set.update(finding.cwe)
        if finding.owasp:
            owasp_set.update(finding.owasp)
    
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:10]),
        "cwe_coverage": sorted(list(cwe_set)),
        "owasp_coverage": sorted(list(owasp_set)),
    }


def install_semgrep_instructions() -> str:
    """Return instructions for installing Semgrep."""
    return """
To install Semgrep:

# Using pip (recommended)
pip install semgrep

# Using Homebrew (macOS)
brew install semgrep

# Using Docker
docker pull returntocorp/semgrep

For more information: https://semgrep.dev/docs/getting-started/
"""
