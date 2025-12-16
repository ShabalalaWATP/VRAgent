"""
Cargo Audit Security Scanner Service

cargo-audit is a security vulnerability scanner for Rust dependencies.
It checks Cargo.lock against the RustSec Advisory Database.

Also includes basic Rust code scanning patterns for common security issues.
"""
import json
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from backend.core.logging import get_logger

logger = get_logger(__name__)

# Severity mapping from RustSec
SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium", 
    "low": "low",
    "informational": "info",
    "none": "info",
}

# Rust security patterns for code scanning
RUST_SECURITY_PATTERNS = [
    {
        "pattern": r"unsafe\s*\{",
        "type": "rust-unsafe-block",
        "severity": "medium",
        "message": "Unsafe block detected - review for memory safety issues",
    },
    {
        "pattern": r"\.unwrap\(\)",
        "type": "rust-unwrap",
        "severity": "low",
        "message": "Use of .unwrap() may cause panic - consider using ? or .expect() with context",
    },
    {
        "pattern": r"std::mem::transmute",
        "type": "rust-transmute",
        "severity": "high",
        "message": "Use of transmute is extremely unsafe - ensure types are compatible",
    },
    {
        "pattern": r"std::ptr::(read|write)_unaligned",
        "type": "rust-unaligned-access",
        "severity": "medium",
        "message": "Unaligned memory access - may cause undefined behavior on some platforms",
    },
    {
        "pattern": r"#\[no_mangle\]",
        "type": "rust-no-mangle",
        "severity": "low",
        "message": "no_mangle attribute exposes function to C ABI - ensure proper input validation",
    },
    {
        "pattern": r"Command::new\([^)]*\)\.arg\(",
        "type": "rust-command-injection",
        "severity": "high",
        "message": "External command execution - ensure inputs are properly sanitized",
    },
    {
        "pattern": r"std::env::(var|args)",
        "type": "rust-env-access",
        "severity": "low",
        "message": "Environment variable access - validate before use in security-sensitive contexts",
    },
    {
        "pattern": r"include_str!|include_bytes!",
        "type": "rust-include-macro",
        "severity": "info",
        "message": "File inclusion at compile time - ensure no sensitive data is included",
    },
]


def is_cargo_audit_available() -> bool:
    """Check if cargo-audit is installed and available."""
    try:
        result = subprocess.run(
            ["cargo", "audit", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        logger.debug(f"cargo-audit not available: {e}")
        return False


def is_rust_project(project_path: Path) -> bool:
    """Check if the directory is a Rust project."""
    return (project_path / "Cargo.toml").exists()


def run_security_audit(project_path: Path, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run cargo-audit and Rust code security scan.
    
    Args:
        project_path: Path to the project directory
        timeout: Maximum time in seconds for the scan
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    
    # Check for Rust files
    rust_files = list(project_path.rglob("*.rs"))
    if not rust_files:
        logger.debug("No Rust files found, skipping Rust security scan")
        return findings
    
    logger.info(f"Running Rust security scan on {len(rust_files)} files in {project_path}")
    
    # Run cargo audit if it's a Cargo project
    if is_rust_project(project_path) and is_cargo_audit_available():
        audit_findings = _run_cargo_audit(project_path, timeout)
        findings.extend(audit_findings)
    
    # Run pattern-based code scan
    code_findings = _scan_rust_code(project_path, rust_files)
    findings.extend(code_findings)
    
    logger.info(f"Rust security scan found {len(findings)} issues")
    return findings


def _run_cargo_audit(project_path: Path, timeout: int) -> List[Dict[str, Any]]:
    """Run cargo-audit for dependency vulnerabilities."""
    findings = []
    
    try:
        cmd = [
            "cargo", "audit",
            "--json",
            "--file", str(project_path / "Cargo.lock")
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(project_path)
        )
        
        if result.stdout:
            try:
                data = json.loads(result.stdout)
                vulnerabilities = data.get("vulnerabilities", {}).get("list", [])
                
                for vuln in vulnerabilities:
                    finding = _convert_audit_vuln(vuln)
                    if finding:
                        findings.append(finding)
                        
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse cargo-audit output: {e}")
        
        logger.info(f"cargo-audit found {len(findings)} dependency vulnerabilities")
        
    except subprocess.TimeoutExpired:
        logger.warning(f"cargo-audit timed out after {timeout}s")
    except Exception as e:
        logger.error(f"cargo-audit failed: {e}")
    
    return findings


def _convert_audit_vuln(vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a cargo-audit vulnerability to our standard format."""
    try:
        advisory = vuln.get("advisory", {})
        package = vuln.get("package", {})
        
        severity = SEVERITY_MAP.get(
            (advisory.get("severity") or "medium").lower(),
            "medium"
        )
        
        cve = advisory.get("id", "UNKNOWN")
        package_name = package.get("name", "unknown")
        package_version = package.get("version", "unknown")
        
        title = advisory.get("title", "Dependency vulnerability")
        description = advisory.get("description", "")
        
        summary = f"{package_name}@{package_version}: {title}"
        if len(summary) > 400:
            summary = summary[:397] + "..."
        
        return {
            "type": f"cargo-audit-{cve.lower()}",
            "severity": severity,
            "file_path": "Cargo.lock",
            "line_number": 1,
            "summary": summary,
            "details": {
                "tool": "cargo-audit",
                "advisory_id": cve,
                "package": package_name,
                "version": package_version,
                "patched_versions": advisory.get("patched_versions", []),
                "unaffected_versions": advisory.get("unaffected_versions", []),
                "url": advisory.get("url"),
                "categories": advisory.get("categories", []),
                "keywords": advisory.get("keywords", []),
                "description": description[:1000] if description else None,
            }
        }
    except Exception as e:
        logger.warning(f"Failed to convert cargo-audit vulnerability: {e}")
        return None


def _scan_rust_code(project_path: Path, rust_files: List[Path]) -> List[Dict[str, Any]]:
    """Scan Rust source files for security patterns."""
    findings = []
    
    for file_path in rust_files:
        try:
            # Skip test files
            if "test" in str(file_path).lower():
                continue
            
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            rel_path = str(file_path.relative_to(project_path))
            
            for pattern_info in RUST_SECURITY_PATTERNS:
                pattern = pattern_info["pattern"]
                
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        # Skip if in a comment
                        stripped = line.strip()
                        if stripped.startswith("//") or stripped.startswith("/*"):
                            continue
                        
                        findings.append({
                            "type": pattern_info["type"],
                            "severity": pattern_info["severity"],
                            "file_path": rel_path,
                            "line_number": i,
                            "summary": f"{pattern_info['message']} at line {i}",
                            "details": {
                                "tool": "rust-pattern-scanner",
                                "pattern": pattern,
                                "line_content": line.strip()[:200],
                            }
                        })
                        
        except Exception as e:
            logger.warning(f"Failed to scan {file_path}: {e}")
    
    return findings
