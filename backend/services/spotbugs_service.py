"""
SpotBugs Security Scanner Service for Java code.

SpotBugs is a static analysis tool that finds bugs in Java programs,
including security vulnerabilities using the Find Security Bugs plugin.
"""

import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import shutil
import os

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class SpotBugsFinding:
    """Represents a SpotBugs security finding."""
    bug_type: str
    category: str
    priority: int  # 1=High, 2=Medium, 3=Low
    severity: str  # Mapped from priority
    file_path: str
    line: int
    class_name: str
    method_name: Optional[str]
    message: str
    cwe: Optional[str] = None


# SpotBugs bug patterns to CWE mapping (Find Security Bugs patterns)
BUG_TYPE_TO_CWE = {
    # SQL Injection
    "SQL_INJECTION": "CWE-89",
    "SQL_INJECTION_HIBERNATE": "CWE-89",
    "SQL_INJECTION_JPA": "CWE-89",
    "SQL_INJECTION_JDO": "CWE-89",
    "SQL_INJECTION_JDBC": "CWE-89",
    "SQL_INJECTION_SPRING_JDBC": "CWE-89",
    "SQL_INJECTION_TURBINE": "CWE-89",
    
    # Command Injection
    "COMMAND_INJECTION": "CWE-78",
    "COMMAND_INJECTION_PROCESS_BUILDER": "CWE-78",
    
    # Path Traversal
    "PATH_TRAVERSAL_IN": "CWE-22",
    "PATH_TRAVERSAL_OUT": "CWE-22",
    "SCALA_PATH_TRAVERSAL_IN": "CWE-22",
    
    # XSS
    "XSS_REQUEST_WRAPPER": "CWE-79",
    "XSS_SERVLET": "CWE-79",
    "XSS_JSP_PRINT": "CWE-79",
    "XSS_REQUEST_PARAMETER_TO_SEND_ERROR": "CWE-79",
    "XSS_REQUEST_PARAMETER_TO_JSP_WRITER": "CWE-79",
    
    # XXE
    "XXE_XMLSTREAMREADER": "CWE-611",
    "XXE_SAXPARSER": "CWE-611",
    "XXE_XMLREADER": "CWE-611",
    "XXE_DOCUMENT": "CWE-611",
    "XXE_XPATHEXPR": "CWE-611",
    
    # LDAP Injection
    "LDAP_INJECTION": "CWE-90",
    
    # Cryptography issues
    "WEAK_TRUST_MANAGER": "CWE-295",
    "WEAK_HOSTNAME_VERIFIER": "CWE-295",
    "WEAK_MESSAGE_DIGEST_MD5": "CWE-327",
    "WEAK_MESSAGE_DIGEST_SHA1": "CWE-327",
    "CUSTOM_MESSAGE_DIGEST": "CWE-327",
    "HAZELCAST_SYMMETRIC_ENCRYPTION": "CWE-327",
    "NULL_CIPHER": "CWE-327",
    "UNENCRYPTED_SOCKET": "CWE-319",
    "DES_USAGE": "CWE-327",
    "TDES_USAGE": "CWE-327",
    "RSA_NO_PADDING": "CWE-780",
    "RSA_KEY_SIZE": "CWE-326",
    "BLOWFISH_KEY_SIZE": "CWE-326",
    "STATIC_IV": "CWE-329",
    "ECB_MODE": "CWE-327",
    "PADDING_ORACLE": "CWE-327",
    
    # Hardcoded credentials
    "HARD_CODE_PASSWORD": "CWE-259",
    "HARD_CODE_KEY": "CWE-321",
    
    # Insecure random
    "PREDICTABLE_RANDOM": "CWE-330",
    "PREDICTABLE_RANDOM_SCALA": "CWE-330",
    
    # Deserialization
    "OBJECT_DESERIALIZATION": "CWE-502",
    "JACKSON_UNSAFE_DESERIALIZATION": "CWE-502",
    
    # SSRF
    "URLCONNECTION_SSRF_FD": "CWE-918",
    
    # Open redirect
    "UNVALIDATED_REDIRECT": "CWE-601",
    
    # Expression Language Injection
    "EL_INJECTION": "CWE-917",
    "SEAM_LOG_INJECTION": "CWE-117",
    "OGNL_INJECTION": "CWE-917",
    "SPEL_INJECTION": "CWE-917",
    
    # Template injection
    "TEMPLATE_INJECTION_VELOCITY": "CWE-94",
    "TEMPLATE_INJECTION_FREEMARKER": "CWE-94",
    "TEMPLATE_INJECTION_PEBBLE": "CWE-94",
    
    # Other
    "HTTP_RESPONSE_SPLITTING": "CWE-113",
    "CRLF_INJECTION_LOGS": "CWE-117",
    "EXTERNAL_CONFIG_CONTROL": "CWE-15",
    "BAD_HEXA_CONVERSION": "CWE-704",
    "ANDROID_EXTERNAL_FILE_ACCESS": "CWE-276",
    "ANDROID_BROADCAST": "CWE-927",
    "ANDROID_WORLD_WRITABLE": "CWE-732",
    "ANDROID_GEOLOCATION": "CWE-200",
    "ANDROID_WEB_VIEW_JAVASCRIPT": "CWE-79",
    "ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE": "CWE-749",
}


def is_spotbugs_available() -> bool:
    """Check if SpotBugs is installed and available."""
    spotbugs_path = shutil.which("spotbugs")
    if spotbugs_path:
        return True
    
    # Check for common installation paths
    common_paths = [
        "/opt/spotbugs/bin/spotbugs",
        "/usr/local/spotbugs/bin/spotbugs",
        "/usr/share/spotbugs/bin/spotbugs",
    ]
    
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return True
    
    return False


def _get_spotbugs_command() -> str:
    """Get the SpotBugs command path."""
    spotbugs_path = shutil.which("spotbugs")
    if spotbugs_path:
        return spotbugs_path
    
    common_paths = [
        "/opt/spotbugs/bin/spotbugs",
        "/usr/local/spotbugs/bin/spotbugs",
        "/usr/share/spotbugs/bin/spotbugs",
    ]
    
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    return "spotbugs"


def _find_java_artifacts(source_root: Path) -> List[Path]:
    """Find Java artifacts (JARs, WARs, class files) for analysis."""
    artifacts = []
    
    # Find compiled artifacts
    for pattern in ["**/*.jar", "**/*.war", "**/*.ear", "**/*.class"]:
        artifacts.extend(source_root.glob(pattern))
    
    # Look for common build output directories
    build_dirs = [
        source_root / "target" / "classes",  # Maven
        source_root / "build" / "classes",   # Gradle
        source_root / "bin",                  # Eclipse
        source_root / "out",                  # IntelliJ
    ]
    
    for build_dir in build_dirs:
        if build_dir.exists():
            artifacts.append(build_dir)
    
    return artifacts


def _has_java_source(source_root: Path) -> bool:
    """Check if there are any Java source files."""
    return any(source_root.glob("**/*.java"))


def _priority_to_severity(priority: int) -> str:
    """Convert SpotBugs priority to severity string."""
    if priority == 1:
        return "critical"
    elif priority == 2:
        return "high"
    else:
        return "medium"


def run_spotbugs_scan(
    source_root: Path,
    include_low_priority: bool = True,
) -> List[SpotBugsFinding]:
    """
    Run SpotBugs security scan on Java artifacts.
    
    Args:
        source_root: Root directory of the source code
        include_low_priority: Include low-priority findings
        
    Returns:
        List of SpotBugsFinding objects
    """
    if not is_spotbugs_available():
        logger.warning("SpotBugs is not available")
        return []
    
    if not _has_java_source(source_root):
        logger.debug("No Java source files found, skipping SpotBugs scan")
        return []
    
    artifacts = _find_java_artifacts(source_root)
    if not artifacts:
        logger.info("No compiled Java artifacts found for SpotBugs analysis. "
                   "Compile the project first (mvn compile, gradle build) for bytecode analysis.")
        return []
    
    findings = []
    spotbugs_cmd = _get_spotbugs_command()
    
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as report_file:
        report_path = report_file.name
    
    try:
        # Build the command
        cmd = [
            spotbugs_cmd,
            "-textui",           # Text-based UI
            "-xml:withMessages", # XML output with human-readable messages
            "-output", report_path,
            "-effort:max",       # Maximum analysis effort
            "-low" if include_low_priority else "-medium",  # Report threshold
        ]
        
        # Add security-focused detectors if Find Security Bugs plugin is available
        cmd.extend([
            "-pluginList", "/opt/spotbugs/plugin/findsecbugs-plugin.jar",
        ])
        
        # Add source directories for better reporting
        cmd.extend(["-sourcepath", str(source_root)])
        
        # Add artifacts to analyze
        for artifact in artifacts:
            cmd.append(str(artifact))
        
        logger.debug(f"Running SpotBugs: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            cwd=str(source_root),
        )
        
        # SpotBugs returns non-zero if bugs found, which is expected
        if result.returncode not in (0, 1) and "Error" in result.stderr:
            logger.warning(f"SpotBugs warning: {result.stderr[:500]}")
        
        # Parse the XML report
        if Path(report_path).exists():
            findings = _parse_spotbugs_xml(report_path)
        
    except subprocess.TimeoutExpired:
        logger.error("SpotBugs scan timed out after 10 minutes")
    except FileNotFoundError:
        logger.error("SpotBugs executable not found")
    except Exception as e:
        logger.error(f"SpotBugs scan failed: {e}")
    finally:
        # Clean up report file
        try:
            Path(report_path).unlink(missing_ok=True)
        except Exception:
            pass
    
    return findings


def _parse_spotbugs_xml(report_path: str) -> List[SpotBugsFinding]:
    """Parse SpotBugs XML report."""
    findings = []
    
    try:
        tree = ET.parse(report_path)
        root = tree.getroot()
        
        for bug in root.findall(".//BugInstance"):
            bug_type = bug.get("type", "UNKNOWN")
            category = bug.get("category", "UNKNOWN")
            priority = int(bug.get("priority", "3"))
            
            # Get source location
            source_line = bug.find("SourceLine")
            if source_line is not None:
                file_path = source_line.get("sourcepath", "")
                class_name = source_line.get("classname", "")
                line = int(source_line.get("start", "0"))
            else:
                file_path = ""
                class_name = bug.find("Class").get("classname", "") if bug.find("Class") is not None else ""
                line = 0
            
            # Get method info
            method = bug.find("Method")
            method_name = method.get("name", "") if method is not None else None
            
            # Get long message
            long_message = bug.find("LongMessage")
            message = long_message.text if long_message is not None else bug_type
            
            # Get CWE if available
            cwe = BUG_TYPE_TO_CWE.get(bug_type)
            
            findings.append(SpotBugsFinding(
                bug_type=bug_type,
                category=category,
                priority=priority,
                severity=_priority_to_severity(priority),
                file_path=file_path,
                line=line,
                class_name=class_name,
                method_name=method_name,
                message=message,
                cwe=cwe,
            ))
        
        logger.info(f"Parsed {len(findings)} findings from SpotBugs report")
        
    except ET.ParseError as e:
        logger.error(f"Failed to parse SpotBugs XML report: {e}")
    except Exception as e:
        logger.error(f"Error parsing SpotBugs report: {e}")
    
    return findings


def run_security_audit(source_root: Path) -> List[SpotBugsFinding]:
    """
    Run a comprehensive security audit with SpotBugs.
    
    This is the main entry point for scan_service.py.
    
    Args:
        source_root: Root directory of the source code
        
    Returns:
        List of SpotBugsFinding objects with security-relevant issues
    """
    findings = run_spotbugs_scan(source_root, include_low_priority=True)
    
    # Filter to security-relevant categories
    security_categories = {
        "SECURITY",
        "MALICIOUS_CODE",
        "MT_CORRECTNESS",  # Thread safety can be security-relevant
    }
    
    security_findings = [
        f for f in findings
        if f.category in security_categories or f.bug_type in BUG_TYPE_TO_CWE
    ]
    
    logger.info(f"SpotBugs security audit found {len(security_findings)} security issues "
                f"(out of {len(findings)} total findings)")
    
    return security_findings
