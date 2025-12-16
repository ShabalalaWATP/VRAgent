"""
Cppcheck Security Scanner Service

Cppcheck is a static analysis tool for C/C++ that detects bugs, undefined behavior,
and dangerous coding patterns. It complements clang-tidy with additional checks.

Detects:
- Buffer overflows and bounds checking
- Memory leaks and resource management
- Null pointer dereferences
- Uninitialized variables
- Format string vulnerabilities
- Integer overflows
- Dangerous functions usage
"""
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
import shutil

from backend.core.logging import get_logger

logger = get_logger(__name__)

# Cppcheck severity to our severity mapping
SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "style": "low",
    "performance": "low",
    "portability": "low",
    "information": "info",
}

# Security-relevant CWE mappings for Cppcheck checks
CHECK_TO_CWE = {
    "bufferAccessOutOfBounds": "CWE-119",
    "arrayIndexOutOfBounds": "CWE-119",
    "arrayIndexOutOfBoundsCond": "CWE-119",
    "outOfBounds": "CWE-119",
    "negativeIndex": "CWE-119",
    "pointerOutOfBounds": "CWE-119",
    "pointerOutOfBoundsCond": "CWE-119",
    "stringLiteralWrite": "CWE-119",
    "negativeArraySize": "CWE-119",
    
    "nullPointer": "CWE-476",
    "nullPointerArithmetic": "CWE-476",
    "nullPointerDefaultArg": "CWE-476",
    "nullPointerRedundantCheck": "CWE-476",
    
    "uninitvar": "CWE-457",
    "uninitdata": "CWE-457",
    "uninitMemberVar": "CWE-457",
    "uninitstring": "CWE-457",
    "uninitStructMember": "CWE-457",
    
    "memleak": "CWE-401",
    "resourceLeak": "CWE-404",
    "memleakOnRealloc": "CWE-401",
    "leakNoVarFunctionCall": "CWE-401",
    "leakReturnValNotUsed": "CWE-401",
    "deallocuse": "CWE-416",
    "doubleFree": "CWE-415",
    "autoVariables": "CWE-562",
    "returnAddressOfAutoVariable": "CWE-562",
    "returnLocalVariable": "CWE-562",
    "returnReference": "CWE-562",
    
    "formatString": "CWE-134",
    "wrongPrintfScanfArgNum": "CWE-134",
    "wrongPrintfScanfParameterPositionError": "CWE-134",
    "invalidPrintfArgType_s": "CWE-134",
    "invalidPrintfArgType_n": "CWE-134",
    "invalidPrintfArgType_p": "CWE-134",
    "invalidScanfArgType_s": "CWE-134",
    
    "integerOverflow": "CWE-190",
    "signedIntegerOverflow": "CWE-190",
    "truncateImplicit": "CWE-681",
    "shiftTooManyBits": "CWE-190",
    "shiftNegative": "CWE-190",
    
    "zerodiv": "CWE-369",
    "zerodivcond": "CWE-369",
    "divideSizeof": "CWE-682",
    
    "danglingLifetime": "CWE-416",
    "danglingReference": "CWE-416",
    "danglingTemporaryLifetime": "CWE-416",
    
    "invalidFunctionArg": "CWE-687",
    "invalidFunctionArgBool": "CWE-687",
    "invalidFunctionArgStr": "CWE-687",
    
    "mismatchAllocDealloc": "CWE-762",
    "mismatchSize": "CWE-131",
    "sizeArgumentAsChar": "CWE-467",
    
    "va_start_wrongParameter": "CWE-676",
    "va_end_missing": "CWE-676",
    "obsoleteFunctions": "CWE-676",
    
    "sprintfOverlappingData": "CWE-787",
    "strncatUsage": "CWE-787",
    "terminateStrncpy": "CWE-170",
}

# High-severity security checks that should be escalated
HIGH_SEVERITY_CHECKS = {
    "bufferAccessOutOfBounds",
    "arrayIndexOutOfBounds", 
    "nullPointer",
    "memleak",
    "doubleFree",
    "deallocuse",
    "formatString",
    "integerOverflow",
    "zerodiv",
    "danglingLifetime",
    "sprintfOverlappingData",
}


def is_cppcheck_available() -> bool:
    """Check if cppcheck is installed and available."""
    return shutil.which("cppcheck") is not None


def run_security_audit(project_path: Path, timeout: int = 300) -> List[Dict[str, Any]]:
    """
    Run Cppcheck security scan on C/C++ files.
    
    Args:
        project_path: Path to the project directory
        timeout: Maximum time in seconds for the scan
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    
    if not is_cppcheck_available():
        logger.warning("cppcheck not available, skipping C/C++ security scan")
        return findings
    
    # Check for C/C++ files
    c_files = list(project_path.rglob("*.c")) + list(project_path.rglob("*.h"))
    cpp_files = (list(project_path.rglob("*.cpp")) + list(project_path.rglob("*.cxx")) + 
                 list(project_path.rglob("*.cc")) + list(project_path.rglob("*.hpp")))
    
    all_files = c_files + cpp_files
    if not all_files:
        logger.debug("No C/C++ files found, skipping cppcheck scan")
        return findings
    
    logger.info(f"Running cppcheck on {len(all_files)} C/C++ files in {project_path}")
    
    try:
        # Run cppcheck with security-focused options
        cmd = [
            "cppcheck",
            "--enable=warning,style,performance,portability,information",
            "--inconclusive",  # Enable inconclusive checks for more coverage
            "--xml",
            "--xml-version=2",
            "--suppress=missingIncludeSystem",  # Suppress missing system headers
            "--suppress=unusedFunction",  # Not security relevant
            f"--include={project_path}",
            str(project_path)
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(project_path)
        )
        
        # Cppcheck outputs XML to stderr
        xml_output = result.stderr
        
        if xml_output:
            findings = _parse_cppcheck_xml(xml_output, project_path)
        
        logger.info(f"cppcheck found {len(findings)} C/C++ issues")
        
    except subprocess.TimeoutExpired:
        logger.warning(f"cppcheck timed out after {timeout}s")
    except Exception as e:
        logger.error(f"cppcheck scan failed: {e}")
    
    return findings


def _parse_cppcheck_xml(xml_output: str, project_path: Path) -> List[Dict[str, Any]]:
    """Parse cppcheck XML output."""
    findings = []
    
    try:
        root = ET.fromstring(xml_output)
        
        for error in root.findall(".//error"):
            error_id = error.get("id", "unknown")
            severity_raw = error.get("severity", "warning")
            message = error.get("msg", "")
            verbose = error.get("verbose", message)
            cwe = error.get("cwe")
            
            # Get location info
            location = error.find("location")
            if location is not None:
                file_path = location.get("file", "unknown")
                line_num = int(location.get("line", 1))
            else:
                file_path = "unknown"
                line_num = 1
            
            # Make path relative
            try:
                file_path = str(Path(file_path).relative_to(project_path))
            except ValueError:
                pass
            
            # Map severity
            severity = SEVERITY_MAP.get(severity_raw, "medium")
            
            # Escalate known high-severity checks
            if error_id in HIGH_SEVERITY_CHECKS:
                severity = "high"
            
            # Get CWE if not provided
            if not cwe and error_id in CHECK_TO_CWE:
                cwe = CHECK_TO_CWE[error_id]
            
            findings.append({
                "type": f"cppcheck-{error_id}",
                "severity": severity,
                "file_path": file_path,
                "line_number": line_num,
                "summary": message[:500],
                "details": {
                    "tool": "cppcheck",
                    "check_id": error_id,
                    "verbose": verbose[:1000] if verbose else None,
                    "cwe": cwe,
                    "raw_severity": severity_raw,
                }
            })
            
    except ET.ParseError as e:
        logger.warning(f"Failed to parse cppcheck XML: {e}")
    
    return findings
