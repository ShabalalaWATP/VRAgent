"""
Clang-Tidy Security Scanner Service for C/C++ code.

Clang-Tidy is a clang-based C/C++ linter that includes many security-focused
checks from various check families including cert, bugprone, and security.
"""

import subprocess
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import shutil
import os

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ClangTidyFinding:
    """Represents a clang-tidy security finding."""
    check_name: str
    severity: str  # critical, high, medium, low
    file_path: str
    line: int
    column: int
    message: str
    code_snippet: Optional[str] = None
    cwe: Optional[str] = None
    fix_available: bool = False


# Map clang-tidy checks to CWE IDs
CHECK_TO_CWE = {
    # CERT checks
    "cert-dcl50-cpp": "CWE-676",    # Variadic functions
    "cert-env33-c": "CWE-78",       # System() call
    "cert-err34-c": "CWE-252",      # Unchecked return value
    "cert-err52-cpp": "CWE-755",    # setjmp/longjmp
    "cert-err58-cpp": "CWE-705",    # Static object exceptions
    "cert-err60-cpp": "CWE-755",    # Exception copies
    "cert-flp30-c": "CWE-835",      # Floating point loops
    "cert-mem57-cpp": "CWE-401",    # Memory alignment
    "cert-msc30-c": "CWE-330",      # rand() usage
    "cert-msc32-c": "CWE-330",      # srand() seeding
    "cert-msc50-cpp": "CWE-330",    # std::rand()
    "cert-msc51-cpp": "CWE-330",    # Random engine seeding
    "cert-oop57-cpp": "CWE-762",    # memset on non-trivial types
    "cert-str34-c": "CWE-704",      # Signed char to int
    
    # Bugprone checks with security implications
    "bugprone-branch-clone": "CWE-561",
    "bugprone-incorrect-roundings": "CWE-682",
    "bugprone-infinite-loop": "CWE-835",
    "bugprone-integer-division": "CWE-682",
    "bugprone-macro-parentheses": "CWE-783",
    "bugprone-misplaced-operator-in-strlen-in-alloc": "CWE-131",
    "bugprone-misplaced-pointer-arithmetic-in-alloc": "CWE-131",
    "bugprone-misplaced-widening-cast": "CWE-681",
    "bugprone-not-null-terminated-result": "CWE-170",
    "bugprone-signed-char-misuse": "CWE-704",
    "bugprone-sizeof-container": "CWE-467",
    "bugprone-sizeof-expression": "CWE-467",
    "bugprone-string-constructor": "CWE-665",
    "bugprone-string-integer-assignment": "CWE-704",
    "bugprone-string-literal-with-embedded-nul": "CWE-170",
    "bugprone-suspicious-memset-usage": "CWE-687",
    "bugprone-suspicious-missing-comma": "CWE-665",
    "bugprone-suspicious-semicolon": "CWE-670",
    "bugprone-suspicious-string-compare": "CWE-697",
    "bugprone-terminating-continue": "CWE-670",
    "bugprone-undefined-memory-manipulation": "CWE-704",
    "bugprone-unhandled-exception-at-new": "CWE-755",
    "bugprone-unused-raii": "CWE-404",
    "bugprone-unused-return-value": "CWE-252",
    "bugprone-use-after-move": "CWE-416",
    
    # Security-specific checks
    "clang-analyzer-security.FloatLoopCounter": "CWE-835",
    "clang-analyzer-security.insecureAPI.UncheckedReturn": "CWE-252",
    "clang-analyzer-security.insecureAPI.bcmp": "CWE-676",
    "clang-analyzer-security.insecureAPI.bcopy": "CWE-676",
    "clang-analyzer-security.insecureAPI.bzero": "CWE-676",
    "clang-analyzer-security.insecureAPI.getpw": "CWE-676",
    "clang-analyzer-security.insecureAPI.gets": "CWE-120",
    "clang-analyzer-security.insecureAPI.mkstemp": "CWE-377",
    "clang-analyzer-security.insecureAPI.mktemp": "CWE-377",
    "clang-analyzer-security.insecureAPI.rand": "CWE-330",
    "clang-analyzer-security.insecureAPI.strcpy": "CWE-120",
    "clang-analyzer-security.insecureAPI.vfork": "CWE-676",
    
    # Memory safety
    "clang-analyzer-core.NullDereference": "CWE-476",
    "clang-analyzer-core.DivideZero": "CWE-369",
    "clang-analyzer-core.StackAddressEscape": "CWE-562",
    "clang-analyzer-core.UndefinedBinaryOperatorResult": "CWE-758",
    "clang-analyzer-core.uninitialized.ArraySubscript": "CWE-457",
    "clang-analyzer-core.uninitialized.Assign": "CWE-457",
    "clang-analyzer-core.uninitialized.Branch": "CWE-457",
    "clang-analyzer-core.uninitialized.CapturedBlockVariable": "CWE-457",
    "clang-analyzer-core.uninitialized.UndefReturn": "CWE-457",
    
    # Buffer overflows
    "clang-analyzer-core.CallAndMessage": "CWE-476",
    "clang-analyzer-alpha.security.ArrayBound": "CWE-119",
    "clang-analyzer-alpha.security.ArrayBoundV2": "CWE-119",
    "clang-analyzer-alpha.security.MallocOverflow": "CWE-190",
    "clang-analyzer-alpha.security.ReturnPtrRange": "CWE-119",
    "clang-analyzer-alpha.security.taint.TaintPropagation": "CWE-20",
    
    # Format string
    "clang-analyzer-security.insecureAPI.printf": "CWE-134",
    
    # Misc security
    "misc-non-private-member-variables-in-classes": "CWE-767",
    "misc-redundant-expression": "CWE-561",
    "misc-static-assert": "CWE-617",
}


# Checks to severity mapping
CHECK_SEVERITY = {
    # Critical - Remote code execution, memory corruption
    "clang-analyzer-security.insecureAPI.gets": "critical",
    "clang-analyzer-security.insecureAPI.strcpy": "critical",
    "clang-analyzer-alpha.security.ArrayBound": "critical",
    "clang-analyzer-alpha.security.ArrayBoundV2": "critical",
    "clang-analyzer-alpha.security.MallocOverflow": "critical",
    "cert-env33-c": "critical",  # system() call
    "bugprone-use-after-move": "critical",
    
    # High - Memory safety, injection
    "clang-analyzer-core.NullDereference": "high",
    "clang-analyzer-core.StackAddressEscape": "high",
    "clang-analyzer-security.insecureAPI.printf": "high",
    "clang-analyzer-alpha.security.taint.TaintPropagation": "high",
    
    # Medium - Various bugs and weak practices
    "cert-msc30-c": "medium",
    "cert-msc32-c": "medium",
    "cert-msc50-cpp": "medium",
    "cert-msc51-cpp": "medium",
    "clang-analyzer-security.insecureAPI.rand": "medium",
}


def is_clangtidy_available() -> bool:
    """Check if clang-tidy is installed and available."""
    return shutil.which("clang-tidy") is not None


def _get_severity(check_name: str) -> str:
    """Get severity for a clang-tidy check."""
    # Check exact match first
    if check_name in CHECK_SEVERITY:
        return CHECK_SEVERITY[check_name]
    
    # Check prefix matches
    for check, severity in CHECK_SEVERITY.items():
        if check_name.startswith(check.rsplit(".", 1)[0]):
            return severity
    
    # Default severity based on check family
    if check_name.startswith("clang-analyzer-security"):
        return "high"
    elif check_name.startswith("clang-analyzer-alpha.security"):
        return "high"
    elif check_name.startswith("clang-analyzer-core"):
        return "high"
    elif check_name.startswith("cert-"):
        return "medium"
    elif check_name.startswith("bugprone-"):
        return "medium"
    else:
        return "low"


def _get_cwe(check_name: str) -> Optional[str]:
    """Get CWE ID for a clang-tidy check."""
    if check_name in CHECK_TO_CWE:
        return CHECK_TO_CWE[check_name]
    
    # Try partial matches
    for check, cwe in CHECK_TO_CWE.items():
        if check_name.startswith(check):
            return cwe
    
    return None


def _has_c_cpp_source(source_root: Path) -> bool:
    """Check if there are any C/C++ source files."""
    patterns = ["**/*.c", "**/*.cpp", "**/*.cc", "**/*.cxx", "**/*.h", "**/*.hpp", "**/*.hxx"]
    for pattern in patterns:
        if any(source_root.glob(pattern)):
            return True
    return False


def _find_c_cpp_files(source_root: Path) -> List[Path]:
    """Find all C/C++ source files."""
    files = []
    patterns = ["**/*.c", "**/*.cpp", "**/*.cc", "**/*.cxx"]
    
    for pattern in patterns:
        files.extend(source_root.glob(pattern))
    
    # Filter out common non-project directories
    exclude_dirs = {"node_modules", ".git", "vendor", "third_party", "build", "cmake-build"}
    
    filtered = []
    for f in files:
        if not any(excluded in f.parts for excluded in exclude_dirs):
            filtered.append(f)
    
    return filtered


def run_clangtidy_scan(
    source_root: Path,
    extra_args: Optional[List[str]] = None,
) -> List[ClangTidyFinding]:
    """
    Run clang-tidy security scan on C/C++ files.
    
    Args:
        source_root: Root directory of the source code
        extra_args: Additional arguments to pass to clang-tidy
        
    Returns:
        List of ClangTidyFinding objects
    """
    if not is_clangtidy_available():
        logger.warning("clang-tidy is not available")
        return []
    
    if not _has_c_cpp_source(source_root):
        logger.debug("No C/C++ source files found, skipping clang-tidy scan")
        return []
    
    findings = []
    c_cpp_files = _find_c_cpp_files(source_root)
    
    if not c_cpp_files:
        logger.debug("No C/C++ files found after filtering")
        return []
    
    logger.info(f"Running clang-tidy on {len(c_cpp_files)} C/C++ files")
    
    # Security-focused checks to enable
    security_checks = [
        "cert-*",
        "bugprone-*",
        "clang-analyzer-security.*",
        "clang-analyzer-core.*",
        "clang-analyzer-alpha.security.*",
        "misc-non-private-member-variables-in-classes",
        "misc-redundant-expression",
    ]
    
    checks_arg = f"-checks=-*,{','.join(security_checks)}"
    
    # Process files in batches to avoid command line length limits
    batch_size = 50
    
    for i in range(0, len(c_cpp_files), batch_size):
        batch = c_cpp_files[i:i + batch_size]
        
        cmd = [
            "clang-tidy",
            checks_arg,
            "-header-filter=.*",  # Check headers too
        ]
        
        if extra_args:
            cmd.extend(extra_args)
        
        # Add files
        cmd.extend([str(f) for f in batch])
        
        # Add -- to separate clang-tidy args from compiler args
        cmd.append("--")
        
        # Add basic compiler flags
        cmd.extend([
            "-std=c++17",  # Use modern C++ by default
            f"-I{source_root}",  # Include source root
        ])
        
        logger.debug(f"Running clang-tidy batch {i // batch_size + 1}: {len(batch)} files")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout per batch
                cwd=str(source_root),
            )
            
            # Parse output
            batch_findings = _parse_clangtidy_output(result.stdout + result.stderr, source_root)
            findings.extend(batch_findings)
            
        except subprocess.TimeoutExpired:
            logger.warning(f"clang-tidy batch timed out after 5 minutes")
        except Exception as e:
            logger.error(f"clang-tidy batch failed: {e}")
    
    # Deduplicate findings
    unique_findings = []
    seen = set()
    
    for f in findings:
        key = (f.check_name, f.file_path, f.line, f.message)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    
    logger.info(f"Found {len(unique_findings)} clang-tidy findings")
    return unique_findings


def _parse_clangtidy_output(output: str, source_root: Path) -> List[ClangTidyFinding]:
    """Parse clang-tidy text output."""
    findings = []
    
    # Pattern: file:line:column: level: message [check-name]
    pattern = re.compile(
        r'^(.+?):(\d+):(\d+): (warning|error|note): (.+?) \[([^\]]+)\]$',
        re.MULTILINE
    )
    
    for match in pattern.finditer(output):
        file_path = match.group(1)
        line = int(match.group(2))
        column = int(match.group(3))
        level = match.group(4)
        message = match.group(5)
        check_name = match.group(6)
        
        # Skip notes (they're associated with warnings)
        if level == "note":
            continue
        
        # Make path relative if possible
        try:
            rel_path = str(Path(file_path).relative_to(source_root))
        except ValueError:
            rel_path = file_path
        
        severity = _get_severity(check_name)
        cwe = _get_cwe(check_name)
        
        findings.append(ClangTidyFinding(
            check_name=check_name,
            severity=severity,
            file_path=rel_path,
            line=line,
            column=column,
            message=message,
            cwe=cwe,
        ))
    
    return findings


def run_security_audit(source_root: Path) -> List[ClangTidyFinding]:
    """
    Run a comprehensive security audit with clang-tidy.
    
    This is the main entry point for scan_service.py.
    
    Args:
        source_root: Root directory of the source code
        
    Returns:
        List of ClangTidyFinding objects with security-relevant issues
    """
    return run_clangtidy_scan(source_root)
