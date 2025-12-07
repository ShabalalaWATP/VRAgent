"""
Reachability Analysis Service

Analyzes whether vulnerable dependency functions are actually called in the codebase.
This helps reduce false positives from vulnerabilities in unused code paths.

Analysis Strategy:
1. Import Analysis - Check if vulnerable packages are imported
2. Function Call Analysis - Check if specific vulnerable functions are called
3. Known Vulnerable Function Mapping - Map CVEs to specific functions
4. Static Import Graph - Build import graph to trace usage

This provides:
- is_reachable: Whether the vulnerable code is actually used
- reachability_confidence: Confidence level (high/medium/low)
- usage_locations: Where the vulnerable package is used
- import_chain: How the package is imported
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

from backend.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ImportInfo:
    """Information about an import statement."""
    module: str
    alias: Optional[str] = None
    from_import: bool = False
    imported_names: List[str] = field(default_factory=list)
    file_path: str = ""
    line_number: int = 0


@dataclass
class UsageLocation:
    """Location where a package/function is used."""
    file_path: str
    line_number: int
    usage_type: str  # "import", "call", "attribute"
    code_snippet: str = ""
    context: str = ""  # function/class name containing the usage


@dataclass
class ReachabilityResult:
    """Result of reachability analysis for a vulnerability."""
    vulnerability_id: str
    package_name: str
    is_reachable: bool
    confidence: str  # "high", "medium", "low"
    reason: str
    # Locations where the package is imported
    import_locations: List[UsageLocation] = field(default_factory=list)
    # Locations where vulnerable functions are called
    call_locations: List[UsageLocation] = field(default_factory=list)
    # Whether specific vulnerable functions are called (if known)
    vulnerable_functions_called: List[str] = field(default_factory=list)
    # Suggested action
    recommendation: str = ""


# Known vulnerable functions by CVE/package
# Maps (package_name, cve_pattern) -> list of vulnerable functions
KNOWN_VULNERABLE_FUNCTIONS: Dict[Tuple[str, str], List[str]] = {
    # Log4j
    ("log4j", "CVE-2021-44228"): ["lookup", "log", "error", "warn", "info", "debug", "trace", "fatal"],
    ("log4j-core", "CVE-2021-44228"): ["lookup", "log", "error", "warn", "info", "debug", "trace", "fatal"],
    
    # Python requests
    ("requests", "CVE-2023"): ["get", "post", "put", "delete", "request", "Session"],
    
    # Python urllib3
    ("urllib3", "CVE"): ["request", "urlopen", "HTTPConnectionPool", "HTTPSConnectionPool"],
    
    # Python PyYAML
    ("pyyaml", "CVE"): ["load", "unsafe_load", "full_load"],
    ("yaml", "CVE"): ["load", "unsafe_load", "full_load"],
    
    # Python pickle
    ("pickle", "CVE"): ["load", "loads", "Unpickler"],
    
    # Python cryptography
    ("cryptography", "CVE"): ["load_pem_private_key", "load_der_private_key"],
    
    # Node.js lodash
    ("lodash", "CVE-2020"): ["template", "merge", "mergeWith", "defaultsDeep", "set", "setWith"],
    ("lodash", "CVE-2019"): ["template", "merge", "mergeWith", "defaultsDeep", "set", "setWith"],
    
    # Node.js express
    ("express", "CVE"): ["render", "sendFile", "redirect"],
    
    # Node.js axios
    ("axios", "CVE"): ["get", "post", "request", "create"],
    
    # Java Spring
    ("spring-core", "CVE"): ["getBean", "createBean", "registerBean"],
    ("spring-web", "CVE"): ["forward", "redirect", "render"],
    
    # Java Jackson
    ("jackson-databind", "CVE"): ["readValue", "readTree", "convertValue", "ObjectMapper"],
    
    # Go yaml
    ("gopkg.in/yaml", "CVE"): ["Unmarshal", "UnmarshalStrict", "Decoder.Decode"],
    
    # Ruby
    ("nokogiri", "CVE"): ["parse", "XML", "HTML", "Nokogiri::XML", "Nokogiri::HTML"],
    ("rails", "CVE"): ["render", "redirect_to", "send_file"],
}

# Package name normalization (different ecosystems may use different names)
PACKAGE_ALIASES: Dict[str, Set[str]] = {
    "pyyaml": {"yaml", "pyyaml"},
    "pillow": {"pil", "pillow", "PIL"},
    "beautifulsoup4": {"bs4", "beautifulsoup", "beautifulsoup4"},
    "python-dateutil": {"dateutil", "python-dateutil"},
    "scikit-learn": {"sklearn", "scikit-learn"},
    "opencv-python": {"cv2", "opencv"},
    "tensorflow": {"tf", "tensorflow"},
    "pytorch": {"torch", "pytorch"},
}


def _normalize_package_name(name: str) -> Set[str]:
    """Get all possible import names for a package."""
    name_lower = name.lower().replace("-", "_").replace(".", "_")
    
    # Check aliases
    for canonical, aliases in PACKAGE_ALIASES.items():
        if name_lower in {a.lower() for a in aliases} or name_lower == canonical:
            return aliases
    
    # Return variations
    return {
        name_lower,
        name_lower.replace("_", "-"),
        name.lower(),
        name,
    }


class PythonImportVisitor(ast.NodeVisitor):
    """AST visitor to extract Python imports and function calls."""
    
    def __init__(self, target_packages: Set[str]):
        self.target_packages = {p.lower() for p in target_packages}
        self.imports: List[ImportInfo] = []
        self.calls: List[Tuple[str, int, str]] = []  # (name, line, context)
        self.current_context = ""
    
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            module_parts = alias.name.split(".")
            if module_parts[0].lower() in self.target_packages:
                self.imports.append(ImportInfo(
                    module=alias.name,
                    alias=alias.asname,
                    from_import=False,
                    line_number=node.lineno,
                ))
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            module_parts = node.module.split(".")
            if module_parts[0].lower() in self.target_packages:
                imported_names = [alias.name for alias in node.names]
                self.imports.append(ImportInfo(
                    module=node.module,
                    from_import=True,
                    imported_names=imported_names,
                    line_number=node.lineno,
                ))
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        old_context = self.current_context
        self.current_context = node.name
        self.generic_visit(node)
        self.current_context = old_context
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        old_context = self.current_context
        self.current_context = node.name
        self.generic_visit(node)
        self.current_context = old_context
    
    def visit_ClassDef(self, node: ast.ClassDef):
        old_context = self.current_context
        self.current_context = node.name
        self.generic_visit(node)
        self.current_context = old_context
    
    def visit_Call(self, node: ast.Call):
        # Extract function name
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            name = ".".join(reversed(parts))
        
        if name:
            self.calls.append((name, node.lineno, self.current_context))
        
        self.generic_visit(node)


def analyze_python_file(
    file_path: Path,
    target_packages: Set[str]
) -> Tuple[List[ImportInfo], List[Tuple[str, int, str]]]:
    """
    Analyze a Python file for imports and calls related to target packages.
    """
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(content)
        
        visitor = PythonImportVisitor(target_packages)
        visitor.visit(tree)
        
        # Update file paths
        for imp in visitor.imports:
            imp.file_path = str(file_path)
        
        return visitor.imports, visitor.calls
        
    except SyntaxError as e:
        logger.debug(f"Syntax error parsing {file_path}: {e}")
        return [], []
    except Exception as e:
        logger.debug(f"Error analyzing {file_path}: {e}")
        return [], []


def analyze_javascript_file(
    file_path: Path,
    target_packages: Set[str]
) -> Tuple[List[ImportInfo], List[Tuple[str, int, str]]]:
    """
    Analyze a JavaScript/TypeScript file for imports and requires.
    Uses regex-based parsing (faster than full AST for this purpose).
    """
    imports: List[ImportInfo] = []
    calls: List[Tuple[str, int, str]] = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.splitlines()
        
        target_lower = {p.lower() for p in target_packages}
        
        for line_num, line in enumerate(lines, 1):
            # ES6 imports: import x from 'package'
            import_match = re.search(
                r'''import\s+(?:(\w+)|(?:\{([^}]+)\})|(?:\*\s+as\s+(\w+)))\s+from\s+['"]([^'"]+)['"]''',
                line
            )
            if import_match:
                package = import_match.group(4).split("/")[0]
                if package.lower() in target_lower:
                    imports.append(ImportInfo(
                        module=package,
                        alias=import_match.group(1) or import_match.group(3),
                        from_import=True,
                        imported_names=import_match.group(2).split(",") if import_match.group(2) else [],
                        file_path=str(file_path),
                        line_number=line_num,
                    ))
            
            # CommonJS require: const x = require('package')
            require_match = re.search(
                r'''(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)''',
                line
            )
            if require_match:
                package = require_match.group(2).split("/")[0]
                if package.lower() in target_lower:
                    imports.append(ImportInfo(
                        module=package,
                        alias=require_match.group(1),
                        from_import=False,
                        file_path=str(file_path),
                        line_number=line_num,
                    ))
            
            # Function calls on imported packages
            for pkg in target_packages:
                if pkg.lower() in line.lower():
                    # Look for method calls
                    call_match = re.search(rf'\b{re.escape(pkg)}\.(\w+)\s*\(', line, re.IGNORECASE)
                    if call_match:
                        calls.append((f"{pkg}.{call_match.group(1)}", line_num, ""))
        
        return imports, calls
        
    except Exception as e:
        logger.debug(f"Error analyzing {file_path}: {e}")
        return [], []


def analyze_java_file(
    file_path: Path,
    target_packages: Set[str]
) -> Tuple[List[ImportInfo], List[Tuple[str, int, str]]]:
    """
    Analyze a Java file for imports.
    Uses regex-based parsing.
    """
    imports: List[ImportInfo] = []
    calls: List[Tuple[str, int, str]] = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        lines = content.splitlines()
        
        target_lower = {p.lower() for p in target_packages}
        
        for line_num, line in enumerate(lines, 1):
            # Java imports: import org.package.Class;
            import_match = re.match(r'^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.]+);', line)
            if import_match:
                full_import = import_match.group(1)
                parts = full_import.split(".")
                
                # Check if any part matches target packages
                for i, part in enumerate(parts):
                    if part.lower() in target_lower:
                        imports.append(ImportInfo(
                            module=".".join(parts[:i+1]),
                            from_import=True,
                            imported_names=[parts[-1]],
                            file_path=str(file_path),
                            line_number=line_num,
                        ))
                        break
        
        return imports, calls
        
    except Exception as e:
        logger.debug(f"Error analyzing {file_path}: {e}")
        return [], []


def analyze_go_file(
    file_path: Path,
    target_packages: Set[str]
) -> Tuple[List[ImportInfo], List[Tuple[str, int, str]]]:
    """
    Analyze a Go file for imports.
    """
    imports: List[ImportInfo] = []
    calls: List[Tuple[str, int, str]] = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        target_lower = {p.lower() for p in target_packages}
        
        # Find import block
        import_match = re.search(r'import\s*\((.*?)\)', content, re.DOTALL)
        if import_match:
            import_block = import_match.group(1)
            for line in import_block.splitlines():
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                
                # Parse import line: [alias] "package/path"
                pkg_match = re.match(r'(?:(\w+)\s+)?"([^"]+)"', line)
                if pkg_match:
                    alias = pkg_match.group(1)
                    package = pkg_match.group(2)
                    
                    # Check if package matches targets
                    pkg_parts = package.split("/")
                    for part in pkg_parts:
                        if part.lower() in target_lower:
                            imports.append(ImportInfo(
                                module=package,
                                alias=alias,
                                from_import=True,
                                file_path=str(file_path),
                                line_number=0,
                            ))
                            break
        
        # Single imports
        for match in re.finditer(r'import\s+"([^"]+)"', content):
            package = match.group(1)
            pkg_parts = package.split("/")
            for part in pkg_parts:
                if part.lower() in target_lower:
                    imports.append(ImportInfo(
                        module=package,
                        from_import=True,
                        file_path=str(file_path),
                        line_number=0,
                    ))
                    break
        
        return imports, calls
        
    except Exception as e:
        logger.debug(f"Error analyzing {file_path}: {e}")
        return [], []


def analyze_codebase_for_package(
    source_root: Path,
    package_name: str,
    ecosystem: str = "auto"
) -> Tuple[List[ImportInfo], List[Tuple[str, int, str]]]:
    """
    Analyze entire codebase for usage of a specific package.
    """
    all_imports: List[ImportInfo] = []
    all_calls: List[Tuple[str, int, str]] = []
    
    # Get all possible names for this package
    package_names = _normalize_package_name(package_name)
    
    # Determine which file types to analyze
    file_patterns = []
    if ecosystem in ("auto", "PyPI", "pip"):
        file_patterns.extend(["*.py"])
    if ecosystem in ("auto", "npm"):
        file_patterns.extend(["*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs"])
    if ecosystem in ("auto", "Maven"):
        file_patterns.extend(["*.java", "*.kt", "*.scala"])
    if ecosystem in ("auto", "Go"):
        file_patterns.extend(["*.go"])
    
    # Analyze files
    for pattern in file_patterns:
        for file_path in source_root.rglob(pattern):
            # Skip common non-source directories
            path_str = str(file_path)
            if any(skip in path_str for skip in [
                "node_modules", "__pycache__", ".git", "vendor",
                "venv", ".venv", "dist", "build", ".tox"
            ]):
                continue
            
            if pattern == "*.py":
                imports, calls = analyze_python_file(file_path, package_names)
            elif pattern in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.mjs"):
                imports, calls = analyze_javascript_file(file_path, package_names)
            elif pattern in ("*.java", "*.kt", "*.scala"):
                imports, calls = analyze_java_file(file_path, package_names)
            elif pattern == "*.go":
                imports, calls = analyze_go_file(file_path, package_names)
            else:
                continue
            
            all_imports.extend(imports)
            all_calls.extend(calls)
    
    return all_imports, all_calls


def check_vulnerable_function_calls(
    calls: List[Tuple[str, int, str]],
    package_name: str,
    vulnerability_id: str
) -> List[str]:
    """
    Check if any known vulnerable functions are called.
    """
    called_vulnerable = []
    
    # Look up known vulnerable functions
    vulnerable_funcs = set()
    for (pkg, cve_pattern), funcs in KNOWN_VULNERABLE_FUNCTIONS.items():
        if pkg.lower() in package_name.lower():
            if cve_pattern in vulnerability_id or vulnerability_id.startswith(cve_pattern):
                vulnerable_funcs.update(funcs)
    
    if not vulnerable_funcs:
        # No known function mapping, assume all usage is potentially vulnerable
        return ["<unknown - package is used>"]
    
    # Check if any vulnerable functions are called
    for call_name, line_num, context in calls:
        for vfunc in vulnerable_funcs:
            if vfunc.lower() in call_name.lower():
                called_vulnerable.append(f"{vfunc} (line {line_num})")
    
    return called_vulnerable


def analyze_reachability(
    source_root: Path,
    vulnerabilities: List[Any],  # List of Vulnerability models
    dependencies: List[Any] = None  # List of Dependency models
) -> List[ReachabilityResult]:
    """
    Analyze reachability for all vulnerabilities.
    
    Returns a list of ReachabilityResult for each vulnerability.
    """
    results: List[ReachabilityResult] = []
    
    # Build map of dependency names to ecosystem
    dep_ecosystems: Dict[str, str] = {}
    if dependencies:
        for dep in dependencies:
            dep_ecosystems[dep.name.lower()] = dep.ecosystem
    
    # Group vulnerabilities by package to avoid re-analyzing
    package_vulns: Dict[str, List[Any]] = defaultdict(list)
    for vuln in vulnerabilities:
        dep = vuln.dependency if hasattr(vuln, 'dependency') else None
        if dep:
            package_vulns[dep.name.lower()].append(vuln)
    
    # Analyze each package once
    for package_name, vulns in package_vulns.items():
        ecosystem = dep_ecosystems.get(package_name, "auto")
        
        logger.debug(f"Analyzing reachability for {package_name} ({len(vulns)} vulnerabilities)")
        
        # Find imports and calls
        imports, calls = analyze_codebase_for_package(source_root, package_name, ecosystem)
        
        # Convert to usage locations
        import_locations = [
            UsageLocation(
                file_path=imp.file_path,
                line_number=imp.line_number,
                usage_type="import",
                code_snippet=f"import {imp.module}" if not imp.from_import else f"from {imp.module} import ...",
            )
            for imp in imports
        ]
        
        # Determine reachability for each vulnerability
        for vuln in vulns:
            dep = vuln.dependency
            vuln_id = vuln.external_id
            
            # Check for vulnerable function calls
            vulnerable_calls = check_vulnerable_function_calls(calls, package_name, vuln_id)
            
            call_locations = [
                UsageLocation(
                    file_path=str(source_root),  # We don't have exact file in calls
                    line_number=line_num,
                    usage_type="call",
                    code_snippet=call_name,
                    context=context,
                )
                for call_name, line_num, context in calls
            ]
            
            # Determine reachability
            if not imports:
                # Package not imported at all
                is_reachable = False
                confidence = "high"
                reason = "Package is not imported anywhere in the codebase"
                recommendation = "Consider removing unused dependency"
            elif not calls and not vulnerable_calls:
                # Imported but no calls found
                is_reachable = True  # Conservative - imported means potentially used
                confidence = "low"
                reason = "Package is imported but no direct function calls detected"
                recommendation = "Manual review recommended - package may be used indirectly"
            elif vulnerable_calls:
                # Specific vulnerable functions are called
                is_reachable = True
                confidence = "high"
                reason = f"Vulnerable functions called: {', '.join(vulnerable_calls[:5])}"
                recommendation = "Update package to patched version immediately"
            else:
                # Package is used but specific vulnerable functions unknown
                is_reachable = True
                confidence = "medium"
                reason = "Package is imported and used, but specific vulnerable functions not in known mapping"
                recommendation = "Review usage and update package"
            
            result = ReachabilityResult(
                vulnerability_id=vuln_id,
                package_name=package_name,
                is_reachable=is_reachable,
                confidence=confidence,
                reason=reason,
                import_locations=import_locations[:10],  # Limit
                call_locations=call_locations[:10],
                vulnerable_functions_called=vulnerable_calls[:10] if vulnerable_calls else [],
                recommendation=recommendation,
            )
            
            results.append(result)
    
    # Log summary
    reachable_count = sum(1 for r in results if r.is_reachable)
    logger.info(
        f"Reachability analysis complete: {reachable_count}/{len(results)} vulnerabilities "
        f"are in reachable code paths"
    )
    
    return results


def enrich_finding_with_reachability(
    finding: Any,
    reachability: ReachabilityResult
) -> Dict:
    """
    Enrich a finding with reachability analysis results.
    """
    details = dict(finding.details) if finding.details else {}
    
    details["reachability"] = {
        "is_reachable": reachability.is_reachable,
        "confidence": reachability.confidence,
        "reason": reachability.reason,
        "recommendation": reachability.recommendation,
        "import_count": len(reachability.import_locations),
        "call_count": len(reachability.call_locations),
        "vulnerable_functions_called": reachability.vulnerable_functions_called[:5],
    }
    
    # Add sample locations
    if reachability.import_locations:
        details["reachability"]["sample_imports"] = [
            {
                "file": loc.file_path,
                "line": loc.line_number,
                "snippet": loc.code_snippet,
            }
            for loc in reachability.import_locations[:3]
        ]
    
    return details


def get_reachability_summary(results: List[ReachabilityResult]) -> Dict[str, Any]:
    """
    Generate a summary of reachability analysis.
    """
    if not results:
        return {
            "total_analyzed": 0,
            "reachable": 0,
            "not_reachable": 0,
            "high_confidence": 0,
        }
    
    reachable = sum(1 for r in results if r.is_reachable)
    high_confidence = sum(1 for r in results if r.confidence == "high")
    
    return {
        "total_analyzed": len(results),
        "reachable": reachable,
        "not_reachable": len(results) - reachable,
        "reachable_percent": round(reachable / len(results) * 100, 1),
        "high_confidence": high_confidence,
        "medium_confidence": sum(1 for r in results if r.confidence == "medium"),
        "low_confidence": sum(1 for r in results if r.confidence == "low"),
        "unused_packages": [r.package_name for r in results if not r.is_reachable][:10],
    }
