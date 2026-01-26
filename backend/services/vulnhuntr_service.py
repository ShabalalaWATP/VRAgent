"""
VulnHuntr Service - LLM-Powered Vulnerability Hunter

Traces user input through call chains to identify remotely exploitable vulnerabilities.
Inspired by Protect AI's VulnHuntr approach.

Key Capabilities:
- Source identification (user input entry points)
- Sink identification (dangerous function calls)
- Call chain tracing across files
- LLM-powered data flow analysis
- Vulnerability classification (XSS, SQLi, LFI, RCE, SSRF, etc.)
"""

import os
import ast
import re
import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)

# Configure Gemini using google-genai SDK
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
        logger.info("VulnHuntr: Gemini API configured successfully")
    except ImportError:
        logger.warning("VulnHuntr: google-genai not installed, LLM analysis disabled")

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class SourcePoint:
    """Represents a user input source point"""
    file_path: str
    line_number: int
    code_snippet: str
    source_type: str  # request_param, form_data, file_upload, env_var, etc.
    variable_name: str
    confidence: float = 1.0
    context: str = ""

@dataclass
class SinkPoint:
    """Represents a dangerous sink point"""
    file_path: str
    line_number: int
    code_snippet: str
    sink_type: str  # sql_query, os_command, eval, file_read, etc.
    function_name: str
    vulnerability_type: str  # SQLi, RCE, LFI, XSS, SSRF, etc.
    severity: str = "high"
    context: str = ""

@dataclass
class CallChainNode:
    """A node in the call chain"""
    file_path: str
    line_number: int
    function_name: str
    code_snippet: str
    data_variable: str
    transformation: str = ""  # How data was transformed

@dataclass
class VulnerabilityFlow:
    """A complete vulnerability flow from source to sink"""
    id: str
    source: SourcePoint
    sink: SinkPoint
    call_chain: List[CallChainNode]
    vulnerability_type: str
    severity: str
    confidence: float
    description: str
    exploit_scenario: str
    remediation: str
    cwe_id: str
    owasp_category: str
    is_exploitable: bool = True
    sanitization_present: bool = False
    sanitization_bypass: Optional[str] = None

@dataclass
class VulnHuntrResult:
    """Complete result from VulnHuntr analysis"""
    project_path: str
    scan_id: str
    timestamp: str
    total_files_scanned: int
    sources_found: int
    sinks_found: int
    vulnerabilities: List[VulnerabilityFlow]
    statistics: Dict[str, Any]
    scan_duration_seconds: float

# ============================================================================
# Source and Sink Patterns
# ============================================================================

# Python sources - where user input enters the application
PYTHON_SOURCES = {
    # Flask/Django request objects
    "request_param": [
        r"request\.args\.get\(['\"](\w+)['\"]\)",
        r"request\.args\[['\"](\w+)['\"]\]",
        r"request\.form\.get\(['\"](\w+)['\"]\)",
        r"request\.form\[['\"](\w+)['\"]\]",
        r"request\.values\.get\(['\"](\w+)['\"]\)",
        r"request\.json\.get\(['\"](\w+)['\"]\)",
        r"request\.json\[['\"](\w+)['\"]\]",
        r"request\.data",
        r"request\.get_json\(\)",
        r"request\.files\.get\(['\"](\w+)['\"]\)",
        r"request\.files\[['\"](\w+)['\"]\]",
        r"request\.headers\.get\(['\"](\w+)['\"]\)",
        r"request\.cookies\.get\(['\"](\w+)['\"]\)",
    ],
    # Django-specific
    "django_request": [
        r"request\.GET\.get\(['\"](\w+)['\"]\)",
        r"request\.GET\[['\"](\w+)['\"]\]",
        r"request\.POST\.get\(['\"](\w+)['\"]\)",
        r"request\.POST\[['\"](\w+)['\"]\]",
        r"request\.body",
        r"request\.META\.get\(['\"](\w+)['\"]\)",
    ],
    # FastAPI
    "fastapi_param": [
        r"(\w+):\s*str\s*=\s*Query\(",
        r"(\w+):\s*str\s*=\s*Path\(",
        r"(\w+):\s*str\s*=\s*Body\(",
        r"(\w+):\s*str\s*=\s*Form\(",
        r"(\w+):\s*str\s*=\s*Header\(",
    ],
    # Standard input
    "user_input": [
        r"input\(['\"].*['\"]\)",
        r"sys\.stdin\.read\(\)",
        r"sys\.argv\[(\d+)\]",
    ],
    # File uploads
    "file_upload": [
        r"\.read\(\)",
        r"\.readline\(\)",
        r"\.readlines\(\)",
    ],
    # Environment variables (can be controlled in some contexts)
    "env_var": [
        r"os\.environ\.get\(['\"](\w+)['\"]\)",
        r"os\.environ\[['\"](\w+)['\"]\]",
        r"os\.getenv\(['\"](\w+)['\"]\)",
    ],
    # URL parameters
    "url_param": [
        r"urlparse\(.*\)\.query",
        r"parse_qs\(.*\)",
        r"parse_qsl\(.*\)",
    ],
}

# Python sinks - dangerous functions that can lead to vulnerabilities
PYTHON_SINKS = {
    # Command Injection (RCE)
    "os_command": {
        "patterns": [
            r"os\.system\((.*)\)",
            r"os\.popen\((.*)\)",
            r"subprocess\.call\((.*)\)",
            r"subprocess\.run\((.*)\)",
            r"subprocess\.Popen\((.*)\)",
            r"commands\.getoutput\((.*)\)",
            r"commands\.getstatusoutput\((.*)\)",
        ],
        "vuln_type": "RCE",
        "cwe": "CWE-78",
        "severity": "critical",
    },
    # Code Injection
    "code_eval": {
        "patterns": [
            r"eval\((.*)\)",
            r"exec\((.*)\)",
            r"compile\((.*)\)",
            r"__import__\((.*)\)",
        ],
        "vuln_type": "RCE",
        "cwe": "CWE-94",
        "severity": "critical",
    },
    # SQL Injection
    "sql_query": {
        "patterns": [
            r"cursor\.execute\((.*)\)",
            r"\.execute\((.*)\)",
            r"\.raw\((.*)\)",
            r"\.extra\((.*)\)",
            r"engine\.execute\((.*)\)",
            r"session\.execute\((.*)\)",
            r"connection\.execute\((.*)\)",
        ],
        "vuln_type": "SQLi",
        "cwe": "CWE-89",
        "severity": "critical",
    },
    # Local File Inclusion / Path Traversal
    "file_read": {
        "patterns": [
            r"open\((.*)\)",
            r"Path\((.*)\)\.read",
            r"pathlib\.Path\((.*)\)",
            r"os\.path\.join\((.*)\)",
            r"shutil\.copy\((.*)\)",
            r"shutil\.move\((.*)\)",
            r"send_file\((.*)\)",
            r"send_from_directory\((.*)\)",
        ],
        "vuln_type": "LFI",
        "cwe": "CWE-22",
        "severity": "high",
    },
    # Server-Side Request Forgery
    "ssrf": {
        "patterns": [
            r"requests\.get\((.*)\)",
            r"requests\.post\((.*)\)",
            r"requests\.request\((.*)\)",
            r"urllib\.request\.urlopen\((.*)\)",
            r"urllib\.urlopen\((.*)\)",
            r"httpx\.get\((.*)\)",
            r"httpx\.post\((.*)\)",
            r"aiohttp\.ClientSession\(\)\.get\((.*)\)",
        ],
        "vuln_type": "SSRF",
        "cwe": "CWE-918",
        "severity": "high",
    },
    # Cross-Site Scripting (reflected in templates)
    "xss": {
        "patterns": [
            r"render_template_string\((.*)\)",
            r"Markup\((.*)\)",
            r"\.format\((.*)\)",
            r"f['\"].*\{.*\}.*['\"]",
            r"Template\((.*)\)\.render\(",
            r"jinja2\.Template\((.*)\)",
        ],
        "vuln_type": "XSS",
        "cwe": "CWE-79",
        "severity": "high",
    },
    # XML External Entity
    "xxe": {
        "patterns": [
            r"xml\.etree\.ElementTree\.parse\((.*)\)",
            r"xml\.etree\.ElementTree\.fromstring\((.*)\)",
            r"lxml\.etree\.parse\((.*)\)",
            r"xml\.dom\.minidom\.parse\((.*)\)",
            r"xml\.sax\.parse\((.*)\)",
        ],
        "vuln_type": "XXE",
        "cwe": "CWE-611",
        "severity": "high",
    },
    # Deserialization
    "deserialization": {
        "patterns": [
            r"pickle\.loads\((.*)\)",
            r"pickle\.load\((.*)\)",
            r"yaml\.load\((.*)\)",
            r"yaml\.unsafe_load\((.*)\)",
            r"marshal\.loads\((.*)\)",
            r"shelve\.open\((.*)\)",
        ],
        "vuln_type": "Insecure Deserialization",
        "cwe": "CWE-502",
        "severity": "critical",
    },
    # LDAP Injection
    "ldap": {
        "patterns": [
            r"ldap\.search_s\((.*)\)",
            r"ldap\.search\((.*)\)",
            r"\.search\(.*filter.*\)",
        ],
        "vuln_type": "LDAP Injection",
        "cwe": "CWE-90",
        "severity": "high",
    },
    # Redirect
    "redirect": {
        "patterns": [
            r"redirect\((.*)\)",
            r"HttpResponseRedirect\((.*)\)",
            r"response\.headers\[['\"]Location['\"]\]",
        ],
        "vuln_type": "Open Redirect",
        "cwe": "CWE-601",
        "severity": "medium",
    },
}

# Sanitization functions that may prevent exploitation
SANITIZATION_FUNCTIONS = [
    "escape", "html.escape", "markupsafe.escape", "bleach.clean",
    "sanitize", "clean", "strip_tags", "escape_html",
    "parameterized", "prepared", "bind", "quote", "escape_string",
    "shlex.quote", "pipes.quote", "sanitize_filename",
    "os.path.basename", "secure_filename",
    "int(", "float(", "bool(",
    "validate", "validator", "is_safe",
]


# ============================================================================
# VulnHuntr Service Class
# ============================================================================

class VulnHuntrService:
    """
    LLM-powered vulnerability hunter that traces data flow from sources to sinks.
    """
    
    def __init__(self):
        self.client = genai_client
        self.model_name = settings.gemini_model_id
        if self.client:
            logger.info("VulnHuntr: Gemini client available")
        else:
            logger.warning("VulnHuntr: No Gemini client, LLM analysis disabled")
    
    async def analyze_project(
        self, 
        project_path: str,
        file_extensions: List[str] = [".py"],
        max_files: int = 500,
        deep_analysis: bool = True
    ) -> VulnHuntrResult:
        """
        Perform full VulnHuntr analysis on a project.
        
        Args:
            project_path: Path to the project root
            file_extensions: File extensions to analyze
            max_files: Maximum number of files to process
            deep_analysis: Whether to use LLM for deep analysis
        
        Returns:
            VulnHuntrResult with all findings
        """
        import time
        start_time = time.time()
        
        scan_id = hashlib.md5(f"{project_path}:{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        logger.info(f"VulnHuntr: Starting analysis of {project_path}")
        
        # Collect all source files
        source_files = self._collect_source_files(project_path, file_extensions, max_files)
        logger.info(f"VulnHuntr: Found {len(source_files)} files to analyze")
        
        # Phase 1: Identify all sources (user input points)
        all_sources = []
        for file_path in source_files:
            sources = await self._find_sources(file_path)
            all_sources.extend(sources)
        
        logger.info(f"VulnHuntr: Found {len(all_sources)} source points")
        
        # Phase 2: Identify all sinks (dangerous functions)
        all_sinks = []
        for file_path in source_files:
            sinks = await self._find_sinks(file_path)
            all_sinks.extend(sinks)
        
        logger.info(f"VulnHuntr: Found {len(all_sinks)} sink points")
        
        # Phase 3: Build function call graph
        call_graph = self._build_call_graph(source_files)
        
        # Phase 4: Trace data flows from sources to sinks
        vulnerabilities = []
        for source in all_sources:
            for sink in all_sinks:
                flow = await self._trace_data_flow(
                    source, sink, call_graph, source_files, deep_analysis
                )
                if flow and flow.confidence > 0.5:
                    vulnerabilities.append(flow)
        
        logger.info(f"VulnHuntr: Found {len(vulnerabilities)} potential vulnerabilities")
        
        # Phase 5: LLM-powered deep analysis and deduplication
        if deep_analysis and vulnerabilities:
            vulnerabilities = await self._llm_analyze_vulnerabilities(
                vulnerabilities, source_files
            )
        
        # Sort by severity and confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulnerabilities.sort(
            key=lambda v: (severity_order.get(v.severity, 4), -v.confidence)
        )
        
        # Build statistics
        stats = self._build_statistics(vulnerabilities, all_sources, all_sinks)
        
        duration = time.time() - start_time
        
        return VulnHuntrResult(
            project_path=project_path,
            scan_id=scan_id,
            timestamp=datetime.now().isoformat(),
            total_files_scanned=len(source_files),
            sources_found=len(all_sources),
            sinks_found=len(all_sinks),
            vulnerabilities=vulnerabilities,
            statistics=stats,
            scan_duration_seconds=round(duration, 2)
        )
    
    def _collect_source_files(
        self, 
        project_path: str, 
        extensions: List[str],
        max_files: int
    ) -> List[str]:
        """Collect all source files in the project"""
        files = []
        project = Path(project_path)
        
        # Directories to skip
        skip_dirs = {
            "node_modules", "venv", ".venv", "env", ".env",
            "__pycache__", ".git", ".svn", "dist", "build",
            ".tox", ".pytest_cache", ".mypy_cache", "htmlcov",
            "site-packages", "migrations"
        }
        
        for ext in extensions:
            for file_path in project.rglob(f"*{ext}"):
                # Skip unwanted directories
                if any(skip in file_path.parts for skip in skip_dirs):
                    continue
                files.append(str(file_path))
                if len(files) >= max_files:
                    break
        
        return files
    
    async def _find_sources(self, file_path: str) -> List[SourcePoint]:
        """Find all user input sources in a file"""
        sources = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.warning(f"VulnHuntr: Could not read {file_path}: {e}")
            return sources
        
        for source_type, patterns in PYTHON_SOURCES.items():
            for pattern in patterns:
                try:
                    for match in re.finditer(pattern, content):
                        # Find line number
                        line_start = content[:match.start()].count('\n')
                        line_num = line_start + 1
                        
                        # Get code snippet (3 lines context)
                        start_line = max(0, line_num - 2)
                        end_line = min(len(lines), line_num + 2)
                        snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Extract variable name if captured
                        var_name = match.group(1) if match.lastindex else match.group(0)
                        
                        sources.append(SourcePoint(
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            source_type=source_type,
                            variable_name=var_name,
                            context=lines[line_num - 1] if line_num <= len(lines) else ""
                        ))
                except Exception as e:
                    continue
        
        return sources
    
    async def _find_sinks(self, file_path: str) -> List[SinkPoint]:
        """Find all dangerous sinks in a file"""
        sinks = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.warning(f"VulnHuntr: Could not read {file_path}: {e}")
            return sinks
        
        for sink_name, sink_info in PYTHON_SINKS.items():
            for pattern in sink_info["patterns"]:
                try:
                    for match in re.finditer(pattern, content):
                        # Find line number
                        line_start = content[:match.start()].count('\n')
                        line_num = line_start + 1
                        
                        # Get code snippet (3 lines context)
                        start_line = max(0, line_num - 2)
                        end_line = min(len(lines), line_num + 2)
                        snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Extract the argument (potential tainted data)
                        func_arg = match.group(1) if match.lastindex else ""
                        
                        sinks.append(SinkPoint(
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            sink_type=sink_name,
                            function_name=match.group(0).split('(')[0],
                            vulnerability_type=sink_info["vuln_type"],
                            severity=sink_info["severity"],
                            context=func_arg
                        ))
                except Exception as e:
                    continue
        
        return sinks
    
    def _build_call_graph(self, source_files: List[str]) -> Dict[str, Any]:
        """Build a simple call graph from source files"""
        call_graph = {
            "functions": {},  # function_name -> {file, line, calls, called_by}
            "imports": {},    # file -> list of imports
            "classes": {},    # class_name -> {file, methods}
        }
        
        for file_path in source_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    # Track function definitions
                    if isinstance(node, ast.FunctionDef):
                        func_name = node.name
                        full_name = f"{file_path}:{func_name}"
                        
                        # Find what this function calls
                        calls = []
                        for child in ast.walk(node):
                            if isinstance(child, ast.Call):
                                if isinstance(child.func, ast.Name):
                                    calls.append(child.func.id)
                                elif isinstance(child.func, ast.Attribute):
                                    calls.append(child.func.attr)
                        
                        call_graph["functions"][full_name] = {
                            "file": file_path,
                            "line": node.lineno,
                            "calls": calls,
                            "called_by": [],
                            "args": [arg.arg for arg in node.args.args]
                        }
                    
                    # Track imports
                    elif isinstance(node, ast.Import):
                        if file_path not in call_graph["imports"]:
                            call_graph["imports"][file_path] = []
                        for alias in node.names:
                            call_graph["imports"][file_path].append(alias.name)
                    
                    elif isinstance(node, ast.ImportFrom):
                        if file_path not in call_graph["imports"]:
                            call_graph["imports"][file_path] = []
                        module = node.module or ""
                        for alias in node.names:
                            call_graph["imports"][file_path].append(f"{module}.{alias.name}")
                    
                    # Track classes
                    elif isinstance(node, ast.ClassDef):
                        class_name = node.name
                        methods = [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                        call_graph["classes"][class_name] = {
                            "file": file_path,
                            "methods": methods
                        }
                        
            except Exception as e:
                continue
        
        # Build called_by relationships
        for func_name, func_info in call_graph["functions"].items():
            for called in func_info["calls"]:
                for other_func, other_info in call_graph["functions"].items():
                    if other_func.endswith(f":{called}"):
                        other_info["called_by"].append(func_name)
        
        return call_graph
    
    async def _trace_data_flow(
        self,
        source: SourcePoint,
        sink: SinkPoint,
        call_graph: Dict[str, Any],
        source_files: List[str],
        deep_analysis: bool
    ) -> Optional[VulnerabilityFlow]:
        """
        Trace data flow from a source to a sink.
        Uses both static analysis and LLM for complex flows.
        """
        # Quick check: are they in the same file?
        same_file = source.file_path == sink.file_path
        
        # Check if the source variable appears in the sink context
        source_var = source.variable_name
        sink_context = sink.context + sink.code_snippet
        
        # Direct flow detection
        if source_var in sink_context or same_file:
            # Check for sanitization
            sanitization_present = any(
                san in sink.code_snippet for san in SANITIZATION_FUNCTIONS
            )
            
            # Build call chain
            call_chain = [
                CallChainNode(
                    file_path=source.file_path,
                    line_number=source.line_number,
                    function_name="<source>",
                    code_snippet=source.code_snippet,
                    data_variable=source.variable_name,
                    transformation="User input received"
                )
            ]
            
            # If same file, check for intermediate transformations
            if same_file:
                intermediate = await self._find_intermediate_steps(
                    source, sink, source.file_path
                )
                call_chain.extend(intermediate)
            
            call_chain.append(
                CallChainNode(
                    file_path=sink.file_path,
                    line_number=sink.line_number,
                    function_name=sink.function_name,
                    code_snippet=sink.code_snippet,
                    data_variable=source.variable_name,
                    transformation=f"Passed to {sink.sink_type}"
                )
            )
            
            # Generate vulnerability ID
            vuln_id = hashlib.md5(
                f"{source.file_path}:{source.line_number}:{sink.file_path}:{sink.line_number}".encode()
            ).hexdigest()[:10]
            
            # Determine confidence based on flow characteristics
            confidence = 0.9 if same_file else 0.7
            if sanitization_present:
                confidence *= 0.5
            
            # Use LLM for deep analysis if enabled
            description = f"User input from {source.source_type} flows to {sink.sink_type}"
            exploit_scenario = f"Attacker-controlled input reaches {sink.vulnerability_type} sink"
            remediation = self._get_remediation(sink.vulnerability_type)
            bypass = None
            
            if deep_analysis and self.model:
                llm_analysis = await self._llm_analyze_flow(source, sink, call_chain)
                if llm_analysis:
                    confidence = llm_analysis.get("confidence", confidence)
                    description = llm_analysis.get("description", description)
                    exploit_scenario = llm_analysis.get("exploit_scenario", exploit_scenario)
                    remediation = llm_analysis.get("remediation", remediation)
                    bypass = llm_analysis.get("sanitization_bypass")
                    
                    if llm_analysis.get("is_false_positive", False):
                        return None
            
            return VulnerabilityFlow(
                id=vuln_id,
                source=source,
                sink=sink,
                call_chain=call_chain,
                vulnerability_type=sink.vulnerability_type,
                severity=sink.severity,
                confidence=confidence,
                description=description,
                exploit_scenario=exploit_scenario,
                remediation=remediation,
                cwe_id=PYTHON_SINKS.get(sink.sink_type, {}).get("cwe", "CWE-Unknown"),
                owasp_category=self._get_owasp_category(sink.vulnerability_type),
                is_exploitable=not sanitization_present or bypass is not None,
                sanitization_present=sanitization_present,
                sanitization_bypass=bypass
            )
        
        return None
    
    async def _find_intermediate_steps(
        self,
        source: SourcePoint,
        sink: SinkPoint,
        file_path: str
    ) -> List[CallChainNode]:
        """Find intermediate data transformations between source and sink"""
        steps = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Look for variable assignments between source and sink lines
            start_line = source.line_number
            end_line = sink.line_number
            var_name = source.variable_name
            
            for i in range(start_line, min(end_line, len(lines))):
                line = lines[i]
                
                # Check if the variable is being transformed
                if var_name in line and '=' in line:
                    steps.append(CallChainNode(
                        file_path=file_path,
                        line_number=i + 1,
                        function_name="<assignment>",
                        code_snippet=line.strip(),
                        data_variable=var_name,
                        transformation="Variable transformation"
                    ))
                    
        except Exception:
            pass
        
        return steps
    
    async def _llm_analyze_flow(
        self,
        source: SourcePoint,
        sink: SinkPoint,
        call_chain: List[CallChainNode]
    ) -> Optional[Dict[str, Any]]:
        """Use LLM to analyze the vulnerability flow in detail"""
        if not self.client:
            return None
        
        try:
            chain_text = "\n".join([
                f"  {i+1}. [{node.file_path}:{node.line_number}] {node.code_snippet}"
                for i, node in enumerate(call_chain)
            ])
            
            prompt = f"""Analyze this potential {sink.vulnerability_type} vulnerability in Python code:

SOURCE (User Input):
- Type: {source.source_type}
- File: {source.file_path}
- Line: {source.line_number}
- Code: {source.code_snippet}

SINK (Dangerous Function):
- Type: {sink.sink_type}
- File: {sink.file_path}
- Line: {sink.line_number}
- Code: {sink.code_snippet}

DATA FLOW CHAIN:
{chain_text}

Analyze this flow and respond in JSON format:
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "description": "Clear description of the vulnerability",
    "exploit_scenario": "How an attacker could exploit this",
    "remediation": "Specific fix recommendation",
    "sanitization_bypass": "If sanitization exists, how it could be bypassed (or null)"
}}

Consider:
1. Is user input actually reaching the sink without proper sanitization?
2. Are there any validation/sanitization steps that would prevent exploitation?
3. What's the realistic exploitability in a real-world scenario?
"""
            
            from google.genai import types
            response = await self.client.aio.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="medium"),
                    max_output_tokens=1000
                )
            )
            text = response.text
            
            # Extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                return json.loads(json_match.group())
                
        except Exception as e:
            logger.warning(f"VulnHuntr: LLM analysis failed: {e}")
        
        return None
    
    async def _llm_analyze_vulnerabilities(
        self,
        vulnerabilities: List[VulnerabilityFlow],
        source_files: List[str]
    ) -> List[VulnerabilityFlow]:
        """Use LLM to perform deep analysis and deduplication"""
        if not self.client or not vulnerabilities:
            return vulnerabilities
        
        # Deduplicate based on source-sink pairs
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = f"{vuln.source.file_path}:{vuln.source.line_number}:{vuln.sink.sink_type}"
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for a vulnerability type"""
        remediations = {
            "SQLi": "Use parameterized queries or ORM methods. Never concatenate user input into SQL strings.",
            "RCE": "Avoid using eval/exec. Use subprocess with shell=False and validate all input.",
            "LFI": "Validate and sanitize file paths. Use os.path.basename() and check against allowed paths.",
            "XSS": "Use proper output encoding. In templates, use auto-escaping or markupsafe.escape().",
            "SSRF": "Validate and whitelist allowed URLs/domains. Block internal IP ranges.",
            "XXE": "Disable external entity processing in XML parsers. Use defusedxml library.",
            "Insecure Deserialization": "Never deserialize untrusted data. Use JSON instead of pickle/yaml.",
            "LDAP Injection": "Use parameterized LDAP queries. Escape special characters.",
            "Open Redirect": "Validate redirect URLs against a whitelist of allowed domains.",
        }
        return remediations.get(vuln_type, "Validate and sanitize all user input before use.")
    
    def _get_owasp_category(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP Top 10 category"""
        mapping = {
            "SQLi": "A03:2021 - Injection",
            "RCE": "A03:2021 - Injection",
            "LFI": "A01:2021 - Broken Access Control",
            "XSS": "A03:2021 - Injection",
            "SSRF": "A10:2021 - Server-Side Request Forgery",
            "XXE": "A05:2021 - Security Misconfiguration",
            "Insecure Deserialization": "A08:2021 - Software and Data Integrity Failures",
            "LDAP Injection": "A03:2021 - Injection",
            "Open Redirect": "A01:2021 - Broken Access Control",
        }
        return mapping.get(vuln_type, "A03:2021 - Injection")
    
    def _build_statistics(
        self,
        vulnerabilities: List[VulnerabilityFlow],
        sources: List[SourcePoint],
        sinks: List[SinkPoint]
    ) -> Dict[str, Any]:
        """Build statistics summary"""
        stats = {
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_type": {},
            "by_file": {},
            "source_types": {},
            "sink_types": {},
            "exploitable_count": 0,
            "with_sanitization": 0,
        }
        
        for vuln in vulnerabilities:
            # By severity
            stats["by_severity"][vuln.severity] = stats["by_severity"].get(vuln.severity, 0) + 1
            
            # By type
            stats["by_type"][vuln.vulnerability_type] = stats["by_type"].get(vuln.vulnerability_type, 0) + 1
            
            # By file
            file_name = Path(vuln.source.file_path).name
            stats["by_file"][file_name] = stats["by_file"].get(file_name, 0) + 1
            
            # Exploitable
            if vuln.is_exploitable:
                stats["exploitable_count"] += 1
            
            # Sanitization
            if vuln.sanitization_present:
                stats["with_sanitization"] += 1
        
        # Source types
        for source in sources:
            stats["source_types"][source.source_type] = stats["source_types"].get(source.source_type, 0) + 1
        
        # Sink types  
        for sink in sinks:
            stats["sink_types"][sink.sink_type] = stats["sink_types"].get(sink.sink_type, 0) + 1
        
        return stats


# ============================================================================
# Report Generation
# ============================================================================

def generate_vulnhuntr_markdown(result: VulnHuntrResult) -> str:
    """Generate a Markdown report from VulnHuntr results"""
    lines = [
        "# 🎯 VulnHuntr Analysis Report",
        "",
        f"**Scan ID:** {result.scan_id}",
        f"**Project:** {result.project_path}",
        f"**Timestamp:** {result.timestamp}",
        f"**Duration:** {result.scan_duration_seconds}s",
        "",
        "---",
        "",
        "## 📊 Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Files Scanned | {result.total_files_scanned} |",
        f"| Source Points | {result.sources_found} |",
        f"| Sink Points | {result.sinks_found} |",
        f"| Vulnerabilities | {len(result.vulnerabilities)} |",
        "",
    ]
    
    # Severity breakdown
    if result.statistics.get("by_severity"):
        lines.extend([
            "### Severity Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        for sev, count in result.statistics["by_severity"].items():
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")
    
    # Vulnerability details
    if result.vulnerabilities:
        lines.extend([
            "---",
            "",
            "## 🔴 Vulnerabilities",
            "",
        ])
        
        for i, vuln in enumerate(result.vulnerabilities, 1):
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(vuln.severity, "⚪")
            
            lines.extend([
                f"### {i}. {severity_emoji} {vuln.vulnerability_type} ({vuln.severity.upper()})",
                "",
                f"**ID:** `{vuln.id}`",
                f"**Confidence:** {vuln.confidence:.0%}",
                f"**CWE:** {vuln.cwe_id}",
                f"**OWASP:** {vuln.owasp_category}",
                "",
                "#### Description",
                vuln.description,
                "",
                "#### Source (User Input)",
                f"- **File:** `{vuln.source.file_path}`",
                f"- **Line:** {vuln.source.line_number}",
                f"- **Type:** {vuln.source.source_type}",
                "```python",
                vuln.source.code_snippet,
                "```",
                "",
                "#### Sink (Dangerous Function)",
                f"- **File:** `{vuln.sink.file_path}`",
                f"- **Line:** {vuln.sink.line_number}",
                f"- **Function:** {vuln.sink.function_name}",
                "```python",
                vuln.sink.code_snippet,
                "```",
                "",
                "#### Data Flow Chain",
            ])
            
            for j, node in enumerate(vuln.call_chain):
                lines.append(f"{j+1}. `{Path(node.file_path).name}:{node.line_number}` - {node.transformation}")
            
            lines.extend([
                "",
                "#### Exploit Scenario",
                vuln.exploit_scenario,
                "",
                "#### Remediation",
                vuln.remediation,
                "",
            ])
            
            if vuln.sanitization_present:
                lines.extend([
                    "⚠️ **Sanitization Detected:** Some sanitization is present but may be bypassable.",
                ])
                if vuln.sanitization_bypass:
                    lines.append(f"  - Potential bypass: {vuln.sanitization_bypass}")
                lines.append("")
            
            lines.append("---")
            lines.append("")
    
    return "\n".join(lines)


def result_to_dict(result: VulnHuntrResult) -> Dict[str, Any]:
    """Convert VulnHuntrResult to dictionary for JSON serialization"""
    return {
        "project_path": result.project_path,
        "scan_id": result.scan_id,
        "timestamp": result.timestamp,
        "total_files_scanned": result.total_files_scanned,
        "sources_found": result.sources_found,
        "sinks_found": result.sinks_found,
        "vulnerabilities": [
            {
                "id": v.id,
                "vulnerability_type": v.vulnerability_type,
                "severity": v.severity,
                "confidence": v.confidence,
                "description": v.description,
                "exploit_scenario": v.exploit_scenario,
                "remediation": v.remediation,
                "cwe_id": v.cwe_id,
                "owasp_category": v.owasp_category,
                "is_exploitable": v.is_exploitable,
                "sanitization_present": v.sanitization_present,
                "sanitization_bypass": v.sanitization_bypass,
                "source": {
                    "file_path": v.source.file_path,
                    "line_number": v.source.line_number,
                    "source_type": v.source.source_type,
                    "variable_name": v.source.variable_name,
                    "code_snippet": v.source.code_snippet,
                },
                "sink": {
                    "file_path": v.sink.file_path,
                    "line_number": v.sink.line_number,
                    "sink_type": v.sink.sink_type,
                    "function_name": v.sink.function_name,
                    "code_snippet": v.sink.code_snippet,
                },
                "call_chain": [
                    {
                        "file_path": n.file_path,
                        "line_number": n.line_number,
                        "function_name": n.function_name,
                        "transformation": n.transformation,
                    }
                    for n in v.call_chain
                ]
            }
            for v in result.vulnerabilities
        ],
        "statistics": result.statistics,
        "scan_duration_seconds": result.scan_duration_seconds,
    }


# Singleton instance
vulnhuntr_service = VulnHuntrService()
