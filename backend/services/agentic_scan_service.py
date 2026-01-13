"""
Agentic AI Security Scan Service

Advanced LLM-powered vulnerability scanner that uses an agentic approach:
1. Code Chunking - Breaks codebase into LLM-digestible chunks
2. Iterative Analysis - AI requests additional code snippets as needed
3. Flow Tracing - Maps complete data flows from user input to dangerous sinks
4. Deep Vulnerability Detection - Finds complex vulnerabilities missed by static analysis

Inspired by Protect AI's VulnHuntr approach but with enhanced agentic capabilities.
"""

import os
import re
import ast
import json
import hashlib
import asyncio
import random
from typing import Dict, List, Any, Optional, Set, Tuple, AsyncGenerator
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime
from enum import Enum

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)


async def _retry_with_backoff(
    func, 
    max_retries: int = 3, 
    base_delay: float = 2.0,
    timeout_seconds: float = 120.0,
    operation_name: str = "AgenticScan API call"
):
    """
    Retry an async function with exponential backoff and timeout.
    Handles 'Server disconnected', timeout, and other transient errors.
    """
    last_error = None
    for attempt in range(max_retries):
        try:
            # Add timeout wrapper
            return await asyncio.wait_for(func(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            last_error = Exception(f"{operation_name} timed out after {timeout_seconds}s")
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            logger.warning(f"{operation_name}: Timeout (attempt {attempt + 1}/{max_retries}), retrying in {delay:.1f}s")
            await asyncio.sleep(delay)
        except Exception as e:
            last_error = e
            error_str = str(e).lower()
            # Retry on transient errors
            retryable = ['disconnected', 'timeout', 'connection', 'unavailable', '503', '429', '500', '502', '504']
            if any(err in error_str for err in retryable):
                delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                logger.warning(f"{operation_name}: Transient error (attempt {attempt + 1}/{max_retries}), retrying in {delay:.1f}s: {e}")
                await asyncio.sleep(delay)
            else:
                # Non-transient error, don't retry
                raise
    
    logger.error(f"{operation_name}: All {max_retries} retries failed")
    raise last_error


def _repair_json(text: str) -> str:
    """
    Attempt to repair common JSON issues from LLM responses.
    
    Handles:
    - Trailing commas before } or ]
    - Missing quotes around keys
    - Unescaped newlines in strings
    - Truncated JSON (tries to close brackets)
    """
    if not text:
        return text
    
    # Remove any markdown code fences
    text = re.sub(r'```json\s*', '', text)
    text = re.sub(r'```\s*$', '', text)
    
    # Fix trailing commas (common LLM mistake)
    text = re.sub(r',\s*}', '}', text)
    text = re.sub(r',\s*]', ']', text)
    
    # Fix unquoted keys (e.g., {key: "value"} -> {"key": "value"})
    text = re.sub(r'{\s*(\w+)\s*:', r'{"\1":', text)
    text = re.sub(r',\s*(\w+)\s*:', r',"\1":', text)
    
    # Try to balance brackets if truncated
    open_braces = text.count('{') - text.count('}')
    open_brackets = text.count('[') - text.count(']')
    
    if open_braces > 0 or open_brackets > 0:
        # Add closing brackets
        text = text.rstrip()
        if text.endswith(','):
            text = text[:-1]
        text += ']' * open_brackets + '}' * open_braces
    
    return text


def _safe_json_parse(text: str, fallback: dict = None) -> dict:
    """
    Safely parse JSON from LLM response with repair attempts.
    
    Args:
        text: Raw text potentially containing JSON
        fallback: Default value if parsing fails
        
    Returns:
        Parsed JSON dict or fallback
    """
    if fallback is None:
        fallback = {}
    
    if not text:
        return fallback
    
    # First try to find JSON object in the text
    json_match = re.search(r'\{[\s\S]*\}', text)
    if not json_match:
        return fallback
    
    json_str = json_match.group()
    
    # Try parsing as-is first
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        pass
    
    # Try with repairs
    try:
        repaired = _repair_json(json_str)
        return json.loads(repaired)
    except json.JSONDecodeError:
        pass
    
    # Last resort: try to extract just the array if present
    try:
        # Look for an array that might be valid
        array_match = re.search(r'\[\s*\{[\s\S]*?\}\s*\]', text)
        if array_match:
            arr = json.loads(array_match.group())
            return {"items": arr}
    except:
        pass
    
    return fallback


# Configure Gemini using google-genai SDK
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
        logger.info("AgenticScan: Gemini API configured successfully")
    except ImportError:
        logger.warning("AgenticScan: google-genai not installed, AI analysis disabled")


# ============================================================================
# Enums and Data Classes
# ============================================================================

class ScanPhase(str, Enum):
    INITIALIZING = "initializing"
    FILE_TRIAGE = "file_triage"  # New: AI examines all file names
    INITIAL_ANALYSIS = "initial_analysis"  # New: First pass on ~60 files
    FOCUSED_ANALYSIS = "focused_analysis"  # New: Second pass on ~20 files  
    DEEP_ANALYSIS = "deep_analysis"  # New: Full analysis of ~8 files
    ULTRA_ANALYSIS = "ultra_analysis"  # Pass 4: Ultra-deep analysis of large files (>50K chars)
    CHUNKING = "chunking"
    ENTRY_POINT_DETECTION = "entry_point_detection"
    FLOW_TRACING = "flow_tracing"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    FALSE_POSITIVE_FILTERING = "false_positive_filtering"
    SYNTHESIS = "synthesis"  # New: AI synthesizes findings from all passes
    REPORT_GENERATION = "report_generation"
    COMPLETE = "complete"
    ERROR = "error"


class VulnerabilityType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    XSS = "Cross-Site Scripting"
    PATH_TRAVERSAL = "Path Traversal"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    DESERIALIZATION = "Insecure Deserialization"
    IDOR = "Insecure Direct Object Reference"
    AUTH_BYPASS = "Authentication Bypass"
    OPEN_REDIRECT = "Open Redirect"
    LDAP_INJECTION = "LDAP Injection"
    CODE_INJECTION = "Code Injection"
    FILE_UPLOAD = "Unrestricted File Upload"
    RACE_CONDITION = "Race Condition"
    INFO_DISCLOSURE = "Information Disclosure"


@dataclass
class CodeChunk:
    """A manageable chunk of code for LLM analysis"""
    id: str
    file_path: str
    start_line: int
    end_line: int
    content: str
    language: str
    chunk_type: str  # function, class, module, block
    imports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # Other chunk IDs this depends on
    analysis_status: str = "pending"  # pending, analyzing, complete
    analysis_result: Optional[Dict] = None


@dataclass
class EntryPoint:
    """A user input entry point in the application"""
    id: str
    chunk_id: str
    file_path: str
    line_number: int
    entry_type: str  # http_param, form_data, file_upload, websocket, etc.
    variable_name: str
    code_snippet: str
    framework: str  # flask, django, fastapi, express, etc.
    http_method: Optional[str] = None
    route_path: Optional[str] = None


@dataclass
class DangerousSink:
    """A dangerous function that could lead to vulnerabilities"""
    id: str
    chunk_id: str
    file_path: str
    line_number: int
    sink_type: str
    function_name: str
    code_snippet: str
    vulnerability_type: str
    severity: str
    cwe_id: str


@dataclass
class DataFlowStep:
    """A step in the data flow from source to sink"""
    file_path: str
    line_number: int
    code_snippet: str
    variable_name: str
    transformation: str  # What happens to the data at this step
    is_sanitized: bool = False
    sanitization_method: Optional[str] = None


@dataclass
class TracedFlow:
    """A complete traced flow from entry point to dangerous sink"""
    id: str
    entry_point: EntryPoint
    sink: DangerousSink
    steps: List[DataFlowStep]
    is_exploitable: bool
    confidence: float
    sanitization_analysis: str


@dataclass
class AgenticVulnerability:
    """A vulnerability found by the agentic scanner"""
    id: str
    vulnerability_type: str
    severity: str
    cwe_id: str
    owasp_category: str
    title: str
    description: str
    flow: TracedFlow
    llm_analysis: str
    exploit_scenario: str
    remediation: str
    code_fix: Optional[str] = None
    confidence: float = 0.0
    false_positive_likelihood: float = 0.0
    related_vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class ScanProgress:
    """Progress tracking for the agentic scan"""
    scan_id: str
    project_id: int
    phase: ScanPhase
    phase_progress: float  # 0.0 to 1.0
    total_chunks: int
    analyzed_chunks: int
    entry_points_found: int
    flows_traced: int
    vulnerabilities_found: int
    current_file: Optional[str] = None
    message: str = ""
    started_at: str = ""
    estimated_completion: Optional[str] = None


@dataclass
class AgenticScanResult:
    """Complete result from the agentic scan"""
    scan_id: str
    project_id: int
    project_path: str
    status: str
    phase: ScanPhase
    total_chunks: int
    analyzed_chunks: int
    entry_points: List[EntryPoint]
    sinks: List[DangerousSink]
    traced_flows: List[TracedFlow]
    vulnerabilities: List[AgenticVulnerability]
    statistics: Dict[str, Any]
    started_at: str
    completed_at: Optional[str]
    scan_duration_seconds: float
    error_message: Optional[str] = None


@dataclass
class FileTriageResult:
    """Result from AI file triage - which files to examine"""
    file_path: str
    relative_path: str
    file_type: str
    priority: str  # critical, high, medium, low, skip
    reasoning: str
    security_relevance: float  # 0.0 to 1.0
    suggested_analysis_depth: str  # full, detailed, quick, skip


@dataclass
class MultiPassAnalysisResult:
    """Results from multi-pass analysis of a file"""
    file_path: str
    pass_number: int  # 1=initial, 2=focused, 3=deep
    analysis_depth: str
    findings: List[Dict[str, Any]]
    entry_points_found: int
    potential_vulnerabilities: int
    requires_deeper_analysis: bool
    security_score: float  # 0-10, higher = more suspicious
    key_observations: List[str]


@dataclass 
class SynthesisResult:
    """AI synthesis of findings across all passes"""
    total_files_triaged: int
    files_analyzed_initial: int
    files_analyzed_focused: int
    files_analyzed_deep: int
    cross_file_flows: List[Dict[str, Any]]
    combined_vulnerabilities: List[AgenticVulnerability]
    attack_chains: List[Dict[str, Any]]
    overall_security_assessment: str
    key_recommendations: List[str]


@dataclass
class ExternalIntelligence:
    """
    External intelligence data to inform AI analysis.
    
    This allows the AI to make smarter decisions about which files
    to analyze deeply based on:
    - Known CVEs in dependencies
    - SAST scanner findings
    - Dependency relationships
    - Application description and architecture
    - Security findings from other scanners
    - Codebase mapping data
    - Exploitability and attack surface analysis
    """
    # CVE/Vulnerability data
    cve_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"external_id": "CVE-2023-XXX", "package": "requests", "severity": "high", 
    #           "cvss_score": 8.5, "epss_score": 0.7, "in_kev": True,
    #           "affected_functions": ["get", "post"], "description": "..."}]
    
    # SAST scanner findings (from Semgrep, Bandit, ESLint, etc.)
    sast_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"file_path": "api.py", "line": 45, "type": "sql-injection", 
    #           "severity": "high", "scanner": "semgrep", "message": "..."}]
    
    # Dependency information
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"name": "requests", "version": "2.25.0", "ecosystem": "pypi"}]
    
    # File-to-dependency mapping (which files import which packages)
    file_imports: Dict[str, List[str]] = field(default_factory=dict)
    # Format: {"api.py": ["requests", "flask"], "db.py": ["sqlalchemy"]}
    
    # Dependency tree (direct vs transitive)
    dependency_tree: Dict[str, Any] = field(default_factory=dict)
    
    # Files with vulnerable dependency imports
    vulnerable_import_files: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"file": "api.py", "package": "requests", "cve": "CVE-2023-XXX"}]
    
    # ========== NEW: Rich Context Fields ==========
    
    # What Does This App Do - AI-generated app description
    app_description: Optional[str] = None
    # Format: "This is a web application that handles user authentication..."
    
    # Code Architecture Diagram (Mermaid format)
    architecture_diagram: Optional[str] = None
    # Format: "graph TD; A[Frontend] --> B[API]; B --> C[Database]..."
    
    # Security Findings Summary from all scanners
    security_findings_summary: Optional[str] = None
    # Format: "Found 5 critical, 12 high, 23 medium severity issues..."
    
    # Detailed security findings list
    security_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"type": "SQL Injection", "file": "api.py", "line": 45, "severity": "critical"}]
    
    # Codebase Mapper data - file relationships and structure
    codebase_map: Optional[str] = None
    # Format: Structured description of how files relate to each other
    
    # Codebase Mapper diagram (Mermaid format)
    codebase_diagram: Optional[str] = None
    # Format: "graph TD; api.py --> db.py; db.py --> models.py..."
    
    # Exploitability assessment
    exploitability_assessment: Optional[str] = None
    # Format: "High exploitability due to unauthenticated endpoints..."
    
    # Attack Surface Map (Mermaid format)
    attack_surface_map: Optional[str] = None
    # Format: "graph LR; Internet --> WAF --> API --> Database..."
    
    # Attack surface summary
    attack_surface_summary: Optional[str] = None
    # Format: "12 public endpoints, 3 unauthenticated, 2 file upload points..."
    
    # Entry points identified by other analysis
    identified_entry_points: List[Dict[str, Any]] = field(default_factory=list)
    # Format: [{"route": "/api/upload", "method": "POST", "auth": false, "risk": "high"}]
    
    def get_priority_files(self) -> List[str]:
        """Get files that should be prioritized for analysis."""
        priority = set()
        
        # Files flagged by SAST
        for finding in self.sast_findings:
            if finding.get("file_path"):
                priority.add(finding["file_path"])
        
        # Files importing vulnerable dependencies
        for item in self.vulnerable_import_files:
            if item.get("file"):
                priority.add(item["file"])
        
        return list(priority)
    
    def get_cves_for_package(self, package_name: str) -> List[Dict]:
        """Get all CVEs affecting a specific package."""
        return [cve for cve in self.cve_findings if cve.get("package") == package_name]
    
    def get_sast_findings_for_file(self, file_path: str) -> List[Dict]:
        """Get SAST findings for a specific file."""
        return [f for f in self.sast_findings if f.get("file_path") == file_path]
    
    def get_high_severity_cves(self) -> List[Dict]:
        """Get high/critical severity CVEs."""
        return [cve for cve in self.cve_findings 
                if cve.get("severity", "").lower() in ("high", "critical")
                or cve.get("cvss_score", 0) >= 7.0
                or cve.get("in_kev", False)]


# ============================================================================
# Code Chunking Engine
# ============================================================================

class CodeChunker:
    """
    Breaks codebases into manageable chunks for LLM analysis.
    
    Chunks are sized to fit within LLM context windows while maintaining
    semantic coherence (functions, classes, logical blocks).
    
    Adaptive sizing based on codebase size:
    - Small (<50 files): 80 lines/chunk - deep analysis
    - Medium (50-150 files): 60 lines/chunk - balanced
    - Large (150-300 files): 40 lines/chunk - broader coverage
    - Very Large (300+ files): 25 lines/chunk - prioritized analysis
    
    Performance optimizations:
    - MAX_FILES reduced to 100 for balanced scan times
    - MAX_CHUNKS limits total chunks to prevent runaway LLM calls
    - Priority-based file selection focuses on security-critical code
    """
    
    # Default values (will be adjusted based on codebase size)
    # Optimized for speed while maintaining quality - prioritizes security-critical files
    MAX_CHUNK_LINES = 60   # Maximum lines per chunk
    MIN_CHUNK_LINES = 10   # Minimum lines to form a chunk
    CONTEXT_OVERLAP = 3    # Lines of overlap between chunks
    MAX_FILES = 75         # Max files to process (focused on security-critical code)
    MAX_CHUNKS = 60        # Max chunks - optimized for faster scans without quality loss
    
    # Adaptive sizing thresholds - more aggressive reduction for large codebases
    SIZE_THRESHOLDS = {
        "small": (0, 50, 80),         # (min_files, max_files, chunk_lines)
        "medium": (50, 150, 60),
        "large": (150, 300, 40),
        "very_large": (300, float('inf'), 25),
    }
    
    # Priority patterns for security-relevant files (higher = more important)
    PRIORITY_PATTERNS = {
        # High priority - entry points and security-sensitive
        r'(route|router|controller|endpoint|api|handler|view)': 100,
        r'(auth|login|session|token|jwt|oauth|password)': 95,
        r'(admin|user|account|permission|role|access)': 90,
        r'(database|db|query|sql|orm|model)': 85,
        r'(upload|file|download|storage)': 80,
        r'(exec|eval|subprocess|shell|command)': 80,
        r'(config|settings|env|secret)': 75,
        # Medium priority - core functionality
        r'(service|manager|helper|util|middleware)': 50,
        r'(main|app|index|server)': 45,
        # Low priority - tests and generated
        r'(test|spec|mock|fixture|__test__)': 10,
        r'(generated|dist|bundle|min\.)': 5,
    }
    
    def __init__(self, adaptive: bool = True, enhanced_mode: bool = False):
        self.chunks: Dict[str, CodeChunk] = {}
        self.adaptive = adaptive
        self.enhanced_mode = enhanced_mode
        self._file_count = 0
        self._chunk_size = self.MAX_CHUNK_LINES
        
        # Enhanced mode: 100% increase in limits (2x standard)
        if enhanced_mode:
            self.MAX_FILES = 225       # 2x the 112 standard
            self.MAX_CHUNKS = 180      # 2x the 90 standard
        else:
            self.MAX_FILES = 112       # Standard: 50% increase from 75
            self.MAX_CHUNKS = 90       # Standard: 50% increase from 60
    
    def chunk_project(self, project_path: str, file_extensions: List[str]) -> List[CodeChunk]:
        """Break the entire project into chunks with adaptive sizing"""
        chunks = []
        
        # Debug: Log project path and check if it exists
        project_dir = Path(project_path)
        logger.info(f"AgenticScan: Chunking project at path: {project_path}")
        logger.info(f"AgenticScan: Path exists: {project_dir.exists()}, is_dir: {project_dir.is_dir() if project_dir.exists() else 'N/A'}")
        if project_dir.exists():
            try:
                contents = list(project_dir.iterdir())[:10]  # First 10 items
                logger.info(f"AgenticScan: Directory contents (first 10): {[str(c.name) for c in contents]}")
            except Exception as e:
                logger.warning(f"AgenticScan: Could not list directory: {e}")
        
        # Collect all source files
        all_files = self._collect_all_files(project_path, file_extensions)
        self._file_count = len(all_files)
        logger.info(f"AgenticScan: Collected {len(all_files)} source files with extensions {file_extensions[:5]}...")
        
        # Determine adaptive chunk size based on codebase size
        if self.adaptive:
            self._chunk_size = self._get_adaptive_chunk_size(self._file_count)
            logger.info(f"AgenticScan: Adaptive chunking enabled - {self._file_count} files detected, using {self._chunk_size} lines/chunk")
        
        # Prioritize and select files if over limit
        source_files = self._prioritize_files(all_files)
        
        for file_path in source_files:
            # Stop if we've hit the max chunk limit
            if len(chunks) >= self.MAX_CHUNKS:
                logger.info(f"AgenticScan: Reached max chunk limit ({self.MAX_CHUNKS}), stopping file processing")
                break
            
            file_chunks = self._chunk_file(file_path)
            
            # Only add chunks up to the limit
            remaining = self.MAX_CHUNKS - len(chunks)
            if remaining > 0:
                chunks.extend(file_chunks[:remaining])
        
        # Build dependency graph between chunks
        self._analyze_dependencies(chunks)
        
        logger.info(f"AgenticScan: Created {len(chunks)} chunks from {min(len(source_files), self.MAX_FILES)} files (limit: {self.MAX_CHUNKS} chunks)")
        return chunks
    
    def _get_adaptive_chunk_size(self, file_count: int) -> int:
        """Determine chunk size based on total file count"""
        for size_name, (min_files, max_files, chunk_lines) in self.SIZE_THRESHOLDS.items():
            if min_files <= file_count < max_files:
                logger.info(f"AgenticScan: Codebase size '{size_name}' ({file_count} files) -> {chunk_lines} lines/chunk")
                return chunk_lines
        return self.MAX_CHUNK_LINES
    
    def _calculate_file_priority(self, file_path: str) -> int:
        """Calculate security priority score for a file (higher = more important)"""
        import re
        file_lower = file_path.lower()
        priority = 50  # Base priority
        
        for pattern, score in self.PRIORITY_PATTERNS.items():
            if re.search(pattern, file_lower, re.IGNORECASE):
                priority = max(priority, score)
        
        # Boost main source files
        if '/src/' in file_path or '/app/' in file_path or '/lib/' in file_path:
            priority += 10
        
        # Lower priority for deep nested paths (often generated/vendored)
        depth = file_path.count('/') + file_path.count('\\')
        if depth > 8:
            priority -= 20
        
        return max(1, priority)
    
    def _prioritize_files(self, files: List[str]) -> List[str]:
        """
        Prioritize files by security relevance when over the limit.
        Returns top MAX_FILES files sorted by priority.
        """
        if len(files) <= self.MAX_FILES:
            return files
        
        # Score all files
        scored_files = [(f, self._calculate_file_priority(f)) for f in files]
        
        # Sort by priority (highest first)
        scored_files.sort(key=lambda x: x[1], reverse=True)
        
        # Take top files
        selected = [f for f, _ in scored_files[:self.MAX_FILES]]
        
        logger.info(f"AgenticScan: Prioritized {len(selected)} of {len(files)} files by security relevance")
        
        # Log what we're prioritizing
        high_priority = [f for f, s in scored_files[:20]]
        logger.info(f"AgenticScan: Top priority files include: {high_priority[:5]}")
        
        return selected
    
    def _collect_all_files(self, project_path: str, extensions: List[str]) -> List[str]:
        """Collect ALL source files in the project (no limit)"""
        files = []
        project = Path(project_path)
        
        # Skip directories relative to project root (not absolute paths)
        # These are directories commonly containing dependencies or non-source files
        skip_dirs = {
            "node_modules", "venv", ".venv", "env", ".env", "__pycache__",
            ".git", ".svn", "dist", "build", ".tox", ".pytest_cache",
            ".mypy_cache", "htmlcov", "site-packages", "migrations",
            "vendor", "third_party", ".next", "coverage", "bower_components",
            ".cache", ".idea", ".vscode"
        }
        # Note: Removed "tmp" and "temp" as they can conflict with /tmp extraction directory
        
        for ext in extensions:
            for file_path in project.rglob(f"*{ext}"):
                # Only check path parts RELATIVE to project root
                try:
                    rel_parts = file_path.relative_to(project).parts
                    if any(skip in rel_parts for skip in skip_dirs):
                        continue
                except ValueError:
                    # Path is not relative to project, skip it
                    continue
                files.append(str(file_path))
        
        return files  # Return all files, prioritization happens later
    
    def _chunk_file(self, file_path: str) -> List[CodeChunk]:
        """Break a single file into semantic chunks"""
        chunks = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return chunks
        
        language = self._detect_language(file_path)
        
        if language == "python":
            chunks = self._chunk_python(file_path, content, lines)
        elif language in ("javascript", "typescript"):
            chunks = self._chunk_javascript(file_path, content, lines)
        else:
            # Generic line-based chunking
            chunks = self._chunk_generic(file_path, content, lines, language)
        
        return chunks
    
    def _chunk_python(self, file_path: str, content: str, lines: List[str]) -> List[CodeChunk]:
        """Chunk Python file by functions and classes"""
        chunks = []
        
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return self._chunk_generic(file_path, content, lines, "python")
        
        # Extract imports
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}")
        
        # Extract functions and classes
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                chunk = self._create_chunk_from_node(file_path, lines, node, "function", imports)
                chunks.append(chunk)
            elif isinstance(node, ast.ClassDef):
                chunk = self._create_chunk_from_node(file_path, lines, node, "class", imports)
                chunks.append(chunk)
        
        # If no functions/classes found, chunk the whole file
        if not chunks and len(lines) > 0:
            chunks = self._chunk_generic(file_path, content, lines, "python")
        
        return chunks
    
    def _chunk_javascript(self, file_path: str, content: str, lines: List[str]) -> List[CodeChunk]:
        """Chunk JavaScript/TypeScript file by functions"""
        chunks = []
        
        # Simple regex-based detection for JS/TS functions
        function_patterns = [
            r'(async\s+)?function\s+(\w+)',
            r'const\s+(\w+)\s*=\s*(async\s+)?\([^)]*\)\s*=>',
            r'(\w+)\s*:\s*(async\s+)?function',
            r'class\s+(\w+)',
        ]
        
        current_chunk_start = 0
        in_block = False
        brace_count = 0
        
        for i, line in enumerate(lines):
            # Track braces for block detection
            brace_count += line.count('{') - line.count('}')
            
            # Check for function/class start
            for pattern in function_patterns:
                if re.search(pattern, line):
                    if current_chunk_start < i and not in_block:
                        # Save previous chunk if exists
                        chunk_lines = lines[current_chunk_start:i]
                        if len(chunk_lines) >= self.MIN_CHUNK_LINES:
                            chunk = self._create_generic_chunk(
                                file_path, chunk_lines, current_chunk_start,
                                "javascript" if file_path.endswith('.js') else "typescript"
                            )
                            chunks.append(chunk)
                    current_chunk_start = i
                    in_block = True
                    break
            
            # Check for block end
            if in_block and brace_count == 0:
                chunk_lines = lines[current_chunk_start:i+1]
                chunk = self._create_generic_chunk(
                    file_path, chunk_lines, current_chunk_start,
                    "javascript" if file_path.endswith('.js') else "typescript"
                )
                chunks.append(chunk)
                current_chunk_start = i + 1
                in_block = False
        
        # Handle remaining lines
        if current_chunk_start < len(lines):
            chunk_lines = lines[current_chunk_start:]
            if len(chunk_lines) >= self.MIN_CHUNK_LINES:
                chunk = self._create_generic_chunk(
                    file_path, chunk_lines, current_chunk_start,
                    "javascript" if file_path.endswith('.js') else "typescript"
                )
                chunks.append(chunk)
        
        if not chunks:
            chunks = self._chunk_generic(file_path, content, lines, 
                "javascript" if file_path.endswith('.js') else "typescript")
        
        return chunks
    
    def _chunk_generic(self, file_path: str, content: str, lines: List[str], language: str) -> List[CodeChunk]:
        """Generic line-based chunking with adaptive sizing"""
        chunks = []
        chunk_size = self._chunk_size  # Use adaptive chunk size
        
        for i in range(0, len(lines), chunk_size - self.CONTEXT_OVERLAP):
            end = min(i + chunk_size, len(lines))
            chunk_lines = lines[i:end]
            
            if len(chunk_lines) >= self.MIN_CHUNK_LINES:
                chunk = self._create_generic_chunk(file_path, chunk_lines, i, language)
                chunks.append(chunk)
        
        return chunks
    
    def _create_chunk_from_node(
        self, file_path: str, lines: List[str], node: ast.AST, 
        chunk_type: str, imports: List[str]
    ) -> CodeChunk:
        """Create a chunk from an AST node"""
        start_line = node.lineno - 1
        end_line = node.end_lineno if hasattr(node, 'end_lineno') else start_line + 20
        
        chunk_lines = lines[start_line:end_line]
        content = '\n'.join(chunk_lines)
        
        chunk_id = hashlib.md5(f"{file_path}:{start_line}:{end_line}".encode()).hexdigest()[:12]
        
        return CodeChunk(
            id=chunk_id,
            file_path=file_path,
            start_line=start_line + 1,
            end_line=end_line,
            content=content,
            language="python",
            chunk_type=chunk_type,
            imports=imports
        )
    
    def _create_generic_chunk(
        self, file_path: str, chunk_lines: List[str], start_line: int, language: str
    ) -> CodeChunk:
        """Create a generic chunk"""
        content = '\n'.join(chunk_lines)
        end_line = start_line + len(chunk_lines)
        
        chunk_id = hashlib.md5(f"{file_path}:{start_line}:{end_line}".encode()).hexdigest()[:12]
        
        return CodeChunk(
            id=chunk_id,
            file_path=file_path,
            start_line=start_line + 1,
            end_line=end_line,
            content=content,
            language=language,
            chunk_type="block"
        )
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.jsx': 'javascript',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.c': 'c',
            '.cpp': 'cpp',
            '.rs': 'rust',
            # Documentation & config
            '.md': 'markdown',
            '.rst': 'restructuredtext',
            '.txt': 'text',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.json': 'json',
            '.toml': 'toml',
            '.xml': 'xml',
            '.properties': 'properties',
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, 'unknown')
    
    def _analyze_dependencies(self, chunks: List[CodeChunk]):
        """Analyze dependencies between chunks"""
        # Build index of function/class names to chunk IDs
        name_to_chunk: Dict[str, str] = {}
        
        for chunk in chunks:
            # Extract function/class names from content
            if chunk.language == "python":
                for match in re.finditer(r'def\s+(\w+)|class\s+(\w+)', chunk.content):
                    name = match.group(1) or match.group(2)
                    name_to_chunk[name] = chunk.id
        
        # Find dependencies
        for chunk in chunks:
            for name, dep_chunk_id in name_to_chunk.items():
                if dep_chunk_id != chunk.id and name in chunk.content:
                    if dep_chunk_id not in chunk.dependencies:
                        chunk.dependencies.append(dep_chunk_id)


# ============================================================================
# Agentic Analysis Engine
# ============================================================================

class AgenticAnalyzer:
    """
    Agentic AI analyzer that iteratively requests code context.
    
    Uses prompt engineering to have the LLM request additional code snippets
    as needed to trace complete data flows.
    
    Enhanced with External Intelligence:
    - CVE data informs which files to analyze (files importing vulnerable deps)
    - SAST findings guide deeper analysis of flagged locations
    - Dependency relationships help trace data flows
    """
    
    def __init__(self, external_intel: Optional[ExternalIntelligence] = None, enhanced_mode: bool = False):
        self.client = genai_client
        self.model_name = settings.gemini_model_id
        self.chunks: Dict[str, CodeChunk] = {}
        self.entry_points: List[EntryPoint] = []
        self.sinks: List[DangerousSink] = []
        self.flows: List[TracedFlow] = []
        # Multi-pass analysis state
        self.triage_results: List[FileTriageResult] = []
        self.multi_pass_results: List[MultiPassAnalysisResult] = []
        # External intelligence (CVEs, SAST findings, etc.)
        self.external_intel = external_intel or ExternalIntelligence()
        self.enhanced_mode = enhanced_mode
        
        # Multi-pass file limits: Standard (+50%) vs Enhanced (+100%/2x)
        if enhanced_mode:
            # Enhanced: 100% increase (2x standard) in file counts
            self.pass1_limit = 240   # 2x standard (was 120)
            self.pass2_limit = 80    # 2x standard (was 40)
            self.pass3_limit = 30    # 2x standard (was 15)
            self.pass4_limit = 10    # Enhanced: 10 files for ultra-deep (vs 7 standard)
            self.pass4_min_size = 50000  # Same threshold
            
            # Enhanced content depth limits - 20-40% more content per file
            self.content_limits = {
                "quick": 6000,       # Pass 1: 6K chars per file (+20%)
                "detailed": 16000,   # Pass 2: 16K chars per file (+33%)
                "full": 65000,       # Pass 3: 65K chars (+30%)
                "ultra": 120000      # Pass 4: 120K chars (+20% for large files)
            }
        else:
            # Standard: 50% increase from original values
            self.pass1_limit = 180   # +50% (was 120)
            self.pass2_limit = 60    # +50% (was 40)
            self.pass3_limit = 22    # +50% (was 15)
            self.pass4_limit = 7     # Max 7 files for ultra-deep analysis
            self.pass4_min_size = 50000  # Only files > 50K chars qualify for Pass 4
            
            # Standard content depth limits per pass
            self.content_limits = {
                "quick": 5000,       # Pass 1: 5K chars per file
                "detailed": 12000,   # Pass 2: 12K chars per file
                "full": 50000,       # Pass 3: 50K chars (full file analysis)
                "ultra": 100000      # Pass 4: 100K chars (ultra-deep for large files)
            }
        
        # Project structure context (built during triage)
        self.project_structure: Optional[str] = None
    
    def _build_project_structure_summary(self, project_path: str, all_files: List[str]) -> str:
        """
        Build a concise project structure summary for LLM context.
        Helps the LLM understand the codebase architecture.
        """
        from collections import defaultdict
        
        # Analyze directory structure
        dir_stats = defaultdict(lambda: {"count": 0, "types": set()})
        framework_hints = set()
        
        for f in all_files:
            try:
                rel_path = os.path.relpath(f, project_path)
                parts = rel_path.replace("\\", "/").split("/")
                ext = os.path.splitext(f)[1].lower()
                
                # Track directory stats
                if len(parts) > 1:
                    top_dir = parts[0]
                    dir_stats[top_dir]["count"] += 1
                    dir_stats[top_dir]["types"].add(ext)
                
                # Detect frameworks from file patterns
                filename = os.path.basename(f).lower()
                if filename in ["manage.py", "wsgi.py"]:
                    framework_hints.add("Django")
                elif filename in ["app.py", "flask_app.py"]:
                    framework_hints.add("Flask")
                elif "fastapi" in filename or "main.py" in filename:
                    framework_hints.add("FastAPI")
                elif filename in ["package.json"]:
                    framework_hints.add("Node.js")
                elif filename in ["pom.xml", "build.gradle"]:
                    framework_hints.add("Java/Spring")
                elif filename == "Gemfile":
                    framework_hints.add("Ruby on Rails")
                elif filename in ["composer.json"]:
                    framework_hints.add("PHP/Laravel")
                elif "router" in filename or "routes" in rel_path.lower():
                    framework_hints.add("Has routing layer")
                elif "model" in filename or "schema" in filename:
                    framework_hints.add("Has data models")
                elif "service" in filename:
                    framework_hints.add("Service layer pattern")
                elif "controller" in filename:
                    framework_hints.add("MVC pattern")
            except Exception:
                continue
        
        # Build summary
        summary_parts = ["## PROJECT STRUCTURE OVERVIEW:"]
        
        if framework_hints:
            summary_parts.append(f"**Detected patterns**: {', '.join(sorted(framework_hints))}")
        
        summary_parts.append(f"**Total files**: {len(all_files)}")
        
        # Top-level directories
        if dir_stats:
            summary_parts.append("\n**Key directories**:")
            for dir_name, stats in sorted(dir_stats.items(), key=lambda x: -x[1]["count"])[:10]:
                types_str = ", ".join(sorted(stats["types"])[:4])
                summary_parts.append(f"- `{dir_name}/`: {stats['count']} files ({types_str})")
        
        # Language breakdown
        lang_counts = defaultdict(int)
        for f in all_files:
            ext = os.path.splitext(f)[1].lower()
            if ext:
                lang_counts[ext] += 1
        
        if lang_counts:
            summary_parts.append("\n**Languages**:")
            for ext, count in sorted(lang_counts.items(), key=lambda x: -x[1])[:6]:
                summary_parts.append(f"- {ext}: {count} files")
        
        return "\n".join(summary_parts)
    
    def set_multi_pass_limits(self, pass1: int = 60, pass2: int = 20, pass3: int = 8, pass4: int = 7,
                              quick_chars: int = 2000, detailed_chars: int = 5000, full_chars: int = 15000,
                              ultra_chars: int = 100000, pass4_min_size: int = 50000):
        """Configure multi-pass file limits and content depth.
        
        Args:
            pass1/pass2/pass3/pass4: Number of files per pass
            quick_chars: Chars per file in Pass 1 (default 2000)
            detailed_chars: Chars per file in Pass 2 (default 5000)
            full_chars: Chars per file in Pass 3 (default 15000)
            ultra_chars: Chars per file in Pass 4 (default 100000)
            pass4_min_size: Minimum file size (chars) to qualify for Pass 4 (default 50000)
        """
        self.pass1_limit = pass1
        self.pass2_limit = pass2
        self.pass3_limit = pass3
        self.pass4_limit = pass4
        self.pass4_min_size = pass4_min_size
        self.content_limits = {
            "quick": quick_chars,
            "detailed": detailed_chars,
            "full": full_chars,
            "ultra": ultra_chars
        }
        logger.info(f"AgenticScan: Multi-pass limits set to {pass1}→{pass2}→{pass3}→{pass4} files, "
                   f"content depth: {quick_chars}→{detailed_chars}→{full_chars}→{ultra_chars} chars")
    
    def set_external_intelligence(self, intel: ExternalIntelligence):
        """Set or update external intelligence data."""
        self.external_intel = intel
        logger.info(f"AgenticScan: Loaded external intelligence - "
                   f"{len(intel.cve_findings)} CVEs, {len(intel.sast_findings)} SAST findings")
    
    def _build_intel_context_for_prompt(self, file_path: Optional[str] = None, include_full_context: bool = False) -> str:
        """Build external intelligence context string for AI prompts.
        
        Args:
            file_path: Optional file path to get file-specific SAST findings
            include_full_context: If True, includes full rich context (app description, diagrams, etc.)
        """
        if not self.external_intel:
            return ""
        
        parts = []
        
        # ========== RICH CONTEXT (App Description, Architecture, Attack Surface) ==========
        if include_full_context:
            # What Does This App Do
            if self.external_intel.app_description:
                parts.append("## 📋 APPLICATION OVERVIEW:")
                parts.append(self.external_intel.app_description)
            
            # Code Architecture Diagram
            if self.external_intel.architecture_diagram:
                parts.append("\n## 🏗️ CODE ARCHITECTURE:")
                parts.append("```mermaid")
                parts.append(self.external_intel.architecture_diagram)
                parts.append("```")
            
            # Security Findings Summary
            if self.external_intel.security_findings_summary:
                parts.append("\n## 🔒 SECURITY FINDINGS SUMMARY:")
                parts.append(self.external_intel.security_findings_summary)
            
            # Detailed Security Findings
            if self.external_intel.security_findings:
                parts.append("\n## 🚨 DETAILED SECURITY FINDINGS:")
                for finding in self.external_intel.security_findings[:15]:  # Top 15
                    severity = finding.get('severity', 'unknown').upper()
                    parts.append(f"- [{severity}] {finding.get('type', 'Unknown')}: "
                               f"{finding.get('file', '?')}:{finding.get('line', '?')} - "
                               f"{finding.get('message', '')[:150]}")
            
            # Codebase Map
            if self.external_intel.codebase_map:
                parts.append("\n## 🗺️ CODEBASE STRUCTURE:")
                parts.append(self.external_intel.codebase_map)
            
            # Codebase Diagram
            if self.external_intel.codebase_diagram:
                parts.append("\n## 📊 CODEBASE RELATIONSHIP DIAGRAM:")
                parts.append("```mermaid")
                parts.append(self.external_intel.codebase_diagram)
                parts.append("```")
            
            # Exploitability Assessment
            if self.external_intel.exploitability_assessment:
                parts.append("\n## ⚔️ EXPLOITABILITY ASSESSMENT:")
                parts.append(self.external_intel.exploitability_assessment)
            
            # Attack Surface Map
            if self.external_intel.attack_surface_map:
                parts.append("\n## 🎯 ATTACK SURFACE MAP:")
                parts.append("```mermaid")
                parts.append(self.external_intel.attack_surface_map)
                parts.append("```")
            
            # Attack Surface Summary
            if self.external_intel.attack_surface_summary:
                parts.append("\n## 🌐 ATTACK SURFACE SUMMARY:")
                parts.append(self.external_intel.attack_surface_summary)
            
            # Identified Entry Points
            if self.external_intel.identified_entry_points:
                parts.append("\n## 🚪 IDENTIFIED ENTRY POINTS:")
                for ep in self.external_intel.identified_entry_points[:20]:
                    auth_status = "🔓 NO AUTH" if not ep.get('auth', True) else "🔐 Auth required"
                    risk = ep.get('risk', 'medium').upper()
                    parts.append(f"- [{risk}] {ep.get('method', 'GET')} {ep.get('route', '/')} - {auth_status}")
        
        # ========== CVE/VULNERABILITY CONTEXT (always included) ==========
        high_cves = self.external_intel.get_high_severity_cves()
        if high_cves:
            parts.append("\n## ⚠️ KNOWN VULNERABILITIES IN DEPENDENCIES:")
            for cve in high_cves[:10]:  # Limit to top 10
                kev_flag = " 🔴 ACTIVELY EXPLOITED" if cve.get("in_kev") else ""
                epss = cve.get('epss_score', 0)
                epss_str = f"{epss:.1%}" if epss else "N/A"
                parts.append(f"- {cve.get('external_id')}: {cve.get('package')} "
                           f"(CVSS: {cve.get('cvss_score', 'N/A')}, "
                           f"EPSS: {epss_str}){kev_flag}")
                if cve.get("affected_functions"):
                    parts.append(f"  Affected functions: {', '.join(cve['affected_functions'][:5])}")
        
        # SAST findings for specific file
        if file_path:
            sast = self.external_intel.get_sast_findings_for_file(file_path)
            if sast:
                parts.append(f"\n## 🔍 SAST SCANNER FLAGS FOR THIS FILE:")
                for finding in sast[:5]:
                    parts.append(f"- Line {finding.get('line', '?')}: {finding.get('type')} "
                               f"({finding.get('severity')}) - {finding.get('message', '')[:100]}")
        
        # Files importing vulnerable packages
        if self.external_intel.vulnerable_import_files:
            parts.append("\n## 📦 FILES IMPORTING VULNERABLE PACKAGES:")
            for item in self.external_intel.vulnerable_import_files[:10]:
                parts.append(f"- {item.get('file')}: imports {item.get('package')} "
                           f"(affected by {item.get('cve')})")
        
        return "\n".join(parts) if parts else ""
    
    def _extract_security_relevant_sections(
        self,
        content: str,
        file_path: str,
        char_limit: int,
        analysis_depth: str
    ) -> str:
        """
        Smart extraction for large files - extracts security-relevant sections
        instead of just truncating from the top.
        
        Strategy:
        1. Always include imports/requires (show dependencies)
        2. Prioritize functions with security keywords
        3. Include SAST-flagged sections if available
        4. For remaining space, include high-value code sections
        """
        lines = content.split('\n')
        ext = os.path.splitext(file_path)[1].lower()
        
        # Security-relevant keywords to look for
        security_keywords = [
            'password', 'secret', 'token', 'auth', 'login', 'session', 'cookie',
            'exec', 'eval', 'system', 'shell', 'command', 'spawn', 'popen',
            'query', 'sql', 'select', 'insert', 'update', 'delete', 'where',
            'request', 'response', 'header', 'cookie', 'input', 'param',
            'file', 'open', 'read', 'write', 'path', 'upload', 'download',
            'encrypt', 'decrypt', 'hash', 'md5', 'sha', 'base64',
            'admin', 'root', 'sudo', 'privilege', 'permission', 'role',
            'api', 'endpoint', 'route', 'controller', 'handler',
            'serialize', 'deserialize', 'pickle', 'yaml.load', 'json.load',
            'redirect', 'url', 'href', 'src', 'include', 'require',
            'csrf', 'xss', 'injection', 'sanitize', 'escape', 'validate'
        ]
        
        sections = []
        current_budget = char_limit
        
        # SECTION 1: Always include first N lines (imports, config)
        # These reveal dependencies and setup
        header_lines = min(50, len(lines) // 10)  # First 10% or 50 lines
        header = '\n'.join(lines[:header_lines])
        if len(header) < current_budget * 0.2:  # Max 20% for header
            sections.append(("# File Header (imports/config):", header))
            current_budget -= len(header)
        
        # SECTION 2: Extract function/class definitions containing security keywords
        in_function = False
        function_start = 0
        function_content = []
        brace_depth = 0
        
        security_functions = []
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Detect function/method start (multi-language support)
            is_func_start = (
                ('def ' in line and ext == '.py') or
                ('function ' in line) or
                ('function(' in line) or
                ('=>' in line and ('const ' in line or 'let ' in line)) or
                ('public ' in line and '(' in line and '{' in line) or
                ('private ' in line and '(' in line and '{' in line) or
                ('protected ' in line and '(' in line and '{' in line)
            )
            
            if is_func_start and not in_function:
                in_function = True
                function_start = i
                function_content = [line]
                brace_depth = line.count('{') - line.count('}')
                # For Python, track indent instead
                if ext == '.py':
                    brace_depth = len(line) - len(line.lstrip())
            elif in_function:
                function_content.append(line)
                
                # Check for function end
                if ext == '.py':
                    # Python: function ends when indent returns to function level or less
                    current_indent = len(line) - len(line.lstrip()) if line.strip() else 999
                    if current_indent <= brace_depth and line.strip() and i > function_start:
                        # Function ended
                        func_text = '\n'.join(function_content[:-1])  # Exclude this line
                        if any(kw in func_text.lower() for kw in security_keywords):
                            security_functions.append((function_start, func_text))
                        in_function = False
                else:
                    # JS/PHP/Java: track braces
                    brace_depth += line.count('{') - line.count('}')
                    if brace_depth <= 0:
                        func_text = '\n'.join(function_content)
                        if any(kw in func_text.lower() for kw in security_keywords):
                            security_functions.append((function_start, func_text))
                        in_function = False
        
        # Sort by relevance (count of security keywords)
        def count_keywords(text):
            return sum(1 for kw in security_keywords if kw in text.lower())
        
        security_functions.sort(key=lambda x: count_keywords(x[1]), reverse=True)
        
        # Add top security-relevant functions within budget
        for line_num, func_text in security_functions:
            if len(func_text) < current_budget * 0.3:  # Each function max 30% of remaining
                sections.append((f"# Security-relevant section (line {line_num}):", func_text))
                current_budget -= len(func_text)
                if current_budget < char_limit * 0.2:  # Stop when 20% budget remaining
                    break
        
        # SECTION 3: If budget remains, add more code from the top
        if current_budget > char_limit * 0.2:
            remaining_content = content[len(header):current_budget + len(header)]
            if remaining_content.strip():
                sections.append(("# Additional code:", remaining_content))
        
        # Build final output
        output_parts = []
        total_size = sum(len(h) + len(c) for h, c in sections)
        
        output_parts.append(f"# [LARGE FILE: {len(lines)} lines, showing security-relevant sections]")
        output_parts.append(f"# Full file: {file_path}")
        output_parts.append("")
        
        for header_text, section_content in sections:
            output_parts.append(header_text)
            output_parts.append(section_content)
            output_parts.append("")
        
        result = '\n'.join(output_parts)
        
        # Final safety truncation
        if len(result) > char_limit:
            result = result[:char_limit - 50] + "\n\n# [Truncated - file too large]"
        
        return result
    
    # ========================================================================
    # Multi-Pass Smart File Selection
    # ========================================================================
    
    async def triage_files(
        self,
        project_path: str,
        all_files: List[str],
        progress_callback: Optional[callable] = None
    ) -> List[FileTriageResult]:
        """
        PASS 0: AI examines ALL file names and types to intelligently select
        which files to analyze further. Much smarter than pattern matching.
        
        NOW ENHANCED: Also considers external intelligence (CVEs, SAST findings)
        to prioritize files that import vulnerable dependencies or were flagged.
        
        Args:
            project_path: Root path of the project
            all_files: List of all file paths in the project
            
        Returns:
            List of FileTriageResult with priority assignments
        """
        if not self.client:
            logger.warning("AgenticScan: No LLM client for file triage, using heuristic selection")
            return self._heuristic_triage(project_path, all_files)
        
        # Build project structure summary for context (stored for later passes)
        self.project_structure = self._build_project_structure_summary(project_path, all_files)
        
        if progress_callback:
            progress_callback(f"🔍 AI analyzing {len(all_files)} file names for security relevance...")
        
        # Prepare file list with metadata
        file_entries = []
        for f in all_files:
            try:
                rel_path = os.path.relpath(f, project_path)
                ext = os.path.splitext(f)[1].lower()
                size = os.path.getsize(f) if os.path.exists(f) else 0
                file_entries.append({
                    "path": rel_path,
                    "extension": ext,
                    "size_kb": round(size / 1024, 1)
                })
            except Exception:
                continue
        
        # Process in batches of 200 file names per LLM call - WITH PARALLEL PROCESSING
        batch_size = 200
        max_parallel_triage = 4  # Run up to 4 triage batches in parallel
        all_triage_results = []
        
        # Create all batches
        batches = []
        for i in range(0, len(file_entries), batch_size):
            batch = file_entries[i:i + batch_size]
            batches.append((i, batch))
        
        if len(batches) <= 1:
            # Single batch - process directly
            if batches:
                if progress_callback:
                    progress_callback(f"🔍 Triaging {len(file_entries)} files...")
                results = await self._triage_batch(project_path, batches[0][1], progress_callback)
                all_triage_results.extend(results)
        else:
            # Multiple batches - process in parallel
            semaphore = asyncio.Semaphore(max_parallel_triage)
            
            async def triage_with_semaphore(batch_idx: int, batch: List[Dict]):
                async with semaphore:
                    if progress_callback:
                        start = batch_idx * batch_size + 1
                        end = min(start + len(batch) - 1, len(file_entries))
                        progress_callback(f"🔍 Triaging files {start}-{end} of {len(file_entries)} (parallel)")
                    return await self._triage_batch(project_path, batch, None)
            
            # Create tasks for all batches
            tasks = [
                triage_with_semaphore(idx, batch) 
                for idx, (_, batch) in enumerate(batches)
            ]
            
            # Execute in parallel
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect results
            for idx, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.warning(f"AgenticScan: Parallel triage batch failed: {result}")
                    # Fall back to heuristic for this failed batch
                    _, batch = batches[idx]
                    for file_info in batch:
                        full_path = os.path.join(project_path, file_info["path"])
                        heuristic = self._heuristic_single_file(full_path, file_info["path"])
                        all_triage_results.append(heuristic)
                elif result:
                    all_triage_results.extend(result)
        
        # Sort by security relevance
        all_triage_results.sort(key=lambda x: x.security_relevance, reverse=True)
        self.triage_results = all_triage_results
        
        # Log summary
        critical = len([r for r in all_triage_results if r.priority == "CRITICAL"])
        high = len([r for r in all_triage_results if r.priority == "HIGH"])
        medium = len([r for r in all_triage_results if r.priority == "MEDIUM"])
        logger.info(f"AgenticScan: File triage complete - {critical} critical, {high} high, {medium} medium priority files")
        
        return all_triage_results
    
    async def _triage_batch(
        self, 
        project_path: str, 
        batch: List[Dict], 
        progress_callback: Optional[callable] = None
    ) -> List[FileTriageResult]:
        """Process a single triage batch with LLM"""
        results = []
        
        # Build concise file listing
        files_text = "\n".join([
            f"{idx+1}. {f['path']} ({f['extension']}, {f['size_kb']}KB)"
            for idx, f in enumerate(batch)
        ])
        
        # Build external intelligence context
        intel_context = self._build_intel_context_for_prompt()
        intel_section = ""
        if intel_context:
            intel_section = f"""
## EXTERNAL INTELLIGENCE (CVEs, SAST findings):
{intel_context}

**USE THIS INFORMATION**: Prioritize files that:
- Import packages with known CVEs
- Were flagged by SAST scanners
- Handle data from vulnerable sources
"""
        
        # Mark files known to import vulnerable deps
        priority_files = set(self.external_intel.get_priority_files()) if self.external_intel else set()
        if priority_files:
            # Annotate files in the listing
            annotated_files = []
            for idx, f in enumerate(batch):
                annotation = ""
                if f['path'] in priority_files:
                    annotation = " ⚠️ [FLAGGED by SAST/CVE]"
                annotated_files.append(f"{idx+1}. {f['path']} ({f['extension']}, {f['size_kb']}KB){annotation}")
            files_text = "\n".join(annotated_files)
        
        prompt = f"""You are an objective security analyst RANKING files by security relevance for deeper analysis.
{intel_section}
## Files to Rank ({len(batch)} files):
{files_text}

## Your Task:
RANK each file by its likelihood of containing security-relevant code. Assign a security_score from 0.0 to 1.0.
The score determines analysis priority - higher scored files are analyzed first.

**Scoring Guide:**
- **0.9-1.0 (CRITICAL)**: Authentication, crypto, session handling, files importing packages with KNOWN CVEs
- **0.7-0.89 (HIGH)**: API endpoints, database access, file operations, command execution, SAST-flagged files
  Also: Architecture docs, API docs (reveal attack surfaces), config files with secrets
- **0.4-0.69 (MEDIUM)**: Business logic, services, validators, data handlers
- **0.2-0.39 (LOW)**: Supporting code, type definitions, constants, generic documentation
- **0.0-0.19 (SKIP)**: Pure test files, mocks, minified bundles, vendor code, image assets

Respond with JSON for ALL {len(batch)} files:
{{
  "triage": [
    {{"index": 1, "priority": "CRITICAL|HIGH|MEDIUM|LOW|SKIP", "security_score": 0.0-1.0, "reason": "brief reason"}}
  ]
}}

**CRITICAL INSTRUCTIONS**: 
- You MUST return an entry for EVERY file (all {len(batch)} files)
- Files marked with ⚠️ should score 0.7+ (HIGH or CRITICAL)
- The security_score is the PRIMARY ranking factor - be precise
- We will analyze the TOP files by score, so accurate ranking matters"""

        try:
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=4000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=120.0,
                operation_name="AgenticScan file triage"
            )
            
            text = response.text if response else ""
            if text:
                # Use safe JSON parser with repair capabilities
                result_data = _safe_json_parse(text, {"triage": []})
                
                # Track which files got AI triage
                triaged_indices = set()
                
                for item in result_data.get("triage", []):
                        idx = item.get("index", 1) - 1
                        if 0 <= idx < len(batch):
                            triaged_indices.add(idx)
                            file_info = batch[idx]
                            full_path = os.path.join(project_path, file_info["path"])
                            
                            triage_result = FileTriageResult(
                                file_path=full_path,
                                relative_path=file_info["path"],
                                file_type=file_info["extension"],
                                priority=item.get("priority", "MEDIUM"),
                                reasoning=item.get("reason", ""),
                                security_relevance=item.get("security_score", 0.5),
                                suggested_analysis_depth=self._priority_to_depth(item.get("priority", "MEDIUM"))
                            )
                            results.append(triage_result)
                
                # IMPORTANT: Fallback to heuristic for files NOT in AI response
                # This ensures we don't lose files when AI returns incomplete results
                for idx, file_info in enumerate(batch):
                    if idx not in triaged_indices:
                        full_path = os.path.join(project_path, file_info["path"])
                        heuristic = self._heuristic_single_file(full_path, file_info["path"])
                        results.append(heuristic)
                        
                if len(triaged_indices) < len(batch):
                    logger.warning(f"AgenticScan: AI only triaged {len(triaged_indices)}/{len(batch)} files, using heuristics for rest")
                            
        except Exception as e:
            logger.warning(f"AgenticScan: File triage batch failed: {e}")
            # Fall back to heuristic for this batch
            for file_info in batch:
                full_path = os.path.join(project_path, file_info["path"])
                heuristic = self._heuristic_single_file(full_path, file_info["path"])
                results.append(heuristic)
        
        return results
    
    def _priority_to_depth(self, priority: str) -> str:
        """Convert priority to suggested analysis depth"""
        mapping = {
            "CRITICAL": "full",
            "HIGH": "detailed",
            "MEDIUM": "quick",
            "LOW": "quick",
            "SKIP": "skip"
        }
        return mapping.get(priority.upper(), "quick")
    
    def _heuristic_triage(self, project_path: str, files: List[str]) -> List[FileTriageResult]:
        """Fallback heuristic-based triage when LLM is unavailable"""
        results = []
        for f in files:
            try:
                rel_path = os.path.relpath(f, project_path)
                results.append(self._heuristic_single_file(f, rel_path))
            except Exception:
                continue
        results.sort(key=lambda x: x.security_relevance, reverse=True)
        return results
    
    def _heuristic_single_file(self, full_path: str, rel_path: str) -> FileTriageResult:
        """Heuristic scoring for a single file"""
        path_lower = rel_path.lower()
        ext = os.path.splitext(full_path)[1].lower()
        
        # Score based on path patterns
        score = 0.3
        priority = "MEDIUM"
        reason = "Standard source file"
        
        # Critical patterns - auth, security, crypto
        if any(p in path_lower for p in ['auth', 'login', 'password', 'token', 'session', 'crypto', 'key', 'secret', 'credential']):
            score = 0.95
            priority = "CRITICAL"
            reason = "Authentication/security-related"
        # High patterns - entry points, data access, vulnerabilities
        elif any(p in path_lower for p in [
            'route', 'controller', 'handler', 'api', 'endpoint', 'upload', 'download', 
            'query', 'db', 'database', 'sql', 'exec', 'command', 'shell', 'include',
            'vulnerab', 'inject', 'xss', 'csrf', 'ssrf', 'lfi', 'rfi', 'brute',
            'index.php', 'main.php', 'app.php'  # Common PHP entry points
        ]):
            score = 0.8
            priority = "HIGH"
            reason = "Entry point or data access"
        # High patterns - security-related source code (PHP files with risky names)
        elif ext == '.php' and any(p in path_lower for p in ['source', 'low', 'medium', 'high', 'impossible']):
            score = 0.75
            priority = "HIGH"
            reason = "Security difficulty level source"
        # Medium patterns - business logic
        elif any(p in path_lower for p in ['service', 'manager', 'util', 'helper', 'validator', 'model', 'view']):
            score = 0.5
            priority = "MEDIUM"
            reason = "Business logic"
        # For PHP files not matching other patterns, default to MEDIUM (not SKIP)
        elif ext == '.php':
            score = 0.4
            priority = "MEDIUM"
            reason = "PHP source file"
        # Low/Skip patterns - tests, generated, vendor
        elif any(p in path_lower for p in ['test', 'spec', 'mock', '__test__', '.min.', 'bundle', 'dist', 'generated', 'vendor/', 'node_modules/']):
            score = 0.1
            priority = "SKIP"
            reason = "Test/generated/vendor code"
        
        return FileTriageResult(
            file_path=full_path,
            relative_path=rel_path,
            file_type=ext,
            priority=priority,
            reasoning=reason,
            security_relevance=score,
            suggested_analysis_depth=self._priority_to_depth(priority)
        )

    async def multi_pass_analysis(
        self,
        project_path: str,
        triage_results: List[FileTriageResult],
        progress_callback: Optional[callable] = None,
        phase_callback: Optional[callable] = None
    ) -> Tuple[List[MultiPassAnalysisResult], List[str]]:
        """
        PASS 1-4: Progressive multi-pass file analysis.
        
        Pass 1: Initial analysis of ~180 files (quick scan)
        Pass 2: Focused analysis of ~60 most interesting files
        Pass 3: Deep analysis of ~22 highest-priority files
        Pass 4: Ultra-deep analysis of ~7 large files (>50K chars only)
        
        Returns:
            Tuple of (all pass results, files selected for deep analysis)
        """
        all_results: List[MultiPassAnalysisResult] = []
        
        # Pass 0 (triage) RANKS files - it doesn't exclude them
        # Sort all files by security_relevance score (highest first)
        # Even "SKIP" priority files get a low score, they're just ranked lower
        ranked_files = sorted(triage_results, key=lambda x: x.security_relevance, reverse=True)
        
        # PASS 1: Initial analysis of top N files by triage score
        # This is where we actually READ the code and make decisions
        pass1_count = min(self.pass1_limit, len(ranked_files))
        pass1_files = ranked_files[:pass1_count]
        
        # Update phase for Pass 1
        if phase_callback:
            phase_callback(ScanPhase.INITIAL_ANALYSIS)
        
        if progress_callback:
            progress_callback(f"📋 Pass 1: Initial scan of {pass1_count} files...")
        
        pass1_results = await self._run_analysis_pass(
            project_path=project_path,
            files=pass1_files,
            pass_number=1,
            analysis_depth="quick",
            chunk_size=50,
            progress_callback=progress_callback
        )
        all_results.extend(pass1_results)
        
        # Sort by security score to find most interesting files
        pass1_results.sort(key=lambda x: x.security_score, reverse=True)
        
        # PASS 2: Focused analysis of TOP N files from Pass 1
        # Take the highest-scoring files from Pass 1, not filtered by threshold
        pass2_count = min(self.pass2_limit, len(pass1_results))
        pass2_candidates = pass1_results[:pass2_count]
        
        if pass2_count > 0:
            # Update phase for Pass 2
            if phase_callback:
                phase_callback(ScanPhase.FOCUSED_ANALYSIS)
            
            if progress_callback:
                progress_callback(f"🔬 Pass 2: Focused analysis of top {pass2_count} files from Pass 1...")
            
            # Get the FileTriageResults for pass2 files
            # Use normalized paths for matching to handle path format differences
            pass2_paths = {os.path.normpath(r.file_path) for r in pass2_candidates}
            pass2_triage = [t for t in triage_results if os.path.normpath(t.file_path) in pass2_paths]
            
            # If path matching failed, fall back to creating triage results from pass1 results
            if len(pass2_triage) < pass2_count * 0.5:  # Less than 50% matched
                logger.warning(f"AgenticScan: Path matching only found {len(pass2_triage)}/{pass2_count} files, using direct approach")
                # Create FileTriageResults from the pass1 candidates directly
                pass2_triage = []
                for r in pass2_candidates:
                    # Find matching triage result or create a minimal one
                    matching = next((t for t in triage_results if os.path.normpath(t.file_path) == os.path.normpath(r.file_path)), None)
                    if matching:
                        pass2_triage.append(matching)
                    else:
                        # Create minimal triage result
                        pass2_triage.append(FileTriageResult(
                            file_path=r.file_path,
                            relative_path=os.path.basename(r.file_path),
                            file_type=os.path.splitext(r.file_path)[1],
                            priority="HIGH",
                            reasoning="Selected from Pass 1 results",
                            security_relevance=r.security_score / 10.0,
                            suggested_analysis_depth="detailed"
                        ))
            
            pass2_results = await self._run_analysis_pass(
                project_path=project_path,
                files=pass2_triage,
                pass_number=2,
                analysis_depth="detailed",
                chunk_size=10,
                progress_callback=progress_callback
            )
            all_results.extend(pass2_results)
            
            # Sort for pass 3 selection
            pass2_results.sort(key=lambda x: x.security_score, reverse=True)
        else:
            pass2_results = []
        
        # PASS 3: Deep analysis of TOP N files from Pass 2 (or Pass 1 if Pass 2 empty)
        # Take the highest-scoring files, not filtered by threshold
        source_for_pass3 = pass2_results if pass2_results else pass1_results
        pass3_count = min(self.pass3_limit, len(source_for_pass3))
        pass3_candidates = source_for_pass3[:pass3_count]
        
        deep_analysis_files = []
        if pass3_count > 0:
            # Update phase for Pass 3
            if phase_callback:
                phase_callback(ScanPhase.DEEP_ANALYSIS)
            
            if progress_callback:
                progress_callback(f"🎯 Pass 3: Deep analysis of top {pass3_count} files...")
            
            # Use normalized paths for matching
            pass3_paths = {os.path.normpath(r.file_path) for r in pass3_candidates}
            pass3_triage = [t for t in triage_results if os.path.normpath(t.file_path) in pass3_paths]
            
            # If path matching failed, fall back to creating triage results from candidates
            if len(pass3_triage) < pass3_count * 0.5:  # Less than 50% matched
                logger.warning(f"AgenticScan: Pass 3 path matching only found {len(pass3_triage)}/{pass3_count} files, using direct approach")
                pass3_triage = []
                for r in pass3_candidates:
                    matching = next((t for t in triage_results if os.path.normpath(t.file_path) == os.path.normpath(r.file_path)), None)
                    if matching:
                        pass3_triage.append(matching)
                    else:
                        pass3_triage.append(FileTriageResult(
                            file_path=r.file_path,
                            relative_path=os.path.basename(r.file_path),
                            file_type=os.path.splitext(r.file_path)[1],
                            priority="CRITICAL",
                            reasoning="Selected from Pass 2 results",
                            security_relevance=r.security_score / 10.0,
                            suggested_analysis_depth="full"
                        ))
            
            deep_analysis_files = [t.file_path for t in pass3_triage]
            
            pass3_results = await self._run_analysis_pass(
                project_path=project_path,
                files=pass3_triage,
                pass_number=3,
                analysis_depth="full",
                chunk_size=3,  # Smaller chunks for deeper analysis
                progress_callback=progress_callback
            )
            all_results.extend(pass3_results)
        
        # ============ PASS 4: Ultra-deep analysis of large files ============
        # Only analyze files that are larger than 50K characters
        pass4_count = 0
        pass4_files = []
        
        # Update phase for Pass 4
        if phase_callback:
            phase_callback(ScanPhase.ULTRA_ANALYSIS)
        
        if progress_callback:
            progress_callback("🚀 Pass 4: Identifying large files for ultra-deep analysis...")
        
        # Find files that are large enough to warrant ultra-deep analysis
        large_file_candidates = []
        
        # Check all files that were analyzed in Pass 3 (or Pass 2 if no Pass 3)
        files_to_check = pass3_triage if pass3_triage else pass2_triage
        
        for triage_result in files_to_check:
            file_path = triage_result.file_path
            full_path = os.path.join(project_path, file_path) if not os.path.isabs(file_path) else file_path
            
            try:
                if os.path.exists(full_path):
                    file_size = os.path.getsize(full_path)
                    # Estimate character count (roughly 1 byte per char for most code files)
                    # But let's read the actual file to get accurate char count
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            char_count = len(content)
                    except Exception:
                        char_count = file_size  # Fallback to byte count
                    
                    if char_count > self.pass4_min_size:
                        # This file qualifies for ultra-deep analysis
                        large_file_candidates.append({
                            'triage': triage_result,
                            'char_count': char_count,
                            'security_score': triage_result.security_relevance
                        })
                        logger.info(f"Pass 4 candidate: {file_path} ({char_count:,} chars, score: {triage_result.security_relevance})")
            except Exception as e:
                logger.warning(f"Error checking file size for {file_path}: {e}")
        
        if large_file_candidates:
            # Sort by security_relevance score (descending), then by size (descending)
            large_file_candidates.sort(key=lambda x: (x['security_score'], x['char_count']), reverse=True)
            
            # Take top N files for ultra-deep analysis
            pass4_candidates = large_file_candidates[:self.pass4_limit]
            pass4_count = len(pass4_candidates)
            
            if progress_callback:
                progress_callback(f"Pass 4: Ultra-deep analysis of {pass4_count} large files (>{self.pass4_min_size:,} chars)...")
            
            logger.info(f"AgenticScan: Pass 4 - Ultra-deep analysis of {pass4_count} large files")
            for candidate in pass4_candidates:
                logger.info(f"  - {candidate['triage'].file_path}: {candidate['char_count']:,} chars, score: {candidate['security_score']}")
            
            # Create triage results for Pass 4
            pass4_triage = [c['triage'] for c in pass4_candidates]
            pass4_files = [t.file_path for t in pass4_triage]
            
            pass4_results = await self._run_analysis_pass(
                project_path=project_path,
                files=pass4_triage,
                pass_number=4,
                analysis_depth="ultra",
                chunk_size=2,  # Even smaller chunks for ultra-deep analysis
                progress_callback=progress_callback
            )
            all_results.extend(pass4_results)
        else:
            if progress_callback:
                progress_callback("Pass 4: No files large enough for ultra-deep analysis (>{:,} chars)".format(self.pass4_min_size))
            logger.info(f"AgenticScan: Pass 4 - No files larger than {self.pass4_min_size:,} chars found")
        
        self.multi_pass_results = all_results
        
        # Log summary
        logger.info(f"AgenticScan: Multi-pass analysis complete - "
                   f"Pass 1: {pass1_count}, Pass 2: {pass2_count}, Pass 3: {pass3_count}, Pass 4: {pass4_count}")
        
        return all_results, deep_analysis_files + pass4_files

    async def _run_analysis_pass(
        self,
        project_path: str,
        files: List[FileTriageResult],
        pass_number: int,
        analysis_depth: str,
        chunk_size: int,
        progress_callback: Optional[callable] = None,
        max_parallel: int = 3  # Limit concurrent API calls to avoid rate limits
    ) -> List[MultiPassAnalysisResult]:
        """Run a single analysis pass on a set of files with parallel processing"""
        
        # Create all batches
        batches = []
        for i in range(0, len(files), chunk_size):
            batch = files[i:i + chunk_size]
            batches.append((i, batch))
        
        if len(batches) <= 1:
            # Single batch - no need for parallelization
            if batches:
                if progress_callback:
                    progress_callback(f"Pass {pass_number}: Analyzing {len(files)} files...")
                return await self._analyze_files_batch(
                    project_path=project_path,
                    files=batches[0][1],
                    pass_number=pass_number,
                    analysis_depth=analysis_depth
                )
            return []
        
        # Process batches in parallel with concurrency limit
        all_results = []
        semaphore = asyncio.Semaphore(max_parallel)
        
        async def process_batch_with_semaphore(batch_idx: int, batch: List[FileTriageResult]):
            async with semaphore:
                if progress_callback:
                    start = batch_idx * chunk_size + 1
                    end = min(start + len(batch) - 1, len(files))
                    progress_callback(f"Pass {pass_number}: Analyzing files {start}-{end} of {len(files)} (parallel)")
                
                return await self._analyze_files_batch(
                    project_path=project_path,
                    files=batch,
                    pass_number=pass_number,
                    analysis_depth=analysis_depth
                )
        
        # Create tasks for all batches
        tasks = [
            process_batch_with_semaphore(idx, batch) 
            for idx, (_, batch) in enumerate(batches)
        ]
        
        # Execute in parallel and gather results
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful results
        for result in batch_results:
            if isinstance(result, Exception):
                logger.warning(f"AgenticScan: Parallel batch failed: {result}")
            elif result:
                all_results.extend(result)
        
        return all_results
    
    async def _analyze_files_batch(
        self,
        project_path: str,
        files: List[FileTriageResult],
        pass_number: int,
        analysis_depth: str
    ) -> List[MultiPassAnalysisResult]:
        """Analyze a batch of files in a single LLM call"""
        if not self.client:
            return [
                MultiPassAnalysisResult(
                    file_path=f.file_path,
                    pass_number=pass_number,
                    analysis_depth=analysis_depth,
                    findings=[],
                    entry_points_found=0,
                    potential_vulnerabilities=0,
                    requires_deeper_analysis=False,
                    security_score=f.security_relevance * 10,
                    key_observations=[]
                )
                for f in files
            ]
        
        # Read file contents based on analysis depth
        files_content = []
        for f in files:
            try:
                with open(f.file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                    content = fh.read()
                    char_limit = self.content_limits.get(analysis_depth, 2000)
                    
                    # Smart handling for large files
                    if len(content) > char_limit:
                        content = self._extract_security_relevant_sections(
                            content, 
                            f.file_path, 
                            char_limit,
                            analysis_depth
                        )
                    
                    files_content.append({
                        "path": f.relative_path,
                        "full_path": f.file_path,
                        "content": content,
                        "priority": f.priority,
                        "was_truncated": len(content) >= char_limit * 0.95  # Flag if near limit
                    })
            except Exception as e:
                logger.debug(f"Could not read {f.file_path}: {e}")
                continue
        
        if not files_content:
            return []
        
        # Build analysis prompt based on depth
        depth_instruction = {
            "quick": "Do a QUICK scan - identify obvious security patterns, entry points, and dangerous functions. Be efficient.",
            "detailed": "Do a DETAILED analysis - trace data flows, identify potential vulnerabilities, check for missing sanitization.",
            "full": "Do a COMPREHENSIVE security audit - examine every function, trace all data flows, identify all potential attack vectors.",
            "ultra": "Do an ULTRA-DEEP security audit - this is a LARGE file requiring exhaustive analysis. Examine EVERY function in detail, trace ALL data flows completely, identify ALL potential attack vectors, analyze complex logic chains, look for subtle race conditions, check all error handling paths, verify all authentication/authorization checks, and identify any architectural security concerns. This file's size warrants extra scrutiny."
        }.get(analysis_depth, "quick")
        
        # Include project structure context (helps LLM understand architecture)
        project_context = ""
        if self.project_structure:
            project_context = f"\n{self.project_structure}\n"
        
        # Build external intelligence context - include FULL context for Pass 2, 3, and 4
        include_full = analysis_depth in ("detailed", "full", "ultra")  # Pass 2, 3, and 4 get full context
        intel_context = self._build_intel_context_for_prompt(include_full_context=include_full)
        
        # Add per-file SAST context
        if self.external_intel:
            file_intel_parts = []
            for fc in files_content:
                file_sast = self.external_intel.get_sast_findings_for_file(fc["path"])
                if file_sast:
                    file_intel_parts.append(f"**{fc['path']}** - SAST flagged: {', '.join(f['type'] for f in file_sast[:3])}")
            
            if file_intel_parts:
                intel_context += "\n\n## 🔍 FILE-SPECIFIC SAST FINDINGS:\n" + "\n".join(file_intel_parts)
        
        files_text = ""
        for idx, fc in enumerate(files_content):
            # Add per-file intelligence annotations
            file_flags = []
            if self.external_intel:
                sast = self.external_intel.get_sast_findings_for_file(fc["path"])
                if sast:
                    file_flags.append(f"SAST:{len(sast)} findings")
                for vuln in self.external_intel.vulnerable_import_files:
                    if vuln.get("file") == fc["path"]:
                        file_flags.append(f"imports vulnerable {vuln.get('package')}")
            
            flag_str = f" ⚠️ [{', '.join(file_flags)}]" if file_flags else ""
            
            files_text += f"""
### File {idx + 1}: {fc['path']} (Priority: {fc['priority']}){flag_str}
```
{fc['content']}
```
"""
        
        # Detect if we have documentation/config files that need different analysis
        doc_extensions = {'.md', '.rst', '.txt', '.yaml', '.yml', '.json', '.toml', '.xml', '.properties'}
        has_docs = any(Path(fc['path']).suffix.lower() in doc_extensions for fc in files_content)
        
        doc_guidance = ""
        if has_docs:
            doc_guidance = """

## DOCUMENTATION & CONFIG FILE ANALYSIS:
For .md, .rst, .txt, .yaml, .yml, .json, .xml, .toml, .properties files, look for:
- **Architecture info**: System diagrams, component descriptions that reveal attack surfaces
- **API documentation**: Endpoints, parameters, authentication methods
- **Hardcoded secrets**: API keys, passwords, tokens (even in examples)
- **Default credentials**: admin/admin, test passwords in examples
- **Infrastructure details**: Database names, internal hostnames, cloud resources
- **Deployment configs**: Ports, exposed services, security settings
- **Database schemas**: Tables, columns that reveal data model
- **Environment variables**: List of expected secrets/configs
These files don't have "entry points" in the code sense, but they can reveal critical security information.
"""
        
        prompt = f"""You are an objective code reviewer performing PASS {pass_number} ({analysis_depth.upper()}) security analysis.

{depth_instruction}
{project_context}{intel_context}{doc_guidance}
## Files to Analyze:
{files_text}

## For each file, objectively assess:
1. Entry points (where external data enters) - if any exist
2. Sensitive operations (database, file system, commands) - if any exist
3. Whether input validation/sanitization is present or missing
4. **If file imports vulnerable packages**: Check if the VULNERABLE FUNCTIONS are actually called
5. **If file was SAST-flagged**: Verify or refute the SAST findings
6. **For documentation/config files**: Architecture details, hardcoded secrets, default credentials
7. Any actual security concerns you can identify with evidence

## Response Format (JSON):
{{
  "files": [
    {{
      "index": 1,
      "security_score": 0-10,
      "requires_deeper_analysis": true/false,
      "entry_points": ["list of entry points if found, empty array if none"],
      "vulnerable_dep_usage": ["pkg.function() called at line X - CVE-XXXX applies/does not apply"],
      "sast_verification": ["SAST finding X is TRUE_POSITIVE/FALSE_POSITIVE because..."],
      "potential_vulns": [
        {{"type": "Type", "severity": "HIGH|MEDIUM|LOW", "location": "line X", "description": "specific evidence"}}
      ],
      "observations": ["factual observations about the code"]
    }}
  ]
}}

## Scoring Guidelines (be objective):
- 0-2: No security-relevant code or all inputs properly validated
- 3-4: Has external interfaces but appears to handle them safely
- 5-6: Some areas that could benefit from review, minor concerns
- 7-8: Clear security issues identified with specific evidence
- 9-10: Critical, confirmed vulnerabilities with exploit path

**IMPORTANT**: 
- It is acceptable to report score 0-2 if the code is secure. Do NOT inflate scores.
- Empty potential_vulns array is valid for secure code.
- If a file imports a vulnerable package but doesn't use the affected functions, note that explicitly.
- SAST findings may be false positives - verify with actual code analysis."""

        try:
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.2,
                        max_output_tokens=4000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=120.0,
                operation_name=f"AgenticScan Pass {pass_number} analysis"
            )
            
            results = []
            returned_indices = set()  # Track which files the AI returned results for
            text = response.text if response else ""
            if text:
                # Use safe JSON parser with repair capabilities
                result = _safe_json_parse(text, {"files": []})
                for item in result.get("files", []):
                        idx = item.get("index", 1) - 1
                        if 0 <= idx < len(files_content):
                            fc = files_content[idx]
                            returned_indices.add(idx)
                            
                            results.append(MultiPassAnalysisResult(
                                file_path=fc["full_path"],
                                pass_number=pass_number,
                                analysis_depth=analysis_depth,
                                findings=item.get("potential_vulns", []),
                                entry_points_found=len(item.get("entry_points", [])),
                                potential_vulnerabilities=len(item.get("potential_vulns", [])),
                                requires_deeper_analysis=item.get("requires_deeper_analysis", False),
                                security_score=item.get("security_score", 5.0),
                                key_observations=item.get("observations", [])
                            ))
            
            # IMPORTANT: Create fallback results for files the AI didn't return
            # This ensures all files are represented in pass results for subsequent passes
            missing_count = 0
            for idx, fc in enumerate(files_content):
                if idx not in returned_indices:
                    missing_count += 1
                    # Create a minimal result for files the AI skipped
                    # Use a mid-range score (5.0) to keep them in consideration
                    results.append(MultiPassAnalysisResult(
                        file_path=fc["full_path"],
                        pass_number=pass_number,
                        analysis_depth=analysis_depth,
                        findings=[],
                        entry_points_found=0,
                        potential_vulnerabilities=0,
                        requires_deeper_analysis=True,  # Mark for deeper analysis since we don't know
                        security_score=5.0,  # Mid-range score to keep in consideration
                        key_observations=["AI did not return explicit analysis - included for completeness"]
                    ))
            
            if missing_count > 0:
                logger.warning(f"AgenticScan: Pass {pass_number} AI only returned {len(returned_indices)}/{len(files_content)} files, created fallback for {missing_count}")
            
            return results
            
        except Exception as e:
            logger.warning(f"AgenticScan: Pass {pass_number} batch analysis failed: {e}")
            return []

    async def synthesize_findings(
        self,
        multi_pass_results: List[MultiPassAnalysisResult],
        vulnerabilities: List[AgenticVulnerability],
        progress_callback: Optional[callable] = None
    ) -> SynthesisResult:
        """
        SYNTHESIS PASS: AI reviews all findings from all passes and creates
        a comprehensive security assessment, identifying cross-file attack
        chains and prioritizing the most critical issues.
        """
        if progress_callback:
            progress_callback("🧠 Synthesizing findings across all analysis passes...")
        
        # Group results by pass
        pass1_results = [r for r in multi_pass_results if r.pass_number == 1]
        pass2_results = [r for r in multi_pass_results if r.pass_number == 2]
        pass3_results = [r for r in multi_pass_results if r.pass_number == 3]
        
        # Prepare summary for synthesis
        high_score_files = [r for r in multi_pass_results if r.security_score >= 6.0]
        all_observations = []
        all_entry_points = []
        all_potential_vulns = []
        
        for r in multi_pass_results:
            all_observations.extend(r.key_observations)
            all_entry_points.extend([f"{r.file_path}: {ep}" for ep in range(r.entry_points_found)])
            all_potential_vulns.extend(r.findings)
        
        if not self.client:
            # Return basic synthesis without LLM
            return SynthesisResult(
                total_files_triaged=len(self.triage_results),
                files_analyzed_initial=len(pass1_results),
                files_analyzed_focused=len(pass2_results),
                files_analyzed_deep=len(pass3_results),
                cross_file_flows=[],
                combined_vulnerabilities=vulnerabilities,
                attack_chains=[],
                overall_security_assessment="LLM unavailable for synthesis",
                key_recommendations=[]
            )
        
        # Build FULL external intelligence context (includes app description, architecture, attack surface)
        full_intel_context = self._build_intel_context_for_prompt(include_full_context=True)
        
        # Build synthesis prompt
        findings_summary = f"""
## Analysis Summary:
- Total files triaged: {len(self.triage_results)}
- Pass 1 (Quick scan): {len(pass1_results)} files
- Pass 2 (Focused): {len(pass2_results)} files  
- Pass 3 (Deep): {len(pass3_results)} files
- High-risk files found: {len(high_score_files)}
- Total potential vulnerabilities: {len(all_potential_vulns)}
- Confirmed vulnerabilities: {len(vulnerabilities)}

## High-Risk Files:
{chr(10).join([f"- {r.file_path} (score: {r.security_score})" for r in high_score_files[:20]])}

## Key Observations from Analysis:
{chr(10).join([f"- {obs}" for obs in all_observations[:40]])}

## Potential Vulnerabilities Found:
{chr(10).join([f"- {v.get('type', 'Unknown')}: {v.get('description', '')[:150]}" for v in all_potential_vulns[:25]])}
"""

        prompt = f"""You are an expert security analyst synthesizing findings from a comprehensive multi-pass code review.

{full_intel_context}

{findings_summary}

## Your Task:
1. Review all findings considering the APPLICATION CONTEXT (what does the app do, its architecture)
2. Consider the ATTACK SURFACE and ENTRY POINTS identified above
3. **Correlate AI findings with CVE/SAST data** - do AI findings match known issues?
4. Identify cross-file attack chains considering the codebase map and relationships
5. Provide an honest overall security assessment
6. Give actionable, prioritized recommendations

## Response Format (JSON):
{{
  "overall_assessment": "honest summary considering app context - can be positive if secure",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|MINIMAL",
  "cve_correlation": [
    {{"cve": "CVE-XXXX", "verified_in_code": true/false, "details": "whether vulnerable code paths exist given the attack surface"}}
  ],
  "attack_chains": [
    {{"name": "chain name", "files": ["file1", "file2"], "entry_point": "how attacker enters", "description": "how attack flows through the architecture", "severity": "HIGH"}}
  ],
  "priority_issues": [
    {{"issue": "description", "severity": "HIGH", "affected_component": "which part of architecture", "remediation": "what to fix"}}
  ],
  "patterns_found": ["security patterns identified - can be empty if none"],
  "recommendations": ["actionable recommendations prioritized by impact"]
}}

**IMPORTANT**: 
- If no significant vulnerabilities were found, say so clearly. A "MINIMAL" risk level is valid.
- Empty arrays for attack_chains, priority_issues, and patterns_found are acceptable.
- Do NOT manufacture issues. If the codebase appears secure, report that finding.
- For CVE correlation: just because a package has a CVE doesn't mean the app is vulnerable - verify the vulnerable functions are actually used.
- Consider the architecture and attack surface when assessing real-world exploitability.
- Recommendations should be specific and reference the application's architecture."""

        try:
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.3,
                        max_output_tokens=4000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=120.0,
                operation_name="AgenticScan synthesis"
            )
            
            text = response.text if response else ""
            attack_chains = []
            recommendations = []
            assessment = "Analysis complete"
            
            if text:
                # Use safe JSON parser with repair capabilities
                result = _safe_json_parse(text, {})
                assessment = result.get("overall_assessment", assessment)
                attack_chains = result.get("attack_chains", [])
                recommendations = result.get("recommendations", [])
            
            return SynthesisResult(
                total_files_triaged=len(self.triage_results),
                files_analyzed_initial=len(pass1_results),
                files_analyzed_focused=len(pass2_results),
                files_analyzed_deep=len(pass3_results),
                cross_file_flows=[],
                combined_vulnerabilities=vulnerabilities,
                attack_chains=attack_chains,
                overall_security_assessment=assessment,
                key_recommendations=recommendations
            )
            
        except Exception as e:
            logger.warning(f"AgenticScan: Synthesis failed: {e}")
            return SynthesisResult(
                total_files_triaged=len(self.triage_results),
                files_analyzed_initial=len(pass1_results),
                files_analyzed_focused=len(pass2_results),
                files_analyzed_deep=len(pass3_results),
                cross_file_flows=[],
                combined_vulnerabilities=vulnerabilities,
                attack_chains=[],
                overall_security_assessment=f"Synthesis error: {e}",
                key_recommendations=[]
            )

    async def analyze_chunks(
        self, 
        chunks: List[CodeChunk],
        progress_callback: Optional[callable] = None,
        max_parallel: int = 3  # Limit concurrent API calls
    ) -> Tuple[List[EntryPoint], List[DangerousSink]]:
        """
        Analyze chunks to identify entry points and dangerous sinks.
        Uses batched LLM calls with parallel processing for efficiency.
        """
        self.chunks = {c.id: c for c in chunks}
        entry_points = []
        sinks = []
        
        # Process chunks in batches (smaller batches = more reliable API calls)
        batch_size = 5
        
        # Create all batches
        batches = []
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]
            batches.append((i, batch))
        
        if len(batches) <= 1:
            # Single batch - process directly
            if batches:
                if progress_callback:
                    progress_callback(f"Analyzing {len(chunks)} chunks...")
                batch_results = await _retry_with_backoff(
                    lambda b=batches[0][1]: self._analyze_batch(b),
                    max_retries=3,
                    base_delay=2.0
                )
                self._process_batch_results(batch_results, entry_points, sinks)
        else:
            # Multiple batches - process in parallel with semaphore
            semaphore = asyncio.Semaphore(max_parallel)
            
            async def analyze_with_semaphore(batch_idx: int, batch: List[CodeChunk]):
                async with semaphore:
                    if progress_callback:
                        start = batch_idx * batch_size + 1
                        end = min(start + len(batch) - 1, len(chunks))
                        progress_callback(f"Analyzing chunks {start}-{end} of {len(chunks)} (parallel)")
                    
                    return await _retry_with_backoff(
                        lambda b=batch: self._analyze_batch(b),
                        max_retries=3,
                        base_delay=2.0
                    )
            
            # Create tasks for all batches
            tasks = [
                analyze_with_semaphore(idx, batch) 
                for idx, (_, batch) in enumerate(batches)
            ]
            
            # Execute in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"AgenticScan: Parallel chunk analysis failed: {result}")
                elif result:
                    self._process_batch_results(result, entry_points, sinks)
        
        self.entry_points = entry_points
        self.sinks = sinks
        
        return entry_points, sinks
    
    def _process_batch_results(
        self, 
        batch_results: Dict[str, Dict], 
        entry_points: List[EntryPoint], 
        sinks: List[DangerousSink]
    ):
        """Process results from a batch analysis"""
        for chunk_id, result in batch_results.items():
            chunk = self.chunks.get(chunk_id)
            if not chunk:
                continue
            chunk.analysis_status = "complete"
            chunk.analysis_result = result
            
            # Extract entry points
            for ep_data in result.get("entry_points", []):
                entry_point = self._create_entry_point(chunk, ep_data)
                entry_points.append(entry_point)
            
            # Extract sinks
            for sink_data in result.get("sinks", []):
                sink = self._create_sink(chunk, sink_data)
                sinks.append(sink)
    
    async def _analyze_batch(self, chunks: List[CodeChunk]) -> Dict[str, Dict]:
        """Analyze a batch of chunks with a single LLM call"""
        if not self.client:
            return {c.id: {"entry_points": [], "sinks": []} for c in chunks}
        
        # Build prompt with all chunks (truncate to reduce payload)
        chunks_text = ""
        for chunk in chunks:
            # Truncate content to 1200 chars for efficiency
            truncated_content = chunk.content[:1200]
            chunks_text += f"""
=== CHUNK {chunk.id} ===
File: {chunk.file_path}
Lines: {chunk.start_line}-{chunk.end_line}
Language: {chunk.language}

```{chunk.language}
{truncated_content}
```

"""
        
        prompt = f"""Objectively analyze these code chunks to identify WHERE data enters and WHERE sensitive operations occur.

{chunks_text}

For each chunk, identify IF PRESENT:

1. ENTRY POINTS (external data sources) - only if they exist:
   - HTTP request parameters, form data, headers, cookies
   - File uploads, WebSocket messages
   - CLI arguments, environment variables used for user data

2. SENSITIVE OPERATIONS - only if they exist AND handle external data unsafely:
   - Raw SQL queries (NOT parameterized queries - those are safe)
   - OS command execution with external input
   - File operations with unvalidated paths
   - eval/exec with external data
   - Deserialization of untrusted data

Return JSON:
{{
  "<chunk_id>": {{
    "entry_points": [],
    "sinks": []
  }}
}}

**CRITICAL GUIDELINES**:
- Empty arrays are expected and correct if no entry points or sinks exist
- Parameterized queries (using ?, $1, :param) are SAFE - do not report as sinks
- ORM methods (query.filter, Model.objects) are generally SAFE
- Framework-provided auth/session handling is generally SAFE
- Only report sinks where user data could actually reach them unsanitized
- When in doubt, do NOT report it - we want to minimize false positives

Entry point format (only if found):
{{"line": N, "type": "type", "variable": "name", "framework": "framework", "http_method": "METHOD or null", "route": "path or null"}}

Sink format (only if genuinely concerning):
{{"line": N, "type": "type", "function": "name", "vuln_type": "type", "severity": "level", "cwe": "CWE-XXX"}}"""

        try:
            from google.genai import types
            
            # Use retry_with_backoff which now includes timeout handling
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=3000  # Reduced for faster responses
                    )
                )
            
            response = await _retry_with_backoff(
                make_request, 
                max_retries=3, 
                base_delay=2.0,
                timeout_seconds=120.0,
                operation_name="AgenticScan batch analysis"
            )
            
            text = response.text
            if text:
                # Use safe JSON parser with repair capabilities
                result = _safe_json_parse(text, {c.id: {"entry_points": [], "sinks": []} for c in chunks})
                if result:
                    return result
            else:
                logger.warning("AgenticScan: Empty response from LLM in batch analysis")
            
        except Exception as e:
            logger.error(f"AgenticScan: Batch analysis failed after retries: {e}")
        
        return {c.id: {"entry_points": [], "sinks": []} for c in chunks}
    
    def _create_entry_point(self, chunk: CodeChunk, data: Dict) -> EntryPoint:
        """Create an EntryPoint from analysis data"""
        lines = chunk.content.split('\n')
        line_idx = data.get("line", 1) - chunk.start_line
        code_snippet = lines[line_idx] if 0 <= line_idx < len(lines) else ""
        
        return EntryPoint(
            id=hashlib.md5(f"{chunk.id}:{data.get('line')}".encode()).hexdigest()[:10],
            chunk_id=chunk.id,
            file_path=chunk.file_path,
            line_number=data.get("line", chunk.start_line),
            entry_type=data.get("type", "unknown"),
            variable_name=data.get("variable", ""),
            code_snippet=code_snippet,
            framework=data.get("framework", "unknown"),
            http_method=data.get("http_method"),
            route_path=data.get("route")
        )
    
    def _create_sink(self, chunk: CodeChunk, data: Dict) -> DangerousSink:
        """Create a DangerousSink from analysis data"""
        lines = chunk.content.split('\n')
        line_idx = data.get("line", 1) - chunk.start_line
        code_snippet = lines[line_idx] if 0 <= line_idx < len(lines) else ""
        
        return DangerousSink(
            id=hashlib.md5(f"{chunk.id}:{data.get('line')}".encode()).hexdigest()[:10],
            chunk_id=chunk.id,
            file_path=chunk.file_path,
            line_number=data.get("line", chunk.start_line),
            sink_type=data.get("type", "unknown"),
            function_name=data.get("function", ""),
            code_snippet=code_snippet,
            vulnerability_type=data.get("vuln_type", "Unknown"),
            severity=data.get("severity", "medium"),
            cwe_id=data.get("cwe", "CWE-Unknown")
        )
    
    async def trace_flows(
        self,
        entry_points: List[EntryPoint],
        sinks: List[DangerousSink],
        progress_callback: Optional[callable] = None,
        max_parallel: int = 4,  # Limit concurrent flow traces
        max_flow_pairs: int = 120  # Max pairs to trace - balances thoroughness vs speed
    ) -> List[TracedFlow]:
        """
        Trace data flows from entry points to sinks with parallel processing.
        This is the core agentic capability - the LLM can request additional code.
        
        IMPORTANT: Limited to max_flow_pairs to prevent runaway scans.
        With 27 entry points × 30 sinks = 810 potential pairs, each taking ~6s,
        an unlimited scan would take 75+ minutes. The limit keeps it reasonable.
        """
        # Build list of pairs to analyze with priority scoring
        scored_pairs = []
        for entry_point in entry_points:
            for sink in sinks:
                if self._could_be_connected(entry_point, sink):
                    # Score pairs to prioritize same-file and high-severity
                    score = 0
                    # Same file = highest priority (most likely to be connected)
                    if entry_point.file_path == sink.file_path:
                        score += 100
                    # High severity sinks get priority
                    if sink.severity == "critical":
                        score += 50
                    elif sink.severity == "high":
                        score += 30
                    # Direct dependencies
                    entry_chunk = self.chunks.get(entry_point.chunk_id)
                    sink_chunk = self.chunks.get(sink.chunk_id)
                    if entry_chunk and sink_chunk:
                        if sink.chunk_id in entry_chunk.dependencies:
                            score += 40
                        if entry_point.chunk_id in sink_chunk.dependencies:
                            score += 40
                    scored_pairs.append((score, entry_point, sink))
        
        # Sort by score (highest first) and limit
        scored_pairs.sort(key=lambda x: x[0], reverse=True)
        pairs_to_trace = [(ep, sink) for _, ep, sink in scored_pairs[:max_flow_pairs]]
        
        total_potential = len(scored_pairs)
        total_pairs = len(pairs_to_trace)
        
        if total_pairs == 0:
            return []
        
        # Log if we're limiting
        if total_potential > max_flow_pairs:
            logger.info(f"AgenticScan: Limiting flow traces from {total_potential} to {max_flow_pairs} (prioritized by likelihood)")
        
        if progress_callback:
            limit_note = f" (limited from {total_potential})" if total_potential > max_flow_pairs else ""
            progress_callback(f"Tracing {total_pairs} data flows{limit_note}...")
        
        # Process in parallel with semaphore to limit concurrency
        semaphore = asyncio.Semaphore(max_parallel)
        processed_count = [0]  # Use list to allow mutation in closure
        
        async def trace_with_semaphore(entry_point: EntryPoint, sink: DangerousSink):
            async with semaphore:
                processed_count[0] += 1
                if progress_callback and processed_count[0] % 5 == 0:
                    progress_callback(f"Tracing flow {processed_count[0]}/{total_pairs} (parallel)")
                return await self._trace_single_flow(entry_point, sink)
        
        # Create tasks for all pairs
        tasks = [
            trace_with_semaphore(entry_point, sink)
            for entry_point, sink in pairs_to_trace
        ]
        
        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful, exploitable flows
        flows = []
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"AgenticScan: Flow trace failed: {result}")
            elif result and result.is_exploitable:
                flows.append(result)
        
        self.flows = flows
        return flows
    
    def _could_be_connected(self, entry_point: EntryPoint, sink: DangerousSink) -> bool:
        """Quick heuristic to check if flow tracing is worth attempting.
        
        IMPORTANT: This is a critical filter to prevent O(n²) explosion.
        Only returns True for pairs that have a realistic chance of being connected.
        """
        # Same file is likely connected - always check
        if entry_point.file_path == sink.file_path:
            return True
        
        # Check if chunks have dependencies
        entry_chunk = self.chunks.get(entry_point.chunk_id)
        sink_chunk = self.chunks.get(sink.chunk_id)
        
        if entry_chunk and sink_chunk:
            # Check if one imports/depends on the other
            if sink.chunk_id in entry_chunk.dependencies:
                return True
            if entry_point.chunk_id in sink_chunk.dependencies:
                return True
            # Check if they share any imports (might call common code)
            common_imports = set(entry_chunk.imports) & set(sink_chunk.imports)
            if common_imports:
                return True
        
        # Different files with no detected dependency - unlikely to be connected
        # This prevents the O(n²) explosion from scanning all pairs
        return False
    
    async def _trace_single_flow(
        self, 
        entry_point: EntryPoint, 
        sink: DangerousSink
    ) -> Optional[TracedFlow]:
        """
        Trace a single flow from entry point to sink.
        Uses agentic approach where LLM can request more code.
        """
        if not self.client:
            return None
        
        entry_chunk = self.chunks.get(entry_point.chunk_id)
        sink_chunk = self.chunks.get(sink.chunk_id)
        
        if not entry_chunk or not sink_chunk:
            return None
        
        # Gather relevant code context
        context_chunks = self._gather_context(entry_point, sink)
        context_code = self._build_context_string(context_chunks)
        
        # Build FULL external intelligence context (includes app description, attack surface, etc.)
        full_intel_context = self._build_intel_context_for_prompt(include_full_context=True)
        
        # Build CVE context specific to this flow
        cve_context = ""
        if self.external_intel:
            relevant_cves = []
            # Check if sink involves a vulnerable package
            for cve in self.external_intel.cve_findings:
                pkg = cve.get("package", "")
                if pkg and (pkg in sink_chunk.content or pkg in entry_chunk.content):
                    relevant_cves.append(cve)
            
            if relevant_cves:
                cve_context = "\n## 🔴 CVEs RELEVANT TO THIS FLOW:\n"
                for cve in relevant_cves[:3]:
                    funcs = ", ".join(cve.get("affected_functions", [])[:3]) if cve.get("affected_functions") else "various"
                    cve_context += f"- **{cve.get('external_id')}** in {cve.get('package')}: {cve.get('description', 'N/A')[:100]}\n"
                    cve_context += f"  Affected functions: {funcs}\n"
                cve_context += "\nCheck if the vulnerable functions are actually called in this flow.\n"
        
        prompt = f"""Determine whether user input from this entry point can actually reach this sink in an exploitable way.

{full_intel_context}
{cve_context}
ENTRY POINT:
File: {entry_point.file_path}
Line: {entry_point.line_number}
Type: {entry_point.entry_type}
Variable: {entry_point.variable_name}
Code:
```
{entry_chunk.content[:2000]}
```

SINK:
File: {sink.file_path}
Line: {sink.line_number}
Type: {sink.sink_type}
Function: {sink.function_name}
Potential Vulnerability: {sink.vulnerability_type}
Code:
```
{sink_chunk.content[:2000]}
```

ADDITIONAL CONTEXT:
{context_code}

ANALYZE OBJECTIVELY:
1. Does a data flow path actually exist from entry to sink?
2. Is there sanitization/validation that PREVENTS exploitation?
3. Is this sink actually dangerous in this context?
4. **If known CVEs are listed above**: Does the code actually use the vulnerable functions?
5. **Consider the attack surface and entry points** provided in the context above

**IMPORTANT - Default to NO vulnerability unless you have clear evidence:**
- If data is validated/sanitized before reaching sink -> NOT exploitable
- If the sink uses parameterized queries/safe APIs -> NOT exploitable  
- If you cannot trace a clear path -> flow_exists: false
- If there's ANY reasonable doubt -> is_exploitable: false
- If a CVE is listed but vulnerable functions aren't called -> NOT exploitable

If you need more code: "NEED_MORE_CODE: <file_path>:<function_name>"

Otherwise return JSON:
{{
  "flow_exists": true/false,
  "is_exploitable": true/false,
  "confidence": 0.0-1.0,
  "flow_steps": [],
  "sanitization_present": true/false,
  "sanitization_analysis": "describe any validation/sanitization found",
  "reason": "clear explanation - especially important if NOT exploitable"
}}

A response of {{"flow_exists": false, "is_exploitable": false}} is completely valid and expected for most entry/sink pairs."""

        try:
            # Initial analysis with retry
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=2000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=90.0,
                operation_name="AgenticScan flow trace"
            )
            
            text = response.text or ""
            
            # Check if LLM needs more code (agentic behavior)
            if text and "NEED_MORE_CODE:" in text:
                # Extract requested code and retry
                additional_context = await self._handle_code_request(text)
                if additional_context:
                    # Retry with additional context
                    return await self._trace_with_additional_context(
                        entry_point, sink, prompt, additional_context
                    )
            
            # Parse response with safe JSON parser
            result = _safe_json_parse(text, {})
            if result.get("flow_exists") and result.get("is_exploitable"):
                return self._create_traced_flow(entry_point, sink, result)
            
        except Exception as e:
            logger.warning(f"AgenticScan: Flow tracing failed: {e}")
        
        return None
    
    def _gather_context(self, entry_point: EntryPoint, sink: DangerousSink) -> List[CodeChunk]:
        """Gather related code chunks for context"""
        context = []
        
        entry_chunk = self.chunks.get(entry_point.chunk_id)
        sink_chunk = self.chunks.get(sink.chunk_id)
        
        if entry_chunk:
            context.append(entry_chunk)
            # Add dependencies
            for dep_id in entry_chunk.dependencies[:3]:
                if dep_id in self.chunks:
                    context.append(self.chunks[dep_id])
        
        if sink_chunk and sink_chunk.id != entry_chunk.id:
            context.append(sink_chunk)
            for dep_id in sink_chunk.dependencies[:3]:
                if dep_id in self.chunks and dep_id not in [c.id for c in context]:
                    context.append(self.chunks[dep_id])
        
        return context[:10]  # Limit context size
    
    def _build_context_string(self, chunks: List[CodeChunk]) -> str:
        """Build a context string from chunks"""
        parts = []
        for chunk in chunks:
            parts.append(f"""
--- {chunk.file_path} (lines {chunk.start_line}-{chunk.end_line}) ---
{chunk.content[:1000]}
""")
        return "\n".join(parts)[:5000]  # Limit total context
    
    async def _handle_code_request(self, llm_response: str) -> Optional[str]:
        """Handle LLM's request for additional code"""
        match = re.search(r'NEED_MORE_CODE:\s*([^:\s]+):(\w+)', llm_response)
        if match:
            file_path = match.group(1)
            function_name = match.group(2)
            
            # Search chunks for the requested function
            for chunk in self.chunks.values():
                if file_path in chunk.file_path and function_name in chunk.content:
                    return f"\n--- Requested: {function_name} from {file_path} ---\n{chunk.content}"
        
        return None
    
    async def _trace_with_additional_context(
        self,
        entry_point: EntryPoint,
        sink: DangerousSink,
        original_prompt: str,
        additional_context: str
    ) -> Optional[TracedFlow]:
        """Retry tracing with additional code context"""
        if not self.client:
            return None
        
        prompt = f"""{original_prompt}

ADDITIONAL REQUESTED CODE:
{additional_context}

Now complete the analysis with this additional context."""

        try:
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=2000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=90.0,
                operation_name="AgenticScan additional context trace"
            )
            
            text = response.text
            if text:
                # Use safe JSON parser
                result = _safe_json_parse(text, {})
                if result.get("flow_exists") and result.get("is_exploitable"):
                    return self._create_traced_flow(entry_point, sink, result)
        
        except Exception as e:
            logger.warning(f"AgenticScan: Additional context tracing failed: {e}")
        
        return None
    
    def _create_traced_flow(
        self, 
        entry_point: EntryPoint, 
        sink: DangerousSink,
        result: Dict
    ) -> TracedFlow:
        """Create a TracedFlow from analysis results"""
        steps = []
        for step_data in result.get("flow_steps", []):
            steps.append(DataFlowStep(
                file_path=step_data.get("file", ""),
                line_number=step_data.get("line", 0),
                code_snippet=step_data.get("code", ""),
                variable_name=step_data.get("variable", ""),
                transformation=step_data.get("transformation", ""),
                is_sanitized=False
            ))
        
        flow_id = hashlib.md5(
            f"{entry_point.id}:{sink.id}".encode()
        ).hexdigest()[:12]
        
        return TracedFlow(
            id=flow_id,
            entry_point=entry_point,
            sink=sink,
            steps=steps,
            is_exploitable=result.get("is_exploitable", False),
            confidence=result.get("confidence", 0.5),
            sanitization_analysis=result.get("sanitization_analysis", "")
        )
    
    async def analyze_vulnerabilities(
        self,
        flows: List[TracedFlow],
        progress_callback: Optional[callable] = None
    ) -> List[AgenticVulnerability]:
        """
        Deep analysis of traced flows to generate vulnerability reports.
        """
        vulnerabilities = []
        
        for i, flow in enumerate(flows):
            if progress_callback:
                progress_callback(f"Analyzing vulnerability {i+1}/{len(flows)}")
            
            vuln = await self._analyze_single_vulnerability(flow)
            if vuln:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _analyze_single_vulnerability(self, flow: TracedFlow) -> Optional[AgenticVulnerability]:
        """Generate detailed vulnerability analysis for a flow"""
        if not self.client:
            # Return basic vulnerability without LLM analysis
            return self._create_basic_vulnerability(flow)
        
        # Build FULL external intelligence context
        full_intel_context = self._build_intel_context_for_prompt(include_full_context=True)
        
        prompt = f"""Generate an accurate vulnerability report for this potential data flow issue.

{full_intel_context}

POTENTIAL ISSUE TYPE: {flow.sink.vulnerability_type}
INITIAL SEVERITY ASSESSMENT: {flow.sink.severity}
CWE: {flow.sink.cwe_id}

ENTRY POINT:
- File: {flow.entry_point.file_path}
- Line: {flow.entry_point.line_number}
- Type: {flow.entry_point.entry_type}
- Variable: {flow.entry_point.variable_name}

SINK:
- File: {flow.sink.file_path}
- Line: {flow.sink.line_number}
- Function: {flow.sink.function_name}

DATA FLOW:
{self._format_flow_steps(flow.steps)}

SANITIZATION ANALYSIS:
{flow.sanitization_analysis}

Generate an HONEST report. Consider the application context, architecture, and attack surface provided above.
If after review this doesn't appear to be a real vulnerability, indicate that with high false_positive_likelihood.

JSON Response:
{{
  "title": "<Brief, accurate title>",
  "description": "<Factual description - include mitigating factors if present>",
  "exploit_scenario": "<Realistic exploit scenario considering the attack surface, or 'Exploitation unlikely due to...' if not exploitable>",
  "remediation": "<Specific fixes, or 'No action needed' if false positive>",
  "code_fix": "<Example fix or null if not needed>",
  "owasp_category": "<OWASP category>",
  "confidence": 0.0-1.0,
  "false_positive_likelihood": 0.0-1.0
}}

**CALIBRATION**:
- false_positive_likelihood 0.7-1.0: Likely NOT a real issue (sanitization present, safe API usage)
- false_positive_likelihood 0.4-0.6: Uncertain, needs manual review
- false_positive_likelihood 0.0-0.3: Likely a genuine vulnerability with clear exploit path

Be conservative - if there's doubt, lean toward higher false_positive_likelihood."""

        try:
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.2,
                        max_output_tokens=2000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=90.0,
                operation_name="AgenticScan vulnerability analysis"
            )
            
            text = response.text
            if text:
                # Use safe JSON parser
                result = _safe_json_parse(text, {})
                if result:
                    return self._create_vulnerability(flow, result)
        
        except Exception as e:
            logger.warning(f"AgenticScan: Vulnerability analysis failed: {e}")
        
        return self._create_basic_vulnerability(flow)
    
    def _format_flow_steps(self, steps: List[DataFlowStep]) -> str:
        """Format flow steps for the prompt"""
        parts = []
        for i, step in enumerate(steps):
            parts.append(f"{i+1}. {step.file_path}:{step.line_number}")
            parts.append(f"   Code: {step.code_snippet}")
            parts.append(f"   Variable: {step.variable_name}")
            parts.append(f"   Transformation: {step.transformation}")
        return "\n".join(parts)
    
    def _create_vulnerability(self, flow: TracedFlow, result: Dict) -> AgenticVulnerability:
        """Create a vulnerability from analysis results"""
        vuln_id = hashlib.md5(f"{flow.id}:{datetime.now().isoformat()}".encode()).hexdigest()[:12]
        
        return AgenticVulnerability(
            id=vuln_id,
            vulnerability_type=flow.sink.vulnerability_type,
            severity=flow.sink.severity,
            cwe_id=flow.sink.cwe_id,
            owasp_category=result.get("owasp_category", "A03:2021 - Injection"),
            title=result.get("title", f"{flow.sink.vulnerability_type} in {flow.sink.function_name}"),
            description=result.get("description", ""),
            flow=flow,
            llm_analysis=result.get("description", ""),
            exploit_scenario=result.get("exploit_scenario", ""),
            remediation=result.get("remediation", ""),
            code_fix=result.get("code_fix"),
            confidence=result.get("confidence", flow.confidence),
            false_positive_likelihood=result.get("false_positive_likelihood", 0.2)
        )
    
    def _create_basic_vulnerability(self, flow: TracedFlow) -> AgenticVulnerability:
        """Create a basic vulnerability without LLM analysis"""
        vuln_id = hashlib.md5(f"{flow.id}".encode()).hexdigest()[:12]
        
        return AgenticVulnerability(
            id=vuln_id,
            vulnerability_type=flow.sink.vulnerability_type,
            severity=flow.sink.severity,
            cwe_id=flow.sink.cwe_id,
            owasp_category="A03:2021 - Injection",
            title=f"{flow.sink.vulnerability_type} via {flow.entry_point.entry_type}",
            description=f"User input from {flow.entry_point.entry_type} reaches {flow.sink.function_name} without proper sanitization.",
            flow=flow,
            llm_analysis="LLM analysis unavailable",
            exploit_scenario="Attacker-controlled input may reach dangerous sink.",
            remediation=self._get_default_remediation(flow.sink.vulnerability_type),
            confidence=flow.confidence
        )
    
    def _get_default_remediation(self, vuln_type: str) -> str:
        """Get default remediation for a vulnerability type"""
        remediations = {
            "SQL Injection": "Use parameterized queries or ORM methods.",
            "Command Injection": "Use subprocess with shell=False, validate input.",
            "Cross-Site Scripting": "Encode output, use auto-escaping templates.",
            "Path Traversal": "Validate paths, use os.path.basename().",
            "Server-Side Request Forgery": "Whitelist allowed URLs/domains.",
            "XML External Entity": "Disable external entity processing.",
            "Insecure Deserialization": "Use JSON instead of pickle/yaml for untrusted data.",
        }
        return remediations.get(vuln_type, "Validate and sanitize all user input.")

    async def filter_false_positives(
        self,
        vulnerabilities: List[AgenticVulnerability],
        progress_callback: Optional[callable] = None,
        max_parallel: int = 3  # Limit concurrent API calls
    ) -> Tuple[List[AgenticVulnerability], Dict[str, Any]]:
        """
        AI-powered false positive filtering phase with parallel processing.
        
        Similar to APK Analyzer's AI Finding Verification, this:
        1. Reviews each vulnerability with full context
        2. Assigns confidence scores
        3. Filters out likely false positives
        4. Returns verified findings + stats
        
        Returns:
            Tuple of (verified_vulnerabilities, filtering_stats)
        """
        if not vulnerabilities:
            return [], {"total": 0, "verified": 0, "filtered": 0, "filter_rate": 0}
        
        if not self.client:
            # No API available, return all with default confidence
            logger.warning("AgenticScan: No LLM client for false positive filtering, returning all findings")
            return vulnerabilities, {
                "total": len(vulnerabilities),
                "verified": len(vulnerabilities),
                "filtered": 0,
                "filter_rate": 0,
                "note": "LLM unavailable - no filtering applied"
            }
        
        if progress_callback:
            progress_callback(f"Filtering false positives from {len(vulnerabilities)} findings (parallel)...")
        
        # Process in batches for efficiency
        batch_size = 5
        batches = []
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            batches.append((i, batch))
        
        if len(batches) <= 1:
            # Single batch - process directly
            if batches:
                return await self._filter_batch(batches[0][1], progress_callback)
            return [], {"total": 0, "verified": 0, "filtered": 0, "filter_rate": 0}
        
        # Multiple batches - process in parallel
        semaphore = asyncio.Semaphore(max_parallel)
        
        async def filter_with_semaphore(batch_idx: int, batch: List[AgenticVulnerability]):
            async with semaphore:
                if progress_callback:
                    start = batch_idx * batch_size + 1
                    end = min(start + len(batch) - 1, len(vulnerabilities))
                    progress_callback(f"Verifying findings {start}-{end} of {len(vulnerabilities)} (parallel)")
                return await self._filter_batch(batch, None)
        
        # Create tasks for all batches
        tasks = [
            filter_with_semaphore(idx, batch)
            for idx, (_, batch) in enumerate(batches)
        ]
        
        # Execute in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        all_verified = []
        all_filtered = []
        
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"AgenticScan: Parallel FP filtering failed: {result}")
            elif result:
                verified, stats = result
                all_verified.extend(verified)
                all_filtered.extend(stats.get("filtered_findings", []))
        
        # Calculate final stats
        total = len(vulnerabilities)
        verified_count = len(all_verified)
        filtered_count = total - verified_count
        filter_rate = filtered_count / total if total > 0 else 0
        
        stats = {
            "total": total,
            "verified": verified_count,
            "filtered": filtered_count,
            "filter_rate": filter_rate,
            "filtered_findings": all_filtered,
            "by_verdict": {
                "high_confidence": sum(1 for v in all_verified if v.false_positive_likelihood < 0.2),
                "medium_confidence": sum(1 for v in all_verified if 0.2 <= v.false_positive_likelihood < 0.4),
                "low_confidence": sum(1 for v in all_verified if v.false_positive_likelihood >= 0.4),
            }
        }
        
        logger.info(f"AgenticScan: FP filtering - {verified_count} verified, {filtered_count} filtered ({filter_rate:.1%} filter rate)")
        
        return all_verified, stats
    
    async def _filter_batch(
        self,
        batch: List[AgenticVulnerability],
        progress_callback: Optional[callable] = None
    ) -> Tuple[List[AgenticVulnerability], Dict[str, Any]]:
        """Filter a single batch of vulnerabilities"""
        verified = []
        filtered_out = []
        
        # Build FULL external intelligence context
        full_intel_context = self._build_intel_context_for_prompt(include_full_context=True)
        
        # Build batch verification prompt
        findings_text = ""
        for idx, vuln in enumerate(batch):
            flow_info = ""
            if vuln.flow:
                flow_info = f"""
  Entry: {vuln.flow.entry_point.file_path}:{vuln.flow.entry_point.line_number} ({vuln.flow.entry_point.entry_type})
  Sink: {vuln.flow.sink.file_path}:{vuln.flow.sink.line_number} ({vuln.flow.sink.function_name})
  Code at entry: {vuln.flow.entry_point.code_snippet[:150] if vuln.flow.entry_point.code_snippet else 'N/A'}
  Code at sink: {vuln.flow.sink.code_snippet[:150] if vuln.flow.sink.code_snippet else 'N/A'}"""
            
            findings_text += f"""
### Finding {idx + 1}: {vuln.vulnerability_type} ({vuln.severity})
- Title: {vuln.title}
- CWE: {vuln.cwe_id}
- Current confidence: {vuln.confidence:.0%}
- Description: {vuln.description[:400] if vuln.description else 'N/A'}
{flow_info}
"""

        prompt = f"""You are a skeptical security reviewer. Your job is to CHALLENGE each finding and determine if it represents a REAL, EXPLOITABLE vulnerability.

Assume findings may be false positives until proven otherwise.

{full_intel_context}

## Findings to Verify:
{findings_text}

## Verification Approach:
For each finding, consider:
1. The APPLICATION CONTEXT (what does this app do? what's its architecture?)
2. The ATTACK SURFACE (how would an attacker reach this code?)
3. Is there CONCRETE evidence of exploitability, or just theoretical risk?
4. Are there sanitization/validation mechanisms I might have missed?
5. Is this a safe pattern that looks dangerous (e.g., parameterized queries, ORM usage)?
6. Would a real attacker actually be able to exploit this given the identified entry points?

## Verdicts:
- **FALSE_POSITIVE**: Not exploitable - safe pattern, sanitization present, trusted data source, or theoretical-only risk
- **UNCERTAIN**: Can't determine - flag for manual review but don't alarm the user
- **LIKELY_TRUE**: Probably exploitable but some uncertainty remains  
- **TRUE_POSITIVE**: Definitely exploitable with clear attack path and no mitigations

Respond with JSON:
{{
  "verifications": [
    {{
      "index": 1,
      "verdict": "FALSE_POSITIVE|UNCERTAIN|LIKELY_TRUE|TRUE_POSITIVE",
      "confidence": 0.0-1.0,
      "reasoning": "<specific explanation with evidence, referencing app context/attack surface>",
      "severity_adjustment": "none|upgrade|downgrade",
      "new_severity": "<only if adjustment needed>"
    }}
  ]
}}

**IMPORTANT**: 
- Err on the side of FALSE_POSITIVE when uncertain - users prefer fewer false alarms
- Common false positive patterns: parameterized queries, ORM methods, framework auth, type-checked inputs, allowlist validation
- A finding needs CLEAR evidence of exploitability to be TRUE_POSITIVE
- It's better to miss a low-confidence issue than to waste user time on false positives"""

        try:
            from google.genai import types
            
            async def make_request():
                return await self.client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.1,
                        max_output_tokens=2000
                    )
                )
            
            response = await _retry_with_backoff(
                make_request,
                max_retries=3,
                base_delay=2.0,
                timeout_seconds=90.0,
                operation_name="AgenticScan FP filtering"
            )
            
            text = response.text if response else ""
            if text:
                # Use safe JSON parser
                result = _safe_json_parse(text, {"verifications": []})
                verifications = result.get("verifications", [])
                
                for ver in verifications:
                    idx = ver.get("index", 1) - 1
                    if 0 <= idx < len(batch):
                        vuln = batch[idx]
                        verdict = ver.get("verdict", "UNCERTAIN")
                        confidence = ver.get("confidence", vuln.confidence)
                        reasoning = ver.get("reasoning", "")
                        
                        # Update confidence based on verification
                        vuln.confidence = confidence
                        
                        # Adjust severity if recommended
                        if ver.get("severity_adjustment") == "downgrade" and ver.get("new_severity"):
                            vuln.severity = ver.get("new_severity")
                        elif ver.get("severity_adjustment") == "upgrade" and ver.get("new_severity"):
                            vuln.severity = ver.get("new_severity")
                        
                        # Filter based on verdict
                        if verdict == "FALSE_POSITIVE":
                            vuln.false_positive_likelihood = 0.9
                            filtered_out.append({
                                "id": vuln.id,
                                "type": vuln.vulnerability_type,
                                "reason": reasoning
                            })
                            logger.info(f"AgenticScan FP filtered: {vuln.vulnerability_type} - {reasoning[:50]}")
                        else:
                            # Keep the finding
                            if verdict == "TRUE_POSITIVE":
                                vuln.false_positive_likelihood = 0.1
                            elif verdict == "LIKELY_TRUE":
                                vuln.false_positive_likelihood = 0.25
                            else:  # UNCERTAIN
                                vuln.false_positive_likelihood = 0.4
                            
                            verified.append(vuln)
                
                # Handle any unprocessed findings in batch
                processed_indices = {v.get("index", 0) - 1 for v in verifications}
                for idx, vuln in enumerate(batch):
                    if idx not in processed_indices:
                        verified.append(vuln)
                
                # Return results for this batch
                return verified, {"filtered_findings": filtered_out}
            
            # If parsing failed, keep all findings
            return batch, {"filtered_findings": []}
            
        except Exception as e:
            logger.warning(f"AgenticScan: FP filtering batch failed: {e}, keeping findings")
            return batch, {"filtered_findings": []}


# ============================================================================
# Main Service Class
# ============================================================================

class AgenticScanService:
    """
    Main service for running agentic AI security scans.
    """
    
    def __init__(self):
        self.chunker = CodeChunker()
        self.analyzer = AgenticAnalyzer()
        self.active_scans: Dict[str, ScanProgress] = {}
        self.results: Dict[str, AgenticScanResult] = {}
    
    async def start_scan(
        self,
        project_id: int,
        project_path: str,
        file_extensions: List[str] = None,
        progress_callback: Optional[callable] = None,
        use_multi_pass: bool = True,  # Enable smart multi-pass by default
        external_intel: Optional[ExternalIntelligence] = None,  # CVE/SAST/dependency context
        enhanced_mode: bool = False  # Enhanced: 240→80→30→10 files vs standard 180→60→22→7
    ) -> str:
        """
        Start a new agentic scan with smart multi-pass file selection.
        
        The scan now uses intelligent AI-driven file triage with RICH CONTEXT:
        - Pass 0: AI examines ALL file names to select security-relevant files
        - Pass 1: Initial analysis - Standard: 180 files × 5K chars | Enhanced: 240 files × 6K chars
        - Pass 2: Focused analysis - Standard: 60 files × 12K chars | Enhanced: 80 files × 16K chars
        - Pass 3: Deep analysis - Standard: 22 files × 50K chars | Enhanced: 30 files × 65K chars
        - Pass 4: Ultra-deep (files >50K only) - Standard: 7 files × 100K | Enhanced: 10 files × 120K
        - Flow Tracing, Vulnerability Analysis, FP Filtering: All receive FULL context including:
          - App description and architecture diagram
          - Security findings summary
          - Codebase map and diagram
          - Exploitability assessment and attack surface map
        - Synthesis: AI combines findings from all passes with full context
        
        Args:
            enhanced_mode: If True, increases file limits AND content depth for more thorough analysis
            external_intel: CVE, SAST, dependency data PLUS app description, architecture diagram,
                          codebase map, attack surface map, and exploitability assessment
        
        Returns the scan_id for tracking.
        """
        import time
        start_time = time.time()
        
        # Set multi-pass limits based on mode
        # Enhanced mode: more files AND more content per file
        if enhanced_mode:
            self.analyzer.set_multi_pass_limits(
                pass1=240, pass2=80, pass3=30, pass4=10,  # Files per pass (enhanced)
                quick_chars=6000,                          # Pass 1: 6K chars
                detailed_chars=16000,                      # Pass 2: 16K chars
                full_chars=65000,                          # Pass 3: 65K chars
                ultra_chars=120000,                        # Pass 4: 120K chars (ultra-deep)
                pass4_min_size=50000                       # Files >50K qualify for Pass 4
            )
            logger.info("AgenticScan: Enhanced mode enabled (240→80→30→10 files, 6K→16K→65K→120K chars)")
        else:
            self.analyzer.set_multi_pass_limits(
                pass1=180, pass2=60, pass3=22, pass4=7,   # Files per pass (standard)
                quick_chars=5000,                          # Pass 1: 5K chars
                detailed_chars=12000,                      # Pass 2: 12K chars
                full_chars=50000,                          # Pass 3: 50K chars
                ultra_chars=100000,                        # Pass 4: 100K chars
                pass4_min_size=50000                       # Files >50K qualify for Pass 4
            )
            logger.info("AgenticScan: Standard mode (180→60→22→7 files, 5K→12K→50K→100K chars)")
        
        # Inject external intelligence into analyzer if provided
        if external_intel:
            self.analyzer.set_external_intelligence(external_intel)
            logger.info(f"AgenticScan: Loaded external intel - {len(external_intel.cve_findings)} CVEs, "
                       f"{len(external_intel.sast_findings)} SAST findings, "
                       f"{len(external_intel.vulnerable_import_files)} vulnerable import files")
        
        if file_extensions is None:
            # Comprehensive list of security-relevant source file extensions
            file_extensions = [
                ".py", ".js", ".ts", ".jsx", ".tsx",  # Python, JavaScript, TypeScript
                ".php", ".phtml",                       # PHP
                ".java", ".kt", ".kts",                 # Java, Kotlin
                ".go",                                  # Go
                ".rb", ".erb",                          # Ruby
                ".cs",                                  # C#
                ".c", ".cpp", ".cc", ".h", ".hpp",      # C/C++
                ".swift",                               # Swift
                ".rs",                                  # Rust
                ".scala",                               # Scala
                ".pl", ".pm",                           # Perl
                ".sh", ".bash",                         # Shell scripts
                # Documentation & config (can reveal architecture, secrets, attack surfaces)
                ".md", ".rst", ".txt",                  # Documentation
                ".yaml", ".yml", ".json", ".toml",      # Config files (secrets, endpoints)
                ".env.example", ".env.sample",          # Env templates (show expected secrets)
                ".xml", ".properties",                  # Java/app configs
            ]
        
        scan_id = hashlib.md5(
            f"{project_id}:{project_path}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Initialize progress tracking
        progress = ScanProgress(
            scan_id=scan_id,
            project_id=project_id,
            phase=ScanPhase.INITIALIZING,
            phase_progress=0.0,
            total_chunks=0,
            analyzed_chunks=0,
            entry_points_found=0,
            flows_traced=0,
            vulnerabilities_found=0,
            started_at=datetime.now().isoformat(),
            message="Initializing scan..."
        )
        self.active_scans[scan_id] = progress
        
        def update_progress(msg: str):
            progress.message = msg
            if progress_callback:
                progress_callback(progress)
        
        try:
            # Collect ALL source files first
            all_files = self.chunker._collect_all_files(project_path, file_extensions)
            total_file_count = len(all_files)
            logger.info(f"AgenticScan: Found {total_file_count} total source files")
            
            multi_pass_results = []
            synthesis_result = None
            
            if use_multi_pass and total_file_count > 20:
                # ================================================================
                # SMART MULTI-PASS ANALYSIS
                # ================================================================
                
                # Phase 0: AI File Triage
                progress.phase = ScanPhase.FILE_TRIAGE
                progress.message = f"🔍 AI analyzing {total_file_count} file names for security relevance..."
                if progress_callback:
                    progress_callback(progress)
                
                triage_results = await self.analyzer.triage_files(
                    project_path, all_files, update_progress
                )
                
                critical_count = len([r for r in triage_results if r.priority == "CRITICAL"])
                high_count = len([r for r in triage_results if r.priority == "HIGH"])
                progress.message = f"🔍 Triage complete: {critical_count} critical, {high_count} high priority files"
                progress.phase_progress = 1.0
                if progress_callback:
                    progress_callback(progress)
                
                # Phases 1-4: Multi-Pass Analysis
                progress.phase = ScanPhase.INITIAL_ANALYSIS
                progress.message = "📋 Starting multi-pass analysis..."
                if progress_callback:
                    progress_callback(progress)
                
                def update_phase(new_phase: ScanPhase):
                    """Update the scan phase for WebSocket tracking"""
                    progress.phase = new_phase
                    if progress_callback:
                        progress_callback(progress)
                
                multi_pass_results, deep_files = await self.analyzer.multi_pass_analysis(
                    project_path, triage_results, update_progress, update_phase
                )
                
                progress.phase = ScanPhase.ULTRA_ANALYSIS  # Final phase after multi-pass
                progress.phase_progress = 1.0
                
                # Get files selected for chunking (combine top triage + deep analysis files)
                selected_for_chunking = set(deep_files)
                # Also include high-scoring files from multi-pass
                high_score_files = [r.file_path for r in multi_pass_results if r.security_score >= 6.0]
                selected_for_chunking.update(high_score_files[:30])  # Cap at reasonable number
                
                # Filter original files to only those selected
                files_to_chunk = [f for f in all_files if f in selected_for_chunking]
                
                logger.info(f"AgenticScan: Multi-pass selected {len(files_to_chunk)} files for deep chunked analysis")
            else:
                # Small codebase or multi-pass disabled - use original prioritization
                files_to_chunk = self.chunker._prioritize_files(all_files)
                triage_results = []
            
            # Phase: Code Chunking (on selected files only)
            progress.phase = ScanPhase.CHUNKING
            progress.message = f"Breaking {len(files_to_chunk)} selected files into analyzable chunks..."
            if progress_callback:
                progress_callback(progress)
            
            # Temporarily override file list for chunking
            chunks = []
            for file_path in files_to_chunk[:self.chunker.MAX_FILES]:
                if len(chunks) >= self.chunker.MAX_CHUNKS:
                    break
                file_chunks = self.chunker._chunk_file(file_path)
                remaining = self.chunker.MAX_CHUNKS - len(chunks)
                if remaining > 0:
                    chunks.extend(file_chunks[:remaining])
            
            # Build dependency graph
            self.chunker._analyze_dependencies(chunks)
            progress.total_chunks = len(chunks)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Created {len(chunks)} code chunks from {len(files_to_chunk)} files")
            
            # Phase: Entry Point Detection
            progress.phase = ScanPhase.ENTRY_POINT_DETECTION
            progress.message = "Identifying user input entry points..."
            if progress_callback:
                progress_callback(progress)
            
            entry_points, sinks = await self.analyzer.analyze_chunks(chunks, update_progress)
            progress.entry_points_found = len(entry_points)
            progress.analyzed_chunks = len(chunks)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Found {len(entry_points)} entry points and {len(sinks)} sinks")
            
            # Track multi-pass findings for synthesis later
            multi_pass_vulns = []
            if use_multi_pass and multi_pass_results:
                for r in multi_pass_results:
                    for finding in r.findings:
                        if isinstance(finding, dict):
                            multi_pass_vulns.append(finding)
                logger.info(f"AgenticScan: Multi-pass found {len(multi_pass_vulns)} potential vulnerabilities")
            
            # Phase: Flow Tracing (always run, limited to 120 pairs max)
            progress.phase = ScanPhase.FLOW_TRACING
            progress.message = f"🔀 Tracing data flows ({len(entry_points)} entry points → sinks)..."
            if progress_callback:
                progress_callback(progress)
            
            flows = await self.analyzer.trace_flows(entry_points, sinks, update_progress)
            progress.flows_traced = len(flows)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Traced {len(flows)} exploitable flows")
            
            # Phase: Vulnerability Analysis
            progress.phase = ScanPhase.VULNERABILITY_ANALYSIS
            progress.message = "Generating detailed vulnerability reports..."
            if progress_callback:
                progress_callback(progress)
            
            vulnerabilities = await self.analyzer.analyze_vulnerabilities(flows, update_progress)
            progress.vulnerabilities_found = len(vulnerabilities)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Generated {len(vulnerabilities)} vulnerability reports")
            
            # Phase: False Positive Filtering
            progress.phase = ScanPhase.FALSE_POSITIVE_FILTERING
            progress.message = "AI verification: Filtering false positives..."
            if progress_callback:
                progress_callback(progress)
            
            verified_vulnerabilities, fp_stats = await self.analyzer.filter_false_positives(
                vulnerabilities, update_progress
            )
            
            progress.vulnerabilities_found = len(verified_vulnerabilities)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Final verified vulnerabilities: {len(verified_vulnerabilities)}")
            
            # Phase: Synthesis (if multi-pass was used)
            if use_multi_pass and multi_pass_results:
                progress.phase = ScanPhase.SYNTHESIS
                progress.message = "🧠 Synthesizing findings across all analysis passes..."
                if progress_callback:
                    progress_callback(progress)
                
                synthesis_result = await self.analyzer.synthesize_findings(
                    multi_pass_results, verified_vulnerabilities, update_progress
                )
                progress.phase_progress = 1.0
                
                logger.info(f"AgenticScan: Synthesis complete - {len(synthesis_result.attack_chains)} attack chains identified")
            
            # Phase: Report Generation
            progress.phase = ScanPhase.REPORT_GENERATION
            progress.message = "Compiling final report..."
            if progress_callback:
                progress_callback(progress)
            
            duration = time.time() - start_time
            
            # Build statistics including multi-pass info
            stats = self._build_statistics(verified_vulnerabilities, entry_points, sinks, flows, fp_stats)
            
            # Add multi-pass stats if available
            if use_multi_pass and multi_pass_results:
                stats["multi_pass"] = {
                    "enabled": True,
                    "total_files_triaged": len(triage_results) if triage_results else 0,
                    "files_selected_for_deep_analysis": len(files_to_chunk),
                    "pass_1_files": len([r for r in multi_pass_results if r.pass_number == 1]),
                    "pass_2_files": len([r for r in multi_pass_results if r.pass_number == 2]),
                    "pass_3_files": len([r for r in multi_pass_results if r.pass_number == 3]),
                    "high_risk_files": len([r for r in multi_pass_results if r.security_score >= 7.0])
                }
                if synthesis_result:
                    stats["synthesis"] = {
                        "attack_chains": len(synthesis_result.attack_chains),
                        "recommendations": len(synthesis_result.key_recommendations),
                        "assessment": synthesis_result.overall_security_assessment[:500] if synthesis_result.overall_security_assessment else ""
                    }
            
            # Build result with verified vulnerabilities
            result = AgenticScanResult(
                scan_id=scan_id,
                project_id=project_id,
                project_path=project_path,
                status="complete",
                phase=ScanPhase.COMPLETE,
                total_chunks=len(chunks),
                analyzed_chunks=len(chunks),
                entry_points=entry_points,
                sinks=sinks,
                traced_flows=flows,
                vulnerabilities=verified_vulnerabilities,
                statistics=stats,
                started_at=progress.started_at,
                completed_at=datetime.now().isoformat(),
                scan_duration_seconds=round(duration, 2)
            )
            
            self.results[scan_id] = result
            
            progress.phase = ScanPhase.COMPLETE
            progress.message = "Scan complete!"
            if progress_callback:
                progress_callback(progress)
            
            return scan_id
            
        except Exception as e:
            logger.error(f"AgenticScan: Scan failed: {e}")
            progress.phase = ScanPhase.ERROR
            progress.message = str(e)
            
            # Store error result
            self.results[scan_id] = AgenticScanResult(
                scan_id=scan_id,
                project_id=project_id,
                project_path=project_path,
                status="error",
                phase=ScanPhase.ERROR,
                total_chunks=progress.total_chunks,
                analyzed_chunks=progress.analyzed_chunks,
                entry_points=[],
                sinks=[],
                traced_flows=[],
                vulnerabilities=[],
                statistics={},
                started_at=progress.started_at,
                completed_at=datetime.now().isoformat(),
                scan_duration_seconds=time.time() - start_time,
                error_message=str(e)
            )
            
            raise
    
    def get_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get the current progress of a scan"""
        return self.active_scans.get(scan_id)
    
    def get_result(self, scan_id: str) -> Optional[AgenticScanResult]:
        """Get the result of a completed scan"""
        return self.results.get(scan_id)
    
    def _build_statistics(
        self,
        vulnerabilities: List[AgenticVulnerability],
        entry_points: List[EntryPoint],
        sinks: List[DangerousSink],
        flows: List[TracedFlow],
        fp_stats: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build statistics summary"""
        stats = {
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_type": {},
            "by_file": {},
            "entry_point_types": {},
            "sink_types": {},
            "avg_confidence": 0.0,
        }
        
        # Include false positive filtering stats if available
        if fp_stats:
            stats["false_positive_filtering"] = fp_stats
        
        confidences = []
        for vuln in vulnerabilities:
            stats["by_severity"][vuln.severity] = stats["by_severity"].get(vuln.severity, 0) + 1
            stats["by_type"][vuln.vulnerability_type] = stats["by_type"].get(vuln.vulnerability_type, 0) + 1
            
            file_name = Path(vuln.flow.entry_point.file_path).name
            stats["by_file"][file_name] = stats["by_file"].get(file_name, 0) + 1
            
            confidences.append(vuln.confidence)
        
        for ep in entry_points:
            stats["entry_point_types"][ep.entry_type] = stats["entry_point_types"].get(ep.entry_type, 0) + 1
        
        for sink in sinks:
            stats["sink_types"][sink.sink_type] = stats["sink_types"].get(sink.sink_type, 0) + 1
        
        if confidences:
            stats["avg_confidence"] = sum(confidences) / len(confidences)
        
        return stats


# ============================================================================
# Serialization Helpers
# ============================================================================

def result_to_dict(result: AgenticScanResult) -> Dict[str, Any]:
    """Convert AgenticScanResult to dictionary for JSON serialization"""
    return {
        "scan_id": result.scan_id,
        "project_id": result.project_id,
        "project_path": result.project_path,
        "status": result.status,
        "phase": result.phase.value if isinstance(result.phase, ScanPhase) else result.phase,
        "total_chunks": result.total_chunks,
        "analyzed_chunks": result.analyzed_chunks,
        "entry_points_count": len(result.entry_points),
        "sinks_count": len(result.sinks),
        "flows_traced": len(result.traced_flows),
        "vulnerabilities": [
            {
                "id": v.id,
                "vulnerability_type": v.vulnerability_type,
                "severity": v.severity,
                "cwe_id": v.cwe_id,
                "owasp_category": v.owasp_category,
                "title": v.title,
                "description": v.description,
                "llm_analysis": v.llm_analysis,
                "exploit_scenario": v.exploit_scenario,
                "remediation": v.remediation,
                "code_fix": v.code_fix,
                "confidence": v.confidence,
                "false_positive_likelihood": v.false_positive_likelihood,
                "flow": {
                    "entry_point": {
                        "file_path": v.flow.entry_point.file_path,
                        "line_number": v.flow.entry_point.line_number,
                        "entry_type": v.flow.entry_point.entry_type,
                        "variable_name": v.flow.entry_point.variable_name,
                        "code_snippet": v.flow.entry_point.code_snippet,
                    },
                    "sink": {
                        "file_path": v.flow.sink.file_path,
                        "line_number": v.flow.sink.line_number,
                        "sink_type": v.flow.sink.sink_type,
                        "function_name": v.flow.sink.function_name,
                        "code_snippet": v.flow.sink.code_snippet,
                    },
                    "steps": [
                        {
                            "file_path": s.file_path,
                            "line_number": s.line_number,
                            "code_snippet": s.code_snippet,
                            "variable_name": s.variable_name,
                            "transformation": s.transformation,
                        }
                        for s in v.flow.steps
                    ]
                }
            }
            for v in result.vulnerabilities
        ],
        "statistics": result.statistics,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "scan_duration_seconds": result.scan_duration_seconds,
        "error_message": result.error_message,
    }


def progress_to_dict(progress: ScanProgress) -> Dict[str, Any]:
    """Convert ScanProgress to dictionary"""
    return {
        "scan_id": progress.scan_id,
        "project_id": progress.project_id,
        "phase": progress.phase.value if isinstance(progress.phase, ScanPhase) else progress.phase,
        "phase_progress": progress.phase_progress,
        "total_chunks": progress.total_chunks,
        "analyzed_chunks": progress.analyzed_chunks,
        "entry_points_found": progress.entry_points_found,
        "flows_traced": progress.flows_traced,
        "vulnerabilities_found": progress.vulnerabilities_found,
        "current_file": progress.current_file,
        "message": progress.message,
        "started_at": progress.started_at,
        "estimated_completion": progress.estimated_completion,
    }


# Singleton instance
agentic_scan_service = AgenticScanService()
