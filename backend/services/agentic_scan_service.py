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
    CHUNKING = "chunking"
    ENTRY_POINT_DETECTION = "entry_point_detection"
    FLOW_TRACING = "flow_tracing"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
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
    MAX_CHUNK_LINES = 60   # Maximum lines per chunk
    MIN_CHUNK_LINES = 10   # Minimum lines to form a chunk
    CONTEXT_OVERLAP = 3    # Lines of overlap between chunks
    MAX_FILES = 100        # Max files to process (balanced for coverage)
    MAX_CHUNKS = 80        # Max chunks - balance between speed and coverage
    
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
    
    def __init__(self, adaptive: bool = True):
        self.chunks: Dict[str, CodeChunk] = {}
        self.adaptive = adaptive
        self._file_count = 0
        self._chunk_size = self.MAX_CHUNK_LINES
    
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
    """
    
    def __init__(self):
        self.client = genai_client
        self.model_name = settings.gemini_model_id
        self.chunks: Dict[str, CodeChunk] = {}
        self.entry_points: List[EntryPoint] = []
        self.sinks: List[DangerousSink] = []
        self.flows: List[TracedFlow] = []
    
    async def analyze_chunks(
        self, 
        chunks: List[CodeChunk],
        progress_callback: Optional[callable] = None
    ) -> Tuple[List[EntryPoint], List[DangerousSink]]:
        """
        Analyze chunks to identify entry points and dangerous sinks.
        Uses batched LLM calls for efficiency.
        """
        self.chunks = {c.id: c for c in chunks}
        entry_points = []
        sinks = []
        
        # Process chunks in batches (smaller batches = more reliable API calls)
        batch_size = 5  # Reduced from 10 for stability with large APKs
        for i in range(0, len(chunks), batch_size):
            batch = chunks[i:i + batch_size]
            
            if progress_callback:
                progress_callback(f"Analyzing chunks {i+1}-{min(i+batch_size, len(chunks))} of {len(chunks)}")
            
            # Analyze batch with retry logic for reliability
            batch_results = await _retry_with_backoff(
                lambda b=batch: self._analyze_batch(b),
                max_retries=3,
                base_delay=2.0
            )
            
            for chunk_id, result in batch_results.items():
                chunk = self.chunks[chunk_id]
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
        
        self.entry_points = entry_points
        self.sinks = sinks
        
        return entry_points, sinks
    
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
        
        prompt = f"""Analyze these code chunks for security-relevant patterns.

{chunks_text}

For each chunk, identify:

1. ENTRY POINTS (where user input enters):
   - HTTP request parameters (query, body, headers, cookies)
   - Form submissions
   - File uploads
   - WebSocket messages
   - CLI arguments
   - Environment variables (when used for user data)

2. DANGEROUS SINKS (functions that could cause vulnerabilities):
   - SQL queries (raw queries, not parameterized)
   - OS command execution
   - File operations with user input
   - eval/exec/compile
   - HTTP requests (SSRF)
   - Template rendering with user input
   - Deserialization of untrusted data
   - XML parsing

Return JSON with this structure:
{{
  "<chunk_id>": {{
    "entry_points": [
      {{
        "line": <line_number>,
        "type": "<entry_type>",
        "variable": "<variable_name>",
        "framework": "<detected_framework>",
        "http_method": "<GET/POST/etc or null>",
        "route": "<route_path or null>"
      }}
    ],
    "sinks": [
      {{
        "line": <line_number>,
        "type": "<sink_type>",
        "function": "<function_name>",
        "vuln_type": "<vulnerability_type>",
        "severity": "<critical/high/medium/low>",
        "cwe": "<CWE-XXX>"
      }}
    ]
  }}
}}

Be thorough but avoid false positives. Only report actual security concerns."""

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
                json_match = re.search(r'\{[\s\S]*\}', text)
                if json_match:
                    return json.loads(json_match.group())
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
        progress_callback: Optional[callable] = None
    ) -> List[TracedFlow]:
        """
        Trace data flows from entry points to sinks.
        This is the core agentic capability - the LLM can request additional code.
        """
        flows = []
        total_pairs = len(entry_points) * len(sinks)
        processed = 0
        
        for entry_point in entry_points:
            for sink in sinks:
                processed += 1
                
                if progress_callback and processed % 10 == 0:
                    progress_callback(f"Tracing flow {processed}/{total_pairs}")
                
                # Quick heuristic: skip if in completely different areas
                if not self._could_be_connected(entry_point, sink):
                    continue
                
                # Use LLM to trace the flow
                flow = await self._trace_single_flow(entry_point, sink)
                if flow and flow.is_exploitable:
                    flows.append(flow)
        
        self.flows = flows
        return flows
    
    def _could_be_connected(self, entry_point: EntryPoint, sink: DangerousSink) -> bool:
        """Quick heuristic to check if flow tracing is worth attempting"""
        # Same file is likely connected
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
        
        return True  # Default to checking (conservative)
    
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
        
        prompt = f"""Analyze if user input can flow from this ENTRY POINT to this SINK.

ENTRY POINT:
File: {entry_point.file_path}
Line: {entry_point.line_number}
Type: {entry_point.entry_type}
Variable: {entry_point.variable_name}
Code:
```
{entry_chunk.content[:1500]}
```

SINK:
File: {sink.file_path}
Line: {sink.line_number}
Type: {sink.sink_type}
Function: {sink.function_name}
Potential Vulnerability: {sink.vulnerability_type}
Code:
```
{sink_chunk.content[:1500]}
```

ADDITIONAL CONTEXT:
{context_code}

ANALYSIS REQUIRED:
1. Can the user input from the entry point reach the sink?
2. If yes, trace the exact data flow path
3. Is there any sanitization/validation that would prevent exploitation?
4. What is the likelihood this is exploitable?

If you need to see additional code to trace the flow, specify:
"NEED_MORE_CODE: <file_path>:<function_name>"

Otherwise, return JSON:
{{
  "flow_exists": true/false,
  "is_exploitable": true/false,
  "confidence": 0.0-1.0,
  "flow_steps": [
    {{
      "file": "<file>",
      "line": <line>,
      "code": "<code_snippet>",
      "variable": "<variable_name>",
      "transformation": "<what_happens_to_data>"
    }}
  ],
  "sanitization_present": true/false,
  "sanitization_analysis": "<analysis of any sanitization>",
  "reason": "<explanation>"
}}"""

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
            
            # Parse response
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                result = json.loads(json_match.group())
                
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
                json_match = re.search(r'\{[\s\S]*\}', text)
                if json_match:
                    result = json.loads(json_match.group())
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
        
        prompt = f"""Generate a detailed security vulnerability report for this data flow.

VULNERABILITY TYPE: {flow.sink.vulnerability_type}
SEVERITY: {flow.sink.severity}
CWE: {flow.sink.cwe_id}

ENTRY POINT:
- File: {flow.entry_point.file_path}
- Line: {flow.entry_point.line_number}
- Type: {flow.entry_point.entry_type}
- Variable: {flow.entry_point.variable_name}

DANGEROUS SINK:
- File: {flow.sink.file_path}
- Line: {flow.sink.line_number}
- Function: {flow.sink.function_name}

DATA FLOW:
{self._format_flow_steps(flow.steps)}

SANITIZATION ANALYSIS:
{flow.sanitization_analysis}

Generate a comprehensive report in JSON:
{{
  "title": "<Brief vulnerability title>",
  "description": "<Detailed description of the vulnerability>",
  "exploit_scenario": "<Step-by-step exploitation scenario>",
  "remediation": "<Specific remediation steps>",
  "code_fix": "<Example fixed code if applicable>",
  "owasp_category": "<OWASP Top 10 category>",
  "confidence": 0.0-1.0,
  "false_positive_likelihood": 0.0-1.0
}}"""

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
                json_match = re.search(r'\{[\s\S]*\}', text)
                if json_match:
                    result = json.loads(json_match.group())
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
        progress_callback: Optional[callable] = None
    ) -> str:
        """
        Start a new agentic scan.
        Returns the scan_id for tracking.
        """
        import time
        start_time = time.time()
        
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
        
        try:
            # Phase 1: Code Chunking
            progress.phase = ScanPhase.CHUNKING
            progress.message = "Breaking code into analyzable chunks..."
            if progress_callback:
                progress_callback(progress)
            
            chunks = self.chunker.chunk_project(project_path, file_extensions)
            progress.total_chunks = len(chunks)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Created {len(chunks)} code chunks")
            
            # Phase 2: Entry Point Detection
            progress.phase = ScanPhase.ENTRY_POINT_DETECTION
            progress.message = "Identifying user input entry points..."
            if progress_callback:
                progress_callback(progress)
            
            def update_progress(msg: str):
                progress.message = msg
                if progress_callback:
                    progress_callback(progress)
            
            entry_points, sinks = await self.analyzer.analyze_chunks(chunks, update_progress)
            progress.entry_points_found = len(entry_points)
            progress.analyzed_chunks = len(chunks)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Found {len(entry_points)} entry points and {len(sinks)} sinks")
            
            # Phase 3: Flow Tracing
            progress.phase = ScanPhase.FLOW_TRACING
            progress.message = "Tracing data flows from inputs to sinks..."
            if progress_callback:
                progress_callback(progress)
            
            flows = await self.analyzer.trace_flows(entry_points, sinks, update_progress)
            progress.flows_traced = len(flows)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Traced {len(flows)} exploitable flows")
            
            # Phase 4: Vulnerability Analysis
            progress.phase = ScanPhase.VULNERABILITY_ANALYSIS
            progress.message = "Generating detailed vulnerability reports..."
            if progress_callback:
                progress_callback(progress)
            
            vulnerabilities = await self.analyzer.analyze_vulnerabilities(flows, update_progress)
            progress.vulnerabilities_found = len(vulnerabilities)
            progress.phase_progress = 1.0
            
            logger.info(f"AgenticScan: Generated {len(vulnerabilities)} vulnerability reports")
            
            # Phase 5: Report Generation
            progress.phase = ScanPhase.REPORT_GENERATION
            progress.message = "Compiling final report..."
            if progress_callback:
                progress_callback(progress)
            
            duration = time.time() - start_time
            
            # Build result
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
                vulnerabilities=vulnerabilities,
                statistics=self._build_statistics(vulnerabilities, entry_points, sinks, flows),
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
        flows: List[TracedFlow]
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
