import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, Callable, Tuple
import hashlib

from sqlalchemy.orm import Session

from backend import models
from backend.core.config import settings
from backend.core.exceptions import ScanError
from backend.core.logging import get_logger
from backend.services import cve_service, dependency_service, report_service
from backend.services import secret_service, eslint_service, epss_service, semgrep_service
from backend.services import nvd_service, bandit_service, gosec_service
from backend.services import spotbugs_service, clangtidy_service
from backend.services import ai_analysis_service
from backend.services import php_scanner_service, brakeman_service, cargo_audit_service, cppcheck_service
from backend.services import deduplication_service, transitive_deps_service, reachability_service
from backend.services import docker_scan_service, iac_scan_service
from backend.services import sensitive_data_service
from backend.services.codebase_service import (
    create_code_chunks,
    iter_source_files,
    split_into_chunks,
    unpack_zip_to_temp,
)
from backend.services.embedding_service import enrich_code_chunks
from backend.services.websocket_service import progress_manager
from backend.services.webhook_service import notify_scan_complete, get_webhooks
# Import ExternalIntelligence for unified AI pipeline
from backend.services.agentic_scan_service import ExternalIntelligence

logger = get_logger(__name__)

# Dynamically determine optimal parallelism based on available CPUs
CPU_COUNT = os.cpu_count() or 4
# Maximum parallel scanners - optimize based on CPU cores (I/O bound so 2x cores works well)
MAX_PARALLEL_SCANNERS = min(settings.max_parallel_scanners, max(4, CPU_COUNT * 2))
# Maximum parallel phases for concurrent execution
MAX_PARALLEL_PHASES = min(4, CPU_COUNT)
# Parallel file processing workers (I/O bound)
MAX_FILE_PROCESSORS = min(8, CPU_COUNT * 2)
# Batch size for processing files in large codebases
FILE_PROCESSING_BATCH_SIZE = 100
# Maximum total chunks to process (prevents memory issues on huge repos)
MAX_TOTAL_CHUNKS = settings.max_total_chunks
# Memory-efficient chunk limit before flushing to DB
CHUNK_FLUSH_THRESHOLD = settings.chunk_flush_threshold

# Files to skip entirely (faster filtering)
SKIP_EXTENSIONS: Set[str] = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv', '.flv',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
    '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm',
    '.ttf', '.woff', '.woff2', '.eot', '.otf',
    '.pyc', '.pyo', '.class', '.o', '.obj',
    '.min.js', '.min.css',  # Minified files
}

# Directories to skip entirely
SKIP_DIRS: Set[str] = {
    'node_modules', '__pycache__', '.git', '.svn', '.hg',
    'venv', '.venv', 'env', '.env', 'virtualenv',
    'dist', 'build', 'target', 'out', 'bin', 'obj',
    '.idea', '.vscode', '.vs',
    'coverage', '.nyc_output', 'htmlcov',
    '.next', '.nuxt', '.cache',
}

# Maximum file size to process (skip huge generated files)
MAX_FILE_SIZE = 1024 * 1024  # 1MB


# Thread-safe progress tracking for parallel phases
class ParallelPhaseTracker:
    """Track progress of multiple parallel phases."""
    
    def __init__(self, scan_run_id: int, base_progress: int, progress_range: int):
        self.scan_run_id = scan_run_id
        self.base_progress = base_progress
        self.progress_range = progress_range
        self.phase_progress: Dict[str, int] = {}
        self._lock = __import__('threading').Lock()
    
    def update(self, phase: str, progress: int, message: str = ""):
        """Update progress for a specific phase."""
        with self._lock:
            self.phase_progress[phase] = progress
            # Calculate overall progress based on all phases
            if self.phase_progress:
                avg_progress = sum(self.phase_progress.values()) / len(self.phase_progress)
                overall = self.base_progress + int((avg_progress / 100) * self.progress_range)
                _broadcast_progress(self.scan_run_id, phase, overall, message)


def _broadcast_progress(scan_run_id: int, phase: str, progress: int, message: str = ""):
    """Helper to broadcast scan progress via Redis pub/sub to WebSocket clients."""
    try:
        # Use synchronous publish for worker process
        progress_manager.publish_progress(scan_run_id, phase, progress, message)
    except Exception as e:
        logger.debug(f"Could not broadcast progress: {e}")


def _detect_language(path: Path) -> str:
    """Detect programming language from file extension."""
    # Get extension in lowercase
    ext = path.suffix.lower()
    
    # Also check for special filenames without extension
    filename = path.name.lower()
    
    # Special filename mappings (files without meaningful extension)
    special_files = {
        "dockerfile": "dockerfile",
        "docker-compose.yml": "yaml",
        "docker-compose.yaml": "yaml",
        ".dockerignore": "dockerfile",
        ".gitignore": "gitignore",
        ".env": "env",
        ".env.example": "env",
        ".env.local": "env",
        "makefile": "makefile",
        "cmakelists.txt": "cmake",
        "gemfile": "ruby",
        "rakefile": "ruby",
        "podfile": "ruby",
        "vagrantfile": "ruby",
        "jenkinsfile": "groovy",
        "procfile": "yaml",
    }
    
    if filename in special_files:
        return special_files[filename]
    
    # Extension-based mapping (comprehensive)
    mapping = {
        # Python
        ".py": "python",
        ".pyx": "python",
        ".pyi": "python",
        ".pyw": "python",
        
        # JavaScript / TypeScript
        ".js": "javascript",
        ".jsx": "javascriptreact",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescriptreact",
        ".mts": "typescript",
        ".cts": "typescript",
        
        # Web
        ".html": "html",
        ".htm": "html",
        ".xhtml": "html",
        ".css": "css",
        ".scss": "scss",
        ".sass": "sass",
        ".less": "less",
        ".vue": "vue",
        ".svelte": "svelte",
        
        # Data / Config
        ".json": "json",
        ".json5": "json5",
        ".jsonc": "jsonc",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".xml": "xml",
        ".toml": "toml",
        ".ini": "ini",
        ".cfg": "ini",
        ".conf": "conf",
        ".properties": "properties",
        ".env": "env",
        
        # JVM Languages
        ".java": "java",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".scala": "scala",
        ".groovy": "groovy",
        ".gradle": "groovy",
        ".clj": "clojure",
        ".cljs": "clojurescript",
        
        # Systems Programming
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".hpp": "cpp",
        ".hxx": "cpp",
        ".hh": "cpp",
        ".rs": "rust",
        ".go": "go",
        ".zig": "zig",
        
        # Apple / Mobile
        ".swift": "swift",
        ".m": "objective-c",
        ".mm": "objective-cpp",
        
        # .NET
        ".cs": "csharp",
        ".fs": "fsharp",
        ".vb": "vb",
        ".csproj": "xml",
        ".fsproj": "xml",
        ".vbproj": "xml",
        ".sln": "sln",
        
        # Scripting
        ".rb": "ruby",
        ".erb": "erb",
        ".php": "php",
        ".phtml": "php",
        ".pl": "perl",
        ".pm": "perl",
        ".lua": "lua",
        ".r": "r",
        ".R": "r",
        
        # Shell
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".fish": "shell",
        ".ps1": "powershell",
        ".psm1": "powershell",
        ".bat": "batch",
        ".cmd": "batch",
        
        # Database
        ".sql": "sql",
        ".psql": "sql",
        ".mysql": "sql",
        
        # Functional
        ".hs": "haskell",
        ".lhs": "haskell",
        ".elm": "elm",
        ".ex": "elixir",
        ".exs": "elixir",
        ".erl": "erlang",
        ".ml": "ocaml",
        ".mli": "ocaml",
        
        # Documentation
        ".md": "markdown",
        ".markdown": "markdown",
        ".rst": "restructuredtext",
        ".txt": "plaintext",
        ".adoc": "asciidoc",
        ".tex": "latex",
        
        # Build / DevOps
        ".dockerfile": "dockerfile",
        ".tf": "terraform",
        ".tfvars": "terraform",
        ".hcl": "hcl",
        ".bicep": "bicep",
        ".nix": "nix",
        
        # GraphQL / API
        ".graphql": "graphql",
        ".gql": "graphql",
        ".proto": "protobuf",
        
        # Images (for reference - usually not scanned)
        ".svg": "svg",
        ".png": "image",
        ".jpg": "image",
        ".jpeg": "image",
        ".gif": "image",
        ".ico": "image",
        ".webp": "image",
        
        # Other
        ".lock": "lockfile",
        ".editorconfig": "editorconfig",
        ".gitattributes": "gitattributes",
    }
    return mapping.get(ext, "unknown")


def _should_skip_file(file_path: Path) -> bool:
    """
    Fast check to determine if a file should be skipped.
    Returns True for binary, large, or irrelevant files.
    """
    # Check extension
    ext = file_path.suffix.lower()
    if ext in SKIP_EXTENSIONS:
        return True
    
    # Check for minified files (common pattern)
    name = file_path.name.lower()
    if name.endswith('.min.js') or name.endswith('.min.css'):
        return True
    
    # Check if in skip directory
    parts = file_path.parts
    for part in parts:
        if part.lower() in SKIP_DIRS:
            return True
    
    # Check file size (skip large files)
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return True
    except (OSError, IOError):
        pass
    
    return False


def _filter_source_files_fast(source_root: Path, files: List[Path]) -> List[Path]:
    """
    Fast parallel filtering of source files.
    Returns only files that should be processed.
    """
    filtered = []
    skipped = 0
    
    for f in files:
        if not _should_skip_file(f):
            filtered.append(f)
        else:
            skipped += 1
    
    if skipped > 0:
        logger.debug(f"Fast filter: skipped {skipped} files (binary/large/irrelevant)")
    
    return filtered


def build_external_intelligence(
    vulns: List[models.Vulnerability],
    scanner_findings: List[models.Finding],
    deps: List[models.Dependency],
    enriched_vulns: Optional[Dict[int, Dict]] = None,
    source_root: Optional[Path] = None
) -> ExternalIntelligence:
    """
    Build ExternalIntelligence from scan results to provide context
    for AI-guided code analysis.
    
    This enables the unified pipeline where AI knows about:
    - Which dependencies have CVEs (and their severity/EPSS)
    - What files were flagged by SAST scanners
    - Which files import vulnerable packages
    
    Args:
        vulns: CVE/vulnerability models from cve_service
        scanner_findings: Findings from SAST scanners (bandit, semgrep, etc.)
        deps: Parsed dependencies from the codebase
        enriched_vulns: Optional dict with NVD/EPSS enrichment data
        source_root: Optional source directory for import analysis
        
    Returns:
        ExternalIntelligence object ready to pass to AgenticAnalyzer
    """
    intel = ExternalIntelligence()
    
    # Build dependency map (name -> version)
    dep_map = {d.id: {"name": d.name, "version": d.version} for d in deps}
    dep_name_map = {d.name.lower(): d for d in deps}
    
    # Process CVE findings
    for vuln in vulns:
        dep_info = dep_map.get(vuln.dependency_id, {})
        epss_data = enriched_vulns.get(vuln.id, {}) if enriched_vulns else {}
        
        cve_entry = {
            "external_id": vuln.external_id,
            "package": dep_info.get("name", "unknown"),
            "version": dep_info.get("version"),
            "severity": vuln.severity or "unknown",
            "cvss_score": vuln.cvss_score,
            "epss_score": epss_data.get("epss_score"),
            "in_kev": epss_data.get("in_kev", False),
            "description": vuln.title,
            "affected_functions": [],  # Could be enriched from NVD
        }
        
        # Try to get affected functions from NVD enrichment
        nvd_data = epss_data.get("nvd_enrichment", {})
        if nvd_data:
            cve_entry["description"] = nvd_data.get("description", vuln.title)
            # Could parse CWE -> common functions mapping here
        
        intel.cve_findings.append(cve_entry)
    
    # Process SAST findings (convert models to dicts)
    for finding in scanner_findings:
        sast_entry = {
            "file": finding.file_path,
            "line": finding.start_line,
            "type": finding.type,
            "severity": finding.severity,
            "summary": finding.summary,
            "scanner": finding.details.get("scanner") if finding.details else None,
        }
        intel.sast_findings.append(sast_entry)
    
    # Analyze which files import vulnerable packages
    if source_root:
        vulnerable_packages = {c["package"].lower() for c in intel.cve_findings}
        
        # Quick scan for imports
        for source_file in source_root.rglob("*"):
            if not source_file.is_file():
                continue
            ext = source_file.suffix.lower()
            if ext not in {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb"}:
                continue
            
            try:
                content = source_file.read_text(encoding="utf-8", errors="ignore")[:50000]
                rel_path = str(source_file.relative_to(source_root))
                
                # Check for imports of vulnerable packages
                for pkg in vulnerable_packages:
                    # Python: import pkg, from pkg import
                    # JS/TS: require('pkg'), import ... from 'pkg'
                    # Simplified check (can be improved with AST parsing)
                    if (f"import {pkg}" in content.lower() or 
                        f"from {pkg}" in content.lower() or
                        f"require('{pkg}')" in content.lower() or
                        f'require("{pkg}")' in content.lower() or
                        f"from '{pkg}'" in content.lower() or
                        f'from "{pkg}"' in content.lower()):
                        
                        # Get the CVEs for this package
                        pkg_cves = [c["external_id"] for c in intel.cve_findings 
                                   if c["package"].lower() == pkg]
                        
                        intel.vulnerable_import_files.append({
                            "file": rel_path,
                            "package": pkg,
                            "cves": pkg_cves,
                        })
                        break  # One per file is enough
                        
            except Exception:
                continue
    
    logger.info(f"Built ExternalIntelligence: {len(intel.cve_findings)} CVEs, "
               f"{len(intel.sast_findings)} SAST findings, "
               f"{len(intel.vulnerable_import_files)} files importing vulnerable deps")
    
    return intel


def _process_single_file(args: Tuple[Path, Path, int]) -> Tuple[Optional[str], List[Any], Optional[List[models.Finding]]]:
    """
    Process a single file: read, chunk, and run static checks.
    Designed to be called in parallel.
    
    Args:
        args: Tuple of (file_path, source_root, project_id)
        
    Returns:
        Tuple of (file_path, chunks, static_findings) or None on error
    """
    file_path, source_root, project_id = args
    
    try:
        # Skip if file should be filtered
        if _should_skip_file(file_path):
            return None, [], None
        
        # Read file content
        try:
            contents = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None, [], None
        
        # Skip empty or very small files
        if len(contents) < 10:
            return None, [], None
        
        # Split into chunks
        chunks = split_into_chunks(contents)
        
        # Limit chunks per file to prevent single file domination
        if len(chunks) > 50:
            chunks = chunks[:50]
        
        # Run static pattern checks
        findings = _static_checks(file_path, contents)
        
        # Get relative path
        try:
            rel_path = str(file_path.relative_to(source_root))
        except ValueError:
            rel_path = str(file_path)
        
        return rel_path, chunks, findings
        
    except Exception as e:
        logger.debug(f"Error processing file {file_path}: {e}")
        return None, [], None


def _process_files_parallel(
    source_root: Path,
    files: List[Path],
    project: models.Project,
    progress_callback: Optional[Callable[[int, str], None]] = None
) -> Tuple[List[Tuple[str, List[Any]]], List[models.Finding]]:
    """
    Process multiple files in parallel for chunking and static analysis.
    
    Returns:
        Tuple of (list of (file_path, chunks), list of static findings)
    """
    all_results = []
    all_findings = []
    processed = 0
    total = len(files)
    
    # Prepare args for parallel processing
    args_list = [(f, source_root, project.id) for f in files]
    
    # Use ThreadPoolExecutor for I/O-bound file reading
    with ThreadPoolExecutor(max_workers=MAX_FILE_PROCESSORS) as executor:
        # Submit all tasks
        futures = {executor.submit(_process_single_file, args): args[0] for args in args_list}
        
        # Collect results as they complete
        for future in as_completed(futures):
            try:
                rel_path, chunks, findings = future.result(timeout=30)
                
                if rel_path and chunks:
                    all_results.append((rel_path, chunks))
                
                if findings:
                    all_findings.extend(findings)
                
                processed += 1
                
                # Progress update every 50 files
                if progress_callback and processed % 50 == 0:
                    progress_callback(processed, f"Processed {processed}/{total} files")
                    
            except Exception as e:
                logger.debug(f"File processing failed: {e}")
                processed += 1
    
    return all_results, all_findings


def _get_file_hashes(files: List[Path]) -> Dict[str, str]:
    """
    Compute hashes for files in parallel.
    Returns dict mapping relative path to content hash.
    """
    hashes = {}
    
    def hash_file(f: Path) -> Tuple[str, Optional[str]]:
        try:
            content = f.read_bytes()
            return str(f), hashlib.md5(content).hexdigest()
        except Exception:
            return str(f), None
    
    with ThreadPoolExecutor(max_workers=MAX_FILE_PROCESSORS) as executor:
        results = executor.map(hash_file, files)
        for path, h in results:
            if h:
                hashes[path] = h
    
    return hashes


def _compute_code_hash(code: str) -> str:
    """Compute a hash of code content for change detection."""
    return hashlib.sha256(code.encode()).hexdigest()[:32]


def _get_existing_embeddings(
    db: Session, 
    project_id: int
) -> dict:
    """
    Get existing code chunks with embeddings for a project.
    Returns a dict mapping (file_path, start_line, code_hash) -> embedding.
    This allows us to reuse embeddings when code hasn't changed.
    """
    existing_chunks = db.query(models.CodeChunk).filter(
        models.CodeChunk.project_id == project_id,
        models.CodeChunk.embedding.isnot(None)
    ).all()
    
    embeddings_map = {}
    for chunk in existing_chunks:
        # Only include chunks that have non-zero embeddings
        if chunk.embedding is not None:
            # Check if it's a zero vector (placeholder)
            embedding_list = list(chunk.embedding) if hasattr(chunk.embedding, '__iter__') else []
            if embedding_list and any(v != 0.0 for v in embedding_list[:10]):  # Check first 10 values
                code_hash = _compute_code_hash(chunk.code)
                key = (chunk.file_path, chunk.start_line, code_hash)
                embeddings_map[key] = embedding_list
    
    return embeddings_map


def _reuse_or_generate_embeddings(
    db: Session,
    project: models.Project,
    new_chunks: List[models.CodeChunk],
    existing_embeddings: dict
) -> tuple:
    """
    Check which chunks already have embeddings that can be reused.
    Returns (chunks_needing_embeddings, chunks_with_reused_embeddings, reuse_count).
    """
    chunks_to_embed = []
    reused_count = 0
    
    for chunk in new_chunks:
        code_hash = _compute_code_hash(chunk.code)
        key = (chunk.file_path, chunk.start_line, code_hash)
        
        if key in existing_embeddings:
            # Reuse existing embedding
            chunk.embedding = existing_embeddings[key]
            reused_count += 1
        else:
            chunks_to_embed.append(chunk)
    
    return chunks_to_embed, reused_count


def _run_scanners_parallel(
    source_root: Path, 
    timeout_per_scanner: int = None,
    tracker: 'ParallelPhaseTracker' = None
) -> Dict[str, List[Any]]:
    """
    Run all SAST scanners in parallel using ThreadPoolExecutor.
    
    Each scanner runs in its own thread (they're subprocess-bound anyway).
    Returns a dict mapping scanner name to list of findings.
    
    Features for large codebases:
    - Per-scanner timeout to prevent hanging
    - Progressive result collection
    - Graceful degradation on scanner failures
    - Real-time progress updates for each scanner
    
    Args:
        source_root: Path to the source code directory
        timeout_per_scanner: Maximum seconds per scanner (uses config default if None)
        tracker: Optional progress tracker for real-time scanner updates
        
    Returns:
        Dict mapping scanner name to list of findings
    """
    if timeout_per_scanner is None:
        timeout_per_scanner = settings.scanner_timeout
    results: Dict[str, List[Any]] = {
        "semgrep": [],
        "bandit": [],
        "gosec": [],
        "spotbugs": [],
        "clangtidy": [],
        "cppcheck": [],
        "eslint": [],
        "secrets": [],
        "php": [],
        "brakeman": [],
        "cargo_audit": [],
    }
    
    # Detect project languages for smart scanner selection
    from backend.services.git_service import detect_project_languages
    detected_languages = detect_project_languages(str(source_root))
    language_set = set(detected_languages.keys())
    
    # Define scanner tasks: (name, check_available_func, run_func)
    # Only run scanners relevant to detected languages
    scanner_tasks = []
    
    # Semgrep (all languages) - always useful as fallback
    if semgrep_service.is_semgrep_available():
        scanner_tasks.append(("semgrep", lambda: semgrep_service.run_security_audit(source_root)))
    
    # Bandit (Python) - only if Python files detected
    if bandit_service.is_bandit_available() and 'python' in language_set:
        scanner_tasks.append(("bandit", lambda: bandit_service.run_security_audit(source_root)))
    elif 'python' not in language_set:
        logger.debug("Skipping Bandit - no Python files detected")
    
    # gosec (Go) - only if Go files detected
    if gosec_service.is_gosec_available() and 'go' in language_set:
        scanner_tasks.append(("gosec", lambda: gosec_service.run_security_audit(source_root)))
    elif 'go' not in language_set:
        logger.debug("Skipping gosec - no Go files detected")
    
    # SpotBugs (Java/Kotlin) - only if Java/Kotlin files detected
    if spotbugs_service.is_spotbugs_available() and language_set & {'java', 'kotlin'}:
        scanner_tasks.append(("spotbugs", lambda: spotbugs_service.run_security_audit(source_root)))
    elif not language_set & {'java', 'kotlin'}:
        logger.debug("Skipping SpotBugs - no Java/Kotlin files detected")
    
    # clang-tidy (C/C++) - only if C/C++ files detected
    if clangtidy_service.is_clangtidy_available() and language_set & {'c', 'cpp'}:
        scanner_tasks.append(("clangtidy", lambda: clangtidy_service.run_security_audit(source_root)))
    elif not language_set & {'c', 'cpp'}:
        logger.debug("Skipping clang-tidy - no C/C++ files detected")
    
    # Cppcheck (C/C++) - complementary scanner for additional coverage
    if cppcheck_service.is_cppcheck_available() and language_set & {'c', 'cpp'}:
        scanner_tasks.append(("cppcheck", lambda: cppcheck_service.run_security_audit(source_root)))
    elif not language_set & {'c', 'cpp'}:
        logger.debug("Skipping Cppcheck - no C/C++ files detected")
    else:
        logger.debug("Skipping Cppcheck - cppcheck not available")
    
    # ESLint (JS/TS) - only if JavaScript/TypeScript files detected
    if language_set & {'javascript', 'typescript'}:
        scanner_tasks.append(("eslint", lambda: eslint_service.run_eslint_security_scan(str(source_root))))
    else:
        logger.debug("Skipping ESLint - no JS/TS files detected")
    
    # PHP Scanner (PHP) - only if PHP files detected
    if php_scanner_service.is_progpilot_available() and 'php' in language_set:
        scanner_tasks.append(("php", lambda: php_scanner_service.run_security_audit(source_root)))
    elif 'php' not in language_set:
        logger.debug("Skipping PHP scanner - no PHP files detected")
    else:
        logger.debug("Skipping PHP scanner - progpilot not available")
    
    # Brakeman (Ruby) - only if Ruby files detected
    if brakeman_service.is_brakeman_available() and 'ruby' in language_set:
        scanner_tasks.append(("brakeman", lambda: brakeman_service.run_security_audit(source_root)))
    elif 'ruby' not in language_set:
        logger.debug("Skipping Brakeman - no Ruby files detected")
    else:
        logger.debug("Skipping Brakeman - brakeman not available")
    
    # Cargo Audit (Rust) - only if Rust files detected
    if 'rust' in language_set:
        scanner_tasks.append(("cargo_audit", lambda: cargo_audit_service.run_security_audit(source_root)))
    else:
        logger.debug("Skipping Cargo Audit - no Rust files detected")
    
    # Secret scanner (Python-based, always available) - always run
    scanner_tasks.append(("secrets", lambda: secret_service.scan_directory(str(source_root))))
    
    if not scanner_tasks:
        logger.warning("No scanners available")
        return results
    
    logger.info(f"Smart scanner selection: Running {len(scanner_tasks)} scanners for languages {list(language_set)}: {[t[0] for t in scanner_tasks]}")
    
    # Broadcast which scanners will run
    if tracker:
        scanner_names = [t[0] for t in scanner_tasks]
        tracker.update("sast", 15, f"🔍 Running {len(scanner_tasks)} scanners: {', '.join(scanner_names)}")
    
    # Scanner display names for nicer progress messages
    scanner_display = {
        "semgrep": "🔎 Semgrep (multi-language)",
        "bandit": "🐍 Bandit (Python)",
        "gosec": "🔷 Gosec (Go)",
        "spotbugs": "☕ SpotBugs (Java)",
        "clangtidy": "🔧 Clang-Tidy (C/C++)",
        "cppcheck": "🔧 Cppcheck (C/C++)",
        "eslint": "📜 ESLint (JS/TS)",
        "secrets": "🔐 Secret Scanner",
        "php": "🐘 PHP Security",
        "brakeman": "💎 Brakeman (Ruby)",
        "cargo_audit": "🦀 Cargo Audit (Rust)",
    }
    
    # Track completed scanners for progress
    completed_count = [0]  # Use list for closure mutability
    
    # Run scanners in parallel with individual timeouts
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANNERS) as executor:
        # Submit all tasks
        future_to_name = {
            executor.submit(run_func): name 
            for name, run_func in scanner_tasks
        }
        
        # Collect results as they complete with timeout
        for future in as_completed(future_to_name, timeout=timeout_per_scanner * len(scanner_tasks)):
            name = future_to_name[future]
            try:
                scanner_results = future.result(timeout=timeout_per_scanner)
                results[name] = scanner_results if scanner_results else []
                completed_count[0] += 1
                count = len(results[name])
                logger.info(f"Scanner {name} completed: {count} findings")
                
                # Broadcast individual scanner completion
                if tracker:
                    display = scanner_display.get(name, name)
                    progress = 15 + int((completed_count[0] / len(scanner_tasks)) * 80)
                    if count > 0:
                        tracker.update("sast", progress, f"✅ {display}: {count} findings")
                    else:
                        tracker.update("sast", progress, f"✅ {display}: clean")
            except TimeoutError:
                logger.warning(f"Scanner {name} timed out after {timeout_per_scanner}s")
                results[name] = []
                completed_count[0] += 1
                if tracker:
                    display = scanner_display.get(name, name)
                    progress = 15 + int((completed_count[0] / len(scanner_tasks)) * 80)
                    tracker.update("sast", progress, f"⏱️ {display}: timeout")
            except Exception as e:
                logger.error(f"Scanner {name} failed: {e}")
                results[name] = []
                completed_count[0] += 1
                if tracker:
                    display = scanner_display.get(name, name)
                    progress = 15 + int((completed_count[0] / len(scanner_tasks)) * 80)
                    tracker.update("sast", progress, f"⚠️ {display}: failed")
    
    total_findings = sum(len(v) for v in results.values())
    logger.info(f"All scanners complete. Total findings: {total_findings}")
    
    return results


def _run_parallel_scan_phases(
    source_root: Path,
    project: models.Project,
    tracker: ParallelPhaseTracker,
    timeout: int = None
) -> Dict[str, Any]:
    """
    Run multiple independent scan phases in parallel.
    
    This includes:
    - SAST scanners (Semgrep, Bandit, etc.)
    - Docker scanning (Dockerfile + image vulns)
    - IaC scanning (Terraform, K8s, CloudFormation)
    - Dependency parsing
    
    These phases don't depend on each other and can run concurrently.
    
    Args:
        source_root: Path to extracted source code
        project: Project being scanned
        tracker: Progress tracker for parallel updates
        timeout: Per-phase timeout
        
    Returns:
        Dict with results from each phase
    """
    if timeout is None:
        timeout = settings.scanner_timeout
    
    results = {
        "sast": {},
        "docker": None,
        "iac": None,
        "dependencies": [],
    }
    
    def run_sast():
        """Run all SAST scanners."""
        tracker.update("sast", 10, "🔍 Initializing security scanners...")
        sast_results = _run_scanners_parallel(source_root, timeout, tracker=tracker)
        total_findings = sum(len(v) for v in sast_results.values())
        tracker.update("sast", 100, f"✅ SAST complete: {total_findings} findings")
        return ("sast", sast_results)
    
    def run_docker():
        """Run Docker scanning."""
        tracker.update("docker", 10, "🐳 Scanning Dockerfiles and images...")
        try:
            docker_result = docker_scan_service.scan_docker_resources(
                source_root,
                scan_images=docker_scan_service.is_trivy_available(),
                image_timeout=timeout
            )
            count = len(docker_result.dockerfile_findings) if docker_result else 0
            tracker.update("docker", 100, f"✅ Docker scan: {count} findings")
            return ("docker", docker_result)
        except Exception as e:
            logger.warning(f"Docker scanning failed: {e}")
            tracker.update("docker", 100, "⏭️ Docker scan skipped")
            return ("docker", None)
    
    def run_iac():
        """Run IaC scanning."""
        tracker.update("iac", 10, "🏗️ Scanning Infrastructure as Code...")
        try:
            iac_result = iac_scan_service.scan_iac(
                source_root,
                use_checkov=iac_scan_service.is_checkov_available(),
                use_tfsec=iac_scan_service.is_tfsec_available(),
                timeout=timeout
            )
            count = len(iac_result.findings) if iac_result else 0
            tracker.update("iac", 100, f"✅ IaC scan: {count} findings")
            return ("iac", iac_result)
        except Exception as e:
            logger.warning(f"IaC scanning failed: {e}")
            tracker.update("iac", 100, "⏭️ IaC scan skipped")
            return ("iac", None)
    
    def run_deps():
        """Parse dependencies."""
        tracker.update("dependencies", 10, "📦 Parsing project dependencies...")
        try:
            deps = dependency_service.parse_dependencies(project, source_root)
            tracker.update("dependencies", 100, f"✅ Found {len(deps)} dependencies")
            return ("dependencies", deps)
        except Exception as e:
            logger.warning(f"Dependency parsing failed: {e}")
            tracker.update("dependencies", 100, "⚠️ Dependency parsing failed")
            return ("dependencies", [])
    
    # Run all phases in parallel
    phases = [run_sast, run_docker, run_iac, run_deps]
    logger.info(f"Running {len(phases)} scan phases in parallel")
    
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_PHASES) as executor:
        futures = {executor.submit(phase): phase.__name__ for phase in phases}
        
        for future in as_completed(futures, timeout=timeout * len(phases)):
            phase_name = futures[future]
            try:
                key, result = future.result(timeout=timeout)
                results[key] = result
                logger.debug(f"Phase {phase_name} completed")
            except TimeoutError:
                logger.warning(f"Phase {phase_name} timed out")
            except Exception as e:
                logger.error(f"Phase {phase_name} failed: {e}")
    
    return results


def _convert_scanner_results_to_findings(
    scanner_results: Dict[str, List[Any]], 
    source_root: Path
) -> List[models.Finding]:
    """Convert raw scanner results into Finding models."""
    findings: List[models.Finding] = []
    
    # Process Semgrep findings
    for sg_finding in scanner_results.get("semgrep", []):
        try:
            rel_path = str(Path(sg_finding.file_path).relative_to(source_root))
        except ValueError:
            rel_path = sg_finding.file_path
        
        findings.append(
            models.Finding(
                type="semgrep",
                severity=sg_finding.severity,
                file_path=rel_path,
                start_line=sg_finding.line_start,
                end_line=sg_finding.line_end,
                summary=f"[{sg_finding.rule_id}] {sg_finding.message}",
                details={
                    "rule_id": sg_finding.rule_id,
                    "category": sg_finding.category,
                    "cwe": sg_finding.cwe,
                    "owasp": sg_finding.owasp,
                    "code_snippet": sg_finding.code_snippet[:500] if sg_finding.code_snippet else None,
                    "fix": sg_finding.fix,
                },
            )
        )
    
    # Process Bandit findings
    for bandit_finding in scanner_results.get("bandit", []):
        try:
            rel_path = str(Path(bandit_finding.file_path).relative_to(source_root))
        except ValueError:
            rel_path = bandit_finding.file_path
        
        findings.append(
            models.Finding(
                type="bandit",
                severity=bandit_finding.severity,
                file_path=rel_path,
                start_line=bandit_finding.line_number,
                end_line=bandit_finding.line_range[1] if bandit_finding.line_range and len(bandit_finding.line_range) > 1 else bandit_finding.line_number,
                summary=f"[{bandit_finding.test_id}] {bandit_finding.message}",
                details={
                    "test_id": bandit_finding.test_id,
                    "test_name": bandit_finding.test_name,
                    "confidence": bandit_finding.confidence,
                    "cwe": bandit_finding.cwe,
                    "code_snippet": bandit_finding.code[:500] if bandit_finding.code else None,
                    "more_info": bandit_finding.more_info,
                },
            )
        )
    
    # Process gosec findings
    for gosec_finding in scanner_results.get("gosec", []):
        try:
            rel_path = str(Path(gosec_finding.file_path).relative_to(source_root))
        except ValueError:
            rel_path = gosec_finding.file_path
        
        findings.append(
            models.Finding(
                type="gosec",
                severity=gosec_finding.severity,
                file_path=rel_path,
                start_line=gosec_finding.line,
                end_line=gosec_finding.line,
                summary=f"[{gosec_finding.rule_id}] {gosec_finding.details}",
                details={
                    "rule_id": gosec_finding.rule_id,
                    "cwe": gosec_finding.cwe,
                    "confidence": gosec_finding.confidence,
                    "code_snippet": gosec_finding.code[:500] if gosec_finding.code else None,
                },
            )
        )
    
    # Process SpotBugs findings
    for sb_finding in scanner_results.get("spotbugs", []):
        findings.append(
            models.Finding(
                type="spotbugs",
                severity=sb_finding.severity,
                file_path=sb_finding.file_path,
                start_line=sb_finding.line,
                end_line=sb_finding.line,
                summary=f"[{sb_finding.bug_type}] {sb_finding.message}",
                details={
                    "bug_type": sb_finding.bug_type,
                    "category": sb_finding.category,
                    "priority": sb_finding.priority,
                    "class_name": sb_finding.class_name,
                    "method_name": sb_finding.method_name,
                    "cwe": sb_finding.cwe,
                },
            )
        )
    
    # Process clang-tidy findings
    for ct_finding in scanner_results.get("clangtidy", []):
        findings.append(
            models.Finding(
                type="clangtidy",
                severity=ct_finding.severity,
                file_path=ct_finding.file_path,
                start_line=ct_finding.line,
                end_line=ct_finding.line,
                summary=f"[{ct_finding.check_name}] {ct_finding.message}",
                details={
                    "check_name": ct_finding.check_name,
                    "column": ct_finding.column,
                    "cwe": ct_finding.cwe,
                    "code_snippet": ct_finding.code_snippet,
                },
            )
        )
    
    # Process ESLint findings
    for eslint_finding in scanner_results.get("eslint", []):
        findings.append(
            models.Finding(
                type="eslint_security",
                severity=eslint_finding.severity,
                file_path=eslint_finding.file_path,
                start_line=eslint_finding.line,
                end_line=eslint_finding.end_line,
                summary=f"[{eslint_finding.rule_id}] {eslint_finding.message}",
                details={
                    "rule_id": eslint_finding.rule_id,
                    "column": eslint_finding.column,
                },
            )
        )
    
    # Process secret findings
    for secret in scanner_results.get("secrets", []):
        findings.append(
            models.Finding(
                type="secret",
                severity=secret.severity,
                file_path=secret.file_path,
                start_line=secret.line_number,
                end_line=secret.line_number,
                summary=f"Potential {secret.secret_type} detected",
                details={
                    "secret_type": secret.secret_type,
                    "description": secret.description,
                    "masked_value": secret.masked_value,
                },
            )
        )
    
    return findings


def _static_checks(file_path: Path, contents: str) -> List[models.Finding]:
    findings: List[models.Finding] = []
    lower = contents.lower()
    patterns = [
        ("eval(", "medium", "Use of eval detected"),
        ("exec(", "medium", "Use of exec detected"),
        ("subprocess", "medium", "Subprocess usage found"),
        ("shell=true", "high", "Potential shell command injection via shell=True"),
        ("password=", "high", "Hard coded password-like string"),
        ("verify=false", "medium", "TLS verification disabled"),
        ("except Exception:", "low", "Overly broad exception handling"),
    ]
    for needle, severity, summary in patterns:
        if needle in lower:
            findings.append(
                models.Finding(
                    type="code_pattern",
                    severity=severity,
                    file_path=str(file_path),
                    start_line=1,
                    end_line=None,
                    summary=summary,
                    details={"pattern": needle},
                )
            )
    return findings


def run_scan(
    db: Session, 
    project: models.Project, 
    scan_run: Optional[models.ScanRun] = None
) -> models.Report:
    """
    Execute a full vulnerability scan on a project with unified AI pipeline.
    
    The unified pipeline runs phases in optimal order:
    1. Extract and parse source files
    2. Generate code embeddings  
    3. Parse dependencies and build trees
    4. CVE lookup + NVD/EPSS/KEV enrichment
    5. SAST scanners (Semgrep, Bandit, etc.)
    6. **AI-Guided Deep Analysis** - Agentic scan WITH CVE/SAST context
    7. Attack chain detection and final AI analysis
    8. Report generation
    
    The AI-Guided phase (step 6) is new - it passes external intelligence
    (CVEs, EPSS scores, SAST findings) to the agentic AI so it knows about
    vulnerable dependencies BEFORE analyzing code.
    
    Progress updates are broadcast via WebSocket for real-time monitoring.
    
    Args:
        db: Database session
        project: Project model to scan
        scan_run: Optional existing ScanRun to update
        
    Returns:
        Generated Report model
        
    Raises:
        ScanError: If scan fails
    """
    logger.info(f"Starting scan for project '{project.name}' (ID: {project.id})")
    
    if scan_run is None:
        scan_run = models.ScanRun(
            project_id=project.id, status="running", started_at=datetime.utcnow(), error_message=None
        )
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)
    else:
        scan_run.status = "running"
        scan_run.started_at = datetime.utcnow()
        scan_run.finished_at = None
        scan_run.error_message = None
        db.add(scan_run)
        db.commit()

    # Broadcast scan started
    _broadcast_progress(scan_run.id, "initializing", 0, "🚀 Scan started")

    # Initialize findings list
    findings: List[models.Finding] = []
    
    try:
        if not project.upload_path:
            raise ScanError("Project has no uploaded archive to scan", project_id=project.id)
        
        # Phase 1: Extract archive (5%)
        _broadcast_progress(scan_run.id, "extracting", 5, "📦 Extracting archive...")
        logger.debug(f"Extracting archive: {project.upload_path}")
        source_root = unpack_zip_to_temp(project.upload_path)
        
        all_chunks: List[models.CodeChunk] = []
        file_count = 0
        
        # Phase 2: Parse source files with PARALLEL processing (10-30%)
        _broadcast_progress(scan_run.id, "parsing", 10, "📝 Parsing source files...")
        scan_start = time.time()
        
        # Collect and filter source files
        source_files = list(iter_source_files(source_root))
        total_files_raw = len(source_files)
        
        # Fast filter to remove binary/irrelevant files
        source_files = _filter_source_files_fast(source_root, source_files)
        total_files = len(source_files)
        skipped_files = total_files_raw - total_files
        
        logger.info(f"Found {total_files} source files to process (skipped {skipped_files} irrelevant)")
        _broadcast_progress(scan_run.id, "parsing", 12, f"📝 Processing {total_files} files ({skipped_files} skipped)")
        
        # Progress callback for parallel processing
        def parsing_progress(processed: int, msg: str):
            progress_pct = 12 + int((processed / total_files) * 18) if total_files > 0 else 12
            _broadcast_progress(scan_run.id, "parsing", progress_pct, msg)
        
        # Process files in PARALLEL using ThreadPoolExecutor
        processed_files = 0
        total_chunks_created = 0
        chunks_buffer: List[models.CodeChunk] = []
        
        # Use parallel processing for file reading and chunking
        file_results, static_findings = _process_files_parallel(
            source_root, source_files, project, parsing_progress
        )
        
        # Add static findings
        findings.extend(static_findings)
        
        # Convert results to CodeChunks and commit in batches
        for rel_path, chunks in file_results:
            try:
                # Check if we've hit the chunk limit
                if total_chunks_created >= MAX_TOTAL_CHUNKS:
                    logger.warning(f"Reached max chunk limit ({MAX_TOTAL_CHUNKS}), stopping")
                    _broadcast_progress(
                        scan_run.id, "parsing", 28, 
                        f"Chunk limit reached at {total_chunks_created} chunks"
                    )
                    break
                
                # Create CodeChunk models
                file_path = source_root / rel_path
                language = _detect_language(file_path)
                db_chunks = create_code_chunks(project, source_root, file_path, language, chunks)
                chunks_buffer.extend(db_chunks)
                total_chunks_created += len(db_chunks)
                processed_files += 1
                
                # Flush buffer periodically to prevent memory buildup
                if len(chunks_buffer) >= CHUNK_FLUSH_THRESHOLD:
                    all_chunks.extend(chunks_buffer)
                    db.add_all(chunks_buffer)
                    db.commit()
                    chunks_buffer = []
                
            except Exception as e:
                logger.warning(f"Error creating chunks for {rel_path}: {e}")
                continue
        
        # Flush remaining chunks
        if chunks_buffer:
            all_chunks.extend(chunks_buffer)
            db.add_all(chunks_buffer)
            db.commit()
        
        file_count = processed_files
        parse_time = time.time() - scan_start
        logger.info(f"Processed {file_count} source files, {len(all_chunks)} code chunks in {parse_time:.1f}s")
        _broadcast_progress(scan_run.id, "parsing", 30, f"✅ Parsed {file_count} files, {len(all_chunks)} chunks ({parse_time:.1f}s)")

        # Phase 3: Generate embeddings (30-45%)
        # Check if we should skip embeddings entirely
        if settings.skip_embeddings:
            logger.info("Skipping embeddings (SKIP_EMBEDDINGS=true)")
            _broadcast_progress(scan_run.id, "embedding", 45, "⏭️ Embeddings skipped (disabled)")
        else:
            _broadcast_progress(scan_run.id, "embedding", 35, "🧠 Generating code embeddings...")
            logger.debug("Checking for reusable embeddings from previous scans")
            
            # Get existing embeddings from previous scans of this project
            existing_embeddings = _get_existing_embeddings(db, project.id)
            
            if existing_embeddings:
                logger.info(f"Found {len(existing_embeddings)} existing embeddings to potentially reuse")
                chunks_to_embed, reused_count = _reuse_or_generate_embeddings(
                    db, project, all_chunks, existing_embeddings
                )
                
                if reused_count > 0:
                    logger.info(f"Reused {reused_count} embeddings from previous scan, "
                               f"{len(chunks_to_embed)} chunks need new embeddings")
                    _broadcast_progress(
                        scan_run.id, "embedding", 38, 
                        f"Reusing {reused_count} embeddings, generating {len(chunks_to_embed)} new"
                    )
                
                # Only generate embeddings for chunks that need them
                if chunks_to_embed:
                    asyncio.run(enrich_code_chunks(chunks_to_embed))
            else:
                # No existing embeddings, generate all
                logger.debug("No existing embeddings found, generating all")
                asyncio.run(enrich_code_chunks(all_chunks))
            
            db.add_all(all_chunks)
            db.commit()
            _broadcast_progress(scan_run.id, "embedding", 45, "✅ Embeddings complete")

        # Phase 4-7: Run parallel scan phases (45-72%)
        # SAST, Docker, IaC, and Dependencies all run concurrently
        _broadcast_progress(scan_run.id, "parallel_scanning", 45, "🔍 Starting security scanners...")
        logger.info("Starting parallel scan phase execution")
        
        tracker = ParallelPhaseTracker(scan_run.id, 45, 25)  # Progress from 45-70%
        
        parallel_results = _run_parallel_scan_phases(
            source_root, project, tracker, settings.scanner_timeout
        )
        
        # Process SAST results
        scanner_results = parallel_results.get("sast", {})
        scanner_findings = _convert_scanner_results_to_findings(scanner_results, source_root)
        findings.extend(scanner_findings)
        logger.info(f"SAST scanners: {len(scanner_findings)} findings")
        
        # Process Docker results
        docker_result = parallel_results.get("docker")
        docker_findings_count = 0
        if docker_result:
            docker_finding_dicts = docker_scan_service.convert_to_findings(docker_result, source_root)
            for df in docker_finding_dicts:
                findings.append(models.Finding(
                    type=df["type"],
                    severity=df["severity"],
                    file_path=df.get("file_path"),
                    start_line=df.get("start_line"),
                    end_line=df.get("end_line"),
                    summary=df["summary"],
                    details=df.get("details", {}),
                ))
            docker_findings_count = len(docker_finding_dicts)
            logger.info(f"Docker scanning: {docker_findings_count} findings "
                       f"({docker_result.dockerfiles_scanned} Dockerfiles, "
                       f"{docker_result.images_scanned} images)")
        
        # Process IaC results
        iac_result = parallel_results.get("iac")
        iac_findings_count = 0
        if iac_result:
            iac_finding_dicts = iac_scan_service.convert_to_findings(iac_result, source_root)
            for iac_f in iac_finding_dicts:
                findings.append(models.Finding(
                    type=iac_f["type"],
                    severity=iac_f["severity"],
                    file_path=iac_f.get("file_path"),
                    start_line=iac_f.get("start_line"),
                    end_line=iac_f.get("end_line"),
                    summary=iac_f["summary"],
                    details=iac_f.get("details", {}),
                ))
            iac_findings_count = len(iac_finding_dicts)
            logger.info(f"IaC scanning: {iac_findings_count} findings "
                       f"({iac_result.files_scanned} files, "
                       f"frameworks: {', '.join(iac_result.frameworks_detected) or 'none'})")
        
        # Get dependencies from parallel results
        deps = parallel_results.get("dependencies", [])
        
        _broadcast_progress(
            scan_run.id, "scanning", 70, 
            f"✅ Parallel phases complete: {len(scanner_findings)} SAST, "
            f"{docker_findings_count} Docker, {iac_findings_count} IaC"
        )
        
        # Phase 8: Deduplicate scanner findings (70-72%)
        _broadcast_progress(scan_run.id, "deduplication", 70, "🔄 Deduplicating scanner findings...")
        logger.debug("Running cross-scanner deduplication")
        
        original_count = len(findings)
        deduplicated, dedup_stats = deduplication_service.deduplicate_findings(findings)
        findings = deduplicated
        
        if dedup_stats.get("duplicates_merged", 0) > 0:
            logger.info(
                f"Deduplication: {original_count} → {len(findings)} findings "
                f"({dedup_stats['duplicates_merged']} duplicates merged)"
            )
            _broadcast_progress(
                scan_run.id, "deduplication", 72, 
                f"✅ Merged {dedup_stats['duplicates_merged']} duplicates ({original_count} → {len(findings)})"
            )
        else:
            _broadcast_progress(scan_run.id, "deduplication", 72, "✅ No duplicates found")
        
        # Cross-file correlation analysis
        cross_file_correlations = deduplication_service.correlate_cross_file_findings(findings)
        if cross_file_correlations:
            logger.info(f"Found {len(cross_file_correlations)} cross-file correlations")
            # Store correlations in dedup_stats for report
            dedup_stats["cross_file_correlations"] = cross_file_correlations[:20]  # Limit for report

        # Phase 9: Save dependencies from parallel phase (72-75%)
        _broadcast_progress(scan_run.id, "dependencies", 72, "💾 Saving dependencies...")
        if deps:
            db.add_all(deps)
            db.commit()
        logger.info(f"Saved {len(deps)} dependencies")
        
        # Phase 10: Transitive dependency analysis (75-77%)
        _broadcast_progress(scan_run.id, "transitive_deps", 75, "🌳 Analyzing dependency trees...")
        logger.debug("Building transitive dependency trees")
        
        try:
            dependency_trees = transitive_deps_service.parse_dependency_tree(source_root)
            tree_stats = {
                "ecosystems_analyzed": len(dependency_trees),
                "total_packages": sum(len(t.all_packages) for t in dependency_trees.values()),
                "direct_deps": sum(len(t.direct_dependencies) for t in dependency_trees.values()),
            }
            logger.info(
                f"Dependency trees: {tree_stats['ecosystems_analyzed']} ecosystems, "
                f"{tree_stats['total_packages']} packages ({tree_stats['direct_deps']} direct)"
            )
            _broadcast_progress(
                scan_run.id, "transitive_deps", 77, 
                f"✅ Analyzed {tree_stats['total_packages']} packages in dependency trees"
            )
        except Exception as e:
            logger.warning(f"Transitive dependency analysis failed (non-critical): {e}")
            dependency_trees = {}
            _broadcast_progress(scan_run.id, "transitive_deps", 77, "⏭️ Skipped (no lock files)")
        
        _broadcast_progress(scan_run.id, "dependencies", 78, f"✅ Found {len(deps)} dependencies")

        # Phase 11: CVE lookup (78-82%)
        _broadcast_progress(scan_run.id, "cve_lookup", 78, "🔒 Looking up known vulnerabilities...")
        logger.debug("Looking up known vulnerabilities")
        vulns = asyncio.run(cve_service.lookup_dependencies(deps))
        db.add_all(vulns)
        db.commit()
        logger.info(f"Found {len(vulns)} known vulnerabilities")
        _broadcast_progress(scan_run.id, "cve_lookup", 82, f"✅ Found {len(vulns)} CVEs")
        
        # Phase 11b: Enrich with transitive dependency info (82-84%)
        if dependency_trees and vulns:
            _broadcast_progress(scan_run.id, "transitive_analysis", 82, "🌳 Analyzing transitive vulnerabilities...")
            logger.debug("Enriching vulnerabilities with dependency tree info")
            
            try:
                tree_analysis = transitive_deps_service.analyze_vulnerable_dependencies(
                    vulns, dependency_trees
                )
                transitive_count = sum(1 for t in tree_analysis.values() if t.is_transitive)
                logger.info(
                    f"Transitive analysis: {transitive_count}/{len(vulns)} vulnerabilities "
                    f"are in transitive dependencies"
                )
                _broadcast_progress(
                    scan_run.id, "transitive_analysis", 83, 
                    f"{transitive_count} transitive, {len(vulns)-transitive_count} direct"
                )
            except Exception as e:
                logger.warning(f"Transitive enrichment failed: {e}")
                tree_analysis = {}
        else:
            tree_analysis = {}
        
        # Phase 11c: Reachability analysis (84-86%)
        if vulns:
            _broadcast_progress(scan_run.id, "reachability", 84, "🎯 Analyzing vulnerability reachability...")
            logger.debug("Running reachability analysis")
            
            try:
                reachability_results = reachability_service.analyze_reachability(
                    source_root, vulns, deps
                )
                reachability_map = {r.vulnerability_id: r for r in reachability_results}
                reachability_summary = reachability_service.get_reachability_summary(reachability_results)
                
                unreachable_count = reachability_summary.get("not_reachable", 0)
                if unreachable_count > 0:
                    logger.info(
                        f"Reachability: {unreachable_count}/{len(vulns)} vulnerabilities "
                        f"are in unreachable code paths"
                    )
                _broadcast_progress(
                    scan_run.id, "reachability", 86, 
                    f"{reachability_summary.get('reachable', len(vulns))} reachable, "
                    f"{unreachable_count} unreachable"
                )
            except Exception as e:
                logger.warning(f"Reachability analysis failed: {e}")
                reachability_map = {}
                reachability_summary = {}
        else:
            reachability_map = {}
            reachability_summary = {}

        # Phase 12: Parallel enrichment - EPSS + NVD + KEV (86-88%)
        # Run all enrichments in parallel for better performance
        _broadcast_progress(scan_run.id, "enrichment", 86, "📊 Enriching vulnerabilities (NVD/EPSS/KEV)...")
        logger.debug("Starting parallel vulnerability enrichment")
        
        vuln_dicts = [
            {"id": v.id, "external_id": v.external_id, "cvss_score": v.cvss_score}
            for v in vulns
        ]
        
        # Use the new parallel enrichment that handles NVD + KEV + EPSS together
        cve_vulns = [v for v in vuln_dicts if v.get("external_id", "").startswith("CVE-")]
        if cve_vulns:
            try:
                enriched_vulns = asyncio.run(nvd_service.enrich_all_parallel(vuln_dicts))
                _broadcast_progress(scan_run.id, "enrichment", 89, f"Enriched {len(cve_vulns)} CVEs")
            except Exception as e:
                logger.warning(f"Parallel enrichment failed, falling back to EPSS only: {e}")
                # Fallback to just EPSS enrichment
                enriched_vulns = asyncio.run(epss_service.enrich_vulnerabilities_with_epss(vuln_dicts))
        else:
            # No CVEs, just do EPSS enrichment for GHSA etc.
            enriched_vulns = asyncio.run(epss_service.enrich_vulnerabilities_with_epss(vuln_dicts))
        
        # Create a mapping for quick lookup
        epss_data = {v["id"]: v for v in enriched_vulns}

        dep_lookup = {d.id: d.name for d in deps}

        # Create findings for dependency vulnerabilities
        for vuln in vulns:
            # Get EPSS, NVD, and KEV data if available
            vuln_epss = epss_data.get(vuln.id, {})
            epss_score = vuln_epss.get("epss_score")
            epss_percentile = vuln_epss.get("epss_percentile")
            epss_priority = vuln_epss.get("epss_priority")
            nvd_enrichment = vuln_epss.get("nvd_enrichment", {})
            in_kev = vuln_epss.get("in_kev", False)
            combined_priority = vuln_epss.get("combined_priority")
            priority_label = vuln_epss.get("priority_label")
            
            # Use combined priority or EPSS priority to potentially escalate severity
            effective_severity = vuln.severity or "medium"
            
            # KEV vulnerabilities should always be high/critical
            if in_kev and effective_severity in ("low", "medium"):
                effective_severity = "high"
                logger.info(f"Escalating {vuln.external_id} to high (in CISA KEV)")
            elif epss_priority == "critical" and effective_severity in ("low", "medium"):
                effective_severity = "high"  # Escalate if highly likely to be exploited
            
            # Build details dict with all enrichment data
            details = {
                "external_id": vuln.external_id,
                "dependency": dep_lookup.get(vuln.dependency_id),
                "cvss_score": vuln.cvss_score,
                "epss_score": epss_score,
                "epss_percentile": epss_percentile,
                "epss_priority": epss_priority,
                "in_kev": in_kev,  # Known Exploited Vulnerability flag
                "combined_priority": combined_priority,
                "priority_label": priority_label,
            }
            
            # Add NVD enrichment if available
            if nvd_enrichment:
                details["nvd_description"] = nvd_enrichment.get("description")
                details["cvss_vector"] = nvd_enrichment.get("cvss_v3", {}).get("vector_string") if nvd_enrichment.get("cvss_v3") else None
                details["cwe"] = nvd_enrichment.get("cwes", [])
                details["references"] = nvd_enrichment.get("references", [])[:5]  # Limit references
            
            # Add transitive dependency info if available
            dep = vuln.dependency
            if dep and tree_analysis:
                tree_info = tree_analysis.get(vuln.external_id)
                if tree_info:
                    details["is_transitive"] = tree_info.is_transitive
                    details["dependency_depth"] = tree_info.depth
                    details["dependency_chain"] = tree_info.dependency_chain[:5]  # Limit chain length
                    details["root_dependency"] = tree_info.root_dependency
            
            # Add reachability info if available
            reachability = reachability_map.get(vuln.external_id)
            if reachability:
                details["reachability"] = {
                    "is_reachable": reachability.is_reachable,
                    "confidence": reachability.confidence,
                    "reason": reachability.reason,
                    "recommendation": reachability.recommendation,
                    "import_count": len(reachability.import_locations),
                    "call_count": len(reachability.call_locations),
                }
                
                # Downgrade severity for unreachable vulnerabilities with high confidence
                if not reachability.is_reachable and reachability.confidence == "high":
                    if effective_severity in ("critical", "high"):
                        logger.debug(
                            f"Downgrading {vuln.external_id} from {effective_severity} to medium "
                            "(unreachable with high confidence)"
                        )
                        effective_severity = "medium"
                        details["severity_downgraded"] = True
                        details["original_severity"] = vuln.severity or "medium"
            
            findings.append(
                models.Finding(
                    project_id=project.id,
                    scan_run_id=scan_run.id,
                    type="dependency_vuln",
                    severity=effective_severity,
                    summary=vuln.title,
                    details=details,
                    linked_vulnerability=vuln,
                )
            )

        # Attach metadata for code findings
        for f in findings:
            f.project_id = project.id
            f.scan_run_id = scan_run.id
        db.add_all(findings)
        db.commit()

        logger.info(f"Total findings: {len(findings)}")
        
        # ================================================================
        # Phase: AI-Guided Deep Analysis (Unified Pipeline)
        # ================================================================
        # Run agentic scan WITH external intelligence from CVE/SAST phases.
        # This enables AI to know about vulnerable dependencies BEFORE analyzing code.
        # Agentic AI is ALWAYS enabled as part of the unified scan pipeline.
        scan_options = scan_run.options or {}
        enhanced_mode = scan_options.get("enhanced_scan", False)
        mode_label = "Enhanced" if enhanced_mode else "Standard"
        _broadcast_progress(scan_run.id, "agentic_scan", 89, 
                           f"🤖 AI-Guided Deep Analysis ({mode_label}, with CVE/SAST context)...")
        
        try:
            # Build external intelligence from CVE/SAST results
            external_intel = build_external_intelligence(
                vulns=vulns,
                scanner_findings=scanner_findings,  # SAST findings
                deps=deps,
                enriched_vulns=epss_data,  # NVD/EPSS enrichment
                source_root=source_root
            )
            
            # Run agentic scan with full context
            from backend.services.agentic_scan_service import AgenticScanService, ScanPhase
            from backend.services.websocket_service import progress_manager
            
            agentic_service = AgenticScanService()
            
            # Map agentic phases to WebSocket phase names for granular tracking
            PHASE_TO_WS_PHASE = {
                ScanPhase.INITIALIZING: "agentic_initializing",
                ScanPhase.FILE_TRIAGE: "agentic_file_triage",
                ScanPhase.INITIAL_ANALYSIS: "agentic_initial_analysis",
                ScanPhase.FOCUSED_ANALYSIS: "agentic_focused_analysis",
                ScanPhase.DEEP_ANALYSIS: "agentic_deep_analysis",
                ScanPhase.CHUNKING: "agentic_chunking",
                ScanPhase.ENTRY_POINT_DETECTION: "agentic_entry_points",
                ScanPhase.FLOW_TRACING: "agentic_flow_tracing",
                ScanPhase.VULNERABILITY_ANALYSIS: "agentic_analyzing",
                ScanPhase.FALSE_POSITIVE_FILTERING: "agentic_fp_filtering",
                ScanPhase.SYNTHESIS: "agentic_synthesis",
                ScanPhase.REPORT_GENERATION: "agentic_reporting",
                ScanPhase.COMPLETE: "agentic_complete",
                ScanPhase.ERROR: "agentic_error",
            }
            
            def agentic_progress(progress):
                """Update WebSocket with granular agentic phase tracking"""
                # Map internal phase to WebSocket phase name
                ws_phase = PHASE_TO_WS_PHASE.get(progress.phase, "agentic_scan")
                msg = f"🤖 {progress.message or progress.phase.value}"
                
                # Build detailed stats line for UI
                stats_parts = []
                if progress.total_chunks > 0:
                    stats_parts.append(f"📄 {progress.analyzed_chunks}/{progress.total_chunks} chunks")
                if progress.entry_points_found > 0:
                    stats_parts.append(f"🎯 {progress.entry_points_found} entry points")
                if progress.flows_traced > 0:
                    stats_parts.append(f"🔀 {progress.flows_traced} flows")
                if progress.vulnerabilities_found > 0:
                    stats_parts.append(f"⚠️ {progress.vulnerabilities_found} vulns")
                
                if stats_parts:
                    msg += "\n" + " | ".join(stats_parts)
                
                progress_manager.publish_progress(scan_run.id, ws_phase, 89, msg)
            
            async def run_agentic_with_intel():
                scan_id = await agentic_service.start_scan(
                    project_id=project.id,
                    project_path=str(source_root),
                    progress_callback=agentic_progress,
                    external_intel=external_intel,  # Pass the CVE/SAST context!
                    enhanced_mode=enhanced_mode  # Pass enhanced mode for larger limits
                )
                return agentic_service.get_result(scan_id)
            
            agentic_result = asyncio.run(run_agentic_with_intel())
            
            if agentic_result and agentic_result.vulnerabilities:
                # Convert agentic vulns to Finding models
                for vuln in agentic_result.vulnerabilities:
                    file_path = vuln.flow.entry_point.file_path if vuln.flow else "unknown"
                    line_number = vuln.flow.entry_point.line_number if vuln.flow else 1
                    
                    agentic_finding = models.Finding(
                        project_id=project.id,
                        scan_run_id=scan_run.id,
                        type=f"agentic-{vuln.vulnerability_type}",
                        severity=vuln.severity,
                        file_path=file_path,
                        start_line=line_number,
                        summary=vuln.description[:500] if vuln.description else "Agentic AI finding",
                        details={
                            "source": "agentic_ai",
                            "vulnerability_type": vuln.vulnerability_type,
                            "confidence": vuln.confidence,
                            "remediation": vuln.remediation,
                            "exploit_scenario": vuln.exploit_scenario,
                            "cwe_id": vuln.cwe_id,
                            "owasp_category": vuln.owasp_category,
                            "title": vuln.title,
                            "informed_by_cve": len(external_intel.cve_findings) > 0,
                            "informed_by_sast": len(external_intel.sast_findings) > 0,
                        }
                    )
                    findings.append(agentic_finding)
                
                db.add_all(findings[-len(agentic_result.vulnerabilities):])  # Add new findings
                db.commit()
                
                logger.info(f"Agentic AI scan (with intel): {len(agentic_result.vulnerabilities)} findings")
                _broadcast_progress(scan_run.id, "agentic_scan", 90,
                                   f"🤖 AI found {len(agentic_result.vulnerabilities)} additional vulnerabilities")
            else:
                _broadcast_progress(scan_run.id, "agentic_scan", 90,
                                   "🤖 AI analysis complete (no additional findings)")
                
        except Exception as e:
            logger.warning(f"Agentic scan with intel failed (non-critical): {e}")
            _broadcast_progress(scan_run.id, "agentic_scan", 90,
                               f"🤖 AI deep analysis skipped: {str(e)[:50]}")
        attack_chains_data = []
        ai_summary = None
        if findings:
            _broadcast_progress(scan_run.id, "ai_analysis", 90, "🧠 AI-enhanced vulnerability analysis...")
            try:
                # Convert findings to dicts for AI analysis
                findings_dicts = []
                code_snippets = {}
                for f in findings:
                    finding_dict = {
                        "id": f.id,
                        "type": f.type,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "start_line": f.start_line,
                        "end_line": f.end_line,
                        "summary": f.summary,
                        "details": f.details or {},
                    }
                    findings_dicts.append(finding_dict)
                    # Get code snippet from details if available
                    if f.details and f.details.get("code_snippet"):
                        code_snippets[f.id] = f.details["code_snippet"]
                
                ai_result = asyncio.run(ai_analysis_service.analyze_findings(
                    findings_dicts,
                    code_snippets=code_snippets,
                    enable_llm=True,
                    max_llm_findings=20
                ))
                if ai_result:
                    from sqlalchemy.orm.attributes import flag_modified
                    
                    # Store AI summary for report (including agentic corroboration stats)
                    ai_summary = {
                        "findings_analyzed": ai_result.findings_analyzed,
                        "false_positives_detected": ai_result.false_positives_detected,
                        "severity_adjustments": ai_result.severity_adjustments,
                        "agentic_corroborated": ai_result.agentic_corroborated,
                        "filtered_out": ai_result.filtered_out,
                    }
                    
                    # Convert attack chains to dicts for storage
                    for chain in ai_result.attack_chains:
                        attack_chains_data.append({
                            "title": chain.title,
                            "severity": chain.severity,
                            "finding_ids": chain.finding_ids,
                            "description": chain.chain_description,
                            "impact": chain.impact,
                            "likelihood": chain.likelihood,
                        })
                    
                    # Apply results to findings and track filtered findings
                    filtered_finding_ids = []
                    for f in findings:
                        if f.id in ai_result.analysis_results:
                            result = ai_result.analysis_results[f.id]
                            
                            # Check if this finding should be filtered out
                            # Filter criteria: high FP score AND not from agentic scan AND not corroborated
                            is_agentic = f.type.startswith("agentic-") or (f.details and f.details.get("source") == "agentic_ai")
                            should_filter = (
                                result.false_positive_score >= 0.6 and 
                                not is_agentic and
                                "Corroborated by Agentic AI" not in (result.false_positive_reason or "")
                            )
                            
                            # Store AI analysis in details (must create new dict for SQLAlchemy)
                            new_details = dict(f.details) if f.details else {}
                            new_details["ai_analysis"] = {
                                "is_false_positive": result.false_positive_score >= 0.5,
                                "false_positive_score": result.false_positive_score,
                                "false_positive_reason": result.false_positive_reason,
                                "severity_adjusted": result.adjusted_severity is not None,
                                "original_severity": f.severity if result.adjusted_severity else None,
                                "severity_reason": result.severity_reason,
                                "data_flow_summary": result.data_flow,
                                "filtered_out": should_filter,
                            }
                            f.details = new_details
                            flag_modified(f, "details")
                            
                            # Update severity if adjusted
                            if result.adjusted_severity:
                                f.severity = result.adjusted_severity
                            
                            if should_filter:
                                filtered_finding_ids.append(f.id)
                    
                    # Log filtered findings
                    if filtered_finding_ids:
                        logger.info(f"AI Analysis filtered out {len(filtered_finding_ids)} likely false positive findings")
                    
                    # Store attack chain info in findings
                    for chain in ai_result.attack_chains:
                        for finding_id in chain.finding_ids:
                            for f in findings:
                                if f.id == finding_id:
                                    new_details = dict(f.details) if f.details else {}
                                    if "ai_analysis" not in new_details:
                                        new_details["ai_analysis"] = {}
                                    new_details["ai_analysis"]["attack_chain"] = chain.title
                                    f.details = new_details
                                    flag_modified(f, "details")
                    
                    db.commit()
                    logger.info(f"AI analysis complete: {ai_result.false_positives_detected} likely false positives, "
                               f"{ai_result.severity_adjustments} severity adjustments, "
                               f"{len(ai_result.attack_chains)} attack chains, "
                               f"{ai_result.agentic_corroborated} agentic-corroborated")
            except Exception as e:
                logger.warning(f"AI analysis failed (non-critical): {e}")
        
        # Phase 13: Generate report (94-98%)
        _broadcast_progress(scan_run.id, "reporting", 94, "📋 Generating final report...")
        # Build sensitive data inventory for UI (non-blocking; may be AI-enhanced if configured)
        sensitive_inventory: Dict[str, Any] = {}
        try:
            sensitive_inventory = sensitive_data_service.build_sensitive_data_inventory(source_root, findings)
        except Exception as e:
            logger.warning(f"Sensitive data inventory generation failed (non-critical): {e}")
            sensitive_inventory = {"error": str(e)}

        # Include deduplication and analysis stats in report
        scan_stats = {
            "deduplication": dedup_stats if 'dedup_stats' in dir() else {},
            "transitive_analysis": tree_stats if 'tree_stats' in dir() else {},
            "reachability": reachability_summary if reachability_summary else {},
            "sensitive_data_inventory": sensitive_inventory,
            "docker": {
                "dockerfiles_scanned": docker_result.dockerfiles_scanned if docker_result else 0,
                "images_scanned": docker_result.images_scanned if docker_result else 0,
                "dockerfile_findings": len(docker_result.dockerfile_findings) if docker_result else 0,
                "image_vulnerabilities": len(docker_result.image_vulnerabilities) if docker_result else 0,
                "base_images": docker_result.base_images_found[:10] if docker_result else [],
            } if docker_result else {},
            "iac": {
                "files_scanned": iac_result.files_scanned if iac_result else 0,
                "findings": len(iac_result.findings) if iac_result else 0,
                "frameworks": list(iac_result.frameworks_detected) if iac_result else [],
            } if iac_result else {},
        }
        
        report = report_service.create_report(
            db, project, scan_run, findings, 
            attack_chains=attack_chains_data,
            ai_summary=ai_summary,
            scan_stats=scan_stats
        )
        scan_run.status = "complete"
        scan_run.finished_at = datetime.utcnow()
        db.add(scan_run)
        db.commit()
        
        # Calculate total scan time
        total_scan_time = time.time() - scan_start
        
        # Phase 14: Complete (100%)
        _broadcast_progress(scan_run.id, "complete", 100, f"✅ Scan complete! {len(findings)} findings in {total_scan_time:.1f}s")
        
        # Log performance summary
        logger.info(
            f"✅ Scan completed for '{project.name}' (ID: {project.id})\n"
            f"   📊 Performance: {total_scan_time:.1f}s total ({file_count} files, {len(all_chunks)} chunks)\n"
            f"   🔍 Findings: {len(findings)} total | "
            f"SAST: {len(scanner_findings)} | Docker: {docker_findings_count} | IaC: {iac_findings_count}\n"
            f"   📦 Dependencies: {len(deps)} packages, {len(vulns)} CVEs\n"
            f"   ⚙️ System: {CPU_COUNT} CPUs, {MAX_PARALLEL_SCANNERS} parallel scanners"
        )
        
        # Send webhook notifications
        webhooks = get_webhooks(project.id)
        if webhooks:
            logger.info(f"Sending {len(webhooks)} webhook notifications")
            try:
                # Calculate summary stats
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for f in findings:
                    if f.severity in severity_counts:
                        severity_counts[f.severity] += 1
                
                asyncio.run(notify_scan_complete(
                    project_id=project.id,
                    project_name=project.name,
                    scan_run_id=scan_run.id,
                    findings_count=len(findings),
                    severity_counts=severity_counts,
                    report_id=report.id
                ))
            except Exception as e:
                logger.warning(f"Failed to send webhook notifications: {e}")
        
        return report
        
    except Exception as exc:
        logger.exception(f"Scan failed for project {project.id}: {exc}")
        scan_run.status = "failed"
        scan_run.error_message = str(exc)
        scan_run.finished_at = datetime.utcnow()
        db.add(scan_run)
        db.commit()
        
        # Broadcast failure
        _broadcast_progress(scan_run.id, "failed", 0, str(exc))
        
        raise
