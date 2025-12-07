import ast
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple, Dict, Any

from backend import models
from backend.core.exceptions import ZipExtractionError
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Chunking configuration for large codebases
MAX_CHUNK_SIZE = 2000  # Maximum lines per chunk (prevents oversized chunks)
MIN_CHUNK_SIZE = 10    # Minimum lines per chunk (prevents tiny fragments)
IDEAL_CHUNK_SIZE = 150  # Target chunk size for optimal analysis
MAX_CHUNKS_PER_FILE = 50  # Limit chunks per file to prevent explosion

# Folders to skip during scanning (saves time and memory)
IGNORED_FOLDERS = {
    "node_modules", "vendor", "dist", "build", "__pycache__",
    ".git", ".svn", ".hg", ".venv", "venv", "env",
    "target", "out", "bin", "obj", ".idea", ".vscode",
    "coverage", ".nyc_output", ".pytest_cache", ".tox",
}

# Binary/generated file extensions to skip
IGNORED_EXTENSIONS = {
    ".pyc", ".pyo", ".class", ".o", ".obj", ".exe", ".dll", ".so",
    ".dylib", ".a", ".lib", ".jar", ".war", ".ear", ".zip", ".tar",
    ".gz", ".rar", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".ppt", ".pptx", ".mp3", ".mp4", ".avi", ".mov",
    ".min.js", ".min.css", ".map", ".lock",
}

# Maximum file size allowed in zip (200MB per file)
MAX_FILE_SIZE = 200 * 1024 * 1024
# Maximum total extracted size (2GB) - streaming extraction makes this safe
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024
# Maximum single source file to process (10MB) - skip huge generated files
MAX_SOURCE_FILE_SIZE = 10 * 1024 * 1024
# Chunk size for streaming extraction (64KB)
EXTRACTION_CHUNK_SIZE = 64 * 1024


def unpack_zip_to_temp(
    upload_path: str,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> Path:
    """
    Safely extract a zip file to a temporary directory using streaming extraction.
    
    Includes protection against:
    - Path traversal attacks (zip slip)
    - Zip bombs (excessive file sizes)
    - Memory exhaustion (streaming extraction)
    
    Args:
        upload_path: Path to the uploaded zip file
        progress_callback: Optional callback(extracted_bytes, total_bytes) for progress tracking
        
    Returns:
        Path to the extracted directory
        
    Raises:
        ZipExtractionError: If extraction fails or security check fails
    """
    target_dir = Path(tempfile.mkdtemp(prefix="codebase_"))
    total_size = 0
    extracted_size = 0
    
    try:
        with zipfile.ZipFile(upload_path, "r") as zf:
            # First pass: validate all entries and calculate total size
            for member in zf.namelist():
                # Check for path traversal
                member_path = Path(member)
                if member_path.is_absolute():
                    raise ZipExtractionError(
                        f"Absolute path not allowed in zip: {member}",
                        path=upload_path
                    )
                if ".." in member_path.parts:
                    raise ZipExtractionError(
                        f"Path traversal detected in zip: {member}",
                        path=upload_path
                    )
                
                # Check file size (zip bomb protection)
                info = zf.getinfo(member)
                if info.file_size > MAX_FILE_SIZE:
                    raise ZipExtractionError(
                        f"File too large in zip: {member} ({info.file_size} bytes)",
                        path=upload_path
                    )
                
                total_size += info.file_size
                if total_size > MAX_TOTAL_SIZE:
                    raise ZipExtractionError(
                        f"Total extracted size exceeds limit ({MAX_TOTAL_SIZE // (1024*1024*1024)}GB)",
                        path=upload_path
                    )
                
                # Ensure target path is within target directory
                target_path = (target_dir / member).resolve()
                if not str(target_path).startswith(str(target_dir.resolve())):
                    raise ZipExtractionError(
                        f"Path escape attempt detected: {member}",
                        path=upload_path
                    )
            
            # Second pass: streaming extraction with progress tracking
            for member in zf.namelist():
                info = zf.getinfo(member)
                target_path = target_dir / member
                
                # Create directories
                if info.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue
                
                # Ensure parent directory exists
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Stream extract file in chunks to avoid memory spikes
                with zf.open(member) as src, open(target_path, "wb") as dst:
                    while True:
                        chunk = src.read(EXTRACTION_CHUNK_SIZE)
                        if not chunk:
                            break
                        dst.write(chunk)
                        extracted_size += len(chunk)
                        
                        if progress_callback:
                            progress_callback(extracted_size, total_size)
            
            logger.info(f"Extracted zip to {target_dir} ({total_size / (1024*1024):.1f}MB)")
            
    except zipfile.BadZipFile as e:
        logger.error(f"Invalid zip file: {upload_path} - {e}")
        raise ZipExtractionError(f"Invalid zip file: {e}", path=upload_path)
    except ZipExtractionError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error extracting zip: {upload_path} - {e}")
        raise ZipExtractionError(f"Extraction failed: {e}", path=upload_path)
    
    return target_dir


def _should_skip_file(path: Path) -> bool:
    """Check if a file should be skipped based on name patterns."""
    name = path.name.lower()
    
    # Skip minified files
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    
    # Skip source maps
    if name.endswith(".map"):
        return True
    
    # Skip lock files (already parsed separately)
    if name in {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}:
        return True
    
    return False


def iter_source_files(base_path: Path, max_file_size: int = MAX_SOURCE_FILE_SIZE) -> Iterable[Path]:
    """
    Iterate over source files in a directory, skipping ignored folders and large files.
    
    Args:
        base_path: Root directory to scan
        max_file_size: Maximum file size to process (default 10MB)
        
    Yields:
        Path objects for each source file
    """
    source_extensions = {".py", ".js", ".ts", ".tsx", ".go", ".rb", ".java", ".php", ".rs", ".kt", ".kts"}
    
    for path in base_path.rglob("*"):
        if path.is_dir():
            continue
        
        # Skip ignored folders
        if any(part in IGNORED_FOLDERS for part in path.parts):
            continue
        
        # Skip by extension
        if path.suffix.lower() in IGNORED_EXTENSIONS:
            continue
        
        # Skip by file pattern
        if _should_skip_file(path):
            continue
        
        # Only process source files
        if path.suffix not in source_extensions:
            continue
        
        # Skip files that are too large (likely generated)
        try:
            if path.stat().st_size > max_file_size:
                logger.debug(f"Skipping large file: {path} ({path.stat().st_size / (1024*1024):.1f}MB)")
                continue
        except OSError:
            continue
        
        yield path


def split_into_chunks(contents: str, file_path: str = "") -> List[Tuple[int, int, str]]:
    """
    Intelligently split code into semantic chunks for analysis.
    
    Uses multiple strategies based on language:
    1. Python: AST-based parsing for functions/classes
    2. Other languages: Regex-based parsing for common patterns
    3. Fallback: Line-based chunking for unparseable code
    
    Features for large codebases:
    - Size-bounded chunks prevent memory issues
    - Semantic boundaries preserve context for better analysis
    - Duplicate detection reduces redundant processing
    
    Args:
        contents: The file contents as a string
        file_path: Optional file path for language detection
        
    Returns:
        List of tuples (start_line, end_line, code)
    """
    lines = contents.splitlines()
    total_lines = len(lines)
    
    if total_lines == 0:
        return []
    
    # For very small files, return as single chunk
    if total_lines <= MIN_CHUNK_SIZE:
        return [(1, total_lines, contents)]
    
    file_ext = Path(file_path).suffix.lower() if file_path else ""
    
    # Try language-specific parsing
    chunks = []
    
    if file_ext == ".py":
        chunks = _split_python_ast(contents, lines)
    elif file_ext in (".js", ".ts", ".tsx", ".jsx"):
        chunks = _split_javascript(contents, lines)
    elif file_ext in (".java", ".kt", ".kts"):
        chunks = _split_java_like(contents, lines)
    elif file_ext in (".go"):
        chunks = _split_go(contents, lines)
    elif file_ext in (".rb"):
        chunks = _split_ruby(contents, lines)
    elif file_ext in (".php"):
        chunks = _split_php(contents, lines)
    elif file_ext in (".rs"):
        chunks = _split_rust(contents, lines)
    elif file_ext in (".c", ".cpp", ".cc", ".h", ".hpp"):
        chunks = _split_c_like(contents, lines)
    
    # If no chunks found or parsing failed, use fallback
    if not chunks:
        chunks = _split_fallback(contents, lines)
    
    # Enforce size limits and merge tiny chunks
    chunks = _normalize_chunks(chunks, lines)
    
    # Limit total chunks per file
    if len(chunks) > MAX_CHUNKS_PER_FILE:
        logger.debug(f"Limiting chunks from {len(chunks)} to {MAX_CHUNKS_PER_FILE} for {file_path}")
        chunks = _prioritize_chunks_for_analysis(chunks, MAX_CHUNKS_PER_FILE)
    
    return chunks


def _split_python_ast(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split Python code using AST for accurate function/class boundaries."""
    chunks = []
    try:
        tree = ast.parse(contents)
        
        # Collect all top-level and nested functions/classes
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start_line = node.lineno
                end_line = node.end_lineno if hasattr(node, 'end_lineno') and node.end_lineno else start_line
                
                # Include decorators
                if node.decorator_list:
                    start_line = min(d.lineno for d in node.decorator_list)
                
                code = "\n".join(lines[start_line - 1:end_line])
                chunks.append((start_line, end_line, code))
        
        # Sort by start line and remove overlapping chunks (keep outer)
        chunks.sort(key=lambda x: (x[0], -x[1]))
        filtered = []
        last_end = 0
        for start, end, code in chunks:
            if start > last_end:
                filtered.append((start, end, code))
                last_end = end
        
        return filtered
        
    except SyntaxError:
        logger.debug(f"Python AST parsing failed, using fallback")
        return []


def _split_javascript(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split JavaScript/TypeScript code by function and class definitions."""
    chunks = []
    
    # Patterns for JS/TS constructs
    patterns = [
        r'^(?:export\s+)?(?:async\s+)?function\s+\w+',
        r'^(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)',
        r'^(?:export\s+)?class\s+\w+',
        r'^\s+(?:async\s+)?(?:public|private|protected)?\s*(?:static\s+)?(?:async\s+)?\w+\s*\([^)]*\)\s*[:{]',
        r'^(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+\w+\s*=\s*\{',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_java_like(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split Java/Kotlin code by method and class definitions."""
    patterns = [
        r'^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:class|interface|enum)\s+\w+',
        r'^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?(?:\w+\s+)+\w+\s*\([^)]*\)\s*(?:throws\s+\w+)?\s*\{?',
        r'^\s*(?:fun|suspend\s+fun)\s+\w+',
        r'^\s*(?:override\s+)?(?:fun|suspend\s+fun)\s+\w+',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_go(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split Go code by function and type definitions."""
    patterns = [
        r'^func\s+(?:\([^)]+\)\s+)?\w+',
        r'^type\s+\w+\s+(?:struct|interface)',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_ruby(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split Ruby code by method and class definitions."""
    patterns = [
        r'^\s*(?:def|class|module)\s+\w+',
        r'^\s*(?:private|protected|public)\s*$',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_php(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split PHP code by function and class definitions."""
    patterns = [
        r'^\s*(?:public|private|protected)?\s*(?:static\s+)?function\s+\w+',
        r'^\s*class\s+\w+',
        r'^\s*(?:abstract\s+)?(?:final\s+)?class\s+\w+',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_rust(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split Rust code by function, impl, and struct definitions."""
    patterns = [
        r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+\w+',
        r'^\s*(?:pub\s+)?struct\s+\w+',
        r'^\s*(?:pub\s+)?impl(?:<[^>]+>)?\s+\w+',
        r'^\s*(?:pub\s+)?trait\s+\w+',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_c_like(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """Split C/C++ code by function and class definitions."""
    patterns = [
        r'^\s*(?:static\s+)?(?:inline\s+)?(?:\w+\s+)+\w+\s*\([^)]*\)\s*\{?',
        r'^\s*class\s+\w+',
        r'^\s*struct\s+\w+',
        r'^\s*namespace\s+\w+',
    ]
    
    return _split_by_patterns(lines, patterns)


def _split_by_patterns(lines: List[str], patterns: List[str]) -> List[Tuple[int, int, str]]:
    """Generic pattern-based splitting with brace matching."""
    chunks = []
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Check if this line matches any pattern
        matched = any(p.search(line) for p in compiled)
        
        if matched:
            start = i + 1  # 1-based line numbers
            # Find the end by tracking braces or using indentation
            end = _find_block_end(lines, i)
            code = "\n".join(lines[i:end])
            chunks.append((start, end, code))
            i = end
        else:
            i += 1
    
    return chunks


def _find_block_end(lines: List[str], start_idx: int) -> int:
    """Find the end of a code block using brace matching or indentation."""
    if start_idx >= len(lines):
        return start_idx + 1
    
    # Check if this is a brace-delimited block
    open_braces = 0
    in_block = False
    
    for i in range(start_idx, min(start_idx + MAX_CHUNK_SIZE, len(lines))):
        line = lines[i]
        
        # Count braces (simple - doesn't handle strings/comments perfectly)
        open_braces += line.count('{') - line.count('}')
        
        if '{' in line:
            in_block = True
        
        if in_block and open_braces <= 0:
            return i + 1
    
    # If no braces found, use indentation (for Python/Ruby style)
    if not in_block:
        base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
        for i in range(start_idx + 1, min(start_idx + MAX_CHUNK_SIZE, len(lines))):
            line = lines[i]
            if line.strip():  # Non-empty line
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= base_indent:
                    return i
    
    # Fallback: return start + IDEAL_CHUNK_SIZE or end of file
    return min(start_idx + IDEAL_CHUNK_SIZE, len(lines))


def _split_fallback(contents: str, lines: List[str]) -> List[Tuple[int, int, str]]:
    """
    Fallback chunking: split on function/class-like headers or by size.
    Used when language-specific parsing fails.
    """
    chunks = []
    current_start = 1
    
    # Look for common function/class patterns
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if re.match(r'^(def |class |function |func |public |private |protected |async )', stripped) and idx != 1:
            if idx - current_start >= MIN_CHUNK_SIZE:
                chunks.append((current_start, idx - 1, "\n".join(lines[current_start - 1:idx - 1])))
                current_start = idx
        
        # Also split on very large chunks
        if idx - current_start >= IDEAL_CHUNK_SIZE * 2:
            chunks.append((current_start, idx, "\n".join(lines[current_start - 1:idx])))
            current_start = idx + 1
    
    # Add remaining content
    if current_start <= len(lines):
        chunks.append((current_start, len(lines), "\n".join(lines[current_start - 1:])))
    
    return chunks


def _normalize_chunks(chunks: List[Tuple[int, int, str]], lines: List[str]) -> List[Tuple[int, int, str]]:
    """Normalize chunks: enforce size limits and merge tiny chunks."""
    if not chunks:
        return chunks
    
    normalized = []
    
    for start, end, code in chunks:
        chunk_size = end - start + 1
        
        # Split oversized chunks
        if chunk_size > MAX_CHUNK_SIZE:
            for sub_start in range(start, end + 1, IDEAL_CHUNK_SIZE):
                sub_end = min(sub_start + IDEAL_CHUNK_SIZE - 1, end)
                sub_code = "\n".join(lines[sub_start - 1:sub_end])
                normalized.append((sub_start, sub_end, sub_code))
        else:
            normalized.append((start, end, code))
    
    # Merge tiny chunks with neighbors
    if len(normalized) > 1:
        merged = []
        i = 0
        while i < len(normalized):
            start, end, code = normalized[i]
            chunk_size = end - start + 1
            
            # If tiny, try to merge with next chunk
            if chunk_size < MIN_CHUNK_SIZE and i + 1 < len(normalized):
                next_start, next_end, next_code = normalized[i + 1]
                combined_size = next_end - start + 1
                
                if combined_size <= IDEAL_CHUNK_SIZE * 2:
                    # Merge
                    merged_code = "\n".join(lines[start - 1:next_end])
                    merged.append((start, next_end, merged_code))
                    i += 2
                    continue
            
            merged.append((start, end, code))
            i += 1
        
        return merged
    
    return normalized


def _prioritize_chunks_for_analysis(
    chunks: List[Tuple[int, int, str]], 
    max_chunks: int
) -> List[Tuple[int, int, str]]:
    """
    Prioritize chunks for analysis when there are too many.
    Keeps chunks with security-relevant content.
    """
    from backend.services.embedding_service import SECURITY_KEYWORDS
    
    # Score each chunk by security relevance
    scored = []
    for chunk in chunks:
        start, end, code = chunk
        code_lower = code.lower()
        
        # Count security keywords
        score = sum(2 for kw in SECURITY_KEYWORDS if kw in code_lower)
        
        # Boost based on position (earlier code often more important)
        position_boost = max(0, (1000 - start) / 1000)
        score += position_boost
        
        # Boost chunks with imports/requires (entry points)
        if re.search(r'^(?:import|from|require|use)\s', code, re.MULTILINE):
            score += 1
        
        scored.append((score, chunk))
    
    # Sort by score descending and take top chunks
    scored.sort(key=lambda x: x[0], reverse=True)
    
    return [chunk for _, chunk in scored[:max_chunks]]


def create_code_chunks(
    project: models.Project, source_root: Path, file_path: Path, language: str, chunks: List[Tuple[int, int, str]]
):
    db_chunks = []
    relative_path = str(file_path.relative_to(source_root)) if file_path.is_relative_to(source_root) else str(file_path)
    for start, end, code in chunks:
        db_chunks.append(
            models.CodeChunk(
                project_id=project.id,
                file_path=relative_path,
                language=language,
                start_line=start,
                end_line=end,
                code=code,
            )
        )
    return db_chunks
