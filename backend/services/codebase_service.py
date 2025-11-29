import re
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from backend import models
from backend.core.exceptions import ZipExtractionError
from backend.core.logging import get_logger

logger = get_logger(__name__)

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


def split_into_chunks(contents: str) -> List[Tuple[int, int, str]]:
    """
    Very naive code chunking: split on function or class-like headers to keep demo simple.
    Returns list of tuples (start_line, end_line, code).
    """
    lines = contents.splitlines()
    chunks = []
    current_start = 1
    for idx, line in enumerate(lines, start=1):
        if re.match(r"^(def |class |function )", line.strip()) and idx != 1:
            chunks.append((current_start, idx - 1, "\n".join(lines[current_start - 1 : idx - 1])))
            current_start = idx
    chunks.append((current_start, len(lines), "\n".join(lines[current_start - 1 :])))
    return chunks


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
