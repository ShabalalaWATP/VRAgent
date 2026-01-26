"""
VRAgent File Validator - Streaming File Validation
Validates files without loading them entirely into memory
"""

import os
import hashlib
import magic
import mimetypes
import uuid
import re
from pathlib import Path
from typing import Optional, BinaryIO, AsyncGenerator
from dataclasses import dataclass
import logging
import asyncio

from backend.core.error_handler import (
    FileNotFoundError as VRAgentFileNotFoundError,
    FileTooLargeError,
    InvalidFileFormatError
)

logger = logging.getLogger(__name__)


@dataclass
class FileInfo:
    """File validation result"""
    path: str
    size_bytes: int
    size_gb: float
    mime_type: str
    file_type: str  # Detailed type from libmagic
    extension: str
    sha256: str
    is_binary: bool
    is_executable: bool
    is_archive: bool
    is_valid: bool
    validation_errors: list[str]


@dataclass
class ValidationConfig:
    """File validation configuration"""
    max_size_gb: float = 5.0
    allowed_extensions: Optional[list[str]] = None  # None = all allowed
    allowed_mime_types: Optional[list[str]] = None
    require_binary: bool = False
    calculate_hash: bool = True
    chunk_size: int = 8192  # 8KB chunks for streaming


class FileValidator:
    """
    Streaming file validator with resource-efficient validation.

    Features:
    - Streaming validation (no full file load)
    - Size limit enforcement
    - Format validation
    - Hash calculation
    - Magic number detection
    """

    # Supported binary formats
    BINARY_EXTENSIONS = {
        # Executables
        '.exe', '.dll', '.sys', '.scr',  # Windows
        '.elf', '.so', '.a', '.o',  # Linux
        '.dylib', '.bundle',  # macOS
        '.bin', '.img', '.rom',  # Generic binary

        # Mobile
        '.apk', '.ipa', '.aab',  # Android/iOS
        '.dex', '.odex',  # Android Dalvik

        # Archives
        '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',

        # Firmware
        '.fw', '.bin', '.hex', '.srec',
    }

    EXECUTABLE_MIME_TYPES = {
        'application/x-executable',
        'application/x-sharedlib',
        'application/x-object',
        'application/x-dosexec',
        'application/x-mach-binary',
        'application/vnd.android.package-archive',
        'application/octet-stream',  # Generic binary
    }

    def __init__(self, config: Optional[ValidationConfig] = None):
        self.config = config or ValidationConfig()

    async def validate_file_async(self, file_path: str) -> FileInfo:
        """
        Validate file with async I/O.
        Returns FileInfo with validation results.
        """
        return await asyncio.to_thread(self.validate_file, file_path)

    def validate_file(self, file_path: str) -> FileInfo:
        """
        Validate file synchronously.
        Returns FileInfo with validation results.
        """
        validation_errors = []

        # Check file exists
        if not os.path.isfile(file_path):
            raise VRAgentFileNotFoundError(file_path)

        path_obj = Path(file_path)
        extension = path_obj.suffix.lower()

        # Get file size
        size_bytes = os.path.getsize(file_path)
        size_gb = size_bytes / (1024 ** 3)

        # Check size limit
        if size_gb > self.config.max_size_gb:
            raise FileTooLargeError(size_gb, self.config.max_size_gb)

        # Get MIME type and file type
        try:
            mime_type = magic.from_file(file_path, mime=True)
            file_type = magic.from_file(file_path)
        except Exception as e:
            logger.warning(f"Failed to detect file type: {e}")
            mime_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
            file_type = "unknown"

        # Check allowed extensions
        if self.config.allowed_extensions is not None:
            if extension not in self.config.allowed_extensions:
                validation_errors.append(
                    f"File extension '{extension}' not allowed. "
                    f"Allowed: {', '.join(self.config.allowed_extensions)}"
                )

        # Check allowed MIME types
        if self.config.allowed_mime_types is not None:
            if mime_type not in self.config.allowed_mime_types:
                validation_errors.append(
                    f"MIME type '{mime_type}' not allowed. "
                    f"Allowed: {', '.join(self.config.allowed_mime_types)}"
                )

        # Determine file characteristics
        is_binary = self._is_binary(file_path, mime_type, file_type)
        is_executable = self._is_executable(extension, mime_type, file_type)
        is_archive = self._is_archive(extension, mime_type)

        # Check if binary required
        if self.config.require_binary and not is_binary:
            validation_errors.append("File must be a binary file")

        # Calculate hash (streaming)
        sha256 = ""
        if self.config.calculate_hash:
            try:
                sha256 = self._calculate_hash_streaming(file_path)
            except Exception as e:
                logger.warning(f"Failed to calculate hash: {e}")
                validation_errors.append(f"Hash calculation failed: {e}")

        is_valid = len(validation_errors) == 0

        return FileInfo(
            path=file_path,
            size_bytes=size_bytes,
            size_gb=size_gb,
            mime_type=mime_type,
            file_type=file_type,
            extension=extension,
            sha256=sha256,
            is_binary=is_binary,
            is_executable=is_executable,
            is_archive=is_archive,
            is_valid=is_valid,
            validation_errors=validation_errors
        )

    def _calculate_hash_streaming(self, file_path: str) -> str:
        """Calculate SHA256 hash using streaming (memory-efficient)"""
        sha256_hash = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(self.config.chunk_size), b""):
                sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    def _is_binary(self, file_path: str, mime_type: str, file_type: str) -> bool:
        """Determine if file is binary"""
        # Check MIME type
        if mime_type.startswith("text/"):
            return False

        # Check file type string
        if "text" in file_type.lower() or "ascii" in file_type.lower():
            return False

        # Check by reading first 8KB (look for null bytes)
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
                if b'\x00' in chunk:
                    return True

                # Check for high ratio of non-printable characters
                non_printable = sum(1 for b in chunk if b < 32 and b not in [9, 10, 13])
                ratio = non_printable / len(chunk) if chunk else 0
                return ratio > 0.3

        except Exception as e:
            logger.warning(f"Failed to check if binary: {e}")
            return True  # Assume binary if can't read

        return False

    def _is_executable(self, extension: str, mime_type: str, file_type: str) -> bool:
        """Determine if file is executable"""
        # Check extension
        if extension in {'.exe', '.dll', '.sys', '.elf', '.so', '.dylib'}:
            return True

        # Check MIME type
        if mime_type in self.EXECUTABLE_MIME_TYPES:
            return True

        # Check file type string
        executable_keywords = ['executable', 'shared object', 'dynamically linked']
        file_type_lower = file_type.lower()
        return any(keyword in file_type_lower for keyword in executable_keywords)

    def _is_archive(self, extension: str, mime_type: str) -> bool:
        """Determine if file is an archive"""
        archive_extensions = {'.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.apk', '.ipa'}
        if extension in archive_extensions:
            return True

        archive_mime_types = {
            'application/zip',
            'application/x-tar',
            'application/gzip',
            'application/x-bzip2',
            'application/x-xz',
            'application/x-7z-compressed',
            'application/x-rar-compressed',
        }
        return mime_type in archive_mime_types

    async def stream_file_chunks(
        self, file_path: str, chunk_size: int = 8192
    ) -> AsyncGenerator[bytes, None]:
        """
        Stream file in chunks asynchronously.
        Use this for processing large files without loading into memory.

        Usage:
            async for chunk in validator.stream_file_chunks(path):
                process_chunk(chunk)
        """
        def _read_chunks():
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

        for chunk in await asyncio.to_thread(list, _read_chunks()):
            yield chunk

    def validate_upload(
        self,
        file: BinaryIO,
        filename: str,
        max_size_bytes: int
    ) -> tuple[bool, str]:
        """
        Validate uploaded file before saving.
        Returns (is_valid, error_message)

        Use this for FastAPI file uploads:
            is_valid, error = validator.validate_upload(file, filename, max_size)
            if not is_valid:
                raise HTTPException(400, detail=error)
        """
        # Check filename
        if not filename:
            return False, "Filename is required"

        path_obj = Path(filename)
        extension = path_obj.suffix.lower()

        # Check extension
        if self.config.allowed_extensions is not None:
            if extension not in self.config.allowed_extensions:
                return False, f"File type '{extension}' not allowed. Supported: {', '.join(self.config.allowed_extensions)}"

        # Check size by reading chunks (don't load entire file)
        total_size = 0
        try:
            file.seek(0)
            while True:
                chunk = file.read(self.config.chunk_size)
                if not chunk:
                    break
                total_size += len(chunk)

                if total_size > max_size_bytes:
                    size_gb = total_size / (1024 ** 3)
                    max_gb = max_size_bytes / (1024 ** 3)
                    return False, f"File too large: {size_gb:.2f}GB (max: {max_gb:.2f}GB)"

            # Reset file pointer
            file.seek(0)

        except Exception as e:
            logger.error(f"Error validating upload: {e}")
            return False, f"Failed to validate file: {str(e)}"

        return True, ""


# Pre-configured validators for common use cases
binary_validator = FileValidator(
    ValidationConfig(
        max_size_gb=5.0,
        allowed_extensions=list(FileValidator.BINARY_EXTENSIONS),
        require_binary=True,
        calculate_hash=True
    )
)

apk_validator = FileValidator(
    ValidationConfig(
        max_size_gb=2.0,
        allowed_extensions=['.apk', '.aab'],
        allowed_mime_types=['application/vnd.android.package-archive', 'application/zip'],
        require_binary=True,
        calculate_hash=True
    )
)

firmware_validator = FileValidator(
    ValidationConfig(
        max_size_gb=5.0,
        allowed_extensions=['.bin', '.fw', '.hex', '.img', '.rom'],
        require_binary=True,
        calculate_hash=True
    )
)

archive_validator = FileValidator(
    ValidationConfig(
        max_size_gb=5.0,
        allowed_extensions=['.zip', '.tar', '.gz', '.bz2', '.xz', '.7z'],
        calculate_hash=True
    )
)


# =============================================================================
# SECURITY: Path Traversal Prevention
# =============================================================================

# Allowed extensions for binary analysis (whitelist approach)
SAFE_BINARY_EXTENSIONS = {
    '.exe', '.dll', '.so', '.elf', '.bin', '.o', '.a', '.dylib',
    '.apk', '.aab', '.dex', '.odex', '.ipa',
    '.sys', '.drv', '.ko', '.kext',
    '.fw', '.hex', '.srec', '.rom', '.img',
    '.zip', '.tar', '.gz', '.7z', '.rar',
}


def sanitize_filename(filename: Optional[str], preserve_extension: bool = True) -> str:
    """
    Sanitize a user-provided filename to prevent path traversal attacks.

    This function:
    1. Generates a UUID-based filename to eliminate path traversal risk
    2. Optionally preserves the original file extension (validated against whitelist)
    3. Removes any directory components from the original filename

    Args:
        filename: The original filename from user input (e.g., file.filename)
        preserve_extension: If True, preserve the original extension if it's safe

    Returns:
        A safe UUID-based filename like "a1b2c3d4-e5f6-7890-abcd-ef1234567890.bin"

    Example:
        >>> sanitize_filename("../../../etc/passwd")
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890.bin'
        >>> sanitize_filename("malware.exe")
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890.exe'
        >>> sanitize_filename("test.apk")
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890.apk'
    """
    safe_uuid = str(uuid.uuid4())

    if not filename or not preserve_extension:
        return f"{safe_uuid}.bin"

    # Extract just the filename part (remove any directory components)
    # This handles both forward and backward slashes
    basename = Path(filename).name

    # Remove any remaining path traversal attempts
    basename = re.sub(r'\.\.+', '', basename)
    basename = re.sub(r'[/\\]', '', basename)

    # Extract extension safely
    if '.' in basename:
        extension = '.' + basename.rsplit('.', 1)[-1].lower()
    else:
        extension = '.bin'

    # Validate extension against whitelist
    if extension not in SAFE_BINARY_EXTENSIONS:
        # For unknown extensions, use .bin as safe default
        extension = '.bin'

    return f"{safe_uuid}{extension}"


def get_safe_path(base_dir: Path, filename: Optional[str]) -> Path:
    """
    Create a safe file path within a base directory.

    This is the recommended way to create file paths for uploaded files.
    It combines sanitize_filename with path resolution to ensure the
    resulting path is always within the base directory.

    Args:
        base_dir: The base directory where files should be stored
        filename: The original filename from user input

    Returns:
        A Path object pointing to a safe location within base_dir

    Raises:
        ValueError: If the resulting path would escape base_dir (should never happen
                   with sanitized filenames, but included as defense in depth)

    Example:
        >>> get_safe_path(Path("/tmp/uploads"), "../../../etc/passwd")
        PosixPath('/tmp/uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890.bin')
    """
    safe_name = sanitize_filename(filename)
    safe_path = (base_dir / safe_name).resolve()

    # Defense in depth: verify path is within base_dir
    try:
        safe_path.relative_to(base_dir.resolve())
    except ValueError:
        logger.error(f"Path traversal attempt detected: {filename} -> {safe_path}")
        raise ValueError("Invalid filename: path traversal detected")

    return safe_path


# Helper function for FastAPI dependency injection
async def validate_binary_file(file_path: str) -> FileInfo:
    """
    Validate binary file (FastAPI dependency).

    Usage in router:
        @router.post("/analyze")
        async def analyze(file_info: FileInfo = Depends(validate_binary_file)):
            ...
    """
    return await binary_validator.validate_file_async(file_path)
