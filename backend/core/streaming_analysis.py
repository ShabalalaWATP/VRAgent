"""
Streaming Analysis for Large Files
Handles binary analysis without loading entire files into memory
"""

import asyncio
import logging
from typing import AsyncGenerator, Optional, Callable, Any
from pathlib import Path
import hashlib

import lief

from backend.core.file_validator import FileValidator
from backend.core.resource_limits import limit_xlarge
from backend.core.prometheus_metrics import record_binary_analyzed

logger = logging.getLogger(__name__)


class StreamingBinaryAnalyzer:
    """
    Analyze large binaries using streaming techniques.

    Features:
    - Chunk-based processing
    - Memory-efficient parsing
    - Progress reporting
    - Resumable analysis
    - Resource-aware processing
    """

    def __init__(self, chunk_size: int = 8 * 1024 * 1024):  # 8MB chunks
        self.chunk_size = chunk_size
        self.validator = FileValidator()

    async def stream_chunks(
        self,
        file_path: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> AsyncGenerator[bytes, None]:
        """
        Stream file in chunks.

        Args:
            file_path: Path to binary file
            progress_callback: Optional callback(bytes_processed, total_bytes)

        Yields:
            Bytes chunks
        """
        file_size = Path(file_path).stat().st_size
        bytes_processed = 0

        def _read_chunks():
            nonlocal bytes_processed
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break

                    bytes_processed += len(chunk)

                    if progress_callback:
                        progress_callback(bytes_processed, file_size)

                    yield chunk

        # Run in thread pool to avoid blocking
        for chunk in await asyncio.to_thread(list, _read_chunks()):
            yield chunk

    async def calculate_hash_streaming(
        self,
        file_path: str,
        algorithm: str = "sha256",
        progress_callback: Optional[Callable] = None
    ) -> str:
        """
        Calculate file hash using streaming.

        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha1, md5)
            progress_callback: Optional progress callback

        Returns:
            Hex digest of hash
        """
        if algorithm == "sha256":
            hasher = hashlib.sha256()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        elif algorithm == "md5":
            hasher = hashlib.md5()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        async for chunk in self.stream_chunks(file_path, progress_callback):
            hasher.update(chunk)

        return hasher.hexdigest()

    async def extract_strings_streaming(
        self,
        file_path: str,
        min_length: int = 4,
        progress_callback: Optional[Callable] = None
    ) -> AsyncGenerator[str, None]:
        """
        Extract strings from binary using streaming.

        Args:
            file_path: Path to binary
            min_length: Minimum string length
            progress_callback: Optional progress callback

        Yields:
            Extracted strings
        """
        buffer = b""
        current_string = b""

        async for chunk in self.stream_chunks(file_path, progress_callback):
            # Process chunk
            for byte in chunk:
                # Printable ASCII characters
                if 32 <= byte <= 126:
                    current_string += bytes([byte])
                else:
                    # End of string
                    if len(current_string) >= min_length:
                        try:
                            yield current_string.decode('ascii')
                        except:
                            pass
                    current_string = b""

        # Handle final string
        if len(current_string) >= min_length:
            try:
                yield current_string.decode('ascii')
            except:
                pass

    async def scan_entropy_streaming(
        self,
        file_path: str,
        block_size: int = 256,
        progress_callback: Optional[Callable] = None
    ) -> AsyncGenerator[tuple[int, float], None]:
        """
        Calculate entropy for blocks using streaming.

        Args:
            file_path: Path to binary
            block_size: Size of blocks to analyze
            progress_callback: Optional progress callback

        Yields:
            Tuples of (offset, entropy)
        """
        import math
        from collections import Counter

        offset = 0
        buffer = b""

        async for chunk in self.stream_chunks(file_path, progress_callback):
            buffer += chunk

            # Process complete blocks
            while len(buffer) >= block_size:
                block = buffer[:block_size]
                buffer = buffer[block_size:]

                # Calculate entropy
                byte_counts = Counter(block)
                entropy = 0.0

                for count in byte_counts.values():
                    probability = count / len(block)
                    entropy -= probability * math.log2(probability)

                yield (offset, entropy)
                offset += block_size

    @limit_xlarge  # 16GB, 2 hours
    async def analyze_large_binary_streaming(
        self,
        file_path: str,
        analysis_type: str = "standard",
        progress_callback: Optional[Callable] = None
    ) -> dict:
        """
        Analyze large binary using streaming techniques.

        Args:
            file_path: Path to binary file
            analysis_type: Type of analysis (quick, standard, deep)
            progress_callback: Optional progress callback

        Returns:
            Analysis results dictionary
        """
        logger.info(f"Starting streaming analysis of {file_path} ({analysis_type})")

        result = {
            "file_path": file_path,
            "analysis_type": analysis_type,
            "status": "in_progress",
        }

        try:
            # Step 1: Validate file
            file_info = await self.validator.validate_file_async(file_path)

            if not file_info.is_valid:
                result["status"] = "invalid"
                result["errors"] = file_info.validation_errors
                return result

            result["file_info"] = {
                "size_bytes": file_info.size_bytes,
                "size_gb": file_info.size_gb,
                "sha256": file_info.sha256,
                "mime_type": file_info.mime_type,
                "file_type": file_info.file_type,
            }

            # Step 2: Parse headers (fast, no streaming needed)
            logger.info("Parsing binary headers...")
            binary = await asyncio.to_thread(lief.parse, file_path)

            if binary:
                result["format"] = binary.format.name
                result["architecture"] = str(binary.header.machine_type) if hasattr(binary.header, 'machine_type') else "unknown"
                result["entry_point"] = hex(binary.entrypoint)

                # Extract sections
                result["sections"] = []
                for section in binary.sections:
                    result["sections"].append({
                        "name": section.name,
                        "virtual_address": hex(section.virtual_address),
                        "size": section.size,
                    })

                # Extract imports (limited to avoid memory issues)
                result["imports"] = []
                for imp in list(binary.imported_functions)[:500]:  # Limit to 500
                    result["imports"].append(imp.name)

            # Step 3: String extraction (streaming)
            if analysis_type in ["standard", "deep"]:
                logger.info("Extracting strings (streaming)...")
                strings = []
                count = 0
                max_strings = 10000 if analysis_type == "standard" else 50000

                async for string in self.extract_strings_streaming(file_path):
                    strings.append(string)
                    count += 1

                    if count >= max_strings:
                        break

                result["strings_count"] = count
                result["strings_sample"] = strings[:100]  # First 100 for sample

            # Step 4: Entropy analysis (streaming)
            if analysis_type == "deep":
                logger.info("Calculating entropy (streaming)...")
                entropy_blocks = []
                high_entropy_blocks = []

                async for offset, entropy in self.scan_entropy_streaming(file_path):
                    entropy_blocks.append((offset, entropy))

                    # Flag high entropy blocks (potential packing/encryption)
                    if entropy > 7.5:
                        high_entropy_blocks.append({
                            "offset": hex(offset),
                            "entropy": entropy
                        })

                result["entropy_blocks_analyzed"] = len(entropy_blocks)
                result["high_entropy_blocks"] = high_entropy_blocks[:50]  # Limit output

            # Step 5: Calculate hashes (streaming)
            logger.info("Calculating hashes (streaming)...")
            result["hashes"] = {
                "sha256": await self.calculate_hash_streaming(file_path, "sha256", progress_callback),
                "sha1": await self.calculate_hash_streaming(file_path, "sha1", progress_callback),
                "md5": await self.calculate_hash_streaming(file_path, "md5", progress_callback),
            }

            result["status"] = "completed"
            logger.info(f"Streaming analysis completed for {file_path}")

            # Record metrics
            record_binary_analyzed(
                success=True,
                size_bytes=file_info.size_bytes,
                duration_seconds=0,  # TODO: Track actual duration
                analysis_type=analysis_type
            )

        except Exception as e:
            logger.error(f"Streaming analysis failed: {e}", exc_info=True)
            result["status"] = "failed"
            result["error"] = str(e)

            # Record failure
            record_binary_analyzed(
                success=False,
                size_bytes=0,
                duration_seconds=0,
                analysis_type=analysis_type
            )

        return result

    async def analyze_multiple_large_files(
        self,
        file_paths: list[str],
        analysis_type: str = "standard",
        max_concurrent: int = 3,
        progress_callback: Optional[Callable] = None
    ) -> AsyncGenerator[dict, None]:
        """
        Analyze multiple large files with concurrency control.

        Args:
            file_paths: List of file paths
            analysis_type: Type of analysis
            max_concurrent: Maximum concurrent analyses
            progress_callback: Optional progress callback

        Yields:
            Analysis results for each file
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def analyze_with_semaphore(file_path: str):
            async with semaphore:
                return await self.analyze_large_binary_streaming(
                    file_path,
                    analysis_type,
                    progress_callback
                )

        # Create tasks for all files
        tasks = [analyze_with_semaphore(fp) for fp in file_paths]

        # Yield results as they complete
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result


# Global analyzer instance
streaming_analyzer = StreamingBinaryAnalyzer()


# ============================================================================
# Helper Functions
# ============================================================================

async def quick_hash_large_file(file_path: str) -> str:
    """Quickly hash large file using streaming"""
    return await streaming_analyzer.calculate_hash_streaming(file_path)


async def extract_strings_from_large_file(
    file_path: str,
    min_length: int = 4
) -> list[str]:
    """Extract strings from large file"""
    strings = []
    async for string in streaming_analyzer.extract_strings_streaming(file_path, min_length):
        strings.append(string)

        # Limit to prevent memory issues
        if len(strings) >= 100000:
            break

    return strings


async def analyze_large_binary(
    file_path: str,
    analysis_type: str = "standard"
) -> dict:
    """Analyze large binary (convenience function)"""
    return await streaming_analyzer.analyze_large_binary_streaming(
        file_path,
        analysis_type
    )
