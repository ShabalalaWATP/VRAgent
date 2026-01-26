"""
Comparison Logging Service (CMPLOG-style)

AFL++'s CMPLOG is one of its most powerful features. It instruments:
- strcmp/memcmp/strncmp calls
- Switch statement cases
- Integer comparisons

When a comparison fails, we extract BOTH operands. This tells us:
- What the input provided
- What the program expected

We can then directly inject the expected value, bypassing the need
for random mutation to stumble upon magic bytes like "ELF\x7f" or "PNG".

This can speed up finding magic bytes by 100-1000x.
"""

import logging
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import hashlib

logger = logging.getLogger(__name__)


class ComparisonType(str, Enum):
    """Types of comparisons we track."""
    STRCMP = "strcmp"  # String comparison
    MEMCMP = "memcmp"  # Memory comparison
    STRNCMP = "strncmp"  # Length-limited string comparison
    INTEGER = "integer"  # Integer comparison (==, !=, <, >, etc.)
    SWITCH = "switch"  # Switch statement
    MAGIC_BYTES = "magic_bytes"  # File magic detection
    CRC_CHECK = "crc_check"  # Checksum validation
    LENGTH_CHECK = "length_check"  # Size/length validation


@dataclass
class ComparisonOperand:
    """One side of a comparison."""
    value: bytes  # Raw bytes
    source: str  # "input", "constant", "computed"
    location: Optional[int] = None  # Offset in input if source="input"
    size: int = 0


@dataclass
class ComparisonLog:
    """A logged comparison operation."""
    comparison_id: str
    comp_type: ComparisonType
    address: int  # Instruction address
    function: Optional[str]  # Function name if known

    operand1: ComparisonOperand  # Usually the input-derived value
    operand2: ComparisonOperand  # Usually the expected constant

    result: bool  # Did comparison succeed?
    input_offset: Optional[int] = None  # Where in input this relates to

    # For integer comparisons
    operation: Optional[str] = None  # ==, !=, <, >, <=, >=

    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    execution_count: int = 1


@dataclass
class MagicByteCandidate:
    """A candidate magic byte sequence to try."""
    value: bytes
    offset: int  # Where to place in input
    confidence: float  # 0-1
    source: str  # "cmplog", "header_analysis", "format_db"
    comp_type: ComparisonType


@dataclass
class ComparisonStats:
    """Statistics about comparisons."""
    total_comparisons: int = 0
    unique_constants: int = 0
    solved_comparisons: int = 0
    magic_bytes_found: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)


class ComparisonLoggingService:
    """
    CMPLOG-style comparison operand extraction.

    Key insight: When fuzzing hits a comparison like:
        if (memcmp(input, "MAGIC", 5) == 0)

    Traditional fuzzing must randomly mutate until it hits "MAGIC".
    With CMPLOG, we extract "MAGIC" directly and inject it.

    This is how AFL++ achieves 100x speedup on magic byte checks.
    """

    # Known magic byte signatures for common formats
    KNOWN_MAGIC = {
        b"\x7fELF": "ELF executable",
        b"MZ": "PE executable",
        b"\x89PNG": "PNG image",
        b"GIF8": "GIF image",
        b"\xff\xd8\xff": "JPEG image",
        b"PK\x03\x04": "ZIP archive",
        b"\x1f\x8b": "GZIP archive",
        b"BZh": "BZIP2 archive",
        b"%PDF": "PDF document",
        b"{\n": "JSON",
        b"<?xml": "XML document",
        b"<!DOCTYPE": "HTML document",
        b"#!": "Script shebang",
        b"\x00\x00\x00\x18ftypmp4": "MP4 video",
        b"RIFF": "RIFF container (WAV/AVI)",
        b"OggS": "OGG container",
        b"\xca\xfe\xba\xbe": "Mach-O fat binary",
        b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
        b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    }

    # Common comparison functions to track
    COMPARISON_FUNCTIONS = {
        "strcmp", "strncmp", "strcasecmp", "strncasecmp",
        "memcmp", "bcmp",
        "wcscmp", "wcsncmp",
        "xmlStrcmp", "xmlStrncmp",
        "g_strcmp0", "g_ascii_strcasecmp",
    }

    def __init__(self):
        # All logged comparisons
        self._comparisons: Dict[str, ComparisonLog] = {}

        # Index by constant value for quick lookup
        self._constant_index: Dict[bytes, List[str]] = defaultdict(list)

        # Magic byte candidates extracted
        self._magic_candidates: List[MagicByteCandidate] = []

        # Statistics
        self._stats = ComparisonStats()

        # Solved comparisons (we know how to satisfy them)
        self._solved: Set[str] = set()

        logger.info("ComparisonLoggingService initialized")

    def log_comparison(
        self,
        address: int,
        comp_type: ComparisonType,
        operand1: bytes,
        operand2: bytes,
        result: bool,
        input_offset: Optional[int] = None,
        function: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> ComparisonLog:
        """
        Log a comparison operation.

        Args:
            address: Instruction address where comparison occurred
            comp_type: Type of comparison
            operand1: First operand (usually input-derived)
            operand2: Second operand (usually constant/expected)
            result: Did comparison succeed?
            input_offset: Offset in input where operand1 came from
            function: Function name if known
            operation: For integer comparisons: ==, !=, <, etc.

        Returns:
            The logged comparison
        """
        self._stats.total_comparisons += 1
        self._stats.by_type[comp_type.value] = self._stats.by_type.get(comp_type.value, 0) + 1

        # Create comparison ID
        comp_id = hashlib.md5(
            f"{address}:{comp_type.value}:{operand2.hex()}".encode()
        ).hexdigest()[:12]

        # Determine operand sources
        op1 = ComparisonOperand(
            value=operand1,
            source="input" if input_offset is not None else "computed",
            location=input_offset,
            size=len(operand1),
        )

        op2 = ComparisonOperand(
            value=operand2,
            source="constant" if self._looks_constant(operand2) else "computed",
            size=len(operand2),
        )

        # Check if this is a known comparison
        if comp_id in self._comparisons:
            existing = self._comparisons[comp_id]
            existing.execution_count += 1
            return existing

        comp_log = ComparisonLog(
            comparison_id=comp_id,
            comp_type=comp_type,
            address=address,
            function=function,
            operand1=op1,
            operand2=op2,
            result=result,
            input_offset=input_offset,
            operation=operation,
        )

        self._comparisons[comp_id] = comp_log

        # Index by constant value
        if op2.source == "constant":
            self._constant_index[operand2].append(comp_id)
            self._stats.unique_constants = len(self._constant_index)

        # Check for magic bytes
        if comp_type in [ComparisonType.MEMCMP, ComparisonType.STRCMP, ComparisonType.MAGIC_BYTES]:
            self._check_magic_candidate(comp_log)

        return comp_log

    def _looks_constant(self, data: bytes) -> bool:
        """Heuristic: does this look like a constant vs computed value?"""
        if len(data) == 0:
            return False

        # Check if it's a known magic
        for magic in self.KNOWN_MAGIC:
            if data.startswith(magic):
                return True

        # Check if it's printable ASCII (likely a string constant)
        try:
            decoded = data.decode('ascii')
            if decoded.isprintable():
                return True
        except (UnicodeDecodeError, ValueError):
            pass

        # Small integers are often constants
        if len(data) <= 8:
            val = int.from_bytes(data, 'little')
            # Common constant ranges
            if val < 1000 or val in [0x100, 0x1000, 0x10000, 0xffffffff]:
                return True

        return False

    def _check_magic_candidate(self, comp: ComparisonLog):
        """Check if a comparison reveals magic bytes."""
        expected = comp.operand2.value

        # Check against known magic
        for magic, description in self.KNOWN_MAGIC.items():
            if expected.startswith(magic) or magic.startswith(expected):
                self._magic_candidates.append(MagicByteCandidate(
                    value=magic,
                    offset=comp.input_offset or 0,
                    confidence=0.95,
                    source="cmplog_known",
                    comp_type=comp.comp_type,
                ))
                self._stats.magic_bytes_found += 1
                logger.info(f"Found magic bytes for {description}: {magic.hex()}")
                return

        # If comparison failed and we have the expected value, it's a candidate
        if not comp.result and len(expected) >= 2:
            self._magic_candidates.append(MagicByteCandidate(
                value=expected,
                offset=comp.input_offset or 0,
                confidence=0.7,
                source="cmplog_extracted",
                comp_type=comp.comp_type,
            ))

    def get_magic_candidates(
        self,
        min_confidence: float = 0.5,
    ) -> List[MagicByteCandidate]:
        """Get magic byte candidates sorted by confidence."""
        candidates = [c for c in self._magic_candidates if c.confidence >= min_confidence]
        candidates.sort(key=lambda c: c.confidence, reverse=True)
        return candidates

    def generate_solving_mutations(
        self,
        input_data: bytes,
        max_mutations: int = 10,
    ) -> List[bytes]:
        """
        Generate mutated inputs that solve logged comparisons.

        This is the key CMPLOG insight: instead of random mutation,
        we directly inject the expected values we've extracted.
        """
        mutations = []
        candidates = self.get_magic_candidates(min_confidence=0.5)

        for candidate in candidates[:max_mutations]:
            if candidate.offset + len(candidate.value) <= len(input_data):
                # Inject the magic bytes at the expected offset
                mutated = bytearray(input_data)
                mutated[candidate.offset:candidate.offset + len(candidate.value)] = candidate.value
                mutations.append(bytes(mutated))
                logger.debug(f"Generated solving mutation: {candidate.value.hex()} at offset {candidate.offset}")

        # Also try injecting constants we've seen
        for const_value, comp_ids in list(self._constant_index.items())[:max_mutations]:
            if len(const_value) > 0 and len(const_value) <= 16:
                # Try at offset 0 (common for file headers)
                if len(const_value) <= len(input_data):
                    mutated = bytearray(input_data)
                    mutated[:len(const_value)] = const_value
                    mutations.append(bytes(mutated))

        return mutations[:max_mutations]

    def parse_strcmp_log(
        self,
        address: int,
        str1_ptr: int,
        str2_ptr: int,
        str1_data: bytes,
        str2_data: bytes,
        result: int,
    ) -> ComparisonLog:
        """Parse a strcmp call log."""
        # Null-terminate strings
        str1 = str1_data.split(b'\x00')[0]
        str2 = str2_data.split(b'\x00')[0]

        return self.log_comparison(
            address=address,
            comp_type=ComparisonType.STRCMP,
            operand1=str1,
            operand2=str2,
            result=(result == 0),
        )

    def parse_memcmp_log(
        self,
        address: int,
        buf1_ptr: int,
        buf2_ptr: int,
        buf1_data: bytes,
        buf2_data: bytes,
        size: int,
        result: int,
        input_offset: Optional[int] = None,
    ) -> ComparisonLog:
        """Parse a memcmp call log."""
        return self.log_comparison(
            address=address,
            comp_type=ComparisonType.MEMCMP,
            operand1=buf1_data[:size],
            operand2=buf2_data[:size],
            result=(result == 0),
            input_offset=input_offset,
        )

    def parse_integer_comparison(
        self,
        address: int,
        val1: int,
        val2: int,
        operation: str,  # "==", "!=", "<", ">", "<=", ">="
        size: int = 8,  # Size in bytes
    ) -> ComparisonLog:
        """Parse an integer comparison."""
        # Determine result based on operation
        results = {
            "==": val1 == val2,
            "!=": val1 != val2,
            "<": val1 < val2,
            ">": val1 > val2,
            "<=": val1 <= val2,
            ">=": val1 >= val2,
        }
        result = results.get(operation, False)

        return self.log_comparison(
            address=address,
            comp_type=ComparisonType.INTEGER,
            operand1=val1.to_bytes(size, 'little'),
            operand2=val2.to_bytes(size, 'little'),
            result=result,
            operation=operation,
        )

    def parse_switch_case(
        self,
        address: int,
        switch_value: int,
        case_values: List[int],
        matched_case: Optional[int],
    ) -> List[ComparisonLog]:
        """Parse a switch statement."""
        logs = []
        for case_val in case_values:
            logs.append(self.log_comparison(
                address=address,
                comp_type=ComparisonType.SWITCH,
                operand1=switch_value.to_bytes(8, 'little'),
                operand2=case_val.to_bytes(8, 'little'),
                result=(case_val == matched_case),
                operation="==",
            ))
        return logs

    def get_unsolved_comparisons(self) -> List[ComparisonLog]:
        """Get comparisons that haven't been satisfied yet."""
        return [
            c for c in self._comparisons.values()
            if not c.result and c.comparison_id not in self._solved
        ]

    def mark_solved(self, comparison_id: str):
        """Mark a comparison as solved (we found input that satisfies it)."""
        self._solved.add(comparison_id)
        self._stats.solved_comparisons = len(self._solved)

    def get_dictionary_entries(self) -> List[bytes]:
        """
        Get dictionary entries extracted from comparisons.

        These can be added to AFL++'s dictionary for more effective fuzzing.
        """
        entries = set()

        for const_value in self._constant_index.keys():
            if 2 <= len(const_value) <= 32:
                entries.add(const_value)

        for candidate in self._magic_candidates:
            if 2 <= len(candidate.value) <= 32:
                entries.add(candidate.value)

        return list(entries)

    def get_statistics(self) -> Dict[str, Any]:
        """Get comparison logging statistics."""
        return {
            "total_comparisons": self._stats.total_comparisons,
            "unique_constants": self._stats.unique_constants,
            "solved_comparisons": self._stats.solved_comparisons,
            "magic_bytes_found": self._stats.magic_bytes_found,
            "comparisons_by_type": self._stats.by_type,
            "dictionary_entries": len(self.get_dictionary_entries()),
            "unsolved_count": len(self.get_unsolved_comparisons()),
        }

    def clear(self):
        """Clear all logged comparisons."""
        self._comparisons.clear()
        self._constant_index.clear()
        self._magic_candidates.clear()
        self._solved.clear()
        self._stats = ComparisonStats()


# =============================================================================
# Integration with Fuzzing Engine
# =============================================================================

class CMPLOGInstrumentor:
    """
    Instruments binaries for CMPLOG-style comparison logging.

    In a full implementation, this would:
    1. Use binary rewriting (QEMU, Frida, or compile-time instrumentation)
    2. Hook comparison functions (strcmp, memcmp, etc.)
    3. Capture operands at runtime
    4. Feed them back to the fuzzer

    This is a simplified version that works with ASAN output and GDB.
    """

    def __init__(self, comparison_service: ComparisonLoggingService):
        self.service = comparison_service

    def parse_asan_strcmp(self, asan_output: str) -> List[ComparisonLog]:
        """Parse strcmp/memcmp calls from ASAN output (if detailed logging enabled)."""
        logs = []

        # Pattern for ASAN comparison logs (custom instrumentation)
        pattern = r"CMPLOG:\s+(strcmp|memcmp|strncmp)\s+@\s+0x([0-9a-fA-F]+)\s+\[([^\]]+)\]\s+vs\s+\[([^\]]+)\]"

        for match in re.finditer(pattern, asan_output):
            func, addr, val1_hex, val2_hex = match.groups()

            try:
                val1 = bytes.fromhex(val1_hex)
                val2 = bytes.fromhex(val2_hex)
            except ValueError:
                continue

            comp_type = {
                "strcmp": ComparisonType.STRCMP,
                "memcmp": ComparisonType.MEMCMP,
                "strncmp": ComparisonType.STRNCMP,
            }.get(func, ComparisonType.MEMCMP)

            log = self.service.log_comparison(
                address=int(addr, 16),
                comp_type=comp_type,
                operand1=val1,
                operand2=val2,
                result=(val1 == val2),
                function=func,
            )
            logs.append(log)

        return logs

    def analyze_input_for_headers(
        self,
        input_data: bytes,
    ) -> List[MagicByteCandidate]:
        """
        Analyze input to detect potential header mismatches.

        If input doesn't start with a known magic, suggest trying magic bytes.
        """
        candidates = []

        if len(input_data) < 4:
            return candidates

        current_header = input_data[:8]

        for magic, description in ComparisonLoggingService.KNOWN_MAGIC.items():
            if not current_header.startswith(magic):
                # This format's magic isn't present - it's a candidate to try
                candidates.append(MagicByteCandidate(
                    value=magic,
                    offset=0,
                    confidence=0.3,  # Lower confidence for speculative
                    source="header_analysis",
                    comp_type=ComparisonType.MAGIC_BYTES,
                ))

        return candidates


# =============================================================================
# Convenience Functions
# =============================================================================

_cmplog_service: Optional[ComparisonLoggingService] = None


def get_comparison_service() -> ComparisonLoggingService:
    """Get global comparison logging service."""
    global _cmplog_service
    if _cmplog_service is None:
        _cmplog_service = ComparisonLoggingService()
    return _cmplog_service


# Alias for compatibility
get_comparison_logging_service = get_comparison_service


def extract_magic_mutations(
    input_data: bytes,
    max_mutations: int = 10,
) -> List[bytes]:
    """
    Generate mutations that inject known/extracted magic bytes.

    This is the key to CMPLOG effectiveness.
    """
    service = get_comparison_service()
    return service.generate_solving_mutations(input_data, max_mutations)
