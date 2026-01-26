"""
Crash Deduplication Service

Industry-standard crash deduplication using multiple strategies:
1. Stack hash bucketing (like AFL++/Mayhem)
2. Program counter clustering
3. Call stack similarity (MinHash)
4. Memory access pattern matching

This is CRITICAL for real-world fuzzing - without it, you get
10,000 "crashes" that are actually 5 unique bugs.
"""

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import struct

logger = logging.getLogger(__name__)


class DeduplicationStrategy(str, Enum):
    """Strategies for crash deduplication."""
    STACK_HASH = "stack_hash"  # Hash of top N stack frames
    PC_BUCKET = "pc_bucket"  # Group by crash PC
    CALL_CHAIN = "call_chain"  # Full call chain similarity
    MINHASH = "minhash"  # Locality-sensitive hashing
    EXPLOITABILITY = "exploitability"  # Group by exploit type
    COMBINED = "combined"  # Multiple strategies


class CrashSeverity(str, Enum):
    """Crash severity levels."""
    CRITICAL = "critical"  # Likely exploitable (controlled PC)
    HIGH = "high"  # Probably exploitable (heap/stack corruption)
    MEDIUM = "medium"  # Possibly exploitable
    LOW = "low"  # Unlikely exploitable (null deref, etc.)
    INFO = "info"  # Not a security issue


@dataclass
class StackFrame:
    """A single stack frame."""
    address: int
    function: Optional[str] = None
    module: Optional[str] = None
    offset: int = 0
    source_file: Optional[str] = None
    line_number: Optional[int] = None

    def to_hash_string(self, include_offset: bool = False) -> str:
        """Convert frame to string for hashing."""
        if self.function:
            base = f"{self.module or 'unknown'}!{self.function}"
        else:
            base = f"{self.module or 'unknown'}+{hex(self.address)}"

        if include_offset and self.offset:
            base += f"+{hex(self.offset)}"

        return base


@dataclass
class CrashSignature:
    """Unique signature for a crash."""
    crash_id: str
    bucket_id: str  # Deduplication bucket
    stack_hash: str  # Hash of top N frames
    pc_hash: str  # Hash of crash PC
    call_chain_hash: str  # Full call chain hash
    minhash_signature: List[int]  # MinHash for similarity

    # Crash details
    crash_address: int
    crash_type: str  # SIGSEGV, SIGABRT, etc.
    access_type: Optional[str] = None  # read, write, execute
    faulting_instruction: Optional[str] = None

    # Stack info
    stack_depth: int = 0
    top_functions: List[str] = field(default_factory=list)

    # Metadata
    severity: CrashSeverity = CrashSeverity.MEDIUM
    first_seen: datetime = field(default_factory=datetime.utcnow)
    occurrence_count: int = 1


@dataclass
class CrashBucket:
    """A bucket of deduplicated crashes."""
    bucket_id: str
    representative_crash: CrashSignature
    crash_ids: List[str] = field(default_factory=list)
    occurrence_count: int = 1
    severity: CrashSeverity = CrashSeverity.MEDIUM
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)

    # Bucket characteristics
    common_functions: List[str] = field(default_factory=list)
    crash_types: Set[str] = field(default_factory=set)
    triggering_inputs: List[bytes] = field(default_factory=list)


@dataclass
class DeduplicationResult:
    """Result of deduplication analysis."""
    crash_signature: CrashSignature
    is_new: bool
    bucket_id: str
    similarity_score: float  # 0-1, how similar to existing
    existing_bucket: Optional[CrashBucket] = None


class CrashDeduplicationService:
    """
    Industrial-strength crash deduplication.

    Uses multiple strategies to accurately bucket crashes:
    1. Stack hash (top N frames) - primary method
    2. PC clustering - for crashes without symbols
    3. MinHash - for fuzzy matching similar crashes
    4. Exploitability grouping - security-focused
    """

    # Configuration
    DEFAULT_STACK_DEPTH = 5  # Top N frames to hash (AFL++ uses 3-5)
    MINHASH_PERMUTATIONS = 128  # Number of MinHash permutations
    SIMILARITY_THRESHOLD = 0.8  # MinHash similarity for same bucket

    # Patterns for interesting crash types
    EXPLOITABLE_PATTERNS = {
        "write": r"(mov|store|st[rwb])\s+\[",  # Memory write
        "call": r"(call|jmp)\s+r[a-z]+",  # Indirect call/jump
        "ret": r"ret",  # Return instruction
    }

    def __init__(
        self,
        stack_depth: int = DEFAULT_STACK_DEPTH,
        strategy: DeduplicationStrategy = DeduplicationStrategy.COMBINED,
    ):
        self.stack_depth = stack_depth
        self.strategy = strategy

        # Buckets storage
        self._buckets: Dict[str, CrashBucket] = {}
        self._signatures: Dict[str, CrashSignature] = {}

        # MinHash state
        self._minhash_a = [hash(f"a_{i}") % (2**31) for i in range(self.MINHASH_PERMUTATIONS)]
        self._minhash_b = [hash(f"b_{i}") % (2**31) for i in range(self.MINHASH_PERMUTATIONS)]

        # Statistics
        self._total_crashes = 0
        self._unique_buckets = 0

        logger.info(f"CrashDeduplicationService initialized with strategy={strategy}")

    def deduplicate(
        self,
        crash_id: str,
        crash_address: int,
        crash_type: str,
        stack_frames: List[StackFrame],
        access_type: Optional[str] = None,
        faulting_instruction: Optional[str] = None,
        triggering_input: Optional[bytes] = None,
    ) -> DeduplicationResult:
        """
        Deduplicate a crash and assign it to a bucket.

        Returns whether this is a new unique crash.
        """
        self._total_crashes += 1

        # Build signature
        signature = self._build_signature(
            crash_id=crash_id,
            crash_address=crash_address,
            crash_type=crash_type,
            stack_frames=stack_frames,
            access_type=access_type,
            faulting_instruction=faulting_instruction,
        )

        # Find or create bucket
        bucket_id, is_new, similarity, existing = self._find_bucket(signature)

        signature.bucket_id = bucket_id

        # Update bucket
        if is_new:
            self._unique_buckets += 1
            bucket = CrashBucket(
                bucket_id=bucket_id,
                representative_crash=signature,
                crash_ids=[crash_id],
                severity=signature.severity,
                common_functions=signature.top_functions[:3],
                crash_types={crash_type},
            )
            if triggering_input:
                bucket.triggering_inputs.append(triggering_input)
            self._buckets[bucket_id] = bucket
            logger.info(f"New unique crash bucket: {bucket_id} ({signature.severity.value})")
        else:
            bucket = self._buckets[bucket_id]
            bucket.crash_ids.append(crash_id)
            bucket.occurrence_count += 1
            bucket.last_seen = datetime.utcnow()
            bucket.crash_types.add(crash_type)
            if triggering_input and len(bucket.triggering_inputs) < 10:
                bucket.triggering_inputs.append(triggering_input)

            # Update severity if this crash is worse
            if self._severity_rank(signature.severity) > self._severity_rank(bucket.severity):
                bucket.severity = signature.severity

        self._signatures[crash_id] = signature

        return DeduplicationResult(
            crash_signature=signature,
            is_new=is_new,
            bucket_id=bucket_id,
            similarity_score=similarity,
            existing_bucket=existing,
        )

    def _build_signature(
        self,
        crash_id: str,
        crash_address: int,
        crash_type: str,
        stack_frames: List[StackFrame],
        access_type: Optional[str],
        faulting_instruction: Optional[str],
    ) -> CrashSignature:
        """Build a crash signature from crash data."""

        # Stack hash (top N frames)
        stack_hash = self._compute_stack_hash(stack_frames)

        # PC hash (crash address with some normalization)
        pc_hash = self._compute_pc_hash(crash_address, stack_frames)

        # Call chain hash (all frames)
        call_chain_hash = self._compute_call_chain_hash(stack_frames)

        # MinHash signature
        minhash_sig = self._compute_minhash(stack_frames)

        # Extract top functions
        top_functions = [
            f.function or f"sub_{f.address:x}"
            for f in stack_frames[:self.stack_depth]
            if f.function or f.address
        ]

        # Determine severity
        severity = self._assess_severity(
            crash_address,
            crash_type,
            access_type,
            faulting_instruction,
            stack_frames,
        )

        return CrashSignature(
            crash_id=crash_id,
            bucket_id="",  # Set later
            stack_hash=stack_hash,
            pc_hash=pc_hash,
            call_chain_hash=call_chain_hash,
            minhash_signature=minhash_sig,
            crash_address=crash_address,
            crash_type=crash_type,
            access_type=access_type,
            faulting_instruction=faulting_instruction,
            stack_depth=len(stack_frames),
            top_functions=top_functions,
            severity=severity,
        )

    def _compute_stack_hash(self, frames: List[StackFrame]) -> str:
        """
        Compute stack hash from top N frames.

        This is the primary deduplication method used by AFL++ and most fuzzers.
        We hash function names (or addresses if no symbols) to create a bucket.
        """
        if not frames:
            return "empty_stack"

        # Use top N frames
        top_frames = frames[:self.stack_depth]

        # Build hash string
        parts = []
        for frame in top_frames:
            parts.append(frame.to_hash_string(include_offset=False))

        hash_input = "|".join(parts)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _compute_pc_hash(self, crash_address: int, frames: List[StackFrame]) -> str:
        """
        Compute PC-based hash.

        Useful when we don't have symbols. Normalizes address to module offset.
        """
        if frames and frames[0].module:
            # Use module + offset
            module = frames[0].module
            offset = crash_address - (frames[0].address - frames[0].offset) if frames[0].offset else crash_address
            hash_input = f"{module}+{offset:x}"
        else:
            # Just use address (less reliable due to ASLR)
            hash_input = f"addr_{crash_address:x}"

        return hashlib.sha256(hash_input.encode()).hexdigest()[:12]

    def _compute_call_chain_hash(self, frames: List[StackFrame]) -> str:
        """Compute hash of full call chain."""
        if not frames:
            return "no_chain"

        parts = [frame.to_hash_string() for frame in frames[:20]]  # Max 20 frames
        hash_input = "->".join(parts)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _compute_minhash(self, frames: List[StackFrame]) -> List[int]:
        """
        Compute MinHash signature for locality-sensitive hashing.

        Allows fuzzy matching of similar crashes even with slight variations.
        """
        # Create set of shingles (n-grams of frames)
        shingles = set()
        frame_strs = [f.to_hash_string() for f in frames]

        # Add individual frames
        for s in frame_strs:
            shingles.add(s)

        # Add pairs (bigrams)
        for i in range(len(frame_strs) - 1):
            shingles.add(f"{frame_strs[i]}|{frame_strs[i+1]}")

        if not shingles:
            return [0] * self.MINHASH_PERMUTATIONS

        # Compute MinHash
        signature = []
        for i in range(self.MINHASH_PERMUTATIONS):
            min_hash = float('inf')
            for shingle in shingles:
                h = hash(shingle)
                # Universal hashing: (a*h + b) mod p
                hash_val = (self._minhash_a[i] * h + self._minhash_b[i]) % (2**31 - 1)
                min_hash = min(min_hash, hash_val)
            signature.append(min_hash)

        return signature

    def _assess_severity(
        self,
        crash_address: int,
        crash_type: str,
        access_type: Optional[str],
        faulting_instruction: Optional[str],
        stack_frames: List[StackFrame],
    ) -> CrashSeverity:
        """Assess crash severity based on crash characteristics."""

        # Critical: controlled instruction pointer
        if crash_type in ["SIGILL", "SIGSEGV"] and access_type == "execute":
            return CrashSeverity.CRITICAL

        # Critical: write to controlled address
        if access_type == "write":
            # Check if crash address looks controlled (e.g., 0x41414141)
            addr_bytes = crash_address.to_bytes(8, 'little')
            if len(set(addr_bytes[:4])) <= 2:  # Repetitive pattern
                return CrashSeverity.CRITICAL

        # High: stack buffer overflow indicators
        top_funcs = [f.function for f in stack_frames[:3] if f.function]
        if any(f in ["__stack_chk_fail", "__fortify_fail"] for f in top_funcs):
            return CrashSeverity.HIGH

        # High: heap corruption
        if any(f in ["malloc", "free", "realloc", "__libc_malloc", "__libc_free"] for f in top_funcs):
            return CrashSeverity.HIGH

        # Medium: general SIGSEGV
        if crash_type == "SIGSEGV":
            if access_type == "write":
                return CrashSeverity.HIGH
            return CrashSeverity.MEDIUM

        # Medium: SIGABRT (assertion, abort)
        if crash_type == "SIGABRT":
            return CrashSeverity.MEDIUM

        # Low: null pointer dereference
        if crash_address < 0x1000:
            return CrashSeverity.LOW

        # Default
        return CrashSeverity.MEDIUM

    def _find_bucket(
        self,
        signature: CrashSignature,
    ) -> Tuple[str, bool, float, Optional[CrashBucket]]:
        """
        Find existing bucket or determine this is a new one.

        Returns: (bucket_id, is_new, similarity_score, existing_bucket)
        """

        # Strategy 1: Exact stack hash match (most common)
        for bucket in self._buckets.values():
            if bucket.representative_crash.stack_hash == signature.stack_hash:
                return bucket.bucket_id, False, 1.0, bucket

        # Strategy 2: MinHash similarity (fuzzy matching)
        best_match = None
        best_similarity = 0.0

        for bucket in self._buckets.values():
            similarity = self._minhash_similarity(
                signature.minhash_signature,
                bucket.representative_crash.minhash_signature,
            )
            if similarity > best_similarity:
                best_similarity = similarity
                best_match = bucket

        if best_match and best_similarity >= self.SIMILARITY_THRESHOLD:
            return best_match.bucket_id, False, best_similarity, best_match

        # Strategy 3: PC hash match (fallback for no symbols)
        for bucket in self._buckets.values():
            if bucket.representative_crash.pc_hash == signature.pc_hash:
                return bucket.bucket_id, False, 0.9, bucket

        # New unique crash
        bucket_id = f"bucket_{signature.stack_hash[:8]}_{len(self._buckets)}"
        return bucket_id, True, 0.0, None

    def _minhash_similarity(self, sig1: List[int], sig2: List[int]) -> float:
        """Compute Jaccard similarity estimate from MinHash signatures."""
        if len(sig1) != len(sig2):
            return 0.0

        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
        return matches / len(sig1)

    def _severity_rank(self, severity: CrashSeverity) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {
            CrashSeverity.CRITICAL: 4,
            CrashSeverity.HIGH: 3,
            CrashSeverity.MEDIUM: 2,
            CrashSeverity.LOW: 1,
            CrashSeverity.INFO: 0,
        }
        return ranks.get(severity, 0)

    def get_unique_crashes(self) -> List[CrashBucket]:
        """Get all unique crash buckets, sorted by severity."""
        buckets = list(self._buckets.values())
        buckets.sort(key=lambda b: (self._severity_rank(b.severity), b.occurrence_count), reverse=True)
        return buckets

    def get_statistics(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        severity_counts = defaultdict(int)
        for bucket in self._buckets.values():
            severity_counts[bucket.severity.value] += 1

        return {
            "total_crashes": self._total_crashes,
            "unique_buckets": self._unique_buckets,
            "deduplication_ratio": (
                1 - (self._unique_buckets / self._total_crashes)
                if self._total_crashes > 0 else 0
            ),
            "severity_distribution": dict(severity_counts),
            "strategy": self.strategy.value,
        }

    def export_buckets(self) -> List[Dict[str, Any]]:
        """Export buckets for reporting."""
        return [
            {
                "bucket_id": b.bucket_id,
                "severity": b.severity.value,
                "occurrence_count": b.occurrence_count,
                "crash_types": list(b.crash_types),
                "common_functions": b.common_functions,
                "first_seen": b.first_seen.isoformat(),
                "last_seen": b.last_seen.isoformat(),
                "sample_inputs": len(b.triggering_inputs),
            }
            for b in self.get_unique_crashes()
        ]


# =============================================================================
# Convenience Functions
# =============================================================================

_dedup_service: Optional[CrashDeduplicationService] = None


def get_deduplication_service() -> CrashDeduplicationService:
    """Get global deduplication service."""
    global _dedup_service
    if _dedup_service is None:
        _dedup_service = CrashDeduplicationService()
    return _dedup_service


# Alias for compatibility
get_crash_deduplication_service = get_deduplication_service


def deduplicate_crash(
    crash_id: str,
    crash_address: int,
    crash_type: str,
    stack_trace: List[Dict[str, Any]],
    triggering_input: Optional[bytes] = None,
) -> DeduplicationResult:
    """
    Convenience function to deduplicate a crash.

    Args:
        crash_id: Unique crash identifier
        crash_address: Address where crash occurred
        crash_type: Signal name (SIGSEGV, SIGABRT, etc.)
        stack_trace: List of frame dicts with 'address', 'function', 'module'
        triggering_input: Optional input that triggered the crash

    Returns:
        DeduplicationResult with is_new flag
    """
    service = get_deduplication_service()

    # Convert stack trace to StackFrame objects
    frames = [
        StackFrame(
            address=f.get("address", 0),
            function=f.get("function"),
            module=f.get("module"),
            offset=f.get("offset", 0),
        )
        for f in stack_trace
    ]

    return service.deduplicate(
        crash_id=crash_id,
        crash_address=crash_address,
        crash_type=crash_type,
        stack_frames=frames,
        access_type=stack_trace[0].get("access_type") if stack_trace else None,
        triggering_input=triggering_input,
    )


def parse_asan_stack(asan_output: str) -> List[StackFrame]:
    """Parse AddressSanitizer stack trace into StackFrame objects."""
    frames = []

    # ASAN frame pattern: #0 0x... in function_name file:line
    pattern = r"#(\d+)\s+0x([0-9a-fA-F]+)\s+in\s+(\S+)\s+(\S+)?(?::(\d+))?"

    for match in re.finditer(pattern, asan_output):
        frame_num, addr, func, source, line = match.groups()
        frames.append(StackFrame(
            address=int(addr, 16),
            function=func if func != "(unknown)" else None,
            source_file=source,
            line_number=int(line) if line else None,
        ))

    return frames


def parse_gdb_backtrace(gdb_output: str) -> List[StackFrame]:
    """Parse GDB backtrace into StackFrame objects."""
    frames = []

    # GDB frame pattern: #0  0x... in function () from /lib/...
    pattern = r"#(\d+)\s+(?:0x)?([0-9a-fA-F]+)\s+in\s+(\S+)\s*\([^)]*\)(?:\s+from\s+(\S+))?"

    for match in re.finditer(pattern, gdb_output):
        frame_num, addr, func, module = match.groups()
        frames.append(StackFrame(
            address=int(addr, 16),
            function=func if func != "??" else None,
            module=module,
        ))

    return frames
