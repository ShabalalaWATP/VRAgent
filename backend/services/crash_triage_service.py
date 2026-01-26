"""
Crash Triage Service

AI-powered crash analysis, exploitability assessment, and triage.
Provides deep analysis of crashes with exploit guidance.
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import struct

from backend.services.binary_ai_reasoning import (
    BinaryProfile,
    BinaryAIClient,
    ExploitabilityScore,
    CrashType,
    SecurityFeatures,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

class AccessType(str, Enum):
    """Type of memory access that caused crash."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    UNKNOWN = "unknown"


class ExploitPrimitive(str, Enum):
    """Available exploit primitives."""
    ARBITRARY_READ = "arbitrary_read"
    ARBITRARY_WRITE = "arbitrary_write"
    CONTROLLED_CALL = "controlled_call"
    CONTROLLED_JUMP = "controlled_jump"
    STACK_PIVOT = "stack_pivot"
    INFO_LEAK = "info_leak"
    HEAP_CONTROL = "heap_control"
    STACK_CONTROL = "stack_control"
    ROP_CHAIN = "rop_chain"
    JOP_CHAIN = "jop_chain"
    FORMAT_STRING = "format_string"


@dataclass
class StackFrame:
    """A single stack frame."""
    address: int
    function_name: Optional[str]
    offset: int
    module: Optional[str]
    source_file: Optional[str] = None
    source_line: Optional[int] = None


@dataclass
class MemoryRegion:
    """A memory region."""
    start: int
    end: int
    size: int
    permissions: str  # e.g., "rwx", "r-x", "rw-"
    name: Optional[str] = None
    is_stack: bool = False
    is_heap: bool = False


@dataclass
class RegisterState:
    """CPU register state at crash."""
    registers: Dict[str, int]
    flags: Optional[int] = None

    def get(self, name: str) -> Optional[int]:
        return self.registers.get(name.lower()) or self.registers.get(name.upper())


@dataclass
class CrashContext:
    """Full context of a crash."""
    crash_id: str
    timestamp: datetime

    # Crash location
    crash_address: int = 0
    crash_instruction: str = ""
    access_address: Optional[int] = None
    access_type: AccessType = AccessType.UNKNOWN

    # CPU state (optional - may not always be available)
    registers: Optional[RegisterState] = None
    stack_trace: List[StackFrame] = field(default_factory=list)

    # Memory state (optional - may not always be available)
    memory_map: List[MemoryRegion] = field(default_factory=list)
    stack_dump: Optional[bytes] = None
    heap_state: Optional[Dict[str, Any]] = None

    # Input
    input_data: bytes = b""
    input_hash: str = ""
    input_size: int = 0

    # Signal info (Unix)
    signal: Optional[int] = None
    signal_name: Optional[str] = None

    # Exception info (Windows)
    exception_code: Optional[int] = None
    exception_name: Optional[str] = None


@dataclass
class RootCauseAnalysis:
    """Root cause analysis of a crash."""
    crash_type: CrashType
    vulnerable_function: Optional[str]
    vulnerability_class: str
    description: str
    confidence: float
    contributing_factors: List[str] = field(default_factory=list)


@dataclass
class PrimitiveAnalysis:
    """Analysis of available exploit primitives."""
    primitives: List[ExploitPrimitive]
    controlled_registers: List[str]
    controlled_memory: List[Tuple[int, int]]  # (address, size)
    constraints: List[str]
    confidence: float


@dataclass
class CVEMatch:
    """A matching CVE."""
    cve_id: str
    description: str
    similarity_score: float
    affected_product: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class BypassTechnique:
    """Technique to bypass a security mitigation."""
    mitigation: str
    technique: str
    description: str
    difficulty: str  # easy, medium, hard
    requirements: List[str] = field(default_factory=list)


@dataclass
class ExploitPath:
    """Path from crash to exploitation."""
    steps: List[str]
    required_primitives: List[ExploitPrimitive]
    bypasses_needed: List[str]
    estimated_difficulty: str
    poc_skeleton: Optional[str] = None


@dataclass
class CrashAnalysisResult:
    """Complete crash analysis result."""
    crash_id: str
    crash_context: CrashContext

    # Analysis
    root_cause: RootCauseAnalysis
    exploitability: ExploitabilityScore
    primitive_analysis: PrimitiveAnalysis

    # Exploitation guidance
    exploit_path: Optional[ExploitPath]
    bypass_techniques: List[BypassTechnique]
    similar_cves: List[CVEMatch]

    # AI reasoning
    reasoning: str
    confidence: float

    # Metadata
    analysis_time_sec: float
    analyzed_at: datetime = field(default_factory=datetime.utcnow)


# =============================================================================
# Crash Classification
# =============================================================================

class CrashClassifier:
    """Classify crash types based on crash context."""

    # Signal to crash type mapping (Unix)
    SIGNAL_MAP = {
        11: CrashType.SEGFAULT,  # SIGSEGV
        6: CrashType.ABORT,      # SIGABRT
        8: CrashType.DIV_ZERO,   # SIGFPE
        4: CrashType.UNKNOWN,    # SIGILL
        7: CrashType.UNKNOWN,    # SIGBUS
    }

    # Exception code to crash type mapping (Windows)
    EXCEPTION_MAP = {
        0xC0000005: CrashType.SEGFAULT,      # ACCESS_VIOLATION
        0xC0000094: CrashType.DIV_ZERO,      # INTEGER_DIVIDE_BY_ZERO
        0xC00000FD: CrashType.STACK_OVERFLOW, # STACK_OVERFLOW
        0xC0000374: CrashType.HEAP_OVERFLOW,  # HEAP_CORRUPTION
        0x80000003: CrashType.UNKNOWN,        # BREAKPOINT
    }

    @classmethod
    def classify(cls, context: CrashContext, profile: Optional[BinaryProfile] = None) -> CrashType:
        """Classify the crash type."""
        # Check signal/exception
        if context.signal:
            crash_type = cls.SIGNAL_MAP.get(context.signal, CrashType.UNKNOWN)
        elif context.exception_code:
            crash_type = cls.EXCEPTION_MAP.get(context.exception_code, CrashType.UNKNOWN)
        else:
            crash_type = CrashType.UNKNOWN

        # Refine based on context
        if crash_type == CrashType.SEGFAULT:
            crash_type = cls._refine_segfault(context)

        return crash_type

    @classmethod
    def _refine_segfault(cls, context: CrashContext) -> CrashType:
        """Refine SEGFAULT into more specific type."""
        # Check if it's a stack-based issue
        stack_regions = [r for r in context.memory_map if r.is_stack]
        if stack_regions:
            stack = stack_regions[0]
            if context.access_address:
                # Check if accessing beyond stack
                if context.access_address < stack.start:
                    return CrashType.STACK_OVERFLOW
                # Check if it looks like a canary check
                if context.crash_instruction and "__stack_chk_fail" in context.crash_instruction:
                    return CrashType.STACK_OVERFLOW

        # Check for heap issues
        heap_regions = [r for r in context.memory_map if r.is_heap]
        if heap_regions and context.access_address:
            for heap in heap_regions:
                if heap.start <= context.access_address <= heap.end:
                    # Accessing heap - could be use-after-free or overflow
                    return CrashType.HEAP_OVERFLOW

        # Check for NULL pointer
        if context.access_address and context.access_address < 0x1000:
            return CrashType.NULL_DEREF

        return CrashType.SEGFAULT


# =============================================================================
# Exploitability Analyzer
# =============================================================================

class ExploitabilityAnalyzer:
    """Analyze crash exploitability."""

    def __init__(self):
        self.ai_client = BinaryAIClient()

    def analyze_primitives(
        self,
        context: CrashContext,
        profile: Optional[BinaryProfile] = None,
    ) -> PrimitiveAnalysis:
        """Analyze what exploit primitives are available."""
        primitives = []
        controlled_registers = []
        controlled_memory = []
        constraints = []

        # Check controlled registers
        if context.registers:
            # Check instruction pointer control
            ip_regs = ['rip', 'eip', 'pc']
            for reg in ip_regs:
                val = context.registers.get(reg)
                if val and self._looks_controlled(val, context.input_data):
                    primitives.append(ExploitPrimitive.CONTROLLED_JUMP)
                    controlled_registers.append(reg)

            # Check stack pointer
            sp_regs = ['rsp', 'esp', 'sp']
            for reg in sp_regs:
                val = context.registers.get(reg)
                if val and self._looks_controlled(val, context.input_data):
                    primitives.append(ExploitPrimitive.STACK_PIVOT)
                    controlled_registers.append(reg)

            # Check other registers for controlled values
            for reg, val in context.registers.registers.items():
                if val and self._looks_controlled(val, context.input_data):
                    if reg not in controlled_registers:
                        controlled_registers.append(reg)

        # Check for arbitrary read/write based on crash type
        if context.access_type == AccessType.WRITE:
            if context.access_address and self._looks_controlled(context.access_address, context.input_data):
                primitives.append(ExploitPrimitive.ARBITRARY_WRITE)
        elif context.access_type == AccessType.READ:
            if context.access_address and self._looks_controlled(context.access_address, context.input_data):
                primitives.append(ExploitPrimitive.ARBITRARY_READ)

        # Check constraints from protections
        if profile and profile.protections:
            if profile.protections.dep_nx:
                constraints.append("DEP/NX enabled - need ROP/JOP")
            if profile.protections.aslr:
                constraints.append("ASLR enabled - need info leak")
            if profile.protections.stack_canary:
                constraints.append("Stack canary - need leak or bypass")
            if profile.protections.cfi:
                constraints.append("CFI enabled - limited control flow")

        # Calculate confidence based on findings
        confidence = 0.5
        if primitives:
            confidence += 0.1 * len(primitives)
        if controlled_registers:
            confidence += 0.05 * len(controlled_registers)
        confidence = min(confidence, 0.95)

        return PrimitiveAnalysis(
            primitives=primitives,
            controlled_registers=controlled_registers,
            controlled_memory=controlled_memory,
            constraints=constraints,
            confidence=confidence,
        )

    def _looks_controlled(self, value: int, input_data: bytes) -> bool:
        """Check if a value looks like it came from input."""
        if not input_data:
            return False

        # Check if value appears in input
        for width in [1, 2, 4, 8]:
            try:
                packed = struct.pack("<Q", value)[:width]
                if packed in input_data:
                    return True
                # Also check big endian
                packed = struct.pack(">Q", value)[:width]
                if packed in input_data:
                    return True
            except struct.error:
                continue

        # Check for ASCII representation
        try:
            ascii_val = hex(value)[2:].encode()
            if ascii_val in input_data:
                return True
        except:
            pass

        return False

    def calculate_exploitability(
        self,
        context: CrashContext,
        primitive_analysis: PrimitiveAnalysis,
        profile: Optional[BinaryProfile] = None,
    ) -> ExploitabilityScore:
        """Calculate overall exploitability score."""
        # Start with UNKNOWN
        score = ExploitabilityScore.UNKNOWN

        # High confidence exploitable conditions
        if ExploitPrimitive.CONTROLLED_JUMP in primitive_analysis.primitives:
            score = ExploitabilityScore.EXPLOITABLE
        elif ExploitPrimitive.ARBITRARY_WRITE in primitive_analysis.primitives:
            score = ExploitabilityScore.EXPLOITABLE
        elif ExploitPrimitive.CONTROLLED_CALL in primitive_analysis.primitives:
            score = ExploitabilityScore.EXPLOITABLE

        # Medium confidence
        elif ExploitPrimitive.STACK_PIVOT in primitive_analysis.primitives:
            score = ExploitabilityScore.PROBABLY_EXPLOITABLE
        elif len(primitive_analysis.controlled_registers) >= 3:
            score = ExploitabilityScore.PROBABLY_EXPLOITABLE
        elif ExploitPrimitive.ARBITRARY_READ in primitive_analysis.primitives:
            score = ExploitabilityScore.PROBABLY_EXPLOITABLE

        # Low confidence
        elif primitive_analysis.primitives:
            score = ExploitabilityScore.PROBABLY_NOT

        # NULL dereference is usually not exploitable
        crash_type = CrashClassifier.classify(context, profile)
        if crash_type == CrashType.NULL_DEREF:
            if score == ExploitabilityScore.UNKNOWN:
                score = ExploitabilityScore.NOT_EXPLOITABLE

        # Consider mitigations
        if profile and profile.protections:
            if profile.protections.cfi and score == ExploitabilityScore.EXPLOITABLE:
                # CFI makes exploitation harder
                score = ExploitabilityScore.PROBABLY_EXPLOITABLE

        return score


# =============================================================================
# Crash Triage Service
# =============================================================================

class CrashTriageService:
    """AI-powered crash triage and analysis."""

    def __init__(self):
        self.ai_client = BinaryAIClient()
        self.classifier = CrashClassifier()
        self.exploitability_analyzer = ExploitabilityAnalyzer()

    async def triage(
        self,
        context: CrashContext,
        profile: Optional[BinaryProfile] = None,
    ) -> CrashAnalysisResult:
        """Perform complete crash triage and analysis."""
        import time
        start_time = time.time()

        # Classify crash type
        crash_type = self.classifier.classify(context, profile)

        # Analyze primitives
        primitive_analysis = self.exploitability_analyzer.analyze_primitives(context, profile)

        # Calculate exploitability
        exploitability = self.exploitability_analyzer.calculate_exploitability(
            context, primitive_analysis, profile
        )

        # Generate root cause analysis
        root_cause = self._analyze_root_cause(context, crash_type, profile)

        # Get AI-enhanced analysis
        ai_analysis = await self._ai_analyze(context, profile, crash_type, primitive_analysis)

        # Generate exploit path
        exploit_path = self._generate_exploit_path(
            context, primitive_analysis, profile, ai_analysis
        )

        # Identify bypass techniques
        bypass_techniques = self._identify_bypasses(profile)

        # Find similar CVEs
        similar_cves = await self._find_similar_cves(context, crash_type, profile)

        analysis_time = time.time() - start_time

        # Use AI analysis to refine exploitability if available
        ai_exploitability = ai_analysis.get("exploitability", "").upper()
        if ai_exploitability == "EXPLOITABLE":
            exploitability = ExploitabilityScore.EXPLOITABLE
        elif ai_exploitability == "PROBABLY_EXPLOITABLE":
            exploitability = ExploitabilityScore.PROBABLY_EXPLOITABLE
        elif ai_exploitability == "PROBABLY_NOT":
            exploitability = ExploitabilityScore.PROBABLY_NOT
        elif ai_exploitability == "NOT_EXPLOITABLE":
            exploitability = ExploitabilityScore.NOT_EXPLOITABLE

        # Refine root cause with AI analysis
        if ai_analysis.get("root_cause_refined"):
            root_cause.description = ai_analysis["root_cause_refined"]
            root_cause.confidence = ai_analysis.get("confidence", 0.7)

        # Enhance exploit path with AI suggestions
        if exploit_path and ai_analysis.get("exploitation_steps"):
            ai_steps = ai_analysis["exploitation_steps"]
            if isinstance(ai_steps, list):
                exploit_path.steps = ai_steps
            elif isinstance(ai_steps, str):
                exploit_path.steps = [s.strip() for s in ai_steps.split('\n') if s.strip()]

        # Add AI-suggested bypass techniques
        if ai_analysis.get("bypass_suggestions"):
            ai_bypasses = ai_analysis["bypass_suggestions"]
            if isinstance(ai_bypasses, list):
                for bypass in ai_bypasses:
                    if isinstance(bypass, dict):
                        bypass_techniques.append(BypassTechnique(
                            mitigation=bypass.get("mitigation", "Unknown"),
                            technique=bypass.get("technique", "AI Suggested"),
                            description=bypass.get("description", str(bypass)),
                            difficulty=bypass.get("difficulty", "medium"),
                            requirements=bypass.get("requirements", []),
                        ))
                    elif isinstance(bypass, str):
                        bypass_techniques.append(BypassTechnique(
                            mitigation="Security",
                            technique="AI Suggested",
                            description=bypass,
                            difficulty="medium",
                        ))

        # Use AI PoC approach in exploit path
        if exploit_path and ai_analysis.get("poc_approach"):
            exploit_path.poc_skeleton = self._generate_poc_skeleton(
                context, primitive_analysis, ai_analysis
            )

        return CrashAnalysisResult(
            crash_id=context.crash_id,
            crash_context=context,
            root_cause=root_cause,
            exploitability=exploitability,
            primitive_analysis=primitive_analysis,
            exploit_path=exploit_path,
            bypass_techniques=bypass_techniques,
            similar_cves=similar_cves,
            reasoning=ai_analysis.get("reasoning", "Analysis complete"),
            confidence=ai_analysis.get("confidence", 0.7),
            analysis_time_sec=analysis_time,
        )

    def _analyze_root_cause(
        self,
        context: CrashContext,
        crash_type: CrashType,
        profile: Optional[BinaryProfile],
    ) -> RootCauseAnalysis:
        """Analyze the root cause of the crash."""
        vulnerable_function = None
        if context.stack_trace:
            vulnerable_function = context.stack_trace[0].function_name

        # Map crash type to vulnerability class
        vuln_class_map = {
            CrashType.STACK_OVERFLOW: "CWE-121: Stack-based Buffer Overflow",
            CrashType.HEAP_OVERFLOW: "CWE-122: Heap-based Buffer Overflow",
            CrashType.USE_AFTER_FREE: "CWE-416: Use After Free",
            CrashType.DOUBLE_FREE: "CWE-415: Double Free",
            CrashType.NULL_DEREF: "CWE-476: NULL Pointer Dereference",
            CrashType.FORMAT_STRING: "CWE-134: Format String Vulnerability",
            CrashType.INT_OVERFLOW: "CWE-190: Integer Overflow",
            CrashType.DIV_ZERO: "CWE-369: Divide By Zero",
        }
        vulnerability_class = vuln_class_map.get(crash_type, "CWE-119: Memory Corruption")

        # Generate description
        description = self._generate_root_cause_description(context, crash_type)

        return RootCauseAnalysis(
            crash_type=crash_type,
            vulnerable_function=vulnerable_function,
            vulnerability_class=vulnerability_class,
            description=description,
            confidence=0.7,
        )

    def _generate_root_cause_description(
        self,
        context: CrashContext,
        crash_type: CrashType,
    ) -> str:
        """Generate human-readable root cause description."""
        desc = f"The program crashed with a {crash_type.value}"

        if context.crash_address:
            desc += f" at address {hex(context.crash_address)}"

        if context.access_address:
            desc += f" while attempting to {context.access_type.value} memory at {hex(context.access_address)}"

        if context.stack_trace and context.stack_trace[0].function_name:
            desc += f". The crash occurred in function '{context.stack_trace[0].function_name}'"

        return desc + "."

    async def _ai_analyze(
        self,
        context: CrashContext,
        profile: Optional[BinaryProfile],
        crash_type: CrashType,
        primitive_analysis: PrimitiveAnalysis,
    ) -> Dict[str, Any]:
        """Get AI-enhanced crash analysis."""
        prompt = f"""Analyze this crash and provide exploitation guidance.

Crash Information:
- Type: {crash_type.value}
- Address: {hex(context.crash_address)}
- Instruction: {context.crash_instruction}
- Access: {context.access_type.value} at {hex(context.access_address) if context.access_address else 'N/A'}

Register State:
{chr(10).join(f'  {k}: {hex(v)}' for k, v in context.registers.registers.items()) if context.registers else 'N/A'}

Stack Trace:
{chr(10).join(f'  {i}: {f.function_name or hex(f.address)}' for i, f in enumerate(context.stack_trace[:10])) if context.stack_trace else 'N/A'}

Primitives Detected:
{chr(10).join(f'  - {p.value}' for p in primitive_analysis.primitives)}

Controlled Registers: {primitive_analysis.controlled_registers}

Input Size: {context.input_size} bytes

{"Binary Protections:" if profile else ""}
{f"- ASLR: {profile.protections.aslr}" if profile else ""}
{f"- DEP/NX: {profile.protections.dep_nx}" if profile else ""}
{f"- Stack Canary: {profile.protections.stack_canary}" if profile else ""}
{f"- PIE: {profile.protections.pie}" if profile else ""}

Provide:
1. exploitability: EXPLOITABLE, PROBABLY_EXPLOITABLE, PROBABLY_NOT, or NOT_EXPLOITABLE
2. root_cause_refined: More specific root cause analysis
3. exploitation_steps: Step-by-step exploitation approach
4. bypass_suggestions: How to bypass each mitigation
5. similar_vulns: Similar vulnerability patterns or CVEs
6. poc_approach: High-level PoC approach
7. reasoning: Your analysis reasoning
8. confidence: 0-1

Respond in JSON format."""

        try:
            response = await self.ai_client.generate(prompt)
            if "error" not in response:
                return response
        except Exception as e:
            logger.warning(f"AI analysis failed: {e}")

        return {"reasoning": "AI analysis unavailable", "confidence": 0.5}

    def _generate_exploit_path(
        self,
        context: CrashContext,
        primitive_analysis: PrimitiveAnalysis,
        profile: Optional[BinaryProfile],
        ai_analysis: Dict[str, Any],
    ) -> Optional[ExploitPath]:
        """Generate exploitation path."""
        if not primitive_analysis.primitives:
            return None

        steps = []
        required_primitives = []
        bypasses_needed = []

        # Determine required bypasses
        if profile and profile.protections:
            if profile.protections.aslr:
                bypasses_needed.append("ASLR")
                steps.append("1. Obtain memory leak to defeat ASLR")
            if profile.protections.dep_nx:
                bypasses_needed.append("DEP/NX")
                steps.append("2. Build ROP chain for code execution")
            if profile.protections.stack_canary:
                bypasses_needed.append("Stack Canary")
                steps.append("3. Leak or brute-force stack canary")

        # Determine exploitation approach based on primitives
        if ExploitPrimitive.CONTROLLED_JUMP in primitive_analysis.primitives:
            required_primitives.append(ExploitPrimitive.CONTROLLED_JUMP)
            steps.append("4. Redirect execution to controlled address")
            if profile and profile.protections.dep_nx:
                steps.append("5. Execute ROP chain to call system/execve")
            else:
                steps.append("5. Execute shellcode at controlled location")

        elif ExploitPrimitive.ARBITRARY_WRITE in primitive_analysis.primitives:
            required_primitives.append(ExploitPrimitive.ARBITRARY_WRITE)
            steps.append("4. Overwrite GOT/function pointer")
            steps.append("5. Trigger call to hijacked pointer")

        # Get difficulty estimate
        difficulty = "hard"
        if not bypasses_needed:
            difficulty = "easy"
        elif len(bypasses_needed) == 1:
            difficulty = "medium"

        # Generate PoC skeleton
        poc_skeleton = self._generate_poc_skeleton(context, primitive_analysis, ai_analysis)

        return ExploitPath(
            steps=steps if steps else ["Analysis required - insufficient primitives"],
            required_primitives=required_primitives,
            bypasses_needed=bypasses_needed,
            estimated_difficulty=difficulty,
            poc_skeleton=poc_skeleton,
        )

    def _generate_poc_skeleton(
        self,
        context: CrashContext,
        primitive_analysis: PrimitiveAnalysis,
        ai_analysis: Dict[str, Any],
    ) -> str:
        """Generate a PoC exploit skeleton with AI-guided exploitation steps."""
        # Get AI-suggested exploitation approach
        poc_approach = ai_analysis.get("poc_approach", "")
        exploitation_steps = ai_analysis.get("exploitation_steps", [])
        bypass_suggestions = ai_analysis.get("bypass_suggestions", [])

        # Format exploitation steps
        if isinstance(exploitation_steps, list):
            steps_code = "\n".join(f"    # Step {i+1}: {step}" for i, step in enumerate(exploitation_steps))
        elif isinstance(exploitation_steps, str):
            steps_code = "\n".join(f"    # {line}" for line in exploitation_steps.split('\n') if line.strip())
        else:
            # Generate default steps based on crash type
            crash_type = CrashClassifier.classify(context)
            if crash_type == CrashType.STACK_OVERFLOW:
                steps_code = """    # Step 1: Calculate offset to return address using cyclic pattern
    # Step 2: Find ROP gadgets or prepare shellcode
    # Step 3: Build payload: padding + return_address/ROP_chain + shellcode
    # Step 4: Test exploit against target"""
            elif crash_type == CrashType.HEAP_OVERFLOW:
                steps_code = """    # Step 1: Trigger heap allocation with controlled size
    # Step 2: Overflow into next chunk's metadata
    # Step 3: Trigger free() or reallocation to exploit corrupted metadata
    # Step 4: Achieve arbitrary write or code execution"""
            elif crash_type == CrashType.USE_AFTER_FREE:
                steps_code = """    # Step 1: Trigger object allocation and save reference
    # Step 2: Free the object
    # Step 3: Reallocate with controlled data in same location
    # Step 4: Trigger use of dangling pointer"""
            elif crash_type == CrashType.FORMAT_STRING:
                steps_code = """    # Step 1: Find format string offset on stack
    # Step 2: Use %n to write arbitrary values
    # Step 3: Overwrite GOT entry or return address
    # Step 4: Redirect control flow to shellcode"""
            else:
                steps_code = """    # Step 1: Analyze crash dump for controlled data
    # Step 2: Identify exploit primitive (write, jump, leak)
    # Step 3: Construct payload to exploit primitive
    # Step 4: Test and refine exploit"""

        # Format bypass suggestions
        if isinstance(bypass_suggestions, list):
            bypass_code = "\n".join(f"    # Bypass: {b if isinstance(b, str) else b.get('description', str(b))}"
                                    for b in bypass_suggestions[:5])
        else:
            bypass_code = ""

        # Determine payload modification based on primitives
        payload_code = ""
        if ExploitPrimitive.CONTROLLED_JUMP in primitive_analysis.primitives:
            payload_code = f'''
    # Control flow hijack detected - modify return address/function pointer
    offset = {primitive_analysis.control_offset if hasattr(primitive_analysis, 'control_offset') else 'CALCULATE_OFFSET'}
    target = 0xdeadbeef  # Replace with: ROP gadget, shellcode, or win function address

    # Modify payload at offset
    payload[offset:offset+8] = p64(target)

    # Alternative: Add ROP chain
    # rop_chain = p64(pop_rdi) + p64(binsh) + p64(system)
    # payload[offset:offset+len(rop_chain)] = rop_chain
'''
        elif ExploitPrimitive.ARBITRARY_WRITE in primitive_analysis.primitives:
            payload_code = '''
    # Arbitrary write detected - overwrite target location
    what = 0x4141414141414141  # Value to write (e.g., shellcode address)
    where = 0x601000  # Target address (e.g., GOT entry at .got.plt)

    # Construct write primitive (format string example):
    # payload = f"%{what & 0xFFFF}c%7$hn".encode() + p64(where)

    # Or for heap overflow:
    # payload += p64(where) + p64(what)  # Overwrite fd/bk pointers
'''
        elif ExploitPrimitive.STACK_PIVOT in primitive_analysis.primitives:
            payload_code = '''
    # Stack pivot possible - redirect stack to controlled buffer
    pivot_gadget = 0x400500  # Find with: ROPgadget --binary target | grep "xchg.*rsp"
    fake_stack = 0x601800  # Address of controlled buffer (e.g., .bss + offset)

    # Build fake stack with ROP chain
    fake_stack_data = p64(pop_rdi) + p64(binsh) + p64(system)

    # Trigger pivot: overwrite return address with pivot gadget
    offset = {primitive_analysis.control_offset if hasattr(primitive_analysis, 'control_offset') else 'CALCULATE_OFFSET'}
    payload[offset:offset+8] = p64(pivot_gadget)
    payload[offset+8:offset+16] = p64(fake_stack)
'''

        # If no specific primitive detected, generate based on crash type
        if not payload_code:
            crash_type = CrashClassifier.classify(context)
            if crash_type == CrashType.STACK_OVERFLOW:
                payload_code = '''
    # Stack-based buffer overflow exploitation
    offset = len(payload)  # Calculate using cyclic pattern
    return_address = 0xdeadbeef  # Replace with target address

    # Option 1: Direct return to shellcode
    # payload += b"\\x90" * 16  # NOP sled
    # payload += SHELLCODE  # x86_64 execve shellcode
    # return_address = ADDRESS_OF_SHELLCODE

    # Option 2: ROP chain (if NX enabled)
    rop_chain = b"".join([
        p64(0x400500),  # pop rdi; ret
        p64(0x601000),  # address of "/bin/sh"
        p64(0x400300),  # system@plt
    ])
    payload += rop_chain
'''
            elif crash_type == CrashType.HEAP_OVERFLOW:
                payload_code = '''
    # Heap-based buffer overflow exploitation
    # Overflow into next chunk's size field
    chunk_size = 0x21  # Target chunk size
    fake_size = 0x20  # Fake size to trigger consolidation

    # Overwrite next chunk metadata
    payload += p64(fake_size)  # Overwrite size field
    payload += p64(0x601000)  # fd: forward pointer
    payload += p64(0x601008)  # bk: backward pointer

    # Trigger malloc/free to exploit corrupted metadata
'''
            else:
                payload_code = '''
    # Generic payload modification
    # Analyze crash to determine:
    # 1. Offset to controlled data
    # 2. Type of corruption (overwrite, format string, etc.)
    # 3. Target addresses (GOT, return address, function pointer)

    # Example: Simple overwrite
    target_offset = len(payload) // 2
    target_value = 0x41424344
    payload[target_offset:target_offset+4] = p32(target_value)
'''

        skeleton = f'''#!/usr/bin/env python3
"""
Exploit PoC for crash at {hex(context.crash_address)}
Generated by Agentic Binary Fuzzer

Crash Type: {CrashClassifier.classify(context).value}
Primitives: {", ".join(p.value for p in primitive_analysis.primitives)}
Controlled Registers: {", ".join(primitive_analysis.controlled_registers)}

AI Analysis:
{poc_approach if poc_approach else "No AI approach available"}
"""

import struct
import sys

# Original crashing input (first 200 bytes shown)
CRASH_INPUT = bytes.fromhex("{context.input_data[:200].hex() if context.input_data else ''}")

# Helper functions
def p64(x): return struct.pack("<Q", x)
def p32(x): return struct.pack("<I", x)
def p16(x): return struct.pack("<H", x)
def p8(x): return struct.pack("<B", x)

# Unpack helpers
def u64(x): return struct.unpack("<Q", x.ljust(8, b"\\x00"))[0]
def u32(x): return struct.unpack("<I", x.ljust(4, b"\\x00"))[0]

def exploit():
    """
    Exploitation Strategy:
{steps_code}

    Required Bypasses:
{bypass_code if bypass_code else "    # None identified"}
    """
    payload = bytearray(CRASH_INPUT)

    # Constraints to work around:
    # {", ".join(primitive_analysis.constraints) if primitive_analysis.constraints else "None identified"}
{payload_code if payload_code else "    # TODO: Add payload construction"}

    return bytes(payload)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--raw":
        # Output raw payload for piping
        sys.stdout.buffer.write(exploit())
    else:
        payload = exploit()
        print(f"[*] Payload length: {{len(payload)}} bytes")
        print(f"[*] Crash address: {hex(context.crash_address)}")
        print(f"[*] Controlled registers: {', '.join(primitive_analysis.controlled_registers)}")

        # Write to file
        with open("exploit_payload.bin", "wb") as f:
            f.write(payload)
        print("[+] Payload written to exploit_payload.bin")

        # Also show hex dump of first 64 bytes
        print("\\n[*] Payload preview (first 64 bytes):")
        for i in range(0, min(64, len(payload)), 16):
            hex_part = " ".join(f"{{b:02x}}" for b in payload[i:i+16])
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[i:i+16])
            print(f"    {{i:04x}}: {{hex_part:<48}} {{ascii_part}}")

if __name__ == "__main__":
    main()
'''
        return skeleton

    def _identify_bypasses(
        self,
        profile: Optional[BinaryProfile],
    ) -> List[BypassTechnique]:
        """Identify techniques to bypass security mitigations."""
        bypasses = []

        if not profile:
            return bypasses

        if profile.protections.aslr:
            bypasses.append(BypassTechnique(
                mitigation="ASLR",
                technique="Information Leak",
                description="Leak a pointer to calculate base addresses",
                difficulty="medium",
                requirements=["Arbitrary read primitive", "Output channel"],
            ))
            bypasses.append(BypassTechnique(
                mitigation="ASLR",
                technique="Brute Force",
                description="Brute force address space (32-bit only)",
                difficulty="easy" if profile.bits == 32 else "hard",
                requirements=["Crash tolerance", "Fast restart"],
            ))

        if profile.protections.dep_nx:
            bypasses.append(BypassTechnique(
                mitigation="DEP/NX",
                technique="ROP Chain",
                description="Chain return-oriented programming gadgets",
                difficulty="medium",
                requirements=["Stack control", "Gadget availability"],
            ))
            bypasses.append(BypassTechnique(
                mitigation="DEP/NX",
                technique="JIT Spray",
                description="Use JIT compiler to create executable memory",
                difficulty="hard",
                requirements=["JIT engine present", "Predictable JIT output"],
            ))

        if profile.protections.stack_canary:
            bypasses.append(BypassTechnique(
                mitigation="Stack Canary",
                technique="Canary Leak",
                description="Leak canary value via format string or other read",
                difficulty="medium",
                requirements=["Read primitive", "Canary in reachable memory"],
            ))
            bypasses.append(BypassTechnique(
                mitigation="Stack Canary",
                technique="Overwrite Saved Frame",
                description="Overwrite non-canary-protected data",
                difficulty="medium",
                requirements=["Specific vulnerability location"],
            ))

        return bypasses

    async def _find_similar_cves(
        self,
        context: CrashContext,
        crash_type: CrashType,
        profile: Optional[BinaryProfile],
    ) -> List[CVEMatch]:
        """Find similar CVEs using NVD API and heuristics."""
        similar = []

        # Build search keywords based on crash type
        cwe_map = {
            CrashType.STACK_OVERFLOW: ("CWE-121", "stack buffer overflow"),
            CrashType.HEAP_OVERFLOW: ("CWE-122", "heap buffer overflow"),
            CrashType.USE_AFTER_FREE: ("CWE-416", "use after free"),
            CrashType.DOUBLE_FREE: ("CWE-415", "double free"),
            CrashType.NULL_DEREF: ("CWE-476", "null pointer dereference"),
            CrashType.FORMAT_STRING: ("CWE-134", "format string"),
            CrashType.INT_OVERFLOW: ("CWE-190", "integer overflow"),
        }

        cwe_id, search_term = cwe_map.get(crash_type, ("CWE-119", "memory corruption"))

        # Try NVD API lookup
        try:
            nvd_results = await self._query_nvd_api(cwe_id, search_term, profile)
            similar.extend(nvd_results)
        except Exception as e:
            logger.debug(f"NVD API query failed: {e}")

        # If no results or API failed, use AI to suggest similar vulnerabilities
        if not similar and self.ai_client:
            try:
                ai_cves = await self._ai_find_similar_vulns(context, crash_type, profile)
                similar.extend(ai_cves)
            except Exception as e:
                logger.debug(f"AI CVE lookup failed: {e}")

        # Fallback to heuristic patterns if nothing found
        if not similar:
            similar = self._get_heuristic_cve_patterns(crash_type)

        return similar[:10]  # Limit to 10 results

    async def _query_nvd_api(
        self,
        cwe_id: str,
        search_term: str,
        profile: Optional[BinaryProfile],
    ) -> List[CVEMatch]:
        """Query the NVD API for similar CVEs."""
        import aiohttp

        matches = []

        # NVD API endpoint
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Build query parameters
        params = {
            "cweId": cwe_id,
            "resultsPerPage": 20,
        }

        # Add keyword search if we have binary name
        if profile and profile.file_path:
            import os
            binary_name = os.path.basename(profile.file_path)
            # Don't search for generic names
            if binary_name and len(binary_name) > 3 and binary_name not in ["a.out", "test", "main"]:
                params["keywordSearch"] = binary_name

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    base_url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"Accept": "application/json"}
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for vuln in data.get("vulnerabilities", [])[:10]:
                            cve = vuln.get("cve", {})
                            cve_id = cve.get("id", "")

                            # Get description
                            descriptions = cve.get("descriptions", [])
                            description = ""
                            for desc in descriptions:
                                if desc.get("lang") == "en":
                                    description = desc.get("value", "")[:200]
                                    break

                            # Get CVSS score
                            cvss_score = None
                            metrics = cve.get("metrics", {})
                            if "cvssMetricV31" in metrics:
                                cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore")
                            elif "cvssMetricV30" in metrics:
                                cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore")
                            elif "cvssMetricV2" in metrics:
                                cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore")

                            # Calculate similarity based on CWE match
                            similarity = 0.7 if cwe_id in str(cve.get("weaknesses", [])) else 0.5

                            if cve_id:
                                matches.append(CVEMatch(
                                    cve_id=cve_id,
                                    description=description,
                                    similarity_score=similarity,
                                    cvss_score=cvss_score,
                                ))

                    elif response.status == 403:
                        logger.debug("NVD API rate limited")
                    else:
                        logger.debug(f"NVD API returned status {response.status}")

        except aiohttp.ClientError as e:
            logger.debug(f"NVD API connection error: {e}")
        except Exception as e:
            logger.debug(f"NVD API error: {e}")

        return matches

    async def _ai_find_similar_vulns(
        self,
        context: CrashContext,
        crash_type: CrashType,
        profile: Optional[BinaryProfile],
    ) -> List[CVEMatch]:
        """Use AI to find similar vulnerabilities."""
        prompt = f"""Find real CVEs similar to this crash:

Crash Type: {crash_type.value}
Crash Address: {hex(context.crash_address)}
Vulnerable Function: {context.stack_trace[0].function_name if context.stack_trace else 'Unknown'}

Provide 3-5 real, specific CVE IDs that match this pattern.
Response format (JSON array):
[
    {{"cve_id": "CVE-YYYY-NNNNN", "description": "Brief description", "similarity": 0.7}},
    ...
]

Only include REAL CVEs, not placeholders."""

        try:
            response = await self.ai_client.generate(prompt)
            if isinstance(response, list):
                return [
                    CVEMatch(
                        cve_id=item.get("cve_id", ""),
                        description=item.get("description", ""),
                        similarity_score=item.get("similarity", 0.5),
                    )
                    for item in response
                    if item.get("cve_id", "").startswith("CVE-")
                ]
            elif isinstance(response, dict) and "cves" in response:
                return [
                    CVEMatch(
                        cve_id=item.get("cve_id", ""),
                        description=item.get("description", ""),
                        similarity_score=item.get("similarity", 0.5),
                    )
                    for item in response["cves"]
                    if item.get("cve_id", "").startswith("CVE-")
                ]
        except Exception as e:
            logger.debug(f"AI CVE lookup failed: {e}")

        return []

    def _get_heuristic_cve_patterns(self, crash_type: CrashType) -> List[CVEMatch]:
        """Return well-known CVE examples for each crash type as reference."""
        # These are real, well-documented CVEs that serve as examples
        patterns = {
            CrashType.STACK_OVERFLOW: [
                CVEMatch("CVE-2021-3156", "Sudo heap-based buffer overflow (Baron Samedit)", 0.6, cvss_score=7.8),
                CVEMatch("CVE-2020-1350", "Windows DNS Server RCE (SIGRed)", 0.5, cvss_score=10.0),
            ],
            CrashType.HEAP_OVERFLOW: [
                CVEMatch("CVE-2021-22555", "Linux Netfilter heap out-of-bounds write", 0.6, cvss_score=7.8),
                CVEMatch("CVE-2022-0847", "Linux Dirty Pipe arbitrary file overwrite", 0.5, cvss_score=7.8),
            ],
            CrashType.USE_AFTER_FREE: [
                CVEMatch("CVE-2021-4034", "Polkit pkexec local privilege escalation", 0.7, cvss_score=7.8),
                CVEMatch("CVE-2022-2588", "Linux route4_change UAF", 0.6, cvss_score=7.8),
            ],
            CrashType.FORMAT_STRING: [
                CVEMatch("CVE-2012-0809", "Sudo format string vulnerability", 0.8, cvss_score=7.2),
            ],
            CrashType.INT_OVERFLOW: [
                CVEMatch("CVE-2021-43527", "NSS integer overflow", 0.6, cvss_score=9.8),
            ],
        }
        return patterns.get(crash_type, [])


# =============================================================================
# Crash Deduplication
# =============================================================================

class CrashDeduplicator:
    """Deduplicate crashes based on various heuristics."""

    def __init__(self):
        self.seen_hashes: Dict[str, str] = {}  # hash -> crash_id

    def get_crash_hash(self, context: CrashContext, depth: int = 5) -> str:
        """Generate a hash for crash deduplication."""
        # Use stack trace for deduplication
        stack_key = []

        for frame in context.stack_trace[:depth]:
            if frame.function_name:
                stack_key.append(frame.function_name)
            else:
                # Use relative offset within module
                stack_key.append(f"offset_{frame.offset}")

        # Include crash type indicators
        stack_key.append(str(context.access_type.value))

        if context.signal:
            stack_key.append(f"sig_{context.signal}")
        elif context.exception_code:
            stack_key.append(f"exc_{context.exception_code}")

        key = ":".join(stack_key)
        return hashlib.md5(key.encode()).hexdigest()

    def is_duplicate(self, context: CrashContext) -> Tuple[bool, Optional[str]]:
        """Check if crash is a duplicate."""
        crash_hash = self.get_crash_hash(context)

        if crash_hash in self.seen_hashes:
            return True, self.seen_hashes[crash_hash]

        self.seen_hashes[crash_hash] = context.crash_id
        return False, None

    def get_unique_count(self) -> int:
        """Get count of unique crashes."""
        return len(self.seen_hashes)


# =============================================================================
# Helper Functions
# =============================================================================

async def triage_crash(
    crash_address: int,
    crash_instruction: str,
    registers: Dict[str, int],
    stack_trace: List[Dict[str, Any]],
    input_data: bytes,
    binary_path: Optional[str] = None,
) -> CrashAnalysisResult:
    """Convenience function to triage a crash."""
    from backend.services.binary_analysis_service import BinaryAnalysisService

    # Build crash context
    context = CrashContext(
        crash_id=hashlib.md5(f"{crash_address}:{input_data[:100].hex()}".encode()).hexdigest()[:16],
        timestamp=datetime.utcnow(),
        crash_address=crash_address,
        crash_instruction=crash_instruction,
        access_address=None,
        access_type=AccessType.UNKNOWN,
        registers=RegisterState(registers=registers),
        stack_trace=[
            StackFrame(
                address=f.get("address", 0),
                function_name=f.get("function"),
                offset=f.get("offset", 0),
                module=f.get("module"),
            )
            for f in stack_trace
        ],
        memory_map=[],
        input_data=input_data,
        input_hash=hashlib.md5(input_data).hexdigest(),
        input_size=len(input_data),
    )

    # Get binary profile if available
    profile = None
    if binary_path:
        analysis_service = BinaryAnalysisService()
        profile = await analysis_service.analyze(binary_path, deep_analysis=False, ai_enhance=False)

    # Triage
    service = CrashTriageService()
    return await service.triage(context, profile)
