"""
Binary Fuzzer Utilities

Robust utility functions with proper error handling, validation,
and graceful fallbacks for the agentic binary fuzzer.
"""

import hashlib
import logging
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import asyncio

logger = logging.getLogger(__name__)


# =============================================================================
# Constants and Limits
# =============================================================================

MAX_BINARY_SIZE = 100 * 1024 * 1024  # 100MB max
MAX_GADGET_SEARCH_SIZE = 10 * 1024 * 1024  # 10MB for gadget search
MAX_STRING_EXTRACT = 10000  # Max strings to extract
MAX_FUNCTIONS = 50000  # Max functions to analyze
MIN_BINARY_SIZE = 64  # Minimum valid binary size


# =============================================================================
# Validation Functions
# =============================================================================

def validate_binary_data(data: bytes, context: str = "binary") -> Tuple[bool, str]:
    """
    Validate binary data before processing.

    Returns (is_valid, error_message).
    """
    if data is None:
        return False, f"{context}: data is None"

    if not isinstance(data, bytes):
        return False, f"{context}: expected bytes, got {type(data).__name__}"

    if len(data) < MIN_BINARY_SIZE:
        return False, f"{context}: too small ({len(data)} bytes, min {MIN_BINARY_SIZE})"

    if len(data) > MAX_BINARY_SIZE:
        return False, f"{context}: too large ({len(data)} bytes, max {MAX_BINARY_SIZE})"

    return True, ""


def detect_binary_format(data: bytes) -> Tuple[str, str, bool]:
    """
    Safely detect binary format.

    Returns (file_type, architecture, is_valid).
    """
    if len(data) < 64:
        return "unknown", "unknown", False

    try:
        # ELF
        if data[:4] == b"\x7fELF":
            if len(data) < 20:
                return "ELF", "unknown", False

            elf_class = data[4]  # 1=32bit, 2=64bit
            machine = data[18] if len(data) > 18 else 0

            arch_map = {
                0x03: "x86",
                0x3e: "x64",
                0x28: "arm",
                0xb7: "arm64",
                0xf3: "riscv",
            }
            arch = arch_map.get(machine, f"unknown_0x{machine:02x}")

            if elf_class == 2 and arch == "x86":
                arch = "x64"

            return "ELF", arch, True

        # PE (Windows)
        if data[:2] == b"MZ":
            if len(data) < 64:
                return "PE", "unknown", False

            try:
                pe_offset = struct.unpack_from("<I", data, 60)[0]
                if pe_offset + 6 > len(data):
                    return "PE", "unknown", False

                if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
                    return "PE", "unknown", False

                machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
                arch_map = {
                    0x14c: "x86",
                    0x8664: "x64",
                    0xaa64: "arm64",
                    0x1c0: "arm",
                }
                arch = arch_map.get(machine, f"unknown_0x{machine:04x}")
                return "PE", arch, True
            except struct.error:
                return "PE", "unknown", False

        # Mach-O
        magic = data[:4]
        if magic in [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                     b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"]:
            is_64 = magic in [b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"]
            return "Mach-O", "x64" if is_64 else "x86", True

        # Universal Mach-O
        if data[:4] in [b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"]:
            return "Mach-O-Universal", "multi", True

        return "unknown", "unknown", False

    except Exception as e:
        logger.warning(f"Binary format detection failed: {e}")
        return "unknown", "unknown", False


# =============================================================================
# Safe Extraction Functions
# =============================================================================

def safe_extract_strings(
    data: bytes,
    min_length: int = 4,
    max_strings: int = MAX_STRING_EXTRACT,
) -> List[str]:
    """
    Safely extract printable strings from binary data.
    """
    if not data:
        return []

    strings = []
    current = []

    # Limit search to first 50MB to avoid OOM
    search_data = data[:50 * 1024 * 1024]

    try:
        for byte in search_data:
            if 0x20 <= byte < 0x7f:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                    if len(strings) >= max_strings:
                        break
                current = []

        # Don't forget last string
        if len(current) >= min_length and len(strings) < max_strings:
            strings.append("".join(current))

    except Exception as e:
        logger.warning(f"String extraction failed: {e}")

    return strings


def safe_find_imports(data: bytes, file_type: str) -> List[str]:
    """
    Safely extract imported function names.
    """
    imports = []

    try:
        if file_type == "ELF":
            imports = _extract_elf_imports(data)
        elif file_type == "PE":
            imports = _extract_pe_imports(data)
        else:
            # Fall back to string search for common functions
            imports = _extract_imports_from_strings(data)
    except Exception as e:
        logger.warning(f"Import extraction failed: {e}")
        imports = _extract_imports_from_strings(data)

    return imports[:MAX_FUNCTIONS]


def _extract_elf_imports(data: bytes) -> List[str]:
    """Extract imports from ELF (simplified, robust)."""
    imports = []

    # Look for common libc function names in .dynstr
    common_functions = [
        b"printf", b"scanf", b"strcpy", b"strcat", b"sprintf",
        b"gets", b"puts", b"fgets", b"fread", b"fwrite",
        b"malloc", b"free", b"realloc", b"calloc",
        b"memcpy", b"memmove", b"memset", b"memcmp",
        b"open", b"close", b"read", b"write",
        b"socket", b"connect", b"send", b"recv",
        b"execve", b"system", b"popen", b"fork",
    ]

    for func in common_functions:
        # Look for null-terminated string
        if func + b"\x00" in data:
            imports.append(func.decode())

    return imports


def _extract_pe_imports(data: bytes) -> List[str]:
    """Extract imports from PE (simplified, robust)."""
    # Similar approach - look for common function names
    return _extract_imports_from_strings(data)


def _extract_imports_from_strings(data: bytes) -> List[str]:
    """Fall back to extracting imports from string table."""
    dangerous_funcs = [
        "strcpy", "strcat", "sprintf", "vsprintf", "gets",
        "scanf", "fscanf", "sscanf", "vscanf",
        "memcpy", "memmove", "strncpy", "strncat",
        "printf", "fprintf", "snprintf", "vprintf",
        "malloc", "free", "realloc", "calloc",
        "system", "popen", "execve", "execl", "execv",
        "fork", "vfork", "clone",
        "open", "fopen", "read", "write", "close",
        "socket", "connect", "bind", "listen", "accept",
        "send", "recv", "sendto", "recvfrom",
    ]

    found = []
    for func in dangerous_funcs:
        if func.encode() + b"\x00" in data:
            found.append(func)

    return found


# =============================================================================
# Robust Disassembler (with Capstone fallback)
# =============================================================================

class RobustDisassembler:
    """
    Disassembler with Capstone support and graceful fallback.
    """

    def __init__(self):
        self._capstone_available = False
        self._cs = None
        self._init_capstone()

    def _init_capstone(self):
        """Try to initialize Capstone disassembler."""
        try:
            import capstone
            self._capstone_available = True
            self._capstone = capstone
            logger.info("Capstone disassembler available")
        except ImportError:
            logger.warning("Capstone not available, using basic disassembly")
            self._capstone_available = False

    def disassemble(
        self,
        data: bytes,
        arch: str = "x64",
        base_address: int = 0,
        max_instructions: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Disassemble binary data.

        Returns list of instruction dicts with address, mnemonic, op_str, bytes.
        """
        if not data:
            return []

        # Limit data size
        data = data[:1024]  # Max 1KB per disassembly

        if self._capstone_available:
            return self._disasm_capstone(data, arch, base_address, max_instructions)
        else:
            return self._disasm_basic(data, arch, base_address, max_instructions)

    def _disasm_capstone(
        self,
        data: bytes,
        arch: str,
        base: int,
        max_insns: int,
    ) -> List[Dict[str, Any]]:
        """Disassemble using Capstone."""
        try:
            cs = self._capstone

            # Map architecture
            if arch in ["x64", "amd64"]:
                md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
            elif arch in ["x86", "i386"]:
                md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
            elif arch in ["arm64", "aarch64"]:
                md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
            elif arch == "arm":
                md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
            else:
                # Default to x64
                md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)

            instructions = []
            for insn in md.disasm(data, base):
                instructions.append({
                    "address": insn.address,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": bytes(insn.bytes),
                    "size": insn.size,
                })
                if len(instructions) >= max_insns:
                    break

            return instructions

        except Exception as e:
            logger.warning(f"Capstone disassembly failed: {e}")
            return self._disasm_basic(data, arch, base, max_insns)

    def _disasm_basic(
        self,
        data: bytes,
        arch: str,
        base: int,
        max_insns: int,
    ) -> List[Dict[str, Any]]:
        """Basic disassembly fallback (x86/x64 only)."""
        instructions = []
        i = 0

        # Common x86/x64 opcodes
        opcodes = {
            0xc3: ("ret", "", 1),
            0xc9: ("leave", "", 1),
            0x90: ("nop", "", 1),
            0xcc: ("int3", "", 1),
            0x50: ("push", "rax", 1),
            0x51: ("push", "rcx", 1),
            0x52: ("push", "rdx", 1),
            0x53: ("push", "rbx", 1),
            0x54: ("push", "rsp", 1),
            0x55: ("push", "rbp", 1),
            0x56: ("push", "rsi", 1),
            0x57: ("push", "rdi", 1),
            0x58: ("pop", "rax", 1),
            0x59: ("pop", "rcx", 1),
            0x5a: ("pop", "rdx", 1),
            0x5b: ("pop", "rbx", 1),
            0x5c: ("pop", "rsp", 1),
            0x5d: ("pop", "rbp", 1),
            0x5e: ("pop", "rsi", 1),
            0x5f: ("pop", "rdi", 1),
        }

        while i < len(data) and len(instructions) < max_insns:
            byte = data[i]

            if byte in opcodes:
                mnem, ops, size = opcodes[byte]
                instructions.append({
                    "address": base + i,
                    "mnemonic": mnem,
                    "op_str": ops,
                    "bytes": data[i:i+size],
                    "size": size,
                })
                i += size

            # Two-byte opcodes
            elif byte == 0x0f and i + 1 < len(data):
                next_byte = data[i + 1]
                if next_byte == 0x05:
                    instructions.append({
                        "address": base + i,
                        "mnemonic": "syscall",
                        "op_str": "",
                        "bytes": data[i:i+2],
                        "size": 2,
                    })
                    i += 2
                else:
                    i += 1

            elif byte == 0xff and i + 1 < len(data):
                next_byte = data[i + 1]
                if 0xe0 <= next_byte <= 0xe7:
                    reg = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][next_byte - 0xe0]
                    instructions.append({
                        "address": base + i,
                        "mnemonic": "jmp",
                        "op_str": reg,
                        "bytes": data[i:i+2],
                        "size": 2,
                    })
                    i += 2
                elif 0xd0 <= next_byte <= 0xd7:
                    reg = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][next_byte - 0xd0]
                    instructions.append({
                        "address": base + i,
                        "mnemonic": "call",
                        "op_str": reg,
                        "bytes": data[i:i+2],
                        "size": 2,
                    })
                    i += 2
                else:
                    i += 1
            else:
                # Unknown instruction - skip byte
                i += 1

        return instructions

    def get_instruction_string(self, insn: Dict[str, Any]) -> str:
        """Format instruction as string."""
        if insn.get("op_str"):
            return f"{insn['mnemonic']} {insn['op_str']}"
        return insn["mnemonic"]


# Global disassembler instance
_disassembler = None

def get_disassembler() -> RobustDisassembler:
    """Get global disassembler instance."""
    global _disassembler
    if _disassembler is None:
        _disassembler = RobustDisassembler()
    return _disassembler


# =============================================================================
# AI Client with Fallbacks
# =============================================================================

class RobustAIClient:
    """
    AI client with multiple provider support and graceful fallbacks.
    """

    def __init__(self, timeout: float = 30.0, max_retries: int = 2):
        self.timeout = timeout
        self.max_retries = max_retries
        self._provider = None
        self._client = None
        self._init_provider()

    def _init_provider(self):
        """Initialize best available AI provider (updated for google.genai SDK)."""
        # Try Gemini first (using new google.genai SDK)
        try:
            from backend.core.config import settings
            if hasattr(settings, 'gemini_api_key') and settings.gemini_api_key:
                from google import genai
                self._client = genai.Client(api_key=settings.gemini_api_key)
                self._model = "gemini-3-flash-preview"  # Fast model for fuzzing
                self._provider = "gemini"
                logger.info(f"AI provider: Gemini ({self._model})")
                return
        except ImportError:
            logger.warning("google-genai package not installed")
        except Exception as e:
            logger.warning(f"Gemini init failed: {e}")

        # Try OpenAI
        try:
            from backend.core.config import settings
            if hasattr(settings, 'openai_api_key') and settings.openai_api_key:
                import openai
                openai.api_key = settings.openai_api_key
                self._provider = "openai"
                logger.info("AI provider: OpenAI")
                return
        except Exception as e:
            logger.warning(f"OpenAI init failed: {e}")

        logger.warning("No AI provider available, using heuristics only")
        self._provider = None

    @property
    def is_available(self) -> bool:
        """Check if AI is available."""
        return self._provider is not None

    async def generate(
        self,
        prompt: str,
        json_response: bool = True,
        fallback: Any = None,
    ) -> Dict[str, Any]:
        """
        Generate AI response with retries and fallback.
        """
        if not self.is_available:
            logger.debug("AI not available, using fallback")
            return fallback if fallback is not None else {"error": "AI not available"}

        last_error = None

        for attempt in range(self.max_retries):
            try:
                result = await self._generate_with_timeout(prompt, json_response)
                if result and "error" not in result:
                    return result
                last_error = result.get("error", "Unknown error")
            except asyncio.TimeoutError:
                last_error = "Request timed out"
                logger.warning(f"AI request timeout (attempt {attempt + 1})")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"AI request failed (attempt {attempt + 1}): {e}")

            if attempt < self.max_retries - 1:
                await asyncio.sleep(1.0 * (attempt + 1))  # Backoff

        logger.error(f"AI request failed after {self.max_retries} attempts: {last_error}")
        return fallback if fallback is not None else {"error": last_error}

    async def _generate_with_timeout(
        self,
        prompt: str,
        json_response: bool,
    ) -> Dict[str, Any]:
        """Generate with timeout."""
        return await asyncio.wait_for(
            self._do_generate(prompt, json_response),
            timeout=self.timeout,
        )

    async def _do_generate(
        self,
        prompt: str,
        json_response: bool,
    ) -> Dict[str, Any]:
        """Actually generate response using google.genai SDK."""
        if json_response:
            prompt += "\n\nRespond ONLY with valid JSON."

        if self._provider == "gemini":
            from google.genai import types

            # Use async API with low thinking for fast responses
            response = await self._client.aio.models.generate_content(
                model=self._model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    thinking_config=types.ThinkingConfig(thinking_level="low")
                ),
            )
            text = response.text.strip() if response.text else ""
        elif self._provider == "openai":
            import openai
            response = await openai.ChatCompletion.acreate(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.choices[0].message.content.strip()
        else:
            return {"error": "No provider"}

        if json_response:
            return self._parse_json_response(text)

        return {"text": text}

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        """Safely parse JSON from response."""
        import json
        import re

        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Extract from markdown code block
        patterns = [
            r'```json\s*(.*?)\s*```',
            r'```\s*(.*?)\s*```',
            r'\{.*\}',
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1) if '```' in pattern else match.group(0))
                except json.JSONDecodeError:
                    continue

        return {"error": "Failed to parse JSON", "raw": text[:500]}


# Global AI client
_ai_client = None

def get_ai_client() -> RobustAIClient:
    """Get global AI client instance."""
    global _ai_client
    if _ai_client is None:
        _ai_client = RobustAIClient()
    return _ai_client


# =============================================================================
# Heuristic Fallbacks (when AI unavailable)
# =============================================================================

def heuristic_exploitability_score(
    crash_type: str,
    controlled_registers: List[str],
    crash_address: int,
    access_type: str,
) -> Tuple[str, float, str]:
    """
    Heuristic exploitability assessment when AI unavailable.

    Returns (score, confidence, reasoning).
    """
    score = "unknown"
    confidence = 0.3
    reasons = []

    # Check for obvious exploitable conditions
    if crash_type in ["stack_buffer_overflow", "heap_overflow"]:
        score = "probably_exploitable"
        confidence = 0.7
        reasons.append(f"{crash_type} often leads to code execution")

    if "rip" in controlled_registers or "eip" in controlled_registers:
        score = "exploitable"
        confidence = 0.9
        reasons.append("Instruction pointer is controlled")

    if "rsp" in controlled_registers or "esp" in controlled_registers:
        score = "probably_exploitable"
        confidence = 0.8
        reasons.append("Stack pointer is controlled (stack pivot possible)")

    if access_type == "write" and crash_address < 0x1000:
        score = "probably_exploitable"
        confidence = 0.6
        reasons.append("Write to low address (potential null deref -> arbitrary write)")

    if access_type == "execute":
        score = "exploitable"
        confidence = 0.85
        reasons.append("Attempted execution at controlled address")

    if crash_type == "use_after_free":
        score = "probably_exploitable"
        confidence = 0.75
        reasons.append("UAF can often be converted to arbitrary read/write")

    if crash_type == "format_string":
        score = "exploitable"
        confidence = 0.8
        reasons.append("Format string provides read/write primitives")

    reasoning = "; ".join(reasons) if reasons else "Insufficient information for assessment"

    return score, confidence, reasoning


def heuristic_attack_surface(
    dangerous_functions: List[str],
    input_handlers: List[str],
    protections: Dict[str, bool],
) -> Tuple[float, List[str]]:
    """
    Heuristic attack surface calculation.

    Returns (score 0-1, list of factors).
    """
    score = 0.0
    factors = []

    # Dangerous functions
    high_risk = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
    medium_risk = ["memcpy", "memmove", "strncpy", "snprintf"]

    high_count = sum(1 for f in dangerous_functions if f in high_risk)
    med_count = sum(1 for f in dangerous_functions if f in medium_risk)

    if high_count > 0:
        score += min(high_count * 0.1, 0.4)
        factors.append(f"{high_count} high-risk functions")

    if med_count > 0:
        score += min(med_count * 0.03, 0.15)
        factors.append(f"{med_count} medium-risk functions")

    # Input handlers
    if input_handlers:
        score += min(len(input_handlers) * 0.02, 0.2)
        factors.append(f"{len(input_handlers)} input handlers")

    # Missing protections
    if not protections.get("stack_canary", True):
        score += 0.15
        factors.append("No stack canary")

    if not protections.get("pie", True):
        score += 0.1
        factors.append("No PIE")

    if not protections.get("relro", True):
        score += 0.05
        factors.append("No RELRO")

    return min(score, 1.0), factors


def heuristic_strategy_recommendation(
    file_type: str,
    arch: str,
    attack_surface: float,
    has_network: bool = False,
    has_file_io: bool = False,
) -> Tuple[str, str]:
    """
    Heuristic strategy recommendation.

    Returns (strategy, reasoning).
    """
    if has_network:
        return "protocol_fuzzing", "Binary has network functions, use protocol-aware fuzzing"

    if attack_surface > 0.6:
        return "coverage_guided", "High attack surface, broad coverage-guided fuzzing recommended"

    if attack_surface < 0.2:
        return "directed_fuzzing", "Low attack surface, focus on specific high-value targets"

    if file_type == "ELF" and arch == "x64":
        return "hybrid", "Standard Linux binary, hybrid fuzzing (AFL + concolic) recommended"

    return "coverage_guided", "Default coverage-guided approach"


# =============================================================================
# Safe Wrapper Functions
# =============================================================================

async def safe_async_call(
    coro,
    timeout: float = 30.0,
    default: Any = None,
    error_msg: str = "Async call failed",
) -> Any:
    """Safely execute async coroutine with timeout and error handling."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        logger.warning(f"{error_msg}: timeout after {timeout}s")
        return default
    except Exception as e:
        logger.warning(f"{error_msg}: {e}")
        return default


def safe_dict_get(d: Optional[Dict], *keys, default: Any = None) -> Any:
    """Safely get nested dictionary value."""
    if d is None:
        return default

    result = d
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        else:
            return default
        if result is None:
            return default

    return result


def safe_list_get(lst: Optional[List], index: int, default: Any = None) -> Any:
    """Safely get list item by index."""
    if lst is None or not isinstance(lst, list):
        return default

    try:
        return lst[index]
    except (IndexError, TypeError):
        return default
