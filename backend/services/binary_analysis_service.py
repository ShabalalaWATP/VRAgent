"""
Binary Analysis Service

Deep binary analysis with AI enhancement for identifying attack surfaces,
input handlers, and vulnerability patterns.

Now uses proper binary parsing via lief/pefile with heuristic fallback.
"""

import hashlib
import logging
import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import asyncio

from backend.services.binary_ai_reasoning import (
    BinaryProfile,
    SecurityFeatures,
    FunctionInfo,
    InputHandler,
    VulnerabilityHint,
    AttackSurface,
    InputFormatGuess,
    BinaryAIClient,
)

# Import proper binary parser
try:
    from backend.services.binary_parser import (
        BinaryParser,
        ParsedBinary,
        parse_binary,
        get_imports,
        get_security_info,
    )
    PARSER_AVAILABLE = True
except ImportError:
    PARSER_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Dangerous functions that may lead to vulnerabilities
DANGEROUS_FUNCTIONS = {
    # Memory operations
    "strcpy": "buffer_overflow",
    "strcat": "buffer_overflow",
    "sprintf": "buffer_overflow",
    "vsprintf": "buffer_overflow",
    "gets": "buffer_overflow",
    "scanf": "buffer_overflow",
    "sscanf": "buffer_overflow",
    "fscanf": "buffer_overflow",

    # Format strings
    "printf": "format_string",
    "fprintf": "format_string",
    "sprintf": "format_string",
    "snprintf": "format_string",
    "vprintf": "format_string",
    "syslog": "format_string",

    # Memory management
    "malloc": "memory",
    "calloc": "memory",
    "realloc": "memory",
    "free": "memory",
    "alloca": "stack_overflow",

    # Command execution
    "system": "command_injection",
    "popen": "command_injection",
    "exec": "command_injection",
    "execl": "command_injection",
    "execle": "command_injection",
    "execlp": "command_injection",
    "execv": "command_injection",
    "execve": "command_injection",
    "execvp": "command_injection",

    # File operations
    "fopen": "path_traversal",
    "open": "path_traversal",
    "fread": "file_read",
    "fwrite": "file_write",
    "read": "file_read",
    "write": "file_write",

    # Network
    "recv": "network_input",
    "recvfrom": "network_input",
    "recvmsg": "network_input",
    "send": "network_output",
    "sendto": "network_output",

    # Windows specific
    "lstrcpy": "buffer_overflow",
    "lstrcpyA": "buffer_overflow",
    "lstrcpyW": "buffer_overflow",
    "lstrcat": "buffer_overflow",
    "WinExec": "command_injection",
    "ShellExecute": "command_injection",
    "CreateProcess": "command_injection",
}

# Input-related functions
INPUT_FUNCTIONS = {
    # File input
    "fopen": "file",
    "fread": "file",
    "fgets": "file",
    "read": "file",
    "mmap": "file",
    "open": "file",
    "CreateFile": "file",
    "ReadFile": "file",

    # Standard input
    "gets": "stdin",
    "fgets": "stdin",
    "scanf": "stdin",
    "getchar": "stdin",
    "getc": "stdin",
    "fgetc": "stdin",
    "getline": "stdin",

    # Network input
    "recv": "network",
    "recvfrom": "network",
    "recvmsg": "network",
    "accept": "network",
    "WSARecv": "network",

    # Arguments
    "getopt": "argv",
    "getopt_long": "argv",
    "GetCommandLine": "argv",

    # Environment
    "getenv": "env",
    "GetEnvironmentVariable": "env",
}

# File signatures for format detection
FILE_SIGNATURES = {
    b"\x7fELF": ("elf", "ELF executable"),
    b"MZ": ("pe", "Windows PE executable"),
    b"\xfe\xed\xfa\xce": ("macho32", "Mach-O 32-bit"),
    b"\xfe\xed\xfa\xcf": ("macho64", "Mach-O 64-bit"),
    b"\xca\xfe\xba\xbe": ("macho_fat", "Mach-O Fat binary"),
    b"\x89PNG": ("png", "PNG image"),
    b"PK\x03\x04": ("zip", "ZIP archive"),
    b"%PDF": ("pdf", "PDF document"),
    b"GIF8": ("gif", "GIF image"),
    b"\xff\xd8\xff": ("jpeg", "JPEG image"),
}


# =============================================================================
# Binary Analysis Service
# =============================================================================

class BinaryAnalysisService:
    """Deep binary analysis service with AI enhancement."""

    def __init__(self):
        self.ai_client = BinaryAIClient()

    async def analyze(
        self,
        binary_path: str,
        deep_analysis: bool = True,
        ai_enhance: bool = True,
    ) -> BinaryProfile:
        """Perform comprehensive binary analysis."""
        start_time = time.time()

        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Read binary
        with open(binary_path, "rb") as f:
            data = f.read()

        file_hash = hashlib.sha256(data).hexdigest()

        # Detect file type
        file_type, architecture, bits, endianness = self._detect_file_type(data)

        # Extract basic info
        imports = self._extract_imports(data, file_type)
        exports = self._extract_exports(data, file_type)
        strings = self._extract_interesting_strings(data)
        sections = self._extract_sections(data, file_type)
        entry_point = self._get_entry_point(data, file_type)

        # Security features
        protections = self._detect_security_features(data, file_type)

        # Create initial profile
        profile = BinaryProfile(
            file_path=binary_path,
            file_hash=file_hash,
            file_type=file_type,
            architecture=architecture,
            bits=bits,
            endianness=endianness,
            file_size=len(data),
            protections=protections,
            entry_point=entry_point,
            imports=imports,
            exports=exports,
            strings_of_interest=strings,
            sections=sections,
            function_count=len(exports) + self._estimate_function_count(data, file_type),
        )

        if deep_analysis:
            # Identify input handlers
            profile.input_handlers = self._identify_input_handlers(imports, exports)

            # Identify vulnerability hints
            profile.vulnerability_hints = self._identify_vulnerability_hints(imports, strings)

            # Calculate attack surface score
            profile.attack_surface_score = self._calculate_attack_surface_score(profile)

        if ai_enhance:
            # AI-enhanced analysis
            profile = await self._ai_enhance_profile(profile)

        profile.analysis_time_sec = time.time() - start_time
        profile.ai_analysis_complete = ai_enhance

        return profile

    def _detect_file_type(self, data: bytes) -> Tuple[str, str, int, str]:
        """Detect file type, architecture, bits, and endianness."""
        if len(data) < 64:
            return "unknown", "unknown", 0, "unknown"

        # Check for known signatures
        for sig, (ftype, _) in FILE_SIGNATURES.items():
            if data.startswith(sig):
                if ftype == "elf":
                    return self._parse_elf_header(data)
                elif ftype == "pe":
                    return self._parse_pe_header(data)
                elif ftype in ("macho32", "macho64", "macho_fat"):
                    return self._parse_macho_header(data, ftype)
                else:
                    return ftype, "unknown", 0, "unknown"

        return "unknown", "unknown", 0, "unknown"

    def _parse_elf_header(self, data: bytes) -> Tuple[str, str, int, str]:
        """Parse ELF header."""
        if len(data) < 52:
            return "elf", "unknown", 0, "unknown"

        ei_class = data[4]
        ei_data = data[5]
        e_machine = struct.unpack("<H" if ei_data == 1 else ">H", data[18:20])[0]

        bits = 32 if ei_class == 1 else 64
        endianness = "little" if ei_data == 1 else "big"

        arch_map = {
            0x03: "x86",
            0x3e: "x86_64",
            0x28: "arm",
            0xb7: "aarch64",
            0x08: "mips",
            0x14: "ppc",
            0x15: "ppc64",
            0xf3: "riscv",
        }
        architecture = arch_map.get(e_machine, f"unknown_{hex(e_machine)}")

        return "elf", architecture, bits, endianness

    def _parse_pe_header(self, data: bytes) -> Tuple[str, str, int, str]:
        """Parse PE header."""
        if len(data) < 64:
            return "pe", "unknown", 0, "little"

        # Get PE header offset
        pe_offset = struct.unpack("<I", data[60:64])[0]
        if pe_offset + 6 > len(data):
            return "pe", "unknown", 0, "little"

        # Check PE signature
        if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return "pe", "unknown", 0, "little"

        # Get machine type
        machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]

        machine_map = {
            0x014c: ("x86", 32),
            0x8664: ("x86_64", 64),
            0x01c0: ("arm", 32),
            0xaa64: ("aarch64", 64),
        }

        arch, bits = machine_map.get(machine, ("unknown", 32))
        return "pe", arch, bits, "little"

    def _parse_macho_header(self, data: bytes, ftype: str) -> Tuple[str, str, int, str]:
        """Parse Mach-O header."""
        if ftype == "macho32":
            bits = 32
        elif ftype == "macho64":
            bits = 64
        else:
            bits = 0

        # Determine endianness from magic
        magic = struct.unpack(">I", data[0:4])[0]
        endianness = "big" if magic in (0xfeedface, 0xfeedfacf) else "little"

        # Get CPU type
        if len(data) >= 8:
            cpu_type = struct.unpack("<I" if endianness == "little" else ">I", data[4:8])[0]
            cpu_map = {
                7: "x86",
                0x01000007: "x86_64",
                12: "arm",
                0x0100000c: "aarch64",
            }
            arch = cpu_map.get(cpu_type, "unknown")
        else:
            arch = "unknown"

        return "macho", arch, bits, endianness

    def _extract_imports(self, data: bytes, file_type: str) -> List[str]:
        """Extract imported functions using proper binary parsing."""
        imports = []

        # Try using proper parser first
        if PARSER_AVAILABLE:
            try:
                parsed = parse_binary(data)
                imports = [imp.name for imp in parsed.imports]
                logger.debug(f"Extracted {len(imports)} imports using {parsed.parse_method}")
                return imports[:500]
            except Exception as e:
                logger.debug(f"Parser failed, falling back to heuristic: {e}")

        # Fallback to heuristic extraction
        if file_type == "elf":
            imports = self._extract_elf_imports_heuristic(data)
        elif file_type == "pe":
            imports = self._extract_pe_imports_heuristic(data)

        return imports

    def _extract_elf_imports_heuristic(self, data: bytes) -> List[str]:
        """Extract imports from ELF using heuristics (fallback)."""
        imports = []
        seen = set()

        # Look for known dangerous/interesting function names
        all_funcs = set(DANGEROUS_FUNCTIONS.keys()) | set(INPUT_FUNCTIONS.keys())

        for func in all_funcs:
            # Check for exact match with null terminator
            if func.encode() + b'\x00' in data:
                if func not in seen:
                    imports.append(func)
                    seen.add(func)

        # Also look for versioned symbols (e.g., printf@@GLIBC_2.0)
        for match in re.finditer(rb'([a-z_][a-z_0-9]{2,30})@@[A-Z_0-9.]+', data, re.IGNORECASE):
            name = match.group(1).decode('ascii', errors='ignore')
            if name not in seen:
                imports.append(name)
                seen.add(name)

        return imports[:200]

    def _extract_pe_imports_heuristic(self, data: bytes) -> List[str]:
        """Extract imports from PE using heuristics (fallback)."""
        imports = []
        seen = set()

        # Look for known function names
        all_funcs = set(DANGEROUS_FUNCTIONS.keys()) | set(INPUT_FUNCTIONS.keys())

        for func in all_funcs:
            func_bytes = func.encode()
            # PE imports often have null padding
            if func_bytes in data:
                if func not in seen:
                    imports.append(func)
                    seen.add(func)

        # Look for Windows API patterns
        for match in re.finditer(rb'([A-Z][a-zA-Z]+(?:Ex)?[AW]?)\x00', data):
            name = match.group(1).decode('ascii', errors='ignore')
            if len(name) > 4 and name not in seen:
                # Filter out common non-API strings
                if not any(x in name.lower() for x in ['copyright', 'microsoft', 'version']):
                    imports.append(name)
                    seen.add(name)
                    if len(imports) >= 200:
                        break

        return imports[:200]

    def _extract_exports(self, data: bytes, file_type: str) -> List[str]:
        """Extract exported functions using proper parsing."""
        exports = []

        # Try using proper parser first
        if PARSER_AVAILABLE:
            try:
                parsed = parse_binary(data)
                exports = [exp.name for exp in parsed.exports]
                logger.debug(f"Extracted {len(exports)} exports using {parsed.parse_method}")
                return exports[:200]
            except Exception as e:
                logger.debug(f"Parser export extraction failed: {e}")

        # Fallback: string-based extraction
        seen = set()
        for match in re.finditer(rb'[\x20-\x7e]{4,64}\x00', data):
            s = match.group()[:-1].decode('ascii', errors='ignore')
            # Look for common export patterns
            if s and s[0].isalpha() and s not in seen:
                if s.startswith(('_', '__')) and not s.startswith('__libc'):
                    exports.append(s)
                    seen.add(s)

        return exports[:100]

    def _extract_interesting_strings(self, data: bytes) -> List[str]:
        """Extract interesting strings for fuzzing."""
        interesting = []

        # Patterns that indicate input format or vulnerabilities
        patterns = [
            rb'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
            rb'https?://[^\s\x00]+',  # URLs
            rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',  # Emails
            rb'%[0-9]*[sdxfp]',  # Format strings
            rb'SELECT|INSERT|UPDATE|DELETE',  # SQL
            rb'<[a-zA-Z][^>]*>',  # XML/HTML tags
            rb'\{["\']?[a-zA-Z]',  # JSON-like
            rb'[A-Z_]{5,}=',  # Config/env vars
            rb'/[a-zA-Z0-9_/]+\.[a-zA-Z]{2,4}',  # File paths
            rb'error|warning|fail|invalid|denied',  # Error messages
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                s = match.group().decode('ascii', errors='ignore')
                if len(s) >= 4 and s not in interesting:
                    interesting.append(s)
                if len(interesting) >= 50:
                    break
            if len(interesting) >= 50:
                break

        # Also extract printable strings
        for match in re.finditer(rb'[\x20-\x7e]{8,100}', data):
            s = match.group().decode('ascii', errors='ignore')
            # Filter common uninteresting strings
            if any(x in s.lower() for x in ['copyright', 'version', 'license', 'gnu', 'glibc']):
                continue
            if s not in interesting and len(interesting) < 100:
                interesting.append(s)

        return interesting[:100]

    def _extract_sections(self, data: bytes, file_type: str) -> List[Dict[str, Any]]:
        """Extract section information."""
        sections = []

        if file_type == "elf":
            # Basic ELF section extraction
            section_names = ['.text', '.data', '.rodata', '.bss', '.plt', '.got']
            for name in section_names:
                if name.encode() in data:
                    sections.append({"name": name, "present": True})

        elif file_type == "pe":
            # Basic PE section extraction
            section_names = ['.text', '.data', '.rdata', '.rsrc', '.reloc']
            for name in section_names:
                if name.encode() in data:
                    sections.append({"name": name, "present": True})

        return sections

    def _get_entry_point(self, data: bytes, file_type: str) -> int:
        """Get entry point address."""
        if file_type == "elf" and len(data) >= 28:
            # ELF entry point
            ei_class = data[4]
            if ei_class == 1:  # 32-bit
                return struct.unpack("<I", data[24:28])[0]
            elif ei_class == 2 and len(data) >= 32:  # 64-bit
                return struct.unpack("<Q", data[24:32])[0]

        elif file_type == "pe" and len(data) >= 64:
            pe_offset = struct.unpack("<I", data[60:64])[0]
            if pe_offset + 44 <= len(data):
                return struct.unpack("<I", data[pe_offset+40:pe_offset+44])[0]

        return 0

    def _detect_security_features(self, data: bytes, file_type: str) -> SecurityFeatures:
        """Detect security features in the binary."""
        features = SecurityFeatures()

        if file_type == "elf":
            # Check for stack canary
            if b"__stack_chk_fail" in data:
                features.stack_canary = True

            # Check for RELRO
            if b"GNU_RELRO" in data:
                features.relro = "partial"
                if b"BIND_NOW" in data:
                    features.relro = "full"

            # Check for PIE
            if len(data) >= 18:
                e_type = struct.unpack("<H", data[16:18])[0]
                if e_type == 3:  # ET_DYN
                    features.pie = True

            # Check for NX
            if b"GNU_STACK" in data:
                features.dep_nx = True

            # ASLR is typically OS-level, assume present for PIE
            features.aslr = features.pie

            # Check for FORTIFY
            if b"__fortify_fail" in data or b"__chk" in data:
                features.fortify = True

        elif file_type == "pe":
            # PE security features are in the optional header
            if len(data) >= 64:
                pe_offset = struct.unpack("<I", data[60:64])[0]

                if pe_offset + 96 <= len(data):
                    # DLL Characteristics
                    dll_chars = struct.unpack("<H", data[pe_offset+94:pe_offset+96])[0]

                    features.aslr = bool(dll_chars & 0x0040)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                    features.dep_nx = bool(dll_chars & 0x0100)  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                    features.cfi = bool(dll_chars & 0x0400)  # IMAGE_DLLCHARACTERISTICS_GUARD_CF

                # Check for SafeSEH
                if b"SAFESEH" in data:
                    features.safe_seh = True

                # Check for Authenticode
                if b"\x00\x00\x80\x00" in data:  # Certificate table entry
                    features.authenticode = True

        return features

    def _estimate_function_count(self, data: bytes, file_type: str) -> int:
        """Estimate number of functions in the binary."""
        # Count function prologues
        count = 0

        if file_type == "elf":
            # x86/x64 function prologues
            count += data.count(b"\x55\x48\x89\xe5")  # push rbp; mov rbp, rsp
            count += data.count(b"\x55\x89\xe5")  # push ebp; mov ebp, esp

        elif file_type == "pe":
            # Similar for PE
            count += data.count(b"\x55\x8b\xec")  # push ebp; mov ebp, esp
            count += data.count(b"\x55\x48\x89\xe5")

        return max(count, 10)  # At least 10 functions

    def _identify_input_handlers(
        self,
        imports: List[str],
        exports: List[str],
    ) -> List[InputHandler]:
        """Identify functions that handle input."""
        handlers = []

        for func in imports:
            for input_func, input_type in INPUT_FUNCTIONS.items():
                if input_func.lower() in func.lower():
                    handlers.append(InputHandler(
                        function_name=func,
                        input_type=input_type,
                        address=0,  # Would need disassembly
                        confidence=0.8,
                    ))
                    break

        return handlers

    def _identify_vulnerability_hints(
        self,
        imports: List[str],
        strings: List[str],
    ) -> List[VulnerabilityHint]:
        """Identify potential vulnerability patterns."""
        hints = []

        # Check for dangerous functions
        for func in imports:
            for dangerous, vuln_type in DANGEROUS_FUNCTIONS.items():
                if dangerous.lower() in func.lower():
                    hints.append(VulnerabilityHint(
                        type=vuln_type,
                        location=func,
                        confidence=0.7,
                        description=f"Use of potentially dangerous function: {dangerous}",
                        dangerous_function=dangerous,
                    ))
                    break

        # Check strings for vulnerability indicators
        vuln_string_patterns = [
            (r'%[0-9]*s', 'format_string', 'Format string with %s'),
            (r'password|passwd|secret|key', 'hardcoded_secret', 'Possible hardcoded secret'),
            (r'admin|root|superuser', 'privilege', 'Privileged user reference'),
            (r'sql|select|insert|update', 'sql_injection', 'SQL-related string'),
        ]

        for pattern, vuln_type, desc in vuln_string_patterns:
            for s in strings:
                if re.search(pattern, s, re.IGNORECASE):
                    hints.append(VulnerabilityHint(
                        type=vuln_type,
                        location=s[:50],
                        confidence=0.5,
                        description=desc,
                    ))
                    break

        return hints[:50]

    def _calculate_attack_surface_score(self, profile: BinaryProfile) -> float:
        """Calculate attack surface score (0-1)."""
        score = 0.0

        # Input handlers increase attack surface
        score += min(len(profile.input_handlers) * 0.1, 0.3)

        # Vulnerability hints increase score
        score += min(len(profile.vulnerability_hints) * 0.05, 0.2)

        # Dangerous imports
        dangerous_count = sum(1 for imp in profile.imports if any(d in imp.lower() for d in DANGEROUS_FUNCTIONS))
        score += min(dangerous_count * 0.03, 0.2)

        # Lack of protections increases score
        if not profile.protections.stack_canary:
            score += 0.1
        if not profile.protections.dep_nx:
            score += 0.1
        if not profile.protections.aslr:
            score += 0.1

        return min(score, 1.0)

    async def _ai_enhance_profile(self, profile: BinaryProfile) -> BinaryProfile:
        """Use AI to enhance the binary profile."""
        prompt = f"""Analyze this binary and provide additional insights.

Binary: {profile.file_path}
Type: {profile.file_type} ({profile.architecture}, {profile.bits}-bit)
Size: {profile.file_size} bytes

Imports (sample):
{chr(10).join(profile.imports[:20])}

Strings of interest (sample):
{chr(10).join(profile.strings_of_interest[:20])}

Input handlers detected: {len(profile.input_handlers)}
Vulnerability hints: {len(profile.vulnerability_hints)}
Current attack surface score: {profile.attack_surface_score:.2f}

Provide:
1. input_format_guess: Best guess for input format (type, confidence, structure_hints)
2. additional_attack_surfaces: Top 3 attack surfaces not yet identified (name, priority, description)
3. refined_attack_surface_score: Updated score 0-1 with reasoning
4. recommended_fuzzing_focus: What to focus on

Respond in JSON format."""

        try:
            response = await self.ai_client.generate(prompt)

            # Validate response is a valid dictionary before accessing
            if response and isinstance(response, dict) and "error" not in response:
                # Update input format guess
                if "input_format_guess" in response:
                    ifg = response["input_format_guess"]
                    profile.input_format_guess = InputFormatGuess(
                        format_type=ifg.get("type", "binary"),
                        confidence=ifg.get("confidence", 0.5),
                        structure_hints=ifg.get("structure_hints", []),
                    )

                # Add attack surfaces
                if "additional_attack_surfaces" in response:
                    for surface in response["additional_attack_surfaces"]:
                        profile.attack_surfaces.append(AttackSurface(
                            name=surface.get("name", "unknown"),
                            entry_point="",
                            input_type="",
                            priority=surface.get("priority", 5),
                            description=surface.get("description", ""),
                        ))

                # Update attack surface score
                if "refined_attack_surface_score" in response:
                    profile.attack_surface_score = response["refined_attack_surface_score"]

        except Exception as e:
            logger.warning(f"AI enhancement failed: {e}")

        return profile


# =============================================================================
# Disassembly Integration (Optional - requires external tools)
# =============================================================================

class DisassemblyService:
    """Integration with disassemblers for deeper analysis."""

    @staticmethod
    async def get_functions_with_radare2(binary_path: str) -> List[FunctionInfo]:
        """Use radare2 for function analysis (if available)."""
        functions = []

        try:
            # Check if r2 is available
            proc = await asyncio.create_subprocess_exec(
                "r2", "-q", "-c", "aaa; aflj", binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            if proc.returncode == 0:
                import json
                funcs = json.loads(stdout.decode())

                for func in funcs:
                    functions.append(FunctionInfo(
                        name=func.get("name", ""),
                        address=func.get("offset", 0),
                        size=func.get("size", 0),
                        complexity=func.get("cc", 0),  # Cyclomatic complexity
                    ))

        except FileNotFoundError:
            logger.debug("radare2 not available")
        except Exception as e:
            logger.warning(f"radare2 analysis failed: {e}")

        return functions

    @staticmethod
    async def get_call_graph_with_ghidra(binary_path: str) -> Dict[str, List[str]]:
        """Use Ghidra for call graph analysis (if available)."""
        # This would require Ghidra headless mode setup
        # Placeholder for now
        return {}


# =============================================================================
# Helper Functions
# =============================================================================

async def analyze_binary(binary_path: str, deep: bool = True) -> BinaryProfile:
    """Convenience function to analyze a binary."""
    service = BinaryAnalysisService()
    return await service.analyze(binary_path, deep_analysis=deep)


def quick_analyze(binary_path: str) -> BinaryProfile:
    """Quick synchronous analysis without AI."""
    import asyncio
    service = BinaryAnalysisService()

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            service.analyze(binary_path, deep_analysis=True, ai_enhance=False)
        )
    finally:
        loop.close()
