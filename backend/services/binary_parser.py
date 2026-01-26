"""
Binary Parser Module

Proper binary parsing using lief library with fallback to heuristics.
Supports ELF, PE, and Mach-O formats.
"""

import hashlib
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try to import lief for proper binary parsing
LIEF_AVAILABLE = False
try:
    import lief
    LIEF_AVAILABLE = True
    logger.info("LIEF library available - using proper binary parsing")
except ImportError:
    logger.warning("LIEF not available - falling back to heuristic parsing")

# Try pefile as PE-specific fallback
PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    pass


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ParsedSection:
    """Parsed binary section."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    permissions: str  # r, w, x combined
    entropy: float = 0.0
    characteristics: List[str] = field(default_factory=list)


@dataclass
class ParsedImport:
    """Parsed import entry."""
    name: str
    library: Optional[str] = None
    ordinal: Optional[int] = None
    address: Optional[int] = None


@dataclass
class ParsedExport:
    """Parsed export entry."""
    name: str
    address: int
    ordinal: Optional[int] = None


@dataclass
class ParsedFunction:
    """Parsed function information."""
    name: str
    address: int
    size: int = 0
    is_exported: bool = False
    is_imported: bool = False


@dataclass
class SecurityInfo:
    """Binary security features."""
    pie: bool = False           # Position Independent Executable
    nx: bool = False            # Non-executable stack (DEP)
    stack_canary: bool = False  # Stack protection
    relro: str = "none"         # Relocation Read-Only: none, partial, full
    fortify: bool = False       # FORTIFY_SOURCE
    aslr: bool = True           # ASLR (OS-dependent, assume true)
    cfi: bool = False           # Control Flow Integrity
    safe_seh: bool = False      # SafeSEH (PE only)
    authenticode: bool = False  # Code signing (PE only)


@dataclass
class ParsedBinary:
    """Complete parsed binary information."""
    file_type: str          # elf, pe, macho
    architecture: str       # x86, x86_64, arm, aarch64
    bits: int              # 32 or 64
    endianness: str        # little or big
    entry_point: int

    sections: List[ParsedSection]
    imports: List[ParsedImport]
    exports: List[ParsedExport]
    functions: List[ParsedFunction]

    security: SecurityInfo
    strings_of_interest: List[str]

    # Metadata
    file_size: int = 0
    file_hash: str = ""
    parse_method: str = "unknown"  # lief, pefile, heuristic


# =============================================================================
# Binary Parser Class
# =============================================================================

class BinaryParser:
    """
    Cross-platform binary parser.

    Uses lief for proper parsing when available, falls back to heuristics.
    """

    def __init__(self):
        self._lief_available = LIEF_AVAILABLE
        self._pefile_available = PEFILE_AVAILABLE

    def parse(self, data: bytes, filename: str = "binary") -> ParsedBinary:
        """
        Parse a binary and extract all information.

        Args:
            data: Binary file contents
            filename: Original filename (for format hints)

        Returns:
            ParsedBinary with all extracted information
        """
        if not data or len(data) < 64:
            raise ValueError("Binary data too small to parse")

        # Detect file type
        file_type = self._detect_type(data)

        # Try lief first
        if self._lief_available:
            try:
                return self._parse_with_lief(data, file_type)
            except Exception as e:
                logger.debug(f"LIEF parsing failed: {e}, falling back")

        # Try pefile for PE files
        if file_type == "pe" and self._pefile_available:
            try:
                return self._parse_with_pefile(data)
            except Exception as e:
                logger.debug(f"pefile parsing failed: {e}, falling back")

        # Fall back to heuristics
        return self._parse_heuristic(data, file_type)

    def _detect_type(self, data: bytes) -> str:
        """Detect binary file type from magic bytes."""
        if data[:4] == b'\x7fELF':
            return "elf"
        elif data[:2] == b'MZ':
            return "pe"
        elif data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                          b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            return "macho"
        elif data[:4] == b'\xca\xfe\xba\xbe':
            return "macho_fat"
        else:
            return "unknown"

    # =========================================================================
    # LIEF Parsing (Proper)
    # =========================================================================

    def _parse_with_lief(self, data: bytes, file_type: str) -> ParsedBinary:
        """Parse using LIEF library for accurate results."""
        binary = lief.parse(raw=data)

        if binary is None:
            raise ValueError("LIEF failed to parse binary")

        # Determine format-specific details
        if isinstance(binary, lief.ELF.Binary):
            return self._parse_elf_lief(binary, data)
        elif isinstance(binary, lief.PE.Binary):
            return self._parse_pe_lief(binary, data)
        elif isinstance(binary, lief.MachO.Binary):
            return self._parse_macho_lief(binary, data)
        else:
            raise ValueError(f"Unknown LIEF binary type: {type(binary)}")

    def _parse_elf_lief(self, binary: 'lief.ELF.Binary', data: bytes) -> ParsedBinary:
        """Parse ELF binary using LIEF."""
        # Architecture
        machine = binary.header.machine_type
        arch_map = {
            lief.ELF.ARCH.i386: ("x86", 32),
            lief.ELF.ARCH.x86_64: ("x86_64", 64),
            lief.ELF.ARCH.ARM: ("arm", 32),
            lief.ELF.ARCH.AARCH64: ("aarch64", 64),
            lief.ELF.ARCH.MIPS: ("mips", 32),
            lief.ELF.ARCH.PPC: ("ppc", 32),
            lief.ELF.ARCH.PPC64: ("ppc64", 64),
        }
        arch, bits = arch_map.get(machine, ("unknown", 32))

        # Endianness
        endianness = "little" if binary.header.identity_data == lief.ELF.ELF_DATA.LSB else "big"

        # Sections
        sections = []
        for section in binary.sections:
            perms = ""
            if section.flags & lief.ELF.SECTION_FLAGS.ALLOC:
                perms += "r"
            if section.flags & lief.ELF.SECTION_FLAGS.WRITE:
                perms += "w"
            if section.flags & lief.ELF.SECTION_FLAGS.EXECINSTR:
                perms += "x"

            sections.append(ParsedSection(
                name=section.name,
                virtual_address=section.virtual_address,
                virtual_size=section.size,
                raw_size=section.size,
                permissions=perms or "r",
                entropy=section.entropy,
            ))

        # Imports
        imports = []
        for func in binary.imported_functions:
            lib = func.library.name if func.library else None
            imports.append(ParsedImport(
                name=func.name,
                library=lib,
                address=func.address if func.address else None,
            ))

        # Exports
        exports = []
        for func in binary.exported_functions:
            exports.append(ParsedExport(
                name=func.name,
                address=func.address,
            ))

        # Functions (from symbols)
        functions = []
        for symbol in binary.symbols:
            if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.value:
                functions.append(ParsedFunction(
                    name=symbol.name,
                    address=symbol.value,
                    size=symbol.size,
                    is_exported=symbol.exported,
                    is_imported=symbol.imported,
                ))

        # Security features
        security = SecurityInfo(
            pie=binary.is_pie,
            nx=binary.has_nx,
            stack_canary=self._check_elf_canary(binary),
            relro=self._get_elf_relro(binary),
            fortify=self._check_elf_fortify(binary),
        )

        # Strings
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="elf",
            architecture=arch,
            bits=bits,
            endianness=endianness,
            entry_point=binary.entrypoint,
            sections=sections,
            imports=imports,
            exports=exports,
            functions=functions,
            security=security,
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="lief",
        )

    def _check_elf_canary(self, binary: 'lief.ELF.Binary') -> bool:
        """Check if ELF has stack canary protection."""
        canary_funcs = ['__stack_chk_fail', '__stack_chk_guard']
        for func in binary.imported_functions:
            if func.name in canary_funcs:
                return True
        return False

    def _get_elf_relro(self, binary: 'lief.ELF.Binary') -> str:
        """Get RELRO status for ELF."""
        if binary.has_relocation:
            # Check for full RELRO (BIND_NOW flag)
            for dyn in binary.dynamic_entries:
                if dyn.tag == lief.ELF.DYNAMIC_TAGS.FLAGS:
                    if dyn.value & 0x1:  # DF_BIND_NOW
                        return "full"
                if dyn.tag == lief.ELF.DYNAMIC_TAGS.FLAGS_1:
                    if dyn.value & 0x1:  # DF_1_NOW
                        return "full"

            # Check for GNU_RELRO segment
            for segment in binary.segments:
                if segment.type == lief.ELF.SEGMENT_TYPES.GNU_RELRO:
                    return "partial"
        return "none"

    def _check_elf_fortify(self, binary: 'lief.ELF.Binary') -> bool:
        """Check if ELF uses FORTIFY_SOURCE."""
        fortify_funcs = ['__printf_chk', '__sprintf_chk', '__strcpy_chk', '__memcpy_chk']
        for func in binary.imported_functions:
            if any(f in func.name for f in fortify_funcs):
                return True
        return False

    def _parse_pe_lief(self, binary: 'lief.PE.Binary', data: bytes) -> ParsedBinary:
        """Parse PE binary using LIEF."""
        # Architecture
        machine = binary.header.machine
        arch_map = {
            lief.PE.MACHINE_TYPES.I386: ("x86", 32),
            lief.PE.MACHINE_TYPES.AMD64: ("x86_64", 64),
            lief.PE.MACHINE_TYPES.ARM: ("arm", 32),
            lief.PE.MACHINE_TYPES.ARM64: ("aarch64", 64),
        }
        arch, bits = arch_map.get(machine, ("unknown", 32))

        # Sections
        sections = []
        for section in binary.sections:
            perms = ""
            chars = section.characteristics
            if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                perms += "x"
            if chars & 0x40000000:  # IMAGE_SCN_MEM_READ
                perms += "r"
            if chars & 0x80000000:  # IMAGE_SCN_MEM_WRITE
                perms += "w"

            sections.append(ParsedSection(
                name=section.name,
                virtual_address=section.virtual_address,
                virtual_size=section.virtual_size,
                raw_size=section.size,
                permissions=perms or "r",
                entropy=section.entropy,
            ))

        # Imports
        imports = []
        for imp in binary.imports:
            lib_name = imp.name
            for entry in imp.entries:
                imports.append(ParsedImport(
                    name=entry.name if entry.name else f"ordinal_{entry.ordinal}",
                    library=lib_name,
                    ordinal=entry.ordinal,
                    address=entry.iat_address,
                ))

        # Exports
        exports = []
        if binary.has_exports:
            for exp in binary.exported_functions:
                exports.append(ParsedExport(
                    name=exp.name,
                    address=exp.address,
                    ordinal=exp.ordinal,
                ))

        # Security
        security = SecurityInfo(
            pie=binary.is_pie,
            nx=binary.optional_header.has_characteristic(
                lief.PE.DLL_CHARACTERISTICS.NX_COMPAT
            ) if binary.optional_header else False,
            aslr=binary.optional_header.has_characteristic(
                lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
            ) if binary.optional_header else False,
            safe_seh=binary.has_seh,
            authenticode=binary.has_signature,
        )

        # Strings
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="pe",
            architecture=arch,
            bits=bits,
            endianness="little",
            entry_point=binary.entrypoint,
            sections=sections,
            imports=imports,
            exports=exports,
            functions=[],
            security=security,
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="lief",
        )

    def _parse_macho_lief(self, binary: 'lief.MachO.Binary', data: bytes) -> ParsedBinary:
        """Parse Mach-O binary using LIEF."""
        # For FAT binaries, use first architecture
        if isinstance(binary, lief.MachO.FatBinary):
            binary = binary.at(0)

        # Architecture
        cpu_type = binary.header.cpu_type
        arch_map = {
            lief.MachO.CPU_TYPES.x86: ("x86", 32),
            lief.MachO.CPU_TYPES.x86_64: ("x86_64", 64),
            lief.MachO.CPU_TYPES.ARM: ("arm", 32),
            lief.MachO.CPU_TYPES.ARM64: ("aarch64", 64),
        }
        arch, bits = arch_map.get(cpu_type, ("unknown", 64))

        # Sections
        sections = []
        for section in binary.sections:
            sections.append(ParsedSection(
                name=section.name,
                virtual_address=section.virtual_address,
                virtual_size=section.size,
                raw_size=section.size,
                permissions="rwx",  # Mach-O section permissions are complex
                entropy=section.entropy,
            ))

        # Imports
        imports = []
        for sym in binary.imported_symbols:
            imports.append(ParsedImport(
                name=sym.name,
                library=sym.library.name if sym.library else None,
            ))

        # Exports
        exports = []
        for sym in binary.exported_symbols:
            exports.append(ParsedExport(
                name=sym.name,
                address=sym.value,
            ))

        # Security
        security = SecurityInfo(
            pie=binary.is_pie,
            nx=True,  # Mach-O typically has NX
        )

        # Strings
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="macho",
            architecture=arch,
            bits=bits,
            endianness="little",
            entry_point=binary.entrypoint,
            sections=sections,
            imports=imports,
            exports=exports,
            functions=[],
            security=security,
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="lief",
        )

    # =========================================================================
    # pefile Parsing (PE-specific fallback)
    # =========================================================================

    def _parse_with_pefile(self, data: bytes) -> ParsedBinary:
        """Parse PE using pefile library."""
        pe = pefile.PE(data=data)

        # Architecture
        if pe.FILE_HEADER.Machine == 0x14c:
            arch, bits = "x86", 32
        elif pe.FILE_HEADER.Machine == 0x8664:
            arch, bits = "x86_64", 64
        else:
            arch, bits = "unknown", 32

        # Sections
        sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            perms = ""
            if section.Characteristics & 0x20000000:
                perms += "x"
            if section.Characteristics & 0x40000000:
                perms += "r"
            if section.Characteristics & 0x80000000:
                perms += "w"

            sections.append(ParsedSection(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                permissions=perms or "r",
            ))

        # Imports
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                lib_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
                    imports.append(ParsedImport(
                        name=name,
                        library=lib_name,
                        ordinal=imp.ordinal,
                        address=imp.address,
                    ))

        # Exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode('utf-8', errors='ignore') if exp.name else f"ordinal_{exp.ordinal}"
                exports.append(ParsedExport(
                    name=name,
                    address=exp.address,
                    ordinal=exp.ordinal,
                ))

        # Security
        nx = False
        aslr = False
        if hasattr(pe, 'OPTIONAL_HEADER'):
            dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
            nx = bool(dll_chars & 0x100)  # NX_COMPAT
            aslr = bool(dll_chars & 0x40)  # DYNAMIC_BASE

        security = SecurityInfo(
            pie=aslr,
            nx=nx,
            aslr=aslr,
        )

        # Strings
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="pe",
            architecture=arch,
            bits=bits,
            endianness="little",
            entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            sections=sections,
            imports=imports,
            exports=exports,
            functions=[],
            security=security,
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="pefile",
        )

    # =========================================================================
    # Heuristic Parsing (Fallback)
    # =========================================================================

    def _parse_heuristic(self, data: bytes, file_type: str) -> ParsedBinary:
        """Parse using heuristics when libraries unavailable."""
        logger.info(f"Using heuristic parsing for {file_type}")

        if file_type == "elf":
            return self._parse_elf_heuristic(data)
        elif file_type == "pe":
            return self._parse_pe_heuristic(data)
        elif file_type in ["macho", "macho_fat"]:
            return self._parse_macho_heuristic(data)
        else:
            return self._parse_unknown_heuristic(data)

    def _parse_elf_heuristic(self, data: bytes) -> ParsedBinary:
        """Heuristic ELF parsing."""
        # ELF header
        bits = 64 if data[4] == 2 else 32
        endian = "little" if data[5] == 1 else "big"

        # Machine type
        if bits == 64:
            machine = struct.unpack("<H" if endian == "little" else ">H", data[18:20])[0]
        else:
            machine = struct.unpack("<H" if endian == "little" else ">H", data[18:20])[0]

        arch_map = {0x03: "x86", 0x3e: "x86_64", 0x28: "arm", 0xb7: "aarch64"}
        arch = arch_map.get(machine, "unknown")

        # Entry point
        if bits == 64:
            entry = struct.unpack("<Q" if endian == "little" else ">Q", data[24:32])[0]
        else:
            entry = struct.unpack("<I" if endian == "little" else ">I", data[24:28])[0]

        # Extract imports via string matching
        imports = self._extract_imports_heuristic(data, "elf")
        exports = self._extract_exports_heuristic(data, "elf")

        # Check security via string patterns
        security = self._detect_security_heuristic(data, "elf")

        # Strings
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="elf",
            architecture=arch,
            bits=bits,
            endianness=endian,
            entry_point=entry,
            sections=[],
            imports=imports,
            exports=exports,
            functions=[],
            security=security,
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="heuristic",
        )

    def _parse_pe_heuristic(self, data: bytes) -> ParsedBinary:
        """Heuristic PE parsing."""
        # Find PE header
        pe_offset = struct.unpack("<I", data[0x3c:0x40])[0]

        if pe_offset + 6 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE header")

        # Machine type
        machine = struct.unpack("<H", data[pe_offset+4:pe_offset+6])[0]
        arch_map = {0x14c: ("x86", 32), 0x8664: ("x86_64", 64)}
        arch, bits = arch_map.get(machine, ("unknown", 32))

        # Entry point
        opt_header_offset = pe_offset + 24
        entry = struct.unpack("<I", data[opt_header_offset+16:opt_header_offset+20])[0]

        # Imports
        imports = self._extract_imports_heuristic(data, "pe")
        exports = self._extract_exports_heuristic(data, "pe")

        # Security
        security = self._detect_security_heuristic(data, "pe")

        # Strings
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="pe",
            architecture=arch,
            bits=bits,
            endianness="little",
            entry_point=entry,
            sections=[],
            imports=imports,
            exports=exports,
            functions=[],
            security=security,
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="heuristic",
        )

    def _parse_macho_heuristic(self, data: bytes) -> ParsedBinary:
        """Heuristic Mach-O parsing."""
        magic = struct.unpack(">I", data[0:4])[0]

        if magic in [0xfeedface, 0xcefaedfe]:
            bits = 32
        else:
            bits = 64

        endian = "big" if magic in [0xfeedface, 0xfeedfacf] else "little"

        # CPU type
        cpu = struct.unpack("<I" if endian == "little" else ">I", data[4:8])[0]
        arch_map = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "aarch64"}
        arch = arch_map.get(cpu, "unknown")

        imports = self._extract_imports_heuristic(data, "macho")
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="macho",
            architecture=arch,
            bits=bits,
            endianness=endian,
            entry_point=0,
            sections=[],
            imports=imports,
            exports=[],
            functions=[],
            security=SecurityInfo(),
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="heuristic",
        )

    def _parse_unknown_heuristic(self, data: bytes) -> ParsedBinary:
        """Fallback for unknown formats."""
        strings = self._extract_interesting_strings(data)

        return ParsedBinary(
            file_type="unknown",
            architecture="unknown",
            bits=0,
            endianness="unknown",
            entry_point=0,
            sections=[],
            imports=[],
            exports=[],
            functions=[],
            security=SecurityInfo(),
            strings_of_interest=strings,
            file_size=len(data),
            file_hash=hashlib.sha256(data).hexdigest(),
            parse_method="heuristic",
        )

    def _extract_imports_heuristic(self, data: bytes, file_type: str) -> List[ParsedImport]:
        """Extract imports using string matching."""
        imports = []
        seen = set()

        # Known dangerous/interesting functions to look for
        target_funcs = [
            # Memory
            "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
            "memcpy", "memmove", "strncpy", "strncat", "sscanf",
            # Format
            "printf", "fprintf", "vprintf", "snprintf", "syslog",
            # System
            "system", "popen", "exec", "execl", "execv", "execve",
            # Memory management
            "malloc", "calloc", "realloc", "free", "alloca",
            # File
            "fopen", "fread", "fwrite", "open", "read", "write",
            # Network
            "recv", "recvfrom", "send", "connect", "accept", "socket",
            # Windows
            "lstrcpy", "lstrcat", "WinExec", "ShellExecute", "CreateProcess",
            "ReadFile", "WriteFile", "CreateFile",
        ]

        # Search for function names in binary
        for func in target_funcs:
            func_bytes = func.encode()
            if func_bytes in data:
                if func not in seen:
                    imports.append(ParsedImport(name=func))
                    seen.add(func)

        # Also look for common libc patterns
        for match in re.finditer(rb'__(stack_chk_fail|printf_chk|strcpy_chk|memcpy_chk)', data):
            name = match.group().decode('ascii', errors='ignore')
            if name not in seen:
                imports.append(ParsedImport(name=name))
                seen.add(name)

        return imports

    def _extract_exports_heuristic(self, data: bytes, file_type: str) -> List[ParsedExport]:
        """Extract exports using string matching."""
        exports = []

        # Look for function-like symbols
        for match in re.finditer(rb'(?:^|[\x00])([_a-zA-Z][_a-zA-Z0-9]{3,30})(?:[\x00])', data):
            name = match.group(1).decode('ascii', errors='ignore')
            if not any(x in name.lower() for x in ['copyright', 'version', 'license']):
                if len(exports) < 100:
                    exports.append(ParsedExport(name=name, address=0))

        return exports

    def _detect_security_heuristic(self, data: bytes, file_type: str) -> SecurityInfo:
        """Detect security features using heuristics."""
        security = SecurityInfo()

        if file_type == "elf":
            # Stack canary
            security.stack_canary = b'__stack_chk_fail' in data
            # FORTIFY
            security.fortify = b'_chk@' in data or b'__printf_chk' in data
            # NX - check for PT_GNU_STACK
            security.nx = b'GNU_STACK' not in data or b'\x06\x00\x00\x00' in data

        elif file_type == "pe":
            # Look for DLL characteristics in optional header
            try:
                pe_offset = struct.unpack("<I", data[0x3c:0x40])[0]
                opt_offset = pe_offset + 24
                # DllCharacteristics at offset 70 (PE32) or 86 (PE32+)
                dll_chars = struct.unpack("<H", data[opt_offset+70:opt_offset+72])[0]
                security.nx = bool(dll_chars & 0x100)
                security.aslr = bool(dll_chars & 0x40)
                security.pie = security.aslr
            except:
                pass

        return security

    def _extract_interesting_strings(self, data: bytes) -> List[str]:
        """Extract strings of interest for fuzzing."""
        strings = []
        seen = set()

        # Patterns that indicate input format or vulnerabilities
        patterns = [
            (rb'https?://[^\s\x00]{5,100}', "url"),
            (rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', "email"),
            (rb'%[0-9]*[sdxfpn]', "format_string"),
            (rb'SELECT|INSERT|UPDATE|DELETE|DROP', "sql"),
            (rb'<[a-zA-Z][^>]{0,50}>', "xml_tag"),
            (rb'\{["\']?[a-zA-Z]', "json"),
            (rb'/[a-zA-Z0-9_/.-]{5,50}\.[a-zA-Z]{1,4}', "file_path"),
        ]

        for pattern, _ in patterns:
            for match in re.finditer(pattern, data, re.IGNORECASE):
                s = match.group().decode('ascii', errors='ignore')
                if s not in seen and len(s) < 200:
                    strings.append(s)
                    seen.add(s)
                if len(strings) >= 100:
                    break

        return strings


# =============================================================================
# Convenience Functions
# =============================================================================

def parse_binary(data: bytes, filename: str = "binary") -> ParsedBinary:
    """Parse a binary file and return structured information."""
    parser = BinaryParser()
    return parser.parse(data, filename)


def get_imports(data: bytes) -> List[str]:
    """Quick function to get just the imports."""
    parsed = parse_binary(data)
    return [imp.name for imp in parsed.imports]


def get_security_info(data: bytes) -> Dict[str, bool]:
    """Quick function to get security features."""
    parsed = parse_binary(data)
    return {
        "pie": parsed.security.pie,
        "nx": parsed.security.nx,
        "stack_canary": parsed.security.stack_canary,
        "relro": parsed.security.relro,
        "fortify": parsed.security.fortify,
        "aslr": parsed.security.aslr,
    }
