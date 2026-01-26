"""
Structured Format Fuzzing Service

Structure-aware binary format fuzzing with checksum and size field handling.
Supports common file formats like PNG, PDF, ZIP, ELF, PE, etc.
"""

import hashlib
import io
import random
import struct
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================

class FormatType(str, Enum):
    """Supported file format types."""
    PNG = "png"
    JPEG = "jpeg"
    GIF = "gif"
    BMP = "bmp"
    PDF = "pdf"
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    PROTOBUF = "protobuf"
    MSGPACK = "msgpack"
    BSON = "bson"
    WAV = "wav"
    MP3 = "mp3"
    MP4 = "mp4"
    UNKNOWN = "unknown"


class FieldType(str, Enum):
    """Field data types."""
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT16_BE = "uint16_be"
    UINT32 = "uint32"
    UINT32_BE = "uint32_be"
    UINT64 = "uint64"
    UINT64_BE = "uint64_be"
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    BYTES = "bytes"
    STRING = "string"
    CRC32 = "crc32"
    ADLER32 = "adler32"
    MD5 = "md5"
    SHA1 = "sha1"


class Endianness(str, Enum):
    """Byte order."""
    LITTLE = "little"
    BIG = "big"


# Magic bytes for format detection
FORMAT_SIGNATURES: Dict[FormatType, List[bytes]] = {
    FormatType.PNG: [b"\x89PNG\r\n\x1a\n"],
    FormatType.JPEG: [b"\xff\xd8\xff"],
    FormatType.GIF: [b"GIF87a", b"GIF89a"],
    FormatType.BMP: [b"BM"],
    FormatType.PDF: [b"%PDF-"],
    FormatType.ZIP: [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    FormatType.GZIP: [b"\x1f\x8b"],
    FormatType.TAR: [b"ustar"],  # At offset 257
    FormatType.ELF: [b"\x7fELF"],
    FormatType.PE: [b"MZ"],
    FormatType.MACHO: [b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"],
    FormatType.WAV: [b"RIFF"],
    FormatType.MP3: [b"\xff\xfb", b"\xff\xfa", b"ID3"],
    FormatType.MP4: [b"ftyp"],  # At offset 4
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class FormatField:
    """A field within a file format structure."""
    name: str
    offset: int
    size: int
    field_type: FieldType
    endianness: Endianness = Endianness.LITTLE
    depends_on: Optional[str] = None  # Field name this depends on
    description: str = ""
    valid_values: Optional[List[Any]] = None
    is_checksum: bool = False
    checksum_range: Optional[Tuple[int, int]] = None  # (start, end) for checksum calc


@dataclass
class FormatChunk:
    """A chunk or section within a file format."""
    name: str
    offset: int
    size: int
    type_field: Optional[str] = None  # Field containing chunk type
    size_field: Optional[str] = None  # Field containing size
    data_offset: int = 0  # Offset to actual data within chunk
    fields: List[FormatField] = field(default_factory=list)
    checksum_field: Optional[str] = None


@dataclass
class FormatStructure:
    """Complete structure definition for a file format."""
    name: str
    format_type: FormatType
    magic: Optional[bytes] = None
    magic_offset: int = 0
    endianness: Endianness = Endianness.LITTLE
    fields: List[FormatField] = field(default_factory=list)
    chunks: List[FormatChunk] = field(default_factory=list)
    checksum_fields: List[str] = field(default_factory=list)
    size_fields: Dict[str, str] = field(default_factory=dict)  # size_field -> data_field
    description: str = ""


@dataclass
class ParsedField:
    """A parsed field from actual data."""
    field: FormatField
    value: Any
    raw_bytes: bytes
    offset: int


@dataclass
class ParsedChunk:
    """A parsed chunk from actual data."""
    chunk: FormatChunk
    fields: List[ParsedField]
    data: bytes
    offset: int
    size: int


@dataclass
class ParsedStructure:
    """Parsed file structure."""
    structure: FormatStructure
    header_fields: List[ParsedField]
    chunks: List[ParsedChunk]
    total_size: int
    valid: bool
    errors: List[str] = field(default_factory=list)


@dataclass
class StructuredMutation:
    """Result of a structure-aware mutation."""
    original: bytes
    mutated: bytes
    mutation_type: str
    field_mutated: Optional[str] = None
    chunk_mutated: Optional[str] = None
    checksum_fixed: bool = False
    size_fixed: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FormatFuzzConfig:
    """Configuration for format-aware fuzzing."""
    format_type: FormatType
    mutation_rate: float = 0.3
    fix_checksums: bool = True
    fix_sizes: bool = True
    preserve_magic: bool = True
    max_mutations_per_input: int = 5
    target_fields: Optional[List[str]] = None  # Specific fields to target


# =============================================================================
# Format Definitions
# =============================================================================

def get_png_structure() -> FormatStructure:
    """Get PNG file format structure."""
    return FormatStructure(
        name="PNG",
        format_type=FormatType.PNG,
        magic=b"\x89PNG\r\n\x1a\n",
        magic_offset=0,
        endianness=Endianness.BIG,
        fields=[
            FormatField("signature", 0, 8, FieldType.BYTES, description="PNG signature"),
        ],
        chunks=[
            FormatChunk(
                name="IHDR",
                offset=8,
                size=25,  # 4 + 4 + 13 + 4
                type_field="type",
                size_field="length",
                data_offset=8,
                fields=[
                    FormatField("length", 0, 4, FieldType.UINT32_BE),
                    FormatField("type", 4, 4, FieldType.BYTES),
                    FormatField("width", 8, 4, FieldType.UINT32_BE),
                    FormatField("height", 12, 4, FieldType.UINT32_BE),
                    FormatField("bit_depth", 16, 1, FieldType.UINT8),
                    FormatField("color_type", 17, 1, FieldType.UINT8),
                    FormatField("compression", 18, 1, FieldType.UINT8),
                    FormatField("filter", 19, 1, FieldType.UINT8),
                    FormatField("interlace", 20, 1, FieldType.UINT8),
                    FormatField("crc", 21, 4, FieldType.CRC32, is_checksum=True, checksum_range=(4, 21)),
                ],
                checksum_field="crc",
            ),
        ],
        checksum_fields=["crc"],
        description="PNG image format (RFC 2083)",
    )


def get_zip_structure() -> FormatStructure:
    """Get ZIP file format structure."""
    return FormatStructure(
        name="ZIP",
        format_type=FormatType.ZIP,
        magic=b"PK\x03\x04",
        magic_offset=0,
        endianness=Endianness.LITTLE,
        fields=[
            FormatField("signature", 0, 4, FieldType.BYTES, description="Local file header signature"),
            FormatField("version_needed", 4, 2, FieldType.UINT16),
            FormatField("flags", 6, 2, FieldType.UINT16),
            FormatField("compression", 8, 2, FieldType.UINT16),
            FormatField("mod_time", 10, 2, FieldType.UINT16),
            FormatField("mod_date", 12, 2, FieldType.UINT16),
            FormatField("crc32", 14, 4, FieldType.CRC32, is_checksum=True),
            FormatField("compressed_size", 18, 4, FieldType.UINT32),
            FormatField("uncompressed_size", 22, 4, FieldType.UINT32),
            FormatField("filename_length", 26, 2, FieldType.UINT16),
            FormatField("extra_length", 28, 2, FieldType.UINT16),
        ],
        size_fields={
            "compressed_size": "file_data",
            "filename_length": "filename",
            "extra_length": "extra",
        },
        checksum_fields=["crc32"],
        description="ZIP archive format (PKWARE)",
    )


def get_pdf_structure() -> FormatStructure:
    """Get PDF file format structure."""
    return FormatStructure(
        name="PDF",
        format_type=FormatType.PDF,
        magic=b"%PDF-",
        magic_offset=0,
        endianness=Endianness.BIG,
        fields=[
            FormatField("header", 0, 8, FieldType.STRING, description="PDF header"),
        ],
        description="PDF document format (ISO 32000)",
    )


def get_elf_structure() -> FormatStructure:
    """Get ELF file format structure."""
    return FormatStructure(
        name="ELF",
        format_type=FormatType.ELF,
        magic=b"\x7fELF",
        magic_offset=0,
        endianness=Endianness.LITTLE,  # Can be overridden by EI_DATA
        fields=[
            FormatField("magic", 0, 4, FieldType.BYTES),
            FormatField("class", 4, 1, FieldType.UINT8, description="32/64-bit"),
            FormatField("data", 5, 1, FieldType.UINT8, description="Endianness"),
            FormatField("version", 6, 1, FieldType.UINT8),
            FormatField("osabi", 7, 1, FieldType.UINT8),
            FormatField("abiversion", 8, 1, FieldType.UINT8),
            FormatField("pad", 9, 7, FieldType.BYTES),
            FormatField("type", 16, 2, FieldType.UINT16),
            FormatField("machine", 18, 2, FieldType.UINT16),
            FormatField("e_version", 20, 4, FieldType.UINT32),
            FormatField("entry", 24, 4, FieldType.UINT32),  # 8 for 64-bit
            FormatField("phoff", 28, 4, FieldType.UINT32),
            FormatField("shoff", 32, 4, FieldType.UINT32),
            FormatField("flags", 36, 4, FieldType.UINT32),
            FormatField("ehsize", 40, 2, FieldType.UINT16),
            FormatField("phentsize", 42, 2, FieldType.UINT16),
            FormatField("phnum", 44, 2, FieldType.UINT16),
            FormatField("shentsize", 46, 2, FieldType.UINT16),
            FormatField("shnum", 48, 2, FieldType.UINT16),
            FormatField("shstrndx", 50, 2, FieldType.UINT16),
        ],
        description="Executable and Linkable Format",
    )


def get_pe_structure() -> FormatStructure:
    """Get PE (Windows executable) format structure."""
    return FormatStructure(
        name="PE",
        format_type=FormatType.PE,
        magic=b"MZ",
        magic_offset=0,
        endianness=Endianness.LITTLE,
        fields=[
            FormatField("e_magic", 0, 2, FieldType.BYTES),
            FormatField("e_cblp", 2, 2, FieldType.UINT16),
            FormatField("e_cp", 4, 2, FieldType.UINT16),
            FormatField("e_crlc", 6, 2, FieldType.UINT16),
            FormatField("e_cparhdr", 8, 2, FieldType.UINT16),
            FormatField("e_minalloc", 10, 2, FieldType.UINT16),
            FormatField("e_maxalloc", 12, 2, FieldType.UINT16),
            FormatField("e_ss", 14, 2, FieldType.UINT16),
            FormatField("e_sp", 16, 2, FieldType.UINT16),
            FormatField("e_csum", 18, 2, FieldType.UINT16),
            FormatField("e_ip", 20, 2, FieldType.UINT16),
            FormatField("e_cs", 22, 2, FieldType.UINT16),
            FormatField("e_lfarlc", 24, 2, FieldType.UINT16),
            FormatField("e_ovno", 26, 2, FieldType.UINT16),
            FormatField("e_res", 28, 8, FieldType.BYTES),
            FormatField("e_oemid", 36, 2, FieldType.UINT16),
            FormatField("e_oeminfo", 38, 2, FieldType.UINT16),
            FormatField("e_res2", 40, 20, FieldType.BYTES),
            FormatField("e_lfanew", 60, 4, FieldType.UINT32, description="PE header offset"),
        ],
        checksum_fields=["e_csum"],
        description="Windows Portable Executable format",
    )


FORMAT_STRUCTURES: Dict[FormatType, FormatStructure] = {
    FormatType.PNG: get_png_structure(),
    FormatType.ZIP: get_zip_structure(),
    FormatType.PDF: get_pdf_structure(),
    FormatType.ELF: get_elf_structure(),
    FormatType.PE: get_pe_structure(),
}


# =============================================================================
# Structured Format Service
# =============================================================================

class StructuredFormatService:
    """Structure-aware binary format fuzzing service."""

    def __init__(self):
        self.structures = FORMAT_STRUCTURES.copy()

    def detect_format(self, data: bytes) -> FormatType:
        """Detect file format from data."""
        if len(data) < 4:
            return FormatType.UNKNOWN

        for format_type, signatures in FORMAT_SIGNATURES.items():
            for sig in signatures:
                # Handle special offset cases
                if format_type == FormatType.TAR:
                    if len(data) > 262 and data[257:262] == sig[:5]:
                        return format_type
                elif format_type == FormatType.MP4:
                    if len(data) > 8 and data[4:8] == sig:
                        return format_type
                else:
                    if data.startswith(sig):
                        return format_type

        return FormatType.UNKNOWN

    def get_structure(self, format_type: FormatType) -> Optional[FormatStructure]:
        """Get structure definition for a format type."""
        return self.structures.get(format_type)

    def register_structure(self, structure: FormatStructure):
        """Register a custom structure definition."""
        self.structures[structure.format_type] = structure

    def parse_structure(self, data: bytes, format_type: Optional[FormatType] = None) -> ParsedStructure:
        """Parse data according to its format structure."""
        if format_type is None:
            format_type = self.detect_format(data)

        if format_type == FormatType.UNKNOWN:
            return ParsedStructure(
                structure=FormatStructure(name="Unknown", format_type=FormatType.UNKNOWN),
                header_fields=[],
                chunks=[],
                total_size=len(data),
                valid=False,
                errors=["Unknown format"],
            )

        structure = self.get_structure(format_type)
        if not structure:
            return ParsedStructure(
                structure=FormatStructure(name="Unknown", format_type=format_type),
                header_fields=[],
                chunks=[],
                total_size=len(data),
                valid=False,
                errors=[f"No structure definition for {format_type.value}"],
            )

        errors = []
        header_fields = []
        chunks = []

        # Parse header fields
        for field_def in structure.fields:
            try:
                parsed = self._parse_field(data, field_def, structure.endianness)
                if parsed:
                    header_fields.append(parsed)
            except Exception as e:
                errors.append(f"Error parsing field {field_def.name}: {e}")

        # Parse chunks if applicable
        if structure.chunks and format_type == FormatType.PNG:
            chunks = self._parse_png_chunks(data, structure)

        valid = len(errors) == 0 and self._validate_magic(data, structure)

        return ParsedStructure(
            structure=structure,
            header_fields=header_fields,
            chunks=chunks,
            total_size=len(data),
            valid=valid,
            errors=errors,
        )

    def _parse_field(self, data: bytes, field_def: FormatField, default_endian: Endianness) -> Optional[ParsedField]:
        """Parse a single field from data."""
        if field_def.offset + field_def.size > len(data):
            return None

        raw = data[field_def.offset:field_def.offset + field_def.size]
        endian = field_def.endianness if field_def.endianness else default_endian
        fmt_char = "<" if endian == Endianness.LITTLE else ">"

        try:
            if field_def.field_type == FieldType.UINT8:
                value = struct.unpack("B", raw)[0]
            elif field_def.field_type in (FieldType.UINT16, FieldType.UINT16_BE):
                fmt = ">H" if field_def.field_type == FieldType.UINT16_BE else fmt_char + "H"
                value = struct.unpack(fmt, raw)[0]
            elif field_def.field_type in (FieldType.UINT32, FieldType.UINT32_BE, FieldType.CRC32):
                fmt = ">I" if field_def.field_type == FieldType.UINT32_BE else fmt_char + "I"
                value = struct.unpack(fmt, raw)[0]
            elif field_def.field_type in (FieldType.UINT64, FieldType.UINT64_BE):
                fmt = ">Q" if field_def.field_type == FieldType.UINT64_BE else fmt_char + "Q"
                value = struct.unpack(fmt, raw)[0]
            elif field_def.field_type == FieldType.BYTES:
                value = raw
            elif field_def.field_type == FieldType.STRING:
                value = raw.decode("utf-8", errors="replace").rstrip("\x00")
            else:
                value = raw

            return ParsedField(
                field=field_def,
                value=value,
                raw_bytes=raw,
                offset=field_def.offset,
            )

        except struct.error as e:
            logger.warning(f"Failed to parse field {field_def.name}: {e}")
            return None

    def _parse_png_chunks(self, data: bytes, structure: FormatStructure) -> List[ParsedChunk]:
        """Parse PNG chunks."""
        chunks = []
        offset = 8  # Skip signature

        while offset + 12 <= len(data):  # Minimum chunk size: length(4) + type(4) + crc(4)
            try:
                length = struct.unpack(">I", data[offset:offset+4])[0]
                chunk_type = data[offset+4:offset+8]
                chunk_data = data[offset+8:offset+8+length] if offset+8+length <= len(data) else b""
                crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0] if offset+12+length <= len(data) else 0

                chunk = FormatChunk(
                    name=chunk_type.decode("ascii", errors="replace"),
                    offset=offset,
                    size=12 + length,
                    fields=[
                        FormatField("length", 0, 4, FieldType.UINT32_BE),
                        FormatField("type", 4, 4, FieldType.BYTES),
                        FormatField("crc", 8 + length, 4, FieldType.CRC32, is_checksum=True),
                    ],
                )

                parsed_fields = [
                    ParsedField(chunk.fields[0], length, data[offset:offset+4], offset),
                    ParsedField(chunk.fields[1], chunk_type, data[offset+4:offset+8], offset+4),
                    ParsedField(chunk.fields[2], crc, data[offset+8+length:offset+12+length] if offset+12+length <= len(data) else b"", offset+8+length),
                ]

                chunks.append(ParsedChunk(
                    chunk=chunk,
                    fields=parsed_fields,
                    data=chunk_data,
                    offset=offset,
                    size=12 + length,
                ))

                offset += 12 + length

                if chunk_type == b"IEND":
                    break

            except Exception as e:
                logger.warning(f"Error parsing PNG chunk at offset {offset}: {e}")
                break

        return chunks

    def _validate_magic(self, data: bytes, structure: FormatStructure) -> bool:
        """Validate magic bytes."""
        if not structure.magic:
            return True

        offset = structure.magic_offset
        if offset + len(structure.magic) > len(data):
            return False

        return data[offset:offset + len(structure.magic)] == structure.magic

    # =========================================================================
    # Mutation Operations
    # =========================================================================

    def mutate_field(
        self,
        data: bytes,
        field_name: str,
        parsed: ParsedStructure,
        fix_checksums: bool = True
    ) -> StructuredMutation:
        """Mutate a specific field in the data."""
        data = bytearray(data)

        # Find the field
        target_field = None
        for pf in parsed.header_fields:
            if pf.field.name == field_name:
                target_field = pf
                break

        if not target_field:
            # Check chunks
            for chunk in parsed.chunks:
                for pf in chunk.fields:
                    if pf.field.name == field_name:
                        target_field = pf
                        target_field.offset = chunk.offset + pf.field.offset
                        break
                if target_field:
                    break

        if not target_field:
            return StructuredMutation(
                original=bytes(data),
                mutated=bytes(data),
                mutation_type="no_mutation",
                details={"error": f"Field {field_name} not found"},
            )

        # Apply mutation based on field type
        mutated_value = self._mutate_value(target_field)

        # Write mutated value
        data[target_field.offset:target_field.offset + target_field.field.size] = mutated_value

        checksum_fixed = False
        if fix_checksums:
            checksum_fixed = self._fix_all_checksums(data, parsed)

        return StructuredMutation(
            original=bytes(data),
            mutated=bytes(data),
            mutation_type="field_mutation",
            field_mutated=field_name,
            checksum_fixed=checksum_fixed,
            details={
                "original_value": target_field.value,
                "field_offset": target_field.offset,
            },
        )

    def _mutate_value(self, parsed_field: ParsedField) -> bytes:
        """Generate a mutated value for a field."""
        field = parsed_field.field
        raw = parsed_field.raw_bytes

        mutation_type = random.choice(["flip", "interesting", "random", "boundary"])

        if mutation_type == "flip":
            # Bit/byte flip
            result = bytearray(raw)
            if random.random() < 0.5:
                pos = random.randint(0, len(result) - 1)
                bit = random.randint(0, 7)
                result[pos] ^= (1 << bit)
            else:
                pos = random.randint(0, len(result) - 1)
                result[pos] ^= 0xFF
            return bytes(result)

        elif mutation_type == "interesting":
            # Replace with interesting values
            if field.field_type in (FieldType.UINT8, FieldType.INT8):
                values = [0, 1, 0x7F, 0x80, 0xFF]
                return bytes([random.choice(values)])
            elif field.field_type in (FieldType.UINT16, FieldType.UINT16_BE, FieldType.INT16):
                values = [0, 1, 0x7FFF, 0x8000, 0xFFFF]
                fmt = ">H" if field.field_type == FieldType.UINT16_BE else "<H"
                return struct.pack(fmt, random.choice(values))
            elif field.field_type in (FieldType.UINT32, FieldType.UINT32_BE, FieldType.INT32, FieldType.CRC32):
                values = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
                fmt = ">I" if field.field_type == FieldType.UINT32_BE else "<I"
                return struct.pack(fmt, random.choice(values))
            else:
                return bytes([random.randint(0, 255) for _ in range(len(raw))])

        elif mutation_type == "boundary":
            # Test boundary conditions
            if field.field_type in (FieldType.UINT8, FieldType.INT8):
                return bytes([random.choice([0, 255])])
            elif field.field_type in (FieldType.UINT16, FieldType.UINT16_BE):
                fmt = ">H" if field.field_type == FieldType.UINT16_BE else "<H"
                return struct.pack(fmt, random.choice([0, 65535]))
            elif field.field_type in (FieldType.UINT32, FieldType.UINT32_BE):
                fmt = ">I" if field.field_type == FieldType.UINT32_BE else "<I"
                return struct.pack(fmt, random.choice([0, 0xFFFFFFFF]))
            else:
                return bytes([random.choice([0, 255]) for _ in range(len(raw))])

        else:  # random
            return bytes([random.randint(0, 255) for _ in range(len(raw))])

    def mutate_chunk(
        self,
        data: bytes,
        chunk_index: int,
        parsed: ParsedStructure,
        fix_checksums: bool = True
    ) -> StructuredMutation:
        """Mutate a specific chunk."""
        if chunk_index >= len(parsed.chunks):
            return StructuredMutation(
                original=data,
                mutated=data,
                mutation_type="no_mutation",
                details={"error": f"Chunk index {chunk_index} out of range"},
            )

        data = bytearray(data)
        chunk = parsed.chunks[chunk_index]

        # Choose mutation strategy
        strategy = random.choice(["mutate_data", "corrupt_type", "change_size"])

        if strategy == "mutate_data" and chunk.data:
            # Mutate chunk data
            start = chunk.offset + 8  # After length and type
            end = start + len(chunk.data)
            mutated_data = self._mutate_bytes(chunk.data)
            data[start:end] = mutated_data

        elif strategy == "corrupt_type":
            # Corrupt chunk type
            type_offset = chunk.offset + 4
            data[type_offset:type_offset+4] = bytes([random.randint(0, 255) for _ in range(4)])

        elif strategy == "change_size":
            # Change size field (will likely break parsing)
            size_offset = chunk.offset
            new_size = random.randint(0, 0xFFFF)
            data[size_offset:size_offset+4] = struct.pack(">I", new_size)

        checksum_fixed = False
        if fix_checksums:
            checksum_fixed = self._fix_all_checksums(data, parsed)

        return StructuredMutation(
            original=bytes(data),
            mutated=bytes(data),
            mutation_type="chunk_mutation",
            chunk_mutated=chunk.chunk.name,
            checksum_fixed=checksum_fixed,
            details={"strategy": strategy},
        )

    def _mutate_bytes(self, data: bytes) -> bytes:
        """Apply random mutations to bytes."""
        result = bytearray(data)

        num_mutations = random.randint(1, max(1, len(data) // 10))
        for _ in range(num_mutations):
            if not result:
                break

            mutation = random.choice(["flip", "insert", "delete", "replace"])

            if mutation == "flip":
                pos = random.randint(0, len(result) - 1)
                result[pos] ^= random.randint(1, 255)

            elif mutation == "insert" and len(result) < len(data) * 2:
                pos = random.randint(0, len(result))
                result.insert(pos, random.randint(0, 255))

            elif mutation == "delete" and len(result) > 1:
                pos = random.randint(0, len(result) - 1)
                del result[pos]

            elif mutation == "replace":
                pos = random.randint(0, len(result) - 1)
                result[pos] = random.randint(0, 255)

        return bytes(result)

    # =========================================================================
    # Checksum and Size Handling
    # =========================================================================

    def fix_checksums(self, data: bytes, format_type: Optional[FormatType] = None) -> bytes:
        """Fix all checksums in the data."""
        if format_type is None:
            format_type = self.detect_format(data)

        parsed = self.parse_structure(data, format_type)
        data = bytearray(data)
        self._fix_all_checksums(data, parsed)
        return bytes(data)

    def _fix_all_checksums(self, data: bytearray, parsed: ParsedStructure) -> bool:
        """Fix all checksums in place."""
        fixed = False

        if parsed.structure.format_type == FormatType.PNG:
            fixed = self._fix_png_checksums(data, parsed)
        elif parsed.structure.format_type == FormatType.ZIP:
            fixed = self._fix_zip_checksum(data, parsed)

        return fixed

    def _fix_png_checksums(self, data: bytearray, parsed: ParsedStructure) -> bool:
        """Fix PNG chunk CRCs."""
        fixed = False

        for chunk in parsed.chunks:
            # Calculate CRC over type + data
            type_offset = chunk.offset + 4
            data_end = chunk.offset + 8 + (chunk.size - 12)
            crc_data = bytes(data[type_offset:data_end])

            new_crc = zlib.crc32(crc_data) & 0xFFFFFFFF
            crc_offset = data_end

            if crc_offset + 4 <= len(data):
                data[crc_offset:crc_offset+4] = struct.pack(">I", new_crc)
                fixed = True

        return fixed

    def _fix_zip_checksum(self, data: bytearray, parsed: ParsedStructure) -> bool:
        """Fix ZIP CRC32."""
        # Find the CRC32 field and compressed data
        crc_field = None
        for pf in parsed.header_fields:
            if pf.field.name == "crc32":
                crc_field = pf
                break

        if not crc_field:
            return False

        # For simplicity, recalculate based on uncompressed data
        # In a real implementation, we'd need to locate the actual file data
        return False  # Not implemented for simplicity

    def fix_size_fields(self, data: bytes, parsed: ParsedStructure) -> bytes:
        """Fix size fields to match actual data."""
        data = bytearray(data)

        for size_field, data_field in parsed.structure.size_fields.items():
            # Find the size field
            for pf in parsed.header_fields:
                if pf.field.name == size_field:
                    # Calculate actual size and update
                    # This is format-specific and simplified here
                    break

        return bytes(data)

    # =========================================================================
    # Sample Generation
    # =========================================================================

    def generate_valid_sample(self, format_type: FormatType) -> bytes:
        """Generate a minimal valid sample of a format."""
        if format_type == FormatType.PNG:
            return self._generate_minimal_png()
        elif format_type == FormatType.ZIP:
            return self._generate_minimal_zip()
        elif format_type == FormatType.PDF:
            return self._generate_minimal_pdf()
        elif format_type == FormatType.GIF:
            return self._generate_minimal_gif()
        else:
            return b""

    def _generate_minimal_png(self) -> bytes:
        """Generate a minimal 1x1 PNG."""
        # PNG signature
        data = bytearray(b"\x89PNG\r\n\x1a\n")

        # IHDR chunk (1x1 RGB)
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)  # width, height, bit_depth, color_type, compression, filter, interlace
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF
        data += struct.pack(">I", 13)  # length
        data += b"IHDR"
        data += ihdr_data
        data += struct.pack(">I", ihdr_crc)

        # IDAT chunk (compressed pixel data for 1x1 red pixel)
        pixel_data = zlib.compress(b"\x00\xff\x00\x00")  # filter byte + RGB
        idat_crc = zlib.crc32(b"IDAT" + pixel_data) & 0xFFFFFFFF
        data += struct.pack(">I", len(pixel_data))
        data += b"IDAT"
        data += pixel_data
        data += struct.pack(">I", idat_crc)

        # IEND chunk
        iend_crc = zlib.crc32(b"IEND") & 0xFFFFFFFF
        data += struct.pack(">I", 0)
        data += b"IEND"
        data += struct.pack(">I", iend_crc)

        return bytes(data)

    def _generate_minimal_zip(self) -> bytes:
        """Generate a minimal ZIP with one empty file."""
        data = bytearray()

        filename = b"test.txt"
        file_data = b""

        # Local file header
        data += b"PK\x03\x04"  # signature
        data += struct.pack("<H", 20)  # version needed
        data += struct.pack("<H", 0)   # flags
        data += struct.pack("<H", 0)   # compression (none)
        data += struct.pack("<H", 0)   # mod time
        data += struct.pack("<H", 0)   # mod date
        data += struct.pack("<I", zlib.crc32(file_data))  # crc32
        data += struct.pack("<I", len(file_data))  # compressed size
        data += struct.pack("<I", len(file_data))  # uncompressed size
        data += struct.pack("<H", len(filename))  # filename length
        data += struct.pack("<H", 0)  # extra field length
        data += filename
        data += file_data

        local_header_offset = 0

        # Central directory header
        cd_start = len(data)
        data += b"PK\x01\x02"  # signature
        data += struct.pack("<H", 20)  # version made by
        data += struct.pack("<H", 20)  # version needed
        data += struct.pack("<H", 0)   # flags
        data += struct.pack("<H", 0)   # compression
        data += struct.pack("<H", 0)   # mod time
        data += struct.pack("<H", 0)   # mod date
        data += struct.pack("<I", zlib.crc32(file_data))  # crc32
        data += struct.pack("<I", len(file_data))  # compressed size
        data += struct.pack("<I", len(file_data))  # uncompressed size
        data += struct.pack("<H", len(filename))  # filename length
        data += struct.pack("<H", 0)   # extra field length
        data += struct.pack("<H", 0)   # comment length
        data += struct.pack("<H", 0)   # disk number
        data += struct.pack("<H", 0)   # internal attrs
        data += struct.pack("<I", 0)   # external attrs
        data += struct.pack("<I", local_header_offset)  # offset
        data += filename
        cd_end = len(data)

        # End of central directory
        data += b"PK\x05\x06"  # signature
        data += struct.pack("<H", 0)   # disk number
        data += struct.pack("<H", 0)   # disk with cd
        data += struct.pack("<H", 1)   # entries on disk
        data += struct.pack("<H", 1)   # total entries
        data += struct.pack("<I", cd_end - cd_start)  # cd size
        data += struct.pack("<I", cd_start)  # cd offset
        data += struct.pack("<H", 0)   # comment length

        return bytes(data)

    def _generate_minimal_pdf(self) -> bytes:
        """Generate a minimal PDF."""
        pdf = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
193
%%EOF"""
        return pdf

    def _generate_minimal_gif(self) -> bytes:
        """Generate a minimal 1x1 GIF."""
        data = bytearray()

        # Header
        data += b"GIF89a"

        # Logical screen descriptor
        data += struct.pack("<H", 1)   # width
        data += struct.pack("<H", 1)   # height
        data += bytes([0x80, 0, 0])    # packed byte, bg color, aspect ratio

        # Global color table (2 colors)
        data += b"\x00\x00\x00"  # black
        data += b"\xff\xff\xff"  # white

        # Image descriptor
        data += b"\x2c"  # image separator
        data += struct.pack("<H", 0)   # left
        data += struct.pack("<H", 0)   # top
        data += struct.pack("<H", 1)   # width
        data += struct.pack("<H", 1)   # height
        data += bytes([0])  # packed byte

        # Image data
        data += bytes([1])  # LZW minimum code size
        data += bytes([1, 0x44, 0])  # data sub-block and terminator

        # Trailer
        data += b"\x3b"

        return bytes(data)

    # =========================================================================
    # Fuzzing Session
    # =========================================================================

    async def fuzz_format(
        self,
        seed: bytes,
        format_type: Optional[FormatType] = None,
        config: Optional[FormatFuzzConfig] = None,
        count: int = 100,
    ) -> AsyncGenerator[StructuredMutation, None]:
        """Run a structure-aware fuzzing session."""
        if format_type is None:
            format_type = self.detect_format(seed)

        if config is None:
            config = FormatFuzzConfig(format_type=format_type)

        parsed = self.parse_structure(seed, format_type)

        for i in range(count):
            data = bytearray(seed)

            # Choose mutation strategy
            if parsed.chunks and random.random() < 0.5:
                # Chunk mutation
                chunk_idx = random.randint(0, len(parsed.chunks) - 1)
                mutation = self.mutate_chunk(bytes(data), chunk_idx, parsed, config.fix_checksums)
            else:
                # Field mutation
                all_fields = [pf.field.name for pf in parsed.header_fields]
                for chunk in parsed.chunks:
                    all_fields.extend(pf.field.name for pf in chunk.fields if not pf.field.is_checksum)

                if config.target_fields:
                    fields = [f for f in all_fields if f in config.target_fields]
                else:
                    fields = [f for f in all_fields if f not in parsed.structure.checksum_fields]

                if fields:
                    field_name = random.choice(fields)
                    mutation = self.mutate_field(bytes(data), field_name, parsed, config.fix_checksums)
                else:
                    # Fall back to random byte mutation
                    mutated = self._mutate_bytes(seed)
                    if config.fix_checksums:
                        mutated = self.fix_checksums(mutated, format_type)
                    mutation = StructuredMutation(
                        original=seed,
                        mutated=mutated,
                        mutation_type="random",
                    )

            mutation.details["iteration"] = i + 1
            mutation.details["total"] = count

            yield mutation


# =============================================================================
# Helper Functions
# =============================================================================

def list_supported_formats() -> Dict[str, str]:
    """List all supported file formats."""
    return {
        fmt.value: FORMAT_STRUCTURES.get(fmt, FormatStructure(name=fmt.value, format_type=fmt)).description
        for fmt in FormatType
        if fmt != FormatType.UNKNOWN
    }


def detect_format(data: bytes) -> FormatType:
    """Detect file format from data."""
    service = StructuredFormatService()
    return service.detect_format(data)


def generate_sample(format_type: str) -> bytes:
    """Generate a minimal valid sample of a format."""
    service = StructuredFormatService()
    return service.generate_valid_sample(FormatType(format_type))
