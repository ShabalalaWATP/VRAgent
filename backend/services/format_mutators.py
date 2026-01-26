"""
Format-Specific Mutators

Specialized mutators for common file formats that understand internal structure
and can generate more effective fuzzing inputs.
"""

import random
import struct
import zlib
import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# Base Mutator
# =============================================================================

@dataclass
class MutationResult:
    """Result of a mutation operation."""
    original: bytes
    mutated: bytes
    mutation_name: str
    description: str
    locations_modified: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class FormatMutator(ABC):
    """Base class for format-specific mutators."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Name of the format this mutator handles."""
        pass

    @abstractmethod
    def validate(self, data: bytes) -> bool:
        """Check if data is valid for this format."""
        pass

    @abstractmethod
    def get_mutations(self) -> List[str]:
        """Get list of available mutation types."""
        pass

    @abstractmethod
    def mutate(self, data: bytes, mutation_type: Optional[str] = None) -> MutationResult:
        """Apply a mutation to the data."""
        pass

    def mutate_random(self, data: bytes, count: int = 1) -> List[MutationResult]:
        """Apply random mutations."""
        results = []
        mutations = self.get_mutations()
        for _ in range(count):
            mutation_type = random.choice(mutations)
            results.append(self.mutate(data, mutation_type))
        return results


# =============================================================================
# PNG Mutator
# =============================================================================

class PNGMutator(FormatMutator):
    """PNG-specific mutations respecting chunk structure."""

    PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

    # Standard chunk types
    CRITICAL_CHUNKS = [b"IHDR", b"PLTE", b"IDAT", b"IEND"]
    ANCILLARY_CHUNKS = [b"tEXt", b"zTXt", b"iTXt", b"cHRM", b"gAMA", b"iCCP",
                        b"sBIT", b"sRGB", b"bKGD", b"hIST", b"tRNS", b"pHYs",
                        b"sPLT", b"tIME"]

    @property
    def format_name(self) -> str:
        return "PNG"

    def validate(self, data: bytes) -> bool:
        return data.startswith(self.PNG_SIGNATURE) and len(data) > 8

    def get_mutations(self) -> List[str]:
        return [
            "mutate_ihdr",
            "mutate_idat",
            "inject_chunk",
            "corrupt_crc",
            "corrupt_length",
            "duplicate_chunk",
            "remove_chunk",
            "reorder_chunks",
            "inject_invalid_chunk",
            "overflow_dimensions",
            "corrupt_filter_bytes",
        ]

    def mutate(self, data: bytes, mutation_type: Optional[str] = None) -> MutationResult:
        if not self.validate(data):
            return MutationResult(data, data, "invalid", "Data is not valid PNG")

        if mutation_type is None:
            mutation_type = random.choice(self.get_mutations())

        method = getattr(self, mutation_type, None)
        if method and callable(method):
            return method(data)
        else:
            return MutationResult(data, data, "unknown", f"Unknown mutation: {mutation_type}")

    def _parse_chunks(self, data: bytes) -> List[Tuple[int, bytes, bytes, bytes]]:
        """Parse PNG chunks. Returns list of (offset, length_bytes, type, data+crc)."""
        chunks = []
        offset = 8  # Skip signature

        while offset + 12 <= len(data):
            length_bytes = data[offset:offset+4]
            length = struct.unpack(">I", length_bytes)[0]
            chunk_type = data[offset+4:offset+8]
            chunk_data_and_crc = data[offset+8:offset+8+length+4]

            chunks.append((offset, length_bytes, chunk_type, chunk_data_and_crc))
            offset += 12 + length

            if chunk_type == b"IEND":
                break

        return chunks

    def _rebuild_png(self, chunks: List[Tuple[bytes, bytes, bytes]]) -> bytes:
        """Rebuild PNG from chunks. Each chunk is (type, data, crc_or_none)."""
        result = bytearray(self.PNG_SIGNATURE)

        for chunk_type, chunk_data, crc in chunks:
            length = len(chunk_data)
            result += struct.pack(">I", length)
            result += chunk_type
            result += chunk_data

            if crc is None:
                # Calculate CRC
                calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                result += struct.pack(">I", calc_crc)
            else:
                result += crc

        return bytes(result)

    def mutate_ihdr(self, data: bytes) -> MutationResult:
        """Mutate IHDR chunk (image header)."""
        chunks = self._parse_chunks(data)
        if not chunks:
            return MutationResult(data, data, "mutate_ihdr", "No chunks found")

        result = bytearray(data)
        for offset, _, chunk_type, chunk_data_crc in chunks:
            if chunk_type == b"IHDR":
                # IHDR structure: width(4) height(4) bit_depth(1) color_type(1) compression(1) filter(1) interlace(1)
                data_start = offset + 8

                mutation = random.choice(["width", "height", "bit_depth", "color_type"])

                if mutation == "width":
                    new_val = random.choice([0, 1, 0xFFFFFFFF, random.randint(10000, 100000)])
                    result[data_start:data_start+4] = struct.pack(">I", new_val)
                elif mutation == "height":
                    new_val = random.choice([0, 1, 0xFFFFFFFF, random.randint(10000, 100000)])
                    result[data_start+4:data_start+8] = struct.pack(">I", new_val)
                elif mutation == "bit_depth":
                    new_val = random.choice([0, 3, 5, 7, 9, 17, 255])
                    result[data_start+8] = new_val
                elif mutation == "color_type":
                    new_val = random.choice([1, 5, 7, 8, 255])
                    result[data_start+9] = new_val

                # Fix CRC
                crc_offset = offset + 8 + 13
                new_crc = zlib.crc32(result[offset+4:crc_offset]) & 0xFFFFFFFF
                result[crc_offset:crc_offset+4] = struct.pack(">I", new_crc)

                return MutationResult(
                    data, bytes(result), "mutate_ihdr",
                    f"Modified {mutation} in IHDR",
                    locations_modified=[data_start],
                )

        return MutationResult(data, data, "mutate_ihdr", "IHDR chunk not found")

    def mutate_idat(self, data: bytes) -> MutationResult:
        """Mutate IDAT chunk (image data)."""
        chunks = self._parse_chunks(data)
        result = bytearray(data)

        for offset, length_bytes, chunk_type, chunk_data_crc in chunks:
            if chunk_type == b"IDAT":
                length = struct.unpack(">I", length_bytes)[0]
                if length == 0:
                    continue

                data_start = offset + 8
                data_end = data_start + length

                # Mutate compressed data
                mutation = random.choice(["flip_byte", "insert_bytes", "truncate"])

                if mutation == "flip_byte":
                    pos = random.randint(data_start, data_end - 1)
                    result[pos] ^= random.randint(1, 255)
                elif mutation == "insert_bytes":
                    pos = random.randint(data_start, data_end)
                    insert_data = bytes([random.randint(0, 255) for _ in range(random.randint(1, 10))])
                    result = result[:pos] + insert_data + result[pos:]
                elif mutation == "truncate":
                    cut_point = random.randint(data_start, data_end)
                    result = result[:cut_point] + result[data_end:]

                return MutationResult(
                    data, bytes(result), "mutate_idat",
                    f"Applied {mutation} to IDAT",
                    locations_modified=[data_start],
                )

        return MutationResult(data, data, "mutate_idat", "IDAT chunk not found")

    def inject_chunk(self, data: bytes, chunk_type: Optional[bytes] = None) -> MutationResult:
        """Inject a new chunk into the PNG."""
        if chunk_type is None:
            chunk_type = random.choice([
                b"tEXt", b"zTXt", b"iTXt",  # Text chunks
                bytes([random.randint(65, 90) for _ in range(4)]),  # Random uppercase
                bytes([random.randint(97, 122) for _ in range(4)]),  # Random lowercase
            ])

        # Generate random chunk data
        chunk_data = bytes([random.randint(0, 255) for _ in range(random.randint(0, 100))])
        crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        # Find insertion point (after IHDR, before IEND)
        chunks = self._parse_chunks(data)
        insert_after = 0

        for i, (offset, _, ctype, _) in enumerate(chunks):
            if ctype == b"IHDR":
                insert_after = i
                break

        if insert_after < len(chunks) - 1:
            insert_offset = chunks[insert_after + 1][0]
        else:
            insert_offset = len(data)

        # Build new chunk
        new_chunk = struct.pack(">I", len(chunk_data)) + chunk_type + chunk_data + struct.pack(">I", crc)

        result = data[:insert_offset] + new_chunk + data[insert_offset:]

        return MutationResult(
            data, result, "inject_chunk",
            f"Injected {chunk_type.decode('ascii', errors='replace')} chunk",
            locations_modified=[insert_offset],
            metadata={"chunk_type": chunk_type.decode('ascii', errors='replace')},
        )

    def corrupt_crc(self, data: bytes) -> MutationResult:
        """Corrupt a chunk's CRC."""
        chunks = self._parse_chunks(data)
        if not chunks:
            return MutationResult(data, data, "corrupt_crc", "No chunks found")

        result = bytearray(data)

        # Pick random chunk to corrupt
        idx = random.randint(0, len(chunks) - 1)
        offset, length_bytes, chunk_type, _ = chunks[idx]
        length = struct.unpack(">I", length_bytes)[0]

        crc_offset = offset + 8 + length
        if crc_offset + 4 <= len(result):
            # Flip some bits in CRC
            for i in range(4):
                if random.random() < 0.5:
                    result[crc_offset + i] ^= random.randint(1, 255)

        return MutationResult(
            data, bytes(result), "corrupt_crc",
            f"Corrupted CRC of {chunk_type.decode('ascii', errors='replace')} chunk",
            locations_modified=[crc_offset],
        )

    def corrupt_length(self, data: bytes) -> MutationResult:
        """Corrupt a chunk's length field."""
        chunks = self._parse_chunks(data)
        if not chunks:
            return MutationResult(data, data, "corrupt_length", "No chunks found")

        result = bytearray(data)

        idx = random.randint(0, len(chunks) - 1)
        offset, _, chunk_type, _ = chunks[idx]

        # Set length to an interesting value
        new_length = random.choice([
            0, 1, 0xFFFFFFFF, 0x7FFFFFFF,
            random.randint(1000000, 10000000),
        ])

        result[offset:offset+4] = struct.pack(">I", new_length)

        return MutationResult(
            data, bytes(result), "corrupt_length",
            f"Set {chunk_type.decode('ascii', errors='replace')} length to {new_length}",
            locations_modified=[offset],
        )

    def duplicate_chunk(self, data: bytes) -> MutationResult:
        """Duplicate a chunk."""
        chunks = self._parse_chunks(data)
        if len(chunks) < 2:
            return MutationResult(data, data, "duplicate_chunk", "Not enough chunks")

        # Pick a non-IEND chunk to duplicate
        valid_chunks = [(i, c) for i, c in enumerate(chunks) if c[2] != b"IEND"]
        if not valid_chunks:
            return MutationResult(data, data, "duplicate_chunk", "No duplicatable chunks")

        idx, (offset, length_bytes, chunk_type, chunk_data_crc) = random.choice(valid_chunks)
        length = struct.unpack(">I", length_bytes)[0]

        # Get full chunk data
        chunk_full = data[offset:offset + 12 + length]

        # Insert after the original
        insert_offset = offset + 12 + length
        result = data[:insert_offset] + chunk_full + data[insert_offset:]

        return MutationResult(
            data, result, "duplicate_chunk",
            f"Duplicated {chunk_type.decode('ascii', errors='replace')} chunk",
            locations_modified=[insert_offset],
        )

    def remove_chunk(self, data: bytes) -> MutationResult:
        """Remove a chunk (not IHDR or IEND)."""
        chunks = self._parse_chunks(data)

        # Find removable chunks
        removable = [(i, c) for i, c in enumerate(chunks) if c[2] not in [b"IHDR", b"IEND"]]
        if not removable:
            return MutationResult(data, data, "remove_chunk", "No removable chunks")

        idx, (offset, length_bytes, chunk_type, _) = random.choice(removable)
        length = struct.unpack(">I", length_bytes)[0]

        result = data[:offset] + data[offset + 12 + length:]

        return MutationResult(
            data, result, "remove_chunk",
            f"Removed {chunk_type.decode('ascii', errors='replace')} chunk",
            locations_modified=[offset],
        )

    def reorder_chunks(self, data: bytes) -> MutationResult:
        """Reorder chunks (may break format)."""
        chunks = self._parse_chunks(data)
        if len(chunks) < 3:
            return MutationResult(data, data, "reorder_chunks", "Not enough chunks")

        # Keep IHDR first and IEND last, shuffle middle
        middle_chunks = []
        for offset, length_bytes, chunk_type, chunk_data_crc in chunks:
            if chunk_type not in [b"IHDR", b"IEND"]:
                length = struct.unpack(">I", length_bytes)[0]
                full_chunk = data[offset:offset + 12 + length]
                middle_chunks.append((chunk_type, full_chunk))

        random.shuffle(middle_chunks)

        # Rebuild
        result = bytearray(self.PNG_SIGNATURE)

        # Add IHDR
        for offset, length_bytes, chunk_type, _ in chunks:
            if chunk_type == b"IHDR":
                length = struct.unpack(">I", length_bytes)[0]
                result += data[offset:offset + 12 + length]
                break

        # Add shuffled middle chunks
        for _, chunk_data in middle_chunks:
            result += chunk_data

        # Add IEND
        for offset, length_bytes, chunk_type, _ in chunks:
            if chunk_type == b"IEND":
                length = struct.unpack(">I", length_bytes)[0]
                result += data[offset:offset + 12 + length]
                break

        return MutationResult(
            data, bytes(result), "reorder_chunks",
            "Reordered middle chunks",
        )

    def inject_invalid_chunk(self, data: bytes) -> MutationResult:
        """Inject a chunk with invalid type."""
        invalid_types = [
            b"\x00\x00\x00\x00",
            b"\xff\xff\xff\xff",
            b"AAAA",
            b"xxxx",
            bytes([random.randint(0, 255) for _ in range(4)]),
        ]

        return self.inject_chunk(data, random.choice(invalid_types))

    def overflow_dimensions(self, data: bytes) -> MutationResult:
        """Set extremely large dimensions in IHDR."""
        chunks = self._parse_chunks(data)
        result = bytearray(data)

        for offset, _, chunk_type, _ in chunks:
            if chunk_type == b"IHDR":
                data_start = offset + 8

                # Set width and height to huge values
                width = 0x7FFFFFFF
                height = 0x7FFFFFFF

                result[data_start:data_start+4] = struct.pack(">I", width)
                result[data_start+4:data_start+8] = struct.pack(">I", height)

                # Fix CRC
                crc_offset = offset + 8 + 13
                new_crc = zlib.crc32(result[offset+4:crc_offset]) & 0xFFFFFFFF
                result[crc_offset:crc_offset+4] = struct.pack(">I", new_crc)

                return MutationResult(
                    data, bytes(result), "overflow_dimensions",
                    f"Set dimensions to {width}x{height}",
                    locations_modified=[data_start],
                )

        return MutationResult(data, data, "overflow_dimensions", "IHDR not found")

    def corrupt_filter_bytes(self, data: bytes) -> MutationResult:
        """Corrupt filter bytes in IDAT (after decompression conceptually)."""
        # This corrupts the compressed data which may affect filter bytes
        return self.mutate_idat(data)


# =============================================================================
# PDF Mutator
# =============================================================================

class PDFMutator(FormatMutator):
    """PDF-specific mutations respecting object structure."""

    @property
    def format_name(self) -> str:
        return "PDF"

    def validate(self, data: bytes) -> bool:
        return data.startswith(b"%PDF-")

    def get_mutations(self) -> List[str]:
        return [
            "mutate_stream",
            "inject_javascript",
            "corrupt_xref",
            "modify_header",
            "inject_object",
            "corrupt_trailer",
            "add_annotation",
            "overflow_object_number",
        ]

    def mutate(self, data: bytes, mutation_type: Optional[str] = None) -> MutationResult:
        if not self.validate(data):
            return MutationResult(data, data, "invalid", "Data is not valid PDF")

        if mutation_type is None:
            mutation_type = random.choice(self.get_mutations())

        method = getattr(self, mutation_type, None)
        if method and callable(method):
            return method(data)
        else:
            return MutationResult(data, data, "unknown", f"Unknown mutation: {mutation_type}")

    def mutate_stream(self, data: bytes) -> MutationResult:
        """Mutate a stream object."""
        # Find stream markers
        stream_start = data.find(b"stream\n")
        if stream_start == -1:
            stream_start = data.find(b"stream\r\n")
        if stream_start == -1:
            return MutationResult(data, data, "mutate_stream", "No stream found")

        stream_end = data.find(b"\nendstream", stream_start)
        if stream_end == -1:
            stream_end = data.find(b"\r\nendstream", stream_start)
        if stream_end == -1:
            return MutationResult(data, data, "mutate_stream", "Stream end not found")

        # Calculate actual stream start (after stream keyword + newline)
        actual_start = stream_start + 7 if data[stream_start:stream_start+8] == b"stream\r\n" else stream_start + 7

        result = bytearray(data)

        # Mutate stream content
        mutation = random.choice(["flip", "insert", "truncate"])

        if mutation == "flip" and actual_start < stream_end:
            pos = random.randint(actual_start, stream_end - 1)
            result[pos] ^= random.randint(1, 255)
        elif mutation == "insert":
            pos = random.randint(actual_start, stream_end)
            insert_data = bytes([random.randint(0, 255) for _ in range(random.randint(1, 20))])
            result = result[:pos] + insert_data + result[pos:]
        elif mutation == "truncate" and stream_end - actual_start > 10:
            cut_point = random.randint(actual_start + 5, stream_end - 5)
            result = result[:cut_point] + result[stream_end:]

        return MutationResult(
            data, bytes(result), "mutate_stream",
            f"Applied {mutation} to stream",
            locations_modified=[actual_start],
        )

    def inject_javascript(self, data: bytes) -> MutationResult:
        """Inject JavaScript code."""
        js_payloads = [
            b"app.alert('XSS');",
            b"this.exportDataObject({cName:'test',nLaunch:2});",
            b"app.launchURL('http://evil.com');",
            b"util.printf('%s%s%s%s%s',1,2,3,4,5);",
            b"this.getAnnots()[0].destroy();",
        ]

        js_code = random.choice(js_payloads)

        # Create a JavaScript action object
        js_object = f"""
999 0 obj
<< /Type /Action /S /JavaScript /JS ({js_code.decode('ascii', errors='replace')}) >>
endobj
""".encode()

        # Find a good insertion point (before xref)
        xref_pos = data.rfind(b"xref")
        if xref_pos == -1:
            insert_pos = len(data) - 20
        else:
            insert_pos = xref_pos

        result = data[:insert_pos] + js_object + data[insert_pos:]

        return MutationResult(
            data, result, "inject_javascript",
            "Injected JavaScript action object",
            locations_modified=[insert_pos],
            metadata={"js_code": js_code.decode('ascii', errors='replace')},
        )

    def corrupt_xref(self, data: bytes) -> MutationResult:
        """Corrupt cross-reference table."""
        xref_pos = data.rfind(b"xref")
        if xref_pos == -1:
            return MutationResult(data, data, "corrupt_xref", "No xref found")

        result = bytearray(data)

        # Find xref entries and corrupt them
        entry_start = data.find(b"\n", xref_pos) + 1
        entry_end = data.find(b"trailer", entry_start)

        if entry_start > 0 and entry_end > entry_start:
            # Corrupt some bytes in the xref
            for _ in range(random.randint(1, 5)):
                pos = random.randint(entry_start, entry_end - 1)
                if result[pos] not in [ord('\n'), ord('\r')]:
                    result[pos] = random.randint(ord('0'), ord('9'))

        return MutationResult(
            data, bytes(result), "corrupt_xref",
            "Corrupted xref table entries",
            locations_modified=[entry_start],
        )

    def modify_header(self, data: bytes) -> MutationResult:
        """Modify PDF header version."""
        versions = [b"%PDF-1.0", b"%PDF-1.1", b"%PDF-1.2", b"%PDF-1.3",
                   b"%PDF-1.4", b"%PDF-1.5", b"%PDF-1.6", b"%PDF-1.7",
                   b"%PDF-2.0", b"%PDF-9.9", b"%PDF-0.0"]

        new_version = random.choice(versions)
        result = new_version + data[8:]

        return MutationResult(
            data, result, "modify_header",
            f"Changed version to {new_version.decode()}",
            locations_modified=[0],
        )

    def inject_object(self, data: bytes) -> MutationResult:
        """Inject a malformed object."""
        malformed_objects = [
            b"999 0 obj\n<< /A (" + b"A" * 10000 + b") >>\nendobj\n",
            b"999 0 obj\n<< /Length -1 >>\nstream\nAAAA\nendstream\nendobj\n",
            b"999 0 obj\n<< /Type /XObject /Subtype /Image /Width 999999999 /Height 999999999 >>\nendobj\n",
            b"999 0 obj\n" + b"<" * 1000 + b">>\nendobj\n",
        ]

        obj = random.choice(malformed_objects)

        xref_pos = data.rfind(b"xref")
        insert_pos = xref_pos if xref_pos > 0 else len(data) - 20

        result = data[:insert_pos] + obj + data[insert_pos:]

        return MutationResult(
            data, result, "inject_object",
            "Injected malformed object",
            locations_modified=[insert_pos],
        )

    def corrupt_trailer(self, data: bytes) -> MutationResult:
        """Corrupt trailer dictionary."""
        trailer_pos = data.rfind(b"trailer")
        if trailer_pos == -1:
            return MutationResult(data, data, "corrupt_trailer", "No trailer found")

        result = bytearray(data)

        # Find and corrupt values in trailer
        dict_start = data.find(b"<<", trailer_pos)
        dict_end = data.find(b">>", dict_start)

        if dict_start > 0 and dict_end > dict_start:
            # Replace some numbers with large values
            for i in range(dict_start, dict_end):
                if chr(result[i]).isdigit():
                    result[i] = ord('9')

        return MutationResult(
            data, bytes(result), "corrupt_trailer",
            "Corrupted trailer dictionary values",
            locations_modified=[dict_start],
        )

    def add_annotation(self, data: bytes) -> MutationResult:
        """Add a malicious annotation."""
        annotation = b"""
999 0 obj
<< /Type /Annot /Subtype /Link /Rect [0 0 100 100]
   /A << /Type /Action /S /URI /URI (javascript:alert(1)) >> >>
endobj
"""
        xref_pos = data.rfind(b"xref")
        insert_pos = xref_pos if xref_pos > 0 else len(data) - 20

        result = data[:insert_pos] + annotation + data[insert_pos:]

        return MutationResult(
            data, result, "add_annotation",
            "Added malicious annotation",
            locations_modified=[insert_pos],
        )

    def overflow_object_number(self, data: bytes) -> MutationResult:
        """Use very large object numbers."""
        large_obj = b"999999999 0 obj\n<< /Type /Test >>\nendobj\n"

        xref_pos = data.rfind(b"xref")
        insert_pos = xref_pos if xref_pos > 0 else len(data) - 20

        result = data[:insert_pos] + large_obj + data[insert_pos:]

        return MutationResult(
            data, result, "overflow_object_number",
            "Injected object with very large number",
            locations_modified=[insert_pos],
        )


# =============================================================================
# ZIP Mutator
# =============================================================================

class ZIPMutator(FormatMutator):
    """ZIP-specific mutations."""

    LOCAL_FILE_HEADER_SIG = b"PK\x03\x04"
    CENTRAL_DIR_SIG = b"PK\x01\x02"
    END_CENTRAL_DIR_SIG = b"PK\x05\x06"

    @property
    def format_name(self) -> str:
        return "ZIP"

    def validate(self, data: bytes) -> bool:
        return data.startswith(self.LOCAL_FILE_HEADER_SIG)

    def get_mutations(self) -> List[str]:
        return [
            "mutate_local_header",
            "mutate_central_directory",
            "inject_zip_slip",
            "corrupt_compression",
            "corrupt_crc",
            "overflow_sizes",
            "duplicate_entry",
            "inject_symlink",
        ]

    def mutate(self, data: bytes, mutation_type: Optional[str] = None) -> MutationResult:
        if not self.validate(data):
            return MutationResult(data, data, "invalid", "Data is not valid ZIP")

        if mutation_type is None:
            mutation_type = random.choice(self.get_mutations())

        method = getattr(self, mutation_type, None)
        if method and callable(method):
            return method(data)
        else:
            return MutationResult(data, data, "unknown", f"Unknown mutation: {mutation_type}")

    def mutate_local_header(self, data: bytes) -> MutationResult:
        """Mutate local file header fields."""
        if len(data) < 30:
            return MutationResult(data, data, "mutate_local_header", "Data too short")

        result = bytearray(data)

        # Choose field to mutate
        field = random.choice(["version", "flags", "compression", "crc", "sizes"])

        if field == "version":
            result[4:6] = struct.pack("<H", random.choice([0, 1, 999, 0xFFFF]))
        elif field == "flags":
            result[6:8] = struct.pack("<H", random.randint(0, 0xFFFF))
        elif field == "compression":
            result[8:10] = struct.pack("<H", random.choice([0, 1, 8, 99, 255, 0xFFFF]))
        elif field == "crc":
            result[14:18] = struct.pack("<I", random.randint(0, 0xFFFFFFFF))
        elif field == "sizes":
            result[18:22] = struct.pack("<I", random.choice([0, 0xFFFFFFFF]))
            result[22:26] = struct.pack("<I", random.choice([0, 0xFFFFFFFF]))

        return MutationResult(
            data, bytes(result), "mutate_local_header",
            f"Mutated {field} in local header",
            locations_modified=[4 if field == "version" else 6],
        )

    def mutate_central_directory(self, data: bytes) -> MutationResult:
        """Mutate central directory entry."""
        cd_pos = data.find(self.CENTRAL_DIR_SIG)
        if cd_pos == -1:
            return MutationResult(data, data, "mutate_central_directory", "No central directory found")

        result = bytearray(data)

        # Mutate fields in central directory
        field = random.choice(["version_made", "version_needed", "attrs"])

        if field == "version_made":
            result[cd_pos+4:cd_pos+6] = struct.pack("<H", random.randint(0, 0xFFFF))
        elif field == "version_needed":
            result[cd_pos+6:cd_pos+8] = struct.pack("<H", random.randint(0, 0xFFFF))
        elif field == "attrs":
            result[cd_pos+38:cd_pos+42] = struct.pack("<I", random.randint(0, 0xFFFFFFFF))

        return MutationResult(
            data, bytes(result), "mutate_central_directory",
            f"Mutated {field} in central directory",
            locations_modified=[cd_pos],
        )

    def inject_zip_slip(self, data: bytes) -> MutationResult:
        """Inject a path traversal filename (Zip Slip vulnerability test)."""
        malicious_paths = [
            b"../../../etc/passwd",
            b"..\\..\\..\\windows\\system32\\config\\sam",
            b"....//....//....//etc/passwd",
            b"..%252f..%252f..%252fetc/passwd",
        ]

        path = random.choice(malicious_paths)

        # Create a new local file header with malicious path
        header = bytearray()
        header += self.LOCAL_FILE_HEADER_SIG
        header += struct.pack("<H", 20)  # version needed
        header += struct.pack("<H", 0)   # flags
        header += struct.pack("<H", 0)   # compression (store)
        header += struct.pack("<H", 0)   # mod time
        header += struct.pack("<H", 0)   # mod date
        header += struct.pack("<I", 0)   # crc32
        header += struct.pack("<I", 0)   # compressed size
        header += struct.pack("<I", 0)   # uncompressed size
        header += struct.pack("<H", len(path))  # filename length
        header += struct.pack("<H", 0)   # extra field length
        header += path

        # Insert after existing local file header
        insert_pos = data.find(self.LOCAL_FILE_HEADER_SIG, 4)
        if insert_pos == -1:
            insert_pos = len(data)

        result = data[:insert_pos] + bytes(header) + data[insert_pos:]

        return MutationResult(
            data, result, "inject_zip_slip",
            f"Injected path traversal: {path.decode('ascii', errors='replace')}",
            locations_modified=[insert_pos],
            metadata={"malicious_path": path.decode('ascii', errors='replace')},
        )

    def corrupt_compression(self, data: bytes) -> MutationResult:
        """Set invalid compression method."""
        if len(data) < 10:
            return MutationResult(data, data, "corrupt_compression", "Data too short")

        result = bytearray(data)
        result[8:10] = struct.pack("<H", random.choice([99, 100, 255, 0xFFFF]))

        return MutationResult(
            data, bytes(result), "corrupt_compression",
            "Set invalid compression method",
            locations_modified=[8],
        )

    def corrupt_crc(self, data: bytes) -> MutationResult:
        """Corrupt CRC32 field."""
        if len(data) < 18:
            return MutationResult(data, data, "corrupt_crc", "Data too short")

        result = bytearray(data)
        result[14:18] = struct.pack("<I", random.randint(0, 0xFFFFFFFF))

        return MutationResult(
            data, bytes(result), "corrupt_crc",
            "Corrupted CRC32 field",
            locations_modified=[14],
        )

    def overflow_sizes(self, data: bytes) -> MutationResult:
        """Set very large sizes to trigger integer overflows."""
        if len(data) < 26:
            return MutationResult(data, data, "overflow_sizes", "Data too short")

        result = bytearray(data)

        # Set extremely large sizes
        result[18:22] = struct.pack("<I", 0xFFFFFFFF)  # compressed size
        result[22:26] = struct.pack("<I", 0xFFFFFFFF)  # uncompressed size

        return MutationResult(
            data, bytes(result), "overflow_sizes",
            "Set maximum size values",
            locations_modified=[18, 22],
        )

    def duplicate_entry(self, data: bytes) -> MutationResult:
        """Duplicate a file entry."""
        # Find end of first local file header
        if len(data) < 30:
            return MutationResult(data, data, "duplicate_entry", "Data too short")

        filename_len = struct.unpack("<H", data[26:28])[0]
        extra_len = struct.unpack("<H", data[28:30])[0]
        compressed_size = struct.unpack("<I", data[18:22])[0]

        entry_end = 30 + filename_len + extra_len + compressed_size

        if entry_end > len(data):
            entry_end = min(100, len(data))

        first_entry = data[:entry_end]
        result = first_entry + data

        return MutationResult(
            data, result, "duplicate_entry",
            "Duplicated first file entry",
            locations_modified=[0],
        )

    def inject_symlink(self, data: bytes) -> MutationResult:
        """Inject a symlink entry (Unix-specific)."""
        # Create entry with Unix symlink external attributes
        header = bytearray()
        header += self.LOCAL_FILE_HEADER_SIG
        header += struct.pack("<H", 10)  # version needed
        header += struct.pack("<H", 0)   # flags
        header += struct.pack("<H", 0)   # compression
        header += struct.pack("<H", 0)   # mod time
        header += struct.pack("<H", 0)   # mod date
        header += struct.pack("<I", 0)   # crc32

        target = b"/etc/passwd"
        filename = b"symlink"

        header += struct.pack("<I", len(target))  # compressed size
        header += struct.pack("<I", len(target))  # uncompressed size
        header += struct.pack("<H", len(filename))  # filename length
        header += struct.pack("<H", 0)   # extra field length
        header += filename
        header += target  # symlink target as content

        insert_pos = data.find(self.CENTRAL_DIR_SIG)
        if insert_pos == -1:
            insert_pos = len(data)

        result = data[:insert_pos] + bytes(header) + data[insert_pos:]

        return MutationResult(
            data, result, "inject_symlink",
            "Injected symlink entry pointing to /etc/passwd",
            locations_modified=[insert_pos],
        )


# =============================================================================
# Mutator Registry
# =============================================================================

MUTATORS: Dict[str, FormatMutator] = {
    "png": PNGMutator(),
    "pdf": PDFMutator(),
    "zip": ZIPMutator(),
}


def get_mutator(format_name: str) -> Optional[FormatMutator]:
    """Get mutator for a format."""
    return MUTATORS.get(format_name.lower())


def list_mutators() -> Dict[str, List[str]]:
    """List all mutators and their mutations."""
    return {
        name: mutator.get_mutations()
        for name, mutator in MUTATORS.items()
    }


def auto_mutate(data: bytes, count: int = 1) -> List[MutationResult]:
    """Auto-detect format and apply mutations."""
    # Try to detect format
    if data.startswith(b"\x89PNG"):
        mutator = MUTATORS["png"]
    elif data.startswith(b"%PDF-"):
        mutator = MUTATORS["pdf"]
    elif data.startswith(b"PK\x03\x04"):
        mutator = MUTATORS["zip"]
    else:
        # Unknown format - return generic mutations
        results = []
        for _ in range(count):
            mutated = bytearray(data)
            pos = random.randint(0, max(0, len(mutated) - 1))
            mutated[pos] ^= random.randint(1, 255)
            results.append(MutationResult(
                data, bytes(mutated), "generic_flip",
                "Generic byte flip (unknown format)",
                locations_modified=[pos],
            ))
        return results

    return mutator.mutate_random(data, count)
