"""
Seed Intelligence Service

AI-powered seed generation for binary fuzzing.
Generates intelligent initial seeds and corpus refinement suggestions.
"""

import base64
import hashlib
import json
import logging
import random
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.services.binary_ai_reasoning import (
    BinaryProfile,
    BinaryAIClient,
    SeedSuggestion,
    InputFormatGuess,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Data Classes
# =============================================================================

class InputFormat(str, Enum):
    """Detected input format types."""
    BINARY = "binary"
    TEXT = "text"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    HTTP = "http"
    IMAGE = "image"
    ARCHIVE = "archive"
    PROTOCOL = "protocol"
    CUSTOM = "custom"


@dataclass
class FormatAnalysis:
    """Analysis of input format."""
    format_type: InputFormat
    confidence: float
    magic_bytes: Optional[bytes] = None
    structure_hints: List[str] = field(default_factory=list)
    field_patterns: List[Dict[str, Any]] = field(default_factory=list)
    delimiters: List[bytes] = field(default_factory=list)
    encoding: str = "binary"


@dataclass
class DictionaryEntry:
    """A dictionary entry for fuzzing."""
    token: bytes
    source: str  # where this token came from
    priority: int = 5  # 1-10
    category: str = "general"  # magic, keyword, delimiter, etc.


@dataclass
class SeedGenerationResult:
    """Result of seed generation."""
    seeds: List[SeedSuggestion]
    dictionary: List[DictionaryEntry]
    format_analysis: FormatAnalysis
    generation_strategy: str
    total_seeds: int
    ai_enhanced: bool
    generation_time_sec: float


@dataclass
class CorpusAnalysis:
    """Analysis of existing corpus."""
    total_inputs: int
    total_size_bytes: int
    unique_formats: List[str]
    coverage_estimate: float
    diversity_score: float
    recommendations: List[str]


@dataclass
class CoverageGap:
    """An identified coverage gap."""
    description: str
    suggested_seeds: List[SeedSuggestion]
    target_code: Optional[str] = None
    confidence: float = 0.5


# =============================================================================
# Format Detection
# =============================================================================

class FormatDetector:
    """Detect input format from binary profile and samples."""

    # Magic bytes for format detection
    FORMAT_SIGNATURES = {
        InputFormat.IMAGE: [
            (b"\x89PNG", "PNG"),
            (b"\xff\xd8\xff", "JPEG"),
            (b"GIF8", "GIF"),
            (b"BM", "BMP"),
            (b"RIFF", "WEBP/WAV"),
        ],
        InputFormat.ARCHIVE: [
            (b"PK\x03\x04", "ZIP"),
            (b"\x1f\x8b", "GZIP"),
            (b"Rar!", "RAR"),
            (b"7z\xbc\xaf", "7Z"),
        ],
        InputFormat.JSON: [
            (b"{", "JSON object"),
            (b"[", "JSON array"),
        ],
        InputFormat.XML: [
            (b"<?xml", "XML"),
            (b"<!", "HTML/XML"),
            (b"<html", "HTML"),
        ],
    }

    @classmethod
    def detect_from_profile(cls, profile: BinaryProfile) -> FormatAnalysis:
        """Detect input format from binary profile."""
        format_type = InputFormat.BINARY
        confidence = 0.5
        hints = []
        magic_bytes = None

        # Check imports for format hints
        format_hints = {
            "json": (InputFormat.JSON, ["json_parse", "cJSON", "rapidjson", "jansson"]),
            "xml": (InputFormat.XML, ["xml_parse", "libxml", "expat", "xerces"]),
            "http": (InputFormat.HTTP, ["http_parse", "curl", "wget", "libcurl"]),
            "image": (InputFormat.IMAGE, ["png_read", "jpeg_read", "libpng", "libjpeg", "ImageMagick"]),
            "archive": (InputFormat.ARCHIVE, ["zip_open", "gzip", "zlib", "libarchive"]),
        }

        for fmt_name, (fmt_type, keywords) in format_hints.items():
            for keyword in keywords:
                if any(keyword.lower() in imp.lower() for imp in profile.imports):
                    format_type = fmt_type
                    confidence = 0.7
                    hints.append(f"Import suggests {fmt_name} processing")
                    break

        # Check strings for format hints
        for s in profile.strings_of_interest:
            if s.startswith("{") or "json" in s.lower():
                if format_type == InputFormat.BINARY:
                    format_type = InputFormat.JSON
                    confidence = 0.6
                    hints.append("Strings suggest JSON format")
            elif s.startswith("<") or "xml" in s.lower():
                if format_type == InputFormat.BINARY:
                    format_type = InputFormat.XML
                    confidence = 0.6
                    hints.append("Strings suggest XML format")
            elif "http" in s.lower() or "GET " in s or "POST " in s:
                if format_type == InputFormat.BINARY:
                    format_type = InputFormat.HTTP
                    confidence = 0.6
                    hints.append("Strings suggest HTTP format")

        # Check for file input patterns
        if any("fopen" in imp or "open" in imp for imp in profile.imports):
            hints.append("Binary reads files")

        # Check for stdin patterns
        if any("stdin" in imp or "getchar" in imp or "fgets" in imp for imp in profile.imports):
            hints.append("Binary reads from stdin")
            if format_type == InputFormat.BINARY:
                format_type = InputFormat.TEXT
                confidence = 0.6

        return FormatAnalysis(
            format_type=format_type,
            confidence=confidence,
            magic_bytes=magic_bytes,
            structure_hints=hints,
        )

    @classmethod
    def detect_from_sample(cls, data: bytes) -> FormatAnalysis:
        """Detect format from sample data."""
        # Check magic bytes
        for fmt_type, signatures in cls.FORMAT_SIGNATURES.items():
            for magic, name in signatures:
                if data.startswith(magic):
                    return FormatAnalysis(
                        format_type=fmt_type,
                        confidence=0.9,
                        magic_bytes=magic,
                        structure_hints=[f"Detected {name} format"],
                    )

        # Check for text-based formats
        try:
            text = data.decode("utf-8")

            # JSON detection
            if text.strip().startswith(("{", "[")):
                try:
                    json.loads(text)
                    return FormatAnalysis(
                        format_type=InputFormat.JSON,
                        confidence=0.95,
                        structure_hints=["Valid JSON detected"],
                        encoding="utf-8",
                    )
                except json.JSONDecodeError:
                    pass

            # XML detection
            if text.strip().startswith("<"):
                return FormatAnalysis(
                    format_type=InputFormat.XML,
                    confidence=0.8,
                    structure_hints=["XML-like structure detected"],
                    encoding="utf-8",
                )

            # HTTP detection
            if text.startswith(("GET ", "POST ", "HTTP/")):
                return FormatAnalysis(
                    format_type=InputFormat.HTTP,
                    confidence=0.9,
                    structure_hints=["HTTP protocol detected"],
                    encoding="utf-8",
                )

            # CSV detection
            if "," in text and "\n" in text:
                lines = text.split("\n")
                if len(lines) > 1:
                    comma_counts = [line.count(",") for line in lines[:5] if line]
                    if len(set(comma_counts)) == 1:
                        return FormatAnalysis(
                            format_type=InputFormat.CSV,
                            confidence=0.7,
                            structure_hints=["CSV-like structure detected"],
                            delimiters=[b","],
                            encoding="utf-8",
                        )

            # Generic text
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text[:1000]):
                return FormatAnalysis(
                    format_type=InputFormat.TEXT,
                    confidence=0.7,
                    structure_hints=["Printable ASCII text"],
                    encoding="utf-8",
                )

        except UnicodeDecodeError:
            pass

        # Default to binary
        return FormatAnalysis(
            format_type=InputFormat.BINARY,
            confidence=0.5,
            structure_hints=["Binary data"],
        )


# =============================================================================
# Seed Generator
# =============================================================================

class SeedGenerator:
    """Generate fuzzing seeds based on format analysis."""

    def __init__(self):
        self.ai_client = BinaryAIClient()

    def generate_for_format(
        self,
        format_analysis: FormatAnalysis,
        count: int = 10,
    ) -> List[SeedSuggestion]:
        """Generate seeds for a specific format."""
        generators = {
            InputFormat.BINARY: self._generate_binary_seeds,
            InputFormat.TEXT: self._generate_text_seeds,
            InputFormat.JSON: self._generate_json_seeds,
            InputFormat.XML: self._generate_xml_seeds,
            InputFormat.HTTP: self._generate_http_seeds,
            InputFormat.IMAGE: self._generate_image_seeds,
            InputFormat.CSV: self._generate_csv_seeds,
        }

        generator = generators.get(format_analysis.format_type, self._generate_binary_seeds)
        return generator(count, format_analysis)

    def _generate_binary_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate binary format seeds."""
        seeds = []

        # Empty input
        seeds.append(SeedSuggestion(
            content=b"",
            rationale="Empty input - test null handling",
            format_type="binary",
        ))

        # Minimal inputs
        seeds.append(SeedSuggestion(
            content=b"\x00",
            rationale="Single null byte",
            format_type="binary",
        ))
        seeds.append(SeedSuggestion(
            content=b"\xff",
            rationale="Single 0xFF byte",
            format_type="binary",
        ))

        # Interesting byte patterns
        patterns = [
            (b"\x00" * 100, "100 null bytes - buffer test"),
            (b"\xff" * 100, "100 0xFF bytes"),
            (b"A" * 1000, "1000 'A' bytes - overflow test"),
            (b"A" * 10000, "10000 'A' bytes - large overflow test"),
            (bytes(range(256)), "All byte values 0-255"),
            (b"\x00\x00\x00\x00" + b"A" * 100, "Null prefix"),
            (b"\x7f\x45\x4c\x46", "ELF magic (test file type detection)"),
            (struct.pack("<I", 0xFFFFFFFF), "Max 32-bit integer"),
            (struct.pack("<Q", 0xFFFFFFFFFFFFFFFF), "Max 64-bit integer"),
            (struct.pack("<i", -1), "Negative integer"),
        ]

        for content, rationale in patterns:
            if len(seeds) >= count:
                break
            seeds.append(SeedSuggestion(
                content=content,
                rationale=rationale,
                format_type="binary",
            ))

        return seeds[:count]

    def _generate_text_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate text format seeds."""
        seeds = []

        text_patterns = [
            ("", "Empty string"),
            ("\n", "Single newline"),
            ("A" * 1000, "Long string"),
            ("A" * 10000, "Very long string - overflow test"),
            ("%s%s%s%s%s", "Format string test"),
            ("%n%n%n%n", "Format string write test"),
            ("../../../etc/passwd", "Path traversal"),
            ("; ls -la", "Command injection"),
            ("' OR '1'='1", "SQL injection"),
            ("<script>alert(1)</script>", "XSS test"),
            ("\x00embedded\x00nulls\x00", "Embedded nulls"),
            ("line1\nline2\nline3", "Multi-line input"),
            ("field1\tfield2\tfield3", "Tab-separated"),
            ("unicode: \u0000\u0001\u0002", "Unicode control chars"),
        ]

        for content, rationale in text_patterns:
            if len(seeds) >= count:
                break
            seeds.append(SeedSuggestion(
                content=content.encode("utf-8", errors="replace"),
                rationale=rationale,
                format_type="text",
            ))

        return seeds[:count]

    def _generate_json_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate JSON format seeds."""
        seeds = []

        json_patterns = [
            ("{}", "Empty object"),
            ("[]", "Empty array"),
            ('{"key": "value"}', "Simple object"),
            ('{"key": null}', "Null value"),
            ('{"key": true}', "Boolean value"),
            ('{"key": 12345}', "Integer value"),
            ('{"key": -1}', "Negative integer"),
            ('{"key": 99999999999999999999}', "Large integer"),
            ('{"key": 1.7976931348623157e+308}', "Max double"),
            ('{"key": "A"*1000}', "Long string value"),
            ('{"' + "A"*1000 + '": "value"}', "Long key"),
            ('[1,2,3,4,5]', "Simple array"),
            ('{"nested": {"deep": {"value": 1}}}', "Nested objects"),
            ('[[[[[1]]]]]', "Deeply nested arrays"),
            ('{"a":1,"a":2}', "Duplicate keys"),
            ('{"key": "\\u0000\\u0001"}', "Unicode escapes"),
            ('{invalid}', "Invalid JSON"),
            ('{"key": undefined}', "Undefined value"),
        ]

        for content, rationale in json_patterns:
            if len(seeds) >= count:
                break
            # Handle the placeholder for long strings
            if '"A"*1000' in content:
                content = content.replace('"A"*1000', '"' + "A"*1000 + '"')
            seeds.append(SeedSuggestion(
                content=content.encode("utf-8"),
                rationale=rationale,
                format_type="json",
            ))

        return seeds[:count]

    def _generate_xml_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate XML format seeds."""
        seeds = []

        xml_patterns = [
            ("<root/>", "Empty element"),
            ("<root></root>", "Empty element with closing tag"),
            ("<root>content</root>", "Simple element"),
            ('<root attr="value"/>', "Element with attribute"),
            ("<root><child/></root>", "Nested elements"),
            ('<?xml version="1.0"?><root/>', "XML declaration"),
            ('<!DOCTYPE root><root/>', "DOCTYPE"),
            ('<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "XXE attack"),
            ('<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><root>&xxe;</root>', "XXE external"),
            ("<root>" + "<a>"*1000 + "</a>"*1000 + "</root>", "Deeply nested - DoS"),
            ('<root attr="' + "A"*10000 + '"/>', "Long attribute"),
            ("<root><!--comment--></root>", "Comment"),
            ("<root><![CDATA[<>&]]></root>", "CDATA section"),
            ("<root xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'/>", "Namespace"),
        ]

        for content, rationale in xml_patterns:
            if len(seeds) >= count:
                break
            seeds.append(SeedSuggestion(
                content=content.encode("utf-8"),
                rationale=rationale,
                format_type="xml",
            ))

        return seeds[:count]

    def _generate_http_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate HTTP format seeds."""
        seeds = []

        http_patterns = [
            ("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "Simple GET"),
            ("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n", "Simple POST"),
            ("GET / HTTP/1.0\r\n\r\n", "HTTP/1.0 request"),
            ("GET / HTTP/2.0\r\nHost: localhost\r\n\r\n", "HTTP/2.0 request"),
            ("INVALID / HTTP/1.1\r\nHost: localhost\r\n\r\n", "Invalid method"),
            ("GET " + "/"*10000 + " HTTP/1.1\r\nHost: localhost\r\n\r\n", "Long path"),
            ("GET / HTTP/1.1\r\nHost: localhost\r\n" + "X-Header: value\r\n"*1000 + "\r\n", "Many headers"),
            ("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n", "Negative content length"),
            ("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 99999999999\r\n\r\n", "Huge content length"),
            ("GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "Chunked encoding"),
        ]

        for content, rationale in http_patterns:
            if len(seeds) >= count:
                break
            seeds.append(SeedSuggestion(
                content=content.encode("utf-8"),
                rationale=rationale,
                format_type="http",
            ))

        return seeds[:count]

    def _generate_image_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate image format seeds."""
        seeds = []

        # Minimal PNG
        minimal_png = (
            b"\x89PNG\r\n\x1a\n"  # Signature
            b"\x00\x00\x00\rIHDR"  # IHDR chunk
            b"\x00\x00\x00\x01"  # Width: 1
            b"\x00\x00\x00\x01"  # Height: 1
            b"\x08\x02"  # Bit depth: 8, Color type: 2 (RGB)
            b"\x00\x00\x00"  # Compression, Filter, Interlace
            b"\x90wS\xde"  # CRC
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"  # IDAT
            b"\x00\x00\x00\x00IEND\xaeB`\x82"  # IEND
        )

        seeds.append(SeedSuggestion(
            content=minimal_png,
            rationale="Minimal valid PNG",
            format_type="image",
        ))

        # Corrupted PNG variants
        seeds.append(SeedSuggestion(
            content=b"\x89PNG\r\n\x1a\n" + b"\x00" * 100,
            rationale="PNG header + nulls",
            format_type="image",
        ))

        seeds.append(SeedSuggestion(
            content=minimal_png[:20] + b"\xff\xff\xff\xff" + minimal_png[24:],
            rationale="PNG with corrupted dimensions",
            format_type="image",
        ))

        # Minimal GIF
        minimal_gif = (
            b"GIF89a"  # Header
            b"\x01\x00\x01\x00"  # Width: 1, Height: 1
            b"\x00\x00\x00"  # Flags, background, aspect
            b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"  # Image descriptor
            b"\x02\x02\x44\x01\x00"  # Image data
            b"\x3b"  # Trailer
        )

        seeds.append(SeedSuggestion(
            content=minimal_gif,
            rationale="Minimal valid GIF",
            format_type="image",
        ))

        # JPEG header
        seeds.append(SeedSuggestion(
            content=b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 100 + b"\xff\xd9",
            rationale="Minimal JPEG structure",
            format_type="image",
        ))

        return seeds[:count]

    def _generate_csv_seeds(
        self,
        count: int,
        analysis: FormatAnalysis,
    ) -> List[SeedSuggestion]:
        """Generate CSV format seeds."""
        seeds = []

        csv_patterns = [
            ("", "Empty CSV"),
            ("a,b,c", "Simple row"),
            ("a,b,c\n1,2,3", "Header and data"),
            ('"quoted","values","here"', "Quoted values"),
            ('a,"b,c",d', "Comma in quoted field"),
            ('a,"b""c",d', "Escaped quote"),
            ("a,b,c\n" + "1,2,3\n" * 1000, "Many rows"),
            (",".join(["col"]*1000), "Many columns"),
            ("a\tb\tc", "Tab-separated"),
            ("a;b;c", "Semicolon-separated"),
            ("=cmd|' /C calc'!A0", "CSV injection"),
            ("@SUM(1+1)*cmd|' /C calc'!A0", "CSV injection variant"),
        ]

        for content, rationale in csv_patterns:
            if len(seeds) >= count:
                break
            seeds.append(SeedSuggestion(
                content=content.encode("utf-8"),
                rationale=rationale,
                format_type="csv",
            ))

        return seeds[:count]


# =============================================================================
# Dictionary Generator
# =============================================================================

class DictionaryGenerator:
    """Generate fuzzing dictionaries from binary analysis."""

    def generate(self, profile: BinaryProfile) -> List[DictionaryEntry]:
        """Generate dictionary entries from binary profile."""
        entries = []

        # Extract from strings
        for s in profile.strings_of_interest:
            # Keywords
            if len(s) >= 3 and len(s) <= 20:
                entries.append(DictionaryEntry(
                    token=s.encode("utf-8", errors="ignore"),
                    source="strings",
                    priority=5,
                    category="keyword",
                ))

        # Format-specific tokens
        format_tokens = {
            "json": [b"{", b"}", b"[", b"]", b":", b",", b"null", b"true", b"false"],
            "xml": [b"<", b">", b"</", b"/>", b"<?xml", b"<!DOCTYPE", b"CDATA"],
            "http": [b"GET", b"POST", b"HTTP/1.1", b"\r\n", b"Host:", b"Content-Length:"],
        }

        if profile.input_format_guess:
            fmt_type = profile.input_format_guess.format_type
            if fmt_type in format_tokens:
                for token in format_tokens[fmt_type]:
                    entries.append(DictionaryEntry(
                        token=token,
                        source="format",
                        priority=7,
                        category="delimiter",
                    ))

        # Common attack tokens
        attack_tokens = [
            (b"%s", "format_string"),
            (b"%n", "format_string"),
            (b"%x", "format_string"),
            (b"../", "path_traversal"),
            (b"..\\", "path_traversal"),
            (b"'", "injection"),
            (b'"', "injection"),
            (b";", "injection"),
            (b"|", "injection"),
            (b"`", "injection"),
            (b"$(", "injection"),
            (b"\x00", "null_byte"),
            (b"\xff\xff\xff\xff", "boundary"),
            (b"\x7f\xff\xff\xff", "boundary"),
            (b"\x80\x00\x00\x00", "boundary"),
        ]

        for token, category in attack_tokens:
            entries.append(DictionaryEntry(
                token=token,
                source="attack",
                priority=8,
                category=category,
            ))

        # Deduplicate
        seen = set()
        unique_entries = []
        for entry in entries:
            if entry.token not in seen:
                seen.add(entry.token)
                unique_entries.append(entry)

        return sorted(unique_entries, key=lambda e: -e.priority)[:100]


# =============================================================================
# Seed Intelligence Service
# =============================================================================

class SeedIntelligenceService:
    """AI-powered seed generation service."""

    def __init__(self):
        self.ai_client = BinaryAIClient()
        self.format_detector = FormatDetector()
        self.seed_generator = SeedGenerator()
        self.dictionary_generator = DictionaryGenerator()

    async def generate_seeds(
        self,
        profile: BinaryProfile,
        count: int = 20,
        ai_enhance: bool = True,
    ) -> SeedGenerationResult:
        """Generate intelligent seeds for fuzzing."""
        import time
        start_time = time.time()

        # Detect format
        format_analysis = self.format_detector.detect_from_profile(profile)

        # Generate base seeds
        seeds = self.seed_generator.generate_for_format(format_analysis, count)

        # Generate dictionary
        dictionary = self.dictionary_generator.generate(profile)

        # AI enhancement
        if ai_enhance:
            ai_seeds = await self._ai_generate_seeds(profile, format_analysis, count // 2)
            seeds.extend(ai_seeds)

        generation_time = time.time() - start_time

        return SeedGenerationResult(
            seeds=seeds[:count],
            dictionary=dictionary,
            format_analysis=format_analysis,
            generation_strategy="ai_enhanced" if ai_enhance else "heuristic",
            total_seeds=len(seeds),
            ai_enhanced=ai_enhance,
            generation_time_sec=generation_time,
        )

    async def _ai_generate_seeds(
        self,
        profile: BinaryProfile,
        format_analysis: FormatAnalysis,
        count: int,
    ) -> List[SeedSuggestion]:
        """Use AI to generate additional seeds."""
        prompt = f"""Generate fuzzing seeds for this binary target.

Binary: {profile.file_path}
Type: {profile.file_type} ({profile.architecture})
Detected input format: {format_analysis.format_type.value}
Format confidence: {format_analysis.confidence}

Input handlers:
{chr(10).join(f'  - {h.function_name} ({h.input_type})' for h in profile.input_handlers[:10])}

Vulnerability hints:
{chr(10).join(f'  - {h.type}: {h.description}' for h in profile.vulnerability_hints[:10])}

Interesting strings:
{chr(10).join(f'  - {s}' for s in profile.strings_of_interest[:20])}

Generate {count} fuzzing seeds that:
1. Target edge cases specific to this binary
2. Exercise identified vulnerability patterns
3. Include format-specific malformed inputs
4. Test boundary conditions

For each seed, provide:
- content_base64: Base64-encoded seed content
- rationale: Why this seed is valuable
- target: What code path or vulnerability this targets

Respond in JSON: {{"seeds": [...]}}"""

        try:
            response = await self.ai_client.generate(prompt)

            if "error" not in response and "seeds" in response:
                ai_seeds = []
                for seed_data in response["seeds"]:
                    try:
                        content = base64.b64decode(seed_data.get("content_base64", ""))
                        ai_seeds.append(SeedSuggestion(
                            content=content,
                            rationale=seed_data.get("rationale", "AI-generated"),
                            target_path=seed_data.get("target"),
                            format_type=format_analysis.format_type.value,
                        ))
                    except Exception:
                        continue
                return ai_seeds

        except Exception as e:
            logger.warning(f"AI seed generation failed: {e}")

        return []

    async def analyze_corpus(
        self,
        corpus_paths: List[str],
        profile: BinaryProfile,
    ) -> CorpusAnalysis:
        """Analyze existing corpus and provide recommendations."""
        import os

        total_size = 0
        formats_seen = set()
        inputs = []

        for path in corpus_paths:
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    data = f.read()
                total_size += len(data)
                format_analysis = self.format_detector.detect_from_sample(data)
                formats_seen.add(format_analysis.format_type.value)
                inputs.append(data)

        # Calculate diversity (simplified)
        if inputs:
            unique_prefixes = len(set(inp[:10] for inp in inputs))
            diversity_score = unique_prefixes / len(inputs)
        else:
            diversity_score = 0

        # Generate recommendations
        recommendations = []

        if len(inputs) < 10:
            recommendations.append("Corpus is small - consider adding more seeds")

        if diversity_score < 0.5:
            recommendations.append("Low diversity - seeds are too similar")

        if len(formats_seen) == 1 and InputFormat.BINARY.value in formats_seen:
            recommendations.append("Consider adding format-specific seeds")

        expected_format = self.format_detector.detect_from_profile(profile)
        if expected_format.format_type.value not in formats_seen:
            recommendations.append(f"No {expected_format.format_type.value} format seeds detected")

        return CorpusAnalysis(
            total_inputs=len(inputs),
            total_size_bytes=total_size,
            unique_formats=list(formats_seen),
            coverage_estimate=0.0,  # Would need coverage data
            diversity_score=diversity_score,
            recommendations=recommendations,
        )

    async def suggest_for_coverage_gap(
        self,
        profile: BinaryProfile,
        uncovered_functions: List[str],
        current_corpus: List[bytes],
    ) -> List[CoverageGap]:
        """Suggest seeds to cover specific code."""
        gaps = []

        prompt = f"""Analyze these uncovered functions and suggest inputs to reach them.

Binary: {profile.file_path}
Uncovered functions:
{chr(10).join(f'  - {f}' for f in uncovered_functions[:20])}

Current corpus size: {len(current_corpus)} inputs
Input format: {profile.input_format_guess.format_type if profile.input_format_guess else 'unknown'}

For each function that looks reachable, suggest:
1. function_name: The target function
2. input_description: What input might reach it
3. input_base64: Base64-encoded suggested input
4. confidence: 0-1

Respond in JSON: {{"suggestions": [...]}}"""

        try:
            response = await self.ai_client.generate(prompt)

            if "error" not in response and "suggestions" in response:
                for suggestion in response["suggestions"]:
                    try:
                        content = base64.b64decode(suggestion.get("input_base64", ""))
                        gaps.append(CoverageGap(
                            description=suggestion.get("input_description", ""),
                            suggested_seeds=[SeedSuggestion(
                                content=content,
                                rationale=f"Target: {suggestion.get('function_name')}",
                            )],
                            target_code=suggestion.get("function_name"),
                            confidence=suggestion.get("confidence", 0.5),
                        ))
                    except Exception:
                        continue

        except Exception as e:
            logger.warning(f"Coverage gap analysis failed: {e}")

        return gaps


# =============================================================================
# Helper Functions
# =============================================================================

async def generate_seeds_for_binary(
    binary_path: str,
    count: int = 20,
) -> SeedGenerationResult:
    """Convenience function to generate seeds for a binary."""
    from backend.services.binary_analysis_service import BinaryAnalysisService

    analysis_service = BinaryAnalysisService()
    profile = await analysis_service.analyze(binary_path)

    seed_service = SeedIntelligenceService()
    return await seed_service.generate_seeds(profile, count)
