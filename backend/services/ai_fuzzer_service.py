"""
AI-Enhanced Binary Fuzzing Service

Provides intelligent AI assistance for binary fuzzing:
1. Smart Seed Generation - Analyze binary to create format-aware seeds
2. Coverage Advisor - Detect stuck campaigns and suggest strategies
3. Exploit Helper - Deep crash analysis with PoC guidance

Uses Gemini AI for intelligent analysis.
"""

import json
import base64
import hashlib
import struct
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime
import re

from backend.core.config import settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

# Use google-genai SDK
genai_client = None
if settings.gemini_api_key:
    try:
        from google import genai
        genai_client = genai.Client(api_key=settings.gemini_api_key)
    except ImportError:
        logger.warning("google-genai not installed, AI fuzzing assistance disabled")


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class BinaryInfo:
    """Information extracted from binary analysis."""
    file_type: str  # ELF, PE, Mach-O
    architecture: str  # x86, x64, ARM
    entry_point: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    file_magic: bytes = b""
    has_symbols: bool = False
    is_stripped: bool = True
    input_functions: List[str] = field(default_factory=list)  # stdin, read, fread, etc.


@dataclass
class GeneratedSeed:
    """A generated seed file for fuzzing."""
    name: str
    content: bytes
    description: str
    format_type: str  # text, binary, structured
    mutation_hints: List[str] = field(default_factory=list)


@dataclass
class SeedGenerationResult:
    """Result of AI seed generation."""
    seeds: List[GeneratedSeed]
    input_format_analysis: str
    recommended_dictionary: List[str]
    fuzzing_strategy: str
    target_analysis: str
    generation_method: str = "heuristic"


@dataclass
class CoverageAdvisorResult:
    """Result of coverage analysis and recommendations."""
    is_stuck: bool
    stuck_reason: Optional[str]
    coverage_trend: str  # increasing, plateaued, declining
    recommendations: List[str]
    suggested_seeds: List[str]  # Base64 encoded seed suggestions
    mutation_adjustments: Dict[str, Any]
    priority_areas: List[str]  # Functions/areas to focus on


@dataclass
class ExploitAnalysisResult:
    """Result of exploit analysis for a crash."""
    crash_id: str
    exploitability: str  # exploitable, probably_exploitable, probably_not, not_exploitable
    exploitability_score: float  # 0-1
    vulnerability_type: str
    root_cause: str
    affected_functions: List[str]
    exploitation_techniques: List[str]
    poc_guidance: str
    mitigation_bypass: List[str]  # How to bypass protections
    cve_similar: List[str]  # Similar CVEs
    remediation: str
    detailed_analysis: str


# =============================================================================
# BINARY ANALYSIS HELPERS
# =============================================================================

def analyze_binary(file_path: str) -> BinaryInfo:
    """
    Analyze a binary to extract useful information for fuzzing.
    """
    info = BinaryInfo(
        file_type="unknown",
        architecture="unknown",
    )
    
    try:
        with open(file_path, "rb") as f:
            data = f.read(min(os.path.getsize(file_path), 1024 * 1024))  # Read up to 1MB
        
        info.file_magic = data[:16]
        
        # Detect file type
        if data[:4] == b'\x7fELF':
            info.file_type = "ELF"
            # ELF class (32/64 bit)
            if len(data) > 4:
                info.architecture = "x64" if data[4] == 2 else "x86"
            # Check if stripped
            info.is_stripped = b'.symtab' not in data
            info.has_symbols = not info.is_stripped
            
        elif data[:2] == b'MZ':
            info.file_type = "PE"
            # Check PE header for architecture
            if len(data) > 64:
                pe_offset = struct.unpack('<I', data[60:64])[0]
                if len(data) > pe_offset + 6:
                    machine = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
                    info.architecture = "x64" if machine == 0x8664 else "x86"
                    
        elif data[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                          b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
            info.file_type = "Mach-O"
            info.architecture = "x64" if data[:4] in [b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'] else "x86"
        
        # Extract strings (printable sequences >= 4 chars)
        strings = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append(''.join(current))
                current = []
        if len(current) >= 4:
            strings.append(''.join(current))
        
        # Filter interesting strings
        info.strings = [s for s in strings[:500] if len(s) < 100]  # Limit to 500 strings
        
        # Identify input-related functions
        input_patterns = [
            'read', 'fread', 'fgets', 'gets', 'scanf', 'fscanf', 'getc', 'fgetc',
            'recv', 'recvfrom', 'recvmsg', 'ReadFile', 'fopen', 'open', 'accept',
            'getenv', 'stdin', 'argv', 'atoi', 'atol', 'strtol', 'sscanf',
            'parse', 'input', 'buffer', 'packet', 'message', 'request', 'data'
        ]
        info.input_functions = [s for s in info.strings if any(p in s.lower() for p in input_patterns)]
        
        # Identify imports (simplified - look for common function names)
        security_funcs = [
            'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
            'memcpy', 'memmove', 'malloc', 'free', 'realloc', 'alloca',
            'system', 'exec', 'popen', 'fork', 'CreateProcess',
        ]
        info.imports = [s for s in info.strings if any(f == s for f in security_funcs)]
        
    except Exception as e:
        logger.error(f"Error analyzing binary: {e}")
    
    return info


def detect_input_format(binary_info: BinaryInfo) -> Tuple[str, List[str]]:
    """
    Detect likely input format based on binary analysis.
    Returns (format_type, format_hints).
    """
    format_hints = []
    format_type = "binary"
    
    strings_lower = [s.lower() for s in binary_info.strings]
    all_strings = ' '.join(strings_lower)
    
    # Check for file format indicators
    format_indicators = {
        'json': ['json', '"type"', '"data"', '"value"', 'application/json'],
        'xml': ['xml', '<?xml', '<root>', '<data>', 'xmlns', '</'],
        'http': ['http/', 'content-type', 'get ', 'post ', 'host:', 'user-agent'],
        'image': ['png', 'jpeg', 'jfif', 'gif8', 'bmp', 'tiff', 'exif'],
        'pdf': ['%pdf', 'endobj', 'xref', 'startxref'],
        'archive': ['pk\x03\x04', 'rar!', '7z', 'gzip'],
        'text': ['usage:', 'error:', 'invalid', 'expected', 'syntax'],
        'config': ['=', 'true', 'false', 'enable', 'disable', 'config'],
        'network': ['socket', 'connect', 'send', 'recv', 'port', 'address'],
    }
    
    for fmt, indicators in format_indicators.items():
        matches = sum(1 for ind in indicators if ind in all_strings)
        if matches >= 2:
            format_type = fmt
            format_hints.append(f"Detected {fmt} format indicators: {matches} matches")
    
    # Check for specific parsers
    if any('parse' in s for s in strings_lower):
        format_hints.append("Binary contains parsing functions")
    
    if any('argv' in s or 'argc' in s for s in binary_info.strings):
        format_hints.append("Binary processes command-line arguments")
    
    if any('stdin' in s or 'read' in s for s in binary_info.strings):
        format_hints.append("Binary reads from stdin")
    
    return format_type, format_hints


# =============================================================================
# AI SEED GENERATOR
# =============================================================================

async def generate_smart_seeds(
    binary_path: str,
    binary_name: str,
    num_seeds: int = 10,
    existing_seeds: Optional[List[bytes]] = None,
) -> SeedGenerationResult:
    """
    Use AI to analyze binary and generate intelligent seed files.
    """
    # Analyze binary first
    binary_info = analyze_binary(binary_path)
    format_type, format_hints = detect_input_format(binary_info)
    
    # Prepare context for AI
    context = {
        "binary_name": binary_name,
        "file_type": binary_info.file_type,
        "architecture": binary_info.architecture,
        "is_stripped": binary_info.is_stripped,
        "input_functions": binary_info.input_functions[:20],
        "security_functions": binary_info.imports[:20],
        "interesting_strings": binary_info.strings[:50],
        "detected_format": format_type,
        "format_hints": format_hints,
        "has_existing_seeds": existing_seeds is not None and len(existing_seeds) > 0,
    }
    
    # Generate seeds using AI
    if genai_client:
        try:
            seeds, dictionary, strategy, analysis = await _ai_generate_seeds(context, num_seeds)
            return SeedGenerationResult(
                seeds=seeds,
                input_format_analysis=analysis,
                recommended_dictionary=dictionary,
                fuzzing_strategy=strategy,
                target_analysis=json.dumps(context, indent=2),
                generation_method="ai",
            )
        except Exception as e:
            logger.error(f"AI seed generation failed: {e}")
    
    # Fallback: Generate basic seeds without AI
    return _generate_fallback_seeds(binary_info, format_type, num_seeds)


async def _ai_generate_seeds(context: Dict, num_seeds: int) -> Tuple[List[GeneratedSeed], List[str], str, str]:
    """Use AI to generate intelligent seeds."""
    
    prompt = f"""You are an expert binary fuzzer analyzing a target program to generate effective seed inputs.

## Target Analysis
- Binary: {context['binary_name']}
- Type: {context['file_type']} ({context['architecture']})
- Stripped: {context['is_stripped']}
- Detected input format: {context['detected_format']}
- Format hints: {json.dumps(context['format_hints'])}

## Interesting Strings Found
{json.dumps(context['interesting_strings'][:30], indent=2)}

## Input-Related Functions
{json.dumps(context['input_functions'][:15], indent=2)}

## Security-Sensitive Functions
{json.dumps(context['security_functions'], indent=2)}

## Task
Generate {num_seeds} intelligent seed inputs that are likely to:
1. Be accepted by the parser (valid enough to process)
2. Exercise different code paths
3. Trigger edge cases and boundary conditions
4. Target security-sensitive functions

For each seed, provide:
1. A descriptive name
2. The actual content (as a string or hex for binary)
3. Why this seed is useful
4. Mutation hints (what parts to mutate)

Also provide:
1. Analysis of the expected input format
2. A dictionary of useful strings/values for mutation
3. Recommended fuzzing strategy

Respond in this exact JSON format:
{{
    "input_format_analysis": "Description of the expected input format...",
    "fuzzing_strategy": "Recommended strategy for fuzzing this target...",
    "dictionary": ["string1", "string2", ...],
    "seeds": [
        {{
            "name": "seed_name",
            "content_type": "text" or "hex",
            "content": "actual content or hex string",
            "description": "Why this seed is useful",
            "mutation_hints": ["hint1", "hint2"]
        }}
    ]
}}"""

    response = genai_client.models.generate_content(
        model="gemini-3-flash-preview",
        contents=prompt,
    )
    
    # Parse response
    try:
        # Extract JSON from response
        text = response.text
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            data = json.loads(json_match.group())
        else:
            raise ValueError("No JSON found in response")
        
        seeds = []
        for seed_data in data.get("seeds", []):
            content = seed_data.get("content", "")
            if seed_data.get("content_type") == "hex":
                try:
                    content = bytes.fromhex(content.replace(" ", ""))
                except ValueError:
                    content = content.encode()
            else:
                content = content.encode() if isinstance(content, str) else content
            
            seeds.append(GeneratedSeed(
                name=seed_data.get("name", f"seed_{len(seeds)}"),
                content=content,
                description=seed_data.get("description", ""),
                format_type=seed_data.get("content_type", "text"),
                mutation_hints=seed_data.get("mutation_hints", []),
            ))
        
        return (
            seeds,
            data.get("dictionary", []),
            data.get("fuzzing_strategy", "Standard coverage-guided fuzzing"),
            data.get("input_format_analysis", "Unknown input format"),
        )
        
    except Exception as e:
        logger.error(f"Failed to parse AI response: {e}")
        raise


def _generate_fallback_seeds(binary_info: BinaryInfo, format_type: str, num_seeds: int) -> SeedGenerationResult:
    """Generate basic seeds without AI assistance."""
    seeds = []
    
    # Generate format-specific seeds
    if format_type == "json":
        seeds.extend([
            GeneratedSeed("empty_json", b'{}', "Empty JSON object", "text"),
            GeneratedSeed("simple_json", b'{"key":"value"}', "Simple key-value", "text"),
            GeneratedSeed("nested_json", b'{"a":{"b":{"c":1}}}', "Nested structure", "text"),
            GeneratedSeed("array_json", b'{"data":[1,2,3]}', "Array data", "text"),
            GeneratedSeed("large_string", b'{"s":"' + b'A' * 1000 + b'"}', "Large string value", "text"),
        ])
    elif format_type == "xml":
        seeds.extend([
            GeneratedSeed("empty_xml", b'<?xml version="1.0"?><root/>', "Empty XML", "text"),
            GeneratedSeed("simple_xml", b'<root><item>data</item></root>', "Simple element", "text"),
            GeneratedSeed("attrs_xml", b'<root attr="value"><item id="1"/></root>', "With attributes", "text"),
        ])
    elif format_type == "http":
        seeds.extend([
            GeneratedSeed("get_request", b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n', "GET request", "text"),
            GeneratedSeed("post_request", b'POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ndata', "POST request", "text"),
        ])
    else:
        # Generic binary seeds
        seeds.extend([
            GeneratedSeed("minimal", b'AAAA', "Minimal input", "binary"),
            GeneratedSeed("zeros", b'\x00' * 64, "Null bytes", "binary"),
            GeneratedSeed("ones", b'\xff' * 64, "All 1s", "binary"),
            GeneratedSeed("mixed", b'A' * 32 + b'\x00' * 32 + b'\xff' * 32, "Mixed pattern", "binary"),
            GeneratedSeed("newlines", b'line1\nline2\nline3\n', "Line-based input", "text"),
            GeneratedSeed("boundary", struct.pack('<I', 0xffffffff) + struct.pack('<I', 0x7fffffff), "Integer boundaries", "binary"),
        ])
    
    # Add strings found in binary as seeds
    for i, s in enumerate(binary_info.strings[:5]):
        if len(s) >= 4:
            seeds.append(GeneratedSeed(f"string_{i}", s.encode(), f"String from binary: {s[:20]}...", "text"))
    
    return SeedGenerationResult(
        seeds=seeds[:num_seeds],
        input_format_analysis=f"Detected format: {format_type}",
        recommended_dictionary=binary_info.strings[:20],
        fuzzing_strategy="Standard mutation-based fuzzing",
        target_analysis="Basic binary analysis (AI unavailable)",
        generation_method="heuristic",
    )


# =============================================================================
# AI COVERAGE ADVISOR
# =============================================================================

async def analyze_coverage_and_advise(
    session_id: str,
    stats_history: List[Dict[str, Any]],
    current_corpus: List[Dict[str, Any]],
    crashes: List[Dict[str, Any]],
    target_info: Optional[Dict[str, Any]] = None,
) -> CoverageAdvisorResult:
    """
    Analyze fuzzing progress and provide recommendations when stuck.
    """
    # Analyze coverage trend
    is_stuck, stuck_reason, trend = _analyze_coverage_trend(stats_history)
    
    if not genai_client:
        return _fallback_coverage_advice(is_stuck, stuck_reason, trend, stats_history)
    
    try:
        # Prepare context
        context = {
            "session_id": session_id,
            "is_stuck": is_stuck,
            "stuck_reason": stuck_reason,
            "coverage_trend": trend,
            "stats_summary": _summarize_stats(stats_history),
            "corpus_info": {
                "size": len(current_corpus),
                "total_size_bytes": sum(c.get("size", 0) for c in current_corpus),
            },
            "crashes_found": len(crashes),
            "crash_types": list(set(c.get("crash_type", "unknown") for c in crashes)),
            "target_info": target_info or {},
        }
        
        return await _ai_coverage_advice(context)
        
    except Exception as e:
        logger.error(f"AI coverage advice failed: {e}")
        return _fallback_coverage_advice(is_stuck, stuck_reason, trend, stats_history)


def _analyze_coverage_trend(stats_history: List[Dict[str, Any]]) -> Tuple[bool, Optional[str], str]:
    """Analyze if fuzzing is stuck based on stats history."""
    if len(stats_history) < 5:
        return False, None, "initializing"
    
    # Look at last N data points
    recent = stats_history[-10:] if len(stats_history) >= 10 else stats_history
    
    # Check coverage growth
    coverage_values = [s.get("total_edges", s.get("paths_total", 0)) for s in recent]
    
    if len(set(coverage_values)) == 1:
        # No change in coverage
        return True, "Coverage has not changed in recent iterations", "plateaued"
    
    # Calculate growth rate
    if coverage_values[-1] > 0 and coverage_values[0] > 0:
        growth_rate = (coverage_values[-1] - coverage_values[0]) / coverage_values[0]
        
        if growth_rate < 0.01:  # Less than 1% growth
            return True, f"Coverage growth is very slow ({growth_rate*100:.2f}%)", "plateaued"
        elif growth_rate < 0.05:
            return False, None, "slow_growth"
        else:
            return False, None, "increasing"
    
    return False, None, "unknown"


def _summarize_stats(stats_history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize fuzzing statistics."""
    if not stats_history:
        return {}
    
    latest = stats_history[-1]
    earliest = stats_history[0]
    
    return {
        "total_executions": latest.get("execs_done", latest.get("total_executions", 0)),
        "exec_per_sec": latest.get("execs_per_sec", latest.get("exec_per_sec", 0)),
        "unique_crashes": latest.get("unique_crashes", 0),
        "unique_hangs": latest.get("unique_hangs", latest.get("total_timeouts", 0)),
        "coverage_start": earliest.get("total_edges", earliest.get("paths_total", 0)),
        "coverage_current": latest.get("total_edges", latest.get("paths_total", 0)),
        "corpus_size": latest.get("corpus_size", latest.get("paths_found", 0)),
        "runtime_seconds": latest.get("runtime_seconds", latest.get("elapsed_seconds", 0)),
    }


async def _ai_coverage_advice(context: Dict) -> CoverageAdvisorResult:
    """Use AI to analyze coverage and provide advice."""
    
    prompt = f"""You are an expert fuzzing engineer analyzing a fuzzing campaign that may be stuck.

## Campaign Status
- Session: {context['session_id']}
- Is Stuck: {context['is_stuck']}
- Reason: {context.get('stuck_reason', 'N/A')}
- Coverage Trend: {context['coverage_trend']}

## Statistics
{json.dumps(context['stats_summary'], indent=2)}

## Corpus Info
- Size: {context['corpus_info']['size']} inputs
- Total bytes: {context['corpus_info']['total_size_bytes']}

## Crashes Found
- Total: {context['crashes_found']}
- Types: {json.dumps(context['crash_types'])}

## Task
Analyze this fuzzing campaign and provide actionable recommendations to improve coverage.

Consider:
1. Is the fuzzer truly stuck or just slow?
2. What might be blocking coverage progress?
3. What mutation strategies might help?
4. Should we try different seed structures?
5. Are there signs of anti-fuzzing?

Provide your analysis in this exact JSON format:
{{
    "is_stuck": true/false,
    "stuck_reason": "explanation if stuck",
    "recommendations": [
        "Specific actionable recommendation 1",
        "Specific actionable recommendation 2"
    ],
    "suggested_seed_patterns": [
        "description of seed pattern to try"
    ],
    "mutation_adjustments": {{
        "increase_havoc": true/false,
        "focus_on_structure": true/false,
        "try_deterministic": true/false,
        "adjust_timeout": "increase/decrease/same"
    }},
    "priority_areas": [
        "area or function to focus on"
    ],
    "analysis_summary": "Brief summary of the situation and prognosis"
}}"""

    response = genai_client.models.generate_content(
        model="gemini-3-flash-preview",
        contents=prompt,
    )
    
    # Parse response
    text = response.text
    json_match = re.search(r'\{[\s\S]*\}', text)
    if json_match:
        data = json.loads(json_match.group())
    else:
        raise ValueError("No JSON found in response")
    
    return CoverageAdvisorResult(
        is_stuck=data.get("is_stuck", context["is_stuck"]),
        stuck_reason=data.get("stuck_reason"),
        coverage_trend=context["coverage_trend"],
        recommendations=data.get("recommendations", []),
        suggested_seeds=[],  # Would need to generate actual seeds
        mutation_adjustments=data.get("mutation_adjustments", {}),
        priority_areas=data.get("priority_areas", []),
    )


def _fallback_coverage_advice(is_stuck: bool, stuck_reason: Optional[str], trend: str, stats_history: List[Dict]) -> CoverageAdvisorResult:
    """Provide basic advice without AI."""
    recommendations = []
    
    if is_stuck:
        recommendations.extend([
            "Try adding more diverse seed inputs",
            "Increase havoc mutation intensity",
            "Consider using a custom dictionary",
            "Check if target has checksums or magic values that block mutations",
            "Try increasing the timeout if target is slow",
        ])
    else:
        recommendations.extend([
            "Fuzzing appears to be progressing normally",
            "Continue monitoring coverage growth",
            "Consider adding specialized seeds for uncovered areas",
        ])
    
    return CoverageAdvisorResult(
        is_stuck=is_stuck,
        stuck_reason=stuck_reason,
        coverage_trend=trend,
        recommendations=recommendations,
        suggested_seeds=[],
        mutation_adjustments={
            "increase_havoc": is_stuck,
            "focus_on_structure": trend == "plateaued",
            "try_deterministic": False,
            "adjust_timeout": "same",
        },
        priority_areas=[],
    )


# =============================================================================
# AI EXPLOIT HELPER
# =============================================================================

async def analyze_crash_for_exploitation(
    crash_data: Dict[str, Any],
    crash_input: Optional[bytes] = None,
    binary_info: Optional[Dict[str, Any]] = None,
    include_poc_guidance: bool = True,
) -> ExploitAnalysisResult:
    """
    Perform deep AI analysis of a crash to assess exploitability and provide PoC guidance.
    """
    crash_id = crash_data.get("id", "unknown")
    
    if not genai_client:
        return _fallback_exploit_analysis(crash_data, crash_id)
    
    try:
        # Prepare crash context
        context = {
            "crash_id": crash_id,
            "crash_type": crash_data.get("crash_type", "unknown"),
            "severity": crash_data.get("severity", "unknown"),
            "crash_address": crash_data.get("crash_address", "N/A"),
            "fault_address": crash_data.get("fault_address", "N/A"),
            "instruction": crash_data.get("instruction", "N/A"),
            "registers": crash_data.get("registers", {}),
            "stack_trace": crash_data.get("stack_trace", []),
            "memory_state": crash_data.get("memory_state", {}),
            "input_preview": base64.b64encode(crash_input[:200]).decode() if crash_input else None,
            "input_size": len(crash_input) if crash_input else 0,
            "binary_info": binary_info or {},
        }
        
        return await _ai_exploit_analysis(context, include_poc_guidance)
        
    except Exception as e:
        logger.error(f"AI exploit analysis failed: {e}")
        return _fallback_exploit_analysis(crash_data, crash_id)


async def _ai_exploit_analysis(context: Dict, include_poc: bool) -> ExploitAnalysisResult:
    """Use AI to perform deep exploit analysis."""
    
    poc_section = """
## PoC Guidance Required
Please also provide:
- Step-by-step exploitation approach
- How to bypass common mitigations (ASLR, DEP, stack canaries)
- Key bytes/offsets in the input that control the crash
- How to transform this crash into code execution
""" if include_poc else ""

    prompt = f"""You are an expert vulnerability researcher and exploit developer analyzing a program crash.

## Crash Information
- ID: {context['crash_id']}
- Type: {context['crash_type']}
- Current Severity: {context['severity']}
- Crash Address: {context['crash_address']}
- Fault Address: {context['fault_address']}
- Instruction: {context['instruction']}

## Registers at Crash
{json.dumps(context.get('registers', {}), indent=2)}

## Stack Trace
{json.dumps(context.get('stack_trace', [])[:10], indent=2)}

## Memory State
{json.dumps(context.get('memory_state', {}), indent=2)}

## Crash Input
- Size: {context['input_size']} bytes
- Preview (base64): {context.get('input_preview', 'N/A')}

{poc_section}

## Task
Perform a comprehensive exploitability analysis. Consider:
1. Is this crash exploitable? Why or why not?
2. What type of vulnerability is this?
3. What is the root cause?
4. What exploitation techniques could apply?
5. Are there similar CVEs?
6. How could this be remediated?

Respond in this exact JSON format:
{{
    "exploitability": "exploitable|probably_exploitable|probably_not|not_exploitable",
    "exploitability_score": 0.0-1.0,
    "vulnerability_type": "type of vulnerability",
    "root_cause": "What caused this crash",
    "affected_functions": ["function1", "function2"],
    "exploitation_techniques": [
        "Technique 1: description",
        "Technique 2: description"
    ],
    "poc_guidance": "Step by step exploitation approach...",
    "mitigation_bypass": [
        "How to bypass protection 1",
        "How to bypass protection 2"
    ],
    "similar_cves": ["CVE-XXXX-YYYY", "CVE-XXXX-ZZZZ"],
    "remediation": "How to fix this vulnerability",
    "detailed_analysis": "Comprehensive analysis of the crash..."
}}"""

    response = genai_client.models.generate_content(
        model="gemini-3-flash-preview",
        contents=prompt,
    )
    
    # Parse response
    text = response.text
    json_match = re.search(r'\{[\s\S]*\}', text)
    if json_match:
        data = json.loads(json_match.group())
    else:
        raise ValueError("No JSON found in response")
    
    return ExploitAnalysisResult(
        crash_id=context["crash_id"],
        exploitability=data.get("exploitability", "unknown"),
        exploitability_score=float(data.get("exploitability_score", 0.5)),
        vulnerability_type=data.get("vulnerability_type", "unknown"),
        root_cause=data.get("root_cause", "Unknown"),
        affected_functions=data.get("affected_functions", []),
        exploitation_techniques=data.get("exploitation_techniques", []),
        poc_guidance=data.get("poc_guidance", ""),
        mitigation_bypass=data.get("mitigation_bypass", []),
        cve_similar=data.get("similar_cves", []),
        remediation=data.get("remediation", ""),
        detailed_analysis=data.get("detailed_analysis", ""),
    )


def _fallback_exploit_analysis(crash_data: Dict, crash_id: str) -> ExploitAnalysisResult:
    """Provide basic exploit analysis without AI."""
    crash_type = crash_data.get("crash_type", "unknown").lower()
    
    # Basic exploitability heuristics
    exploitability = "probably_not"
    score = 0.3
    techniques = []
    
    if "write" in crash_type or "heap" in crash_type or "stack" in crash_type:
        exploitability = "probably_exploitable"
        score = 0.7
        techniques = [
            "Control flow hijacking via overwritten return address",
            "Arbitrary write primitive for GOT/PLT overwrite",
        ]
    elif "use_after_free" in crash_type or "double_free" in crash_type:
        exploitability = "exploitable"
        score = 0.9
        techniques = [
            "Heap feng shui for controlled allocation",
            "Type confusion via UAF object replacement",
        ]
    elif "read" in crash_type:
        exploitability = "probably_not"
        score = 0.2
        techniques = ["Information disclosure via out-of-bounds read"]
    
    return ExploitAnalysisResult(
        crash_id=crash_id,
        exploitability=exploitability,
        exploitability_score=score,
        vulnerability_type=crash_type,
        root_cause="Unable to determine without AI analysis",
        affected_functions=[],
        exploitation_techniques=techniques,
        poc_guidance="AI analysis unavailable. Manual analysis required.",
        mitigation_bypass=[],
        cve_similar=[],
        remediation="Fix the vulnerable code path that led to this crash.",
        detailed_analysis="Basic heuristic analysis. Enable AI for detailed analysis.",
    )


# =============================================================================
# COMBINED AI ASSISTANT
# =============================================================================

async def get_fuzzing_ai_summary(
    session_id: str,
    binary_path: str,
    binary_name: str,
    stats_history: List[Dict],
    crashes: List[Dict],
    current_corpus: List[Dict],
) -> Dict[str, Any]:
    """
    Get a comprehensive AI summary of the fuzzing session with all insights.
    """
    # Gather all analyses
    results = {
        "session_id": session_id,
        "timestamp": datetime.utcnow().isoformat(),
        "ai_enabled": genai_client is not None,
    }
    
    # Coverage advice
    try:
        coverage_advice = await analyze_coverage_and_advise(
            session_id, stats_history, current_corpus, crashes
        )
        results["coverage_analysis"] = {
            "is_stuck": coverage_advice.is_stuck,
            "stuck_reason": coverage_advice.stuck_reason,
            "trend": coverage_advice.coverage_trend,
            "recommendations": coverage_advice.recommendations,
            "mutation_adjustments": coverage_advice.mutation_adjustments,
        }
    except Exception as e:
        results["coverage_analysis"] = {"error": str(e)}
    
    # Analyze top crashes
    crash_analyses = []
    for crash in crashes[:5]:  # Top 5 crashes
        try:
            analysis = await analyze_crash_for_exploitation(crash)
            crash_analyses.append({
                "crash_id": analysis.crash_id,
                "exploitability": analysis.exploitability,
                "score": analysis.exploitability_score,
                "type": analysis.vulnerability_type,
                "techniques": analysis.exploitation_techniques[:3],
            })
        except Exception as e:
            crash_analyses.append({"crash_id": crash.get("id"), "error": str(e)})
    
    results["crash_analyses"] = crash_analyses
    
    return results
